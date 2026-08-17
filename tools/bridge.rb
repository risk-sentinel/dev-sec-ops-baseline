#!/usr/bin/env ruby
# encoding: utf-8
# =============================================================================
# bridge.rb — fetch the three GitHub security dashboards and write SARIF plus a
# provenance record, ready for `saf convert sarif2hdf`.
#
#   ruby tools/bridge.rb --repo owner/name --out DIR [--ref refs/heads/main]
#
# Reuses the profile's own libraries rather than reimplementing the API layer,
# so the bridge and the controls cannot drift into disagreeing about what the
# platform said. GithubSecurity subclasses Inspec.resource, so a minimal stub
# stands in when running outside the runner.
#
# ---- What it writes ---------------------------------------------------------
#
#   code-scanning-<language>.sarif   verbatim from GitHub, one per language
#   secret-scanning.sarif            mapped by AlertSarif
#   dependabot.sarif                 mapped by AlertSarif
#   dispositions.json                alert state, for tools/apply_dispositions.py
#   provenance.json                  what ran, where, when, with what result
#
# ---- Why provenance is written on every run, including clean ones -----------
#
# A repository with nothing wrong is the outcome we want, and it is the one the
# evidence stream is worst at recording: a clean scan emitting no artifact is
# byte-for-byte identical to a bridge that never ran. The provenance record is
# what the profile turns into a passing control. It is written even when there
# is nothing else to write.
# =============================================================================

require 'json'
require 'fileutils'
require 'optparse'
# Must precede the library requires below: they subclass Inspec.resource.
require_relative 'inspec_stub'
require_relative '../libraries/github_security'
require_relative '../libraries/alert_sarif'

options = { ref: 'refs/heads/main' }
OptionParser.new do |o|
  o.banner = 'Usage: bridge.rb --repo owner/name --out DIR [--ref REF]'
  o.on('--repo REPO')   { |v| options[:repo] = v }
  o.on('--out DIR')     { |v| options[:out]  = v }
  o.on('--ref REF')     { |v| options[:ref]  = v }
  o.on('--api-base URL') { |v| options[:api_base] = v }
end.parse!

abort('--repo is required') if options[:repo].to_s.empty?
abort('--out is required')  if options[:out].to_s.empty?

FileUtils.mkdir_p(options[:out])

gh = GithubSecurity.new(options[:repo],
                        token: ENV.fetch('GITHUB_TOKEN', nil) || ENV.fetch('GH_TOKEN', nil),
                        api_base: options[:api_base])

# Timestamp is supplied by the caller where possible so re-running the bridge
# over a cached fetch is reproducible; it falls back to now.
generated_at = ENV.fetch('BRIDGE_TIMESTAMP', nil) || Time.now.utc.strftime('%Y-%m-%dT%H:%M:%SZ')

provenance = {
  'schemaVersion' => 1,
  'repository'    => options[:repo],
  'ref'           => options[:ref],
  'generatedAt'   => generated_at,
  'bridgeVersion' => 'dev-sec-ops-baseline/tools/bridge.rb',
  'sources'       => {}
}
dispositions = {}
written = []

def source_record(status:, reason: nil, **extra)
  { 'status' => status.to_s, 'reason' => reason }.compact.merge(extra.transform_keys(&:to_s))
end

# ---- Code scanning -----------------------------------------------------------
# The SARIF is taken verbatim. It is the tool's own output and re-serialising it
# through our own mapper would put us between CodeQL and the evidence.
cs_status = gh.capability_status(:code_scanning)
if cs_status == :enabled
  per_lang = gh.scan_provenance(ref: options[:ref]) || []
  analyses = []

  per_lang.each do |p|
    sarif = gh.analysis_sarif(p['analysisId'])
    if sarif.nil?
      analyses << p.merge('sarifFetched' => false)
      warn "WARN  code scanning: SARIF fetch failed for analysis #{p['analysisId']} (#{p['language']})"
      next
    end
    name = "code-scanning-#{p['language'].gsub(/[^a-z0-9._-]/i, '_')}.sarif"
    File.write(File.join(options[:out], name), JSON.pretty_generate(sarif))
    written << name
    analyses << p.merge('sarifFetched' => true, 'sarifFile' => name)
  end

  total = analyses.sum { |a| a['resultsCount'].to_i }
  provenance['sources']['code_scanning'] = source_record(
    status: :enabled, 'analyses' => analyses, 'languages' => analyses.size,
    'resultsCount' => total
  )

  # Dispositions: results_count counts everything in the upload, including
  # findings already triaged. Without this the bridge would republish closed
  # triage decisions as live failures on every run.
  alerts = gh.code_scanning_alerts(state: 'all') || []
  dispositions['code_scanning'] = Array(alerts).map do |a|
    inst = a['most_recent_instance'] || {}
    loc  = inst['location'] || {}
    {
      'number'          => a['number'],
      'ruleId'          => a.dig('rule', 'id'),
      'state'           => a['state'],
      'dismissedReason' => a['dismissed_reason'],
      'dismissedBy'     => a.dig('dismissed_by', 'login'),
      'dismissedAt'     => a['dismissed_at'],
      'dismissedComment' => a['dismissed_comment'],
      'path'            => loc['path'],
      'startLine'       => loc['start_line']
    }
  end
else
  provenance['sources']['code_scanning'] =
    source_record(status: cs_status, reason: gh.capability_reason(:code_scanning))
  warn "INFO  code scanning #{cs_status}: #{gh.capability_reason(:code_scanning)}"
end

# ---- Secret scanning ---------------------------------------------------------
ss_status = gh.capability_status(:secret_scanning)
if ss_status == :enabled
  bundle = gh.secret_scanning_bundle || { 'alerts' => [], 'locations' => {} }
  sarif  = AlertSarif.from_secret_scanning(bundle['alerts'],
                                           repo: options[:repo],
                                           locations: bundle['locations'])
  filename = 'secret-scanning.sarif'
  File.write(File.join(options[:out], filename), JSON.pretty_generate(sarif))
  written << filename

  bypasses = gh.push_protection_bypasses || []
  provenance['sources']['secret_scanning'] = source_record(
    status: :enabled,
    'openAlerts' => bundle['alerts'].size,
    'pushProtectionBypasses' => bypasses.size,
    'sarifFile' => filename
  )
  warn "WARN  #{bypasses.size} push-protection bypass(es) recorded" unless bypasses.empty?
else
  provenance['sources']['secret_scanning'] =
    source_record(status: ss_status, reason: gh.capability_reason(:secret_scanning))
  warn "INFO  secret scanning #{ss_status}: #{gh.capability_reason(:secret_scanning)}"
end

# ---- Dependabot --------------------------------------------------------------
db_status = gh.capability_status(:dependabot_alerts)
if db_status == :enabled
  alerts = gh.open_alerts(:dependabot_alerts) || []
  sarif  = AlertSarif.from_dependabot(alerts, repo: options[:repo])
  filename = 'dependabot.sarif'
  File.write(File.join(options[:out], filename), JSON.pretty_generate(sarif))
  written << filename
  provenance['sources']['dependabot'] = source_record(
    status: :enabled, 'openAlerts' => alerts.size,
    'scanType' => 'sca', 'sarifFile' => filename
  )
else
  provenance['sources']['dependabot'] =
    source_record(status: db_status, reason: gh.capability_reason(:dependabot_alerts))
  warn "INFO  dependabot #{db_status}: #{gh.capability_reason(:dependabot_alerts)}"
end

# A transport failure must never look like a clean scan. It is recorded in the
# provenance so the profile fails the freshness control rather than passing on
# a record that was written by a broken run.
provenance['connectionError'] = gh.connection_error if gh.connection_error

File.write(File.join(options[:out], 'dispositions.json'), JSON.pretty_generate(dispositions))
File.write(File.join(options[:out], 'provenance.json'),   JSON.pretty_generate(provenance))

puts "bridge: #{options[:repo]} @ #{options[:ref]}"
provenance['sources'].each do |name, rec|
  detail = rec['status'] == 'enabled' ? rec.reject { |k, _| k == 'status' }.to_json : rec['reason']
  puts "  #{name}: #{rec['status']} #{detail}"
end
puts "  wrote: #{(written + %w[dispositions.json provenance.json]).join(', ')}"
warn "WARN  connection error recorded: #{gh.connection_error}" if gh.connection_error
