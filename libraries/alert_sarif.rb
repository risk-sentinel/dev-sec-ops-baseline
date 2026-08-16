# encoding: utf-8
# =============================================================================
# alert_sarif — maps GitHub alert JSON into SARIF 2.1.0.
#
# Code scanning already serves SARIF; secret scanning and Dependabot do not,
# and neither has a converter in saf-cli. This module supplies the missing
# half so all three dashboards reach HDF through one maintained converter
# (`saf convert sarif2hdf`).
#
# ---- Why SARIF and not TruffleHog's shape -----------------------------------
#
# `trufflehog2hdf` exists and would happily accept secret-scanning alerts
# re-shaped into TruffleHog's JSON. It would also validate, convert cleanly,
# and attribute GitHub's findings to a scanner that never ran. SARIF carries
# `tool.driver.name`, so provenance survives the conversion — which is the
# whole point of putting this in an evidence package.
#
# ---- Purity -----------------------------------------------------------------
#
# No I/O, no HTTP, no clock. Every input is already-parsed JSON, so the mapping
# is fixture-testable without a token and without the network. The fetchers
# live in github_security; this module only shapes what they return.
#
# ---- The `secret` field -----------------------------------------------------
#
# GitHub returns the raw secret value on the secret-scanning endpoint when the
# caller holds sufficient scope. It must never reach an artifact that gets
# written to an evidence bucket, so it is dropped EXPLICITLY here rather than
# left out by only copying known-good fields — an allow-list that later grows
# a `properties` passthrough would silently start leaking it.
# =============================================================================

require 'set'

module AlertSarif
  SCHEMA  = 'https://json.schemastore.org/sarif-2.1.0.json'.freeze
  VERSION = '2.1.0'.freeze

  # Fields that must never be serialised, whatever the caller passes in.
  REDACTED_KEYS = %w[secret].freeze

  # Dependabot severity -> SARIF level. SARIF has no "critical", so critical
  # and high both map to error and severity is preserved in properties.
  SEVERITY_LEVEL = {
    'critical' => 'error',
    'high'     => 'error',
    'medium'   => 'warning',
    'moderate' => 'warning',
    'low'      => 'note'
  }.freeze

  module_function

  # ---- Secret scanning -------------------------------------------------------
  # `locations` is a hash of alert number => the array returned by
  # GET /repos/{o}/{r}/secret-scanning/alerts/{n}/locations. The list payload
  # carries no location at all, so a caller that omits it gets findings with
  # no file attached rather than an exception — a finding without a path is
  # still a finding, and failing the whole conversion over it would be worse.
  def from_secret_scanning(alerts, repo:, locations: {})
    results = Array(alerts).map do |alert|
      rule_id = alert['secret_type'].to_s
      rule_id = 'unknown_secret_type' if rule_id.empty?

      result(
        rule_id: rule_id,
        level:   secret_level(alert),
        text:    secret_message(alert),
        places:  secret_locations(locations[alert['number']] || locations[alert['number'].to_s]),
        props:   {
          'alertNumber' => alert['number'],
          'state'       => alert['state'],
          'validity'    => alert['validity'],
          'resolution'  => alert['resolution'],
          'htmlUrl'     => alert['html_url'],
          'createdAt'   => alert['created_at']
        }
      )
    end

    document(
      tool_name: 'GitHub Secret Scanning',
      info_uri:  'https://docs.github.com/code-security/secret-scanning',
      repo:      repo,
      results:   results,
      rules:     rules_from(results) { |r| secret_rule(r) }
    )
  end

  # ---- Dependabot ------------------------------------------------------------
  # Typed as SCA: these are vulnerability findings against declared
  # dependencies, the same assertion Grype and Trivy make from a different
  # vantage point. An SBOM is inventory and does NOT satisfy this.
  def from_dependabot(alerts, repo:)
    results = Array(alerts).map do |alert|
      adv  = alert['security_advisory'] || {}
      vuln = alert['security_vulnerability'] || {}
      pkg  = vuln['package'] || {}

      rule_id = adv['ghsa_id'].to_s
      rule_id = "dependabot-#{alert['number']}" if rule_id.empty?

      result(
        rule_id: rule_id,
        level:   SEVERITY_LEVEL.fetch(vuln['severity'].to_s.downcase, 'warning'),
        text:    dependabot_message(alert, adv, vuln, pkg),
        places:  dependabot_locations(alert),
        props:   {
          'alertNumber'        => alert['number'],
          'state'              => alert['state'],
          'severity'           => vuln['severity'],
          'ghsaId'             => adv['ghsa_id'],
          'cveId'              => adv['cve_id'],
          'packageName'        => pkg['name'],
          'packageEcosystem'   => pkg['ecosystem'],
          'vulnerableRange'    => vuln['vulnerable_version_range'],
          'firstPatchedVersion' => (vuln['first_patched_version'] || {})['identifier'],
          'htmlUrl'            => alert['html_url'],
          'createdAt'          => alert['created_at']
        }
      )
    end

    document(
      tool_name: 'GitHub Dependabot',
      info_uri:  'https://docs.github.com/code-security/dependabot',
      repo:      repo,
      results:   results,
      rules:     rules_from(results) { |r| dependabot_rule(r) }
    )
  end

  # ---- Shared ----------------------------------------------------------------

  def document(tool_name:, info_uri:, repo:, results:, rules:)
    {
      '$schema' => SCHEMA,
      'version' => VERSION,
      'runs'    => [
        {
          'tool' => {
            'driver' => {
              'name'           => tool_name,
              'informationUri' => info_uri,
              'rules'          => rules
            }
          },
          'automationDetails' => { 'id' => "#{tool_name}/#{repo}" },
          'results'           => results
        }
      ]
    }
  end

  def result(rule_id:, level:, text:, places:, props:)
    r = {
      'ruleId'  => rule_id,
      'level'   => level,
      'message' => { 'text' => text }
    }
    r['locations'] = places unless places.empty?
    r['properties'] = scrub(props.compact)
    r
  end

  # Explicit removal, applied to every property bag on the way out.
  def scrub(hash)
    hash.reject { |k, _| REDACTED_KEYS.include?(k.to_s.downcase) }
  end

  def physical(uri, start_line, end_line = nil)
    region = { 'startLine' => (start_line || 1).to_i }
    region['endLine'] = end_line.to_i if end_line
    {
      'physicalLocation' => {
        'artifactLocation' => { 'uri' => uri.to_s },
        'region'           => region
      }
    }
  end

  # One rule entry per distinct ruleId actually present in the results, built
  # from the first result carrying it. Deduped so a repository with forty
  # alerts of one type does not emit forty identical rules.
  def rules_from(results)
    seen = Set.new
    results.each_with_object([]) do |res, acc|
      id = res['ruleId']
      next unless seen.add?(id)
      acc << yield(res)
    end
  end

  # ---- Secret-scanning detail ------------------------------------------------

  def secret_level(alert)
    # An open alert whose credential is confirmed live is the urgent case.
    return 'note' unless alert['state'].to_s == 'open'
    alert['validity'].to_s == 'active' ? 'error' : 'warning'
  end

  def secret_message(alert)
    name = alert['secret_type_display_name'] || alert['secret_type'] || 'secret'
    bits = ["#{name} detected by GitHub secret scanning"]
    bits << "validity: #{alert['validity']}" unless alert['validity'].to_s.empty?
    bits << "state: #{alert['state']}"       unless alert['state'].to_s.empty?
    bits << "resolution: #{alert['resolution']}" unless alert['resolution'].to_s.empty?
    bits.join(' — ')
  end

  def secret_locations(entries)
    Array(entries).filter_map do |loc|
      details = loc['details'] || {}
      path = details['path'] || details['blob_path']
      next if path.to_s.empty?
      physical(path, details['start_line'], details['end_line'])
    end
  end

  def secret_rule(res)
    {
      'id'               => res['ruleId'],
      'name'             => res['ruleId'],
      'shortDescription' => { 'text' => "Secret of type #{res['ruleId']}" },
      'fullDescription'  => { 'text' => 'GitHub secret scanning matched a known credential pattern in this repository.' },
      'help'             => { 'text' => 'Revoke the credential at its issuer, then remove it from the repository. Rotation alone is insufficient while the value remains reachable in history.' },
      'properties'       => { 'tags' => %w[secrets] }
    }
  end

  # ---- Dependabot detail -----------------------------------------------------

  def dependabot_message(alert, adv, vuln, pkg)
    name  = pkg['name'] || 'dependency'
    range = vuln['vulnerable_version_range']
    fixed = (vuln['first_patched_version'] || {})['identifier']
    bits  = [adv['summary'] || "Vulnerability in #{name}"]
    bits << "package: #{name}"           unless name.to_s.empty?
    bits << "vulnerable: #{range}"       unless range.to_s.empty?
    bits << (fixed.to_s.empty? ? 'no patched version published' : "patched in: #{fixed}")
    bits << "state: #{alert['state']}"   unless alert['state'].to_s.empty?
    bits.join(' — ')
  end

  def dependabot_locations(alert)
    path = (alert['dependency'] || {})['manifest_path']
    return [] if path.to_s.empty?
    [physical(path, 1)]
  end

  def dependabot_rule(res)
    props = res['properties'] || {}
    {
      'id'               => res['ruleId'],
      'name'             => res['ruleId'],
      'shortDescription' => { 'text' => "#{props['severity']} severity in #{props['packageName']}" },
      'fullDescription'  => { 'text' => res.dig('message', 'text').to_s },
      'help'             => { 'text' => 'Upgrade the dependency to the first patched version. Where none exists, record a compensating control or an accepted risk.' },
      'properties'       => { 'tags' => %w[sca dependencies], 'security-severity' => severity_score(props['severity']) }
    }
  end

  # Heimdall reads security-severity to bucket findings by impact; without it
  # every SCA finding lands in the same undifferentiated pile.
  def severity_score(severity)
    case severity.to_s.downcase
    when 'critical' then '9.0'
    when 'high'     then '7.0'
    when 'medium', 'moderate' then '5.0'
    when 'low'      then '3.0'
    else '0.0'
    end
  end
end

# Plain modules defined in libraries/ never reach Object on their own — only
# custom resources self-register. Without this the control files raise
# NameError at exec while `check` and `json` both pass.
::Object.const_set(:AlertSarif, AlertSarif) unless ::Object.const_defined?(:AlertSarif)
