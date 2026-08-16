# encoding: utf-8
# =============================================================================
# Fixture test for the alert -> SARIF mapper.
#
# Plain Ruby, no InSpec and no network: alert_sarif is pure by design, so this
# runs anywhere Ruby does. `ruby tests/mapper_test.rb [outdir]` — when outdir is
# given the SARIF documents are written there so CI can push them through the
# real `saf convert sarif2hdf`. Shape assertions alone would not prove the
# converter accepts the output.
# =============================================================================

require 'json'
require 'fileutils'
require_relative '../libraries/alert_sarif'

FAILURES = []

def check(label)
  ok = yield
  puts(ok ? "  ok   #{label}" : "  FAIL #{label}")
  FAILURES << label unless ok
rescue StandardError => e
  puts "  FAIL #{label} (#{e.class}: #{e.message})"
  FAILURES << label
end

here     = File.expand_path(__dir__)
fixtures = File.join(here, 'fixtures')
outdir   = ARGV[0]

secret_alerts = JSON.parse(File.read(File.join(fixtures, 'secret_scanning_alerts.json')))
locations     = JSON.parse(File.read(File.join(fixtures, 'secret_scanning_locations.json')))
dep_alerts    = JSON.parse(File.read(File.join(fixtures, 'dependabot_alerts.json')))

secret_sarif = AlertSarif.from_secret_scanning(secret_alerts, repo: 'risk-sentinel/example', locations: locations)
dep_sarif    = AlertSarif.from_dependabot(dep_alerts, repo: 'risk-sentinel/example')

puts 'secret scanning -> SARIF'
run = secret_sarif['runs'].first

check('document declares SARIF 2.1.0') { secret_sarif['version'] == '2.1.0' && !secret_sarif['$schema'].to_s.empty? }
check('provenance names GitHub, not the scanner whose shape we reused') do
  run.dig('tool', 'driver', 'name') == 'GitHub Secret Scanning'
end
check('one result per alert') { run['results'].size == secret_alerts.size }
check('rules deduped by type (3 alerts, 2 distinct types)') { run.dig('tool', 'driver', 'rules').size == 2 }
check('active credential in an open alert is error') do
  run['results'].find { |r| r.dig('properties', 'alertNumber') == 42 }['level'] == 'error'
end
check('resolved alert is downgraded, not dropped') do
  r = run['results'].find { |r| r.dig('properties', 'alertNumber') == 43 }
  r && r['level'] == 'note'
end
check('unknown validity is warning, not error') do
  run['results'].find { |r| r.dig('properties', 'alertNumber') == 44 }['level'] == 'warning'
end
check('location resolved from the locations sub-call') do
  loc = run['results'].find { |r| r.dig('properties', 'alertNumber') == 42 }['locations'].first
  loc.dig('physicalLocation', 'artifactLocation', 'uri') == 'terraform/modules/iam/main.tf' &&
    loc.dig('physicalLocation', 'region', 'startLine') == 118
end
check('alert with no location still produces a finding') do
  r = run['results'].find { |r| r.dig('properties', 'alertNumber') == 44 }
  r && !r.key?('locations')
end

# The one that matters most. Serialise the whole document and search the raw
# text: an assertion on specific keys would pass while a nested passthrough
# leaked the value somewhere else in the tree.
puts 'redaction'
serialised = JSON.generate(secret_sarif)
%w[AKIAIOSFODNN7EXAMPLE ghp_examplevalueshouldneverbeserialised].each do |value|
  check("raw secret #{value[0, 8]}... absent from serialised SARIF") { !serialised.include?(value) }
end
check('scrub drops an explicitly injected secret key') do
  !JSON.generate(AlertSarif.scrub('secret' => 'leak', 'state' => 'open')).include?('leak')
end

puts 'dependabot -> SARIF'
drun = dep_sarif['runs'].first
check('provenance names Dependabot') { drun.dig('tool', 'driver', 'name') == 'GitHub Dependabot' }
check('one result per alert') { drun['results'].size == dep_alerts.size }
check('critical maps to error') do
  drun['results'].find { |r| r.dig('properties', 'alertNumber') == 8 }['level'] == 'error'
end
check('security-severity set so Heimdall can bucket by impact') do
  drun.dig('tool', 'driver', 'rules').all? { |r| !r.dig('properties', 'security-severity').to_s.empty? }
end
check('manifest path becomes the location') do
  drun['results'].first.dig('locations', 0, 'physicalLocation', 'artifactLocation', 'uri') == 'Gemfile.lock'
end
check('unpatched advisory says so rather than emitting an empty version') do
  drun['results'].find { |r| r.dig('properties', 'alertNumber') == 8 }
      .dig('message', 'text').include?('no patched version published')
end
check('tagged sca') do
  drun.dig('tool', 'driver', 'rules').all? { |r| Array(r.dig('properties', 'tags')).include?('sca') }
end

puts 'empty input'
empty = AlertSarif.from_dependabot([], repo: 'risk-sentinel/example')
check('no alerts yields a valid SARIF document with zero results') do
  empty['version'] == '2.1.0' && empty['runs'].first['results'] == []
end

if outdir
  FileUtils.mkdir_p(outdir)
  File.write(File.join(outdir, 'secret-scanning.sarif'), JSON.pretty_generate(secret_sarif))
  File.write(File.join(outdir, 'dependabot.sarif'),      JSON.pretty_generate(dep_sarif))
  File.write(File.join(outdir, 'empty.sarif'),           JSON.pretty_generate(empty))
  puts "wrote SARIF fixtures to #{outdir}"
end

puts
if FAILURES.empty?
  puts 'PASS — all mapper assertions held'
  exit 0
else
  puts "FAIL — #{FAILURES.size} assertion(s): #{FAILURES.join(', ')}"
  exit 1
end
