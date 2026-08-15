# encoding: utf-8
# =============================================================================
# github_security — reads GitHub's security control plane.
#
# Modelled directly on the document_attestation resource in the consumer repo.
# Three things are copied deliberately rather than re-derived:
#
#   1. `initialize(repo = nil, opts = {})` — a POSITIONAL opts hash, not
#      keyword arguments. InSpec dispatches resource construction through a
#      *args splat, so under Ruby 3 `github_security('x', token: 't')` arrives
#      as `.new('x', {token: 't'})` — two positional args. A kwargs signature
#      raises "given 2, expected 0..1" at exec time, and unit-testing `.new`
#      directly never surfaces it.
#
#   2. Every transport failure is captured in `connection_error` rather than
#      raised. Controls assert on it, so an unreachable API FAILS instead of
#      passing vacuously.
#
#   3. Tokens arrive through opts, never `input()`. InSpec resources cannot
#      read inputs — `input()` raises in resource scope and `defined?(input)`
#      is not a usable guard. The control body reads the input and passes it
#      down.
#
# ---- Why a disabled capability is a FAIL, not an empty result ---------------
#
# Probing this organisation returns, for repositories without Code Security:
#
#   GET /repos/{o}/{r}/code-scanning/alerts   -> 403 "Code Security must be enabled"
#   GET /repos/{o}/{r}/dependabot/alerts      -> 403 "Dependabot alerts are disabled"
#   GET /repos/{o}/{r}/secret-scanning/alerts -> 404 "Secret scanning is disabled"
#
# A resource that treats those as "no alerts" reports a repository nobody is
# scanning as clean. `capability_status` therefore returns a THREE-state value
# — :enabled, :disabled, :error — and both non-enabled states fail, with
# different messages, because they have different owners: :disabled is a
# configuration or licensing action, :error is a broken scan.
#
# Note also that on PUBLIC repositories code scanning and secret scanning are
# free, so an :enabled result there reflects GitHub's default rather than a
# deliberate control decision. Private repositories need Code Security
# licensing for those two; Dependabot alerts are a free toggle on both.
# =============================================================================

require 'json'
require 'net/http'
require 'set'
require 'uri'

class GithubSecurity < Inspec.resource(1)
  name 'github_security'
  supports platform: 'os'
  desc 'Enablement, merge-protection and alert state for a GitHub repository or organisation.'
  example <<~EXAMPLE
    # Repository scope
    describe github_security('risk-sentinel/sparc', token: input('github_token')) do
      it { should be_code_security_enabled }
      its('open_alert_count') { should cmp 0 }
    end

    # Organisation scope — the reconciliation denominator
    describe github_security(org: 'risk-sentinel', token: input('github_token')) do
      its('repo_names') { should include 'sparc-validate' }
    end
  EXAMPLE

  DEFAULT_API = 'https://api.github.com'.freeze

  # Blank-safe credential resolution — "" and whitespace count as absent,
  # because an unset InSpec input is an empty string, not nil.
  def self.first_credential(*candidates)
    candidates.map { |c| c.to_s.strip }.find { |c| !c.empty? }
  end

  # message fragments GitHub returns when a capability is off rather than
  # when the caller is genuinely unauthorised
  DISABLED_HINTS = [
    'must be enabled',
    'are disabled',
    'is disabled',
    'not enabled'
  ].freeze

  CAPABILITY_PATHS = {
    code_scanning:     'code-scanning/alerts',
    secret_scanning:   'secret-scanning/alerts',
    dependabot_alerts: 'dependabot/alerts'
  }.freeze

  attr_reader :repo, :org, :connection_error

  def initialize(repo = nil, opts = {})
    # Single-hash form: github_security(org: 'x', token: 't')
    if repo.is_a?(Hash)
      opts = repo
      repo = opts[:repo] || opts['repo']
    end
    opts = {} unless opts.is_a?(Hash)

    @repo     = repo.to_s.empty? ? nil : repo.to_s
    @org      = (opts[:org] || opts['org'] || (@repo&.include?('/') ? @repo.split('/').first : nil))
    @api_base = (opts[:api_base] || opts['api_base'] || DEFAULT_API).to_s.chomp('/')
    # Blank-safe, NOT `a || b || c`. An InSpec input declared with an
    # empty-string default arrives as "", which is TRUTHY in Ruby, so a plain
    # || chain short-circuits on it and never reaches the environment. That
    # breaks the documented "org-level CI secret needs no input plumbing" path.
    #
    # ENV.fetch with an explicit nil default rather than ENV[...]: the bracket
    # form reads as an assertion that the variable exists.
    @token    = self.class.first_credential(opts[:token], opts['token'],
                                            ENV.fetch('GITHUB_TOKEN', nil),
                                            ENV.fetch('GH_TOKEN', nil))
    @timeout  = (opts[:timeout] || opts['timeout'] || 15).to_i

    @connection_error = nil
    @cache = {}

    return unless @repo.nil? && @org.nil?
    @connection_error = 'neither a repo (owner/name) nor an org was supplied'
  end

  def to_s
    @repo ? "GitHub Security '#{@repo}'" : "GitHub Security org '#{@org}'"
  end

  # ---- Enablement ----------------------------------------------------------
  # :enabled | :disabled | :error — never a bare boolean, because "off" and
  # "could not tell" must not collapse into the same answer.
  def capability_status(capability)
    key = capability.to_sym
    path = CAPABILITY_PATHS[key]
    return :error unless path && repo_scoped?

    @cache[[:status, key]] ||= begin
      resp = get("/repos/#{@repo}/#{path}?per_page=1")
      case resp[:code]
      when 200, 206 then :enabled
      when 403, 404 then disabled_response?(resp) ? :disabled : :error
      else               :error
      end
    end
  end

  def code_security_enabled?     = capability_status(:code_scanning)     == :enabled
  def secret_scanning_enabled?   = capability_status(:secret_scanning)   == :enabled
  def dependabot_enabled?        = capability_status(:dependabot_alerts) == :enabled

  # Why a capability is not enabled, for the control's failure message.
  def capability_reason(capability)
    key  = capability.to_sym
    resp = @cache[[:resp, key]]
    return 'not evaluated' unless resp
    resp[:message] || "HTTP #{resp[:code]}"
  end

  # ---- Findings ------------------------------------------------------------
  # Returns nil (never []) when the capability is not enabled, so a caller
  # cannot mistake "off" for "clean". Controls must check enablement first.
  def open_alerts(capability)
    return nil unless capability_status(capability) == :enabled
    path = CAPABILITY_PATHS[capability.to_sym]
    @cache[[:alerts, capability.to_sym]] ||= paginate("/repos/#{@repo}/#{path}?state=open&per_page=100")
  end

  def open_alert_count(capability = :code_scanning)
    alerts = open_alerts(capability)
    alerts.nil? ? nil : alerts.size
  end

  # ---- Merge protection (API surface of the MR/PR question) ----------------
  def branch_protection(branch = 'main')
    @cache[[:protection, branch]] ||= begin
      resp = get("/repos/#{@repo}/branches/#{branch}/protection")
      resp[:code] == 200 ? resp[:body] : nil
    end
  end

  def required_status_checks(branch = 'main')
    Array(branch_protection(branch)&.dig('required_status_checks', 'contexts'))
  end

  def required_reviewers(branch = 'main')
    branch_protection(branch)&.dig('required_pull_request_reviews',
                                   'required_approving_review_count').to_i
  end

  def rulesets
    @cache[:rulesets] ||= begin
      resp = get("/repos/#{@repo}/rulesets")
      resp[:code] == 200 ? Array(resp[:body]) : []
    end
  end

  def active_ruleset_names
    rulesets.select { |r| r['enforcement'] == 'active' }.map { |r| r['name'] }
  end

  # ---- Repository contents (the OTHER half of the MR/PR question) ----------
  # Whether a scan fires on a pull request is a fact about a YAML file, not
  # platform state. Different surface, different access requirement.
  def file_contents(path)
    @cache[[:file, path]] ||= begin
      resp = get("/repos/#{@repo}/contents/#{path}",
                 accept: 'application/vnd.github.raw')
      resp[:code] == 200 ? resp[:raw] : nil
    end
  end

  def workflow_triggers(path)
    body = file_contents(path)
    return nil if body.nil?
    on = body[/^on:\s*(.*?)^\S/m] || body[/^on:.*$/]
    %w[pull_request push schedule workflow_dispatch merge_group]
      .select { |t| on.to_s.include?(t) }
  end

  def scans_on_pull_request?(path)
    Array(workflow_triggers(path)).include?('pull_request')
  end

  # ---- Organisation enumeration — the denominator --------------------------
  # Independent of any declaration file, which is the entire point: a document
  # cannot be the evidence that it is complete.
  def repos
    @cache[:repos] ||= paginate("/orgs/#{@org}/repos?per_page=100&type=all")
  end

  def repo_names
    Array(repos).map { |r| r['name'] }.compact.sort
  end

  def archived_repo_names
    Array(repos).select { |r| r['archived'] }.map { |r| r['name'] }.compact.sort
  end

  private

  def repo_scoped?
    return true if @repo
    @connection_error ||= 'repository scope required for this call'
    false
  end

  def disabled_response?(resp)
    msg = resp[:message].to_s.downcase
    DISABLED_HINTS.any? { |h| msg.include?(h) }
  end

  def headers(accept: 'application/vnd.github+json')
    h = {
      'Accept'               => accept,
      'X-GitHub-Api-Version' => '2022-11-28',
      'User-Agent'           => 'dev-sec-ops-baseline'
    }
    h['Authorization'] = "Bearer #{@token}" if @token && !@token.to_s.empty?
    h
  end

  # Never raises. Transport failure lands in connection_error and is reported
  # as a distinct code so callers can tell it apart from an HTTP answer.
  def get(path, accept: 'application/vnd.github+json')
    uri = URI.parse("#{@api_base}#{path}")
    resp = Net::HTTP.start(uri.host, uri.port,
                           use_ssl: uri.scheme == 'https',
                           open_timeout: @timeout, read_timeout: @timeout) do |http|
      http.get(uri.request_uri, headers(accept: accept))
    end

    parsed = begin
      resp.body.to_s.empty? ? nil : JSON.parse(resp.body)
    rescue JSON::ParserError
      nil
    end

    out = {
      code:    resp.code.to_i,
      body:    parsed,
      raw:     resp.body,
      message: parsed.is_a?(Hash) ? parsed['message'] : nil,
      link:    resp['link']
    }
    cache_capability_response(path, out)
    out
  rescue StandardError => e
    @connection_error = "GET #{path} failed: #{e.class}: #{e.message}"
    # Cache the failure too. Without this, capability_reason reports
    # "not evaluated" after a transport error — which reads as though nothing
    # was attempted rather than as a broken scan, and would land in a control
    # message as the least useful thing we could say.
    { code: 0, body: nil, raw: nil, message: @connection_error, link: nil }
      .tap { |out| cache_capability_response(path, out) }
  end

  def cache_capability_response(path, out)
    CAPABILITY_PATHS.each do |key, frag|
      @cache[[:resp, key]] = out if path.include?(frag)
    end
  end

  def paginate(path)
    items = []
    next_path = path
    while next_path
      resp = get(next_path)
      unless resp[:code] == 200
        @connection_error ||= "GET #{next_path} returned HTTP #{resp[:code]}" \
                              "#{resp[:message] ? " (#{resp[:message]})" : ''}"
        return items
      end
      items.concat(Array(resp[:body]))
      next_path = next_link(resp[:link])
    end
    items
  end

  def next_link(link_header)
    return nil if link_header.to_s.empty?
    link_header.split(',').each do |part|
      url, rel = part.split(';', 2)
      next unless rel.to_s.include?('rel="next"')
      return url.to_s.strip.delete('<>').sub(@api_base, '')
    end
    nil
  end
end

# Small cache so a control asserting several capabilities for one repository
# does not construct (and re-request) a fresh resource each time.
module GithubSecurityHandle
  def self.call(repo, org, token, api_base)
    @cache ||= {}
    slug = repo.include?('/') ? repo : "#{org}/#{repo}"
    @cache[slug] ||= GithubSecurity.new(slug, token: token, api_base: api_base)
  end
end
::Object.const_set(:GithubSecurityHandle, GithubSecurityHandle) unless ::Object.const_defined?(:GithubSecurityHandle)
