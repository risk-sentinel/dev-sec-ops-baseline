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

  # A ruleset in `evaluate` mode reports its name and blocks nothing. Asserting
  # on presence rather than enforcement is the same error as counting controls
  # without checking whether any carried attribution.
  def evaluate_mode_ruleset_names
    rulesets.reject { |r| r['enforcement'] == 'active' }.map { |r| r['name'] }
  end

  def ruleset_detail(id)
    @cache[[:ruleset, id]] ||= begin
      resp = get("/repos/#{@repo}/rulesets/#{id}")
      resp[:code] == 200 ? resp[:body] : nil
    end
  end

  def default_branch
    @cache[:default_branch] ||= begin
      resp = get("/repos/#{@repo}")
      resp[:code] == 200 ? resp[:body].to_h['default_branch'] : nil
    end
  end

  # Active rulesets whose ref conditions actually cover this branch. A ruleset
  # scoped to ~DEFAULT_BRANCH says nothing about a release branch, and counting
  # it would report protection the branch does not have.
  def active_rulesets_for(branch)
    @cache[[:rs_for, branch]] ||= rulesets
      .select { |r| r['enforcement'] == 'active' }
      .filter_map { |r| ruleset_detail(r['id']) }
      .select { |d| ruleset_covers?(d, branch) }
  end

  def rules_of_type(branch, type)
    active_rulesets_for(branch).flat_map { |d| Array(d['rules']) }
                               .select { |r| r['type'] == type }
  end

  # ---- Effective governance -------------------------------------------------
  #
  # GitHub evaluates classic branch protection AND rulesets together, and the
  # most restrictive wins. Reading only one is how you get a confident false
  # finding: five of seven repositories here have NO classic protection at all,
  # and the two that do report zero required reviews while their rulesets
  # require one. A classic-only reading calls the whole estate unprotected.
  def effective_required_reviews(branch = 'main')
    from_classic = branch_protection(branch)
                   &.dig('required_pull_request_reviews', 'required_approving_review_count').to_i
    from_rules = rules_of_type(branch, 'pull_request')
                 .map { |r| r.dig('parameters', 'required_approving_review_count').to_i }
    ([from_classic] + from_rules).compact.max.to_i
  end

  def effective_required_checks(branch = 'main')
    classic = Array(branch_protection(branch)&.dig('required_status_checks', 'contexts'))
    ruled = rules_of_type(branch, 'required_status_checks').flat_map do |r|
      Array(r.dig('parameters', 'required_status_checks')).map { |c| c['context'] }
    end
    (classic + ruled).compact.uniq.sort
  end

  def signed_commits_required?(branch = 'main')
    classic = branch_protection(branch)&.dig('required_signatures', 'enabled')
    return true if classic
    rules_of_type(branch, 'required_signatures').any?
  end

  def stale_reviews_dismissed?(branch = 'main')
    classic = branch_protection(branch)&.dig('required_pull_request_reviews', 'dismiss_stale_reviews')
    return true if classic
    rules_of_type(branch, 'pull_request')
      .any? { |r| r.dig('parameters', 'dismiss_stale_reviews_on_push') }
  end

  def code_owner_review_required?(branch = 'main')
    classic = branch_protection(branch)&.dig('required_pull_request_reviews', 'require_code_owner_reviews')
    return true if classic
    rules_of_type(branch, 'pull_request')
      .any? { |r| r.dig('parameters', 'require_code_owner_review') }
  end

  # Which mechanism actually supplied the protection. Carried into the result
  # so a passing control says HOW the repository is protected, not merely that
  # it is — the two mechanisms have different owners and different blast radius.
  def governance_sources(branch = 'main')
    src = []
    src << 'classic branch protection' unless branch_protection(branch).nil?
    active_rulesets_for(branch).each do |d|
      # Repository vs Organization matters: an org-level ruleset cannot be
      # weakened by the repository owner, which is a materially stronger
      # guarantee than the same rule set locally. The repo endpoint returns
      # parent rulesets by default, so org rules are already included here.
      scope = d['source_type'] == 'Organization' ? 'org ruleset' : 'repo ruleset'
      src << "#{scope} '#{d['name']}'"
    end
    src.empty? ? ['none'] : src
  end

  # ---- Workflow inventory (repo_contents surface) ---------------------------
  def workflow_paths
    @cache[:wf_paths] ||= begin
      resp = get("/repos/#{@repo}/contents/.github/workflows")
      return [] unless resp[:code] == 200
      Array(resp[:body]).map { |f| f['path'] }
                        .select { |p| p.end_with?('.yml', '.yaml') }
    end
  end

  # Workflows that actually run one of the named scanners. Passing the tool list
  # in rather than hardcoding it keeps the registry the single source of truth
  # for what counts as a security tool.
  def security_workflows(tool_names)
    @cache[[:sec_wf, tool_names]] ||= workflow_paths.select do |path|
      body = file_contents(path).to_s.downcase
      tool_names.any? { |t| body.include?(t.to_s.downcase) }
    end
  end

  # Shift-left, asked PER TOOL rather than per workflow.
  #
  # "This workflow mentions a scanner and does not run on a pull request" is the
  # wrong question: deploy.yml legitimately mentions cosign, and an HDF emit
  # workflow legitimately runs only after merge because it FETCHES results.
  # Flagging those produces noise that trains people to ignore the control.
  #
  # The question that matters is whether a given scanner runs on a pull request
  # ANYWHERE. If every workflow that runs it fires only post-merge, then that
  # scanner finds problems already on the default branch — which is the thing
  # shift-left means, and which no security endpoint reports because it is a
  # fact about a YAML file.
  # Two ways a tool can gate a pull request, and BOTH must count:
  #
  #   1. a workflow that runs it fires on `pull_request`
  #   2. it appears as a REQUIRED STATUS CHECK context
  #
  # The second is not a technicality. SonarCloud analysis is triggered by the
  # GitHub App rather than by any workflow, so no file mentions it with a
  # pull_request trigger — yet "SonarCloud Code Analysis" is a required check
  # and genuinely blocks merges. Judging by triggers alone reports the estate's
  # most consistently-enforced scanner as not gating anything.
  #
  # A required check is also the STRONGER signal: a trigger means it runs, a
  # required check means it must pass.
  # `names` carries the tool key plus any registry aliases: a tool's identity and
  # the string a CI system reports it under are frequently different. SonarQube
  # reports as "SonarCloud Code Analysis", so matching the key alone declares
  # the estate's most consistently-enforced scanner ungated.
  def tool_runs_on_pull_request?(tool, branch = 'main', names = nil)
    needles = Array(names).unshift(tool).compact
                          .map { |n| n.to_s.downcase.tr('_ -', '') }.uniq
    @cache[[:tool_pr, tool, branch]] ||= begin
      gated_by_check = effective_required_checks(branch).any? do |ctx|
        c = ctx.to_s.downcase.tr('_ -', '')
        needles.any? { |n| c.include?(n) }
      end
      gated_by_check || workflow_paths.any? do |path|
        body = file_contents(path).to_s
        next false unless body.downcase.include?(tool.to_s.downcase)
        scans_on_pull_request?(path)
      end
    end
  end

  # tool_names may be plain keys or [key, [aliases...]] pairs.
  def tools_not_gating_pull_requests(tool_names, branch = 'main', alias_map = {})
    Array(tool_names).reject do |t|
      tool_runs_on_pull_request?(t, branch, alias_map[t.to_s])
    end
  end

  def codeowners
    @cache[:codeowners] ||= ['.github/CODEOWNERS', 'CODEOWNERS', 'docs/CODEOWNERS']
                            .filter_map { |p| file_contents(p) }.first
  end

  def codeowners?
    !codeowners.nil?
  end

  # Paths named in CODEOWNERS, ignoring comments and blank lines. Presence of
  # the file is not coverage: a CODEOWNERS listing only docs/ leaves every
  # security-relevant path unowned while looking configured.
  def codeowners_paths
    return [] if codeowners.nil?
    codeowners.each_line.filter_map do |line|
      l = line.strip
      next if l.empty? || l.start_with?('#')
      l.split(/\s+/).first
    end
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

  # ~ALL covers everything; ~DEFAULT_BRANCH resolves against the repo's default;
  # anything else is a ref pattern. Exclusions win over inclusions, which is how
  # GitHub evaluates them.
  def ruleset_covers?(detail, branch)
    cond = detail.to_h.dig('conditions', 'ref_name') || {}
    inc = Array(cond['include'])
    exc = Array(cond['exclude'])
    return false if exc.any? { |p| ref_matches?(p, branch) }
    return true if inc.empty?
    inc.any? { |p| ref_matches?(p, branch) }
  end

  def ref_matches?(pattern, branch)
    case pattern
    when '~ALL' then true
    when '~DEFAULT_BRANCH' then branch == default_branch
    else
      ref = pattern.sub(%r{\Arefs/heads/}, '')
      File.fnmatch?(ref, branch)
    end
  end

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
