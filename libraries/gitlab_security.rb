# encoding: utf-8
# =============================================================================
# gitlab_security — reads GitLab's merge-request governance, across all three
# places it can live.
#
# Same construction contract as github_security, for the same reasons:
# positional opts hash (InSpec dispatches through a *args splat, so kwargs raise
# "given 2, expected 0..1" at exec time), transport failure captured in
# `connection_error` rather than raised, and credentials through opts because
# resources cannot read inputs.
#
# ---- Why this resource is shaped by a defect we already shipped -------------
#
# Phase 3 shipped `github_security` reading CLASSIC branch protection only. Five
# of seven repositories here had none — their rules lived in rulesets — so the
# control would have reported the entire estate unprotected. Then a second
# defect: the shift-left control read "no `pull_request` trigger" as post-merge,
# when push-triggered checks appear on pull requests and can be required.
#
# Both had one shape: READ ONE PLACE, CONCLUDE ABOUT THE WHOLE.
#
# GitLab has the same shape and one more layer of it.
#
# ---- Where merge-request rules actually live --------------------------------
#
#   1. The PROJECT.       approval_rules, approval settings, protected branches,
#                         push rules. The obvious one.
#
#   2. The GROUP.         Group protected branches and group approval settings
#                         apply to member projects and are INVISIBLE in project
#                         configuration. This is the analogue of GitHub
#                         org-level rulesets — except GitHub's repo endpoint
#                         folds parent rulesets in for us and GitLab does not.
#                         They must be fetched and merged deliberately.
#
#   3. A separate SECURITY POLICY PROJECT.
#                         Merge-request approval policies and scan execution
#                         policies are authored as YAML in a linked project and
#                         applied to the target. The rules governing project A
#                         live in project B, and reading A tells you nothing.
#                         This is first-class GitLab design, not a workaround.
#
# A rule set in a policy project cannot be weakened by the project maintainer.
# That is a materially stronger guarantee than the same rule set locally, so
# `governance_sources` names which layer supplied each rule rather than
# reporting a single merged number. An assessment that cannot distinguish them
# is worth less than one that can.
#
# ---- Absence is not the same as unreachable ---------------------------------
#
# A project with no approval rules and a project whose policy project we cannot
# read are different findings, and only the first is about the project. The
# second is a credential or visibility problem and says nothing at all.
#
# `policy_project_state` therefore returns FOUR values, not a boolean:
#
#   :none          no policy project is linked
#   :unreadable    one is linked and we cannot read it — the caller should
#                  ERROR, following the evidence_store precedent, not report
#                  absence
#   :out_of_scope  readable, but no policy in it scopes to this project
#   :applies       readable, and at least one policy scopes here
#
# Collapsing those into "no rules" would repeat the phase-3 defect in a new
# place, which is the one outcome this design exists to prevent.
#
# ---- Not exec-validated -----------------------------------------------------
#
# Every repository in this organisation is on GitHub and there is no GitLab
# instance to run against. This ships fixture-tested and explicitly NOT
# exec-validated. That label is carried honestly rather than quietly: v0.1.4
# shipped a defect that broke a consumer's exec leg precisely because static
# checks only LOAD a library, and fixtures are the only net here.
# =============================================================================

require 'json'
require 'net/http'
require 'yaml'
require 'set'
require 'uri'

class GitlabSecurity < Inspec.resource(1)
  name 'gitlab_security'
  supports platform: 'os'
  desc 'Merge-request governance for a GitLab project, resolved across project, group and policy-project layers.'
  example <<~EXAMPLE
    describe gitlab_security('group/project', token: input('gitlab_token')) do
      its('effective_required_approvals') { should cmp 2 }
      its('governance_sources') { should include 'policy project' }
    end
  EXAMPLE

  DEFAULT_API = 'https://gitlab.com/api/v4'.freeze

  # Where GitLab keeps security policies inside a policy project. Fixed by the
  # platform, not configurable per project.
  POLICY_PATH = '.gitlab/security-policies/policy.yml'.freeze

  attr_reader :project, :group, :connection_error

  def self.first_credential(*candidates)
    candidates.map { |c| c.to_s.strip }.find { |c| !c.empty? }
  end

  def initialize(project = nil, opts = {})
    if project.is_a?(Hash)
      opts = project
      project = opts[:project] || opts['project'] || opts[:repo] || opts['repo']
    end
    opts = {} unless opts.is_a?(Hash)

    @project = project.to_s.empty? ? nil : project.to_s
    # A GitLab namespace can be nested several levels deep, so the group is
    # everything above the final segment — not `split('/').first`, which would
    # look up the top-level group and miss a subgroup's protected branches.
    @group = (opts[:group] || opts['group'] || opts[:org] || opts['org'] ||
              (@project&.include?('/') ? @project.split('/')[0..-2].join('/') : nil))
    @api_base = (opts[:api_base] || opts['api_base'] || DEFAULT_API).to_s.chomp('/')
    # Blank-safe. An unset InSpec input arrives as "", which is truthy, so a
    # plain `||` chain short-circuits on it and never reaches the environment.
    @token = self.class.first_credential(opts[:token], opts['token'],
                                         ENV.fetch('GITLAB_TOKEN', nil))
    @timeout = (opts[:timeout] || opts['timeout'] || 15).to_i

    @connection_error = nil
    @cache = {}

    return unless @project.nil? && @group.nil?
    @connection_error = 'neither a project (group/name) nor a group was supplied'
  end

  def to_s
    @project ? "GitLab Security '#{@project}'" : "GitLab Security group '#{@group}'"
  end

  # ---- Authentication state -------------------------------------------------
  # Same trap as GitHub: an unauthenticated GET /groups/:id/projects answers 200
  # and simply omits everything private. The denominator comes back SHORT, not
  # broken, and reconciliation then reports real projects as stale declarations.
  def token_present?
    !@token.to_s.strip.empty?
  end

  def viewer_login
    return nil unless token_present?
    @cache[:viewer] ||= begin
      resp = get('/user')
      resp[:code] == 200 ? (resp[:body] || {})['username'] : nil
    end
  end

  def authenticated?
    !viewer_login.nil?
  end

  def enumeration_trust
    return 'no token supplied — private projects are invisible and the ' \
           'project list is silently short' unless token_present?
    login = viewer_login
    return 'token was supplied but rejected — the project list reflects ' \
           'anonymous access only' if login.nil?
    "authenticated as #{login}"
  end

  # ---- Layer 1: the project -------------------------------------------------
  def approval_rules
    @cache[:approval_rules] ||= begin
      resp = get("/projects/#{encoded_project}/approval_rules")
      resp[:code] == 200 ? Array(resp[:body]) : []
    end
  end

  def approval_settings
    @cache[:approval_settings] ||= begin
      resp = get("/projects/#{encoded_project}/approvals")
      resp[:code] == 200 ? (resp[:body] || {}) : {}
    end
  end

  def protected_branches
    @cache[:protected] ||= begin
      resp = get("/projects/#{encoded_project}/protected_branches")
      resp[:code] == 200 ? Array(resp[:body]) : []
    end
  end

  # GitLab protected-branch names may be wildcards (`release/*`), so an
  # equality test would report a branch as unprotected while a rule covers it.
  def protected_branch(branch = 'main')
    protected_branches.find { |b| branch_pattern_covers?(b['name'].to_s, branch) }
  end

  def push_rules
    @cache[:push_rules] ||= begin
      resp = get("/projects/#{encoded_project}/push_rule")
      # 404 here means "no push rules configured", which is an answer, not a
      # failure. Anything else is left to connection_error.
      resp[:code] == 200 ? (resp[:body] || {}) : {}
    end
  end

  # ---- Layer 2: the group ---------------------------------------------------
  # Fetched deliberately. GitLab does NOT fold these into the project response,
  # so a project can look entirely unconfigured while being fully governed from
  # above — the exact false finding that motivated this design.
  def group_protected_branches
    return [] if @group.to_s.empty?
    @cache[:group_protected] ||= begin
      resp = get("/groups/#{encoded_group}/protected_branches")
      resp[:code] == 200 ? Array(resp[:body]) : []
    end
  end

  def group_protected_branch(branch = 'main')
    group_protected_branches.find { |b| branch_pattern_covers?(b['name'].to_s, branch) }
  end

  # ---- Layer 3: the security policy project ---------------------------------
  #
  # Resolved through GraphQL: the REST API has no endpoint that names a
  # project's linked policy project.
  def policy_project_path
    return @cache[:policy_path] if @cache.key?(:policy_path)
    @cache[:policy_path] = begin
      body = graphql(
        'query($fullPath: ID!) { project(fullPath: $fullPath) ' \
        '{ securityPolicyProject { fullPath } } }',
        { 'fullPath' => @project.to_s }
      )
      body&.dig('data', 'project', 'securityPolicyProject', 'fullPath')
    end
  end

  def policy_project_linked?
    !policy_project_path.to_s.empty?
  end

  # Raw policy documents from the linked project, or nil when it could not be
  # read. nil and [] mean different things here and must not be collapsed:
  # nil is "we could not look", [] is "we looked and it is empty".
  def policy_documents
    return @cache[:policy_docs] if @cache.key?(:policy_docs)
    @cache[:policy_docs] = begin
      path = policy_project_path
      if path.to_s.empty?
        []
      else
        raw = file_contents(POLICY_PATH, project: path)
        if raw.nil?
          nil
        else
          begin
            doc = YAML.safe_load(raw, aliases: true) || {}
            # Both policy types live in one document under separate keys.
            Array(doc['approval_policy']) +
              Array(doc['scan_result_policy']) +
              Array(doc['scan_execution_policy'])
          rescue StandardError => e
            @connection_error ||= "policy.yml in #{path} did not parse: #{e.message}"
            nil
          end
        end
      end
    end
  end

  # Enabled policies that scope to THIS project. A policy that exists but does
  # not scope here governs nothing, and counting it would claim protection the
  # project does not have.
  def scoped_policies
    docs = policy_documents
    return [] if docs.nil?
    docs.select { |p| p['enabled'] != false && policy_scopes_here?(p) }
  end

  # :none | :unreadable | :out_of_scope | :applies — see the header. The caller
  # must treat :unreadable as an ERROR, not as absence.
  def policy_project_state
    return :none unless policy_project_linked?
    return :unreadable if policy_documents.nil?
    scoped_policies.empty? ? :out_of_scope : :applies
  end

  def policy_project_detail
    case policy_project_state
    when :none         then 'no security policy project is linked'
    when :unreadable   then "policy project '#{policy_project_path}' is linked but " \
                            "could not be read — this says nothing about the project's " \
                            'governance, only about our access'
    when :out_of_scope then "policy project '#{policy_project_path}' is readable but no " \
                            'enabled policy scopes to this project'
    else "policy project '#{policy_project_path}' supplies " \
         "#{scoped_policies.length} scoped polic#{scoped_policies.length == 1 ? 'y' : 'ies'}"
    end
  end

  # ---- Effective governance across all three layers -------------------------
  #
  # Most restrictive wins, same principle as github_security's classic-plus-
  # rulesets merge. Reading any one layer alone is the phase-3 defect.
  def effective_required_approvals(branch = 'main')
    ([project_required_approvals,
      group_required_approvals(branch),
      policy_required_approvals].compact.max || 0).to_i
  end

  def project_required_approvals
    from_rules = approval_rules.map { |r| r['approvals_required'].to_i }
    from_settings = approval_settings['approvals_before_merge'].to_i
    ([from_settings] + from_rules).max.to_i
  end

  # Group protected branches carry merge access levels rather than an approval
  # count. A branch nobody may merge to directly is a governance fact, but it is
  # not an approval requirement, so this returns nil rather than inventing a
  # number.
  def group_required_approvals(_branch = 'main')
    nil
  end

  def policy_required_approvals
    return nil if scoped_policies.empty?
    counts = scoped_policies.flat_map do |p|
      Array(p['actions']).map { |a| a['approvals_required'] }
    end.compact.map(&:to_i)
    counts.empty? ? nil : counts.max
  end

  # Takes a branch for interface parity with github_security, and ignores it:
  # GitLab push rules are project-wide, not per-branch. Accepting and dropping
  # the argument is honest — silently applying a project-wide answer to a
  # branch-scoped question is what the caller needs to know, and it is stated
  # here rather than discovered later.
  def signed_commits_required?(_branch = 'main')
    push_rules['reject_unsigned_commits'] == true
  end

  # ---- Project settings -----------------------------------------------------
  def project_settings
    @cache[:settings] ||= begin
      resp = get("/projects/#{encoded_project}")
      resp[:code] == 200 ? (resp[:body] || {}) : {}
    end
  end

  # The nearest thing GitLab has to a required status check. Deliberately NOT
  # wired into the required-checks control: that control asserts a DECLARED
  # SECURITY TOOL is among the required contexts, and GitLab exposes no context
  # names to check against — only this boolean. Passing that control on the
  # strength of "some pipeline must succeed" would be a weaker claim wearing a
  # stronger control's id.
  def pipeline_must_succeed?
    project_settings['only_allow_merge_if_pipeline_succeeds'] == true
  end

  def all_discussions_resolved_required?
    project_settings['only_allow_merge_if_all_discussions_are_resolved'] == true
  end

  # ---- CODEOWNERS -----------------------------------------------------------
  # GitLab looks in three places, in this order. Reading only the root — the
  # obvious implementation — would report a project using the conventional
  # `.gitlab/CODEOWNERS` as having no owners at all.
  CODEOWNERS_PATHS = ['CODEOWNERS', 'docs/CODEOWNERS', '.gitlab/CODEOWNERS'].freeze

  def codeowners
    return @cache[:codeowners] if @cache.key?(:codeowners)
    @cache[:codeowners] = CODEOWNERS_PATHS.filter_map { |p| file_contents(p) }.first
  end

  def codeowners?
    !codeowners.nil?
  end

  def codeowners_paths
    return [] if codeowners.nil?
    codeowners.to_s.each_line.filter_map do |line|
      stripped = line.strip
      next if stripped.empty? || stripped.start_with?('#') || stripped.start_with?('[')
      stripped.split(/\s+/).first
    end
  end

  def code_owner_approval_required?(branch = 'main')
    [protected_branch(branch), group_protected_branch(branch)]
      .compact.any? { |b| b['code_owner_approval_required'] == true }
  end

  def author_may_self_approve?
    # GitLab words this as "author approval ALLOWED", so the safe reading of a
    # missing key is that self-approval is possible. Defaulting the other way
    # would report a stricter posture than was verified.
    approval_settings.fetch('merge_requests_author_approval', true) == true
  end

  def stale_approvals_dismissed?
    approval_settings['reset_approvals_on_push'] == true
  end

  # ---- Interface parity with github_security --------------------------------
  # Same question, same method name, so a control asking "how many reviews does
  # merging need" does not have to know which forge answered. Where the question
  # does NOT translate, there is deliberately no alias — see ForgeSecurity.
  def effective_required_reviews(branch = 'main')
    effective_required_approvals(branch)
  end

  def code_owner_review_required?(branch = 'main')
    code_owner_approval_required?(branch)
  end

  def branch_protected?(branch = 'main')
    !protected_branch(branch).nil? || !group_protected_branch(branch).nil?
  end

  # Which layer supplied what. Not decoration: a rule from a policy project
  # cannot be weakened by the project maintainer, and an assessment that cannot
  # say where a rule came from cannot say how strong it is.
  def governance_sources(branch = 'main')
    src = []
    src << 'project approval rules' unless approval_rules.empty?
    src << 'project approval settings' if approval_settings['approvals_before_merge'].to_i.positive?
    src << "project protected branch '#{protected_branch(branch)['name']}'" if protected_branch(branch)
    src << 'project push rules' unless push_rules.empty?
    if group_protected_branch(branch)
      src << "group protected branch '#{group_protected_branch(branch)['name']}' (#{@group})"
    end
    src << "policy project '#{policy_project_path}'" if policy_project_state == :applies
    src.empty? ? ['none'] : src
  end

  # ---- Repository contents --------------------------------------------------
  # The other half of the merge-rules question: whether a scan fires on a merge
  # request at all is a fact about a file, and no policy read can answer it.
  def file_contents(path, project: nil)
    target = project || @project
    key = [:file, target, path]
    return @cache[key] if @cache.key?(key)
    @cache[key] = begin
      encoded_path = url_encode(path.to_s)
      resp = get("/projects/#{url_encode(target.to_s)}/repository/files/" \
                 "#{encoded_path}/raw?ref=#{url_encode(default_branch(target))}",
                 raw: true)
      resp[:code] == 200 ? resp[:raw] : nil
    end
  end

  def default_branch(project = nil)
    target = project || @project
    @cache[[:default_branch, target]] ||= begin
      resp = get("/projects/#{url_encode(target.to_s)}")
      (resp[:code] == 200 ? (resp[:body] || {})['default_branch'] : nil) || 'main'
    end
  end

  def ci_config
    @cache[:ci_config] ||= begin
      raw = file_contents('.gitlab-ci.yml')
      raw.nil? ? nil : (begin
        YAML.safe_load(raw, aliases: true)
      rescue StandardError
        nil
      end)
    end
  end

  # Does the pipeline run on merge requests at all? A job list that only ever
  # runs on the default branch is post-merge, whatever it scans.
  def scans_on_merge_request?
    doc = ci_config
    return false if doc.nil?
    serialised = doc.to_s
    serialised.include?('merge_request_event') ||
      serialised.include?('$CI_MERGE_REQUEST_IID') ||
      serialised.include?('Jobs/Secret-Detection') ||
      serialised.include?('Jobs/SAST')
  end

  # ---- Enumeration — the denominator ----------------------------------------
  def projects
    return [] if @group.to_s.empty?
    @cache[:projects] ||= paginate(
      "/groups/#{encoded_group}/projects?per_page=100&include_subgroups=true"
    )
  end

  def project_names
    projects.map { |p| p['path_with_namespace'] }.compact.sort
  end

  # Interface parity again: reconciliation asks one forge-neutral question and
  # should not have to rename it per platform. `path_with_namespace` is the full
  # path, matching what a declaration writes in `repo:`.
  def repo_names
    project_names
  end

  private

  def encoded_project
    url_encode(@project.to_s)
  end

  def encoded_group
    url_encode(@group.to_s)
  end

  # GitLab identifies projects and groups by URL-encoded path, so the slashes
  # in `group/sub/project` must survive as %2F rather than becoming path
  # separators.
  def url_encode(value)
    # NOT URI.encode_www_form_component: that renders a space as `+`, which is
    # correct for a form body and wrong inside a path segment, where GitLab
    # reads it literally. ERB::Util.url_encode would do, at the cost of pulling
    # erb into a resource that needs nothing else from it.
    value.to_s.b.gsub(/[^a-zA-Z0-9_.\-~]/) { |c| format('%%%02X', c.ord) }
  end

  # Protected-branch names may be wildcards. `release/*` covers `release/1.2`
  # and an equality test would call that branch unprotected.
  def branch_pattern_covers?(pattern, branch)
    return true if pattern == branch
    return false unless pattern.include?('*')
    escaped = Regexp.escape(pattern).gsub('\*', '.*')
    Regexp.new("\\A#{escaped}\\z").match?(branch)
  end

  # A policy with no scope block applies to the whole linked group, so an
  # absent scope means "applies here", not "applies nowhere". Getting this
  # backwards would silently drop the most common configuration.
  def policy_scopes_here?(policy)
    scope = policy['policy_scope']
    return true if scope.nil? || scope.empty?

    including = Array(scope.dig('projects', 'including'))
    excluding = Array(scope.dig('projects', 'excluding'))
    return false if excluding.any? { |p| project_matches?(p) }
    return true if including.empty?
    including.any? { |p| project_matches?(p) }
  end

  def project_matches?(entry)
    return false if @project.to_s.empty?
    value = entry.is_a?(Hash) ? (entry['full_path'] || entry['id']) : entry
    value.to_s == @project.to_s
  end

  def headers(raw: false)
    h = {
      'Accept'     => raw ? '*/*' : 'application/json',
      'User-Agent' => 'dev-sec-ops-baseline'
    }
    # PRIVATE-TOKEN is the personal / group / project access-token header.
    # OAuth tokens use Authorization: Bearer; PATs sent that way are rejected,
    # so the two are not interchangeable.
    h['PRIVATE-TOKEN'] = @token if @token && !@token.to_s.empty?
    h
  end

  # Never raises. Transport failure lands in connection_error and returns a
  # distinct code, so a caller can tell it from an HTTP answer.
  def get(path, raw: false)
    uri = URI.parse("#{@api_base}#{path}")
    resp = Net::HTTP.start(uri.host, uri.port,
                           use_ssl: uri.scheme == 'https',
                           open_timeout: @timeout, read_timeout: @timeout) do |http|
      http.get(uri.request_uri, headers(raw: raw))
    end

    parsed = if raw
               nil
             else
               begin
                 resp.body.to_s.empty? ? nil : JSON.parse(resp.body)
               rescue JSON::ParserError
                 nil
               end
             end

    {
      code:      resp.code.to_i,
      body:      parsed,
      raw:       resp.body,
      message:   parsed.is_a?(Hash) ? parsed['message'] || parsed['error'] : nil,
      next_page: resp['x-next-page']
    }
  rescue StandardError => e
    @connection_error = "GET #{path} failed: #{e.class}: #{e.message}"
    { code: 0, body: nil, raw: nil, message: @connection_error, next_page: nil }
  end

  # Takes an ABSOLUTE url, unlike `get`. The only caller is GraphQL, which lives
  # off the /api/v4 base rather than under it.
  def post_json(url, payload)
    uri = URI.parse(url)
    resp = Net::HTTP.start(uri.host, uri.port,
                           use_ssl: uri.scheme == 'https',
                           open_timeout: @timeout, read_timeout: @timeout) do |http|
      http.post(uri.request_uri, JSON.dump(payload),
                headers.merge('Content-Type' => 'application/json'))
    end
    return nil unless resp.code.to_i == 200
    begin
      JSON.parse(resp.body)
    rescue JSON::ParserError
      nil
    end
  rescue StandardError => e
    @connection_error = "POST #{url} failed: #{e.class}: #{e.message}"
    nil
  end

  # The policy-project link is GraphQL-only; no REST endpoint exposes it.
  def graphql(query, variables)
    body = post_json(graphql_endpoint, { 'query' => query, 'variables' => variables })
    return nil if body.nil?
    if body['errors']
      @connection_error ||= "GraphQL error: #{Array(body['errors']).map { |e| e['message'] }.join('; ')}"
      return nil
    end
    body
  end

  # /api/v4 -> /api/graphql on the same host. Derived rather than configured so
  # a self-managed instance needs one setting rather than two that can disagree.
  def graphql_endpoint
    @api_base.sub(%r{/api/v\d+\z}, '/api/graphql')
  end

  # GitLab paginates with x-next-page rather than a Link header for keyset-less
  # requests; both are present, and the header is the simpler contract.
  def paginate(path)
    items = []
    page = nil
    loop do
      target = page ? "#{path}&page=#{page}" : path
      resp = get(target)
      unless resp[:code] == 200
        @connection_error ||= "GET #{target} returned HTTP #{resp[:code]}" \
                              "#{resp[:message] ? " (#{resp[:message]})" : ''}"
        return items
      end
      items.concat(Array(resp[:body]))
      page = resp[:next_page].to_s
      break if page.empty?
    end
    items
  end
end

# Same per-target cache as GithubSecurityHandle, so a control asserting several
# things about one project does not re-request everything each time.
module GitlabSecurityHandle
  def self.call(project, group, token, api_base)
    @cache ||= {}
    path = project.to_s.include?('/') ? project.to_s : "#{group}/#{project}"
    @cache[path] ||= GitlabSecurity.new(path, token: token, api_base: api_base)
  end
end
::Object.const_set(:GitlabSecurityHandle, GitlabSecurityHandle) unless ::Object.const_defined?(:GitlabSecurityHandle)
