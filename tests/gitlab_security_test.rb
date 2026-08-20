# encoding: utf-8
# =============================================================================
# Fixture test for gitlab_security and the forge dispatcher.
#
# Plain Ruby, no InSpec runner and no network: HTTP is stubbed at the single
# private `get` / `post_json` seam, so every API shape below is a canned
# response rather than a live call. `ruby tests/gitlab_security_test.rb`.
#
# ---- Why this file carries more weight than usual ---------------------------
#
# Every repository in this organisation is on GitHub. There is no GitLab
# instance to exec against, so this profile ships gitlab_security explicitly NOT
# exec-validated, and these fixtures are the ONLY thing standing between the
# resource and a consumer.
#
# That is not a hypothetical. v0.1.4 shipped a defect that broke a consumer's
# exec leg because `check` and `json` only LOAD a library — they never call a
# method on it. Everything asserted here is invisible to both.
#
# The assertions are therefore weighted toward the failure the design exists to
# prevent: reading ONE place and concluding about the whole.
# =============================================================================

require 'json'
require 'yaml'
require_relative '../tools/inspec_stub'
require_relative '../libraries/github_security'
require_relative '../libraries/gitlab_security'
require_relative '../libraries/forge_security'

FAILURES = []

def check(label)
  ok = yield
  puts(ok ? "  ok   #{label}" : "  FAIL #{label}")
  FAILURES << label unless ok
rescue StandardError => e
  puts "  FAIL #{label} (#{e.class}: #{e.message})"
  FAILURES << label
end

# A GitlabSecurity whose HTTP layer answers from a hash of path fragment =>
# body. Overriding the two seams rather than the individual readers keeps the
# real routing, encoding and response handling under test — a stub at the
# method level would prove only that the stub works.
class StubbedGitlab < GitlabSecurity
  attr_reader :requested

  def initialize(project, routes: {}, graphql: nil, opts: {})
    super(project, opts)
    @routes = routes
    @graphql = graphql
    @requested = []
  end

  private

  def get(path, raw: false)
    @requested << path
    # FIRST match wins, in declaration order, so routes read specific-to-general.
    # A `=` prefix means the whole path must match exactly.
    #
    # Substring matching alone is genuinely ambiguous here: the project and
    # group protected-branch paths both contain `protected_branches`, and every
    # path contains `projects/`. Whichever tie-break is chosen, a shadowed route
    # surfaces as a TypeError deep inside the resource and reads like a resource
    # bug rather than a fixture one. Making the order explicit is the fix.
    _, body = @routes.find do |fragment, _|
      fragment.start_with?('=') ? path == fragment[1..] : path.include?(fragment)
    end
    return { code: 404, body: nil, raw: nil, message: 'Not Found', next_page: nil } if body.nil?
    return { code: body, body: nil, raw: nil, message: 'stubbed status', next_page: nil } if body.is_a?(Integer)
    raw ? { code: 200, body: nil, raw: body, next_page: nil }
        : { code: 200, body: body, raw: JSON.dump(body), next_page: nil }
  end

  def post_json(url, _payload)
    @requested << url
    @graphql
  end
end

def graphql_reply(path)
  { 'data' => { 'project' => { 'securityPolicyProject' => path.nil? ? nil : { 'fullPath' => path } } } }
end

POLICY_YAML = <<~YAML.freeze
  approval_policy:
    - name: Require two approvals on vulnerable MRs
      enabled: true
      actions:
        - type: require_approval
          approvals_required: 2
YAML

puts 'construction'
plain = GitlabSecurity.new('group/sub/project', {})
check('nested namespace becomes the group, not just the top level') do
  # split('/').first would yield 'group' and look up the wrong protected
  # branches — a subgroup's rules would be invisible.
  plain.group == 'group/sub'
end
check('a bare hash form is accepted like github_security') do
  GitlabSecurity.new(project: 'g/p').project == 'g/p'
end
check('neither project nor group is a connection error, not a crash') do
  GitlabSecurity.new(nil, {}).connection_error.to_s.include?('neither a project')
end
check('positional opts hash, not kwargs — InSpec dispatches through *args') do
  GitlabSecurity.instance_method(:initialize).parameters.map(&:first).all? { |k| k == :opt }
end

puts
puts 'credentials'
check('an empty-string token counts as absent, not as a token') do
  # An unset InSpec input arrives as "" which is TRUTHY, so a plain || chain
  # short-circuits on it and never reaches the environment.
  GitlabSecurity.new('g/p', token: '   ').token_present? == false
end
check('no token names the consequence, not just the absence') do
  GitlabSecurity.new('g/p', token: '').enumeration_trust.include?('silently short')
end

puts
puts 'layer 1 — the project'
project_only = StubbedGitlab.new(
  'group/project',
  routes: {
    'approval_rules' => [{ 'name' => 'Security', 'approvals_required' => 1 }],
    '/approvals' => { 'approvals_before_merge' => 0, 'merge_requests_author_approval' => false },
    'protected_branches' => [{ 'name' => 'main', 'code_owner_approval_required' => true }],
    'push_rule' => { 'reject_unsigned_commits' => true }
  },
  graphql: graphql_reply(nil)
)
check('project approval rules resolve') { project_only.effective_required_approvals == 1 }
check('signed commits read from push rules') { project_only.signed_commits_required? }
check('code-owner approval read from the protected branch') do
  project_only.code_owner_approval_required?('main')
end
check('author self-approval defaults to ALLOWED when unstated') do
  # Defaulting the other way would report a stricter posture than was verified.
  StubbedGitlab.new('g/p', routes: { '/approvals' => {} }, graphql: graphql_reply(nil))
               .author_may_self_approve?
end

puts
puts 'wildcards'
wild = StubbedGitlab.new(
  'group/project',
  routes: { 'protected_branches' => [{ 'name' => 'release/*' }],
            '=/projects/group%2Fproject' => { 'default_branch' => 'main' } },
  graphql: graphql_reply(nil)
)
check('a wildcard protected branch covers a matching branch') do
  # An equality test would call release/1.2 unprotected while a rule covers it.
  wild.branch_protected?('release/1.2')
end
check('...and does not cover a non-matching one') { wild.branch_protected?('develop') == false }

puts
puts 'layer 2 — the group (invisible in project config)'
group_governed = StubbedGitlab.new(
  'group/project',
  routes: {
    '/groups/group/protected_branches' => [{ 'name' => 'main',
                                             'code_owner_approval_required' => true }],
    'approval_rules' => [],
    '/approvals' => {},
    'protected_branches' => []
  },
  graphql: graphql_reply(nil)
)
check('a project protected ONLY from the group reads as protected') do
  # GitLab does not fold group rules into the project response, unlike GitHub
  # with parent rulesets. Reading the project alone reports it unprotected.
  group_governed.branch_protected?('main')
end
check('group protection is attributed to the group, not the project') do
  group_governed.governance_sources('main').any? { |s| s.start_with?('group protected branch') }
end
check('code-owner requirement inherited from the group is seen') do
  group_governed.code_owner_approval_required?('main')
end

puts
puts 'layer 3 — the security policy project'
policy_governed = StubbedGitlab.new(
  'group/project',
  routes: {
    'approval_rules' => [],
    '/approvals' => {},
    'protected_branches' => [],
    'policy.yml' => POLICY_YAML,
    '=/projects/policy%2Fproject' => { 'default_branch' => 'main' }
  },
  graphql: graphql_reply('policy/project')
)
check('a project governed ONLY by a policy project is governed, not unprotected') do
  # The rules for project A live in project B. Reading A tells you nothing.
  policy_governed.effective_required_approvals == 2
end
check('the policy project is named as the source') do
  policy_governed.governance_sources.any? { |s| s.include?("policy project 'policy/project'") }
end
check('state is :applies') { policy_governed.policy_project_state == :applies }

puts
puts 'the four policy-project outcomes stay distinct'
none = StubbedGitlab.new('group/project', routes: {}, graphql: graphql_reply(nil))
check('no policy project linked -> :none') { none.policy_project_state == :none }

unreadable = StubbedGitlab.new(
  'group/project',
  routes: { 'projects/' => 403 },   # linked, and we cannot read it
  graphql: graphql_reply('policy/project')
)
check('linked but unreadable -> :unreadable, NOT absence') do
  # This is the assertion the whole four-state design exists for. A project
  # with no rules and a project we cannot see are different findings, and only
  # the first is about the project.
  unreadable.policy_project_state == :unreadable
end
check('unreadable says it is about OUR access, not their governance') do
  unreadable.policy_project_detail.include?('only about our access')
end

out_of_scope = StubbedGitlab.new(
  'group/project',
  routes: {
    'policy.yml' => <<~YAML,
      approval_policy:
        - name: Applies elsewhere
          enabled: true
          policy_scope:
            projects:
              including:
                - full_path: other/project
          actions:
            - type: require_approval
              approvals_required: 5
    YAML
    '=/projects/policy%2Fproject' => { 'default_branch' => 'main' }
  },
  graphql: graphql_reply('policy/project')
)
check('readable but scoped elsewhere -> :out_of_scope') do
  out_of_scope.policy_project_state == :out_of_scope
end
check('a policy scoped elsewhere contributes no approvals') do
  # Counting it would claim protection this project does not have.
  out_of_scope.effective_required_approvals.zero?
end

puts
puts 'policy scoping'
def scoped(yaml)
  StubbedGitlab.new('group/project',
                    routes: { 'policy.yml' => yaml,
                              '=/projects/policy%2Fproject' => { 'default_branch' => 'main' } },
                    graphql: graphql_reply('policy/project'))
end
check('a policy with NO scope block applies here') do
  # An absent scope means "the whole linked group", not "nowhere". Getting this
  # backwards would silently drop the most common configuration.
  scoped(POLICY_YAML).scoped_policies.length == 1
end
check('an explicit exclusion wins over an inclusion') do
  scoped(<<~YAML).scoped_policies.empty?
    approval_policy:
      - name: Excluded here
        enabled: true
        policy_scope:
          projects:
            including: [{ full_path: group/project }]
            excluding: [{ full_path: group/project }]
        actions: [{ type: require_approval, approvals_required: 3 }]
  YAML
end
check('a disabled policy is not counted') do
  scoped(<<~YAML).scoped_policies.empty?
    approval_policy:
      - name: Off
        enabled: false
        actions: [{ type: require_approval, approvals_required: 9 }]
  YAML
end

puts
puts 'most restrictive wins across layers'
combined = StubbedGitlab.new(
  'group/project',
  routes: {
    'approval_rules' => [{ 'name' => 'Local', 'approvals_required' => 1 }],
    '/approvals' => { 'approvals_before_merge' => 0 },
    'protected_branches' => [{ 'name' => 'main' }],
    'policy.yml' => POLICY_YAML,
    '=/projects/policy%2Fproject' => { 'default_branch' => 'main' }
  },
  graphql: graphql_reply('policy/project')
)
check('the policy project raises the effective requirement above the project rule') do
  combined.effective_required_approvals == 2
end
check('both layers are named, not merged into one number') do
  src = combined.governance_sources('main')
  src.any? { |s| s.include?('project approval rules') } &&
    src.any? { |s| s.include?('policy project') }
end
check('no governance at all reports none, not an empty list') do
  StubbedGitlab.new('g/p', routes: {}, graphql: graphql_reply(nil)).governance_sources == ['none']
end

puts
puts 'path encoding'
enc = StubbedGitlab.new('group/sub/project', routes: {}, graphql: graphql_reply(nil))
enc.approval_rules
check('nested project paths are URL-encoded, not split into path segments') do
  enc.requested.first.include?('group%2Fsub%2Fproject')
end

puts
puts 'CODEOWNERS'
gitlab_placed = StubbedGitlab.new(
  'group/project',
  routes: { '.gitlab%2FCODEOWNERS' => "docs/ @team\n",
            '=/projects/group%2Fproject' => { 'default_branch' => 'main' } },
  graphql: graphql_reply(nil)
)
check('CODEOWNERS is found at .gitlab/, not only at the root') do
  # Reading only the root — the obvious implementation — would report a project
  # using the conventional location as having no owners at all.
  gitlab_placed.codeowners?
end
check('owner paths are parsed from it') { gitlab_placed.codeowners_paths == ['docs/'] }

puts
puts 'transport failure is captured, never raised'
class ExplodingGitlab < GitlabSecurity
  private

  def get(_path, raw: false)
    raise Errno::ECONNREFUSED, 'stubbed'
  rescue StandardError => e
    @connection_error = "GET failed: #{e.class}"
    { code: 0, body: nil, raw: nil, message: @connection_error, next_page: nil }
  end
end
boom = ExplodingGitlab.new('g/p', {})
check('an unreachable API returns empty and records why') do
  boom.approval_rules.empty? && boom.connection_error.to_s.include?('GET failed')
end

puts
puts 'interface parity with github_security'
%i[effective_required_reviews code_owner_review_required? signed_commits_required?
   governance_sources repo_names connection_error].each do |m|
  check("responds to #{m}") { GitlabSecurity.new('g/p', {}).respond_to?(m) }
end

puts
puts 'forge dispatch'
DECLARATION = {
  'organization' => { 'forge' => 'github', 'name' => 'risk-sentinel' },
  'defaults'     => { 'forge' => 'gitlab' },
  'targets'      => [
    { 'repo' => 'explicit', 'forge' => 'github' },
    { 'repo' => 'inherits-defaults' }
  ]
}.freeze

check('a target forge beats defaults') do
  ForgeSecurity.for_target(DECLARATION, 'explicit') == 'github'
end
check('defaults beat the organisation block') do
  ForgeSecurity.for_target(DECLARATION, 'inherits-defaults') == 'gitlab'
end
check('an undeclared target still resolves through defaults') do
  ForgeSecurity.for_target(DECLARATION, 'never-heard-of-it') == 'gitlab'
end
check('an unknown forge RAISES rather than defaulting to github') do
  # A silent default would mean `Github` or `gitlabs` produces GitHub results
  # for a GitLab project — the hardest failure here to notice, because
  # everything downstream looks normal.
  begin
    ForgeSecurity.for_target({ 'organization' => { 'forge' => 'gitlabs' } }, 'x')
    false
  rescue Inspec::Exceptions::ResourceFailed => e
    e.message.include?('gitlabs')
  end
end
check('a declaration naming no forge anywhere raises') do
  begin
    ForgeSecurity.for_target({ 'targets' => [{ 'repo' => 'x' }] }, 'x')
    false
  rescue Inspec::Exceptions::ResourceFailed => e
    e.message.include?('no forge declared')
  end
end
check('case and stray whitespace normalise rather than raising') do
  ForgeSecurity.for_target({ 'organization' => { 'forge' => ' GitHub ' } }, 'x') == 'github'
end

check('handle returns the GitHub resource for a github target') do
  ForgeSecurity.handle('o/r', forge: 'github', org: 'o',
                       creds: { 'github' => { token: 't' } }).is_a?(GithubSecurity)
end
check('handle returns the GitLab resource for a gitlab target') do
  ForgeSecurity.handle('g/p', forge: 'gitlab', org: 'g',
                       creds: { 'gitlab' => { token: 't' } }).is_a?(GitlabSecurity)
end

check('GitLab claims required_reviews') { ForgeSecurity.supported?('gitlab', 'required_reviews') }
check('GitLab does NOT claim required_checks') do
  # GitLab can gate on a pipeline, and gitlab_security reads that — but the
  # control asserts a DECLARED SECURITY TOOL is among the required contexts,
  # and GitLab exposes no context names. Passing on the weaker fact would be an
  # overclaim wearing a stronger control's id.
  ForgeSecurity.supported?('gitlab', 'required_checks') == false
end
check('GitLab does NOT claim the dashboard bridge') do
  ForgeSecurity.supported?('gitlab', 'dashboard') == false
end
check('an unsupported pairing explains itself, naming forge and capability') do
  msg = ForgeSecurity.unsupported_reason('gitlab', 'dashboard')
  msg.include?('gitlab') && msg.include?('dashboard') &&
    msg.include?('not as a finding about the project')
end
check('every capability GitLab claims is also claimed by GitHub') do
  # A capability GitLab has and GitHub does not would mean the estate's own
  # 21 repositories are assessed on a narrower interface than an outside
  # adopter's — a gap nobody here would ever see.
  (ForgeSecurity::IMPLEMENTED['gitlab'] - ForgeSecurity::IMPLEMENTED['github']).empty?
end

puts
if FAILURES.empty?
  puts 'PASS — all gitlab_security and forge-dispatch assertions held'
  exit 0
else
  puts "FAIL — #{FAILURES.size} assertion(s): #{FAILURES.join(', ')}"
  exit 1
end
