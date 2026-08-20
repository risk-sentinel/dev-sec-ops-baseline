# encoding: utf-8
# =============================================================================
# Governance controls — delivery gating on the control plane (#16).
#
# Hand-written rather than generated: these are not per-scan-type, so there is
# no registry loop to derive them from and their tags are already literals.
#
# ---- Effective governance, not one mechanism --------------------------------
#
# GitHub evaluates classic branch protection AND rulesets together, most
# restrictive wins. Reading one is how you produce a confident false finding:
# five of seven repositories here have no classic protection at all, and the two
# that do report ZERO required reviews while their rulesets require one. A
# classic-only reading calls the whole estate unprotected. Every assertion below
# goes through the effective_* methods, which combine both.
#
# Org-level rulesets are included automatically — the repo endpoint returns
# parent rulesets by default — and are reported distinctly, because a rule the
# repository owner cannot weaken is a stronger guarantee than the same rule set
# locally.
#
# ---- Exemptions are declared, never inferred --------------------------------
#
# Some repositories will legitimately not meet a baseline. Per the rule already
# established for scan types and repository exclusions, an exemption is written
# down with a reason and produces a skip carrying that reason. There is no
# inferred exception and no silent pass.
# =============================================================================

registry    = ::CapabilityMatrix.load(inspec.profile.file('tool_registry.yml'))
declaration = {
  'organization' => input('organization'),
  'targets'      => input('targets'),
  'exclusions'   => input('exclusions'),
  'defaults'     => input('defaults')
}
run_mode  = input('run_mode')
gh_token  = input('github_token')
gh_api    = input('github_api_base')
gl_token  = input('gitlab_token')
gl_api    = input('gitlab_api_base')
org_name  = input('organization').to_h['name']
branch    = input('protected_branch')

min_reviews   = input('min_required_reviews')
want_signing  = input('require_signed_commits')
exemptions    = Array(input('governance_exemptions'))

targets = Array(input('targets')).map { |t| t['repo'] }.compact

# A tool's identity and the string CI reports it under are frequently different
# — SonarQube reports as "SonarCloud Code Analysis" — so the registry's aliases
# come along for matching.
alias_map = registry.tools.each_with_object({}) { |(k, v), h| h[k] = Array(v['aliases']) }

# Both sets of credentials go down; the dispatcher picks. A control does not
# have to know which forge it is about to be handed.
forge_creds = {
  'github' => { token: gh_token, api_base: gh_api },
  'gitlab' => { token: gl_token, api_base: gl_api }
}

gh = lambda do |repo|
  ::ForgeSecurity.handle(repo,
                         forge: ::ForgeSecurity.for_target(declaration, repo),
                         org: org_name, creds: forge_creds)
end

# Returns the reason string when exempt, nil otherwise.
exempt = lambda do |repo, control|
  e = exemptions.find { |x| x['repo'] == repo && x['control'] == control }
  e && e['reason'].to_s
end

# Declared, enabled tools for a repository — the set the shift-left and
# required-checks controls judge against. Judging against every tool in the
# registry would fail repositories for not running scanners they never claimed.
declared_tools = lambda do |repo|
  target = Array(input('targets')).find { |t| t['repo'] == repo } || {}
  ::CapabilityMatrix.effective_scans(declaration, target)
                    .values.compact.select { |v| v['enabled'] }
                    .flat_map { |v| ::CapabilityMatrix.normalize_tools(v['tools']) }
                    .map { |t| t[:name] }.uniq
end

GOV_MODES       = %w[control-plane both].freeze
GOV_ONLY_IF     = 'Governance checks need control-plane access'.freeze
GOV_EXEMPT_DESC = 'is exempt'.freeze
GOV_OK          = 'ok'.freeze

# Shared per-repository body, emitted once and invoked with instance_exec so
# `describe` binds to the calling control. Six copies of the exemption block and
# describe shape is duplication whether or not it is short: it makes every
# future change six edits and buries the one line that differs.
#
# `capability` names the QUESTION the control asks, so a forge that cannot
# answer it produces a named skip rather than a wrong answer. Before this,
# `forge:` was declared everywhere and read nowhere: a target declaring
# `forge: gitlab` was probed against api.github.com, 404'd on every call, and
# reported as having no protection at all.
per_repo = lambda do |control_key, label, probe, capability = 'required_reviews'|
  targets.each do |repo|
    why = exempt.call(repo, control_key)
    if why
      describe "#{repo} — #{label}" do
        it(GOV_EXEMPT_DESC) { skip "Declared exemption: #{why}" }
      end
      next
    end

    # Resolved out here, but the raise is deferred into the example. A malformed
    # `forge:` raising in the control BODY would abort the whole control and
    # take every other repository's result down with it — one bad line in a
    # declaration silently costing twenty real assessments.
    forge = begin
      ::ForgeSecurity.for_target(declaration, repo)
    rescue ::Inspec::Exceptions::ResourceFailed => e
      describe "#{repo} — #{label}" do
        subject { raise ::Inspec::Exceptions::ResourceFailed, e.message }
        it { should cmp GOV_OK }
      end
      next
    end

    unless ::ForgeSecurity.supported?(forge, capability)
      describe "#{repo} — #{label}" do
        it('is not readable on this forge') do
          skip ::ForgeSecurity.unsupported_reason(forge, capability)
        end
      end
      next
    end

    describe "#{repo} — #{label}" do
      subject { probe.call(repo) }
      it { should cmp GOV_OK }
    end
  end
end

# =============================================================================
control 'devsecops-governance-required-reviews' do
  impact 1.0
  title 'Merges into the protected branch require review (CM-3)'
  desc <<~DESC
    Effective required-review count across classic branch protection and every
    active ruleset covering the branch. Reported with the mechanism that
    supplied it: the two have different owners and different blast radius, and
    a passing result that does not say which is not much use in an assessment.
  DESC
  tag nist: ['CM-3', 'SA-11(4)', 'AC-6']
  tag ksi: ['KSI-CMT-LMC', 'KSI-CMT-RMV', 'KSI-CMT-RVP', 'KSI-CMT-VTD', 'KSI-IAM-ELP', 'KSI-IAM-JIT', 'KSI-SCR-MIT']
  tag layer: 'governance'
  only_if(GOV_ONLY_IF) { GOV_MODES.include?(run_mode) }

  instance_exec('required-reviews', "required reviews on #{branch}",
                lambda { |repo|
    g = gh.call(repo)
    n = g.effective_required_reviews(branch)
    n >= min_reviews ? GOV_OK : "#{n} required, minimum #{min_reviews} (via #{g.governance_sources(branch).join(' + ')})"
  },
                'required_reviews',
                &per_repo)
end

# =============================================================================
control 'devsecops-governance-required-checks' do
  impact 1.0
  title 'A security scan is in the required status checks (CM-3, SA-10)'
  desc <<~DESC
    Not merely that SOME check is required. A repository can require status
    checks that include no security scan at all — strong on the API surface,
    hollow in practice — and a control that counts required checks without
    asking what they are would pass it.

    A required context counts when it names a tool the repository declares.
  DESC
  tag nist: ['CM-3', 'SA-10', 'SA-11']
  tag ksi: ['KSI-CMT-LMC', 'KSI-CMT-RMV', 'KSI-CMT-RVP', 'KSI-CMT-VTD', 'KSI-SCR-MIT']
  tag layer: 'governance'
  only_if(GOV_ONLY_IF) { GOV_MODES.include?(run_mode) }

  instance_exec('required-checks', 'a declared security tool is a required check',
                lambda { |repo|
    contexts = gh.call(repo).effective_required_checks(branch)
    tools = declared_tools.call(repo)
    matched = contexts.select do |ctx|
      c = ctx.to_s.downcase.tr('_ -', '')
      tools.any? { |t| ([t] + Array(alias_map[t])).any? { |n| c.include?(n.to_s.downcase.tr('_ -', '')) } }
    end
    if matched.any? then GOV_OK
    elsif contexts.empty? then 'no required status checks at all'
    else "#{contexts.size} required check(s), none naming a declared security tool: #{contexts.join(', ')}"
    end
  },
                'required_checks',
                &per_repo)
end

# =============================================================================
control 'devsecops-governance-rulesets-enforced' do
  impact 0.7
  title 'Rulesets are enforced, not evaluating (CM-2, CM-6)'
  desc <<~DESC
    A ruleset in evaluate mode reports its name and blocks nothing. Asserting on
    presence rather than enforcement is the same error as counting controls
    without checking whether any carried attribution: the shape is there and the
    effect is not.
  DESC
  tag nist: ['CM-2', 'CM-6']
  tag ksi: ['KSI-CMT-LMC', 'KSI-CMT-RMV', 'KSI-CNA-DFP', 'KSI-CNA-IBP', 'KSI-MLA-EVC', 'KSI-SVC-ACM']
  tag layer: 'governance'
  only_if(GOV_ONLY_IF) { GOV_MODES.include?(run_mode) }

  instance_exec('rulesets-enforced', 'rulesets in evaluate mode',
                lambda { |repo|
    names = gh.call(repo).evaluate_mode_ruleset_names
    names.empty? ? GOV_OK : "evaluating, not enforcing: #{names.join(', ')}"
  },
                'rulesets',
                &per_repo)
end

# =============================================================================
control 'devsecops-governance-signed-commits' do
  impact 0.5
  title 'Commit signing is required on the protected branch (SI-7, SR-4)'
  desc <<~DESC
    Off by default. Commit signing is a deliberate organisational choice rather
    than a universal baseline, and a control that fails every repository for a
    policy nobody adopted trains people to ignore the output. Enable through
    `require_signed_commits` when the estate is ready for it.
  DESC
  tag nist: ['SI-7', 'SR-4']
  tag ksi: ['KSI-SVC-VRI']
  tag ksi_unmapped: ['sr-4']
  tag layer: 'governance'
  only_if('Signed-commit enforcement is not required by policy') do
    GOV_MODES.include?(run_mode) && want_signing
  end

  instance_exec('signed-commits', "signed commits required on #{branch}",
                lambda { |repo|
    gh.call(repo).signed_commits_required?(branch) ? GOV_OK : 'not required'
  },
                'signed_commits',
                &per_repo)
end

# =============================================================================
control 'devsecops-governance-codeowners' do
  impact 0.7
  title 'CODEOWNERS exists and review by owners is required (SA-15(7))'
  desc <<~DESC
    Both halves, because either alone is hollow. A CODEOWNERS file that nothing
    enforces is documentation; a code-owner review requirement with no
    CODEOWNERS file has no owners to ask.
  DESC
  tag nist: ['SA-15(7)', 'CM-3']
  tag ksi: ['KSI-CMT-LMC', 'KSI-CMT-RMV', 'KSI-CMT-RVP', 'KSI-CMT-VTD']
  tag ksi_broader: ['KSI-SCR-MIT']
  tag layer: 'governance'
  only_if(GOV_ONLY_IF) { GOV_MODES.include?(run_mode) }

  instance_exec('codeowners', 'CODEOWNERS present and enforced',
                lambda { |repo|
    g = gh.call(repo)
    present  = g.codeowners?
    enforced = g.code_owner_review_required?(branch)
    if present && enforced then GOV_OK
    elsif !present && !enforced then 'no CODEOWNERS file, and owner review not required'
    elsif !present then 'owner review is required but there is no CODEOWNERS file'
    else "CODEOWNERS covers #{g.codeowners_paths.join(' ')} but owner review is not required"
    end
  },
                'codeowners',
                &per_repo)
end

# =============================================================================
control 'devsecops-governance-shift-left' do
  impact 0.7
  title 'Declared scanners gate pull requests, not only pushes (SA-11(1))'
  desc <<~DESC
    A scanner that runs only after merge finds problems already on the default
    branch, which is the opposite of shifting left. No security endpoint reports
    this: it is a fact about workflow triggers, readable only from repository
    contents.

    A tool counts as gating when a workflow that runs it fires on
    `pull_request`, OR when it appears as a required status check — the second
    matters because SonarCloud is triggered by its GitHub App rather than by any
    workflow, and is the stronger signal anyway: a trigger means it runs, a
    required check means it must pass.
  DESC
  tag nist: ['SA-11(1)', 'SA-15(5)']
  tag ksi: ['KSI-SCR-MIT']
  tag layer: 'governance'
  only_if(GOV_ONLY_IF) { GOV_MODES.include?(run_mode) }

  instance_exec('shift-left', 'declared scanners gate pull requests',
                lambda { |repo|
    gaps = gh.call(repo).tools_not_gating_pull_requests(declared_tools.call(repo), branch, alias_map)
    gaps.empty? ? GOV_OK : "runs only post-merge: #{gaps.join(', ')}"
  },
                'shift_left',
                &per_repo)
end
