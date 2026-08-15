# encoding: utf-8
# =============================================================================
# Scan-type coverage.  GENERATED FILE — DO NOT EDIT.
#
#   Source:    files/tool_registry.yml
#   Generator: tools/render_controls.py
#   Regenerate after any registry change; `--check` fails on drift.
#
# Generated rather than looped because InSpec reads `tag` values from the AST at
# parse time and crashes on a method call ("undefined method 'value' for an
# instance of RuboCop::AST::SendNode"), taking `check` down with it. Tags must be
# literals, so they are written out here instead of derived at runtime.
#
# One control per scan type, one describe per repository. Control IDs are STATIC
# — derived from the registry, which is version-controlled profile data, never
# from the user's declaration. IDs generated from an input would churn whenever
# the repository list changed, breaking SAR continuity across runs.
#
# ---- The four outcomes, and why they are four -------------------------------
#
#   covered       a declared tool is verifiable on a surface this mode reaches
#   attest        not enabled -> skip, satisfiable by an attestation.
#                 A statement about the REPOSITORY.
#   unverifiable  enabled and detectable, but not on a surface this run mode can
#                 reach -> skip naming the mode that could. A statement about
#                 THIS RUN. Failing it would report red against a repository
#                 doing everything right.
#   gap           we never built the detection -> skip. A statement about the
#                 PROFILE; an attestation must not paper over it.
#
# There is deliberately no "not declared" outcome. Omission would render as Not
# Applicable, which reads as "does not apply" rather than "nobody looked".
# =============================================================================

# ---- Per-file setup ---------------------------------------------------------
# LOCALS, not constants, and repeated in every control file on purpose.
#
# InSpec evaluates each control FILE in its own anonymous eval context, so a
# constant defined in one file is invisible in another:
#
#   uninitialized constant #<Class:#<Inspec::ControlEvalContext>>::REGISTRY
#
# Locals defined above a `control` block are captured by the block's closure and
# work reliably. Sharing across files is what does not work, so each file builds
# its own.
registry    = ::CapabilityMatrix.load(inspec.profile.file('tool_registry.yml'))
declaration = {
  'organization' => input('organization'),
  'targets'      => input('targets'),
  'exclusions'   => input('exclusions'),
  'defaults'     => input('defaults')
}
run_mode = input('run_mode')

# ---- Credentials ------------------------------------------------------------
# Resources cannot call input(), so the control body reads these and passes them
# down through the opts hash. Each also falls back to a conventional environment
# variable inside its resource, so an organisation-level CI secret works with no
# input plumbing at all:
#
#   github_token -> GITHUB_TOKEN / GH_TOKEN
#   sonar_token  -> SONAR_TOKEN / SONARQUBE_TOKEN
gh_token = input('github_token')
gh_api   = input('github_api_base')
org_name = input('organization').to_h['name']

# ---- Live verification ------------------------------------------------------
# coverage() resolves declaration x registry: it says a tool SHOULD be visible
# on a surface. It does not look. Asserting on it alone passes a repository that
# declares SonarQube but has no project, without a single API call — a control
# that reports clean without assessing anything.
#
# So every covered cell is verified against the real source here. Failure to
# reach a source is a FAIL, never an empty pass.
targets_by_repo = Array(input('targets')).each_with_object({}) { |t, h| h[t['repo']] = t }
artifact_dir    = input('artifact_dir')
freshness_days  = input('evidence_freshness_days')


SCOPE_RUN         = 'run-scoped'.freeze
SCOPE_POINT       = 'point-in-time'.freeze
DESC_ATTEST       = 'is not enabled and requires attestation'.freeze
DESC_UNVERIFIABLE = 'is enabled but not reachable from this run mode'.freeze
DESC_GAP          = 'is not yet detectable by this profile'.freeze

verify = lambda do |repo, tool, surface|
  target = targets_by_repo[repo] || {}
  case surface
  when 'artifact'
    pats = registry.surfaces_for(tool).dig('artifact', 'patterns')
    r = ::ArtifactHelper.resolve(artifact_dir, pats)
    next "no artifact matching #{Array(pats).join(', ')} in #{artifact_dir}" unless r[:found]
    'verified'
  when 'platform_api'
    api = registry.surfaces_for(tool)['platform_api']
    cap = api && api['capability']
    if cap == 'issues'
      key = target.dig('evidence_sources', 'sonarqube', 'project_key')
      next 'no sonarqube project_key declared for this repository' if key.to_s.empty?
      sq = sonarqube_project(key, token: input('sonar_token'))
      # readable?, not exists?: readable? populates connection_error with the
      # reason. exists? alone returns a bare false and leaves the message nil,
      # so the failure reads "sonarqube:" with nothing after it.
      next "sonarqube: #{sq.connection_error || 'project not readable'}" unless sq.readable?
      age = sq.analysis_age_days
      # A project that exists but has NEVER been analysed is a different finding
      # from one whose analysis went stale, and "nil days old" tells nobody
      # which they are looking at.
      next 'sonarqube project exists but has never been analysed' if age.nil?
      next "sonarqube analysis is #{age} days old (limit #{freshness_days})" if age > freshness_days
      'verified'
    else
      gs = ::GithubSecurityHandle.call(repo, org_name, gh_token, gh_api)
      st = gs.capability_status(cap)
      next "#{cap}: #{st} — #{gs.capability_reason(cap)}" unless st == :enabled
      'verified'
    end
  else
    "unsupported surface #{surface}"
  end
end
# ---- Shared coverage body ---------------------------------------------------
# Emitted ONCE and invoked from each control with instance_exec, which rebinds
# self to the Inspec::Rule so `describe` registers against the calling control.
#
# The alternative — generating ten copies of this block — duplicated ~40% of the
# file. Generated duplication is still duplication: it makes every future change
# ten edits and buries the one line that differs between controls.
coverage_body = lambda do |scan_type|
  results = ::CapabilityMatrix.coverage(registry, declaration, run_mode: run_mode)
                              .select { |c| c.scan_type == scan_type }

  if results.empty?
    describe "#{scan_type} coverage" do
      it 'has no declared targets' do
        skip 'No repository declares this scan type. Every scan type must be '              'declared enabled true or false — omission would render as Not '              'Applicable, which reads as "does not apply" rather than "nobody looked".'
      end
    end
  end

  results.each do |c|
    case c.status
    when :covered
      # Verify each satisfying (tool, surface) against the real source. Passing
      # on the registry alone would report a repository as covered without a
      # single API call or file read.
      c.covered_by.each do |hit|
        scope   = hit[:scope] == :run_scoped ? SCOPE_RUN : SCOPE_POINT
        outcome = verify.call(c.repo, hit[:tool], hit[:surface])
        describe "#{c.repo} — #{scan_type} via #{hit[:tool]} (#{hit[:surface]}, #{scope})" do
          subject { outcome }
          it { should cmp 'verified' }
        end
      end
    when :attest
      describe "#{c.repo} — #{scan_type}" do
        it(DESC_ATTEST) { skip ::CapabilityMatrix::ATTEST_RATIONALE }
      end
    when :unverifiable
      describe "#{c.repo} — #{scan_type}" do
        it(DESC_UNVERIFIABLE) { skip "#{::CapabilityMatrix::UNVERIFIABLE_RATIONALE}: #{c.detail}" }
      end
    when :gap
      describe "#{c.repo} — #{scan_type}" do
        it(DESC_GAP) { skip "#{::CapabilityMatrix::GAP_RATIONALE}: #{c.detail}" }
      end
    else
      # An unrecognised status must never vanish. Silently emitting no describe
      # would make the control assess nothing while reporting not-red.
      describe "#{c.repo} — #{scan_type}" do
        subject { "unrecognised coverage status #{c.status.inspect}" }
        it { should cmp 'unreachable' }
      end
    end
  end
end

control 'devsecops-coverage-sast' do
  impact 0.7
  title 'Static Application Security Testing coverage'
  desc <<~DESC
    Analyses source without executing it.

    Satisfied by any declared tool on any execution surface this run mode can
    reach, then VERIFIED against that source. Configuration evidence does not
    count: a workflow file naming a scanner proves somebody wired it up, not
    that it ran.
  DESC
  tag nist: ['SA-11(1)']
  tag ssdf: ['PW.7', 'PW.8']
  tag sdlc_stage: 'code'
  tag scan_type: 'sast'
  tag layer: 'coverage'

  instance_exec('sast', &coverage_body)
end

control 'devsecops-coverage-secrets' do
  impact 0.7
  title 'Secrets Detection coverage'
  desc <<~DESC
    Finds embedded static authenticators in source and git history.

    Satisfied by any declared tool on any execution surface this run mode can
    reach, then VERIFIED against that source. Configuration evidence does not
    count: a workflow file naming a scanner proves somebody wired it up, not
    that it ran.
  DESC
  tag nist: ['IA-5(7)', 'SA-11']
  tag ssdf: ['PW.1']
  tag sdlc_stage: 'code'
  tag scan_type: 'secrets'
  tag layer: 'coverage'

  instance_exec('secrets', &coverage_body)
end

control 'devsecops-coverage-iac' do
  impact 0.7
  title 'Infrastructure as Code Scanning coverage'
  desc <<~DESC
    Misconfiguration analysis of declarative infrastructure.

    Satisfied by any declared tool on any execution surface this run mode can
    reach, then VERIFIED against that source. Configuration evidence does not
    count: a workflow file naming a scanner proves somebody wired it up, not
    that it ran.
  DESC
  tag nist: ['CM-2', 'CM-6', 'RA-5']
  tag ssdf: ['PW.9']
  tag sdlc_stage: 'code'
  tag scan_type: 'iac'
  tag layer: 'coverage'

  instance_exec('iac', &coverage_body)
end

control 'devsecops-coverage-sca' do
  impact 0.7
  title 'Software Composition Analysis coverage'
  desc <<~DESC
    Known-vulnerable third-party components. GitLab calls this "Dependency Scanning"; `sca` is canonical here and `dependency` resolves to it.

    Satisfied by any declared tool on any execution surface this run mode can
    reach, then VERIFIED against that source. Configuration evidence does not
    count: a workflow file naming a scanner proves somebody wired it up, not
    that it ran.
  DESC
  tag nist: ['RA-5', 'SA-11(1)', 'SR-3']
  tag ssdf: ['RV.1', 'PW.4']
  tag sdlc_stage: 'build'
  tag scan_type: 'sca'
  tag layer: 'coverage'

  instance_exec('sca', &coverage_body)
end

control 'devsecops-coverage-sbom' do
  impact 0.7
  title 'Software Bill of Materials coverage'
  desc <<~DESC
    Component inventory and provenance record.

    Satisfied by any declared tool on any execution surface this run mode can
    reach, then VERIFIED against that source. Configuration evidence does not
    count: a workflow file naming a scanner proves somebody wired it up, not
    that it ran.
  DESC
  tag nist: ['SR-3', 'SR-4']
  tag ssdf: ['PS.3', 'PW.4']
  tag sdlc_stage: 'build'
  tag scan_type: 'sbom'
  tag layer: 'coverage'

  instance_exec('sbom', &coverage_body)
end

control 'devsecops-coverage-container' do
  impact 0.7
  title 'Container Image Scanning coverage'
  desc <<~DESC
    Vulnerability and misconfiguration analysis of a built image. Frequently the same binary as `sca` pointed at a different target — the target is what separates the two axes, not the tool.

    Satisfied by any declared tool on any execution surface this run mode can
    reach, then VERIFIED against that source. Configuration evidence does not
    count: a workflow file naming a scanner proves somebody wired it up, not
    that it ran.
  DESC
  tag nist: ['RA-5', 'CM-6', 'SR-3']
  tag ssdf: ['RV.1']
  tag sdlc_stage: 'build'
  tag scan_type: 'container'
  tag layer: 'coverage'

  instance_exec('container', &coverage_body)
end

control 'devsecops-coverage-licensing' do
  impact 0.7
  title 'Software Licensing Review coverage'
  desc <<~DESC
    OSS licence governance over acquired and reused components.

    Satisfied by any declared tool on any execution surface this run mode can
    reach, then VERIFIED against that source. Configuration evidence does not
    count: a workflow file naming a scanner proves somebody wired it up, not
    that it ran.
  DESC
  tag nist: ['SR-3', 'SA-4']
  tag ssdf: ['PW.4']
  tag sdlc_stage: 'build'
  tag scan_type: 'licensing'
  tag layer: 'coverage'

  instance_exec('licensing', &coverage_body)
end

control 'devsecops-coverage-dast' do
  impact 0.7
  title 'Dynamic Application Security Testing coverage'
  desc <<~DESC
    Exercises a running application from the outside.

    Satisfied by any declared tool on any execution surface this run mode can
    reach, then VERIFIED against that source. Configuration evidence does not
    count: a workflow file naming a scanner proves somebody wired it up, not
    that it ran.
  DESC
  tag nist: ['SA-11(8)', 'RA-5', 'CA-8']
  tag ssdf: ['PW.8', 'RV.1']
  tag sdlc_stage: 'test'
  tag scan_type: 'dast'
  tag layer: 'coverage'

  instance_exec('dast', &coverage_body)
end

control 'devsecops-coverage-runtime' do
  impact 0.7
  title 'Post-Deployment Validation coverage'
  desc <<~DESC
    Assessment of what is actually deployed, not what was built. The SDLC does not end at deploy: configuration drifts, and a pipeline that was clean at build time says nothing about the running estate. This is where our own InSpec baselines, AWS Config rules and Security Hub findings land. The existing `artifact-inspec-deployed` control belongs to this scan type.

    Satisfied by any declared tool on any execution surface this run mode can
    reach, then VERIFIED against that source. Configuration evidence does not
    count: a workflow file naming a scanner proves somebody wired it up, not
    that it ran.
  DESC
  tag nist: ['CA-2(2)', 'CA-7', 'CM-6', 'RA-5']
  tag ssdf: ['RV.1', 'PW.9']
  tag sdlc_stage: 'operate'
  tag scan_type: 'runtime'
  tag layer: 'coverage'

  instance_exec('runtime', &coverage_body)
end

control 'devsecops-coverage-iast' do
  impact 0.3
  title 'Interactive Application Security Testing coverage'
  desc <<~DESC
    Instrumented analysis of a running application. NIST 800-53r5 names this exactly at SA-11(9). No tooling anywhere in the organisation today — this entry exists so the gap is declared rather than silently absent.

    Satisfied by any declared tool on any execution surface this run mode can
    reach, then VERIFIED against that source. Configuration evidence does not
    count: a workflow file naming a scanner proves somebody wired it up, not
    that it ran.
  DESC
  tag nist: ['SA-11(9)']
  tag ssdf: ['PW.8']
  tag sdlc_stage: 'test'
  tag scan_type: 'iast'
  tag layer: 'coverage'

  instance_exec('iast', &coverage_body)
end
