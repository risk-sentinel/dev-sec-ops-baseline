# encoding: utf-8
# =============================================================================
# Inventory reconciliation + forge-native capability enablement.
#
# CONTRACT:
#   - Reconciliation proves the declaration is complete, using a source outside
#     the declaration. A file cannot be the evidence that it is complete.
#   - Native enablement is asserted ONLY for tools that cannot be seen any
#     other way. See ::CapabilityMatrix.native_capabilities_required.
# =============================================================================

require 'yaml'

# Read the registry from the profile's files/ directory. Deliberately File.read
# rather than inspec.profile.file: this runs at PARSE time (control IDs must be
# static, so the scan-type loop cannot wait for a backend), and inspec.profile
# is not reliably available then.
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

gh_token = input('github_token')
gh_api   = input('github_api_base')
gl_token = input('gitlab_token')
gl_api   = input('gitlab_api_base')
org_name = input('organization').to_h['name']

# Both forges' credentials; ForgeSecurity picks by declaration. `forge:` has
# been declared on every target since the schema was written and was read by
# nothing — a GitLab target was probed against api.github.com and reported as
# entirely unprotected.
forge_creds = {
  'github' => { token: gh_token, api_base: gh_api },
  'gitlab' => { token: gl_token, api_base: gl_api }
}

# =============================================================================
# The denominator.
#
# Enumerates the organisation through the forge API and compares it with the
# declaration. Everything else in this profile is a statement about the
# repositories someone remembered to list; this control is what makes that list
# trustworthy.
# =============================================================================
control 'devsecops-inventory-reconciliation' do
  impact 1.0
  title 'Declared repositories reconcile with the organisation (CM-8)'
  desc <<~DESC
    The repository list is verified against an independent enumeration of the
    organisation, not against itself. Undeclared repositories, stale
    declarations, and exclusions without a written reason all fail.

    Archived, fork and template repositories are NOT auto-excluded. Churn in
    the declaration when a repository is archived is the intended cost of never
    silently shrinking the denominator.
  DESC
  tag nist: ['CM-8', 'CM-8(1)', 'PM-5', 'CA-7']
  tag nist_r4: ['CA-7', 'CM-8', 'CM-8(1)', 'PM-5']
  tag cci:  ['CCI-000274', 'CCI-000398', 'CCI-000408', 'CCI-004328']
  tag ksi: ['KSI-CMT-RMV', 'KSI-MLA-EVC', 'KSI-PIY-GIV']
  tag ksi_unmapped: ['pm-5']
  tag layer: 'inventory'
  only_if('Organisation enumeration needs control-plane access') do
    %w[control-plane both].include?(run_mode) && !org_name.to_s.empty?
  end

  # Resolved without raising. `organisation_forge` raises by design, and a raise
  # in a control BODY aborts the whole control — an undeclared forge would take
  # the entire reconciliation down rather than reporting itself. The problem
  # becomes a failing example below instead.
  org_forge = ::ForgeSecurity.declared_forge(declaration)

  if org_forge.nil?
    describe 'organisation forge' do
      subject do
        raise ::Inspec::Exceptions::ResourceFailed,
              "organisation '#{org_name}' declares no usable `forge:`. " \
              'Reconciliation cannot enumerate a platform it was not told ' \
              'about, and guessing would compare this declaration against the ' \
              'wrong estate.'
      end
      it { should be_nil }
    end
    next
  end

  gs     = ::ForgeSecurity.org_handle(org_name, forge: org_forge, creds: forge_creds)
  actual = gs.repo_names
  rec    = ::CapabilityMatrix.reconcile(declaration, actual)

  # Assert reachability FIRST. An enumeration that failed returns an empty
  # list, and an empty list makes every other assertion below pass vacuously.
  describe 'organisation enumeration' do
    subject { gs.connection_error }
    it { should be_nil }
  end

  # Then assert it was AUTHENTICATED, which reachability does not imply. The
  # org endpoint answers 200 for an anonymous caller and simply omits every
  # private repository, so an unauthenticated sweep returns a short list with
  # nothing marking it as short. Reconciliation then compares that truncated
  # reality against a complete declaration and reports the invisible
  # repositories as STALE — accusing the declaration of being wrong when the
  # credential was the problem.
  #
  # Asserted before the stale check, and the stale check is gated on it, so the
  # run reports the real fault instead of a plausible one derived from it.
  describe 'organisation enumeration is authenticated' do
    subject { gs.enumeration_trust }
    it { should match(/\Aauthenticated as /) }
  end

  describe "repositories found in the organisation (#{rec[:counts][:actual]})" do
    subject { rec[:counts][:actual] }
    it { should be > 0 }
  end

  describe 'repositories in the organisation but neither declared nor excluded' do
    subject { rec[:undeclared] }
    it { should be_empty }
  end

  # Gated on authentication. Unauthenticated, this assertion does not mean what
  # it says: every private repository is missing from `actual`, so each one
  # reads as a declaration for something that no longer exists. Reporting the
  # credential fault once beats reporting five fabricated stale declarations
  # that each look worth investigating.
  describe 'declared repositories that no longer exist in the organisation' do
    subject do
      next rec[:stale] if gs.authenticated?
      ["not assessed — #{gs.enumeration_trust}"]
    end
    it { should be_empty }
  end

  describe 'exclusions with no written reason' do
    subject { rec[:undocumented_exclusions] }
    it { should be_empty }
  end
end

# =============================================================================
# Forge-native capability enablement.
#
# Asserted ONLY where a declared tool cannot be seen any other way. If nobody
# declared the forge's native scanning, that feature being switched off is not
# a finding — it is simply not the tool this repository uses. Asserting it
# unconditionally would light up every private repository for failing to buy a
# product it does not need.
# =============================================================================
control 'devsecops-native-capability-enablement' do
  impact 1.0
  title 'Forge-native scanning is enabled where it is the only evidence (RA-5, SI-5)'
  desc <<~DESC
    Some tools leave nothing on a runner — platform secret scanning, Dependabot,
    GitLab Dependency Scanning. For those, the platform API is the only proof
    they ran, so the capability must be enabled.

    A disabled capability is reported as a FAIL carrying the API's own message,
    never as an empty finding list. The platform does not answer "disabled": it
    returns 403 or 404, and a client that reads those as "no alerts" reports a
    repository nobody scans as clean.
  DESC
  tag nist: ['RA-5', 'SI-5', 'SA-11']
  tag nist_r4: ['RA-5', 'SA-11', 'SI-5']
  tag cci:  ['CCI-001054', 'CCI-001285', 'CCI-003171']
  tag ksi: ['KSI-SCR-MIT', 'KSI-SCR-MON', 'KSI-SVC-ACM']
  tag layer: 'platform-enablement'
  only_if('Native capability checks need control-plane access') do
    %w[control-plane both].include?(run_mode)
  end

  required = ::CapabilityMatrix.native_capabilities_required(
    registry, declaration, run_mode: run_mode
  )

  if required.empty?
    describe 'forge-native capabilities required by the declaration' do
      it 'none — no declared tool depends on a forge-native capability' do
        skip 'No declared tool is API-only, so no forge-native capability is ' \
             'required. Unlicensed platform features are correctly not reported ' \
             'as findings.'
      end
    end
  else
    required.each do |repo, caps|
      forge = ::ForgeSecurity.for_target(declaration, repo)
      caps.each do |cap|
        # Forge-native capability state is read on GitHub only. GitHub exposes a
        # separate endpoint per capability with its own enablement state and its
        # own failure code; GitLab funnels the equivalents through one
        # vulnerability-findings endpoint with a different shape. Running the
        # GitHub reader against a GitLab project would 404 and report every
        # capability disabled — a confident false finding.
        unless ::ForgeSecurity.supported?(forge, 'capabilities')
          describe "#{repo} — #{cap[:capability]} (required by #{cap[:tool]})" do
            it('is not readable on this forge') do
              skip ::ForgeSecurity.unsupported_reason(forge, 'capabilities')
            end
          end
          next
        end

        gs = ::ForgeSecurity.handle("#{org_name}/#{repo}", forge: forge,
                                    org: org_name, creds: forge_creds)
        status = gs.capability_status(cap[:capability])
        describe "#{repo} — #{cap[:capability]} (required by #{cap[:tool]}: #{cap[:reason]})" do
          subject { "#{status}#{status == :enabled ? '' : " — #{gs.capability_reason(cap[:capability])}"}" }
          it { should cmp 'enabled' }
        end
      end
    end
  end
end
