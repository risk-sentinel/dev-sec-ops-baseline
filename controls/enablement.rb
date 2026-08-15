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
org_name = input('organization').to_h['name']

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
  tag layer: 'inventory'
  only_if('Organisation enumeration needs control-plane access') do
    %w[control-plane both].include?(run_mode) && !org_name.to_s.empty?
  end

  gs     = github_security(org: org_name, token: gh_token, api_base: gh_api)
  actual = gs.repo_names
  rec    = ::CapabilityMatrix.reconcile(declaration, actual)

  # Assert reachability FIRST. An enumeration that failed returns an empty
  # list, and an empty list makes every other assertion below pass vacuously.
  describe 'organisation enumeration' do
    subject { gs.connection_error }
    it { should be_nil }
  end

  describe "repositories found in the organisation (#{rec[:counts][:actual]})" do
    subject { rec[:counts][:actual] }
    it { should be > 0 }
  end

  describe 'repositories in the organisation but neither declared nor excluded' do
    subject { rec[:undeclared] }
    it { should be_empty }
  end

  describe 'declared repositories that no longer exist in the organisation' do
    subject { rec[:stale] }
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
      caps.each do |cap|
        gs = github_security("#{org_name}/#{repo}", token: gh_token, api_base: gh_api)
        status = gs.capability_status(cap[:capability])
        describe "#{repo} — #{cap[:capability]} (required by #{cap[:tool]}: #{cap[:reason]})" do
          subject { "#{status}#{status == :enabled ? '' : " — #{gs.capability_reason(cap[:capability])}"}" }
          it { should cmp 'enabled' }
        end
      end
    end
  end
end
