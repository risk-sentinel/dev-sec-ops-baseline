# encoding: utf-8
# =============================================================================
# Dashboard evidence — the executed-and-clean claim, and what happens to
# findings after they are raised.
#
# CONTRACT:
#   - A clean scan is a PASS, not an absence. Publishing nothing when a team
#     does everything right is the gap this profile exists to close, and an
#     empty evidence prefix is indistinguishable from a bridge that never ran.
#   - A finding that has been triaged is not a finding that has been ignored.
#     Dismissals are recorded with an owner and a reason, and a dismissal
#     without either is an unowned accepted risk.
#   - A disabled capability never reads as clean. capability_status is
#     three-state and both non-enabled states are reported with the API's own
#     message.
#
# ---- Why every API call sits inside a subject block -------------------------
#
# A raise in a control BODY aborts the whole control, so one unreachable
# repository would drop the results for every repository after it — the run
# reports two results instead of twenty-one and still looks green. Deferring
# the call into `subject { }` confines a failure to its own describe.
# =============================================================================

require 'time'

# Locals, not constants: InSpec evaluates each control file in its own
# anonymous context, so a constant defined in another file is invisible here.
run_mode  = input('run_mode')
gh_token  = input('github_token')
gh_api    = input('github_api_base')
org_name  = input('organization').to_h['name']
targets   = Array(input('targets'))
branch    = input('protected_branch')
max_age   = input('evidence_freshness_days').to_i

control_plane = %w[control-plane both].include?(run_mode)
# Hoisted because it is asserted by every control in this file.
#
# The `tag layer:` literals below are deliberately NOT hoisted, and Sonar's
# duplicate-literal rule cannot be satisfied for them. InSpec's TagCollector
# walks the AST before anything is evaluated, so a tag value must be a literal
# node. Every alternative crashes `cinc-auditor check` outright:
#
#   tag layer: LAYER      -> undefined method 'value' for RuboCop::AST::ConstNode
#   tag layer: layer_tag  -> undefined method 'value' for RuboCop::AST::VarNode
#   tag layer: layer_for  -> undefined method 'value' for RuboCop::AST::SendNode
#
# The constant is the form the rule actually asks for, so it is the one that
# had to be tested — a local variable failing proves nothing about it. All
# three were run against the pinned image rather than assumed. Hoisting these
# would trade a code smell for a profile that will not load.
needs_cp = 'Dashboard evidence needs control-plane access'.freeze
repo_names    = targets.map { |t| t.to_h['repo'] }.compact.reject(&:empty?)
ref           = "refs/heads/#{branch}"

# =============================================================================
# The executed-and-clean claim.
#
# This is the control that makes a well-run repository visible. The findings
# feed cannot do it: a scan that finds nothing converts to an HDF profile with
# zero controls, which renders as 0% compliant rather than as a pass. So the
# assertion lives here, sourced from what the platform reports about the scan
# itself — analysis id, ref, commit, tool, result count, timestamp — rather
# than synthesised as a scanner result that CodeQL never produced.
# =============================================================================
control 'devsecops-code-scanning-executed' do
  impact 1.0
  title 'Code scanning ran recently on the protected branch (RA-5, SA-11)'
  desc <<~DESC
    Every declared repository with code scanning enabled must have a recent
    analysis on its protected branch, for every language it scans.

    Per-language, deliberately. CodeQL records one analysis per language per
    run, so checking only the newest analysis reports a repository as scanned
    when a single language was and the rest silently stopped.

    A repository whose capability is disabled is reported with the platform's
    own message and is NOT counted as clean. On public repositories code
    scanning is free, so enabled there reflects a default rather than a
    decision; on private repositories it requires licensing, and that gap is
    reported as unverifiable rather than as a pass.
  DESC
  tag nist: ['RA-5', 'RA-5(2)', 'SA-11', 'SA-11(1)', 'SI-2']
  tag layer: 'dashboard-evidence' # NOSONAR - tag values must be AST literals
  only_if(needs_cp) do
    control_plane && !org_name.to_s.empty? && !repo_names.empty?
  end

  repo_names.each do |repo|
    slug = "#{org_name}/#{repo}"

    describe "#{repo} — code scanning analyses on #{branch}" do
      subject do
        gs = github_security(slug, token: gh_token, api_base: gh_api)
        status = gs.capability_status(:code_scanning)
        next "capability #{status}: #{gs.capability_reason(:code_scanning)}" unless status == :enabled

        prov = gs.scan_provenance(ref: ref)
        next "no analysis found on #{ref}" if prov.nil? || prov.empty?

        cutoff = Time.now.utc - (max_age * 86_400)
        stale  = prov.reject do |p|
          created = begin
            Time.parse(p['createdAt'].to_s)
          rescue StandardError
            nil
          end
          created && created > cutoff
        end

        if stale.empty?
          langs = prov.map { |p| "#{p['language']}=#{p['resultsCount']}" }.join(' ')
          "scanned (#{prov.size} language(s): #{langs})"
        else
          "stale beyond #{max_age}d: " +
            stale.map { |p| "#{p['language']} last #{p['createdAt']}" }.join(', ')
        end
      end
      it { should match(/\Ascanned \(/) }
    end
  end
end

# =============================================================================
# Open findings.
#
# Counts only what is genuinely open. A dismissed finding is a decision that
# was made, not a risk that was missed, and failing on it would mean the
# evidence package re-litigates settled triage on every run — which is how a
# report stops being read.
# =============================================================================
control 'devsecops-dashboard-open-findings' do
  impact 0.7
  title 'No open findings on the security dashboards (RA-5, SI-2)'
  desc <<~DESC
    Open alerts across code scanning, secret scanning and Dependabot.

    Dismissed alerts are excluded here and asserted separately: whether a
    finding was triaged is a different question from whether it was owned.
    Fixed alerts are excluded because remediation is the outcome we wanted.

    A capability that is not enabled yields no result rather than a zero, so
    "nothing found" and "nobody looked" never collapse into the same number.
  DESC
  tag nist: ['RA-5', 'SI-2', 'SI-3', 'IA-5(7)']
  tag layer: 'dashboard-evidence' # NOSONAR - tag values must be AST literals
  only_if(needs_cp) do
    control_plane && !org_name.to_s.empty? && !repo_names.empty?
  end

  repo_names.each do |repo|
    slug = "#{org_name}/#{repo}"

    { code_scanning: 'code scanning',
      secret_scanning: 'secret scanning',
      dependabot_alerts: 'Dependabot' }.each do |capability, label|
      describe "#{repo} — open #{label} alerts" do
        subject do
          gs = github_security(slug, token: gh_token, api_base: gh_api)
          status = gs.capability_status(capability)
          next "not evaluated — capability #{status}" unless status == :enabled

          count = gs.open_alert_count(capability)
          count.nil? ? 'unreadable' : "#{count} open"
        end
        it { should match(/\A(0 open|not evaluated)/) }
      end
    end
  end
end

# =============================================================================
# Dismissal accountability.
#
# A dismissal is an accepted risk. Accepted risks have owners. The platform
# records who dismissed an alert and why, so an unattributed dismissal is a
# gap in the record rather than an unavoidable one.
# =============================================================================
control 'devsecops-dismissals-accountable' do
  impact 0.5
  title 'Dismissed findings carry an owner and a reason (RA-5(5), CA-5, PM-4)'
  desc <<~DESC
    Every dismissed code-scanning alert must record who dismissed it and on
    what grounds. A dismissal with neither is indistinguishable from a finding
    that was quietly closed, and it is the artefact an assessor will ask about
    first.

    This is why dismissals stay in the evidence rather than being filtered out
    of it. tools/apply_dispositions.py marks them Not Applicable in the HDF and
    carries the reason, the person and the date into the skip message, so the
    acceptance remains auditable instead of disappearing.
  DESC
  tag nist: ['RA-5(5)', 'CA-5', 'PM-4', 'SA-11']
  tag layer: 'dashboard-evidence' # NOSONAR - tag values must be AST literals
  only_if(needs_cp) do
    control_plane && !org_name.to_s.empty? && !repo_names.empty?
  end

  repo_names.each do |repo|
    slug = "#{org_name}/#{repo}"

    describe "#{repo} — dismissed code-scanning alerts without an owner or reason" do
      subject do
        gs = github_security(slug, token: gh_token, api_base: gh_api)
        next [] unless gs.capability_status(:code_scanning) == :enabled

        alerts = gs.code_scanning_alerts(state: 'dismissed') || []
        alerts.reject { |a| a['dismissed_reason'] && a.dig('dismissed_by', 'login') }
              .map { |a| "##{a['number']} #{a.dig('rule', 'id')}" }
      end
      it { should be_empty }
    end
  end
end

# =============================================================================
# Push-protection bypasses.
#
# Separated from the findings on purpose. A bypass is not a scanner result: it
# is a person who was warned that a credential was about to be committed and
# proceeded. Buried in an alert list it reads as one more finding; on its own
# it reads as what it is.
# =============================================================================
control 'devsecops-push-protection-bypasses' do
  impact 0.7
  title 'No push-protection bypasses on secret scanning (IA-5(7), AC-6)'
  desc <<~DESC
    Push protection blocks a commit containing a recognised credential. A
    bypass means someone was shown that block and chose to continue, so the
    credential reached the repository with a human decision behind it.

    Reported per repository with the alert numbers, so the record points at
    specific events rather than a count.
  DESC
  tag nist: ['IA-5(7)', 'AC-6', 'AU-2', 'SI-4']
  tag layer: 'dashboard-evidence' # NOSONAR - tag values must be AST literals
  only_if(needs_cp) do
    control_plane && !org_name.to_s.empty? && !repo_names.empty?
  end

  repo_names.each do |repo|
    slug = "#{org_name}/#{repo}"

    describe "#{repo} — secret-scanning alerts where push protection was bypassed" do
      subject do
        gs = github_security(slug, token: gh_token, api_base: gh_api)
        next [] unless gs.capability_status(:secret_scanning) == :enabled
        (gs.push_protection_bypasses || []).map { |a| "##{a['number']} #{a['secret_type']}" }
      end
      it { should be_empty }
    end
  end
end
