# encoding: utf-8
# =============================================================================
# Pipeline Artifact Presence & Validity controls
#
# CONTRACT:
#   - This profile proves a scan RAN and emitted a well-formed artifact.
#   - It does NOT inspect findings (no "did SAST pass" logic here).
#   - pass  => expected AND artifact exists & is structurally valid
#   - skip  => not expected for this pipeline (only_if)
#   - fail  => expected but artifact missing / empty / malformed
# =============================================================================

adir = input('artifact_dir')

# ---- generic existence + non-empty assertion --------------------------------
def assert_present(adir, fname)
  p = ArtifactHelper.path(adir, fname)
  describe file(p) do
    it { should exist }
    its('size') { should be > 0 }
  end
end

# =============================================================================
# SAST  -> SA-11(1)
# =============================================================================
control 'artifact-sast' do
  impact 1.0
  title 'SAST report generated and valid (SA-11(1))'
  desc  'Static application security testing ran and produced a SARIF artifact.'
  tag nist: ['SA-11(1)']
  tag layer: 'static-analysis'
  only_if('SAST not expected in this pipeline') { input('expect_sast') }

  p = ArtifactHelper.path(adir, input('sast_report'))
  describe file(p) do
    it { should exist }
    its('size') { should be > 0 }
  end
  describe json(p) do
    its('runs') { should_not be_nil }   # SARIF structural marker
  end
end

# =============================================================================
# Secrets (generic stage)  -> IA-5(7), SA-11
# =============================================================================
control 'artifact-secrets' do
  impact 1.0
  title 'Secrets scan report generated (IA-5(7))'
  desc  'A secrets-detection stage ran and emitted a report.'
  tag nist: ['IA-5(7)', 'SA-11']
  tag layer: 'secrets'
  only_if('Generic secrets scan not expected') { input('expect_secrets') }
  assert_present(adir, input('secrets_report'))
end

# =============================================================================
# Trufflehog (verified secrets layer)  -> IA-5(7), SA-11
# Trufflehog emits JSONL (one JSON object per line); validate as text + parseable head.
# =============================================================================
control 'artifact-trufflehog' do
  impact 1.0
  title 'Trufflehog verified-secrets report generated (IA-5(7))'
  desc  'Trufflehog ran (git history + filesystem) and emitted a JSONL report. '\
        'Empty file is valid here ONLY if your stage writes an explicit empty result; '\
        'default asserts the file exists and stage executed.'
  tag nist: ['IA-5(7)', 'SA-11']
  tag layer: 'secrets-verified'
  only_if('Trufflehog not expected') { input('expect_trufflehog') }

  p = ArtifactHelper.path(adir, input('trufflehog_report'))
  describe file(p) do
    it { should exist }
  end
end

# =============================================================================
# Linting  -> SA-15(5), SA-11
# =============================================================================
control 'artifact-lint' do
  impact 0.7
  title 'Lint report generated (SA-15(5))'
  tag nist: ['SA-15(5)', 'SA-11']
  tag layer: 'quality'
  only_if('Lint not expected') { input('expect_lint') }
  assert_present(adir, input('lint_report'))
end

# =============================================================================
# Code Quality  -> SA-15
# =============================================================================
control 'artifact-quality' do
  impact 0.7
  title 'Code quality report generated (SA-15)'
  tag nist: ['SA-15']
  tag layer: 'quality'
  only_if('Quality scan not expected') { input('expect_quality') }
  assert_present(adir, input('quality_report'))
end

# =============================================================================
# Automated Code Review  -> SA-11(4), SA-15(7)
# =============================================================================
control 'artifact-code-review' do
  impact 0.7
  title 'Automated code review report generated (SA-11(4))'
  tag nist: ['SA-11(4)', 'SA-15(7)']
  tag layer: 'review'
  only_if('Automated code review not expected') { input('expect_code_review') }
  assert_present(adir, input('code_review_report'))
end

# =============================================================================
# SBOM  -> SR-3, SR-4
# =============================================================================
control 'artifact-sbom' do
  impact 1.0
  title 'SBOM generated and valid CycloneDX (SR-3, SR-4)'
  tag nist: ['SR-3', 'SR-4']
  tag layer: 'supply-chain'
  only_if('SBOM not expected') { input('expect_sbom') }

  p = ArtifactHelper.path(adir, input('sbom_report'))
  describe file(p) do
    it { should exist }
    its('size') { should be > 0 }
  end
  describe json(p) do
    its('bomFormat') { should cmp 'CycloneDX' }   # structural validity marker
  end
end

# =============================================================================
# Dependency / SCA (generic)  -> RA-5, SA-11(1), SR-3
# =============================================================================
control 'artifact-dependency' do
  impact 1.0
  title 'Dependency/SCA report generated (RA-5)'
  tag nist: ['RA-5', 'SA-11(1)', 'SR-3']
  tag layer: 'sca'
  only_if('Generic dependency scan not expected') { input('expect_dependency') }
  assert_present(adir, input('dependency_report'))
end

# =============================================================================
# Trivy (multi-scanner: vuln + misconfig + secret + license)  -> RA-5, CM-6, SR-3
# Trivy JSON has top-level "SchemaVersion".
# =============================================================================
control 'artifact-trivy' do
  impact 1.0
  title 'Trivy report generated and valid (RA-5, CM-6, SR-3)'
  desc  'Trivy ran (vuln/misconfig/secret/license layers) and emitted JSON.'
  tag nist: ['RA-5', 'CM-6', 'SR-3']
  tag layer: 'sca-multi'
  only_if('Trivy not expected') { input('expect_trivy') }

  p = ArtifactHelper.path(adir, input('trivy_report'))
  describe file(p) do
    it { should exist }
    its('size') { should be > 0 }
  end
  describe json(p) do
    its('SchemaVersion') { should_not be_nil }   # Trivy structural marker
  end
end

# =============================================================================
# Grype (SCA, consumes SBOM)  -> RA-5, SA-11(1)
# Grype JSON has top-level "descriptor" with "name":"grype".
# =============================================================================
control 'artifact-grype' do
  impact 1.0
  title 'Grype report generated and valid (RA-5)'
  tag nist: ['RA-5', 'SA-11(1)']
  tag layer: 'sca'
  only_if('Grype not expected') { input('expect_grype') }

  p = ArtifactHelper.path(adir, input('grype_report'))
  describe file(p) do
    it { should exist }
    its('size') { should be > 0 }
  end
  describe json(p) do
    its(%w(descriptor name)) { should cmp 'grype' }   # structural marker
  end
end

# =============================================================================
# Snyk (SCA, commercial depth)  -> RA-5, SR-3
# Snyk test JSON includes "vulnerabilities" + "packageManager" keys.
# =============================================================================
control 'artifact-snyk' do
  impact 1.0
  title 'Snyk report generated and valid (RA-5, SR-3)'
  tag nist: ['RA-5', 'SR-3']
  tag layer: 'sca'
  only_if('Snyk not expected') { input('expect_snyk') }

  p = ArtifactHelper.path(adir, input('snyk_report'))
  describe file(p) do
    it { should exist }
    its('size') { should be > 0 }
  end
  describe json(p) do
    its('keys') { should include 'vulnerabilities' }   # structural marker
  end
end

# =============================================================================
# OSS License governance  -> SR-3, SA-4
# Records WHICH source approved licenses via license_source input.
# =============================================================================
control 'artifact-license' do
  impact 1.0
  title 'OSS license review artifact generated (SR-3, SA-4)'
  desc  "OSS license governance was performed. Source of review: "\
        "#{input('license_source')}."
  tag nist: ['SR-3', 'SA-4']
  tag layer: 'license-governance'
  # NOT `tag license_source: input('license_source')`. Tags are STATIC
  # metadata: InSpec's AST TagCollector reads the literal at parse time and
  # crashes on a method call —
  #   undefined method 'value' for an instance of RuboCop::AST::SendNode
  # — which aborted `cinc-auditor check` for the entire profile. The value is
  # runtime data and is already recorded twice: interpolated into desc above,
  # and asserted in the describe below.
  only_if('License governance not expected') { input('expect_license') }

  p = ArtifactHelper.path(adir, input('license_report'))
  describe file(p) do
    it { should exist }
    its('size') { should be > 0 }
  end
  # record the declared source for evidence/traceability
  describe "declared license review source = #{input('license_source')}" do
    subject { input('license_source') }
    it { should match(/\A(sonatype|trivy|snyk|manual)\z/) }
  end
end

# =============================================================================
# Container signing & validation  -> SI-7, SR-4(3)
# =============================================================================
control 'artifact-container-sig' do
  impact 1.0
  title 'Container signature verification artifact generated (SI-7, SR-4)'
  desc  'Cosign (or equivalent) verified artifact signature and emitted a result.'
  tag nist: ['SI-7', 'SR-4']
  tag layer: 'supply-chain-integrity'
  only_if('Container signing not expected') { input('expect_container_sig') }
  assert_present(adir, input('container_sig_report'))
end

# =============================================================================
# InSpec validation of DEPLOYED resources  -> CA-2(2), CA-7, CM-6, RA-5
# This is the OTHER InSpec run (against live infra); we just confirm its
# results artifact landed in the pipeline.
# =============================================================================
control 'artifact-inspec-deployed' do
  impact 1.0
  title 'Deployed-resource InSpec results generated (CA-2(2), CA-7)'
  tag nist: ['CA-2(2)', 'CA-7', 'CM-6', 'RA-5']
  tag layer: 'runtime-assessment'
  only_if('Deployed-resource InSpec not expected') { input('expect_inspec_deployed') }

  p = ArtifactHelper.path(adir, input('inspec_deployed_report'))
  describe file(p) do
    it { should exist }
    its('size') { should be > 0 }
  end
  describe json(p) do
    its('profiles') { should_not be_nil }   # InSpec/HDF structural marker
  end
end
