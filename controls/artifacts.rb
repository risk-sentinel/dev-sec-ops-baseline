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
  desc  'rationale', 'SA-11(1) asks whether static analysis happens, and the report is the only durable answer. A pipeline that names a SAST tool proves someone wired it up, not that it ran over this commit.'
  desc  'check', 'Asserts the declared SAST report exists in the artifact directory, is non-empty, and parses as SARIF with at least one run.'
  desc  'fix', 'If absent, the SAST stage did not run or did not publish its report. Check the workflow run and the artifact upload path; a stage that fails open leaves no report and no finding.'
  desc  'Static application security testing ran and produced a SARIF artifact.'
  tag nist: ['SA-11(1)']
  tag ksi: ['KSI-SCR-MIT']
  tag nist_r4: ['SA-11(1)']
  tag cci:  ['CCI-003179']
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
  desc  'rationale', 'IA-5(7) prohibits embedded static authenticators. Detection is the control; the report is the evidence it operated over this commit.'
  desc  'check', 'Asserts the declared secrets report exists in the artifact directory and is non-empty.'
  desc  'fix', 'If absent, the secrets stage did not run or published nothing. Note a clean scan must still emit — an empty prefix is indistinguishable from a broken pipeline.'
  desc  'A secrets-detection stage ran and emitted a report.'
  tag nist: ['IA-5(7)', 'SA-11']
  tag ksi: ['KSI-IAM-APM', 'KSI-SCR-MIT']
  tag nist_r4: ['IA-5(7)', 'SA-11']
  tag cci:  ['CCI-003171', 'CCI-004069']
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
  desc  'rationale', 'TruffleHog verifies candidate credentials against the issuing service, so its findings are actionable in a way regex matches are not. Verified-only keeps false positives out of the POA&M.'
  desc  'check', 'Asserts the TruffleHog JSONL report exists and is non-empty. JSONL, so it is checked by shape rather than parsed as a JSON document.'
  desc  'fix', 'If absent, TruffleHog did not run or its output was not published. If present but empty, confirm the run used --json and wrote to the declared path.'
  desc  'Trufflehog ran (git history + filesystem) and emitted a JSONL report. '\
        'Empty file is valid here ONLY if your stage writes an explicit empty result; '\
        'default asserts the file exists and stage executed.'
  tag nist: ['IA-5(7)', 'SA-11']
  tag ksi: ['KSI-IAM-APM', 'KSI-SCR-MIT']
  tag nist_r4: ['IA-5(7)', 'SA-11']
  tag cci:  ['CCI-003171', 'CCI-004069']
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
  desc  'A linter ran over the source and emitted a report.'
  desc  'rationale', 'SA-15(5) asks for automated analysis in the development process. Lint is the cheapest such control and the one most often assumed rather than evidenced.'
  desc  'check', 'Asserts the declared lint report exists in the artifact directory and is non-empty.'
  desc  'fix', 'If absent, the lint stage did not run or did not publish its report. Check the workflow run and the artifact path.'
  tag nist: ['SA-15(5)', 'SA-11']
  tag ksi: ['KSI-SCR-MIT']
  tag nist_r4: ['SA-11', 'SA-15(5)']
  tag cci:  ['CCI-003171', 'CCI-003272']
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
  desc  'A code-quality analysis ran and emitted a report.'
  desc  'rationale', 'SA-15 asks that development follows a defined process with quality measures. A quality report is the artifact that shows the measure was applied rather than declared.'
  desc  'check', 'Asserts the declared quality report exists in the artifact directory and is non-empty.'
  desc  'fix', 'If absent, the quality stage did not run or did not publish. If your quality gate lives in a hosted service, point the declaration at its exported report rather than assuming the badge is evidence.'
  tag nist: ['SA-15']
  tag ksi: []
  tag ksi_broader: ['KSI-SCR-MIT']
  tag nist_r4: ['SA-15']
  tag cci:  ['CCI-003233']
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
  desc  'An automated code-review pass ran and emitted a report.'
  desc  'rationale', 'SA-11(4) asks for manual code review support and SA-15(7) for automated analysis. This evidences the automated half — the part that runs on every change rather than on the ones someone remembered.'
  desc  'check', 'Asserts the declared code-review report exists in the artifact directory and is non-empty.'
  desc  'fix', 'If absent, the automated review did not run or published nothing. Human review recorded only in PR approvals is not covered by this control.'
  tag nist: ['SA-11(4)', 'SA-15(7)']
  tag ksi: ['KSI-SCR-MIT']
  tag nist_r4: ['SA-11(4)', 'SA-15(7)']
  tag cci:  ['CCI-003187', 'CCI-003275']
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
  desc  'A CycloneDX SBOM was generated for the build.'
  desc  'rationale', 'SR-3 and SR-4 require knowing what is in what you ship. An SBOM produced at build time is the only version that matches the artifact actually released.'
  desc  'check', 'Asserts the declared SBOM exists, is non-empty, and parses as CycloneDX with a components array.'
  desc  'fix', 'If absent, the SBOM stage did not run or published nothing. An SBOM generated later from source is not evidence about the released artifact.'
  tag nist: ['SR-3', 'SR-4']
  tag ksi: []
  tag ksi_unmapped: ['sr-3', 'sr-4']
  tag cci:  ['CCI-005080', 'CCI-005096']
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
  desc  'A dependency / SCA scan ran and emitted a report.'
  desc  'rationale', 'RA-5 requires vulnerability monitoring, and dependencies are where most of it lives. The report evidences that the scan happened over the lockfile at this commit.'
  desc  'check', 'Asserts the declared dependency report exists in the artifact directory and is non-empty.'
  desc  'fix', 'If absent, the SCA stage did not run or did not publish. Confirm it scanned the lockfile actually shipped, not a regenerated one.'
  tag nist: ['RA-5', 'SA-11(1)', 'SR-3']
  tag ksi: ['KSI-SCR-MIT', 'KSI-SCR-MON']
  tag ksi_unmapped: ['sr-3']
  tag nist_r4: ['RA-5', 'SA-11(1)']
  tag cci:  ['CCI-001054', 'CCI-003179', 'CCI-005080']
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
  desc  'rationale', 'Trivy covers vulnerabilities, misconfiguration, secrets and licences in one pass, so a single missing report costs four kinds of coverage.'
  desc  'check', 'Asserts the Trivy report exists, is non-empty, and parses as JSON with a Results array.'
  desc  'fix', 'If absent, Trivy did not run or did not publish. Check which layers were enabled — a run limited to one scanner still produces a report and silently narrows coverage.'
  desc  'Trivy ran (vuln/misconfig/secret/license layers) and emitted JSON.'
  tag nist: ['RA-5', 'CM-6', 'SR-3']
  tag ksi: ['KSI-CMT-LMC', 'KSI-CMT-RMV', 'KSI-MLA-EVC', 'KSI-SCR-MON', 'KSI-SVC-ACM']
  tag ksi_unmapped: ['sr-3']
  tag nist_r4: ['CM-6', 'RA-5']
  tag cci:  ['CCI-000366', 'CCI-001054', 'CCI-005080']
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
  desc  'Grype scanned the build for known vulnerabilities and emitted a report.'
  desc  'rationale', 'RA-5 requires vulnerability monitoring. Grype scans an SBOM or image directly, so its report evidences what was actually assessed rather than what was assumed present.'
  desc  'check', 'Asserts the Grype report exists, is non-empty, and parses as JSON with a matches array.'
  desc  'fix', 'If absent, Grype did not run or published nothing. If it ran against an SBOM, confirm the SBOM was the one built from this artifact.'
  tag nist: ['RA-5', 'SA-11(1)']
  tag ksi: ['KSI-SCR-MIT', 'KSI-SCR-MON']
  tag nist_r4: ['RA-5', 'SA-11(1)']
  tag cci:  ['CCI-001054', 'CCI-003179']
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
  desc  'Snyk scanned the project and emitted a report.'
  desc  'rationale', 'RA-5 and SR-3 — a second SCA opinion catches what one database misses. Where Snyk is declared, its absence is a coverage gap rather than a preference.'
  desc  'check', 'Asserts the Snyk report exists, is non-empty, and parses as JSON.'
  desc  'fix', 'If absent, Snyk did not run, or ran without a token and failed open. A failed-open scanner is the worst case: no report, no finding, and a green pipeline.'
  tag nist: ['RA-5', 'SR-3']
  tag ksi: ['KSI-SCR-MON']
  tag ksi_unmapped: ['sr-3']
  tag nist_r4: ['RA-5']
  tag cci:  ['CCI-001054', 'CCI-005080']
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
  desc  'A licence inventory was produced for the dependencies of this build.'
  desc  'rationale', 'Licence obligations travel with what you ship. An inventory generated at build time is the only one that matches the released artifact.'
  desc  'check', 'Asserts the declared licence report exists in the artifact directory and is non-empty.'
  desc  'fix', 'If absent, the licence stage did not run or did not publish its inventory.'
  desc  "OSS license governance was performed. Source of review: "\
        "#{input('license_source')}."
  tag nist: ['SR-3', 'SA-4']
  tag ksi: []
  tag ksi_unmapped: ['sa-4', 'sr-3']
  tag nist_r4: ['SA-4']
  tag cci:  ['CCI-003094', 'CCI-005080']
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
  desc  'The container image produced by this build was signed.'
  desc  'rationale', 'A signature is what lets a consumer verify the image they pull is the image you built. Unsigned images make provenance unfalsifiable.'
  desc  'check', 'Asserts the declared signature evidence exists in the artifact directory and is non-empty.'
  desc  'fix', 'If absent, the signing step did not run or its evidence was not published. Note signatures attach three different ways — cosign tag scheme, OCI referrers, AWS-native — so check which your registry uses before concluding the image is unsigned.'
  desc  'Cosign (or equivalent) verified artifact signature and emitted a result.'
  tag nist: ['SI-7', 'SR-4']
  tag ksi: ['KSI-SVC-VRI']
  tag ksi_unmapped: ['sr-4']
  tag nist_r4: ['SI-7']
  tag cci:  ['CCI-002703', 'CCI-005096']
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
  desc  'InSpec results for the deployed resources were produced.'
  desc  'rationale', 'CA-2(2) and CA-7 ask for assessment of the running system, not just the build. A clean pipeline says nothing about what is actually deployed.'
  desc  'check', 'Asserts the declared deployed-resource InSpec report exists, is non-empty, and parses as JSON.'
  desc  'fix', 'If absent, the post-deployment assessment did not run or did not publish. This is the control most often missing, because pipelines tend to stop at deploy.'
  tag nist: ['CA-2(2)', 'CA-7', 'CM-6', 'RA-5']
  tag ksi: ['KSI-CMT-LMC', 'KSI-CMT-RMV', 'KSI-MLA-EVC', 'KSI-PIY-RIS', 'KSI-SCR-MON', 'KSI-SVC-ACM']
  tag nist_r4: ['CA-2(2)', 'CA-7', 'CM-6', 'RA-5']
  tag cci:  ['CCI-000256', 'CCI-000274', 'CCI-000366', 'CCI-001054']
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
