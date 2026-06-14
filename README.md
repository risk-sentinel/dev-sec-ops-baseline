# pipeline-artifact-validation

A portable InSpec profile that verifies **which security/quality scan artifacts a
pipeline produced** and whether they are **structurally valid** — driven entirely
by per-pipeline input toggles.

## Contract

| State | Meaning |
|-------|---------|
| **pass** | Artifact was expected (`expect_* = true`) **and** exists and is structurally valid |
| **skip** | Artifact was **not** expected for this pipeline (`only_if` short-circuits) |
| **fail** | Artifact was expected but is **missing, empty, or malformed** |

This profile proves a scan **ran and emitted a real report**. It deliberately does
**not** inspect findings inside the reports — keep "did SAST run" separate from
"did SAST pass" so the pass/skip/fail signal stays clean.

## Tool layers covered

| Tool / stage | Layer | Validity marker | NIST (Rev4/Rev5) |
|---|---|---|---|
| SAST | static analysis | SARIF `runs[]` | SA-11(1) |
| Trufflehog | verified secrets (git history + fs) | file exists | IA-5(7), SA-11 |
| Secrets (generic) | secrets | size > 0 | IA-5(7), SA-11 |
| Lint | quality | size > 0 | SA-15(5) |
| Quality | quality | size > 0 | SA-15 |
| Automated code review | review | size > 0 | SA-11(4), SA-15(7) |
| SBOM | supply chain | CycloneDX `bomFormat` | SR-3, SR-4 |
| Dependency (generic SCA) | sca | size > 0 | RA-5, SA-11(1), SR-3 |
| Trivy | sca-multi (vuln+misconfig+secret+license) | `SchemaVersion` | RA-5, CM-6, SR-3 |
| Grype | sca (consumes SBOM) | `descriptor.name == grype` | RA-5, SA-11(1) |
| Snyk | sca (commercial depth) | `vulnerabilities` key | RA-5, SR-3 |
| OSS License | license governance | size > 0 + `license_source` | SR-3, SA-4 |
| Container signing | supply-chain integrity | size > 0 | SI-7, SR-4(3) |
| Deployed-resource InSpec | runtime assessment | InSpec `profiles[]` | CA-2(2), CA-7, CM-6, RA-5 |

### Why run several SCA tools
They sit at different layers and use different vuln DBs:
- **Trufflehog** = verified secrets (confirms a leaked cred is live), git-history aware.
- **Grype** = fast SBOM-driven SCA; pairs with Syft-generated SBOM.
- **Trivy** = breadth: vulns + IaC misconfig + secrets + license in one pass.
- **Snyk** = commercial DB depth + license policy.
- **Sonatype** = dependency/license **policy governance** (approve/deny), not just detection.

## OSS license review source

`license_source` records *which* tool/process approved licenses
(`sonatype | trivy | snyk | manual`). It is stamped as a control tag for
evidence traceability, so your SAR shows not just that license review happened
but who performed it.

## Usage

```bash
# Full suite
inspec exec pipeline-artifact-validation \
  --input-file inputs/full-pipeline.yml \
  --reporter cli json:reports/artifact-validation.json \
  --chef-license accept-silent

# Or inline toggles
inspec exec pipeline-artifact-validation \
  --input expect_sast=true expect_sbom=true license_source=sonatype \
  --reporter cli
```

## OSCAL / HDF integration

Every control is `nist`-tagged, so the JSON reporter output feeds the SAF CLI
HDF/OSCAL converters. Each artifact-presence control becomes a control-satisfaction
record in your Assessment Results (SAR) — the "artifact was produced" assertion
maps to its 800-53 control ID independent of the underlying scan's findings.

Recommended: commit one input file per pipeline under `inputs/` so the
"which reports should be detected" contract is version-controlled and reviewable
in an MR (fits an authoritative-layer posture better than ephemeral CI variables).

## License

MIT OR Apache-2.0. No ownership claims asserted.
