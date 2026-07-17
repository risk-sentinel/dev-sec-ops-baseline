# Provenance — `dev-sec-ops-baseline`

## What this profile is

A **bespoke, Risk Sentinel–authored** profile (`name:` `dev-sec-ops-v1r1`) that validates the
**presence and validity of the security artifacts a CI/CD pipeline is expected to produce** —
SAST, secrets scans, SBOM, SCA/vulnerability reports, license review, container-signature
verification, and deployed-resource evidence. It is not a benchmark; it is the *evidence layer*
that proves the secure-development pipeline actually ran. Each control is anchored to a NIST
authoritative source, documented here so each check is defensible in an assessment. 14 controls,
each carrying a `tag nist:` (NIST 800‑53 Rev 5).

## Authoritative sources

| Key | Source | Role here |
|---|---|---|
| **NIST SSDF (800-218)** | Secure Software Development Framework | The framework each artifact evidences — a produced/valid artifact = an SSDF practice performed (PW review/test, PW.4 components, RV vuln response, PS provenance/integrity). |
| **NIST 800-53r5** | SP 800-53 Rev 5 control catalog | The control each check maps to (`tag nist:`) — **SA** (dev testing/process), **SR** (supply chain), **RA-5** (vuln scanning), **IA-5(7)** (no embedded static authenticators), **SI-7** (software integrity), **CA** (assessment/monitoring). |

## Control provenance

| Control | Pipeline artifact validated | NIST 800-53r5 | SSDF (800-218) | Rationale |
|---|---|---|---|---|
| `artifact-sast` | SAST report (SARIF) | SA-11 (1) | PW.7/PW.8 | Static analysis ran — developer security testing. |
| `artifact-secrets` | Secrets scan report | IA-5 (7), SA-11 | PW.1 | No hardcoded static authenticators in source. |
| `artifact-trufflehog` | TruffleHog verified-secrets report | IA-5 (7), SA-11 | PW.1 | Verified-secret detection ran. |
| `artifact-lint` | Lint report | SA-15 (5), SA-11 | PW.8 | Automated static quality/analysis tooling ran. |
| `artifact-quality` | Code-quality report | SA-15 | PW.7 | Development process produces quality evidence. |
| `artifact-code-review` | Automated code-review report | SA-11 (4), SA-15 (7) | PW.7 | Manual/automated code review performed. |
| `artifact-sbom` | SBOM (valid CycloneDX) | SR-3, SR-4 | PS.3 / PW.4 | Component provenance recorded — supply-chain transparency. |
| `artifact-dependency` | Dependency / SCA report | RA-5, SA-11 (1), SR-3 | RV.1 / PW.4 | Known-vulnerable dependencies identified. |
| `artifact-trivy` | Trivy report | RA-5, CM-6, SR-3 | RV.1 | Container/dependency vuln + misconfig scan ran. |
| `artifact-grype` | Grype report | RA-5, SA-11 (1) | RV.1 | SBOM-driven vulnerability scan ran. |
| `artifact-snyk` | Snyk report | RA-5, SR-3 | RV.1 / PW.4 | Dependency vulnerability scan ran. |
| `artifact-license` | OSS license-review artifact | SR-3, SA-4 | PW.4 | Acquired/reused components are license-reviewed. |
| `artifact-container-sig` | Container signature verification | SI-7, SR-4 | PS.2 | Deployed image integrity/provenance verified. |
| `artifact-inspec-deployed` | Deployed-resource InSpec results | CA-2 (2), CA-7, CM-6, RA-5 | RV / PW.9 | Runtime config of deployed resources assessed. |

## Notes

- **Presence + validity, not the finding itself:** each control proves the *artifact* was produced
  and is well-formed (the pipeline step ran and emitted valid evidence); the findings inside those
  artifacts are evaluated by their own producers (SonarCloud, TruffleHog, Grype, InSpec, …). This
  profile is the completeness gate over the secure-development pipeline.
- **NIST mappings** mirror each control's `tag nist:` — the per-control cross-reference for
  OSCAL/Heimdall rollup.
- Keep this doc in sync when artifact checks are added/removed or re-anchored.

_Closes #1._
