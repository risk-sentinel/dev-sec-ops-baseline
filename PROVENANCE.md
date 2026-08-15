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

## Phase 2 controls — control plane

| Control | What it validates | NIST 800-53r5 | SSDF | Rationale |
|---|---|---|---|---|
| `devsecops-inventory-reconciliation` | The declared repository list against an independent enumeration of the organisation | CM-8, CM-8 (1), PM-5, CA-7 | PO.1 | A declaration cannot be the evidence that it is complete. Undeclared repositories, stale declarations and unreasoned exclusions all fail. |
| `devsecops-native-capability-enablement` | Forge-native scanning is on where it is the only possible evidence | RA-5, SI-5, SA-11 | PW.7, RV.1 | Asserted only for tools with no non-API surface. A disabled capability returns 403/404, never "no findings", so it fails with the API's own message. |
| `devsecops-coverage-sast` | Static Application Security Testing coverage across declared repositories | SA-11(1) | PW.7, PW.8 | Any declared tool verified on an execution surface this run mode can reach. |
| `devsecops-coverage-secrets` | Secrets Detection coverage across declared repositories | IA-5(7), SA-11 | PW.1 | Any declared tool verified on an execution surface this run mode can reach. |
| `devsecops-coverage-iac` | Infrastructure as Code Scanning coverage across declared repositories | CM-2, CM-6, RA-5 | PW.9 | Any declared tool verified on an execution surface this run mode can reach. |
| `devsecops-coverage-sca` | Software Composition Analysis coverage across declared repositories | RA-5, SA-11(1), SR-3 | RV.1, PW.4 | Any declared tool verified on an execution surface this run mode can reach. |
| `devsecops-coverage-sbom` | Software Bill of Materials coverage across declared repositories | SR-3, SR-4 | PS.3, PW.4 | Any declared tool verified on an execution surface this run mode can reach. |
| `devsecops-coverage-container` | Container Image Scanning coverage across declared repositories | RA-5, CM-6, SR-3 | RV.1 | Any declared tool verified on an execution surface this run mode can reach. |
| `devsecops-coverage-licensing` | Software Licensing Review coverage across declared repositories | SR-3, SA-4 | PW.4 | Any declared tool verified on an execution surface this run mode can reach. |
| `devsecops-coverage-dast` | Dynamic Application Security Testing coverage across declared repositories | SA-11(8), RA-5, CA-8 | PW.8, RV.1 | Any declared tool verified on an execution surface this run mode can reach. |
| `devsecops-coverage-runtime` | Post-Deployment Validation coverage across declared repositories | CA-2(2), CA-7, CM-6, RA-5 | RV.1, PW.9 | Any declared tool verified on an execution surface this run mode can reach. |
| `devsecops-coverage-iast` | Interactive Application Security Testing coverage across declared repositories | SA-11(9) | PW.8 | Any declared tool verified on an execution surface this run mode can reach. |

### Why the coverage controls verify rather than resolve

`coverage()` resolves the declaration against the registry — it says a tool *should* be
visible on a surface. Asserting on that alone would pass a repository that declares
SonarQube but has no project, without making a single API call. Each covered cell is
therefore verified against the real source, and an unreachable source fails.

### The evidence store surface

`evidence_store` reads converted HDF out of the S3 evidence bucket. It is the
only surface that can see a tool with **no API** from outside its own pipeline —
TruffleHog is the standing case — and so it is what makes a standalone sweep
meaningful rather than a list of things it cannot reach.

Attribution is corroborated, not asserted. The S3 key path says which repository
the evidence belongs to; the HDF's own labels (`repo`, `commit`, `run_id`,
stamped at emit) say it independently. Path alone is a convention — anything
with write access can file an object anywhere. Labels alone cannot prove the
object is where a reader will look. Agreement makes the attribution
trustworthy, and disagreement is a finding in its own right: evidence filed
under the wrong repository is worse than absent, because it credits the wrong
thing.

Freshness is bounded by `evidence_lookback_days` (default 7). Absent, stale and
misattributed evidence are three different findings and are reported separately.

**Credential failures raise rather than fail.** A missing or unusable AWS
credential says nothing about whether a scan ran: failing would assert
something untrue, passing would be worse, and skipping would read as "not
applicable". Raising makes InSpec emit `failed` *with a backtrace*, which
Heimdall's rollup renders as Profile Error — no credit, and visibly not an
assessment. This is deliberately inconsistent with `github_security` and
`sonarqube_project`, which capture and fail; whether those should follow is an
open question rather than an oversight.

### Evidence strength is recorded, not assumed

A platform API reports whatever it last analysed; an artifact was produced by the run in
progress. Results are labelled `run-scoped` or `point-in-time`, and API evidence is bounded
by `evidence_freshness_days` so a year-old analysis cannot satisfy a coverage control.

## Notes

- **Presence + validity, not the finding itself:** each control proves the *artifact* was produced
  and is well-formed (the pipeline step ran and emitted valid evidence); the findings inside those
  artifacts are evaluated by their own producers (SonarCloud, TruffleHog, Grype, InSpec, …). This
  profile is the completeness gate over the secure-development pipeline.
- **NIST mappings** mirror each control's `tag nist:` — the per-control cross-reference for
  OSCAL/Heimdall rollup.
- Keep this doc in sync when artifact checks are added/removed or re-anchored.

_Closes #1._
