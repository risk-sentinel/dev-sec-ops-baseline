# Tokens and scopes

**A clean scan is a pass, not an absence.** `sarif2hdf` emits one control per
*finding*, so a repository with nothing wrong converts to a profile with zero
controls and renders as `compliance: 0` — a team doing everything right
publishes a zero. Skipping the emit is worse: then a clean scan and a broken
bridge leave the same empty prefix. So the findings HDF is emitted only when
there are findings, and every run writes a `provenance.json` that
`devsecops-code-scanning-executed` turns into a passing control. The profile
asserts what the platform reported; it never invents a scanner result.

**A dismissed finding is a decision, not a failure.** An analysis's SARIF still
contains findings already triaged, so converting it alone republishes closed
dismissals as live failures on every run. SARIF's `suppressions` array exists
for this and the converter ignores it, so `tools/apply_dispositions.py` applies
the disposition afterwards — dismissed becomes Not Applicable carrying who,
when and why; fixed becomes passed; unmatched is reported rather than dropped.

### The dashboard controls

| Control | Passes when | NIST |
|---|---|---|
| `devsecops-code-scanning-executed` | Every enabled repository has a recent analysis on its protected branch, **per language** | `RA-5`, `SA-11(1)`, `SI-2` |
| `devsecops-dashboard-open-findings` | No open alerts across the three dashboards | `RA-5`, `SI-2`, `IA-5(7)` |
| `devsecops-dismissals-accountable` | Every dismissal records who dismissed it and why | `RA-5(5)`, `CA-5`, `PM-4` |
| `devsecops-push-protection-bypasses` | Nobody overrode a push-protection block | `IA-5(7)`, `AC-6`, `AU-2` |

Dependabot alerts are typed `sca`: they are vulnerability findings against
declared dependencies, the same assertion Grype and Trivy make from elsewhere.
An SBOM is inventory and does not satisfy that scan type. They are also a **free
toggle even on private repositories**, unlike code scanning and secret scanning,
which need Code Security licensing.

## Usage

```bash
# Standalone — read the control plane, no pipeline required
export GITHUB_TOKEN=...            # or pass token: through the control body
cinc-auditor exec . -t local:// \
  --input-file inputs/example-org.yml \
  --reporter cli json:hdf.json

# Bolt-on — last step of a pipeline, with reports/ populated
cinc-auditor exec . -t local:// \
  --input-file inputs/full-pipeline.yml \
  --input run_mode=pipeline \
  --reporter cli json:hdf.json
```

Repeated `--input` flags are **silently dropped** — only the last survives. Use one
flag with several pairs, or a second `--input-file`.

### Regenerating the coverage matrix

The tables above are generated. Edit the registry, never the table:

```bash
python3 tools/render_matrix.py           # rewrite README.md
python3 tools/render_matrix.py --check   # exit 1 if stale
```

---

## Tokens

Every credential can be supplied **either** as an InSpec input **or** as a conventional
environment variable. The environment fallback means an organisation- or group-level CI
secret works with no input plumbing at all.

| Credential | Input | Environment variable | Needed for |
|---|---|---|---|
| GitHub | `github_token` | `GITHUB_TOKEN`, then `GH_TOKEN` | Enablement, alerts, branch protection, org enumeration |
| SonarQube | `sonar_token` | `SONAR_TOKEN`, then `SONARQUBE_TOKEN` | Project existence, analysis freshness, issues |
| GitLab | `gitlab_token` | `GITLAB_TOKEN` | Portability only; not exec-validated |

```bash
# Environment — the usual CI shape, nothing passed as an input
export GITHUB_TOKEN=$GH_ORG_TOKEN
export SONAR_TOKEN=$SONAR_ORG_TOKEN
cinc-auditor exec . -t local:// --input-file inputs/example-org.yml

# Or explicitly. NOTE: repeated --input flags are silently dropped — only the
# last survives. One flag, many pairs.
cinc-auditor exec . -t local:// --input-file inputs/example-org.yml \
  --input github_token="$GH_ORG_TOKEN" sonar_token="$SONAR_ORG_TOKEN"
```

### Scopes

| Surface | GitHub | GitLab | SonarQube |
|---|---|---|---|
| Enablement + findings | `security_events` (or `repo` on private) | `read_api` | `Execute Analysis` / read |
| Dashboard bridge (analyses, SARIF, alert locations) | `security_events` | &mdash; | &mdash; |
| Branch protection, rulesets | `repo` | `read_api` | &mdash; |
| Repo contents | `contents:read` | `read_repository` | &mdash; |
| Organisation enumeration | `read:org` | `read_api` | &mdash; |

Inside a workflow the equivalent is `permissions: security-events: read`. Omit
it and every capability reads as *disabled* rather than as a permission problem,
because that is genuinely what GitHub returns.

**`read:org` is load-bearing and fails quietly if missing.** `GET /orgs/{org}/repos`
answers `200` for a caller that cannot see private repositories — it just returns
a shorter list, with nothing marking it as short. On this organisation that is 16
repositories instead of 21. Reconciliation would then compare a truncated reality
against a complete declaration and report the invisible repositories as *stale
declarations*, blaming the declaration for a credential fault. So
`devsecops-inventory-reconciliation` asserts that the enumeration was
authenticated, before and separately from asserting anything about its contents.

**A missing token is not the same finding as a disabled feature**, and this profile keeps
them apart. GitHub returns `403`/`404` with its own message for a switched-off capability
and `401 Bad credentials` for a bad token; both fail, with different text, because they
have different owners.

SonarQube needs particular care: it returns **404 for a private project the caller cannot
see**, deliberately not leaking existence. So without a token, "absent" and "private" are
the same response — the profile reports that as *indeterminate* rather than claiming the
project is missing.

---
