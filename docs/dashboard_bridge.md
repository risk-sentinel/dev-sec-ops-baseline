# The dashboard bridge

Getting GitHub's three security dashboards — code scanning, secret scanning and
Dependabot — into the evidence stream as HDF, and turning what they say into
controls.

Everything here is the **control-plane** side. Nothing needs to run in your
pipeline.

---

## Why a bridge exists at all

The findings are already in GitHub. The problem is that they stay there: an
assessor cannot read your Security tab, a dashboard has no point-in-time record,
and "we scanned it" is not evidence until it is written down in a format the
evidence store accepts.

Only code scanning speaks a format anything else understands. So:

| Dashboard | Native form | Route to HDF |
|---|---|---|
| Code scanning (CodeQL) | SARIF, served by the API | fetch → `sarif2hdf` |
| Secret scanning | JSON alerts, **no SARIF** | map → SARIF → `sarif2hdf` |
| Dependabot | JSON alerts, **no SARIF** | map → SARIF → `sarif2hdf`, typed `sca` |

The mapping is in `libraries/alert_sarif.rb`. It targets SARIF rather than
TruffleHog's JSON, which `trufflehog2hdf` would also have accepted — and which
would have attributed GitHub's findings to a scanner that never ran. SARIF
carries `tool.driver.name`, so provenance survives the conversion.

---

## The two ideas worth understanding before you wire it up

Both exist because the obvious implementation reports the wrong thing.

### A clean scan is a pass, not an absence

`sarif2hdf` emits one control per **finding**. A repository with nothing wrong
therefore converts to a profile with **zero controls**, which renders as:

```
profileName: SARIF
compliance: 0
```

A team doing exactly what it should publishes a zero. Skipping the emit instead
is worse — then a clean scan and a broken bridge leave the same empty prefix.

So the two claims are separated:

- **Findings** are a scanner result. The HDF is emitted only when there are
  live findings.
- **"Scanned on `main@<sha>`, nothing found"** is a compliance claim, and it
  belongs to this profile. Every run writes `provenance.json` — analysis id,
  ref, commit, tool, version, per-language result counts, timestamp — and
  `devsecops-code-scanning-executed` turns that into a passing control.

The profile asserts what the platform reported. It never synthesises a CodeQL
result that CodeQL did not produce.

### A dismissed finding is a decision, not a failure

An analysis's SARIF contains **every result in that upload, including findings
already triaged**, and `results_count` counts them. Converting the SARIF alone
republishes closed dismissals as live failures on every run, forever.

SARIF has a `suppressions` array for exactly this. `saf convert sarif2hdf`
**ignores it** — verified against the pinned image, where a suppressed result
still converts to `failed`. So the disposition is applied afterwards, by
`tools/apply_dispositions.py`:

| Alert state | HDF result | Carries |
|---|---|---|
| `open` | `failed` | the finding |
| `dismissed` | `skipped`, control impact `0.0` → **Not Applicable** | who dismissed it, when, why |
| `fixed` | `passed` | found and remediated |
| unmatched | untouched, and **reported** | — |

Unmatched results are never silently dropped. A dropped result is
indistinguishable from a finding that was never there.

The `impact: 0.0` matters as much as the status. Status alone renders as
*Skipped*, which reads as "nobody looked"; the pair is what HDF rolls up as
*Not Applicable*.

---

## Setting it up in a repository

### 1. Turn the capabilities on

| Capability | Public repo | Private repo |
|---|---|---|
| Code scanning | free | needs Code Security licensing |
| Secret scanning | free | needs Code Security licensing |
| **Dependabot alerts** | free | **free — just a toggle** |

Dependabot alerts are worth doing immediately whatever you decide about
licensing:

```bash
gh api -X PUT repos/<owner>/<repo>/vulnerability-alerts
```

A capability that is off is reported with the platform's own message and is
**never** counted as clean.

### 2. Add a caller workflow

The bridge is a reusable workflow. Call it — do not copy it. A copied workflow
needs one PR per repository to correct.

```yaml
# .github/workflows/dashboard-hdf-emit.yml
name: Dashboard HDF emit

on:
  push:
    branches: [main]
  schedule:
    - cron: '0 6 * * *'
  workflow_dispatch:

permissions:
  contents: read
  security-events: read
  id-token: write

jobs:
  bridge:
    uses: risk-sentinel/dev-sec-ops-baseline/.github/workflows/dashboard-hdf-emit.yml@v0.3.0
    with:
      boundary: ${{ vars.EVIDENCE_BOUNDARY || 'sparc' }}
    secrets:
      S3_EMIT_ROLE_ARN: ${{ secrets.MY_REPO_EMIT_ARN }}
      AWS_REGION: ${{ secrets.AWS_REGION }}
      COMPLIANCE_S3_BUCKET: ${{ secrets.COMPLIANCE_S3_BUCKET }}
      DOCKERHUB_USERNAME: ${{ secrets.DOCKERHUB_USERNAME }}
      DOCKERHUB_TOKEN: ${{ secrets.DOCKERHUB_TOKEN }}
```

Three things that will bite you if changed:

- **`security-events: read`** is required. Without it the alert endpoints answer
  403 and every capability reads as disabled.
- **Do not add a job-level `environment:`.** It flips the OIDC subject to
  `environment:NAME`, and emit roles are trust-pinned to `refs/heads/main`, so
  the assume fails.
- **The schedule is not decoration.** A newly published advisory raises a
  Dependabot alert on code nobody touched. A push-only bridge reports the
  posture as of the last commit and presents it as current.

The emit secret is the repository's own `{REPO}_EMIT_ARN`, so a compromised
repository can only write its own prefix. If it is missing, it resolves empty,
the credential step is skipped, and the job warns loudly rather than passing
silently — but nothing reaches the bucket.

### 3. What lands in the bucket

```
<boundary>/<date|latest>/<repo>/dashboard/provenance.json          every run
<boundary>/<date|latest>/<repo>/code-scanning/code-scanning-<lang>-hdf.json
<boundary>/<date|latest>/<repo>/secret-scanning/secret-scanning-hdf.json
<boundary>/<date|latest>/<repo>/dependabot/dependabot-hdf.json
```

Only `provenance.json` is unconditional. The HDF files appear when there is
something live to report.

### 4. Reading the job log

`saf view summary` runs for every converted document, in the log, not only in
the artifact — a file holding nothing and a conversion that silently failed
produce identical green checks otherwise. The step summary carries a
source-by-source table from the provenance record.

---

## The controls

All four need `run_mode: control-plane` or `both`, and a GitHub token.

### `devsecops-code-scanning-executed`

**Passes** when every declared repository with code scanning enabled has an
analysis on its protected branch, for **every language it scans**, newer than
`evidence_freshness_days`.

Per language deliberately: CodeQL records one analysis per language per run, so
checking only the newest analysis reports a repository as scanned when a single
language ran and the rest stopped.

**Fails** on a disabled capability (with the platform's message), on no analysis
for the ref, or on staleness — naming the language and its last run.

`RA-5`, `RA-5(2)`, `SA-11`, `SA-11(1)`, `SI-2`

### `devsecops-dashboard-open-findings`

**Passes** on zero open alerts across all three dashboards, per repository.

Dismissed alerts are excluded — that is a separate question, asked below. Fixed
alerts are excluded because remediation is the outcome we wanted. A capability
that is off yields *not evaluated*, never a zero, so "nothing found" and "nobody
looked" cannot collapse into the same number.

`RA-5`, `SI-2`, `SI-3`, `IA-5(7)`

### `devsecops-dismissals-accountable`

**Passes** when every dismissed code-scanning alert records **who** dismissed it
and **why**.

This is the control that makes dismissal a legitimate answer. An accepted risk
with a name and a reason attached is a decision; one without either is
indistinguishable from a finding quietly closed, and it is the first thing an
assessor asks about.

`RA-5(5)`, `CA-5`, `PM-4`, `SA-11`

### `devsecops-push-protection-bypasses`

**Passes** when no secret-scanning alert records a push-protection bypass.

Separated from findings on purpose. A bypass is not a scanner result — it is a
person who was shown a block and continued. Buried in an alert list it reads as
one more finding.

`IA-5(7)`, `AC-6`, `AU-2`, `SI-4`

---

## Intentionally vulnerable fixtures

Repositories that test their own scanners pin deliberately vulnerable
dependencies, and those raise alerts identical to real ones. Left alone, such a
repository fails `devsecops-dashboard-open-findings` permanently — and a control
that can never pass gets ignored.

**Dismiss them in GitHub with a reason** (`not_used` or `tolerable_risk`) rather
than adding an exclusion list to the profile inputs. The dismissal records who
decided and why, in the platform, where it can be audited; an exclusion path
records only that someone once decided not to look. The reconciler then renders
them Not Applicable with the reason attached, and
`devsecops-dismissals-accountable` checks the reason is really there.

Pair it with a `.github/dependabot.yml` that does not open update PRs against
the fixture paths, or Dependabot will keep proposing to fix the fixtures.

---

## Running the bridge by hand

```bash
# Fetch the dashboards -> SARIF + provenance + dispositions
docker run --rm -v "$PWD:/work" -w /work -e GITHUB_TOKEN \
  --entrypoint /opt/cinc-workstation/embedded/bin/ruby \
  risksentinel/sparc-auditor:v0.5.0 \
  tools/bridge.rb --repo <owner>/<name> --out bridge-out

# Convert, then apply dispositions to the code-scanning output
docker run --rm -v "$PWD:/work" -w /work --entrypoint saf \
  risksentinel/sparc-auditor:v0.5.0 \
  convert sarif2hdf -i bridge-out/code-scanning-ruby.sarif -o out.json

python3 tools/apply_dispositions.py \
  --hdf out.json --dispositions bridge-out/dispositions.json
```

Paths are confined to the working directory. `--base DIR` widens that
deliberately — the arguments are assembled by a workflow from a repository
name, and the tool writes its output, so a `../..` would otherwise choose which
file gets rewritten.

Fixture tests for the mapper, including the redaction assertions:

```bash
ruby tests/mapper_test.rb            # assertions only
ruby tests/mapper_test.rb ./sarif    # also export SARIF for a converter round-trip
```

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| Every capability reads `disabled` | `security-events: read` missing from `permissions:` |
| `Code Security must be enabled` | Private repository without licensing. Real, and reported as such — not a pass |
| Enumeration finds 16 repositories, not 21 | Token cannot see private repositories. Asserted directly by `devsecops-inventory-reconciliation`, which fails on the credential rather than reporting the invisible repositories as stale declarations |
| Nothing in the bucket, job green | Emit role secret missing or misnamed — it resolves empty and the upload is skipped. The job logs a warning; the artifact is still attached to the run |
| `unmatched` results in the reconciler | A finding could not be tied to an alert, so its disposition is unknown and it is reported at face value. `--check` makes that fatal |

---

## Known limitation

SARIF has no `critical` level. Critical and high Dependabot findings both
convert at impact `0.7`, so the HDF rollup cannot distinguish them. The severity
is preserved in `properties.severity` and in the rule's `security-severity`.
