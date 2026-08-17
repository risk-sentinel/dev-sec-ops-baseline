# Code

**Scan types:** `sast`, `secrets`, `iac`

## What is expected

| Scan type | Expectation | NIST 800-53r5 |
|---|---|---|
| `sast` | Static analysis runs on every change, not only on the default branch | `SA-11(1)` |
| `secrets` | Secrets detection covers git history, not just the working tree | `IA-5(7)`, `SA-11` |
| `iac` | Declarative infrastructure is scanned for misconfiguration as source | `CM-2`, `CM-6`, `RA-5` |

## Shift-left is a trigger question, not a tooling question

Running a SAST tool proves nothing about *when* it runs. A scanner wired to fire only
after merge finds problems that are already on the default branch, which is the
opposite of shifting left.

That distinction is only visible on the **repo contents** surface: whether the scan
fires on a merge request is a fact about a YAML file, readable through the contents
API, not through any security endpoint. It is why `repo_contents` exists as a surface
in its own right rather than being folded into the platform API.

## Secrets: two different things share one name

- **Detection** finds a credential in the history. It is retrospective; by the time it
  fires, the secret has been committed and must be rotated.
- **Push protection** blocks the commit. It is preventive.

A repository with detection but not push protection is materially weaker than one with
both, so the profile records them separately rather than collapsing them into
"secret scanning: on".

A **bypass** is a third thing again, and it is not a scanner result: it is a person
who was shown a block and continued, so the credential reached the repository with a
human decision behind it. `devsecops-push-protection-bypasses` reports those on their
own rather than among the findings, where they would read as one more alert.

## What happens to a finding after it is raised

A dismissed alert is a decision that was made, not a risk that was missed. Failing on
it would have the evidence package re-litigate settled triage on every run, which is
how a report stops being read.

So dismissals are asserted on a different axis: not *are there any*, but *does each one
record who accepted the risk and why*. An accepted risk with a name attached is a
decision; one without either is indistinguishable from a finding quietly closed, and it
is the first thing an assessor asks about. That is `devsecops-dismissals-accountable`.

The evidence keeps them rather than filtering them out — rendered Not Applicable,
carrying the dismisser, the date and the reason. See
[the dashboard bridge](../dashboard_bridge.md) for how the disposition is applied, and
why it has to happen after conversion rather than in the SARIF.
