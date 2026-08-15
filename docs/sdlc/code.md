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
