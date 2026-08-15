# Operate

**Scan types:** `runtime` (post-deployment validation)

## What is expected

| Expectation | Surface | NIST 800-53r5 |
|---|---|---|
| Scanning capabilities enabled, not merely available | Platform API | `RA-5`, `SI-5` |
| The vulnerability dashboard is populated and read | Platform API | `RA-5`, `CA-7` |
| Findings remediated within policy timeframes | Platform API | `RA-5(2)`, `SI-2` |
| Deployed-resource configuration assessed continuously | Artifact | `CA-2(2)`, `CA-7`, `CM-6` |

## The SDLC does not end at deploy

A pipeline that was clean at build time says nothing about the running estate.
Configuration drifts, resources are created outside the pipeline, and controls that
passed at merge can be switched off in production a week later. Evidence that stops at
the deploy step claims more than it checked.

`runtime` is therefore a scan type in its own right, not a footnote:

| Tool | What it validates | Surface |
|---|---|---|
| InSpec / CINC baselines | Deployed resources against our own CIS, STIG and bespoke profiles | Artifact |
| AWS Config | Configuration compliance of live resources | Artifact + platform API |
| AWS Security Hub | Aggregated findings across the account | Artifact + platform API |
| Prowler | Account-level posture assessment | Artifact |

The existing `artifact-inspec-deployed` control belongs to this scan type. It confirms
that the *other* InSpec run — the one against live infrastructure — delivered its
results into the pipeline. It deliberately does not assert that run passed: that is the
deployed profile's job, and conflating "the assessment happened" with "the assessment
was clean" is the same category error as treating an artifact's existence as evidence
of what it contains.

### Declared, never inferred

Post-deployment validation is declared per repository like every other scan type. It is
tempting to infer it — "this repo deploys infrastructure, so of course it is assessed"
— but inference produces exactly the false maturity signal the whole declaration model
exists to prevent. A repository that deploys and is *not* assessed afterwards should
say so and attest to it.

## Enablement is checked before findings, always

An alert count of zero means two completely different things depending on whether
scanning is switched on. Querying findings without first establishing enablement lets
a repository nobody scans report as clean.

The platform APIs make this trap easy to fall into, because a disabled capability does
not answer "disabled" — it returns an HTTP error that a careless client treats as an
empty list:

```
code scanning    -> 403  "Code Security must be enabled"
Dependabot       -> 403  "Dependabot alerts are disabled"
secret scanning  -> 404  "Secret scanning is disabled"
```

The `github_security` resource therefore reports a three-state value — enabled,
disabled, or error — and never a bare boolean. Both non-enabled states fail, with
different messages, because they have different owners: *disabled* is a configuration
or licensing action, *error* is a broken scan or a bad token.

## Free versus licensed capabilities

On public repositories, code scanning and secret scanning are available at no cost, so
an enabled result there reflects a platform default rather than a deliberate decision.
On private repositories those two require paid licensing, while Dependabot alerts
remain a free toggle. A remediation plan that treats all three as one switch will
stall on the wrong blocker.
