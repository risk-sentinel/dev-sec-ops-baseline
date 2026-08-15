# Operate

**Scan types:** none directly. This stage is about *monitoring what the earlier stages
produced*.

## What is expected

| Expectation | Surface | NIST 800-53r5 |
|---|---|---|
| Scanning capabilities enabled, not merely available | Platform API | `RA-5`, `SI-5` |
| The vulnerability dashboard is populated and read | Platform API | `RA-5`, `CA-7` |
| Findings remediated within policy timeframes | Platform API | `RA-5(2)`, `SI-2` |
| Deployed-resource configuration assessed continuously | Artifact | `CA-2(2)`, `CA-7`, `CM-6` |

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
