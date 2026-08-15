# Deploy

**Scan types:** none. This stage is about *gating*, not scanning.

## What is expected

Nothing reaches the default branch without passing the checks the earlier stages
produce. That is a property of the forge's merge rules, not of any scanner.

| Expectation | Surface | NIST 800-53r5 |
|---|---|---|
| Required status checks include the security scans | Platform API | `CM-3`, `SA-10` |
| Reviews required before merge | Platform API | `SA-11(4)`, `CM-3` |
| Rulesets active, not merely present | Platform API | `CM-2`, `CM-6` |
| Signed commits required | Platform API | `SI-7`, `SR-4` |
| CODEOWNERS covers the security-relevant paths | Repo contents | `SA-15(7)` |

## The merge-rules question splits across two surfaces

This is the clearest case for keeping the surfaces distinct:

- *Are reviews required?* — platform state. A token reads it from the protection or
  approval-rules endpoint.
- *Does the security scan run on the merge request at all?* — repository content. It
  is a fact about a workflow file, and no security endpoint reports it.

A repository can require status checks that do not include any security scan, which
looks strong on the API surface and is hollow in practice. Reading only one surface
would miss that entirely.

## A ruleset that exists but is not enforced

Rulesets carry an enforcement status. One in evaluate mode reports its name happily
while blocking nothing. The profile asserts on enforcement, not existence — presence
is not the same as effect, which is the same error as treating a scan artifact's
existence as evidence the scan found nothing.
