# GitLab

What this profile reads on GitLab, what it deliberately does not, and why the
merge-rule resolution is more involved than GitHub's.

> **Not exec-validated.** Every repository in this organisation is on GitHub and
> there is no GitLab instance to run against. `gitlab_security` ships
> fixture-tested only — 55 assertions in
> [`tests/gitlab_security_test.rb`](../tests/gitlab_security_test.rb), run in CI.
> That label is stated rather than implied: `cinc-auditor check` and `json` only
> **load** a library, they never call a method on it, and this profile has
> already shipped a defect that got past both.

---

## Declaring a GitLab target

`forge:` resolves most-specific-first — the target, then `defaults`, then
`organization`. There is no final fallback: a declaration that names no forge
anywhere is a declaration that never said what it is describing, and defaulting
it would silently read the wrong platform.

```yaml
organization:
  forge: gitlab
  name: my-group          # a full group path, subgroups included

defaults:
  forge: gitlab

targets:
  - repo: my-group/my-project    # path with namespace, as GitLab writes it
```

Credentials: `gitlab_token` as an input, or `GITLAB_TOKEN` in the environment.
Sent as `PRIVATE-TOKEN`, the personal / group / project access-token header —
OAuth tokens use `Authorization: Bearer` and the two are **not** interchangeable.

An unauthenticated `GET /groups/:id/projects` answers `200` and simply omits
everything private. The denominator comes back **short, not broken**, and
reconciliation then reports real projects as stale declarations. `enumeration_trust`
names which case you are in.

## Merge-request rules live in three places

This is the part that makes GitLab harder than GitHub, and the reason this
resource exists rather than a few extra methods on the existing one.

| | Where | Read from |
|---|---|---|
| 1 | **The project** | `approval_rules`, `approvals`, `protected_branches`, `push_rule` |
| 2 | **The group** | `GET /groups/{id}/protected_branches` |
| 3 | **A linked security policy project** | GraphQL `project.securityPolicyProject`, then that project's `.gitlab/security-policies/policy.yml` |

**Layer 2 is invisible from the project.** GitHub's repository endpoint returns
parent rulesets by default, so org-level rules arrive for free. GitLab does not
fold them in. A project can look entirely unconfigured while being fully
governed from above.

**Layer 3 is the one that breaks naive readings.** Merge-request approval
policies and scan execution policies are authored as YAML in a *separate*
project and applied to the target. The rules governing project A live in
project B. Reading A tells you nothing at all.

Both are the same shape as the defect this profile already shipped once on
GitHub: **read one place, conclude about the whole.** `github_security` read
classic branch protection only, five of seven repositories kept their rules in
rulesets, and the control would have reported the entire estate unprotected.

### Attribution, not just a number

`governance_sources(branch)` names which layer supplied each rule. A rule set in
a policy project **cannot be weakened by the project maintainer**, which is a
materially stronger guarantee than the same rule set locally. An assessment that
cannot tell them apart is worth less than one that can.

### Four policy-project outcomes, kept distinct

| State | Meaning | What it says about the project |
|---|---|---|
| `:none` | No policy project is linked | It is not governed this way |
| `:unreadable` | Linked, and we cannot read it | **Nothing.** This is about our access |
| `:out_of_scope` | Readable, but no enabled policy scopes here | It is not governed this way |
| `:applies` | Readable, and at least one policy scopes here | It is governed from the policy project |

`:unreadable` must be surfaced as a control **error**, following the
`evidence_store` precedent — never as absence. A project with no rules and a
project we cannot see are different findings, and only the first is a finding
about the project.

A policy with **no** `policy_scope` block applies to the whole linked group. An
absent scope means "applies here", not "applies nowhere"; reading it the other
way would silently drop the most common configuration.

## What is read, per question

| Question | GitHub | GitLab |
|---|---|---|
| Required reviews / approvals | ✅ | ✅ across all three layers |
| Signed commits | ✅ | ✅ via push rules |
| CODEOWNERS present and enforced | ✅ | ✅ (root, `docs/`, `.gitlab/`) |
| Project / group enumeration | ✅ | ✅ including subgroups |
| Repository contents | ✅ | ✅ |
| Required **status checks** | ✅ | ❌ |
| Ruleset enforcement mode | ✅ | ❌ |
| Shift-left trigger attribution | ✅ | ❌ |
| Forge-native capability state | ✅ | ❌ |
| Security dashboard bridge | ✅ | ❌ |

A ❌ is a **named skip**, never a silent pass and never a probe against the
wrong API. The message names the forge and the capability so it is a coverage
gap someone can act on.

### Why `required_checks` is a gap and not a pass

GitLab *can* gate merges on a pipeline — `only_allow_merge_if_pipeline_succeeds`
— and `gitlab_security` reads it. But that control asserts something stronger:
that a **declared security tool** is among the required contexts. A repository
can require checks that include no security scan at all, and the control exists
to catch exactly that.

GitLab exposes no context names to check against, only the boolean. Passing the
control on the weaker fact would be an overclaim wearing a stronger control's
id, so it is recorded as a gap instead.

### Why the dashboard bridge is a gap

GitHub exposes code scanning, secret scanning and Dependabot as three endpoints
with three enablement states and three failure codes. GitLab funnels the
equivalents through one vulnerability-findings endpoint with a different shape.
Those are not the same question asked twice, and a shared interface over them
would be a shared *name* over two different claims.

## Wildcards and nested groups

Protected-branch names may be wildcards, so `release/*` covers `release/1.2` —
an equality test would report that branch unprotected while a rule covers it.

A namespace can nest several levels deep, so the group is everything above the
final path segment. `split('/').first` would look up the top-level group and
miss a subgroup's protected branches entirely.

## Known gaps

- Group-level **approval settings** are not read; only group protected branches
  are. Group approval settings are an EE endpoint with a different shape.
- `group_required_approvals` returns `nil` rather than a number. A branch nobody
  may merge to directly is a governance fact, but it is not an approval
  requirement, and inventing a count would be worse than reporting none.
- The coverage controls' `platform_api` surface fails rather than skips on a
  forge that cannot answer. The registry models coverage gaps per tool and
  surface, not per forge; making that forge-aware is a schema change.
