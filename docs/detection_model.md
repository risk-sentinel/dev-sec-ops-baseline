# How the profile decides what to check

The registry says what this profile *can* detect. Your declaration says what your
organisation *runs*. Controls evaluate the intersection, and the denominator is
verified against the forge rather than against the file that claims it.

---

## How it decides what to check

Two files, doing two different jobs. Controls evaluate the **intersection**.

| | [`files/tool_registry.yml`](../files/tool_registry.yml) | [`inputs/*.yml`](../inputs/) |
|---|---|---|
| Answers | What *can* this profile detect, and where? | What does *my* organisation run? |
| Owned by | The profile | You |
| Changes when | We add detection capability | A team adopts a tool |

### The rule that makes the results trustworthy

**Every scan type is declared for every repository — `enabled: true` or `enabled: false`.
There is no "leave it out" option.**

Omitting a scan type would render as *Not Applicable*, which reads as "does not apply
here" rather than "nobody has looked." In an assessment that is a false maturity
signal. An explicit `enabled: false` instead produces a **skip** carrying
*"not enabled and must be manually verified and attested to"* — which the SAF
attestation flow can satisfy with a real, signed rationale.

That gives three outcomes, and they are deliberately distinguishable in HDF:

| Declaration | Registry | Result |
|---|---|---|
| `enabled: true` | detectable today | **Real check** — pass or fail |
| `enabled: false` | — | **Skip**, attestation candidate. A statement about *your repository* |
| `enabled: true` | not built yet | **Skip**, coverage gap. A statement about *this profile* — an attestation must not paper over it |

The same principle governs the repository list. See [the denominator](#the-denominator-trust-but-verify).

---

## The denominator (trust, but verify)

A declaration file cannot be the evidence that it is complete. If `targets` were both
the claim and the scope, a repository nobody added would be invisible.

So reconciliation enumerates the organisation **through the forge API** and compares
it against what the file declares:

| Condition | Result |
|---|---|
| In the organisation, neither declared nor excluded | **Fail** — undeclared repository |
| Declared, no longer in the organisation | **Fail** — stale declaration |
| Excluded with no written reason | **Fail** — undocumented exclusion |

Archived, fork, and template repositories are **not** auto-excluded. Churn in the input
file when a repository is archived is the intended cost of never silently dropping
something out of the denominator.

---

---

Surfaces, run modes and the generated coverage tables live in
[coverage.md](coverage.md).
