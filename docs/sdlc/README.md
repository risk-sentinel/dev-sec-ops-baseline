# SDLC stage reference

What each stage of the software development lifecycle is expected to produce, and
how this profile verifies it.

| Stage | Scan types | Reference |
|---|---|---|
| Plan and Design | _(none automated)_ | [plan.md](plan.md) |
| Code | `sast`, `secrets`, `iac` | [code.md](code.md) |
| Build | `sca`, `sbom`, `container`, `licensing` | [build.md](build.md) |
| Test | `dast`, `iast` | [test.md](test.md) |
| Deploy | _(gating, not scanning)_ | [deploy.md](deploy.md) |
| Operate | _(monitoring)_ | [operate.md](operate.md) |

The authoritative machine-readable mapping is [`files/tool_registry.yml`](../../files/tool_registry.yml);
these pages explain the intent behind it. Coverage tables in the root
[README](../../README.md) are generated from the registry — never hand-edited.

## A note on reading these pages

Each page lists the scan types expected at that stage and the surface each is
detectable on. "Expected" is not the same as "enforced": whether your pipeline runs
a given scan is your declaration to make in `inputs/`, and a scan declared
`enabled: false` produces a skip that must be attested to, not a silent absence.
