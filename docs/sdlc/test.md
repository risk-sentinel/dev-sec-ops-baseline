# Test

**Scan types:** `dast`, `iast`, `test_execution`

## What is expected

| Scan type | Expectation | NIST 800-53r5 |
|---|---|---|
| `dast` | A running instance exercised from the outside | `SA-11(8)`, `RA-5`, `CA-8` |
| `iast` | Instrumented analysis of the running application | `SA-11(9)` |
| `test_execution` | Developer test suites ran over the commit, with measured coverage | `SA-11` |

NIST 800-53r5 names both of these precisely: `SA-11(8)` is Dynamic Code Analysis and
`SA-11(9)` is Interactive Application Security Testing. The mapping needs no
interpretation.

## Test execution is not IAST, and the distinction is load-bearing

`test_execution` and `iast` sit next to each other in the coverage table and are
easy to conflate. They are not the same claim:

- **Coverage** says which lines executed.
- **A test suite** says whether behaviour was correct.
- **IAST** says untrusted input reached a dangerous sink.

The first two are evidence that developers tested the software. Only the third is a
security analysis. Mapping test output to `iast` would have the profile assert
coverage it does not have — the single failure mode the declared-gap model exists to
prevent.

There is also a practical reason to care which one you are chasing. Checked against
the OSCAL baseline seeds: **`SA-11` base is selected in the FedRAMP Moderate
baseline, and `SA-11(9)` is not.** So the evidence a pipeline already produces maps
to a control that is actually required, while IAST — the harder, unbought thing —
maps to one that is not.

### Coverage is recorded, never gated

`tools/test_evidence.py` emits coverage with `impact 0.0`, which renders as Not
Applicable rather than as a pass or a failure. Turning a percentage into a control
invents a threshold nobody agreed to, and the conversation becomes "is 78%
compliant" instead of "was this tested". If a threshold is wanted it belongs in a
declared input, defaulting to off.

### Granularity

One control per **suite**, not per test case. A few thousand examples mapped to
controls would swamp Heimdall and tell an assessor nothing. A clean suite is one
control with one passing result; a failing suite additionally gets one result per
failure, so failures stay individually visible where that matters.

## IAST is an open gap, stated rather than hidden

**No tooling anywhere in this organisation performs IAST today.**

The scan type is kept in the registry with no tools attached, and the generated
coverage table renders it as an empty row with an explicit note. Removing the row
would be tidier and would imply the concept does not apply here — which is a
different claim, and a false one. An empty row says nobody performs it; an absent row
says it was never considered.

## DAST evidence arrives pre-converted

DAST runs from a dedicated repository against a deployed environment, and its output
reaches this profile already in HDF rather than as a raw scanner report. The registry
records `hdf` as the artifact format for that reason — the validity marker is the HDF
`profiles[]` structure, not a vendor schema.
