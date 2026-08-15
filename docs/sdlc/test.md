# Test

**Scan types:** `dast`, `iast`

## What is expected

| Scan type | Expectation | NIST 800-53r5 |
|---|---|---|
| `dast` | A running instance exercised from the outside | `SA-11(8)`, `RA-5`, `CA-8` |
| `iast` | Instrumented analysis of the running application | `SA-11(9)` |

NIST 800-53r5 names both of these precisely: `SA-11(8)` is Dynamic Code Analysis and
`SA-11(9)` is Interactive Application Security Testing. The mapping needs no
interpretation.

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
