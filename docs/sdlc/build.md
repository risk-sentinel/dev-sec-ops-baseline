# Build

**Scan types:** `sca`, `sbom`, `container`, `licensing`

## What is expected

| Scan type | Expectation | NIST 800-53r5 |
|---|---|---|
| `sbom` | A valid CycloneDX or SPDX bill of materials per build | `SR-3`, `SR-4` |
| `sca` | Known-vulnerable dependencies identified | `RA-5`, `SA-11(1)`, `SR-3` |
| `container` | The built image scanned for vulnerabilities and misconfiguration | `RA-5`, `CM-6`, `SR-3` |
| `licensing` | Acquired and reused components licence-reviewed | `SR-3`, `SA-4` |

## SCA and container scanning are the same tools pointed at different things

Grype and Trivy appear under both. That is not duplication in the registry — it is the
actual situation. The axis separating them is the **target**, not the tool: source
dependency manifests versus a built image layer set. A repository can do one and not
the other, and conflating them would let a dependency scan stand in as evidence that
images are scanned.

`dependency` is accepted as an alias for `sca`, because GitLab names the same concern
"Dependency Scanning". The registry resolves the alias once so both spellings cannot
drift apart in the codebase.

## Why several SCA tools are reasonable

They sit at different layers and draw on different vulnerability databases. Grype is
fast and SBOM-driven; Trivy adds misconfiguration, secrets, and licence in one pass;
Snyk brings commercial database depth; Sonatype does policy governance — approve or
deny — rather than detection alone. Running more than one is a defensible choice, not
redundancy, and the profile records which ran rather than assuming one implies another.

## Licensing is governance, not scanning

The useful question is not "which licences are present" but "who approved them, and
against what policy". The declaration records the reviewing source so a SAR shows not
only that licence review happened but who performed it.
