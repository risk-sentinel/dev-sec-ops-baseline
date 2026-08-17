# Meeting a team where they are

Three ways evidence reaches this profile. None of them requires a team to change
their pipeline first.

---

Evidence reaches this profile three ways. A team adopts whichever matches how
they already work — none of them requires changing their pipeline first.

| Their situation | Mode | What they set |
|---|---|---|
| Scans run in CI; reports land on the runner | `pipeline` | `artifact_dir` — the directory their scanners write to |
| They already aggregate evidence to a store | `control-plane` | `evidence_bucket` + `evidence_key_template` |
| They rely on platform features (code scanning, SonarCloud) | `control-plane` | tokens |
| All of the above | `both` | all of the above |

### In-pipeline: point at the directory

Add the profile as a dependency and `include_controls` it, then pass the
directory the scanners already write to. Filenames are matched by **glob**, so
timestamped and target-tagged names work as-is:

```bash
cinc-auditor exec . -t local:// \
  --input-file inputs/<your-declaration>.yml \
  --input run_mode=pipeline artifact_dir=./reports
```

`trivy-2026-08-15.json`, `grype-20260815T1000.json` and `sast-codeql.sarif` all
match without anyone renaming anything.

### Already aggregating: point at the storage

A team with an existing evidence store should not have to re-file it. Override
the key layout instead:

```yaml
evidence_bucket: their-security-evidence
evidence_key_template: 'security-evidence/{repo}/{source}/{slot}.hdf.json'
evidence_lookback_days: 7
```

Placeholders are `{boundary}` `{slot}` `{repo}` `{source}`. `{slot}` is required
— it is what separates the current pointer from a dated object, and without it
every lookback candidate would resolve to the same key and stale evidence would
read as current.

### Credentials for reading the store

The profile does **not** assume a role. Like every other AWS-touching InSpec
profile, it uses whatever credentials the runner already holds — so the caller
assumes the read role before InSpec starts, typically with
`aws-actions/configure-aws-credentials`.

Reads are deliberately asymmetric to writes. Writers are per-repository
(`{REPO}_EMIT_ARN`) so a compromised repository can only write its own prefix.
Readers are a short explicit list — one ARN each for the two repositories that
consume the bucket — so *who can see the estate's evidence* stays auditable.

The read role needs `s3:GetObject` **and `kms:Decrypt`** on the bucket CMK.
`GetObject` alone on an encrypted bucket fails as an `AccessDenied` that looks
exactly like a missing object, which would report a scanned repository as
unevidenced. `evidence_store` raises on that rather than reporting absence, so
it surfaces as a control error — but granting both together avoids debugging it
at all.

### What shape is the evidence in?

Both are supported, because insisting on converted HDF would make this surface
useful only to the teams who least need it.

| `evidence_format` | Expects | Who |
|---|---|---|
| `hdf` | Converted HDF — `baselines[]` or `profiles[]` | Teams already running the conversion |
| `native` | Raw scanner output, identified by the same structural marker the artifact surface uses | Teams aggregating what their scanners emit |
| `auto` *(default)* | Either | Mixed estates |

Native TruffleHog output is JSONL rather than a JSON document; it is detected by
parsing the first record, so a whole-file parse failing is not treated as
corrupt evidence.

### Attribution, and what happens without our labels

Evidence we emit carries `repo`, `commit`, `ref` and `run_id` labels, so the
file corroborates the key path it was filed under. Evidence from **your** store
will not — we did not write it. That is expected, not a failure:

| State | Meaning | Result |
|---|---|---|
| Corroborated | Labels present and agree with the path | Pass |
| Path-only | No labels; attribution rests on the key path convention | **Pass**, and the result says so |
| Contradicted | Labels name a *different* repository | **Fail, always** |

A contradiction fails regardless of policy. Evidence filed under the wrong
repository is worse than absent, because it credits the wrong thing. Only the
treatment of *absent* labels is configurable, via `evidence_require_labels`
(default `false`).

---

---

## A clean scan still produces evidence

A scanner that finds nothing produces nothing to convert — `hdf convert` errors on
empty input. The obvious response is to skip the upload, and that is what this
repository's secret-scan emit did for months.

It is the wrong response, and the reason is worth stating plainly: **a clean
repository and a broken pipeline then leave byte-for-byte identical state in the
bucket.** Nothing. Fourteen repositories sat that way, and the coverage control read
every one of them as unevidenced while the scans were in fact running fine — 20 of
21 repositories failing secrets coverage for a defect in the *recording*, not the
scanning.

So a clean run now emits a one-control HDF recording the **execution**: which
scanner, at what version, over which commit, in which mode, reporting zero findings.
See [`tools/scan_receipt.py`](../tools/scan_receipt.py).

### Why that is not fabricating a result

It asserts that a scan *ran*, which is an observed fact about the run, and it says so
in the control description rather than implying it. It does not assert that anything
was or was not found beyond the count the scanner itself reported.

The distinction matters against the code-scanning case, which is handled the opposite
way. There, the "ran clean" claim is made by a *control* that queries the API, because
GitHub can still answer "what did CodeQL find last Tuesday" long afterwards. **Nothing
can answer whether TruffleHog ran in a pipeline last Tuesday.** The run is the only
witness, so the record has to be written while it is true or it is not recoverable.

It also renders correctly: one passing control reads as `compliance: 100`, where an
empty profile reads as `compliance: 0` — a team doing exactly what it should
publishing a zero.

### Wiring it up

```yaml
jobs:
  emit:
    uses: risk-sentinel/dev-sec-ops-baseline/.github/workflows/secret-scan-hdf.yml@<release-tag>
    permissions:
      contents: read
      id-token: write
    secrets:
      S3_EMIT_ROLE_ARN: ${{ secrets.MY_REPO_EMIT_ARN }}
      AWS_REGION: ${{ secrets.AWS_REGION }}
      COMPLIANCE_S3_BUCKET: ${{ secrets.COMPLIANCE_S3_BUCKET }}
```

The object lands at the exact key the `evidence_store` surface heads:
`<boundary>/<date|latest>/<repo>/trufflehog/trufflehog-hdf.json`.

One trap worth knowing if you write your own emit: **do not call `hdf validate`.**
hdf 3.4.1 validates the newer `baselines[]` schema and rejects the legacy
`profiles[]` that every saf converter emits, so the call fails on real converter
output. Assert the shape you actually need instead — that it parses, and carries at
least one control with at least one result.
