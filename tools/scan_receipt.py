#!/usr/bin/env python3
"""Emit a one-control HDF recording that a scan ran and found nothing.

    scan_receipt.py --scanner trufflehog --repo owner/name --sha abc123 \
                    --ref refs/heads/main --run-id 42 --findings 0 \
                    --out receipt-hdf.json

Why this exists
---------------
A scanner that finds nothing produces nothing to convert — `hdf convert` errors
on empty input. The previous emit workflow therefore skipped the upload on a
clean scan, which left the evidence bucket byte-for-byte identical whether the
scan ran clean or the workflow was broken. Fourteen repositories sat in that
state, and the coverage control read every one of them as unevidenced.

Why a passing control rather than a bare receipt
------------------------------------------------
Two reasons, and the second is the one that decides it.

Heimdall renders an HDF profile with zero controls as `compliance: 0`, so a
clean repository would publish a zero. One passing control renders as what it
is.

And unlike code scanning, **there is no API to ask afterwards.** GitHub can be
queried for what CodeQL found last Tuesday; nothing can be queried for whether
TruffleHog ran in a pipeline. The run is the only witness, so the claim has to
be recorded at the point it is true or it is not recoverable.

What this does and does not assert
----------------------------------
It asserts an EXECUTION: this scanner, at this version, over this commit, in
this mode, reported this many findings. Every one of those is an observed fact
about the run, carried in the control description so the claim is legible
rather than implied.

It does NOT synthesise a finding, and it must never be used to manufacture a
pass for a scan that did not run. If the scanner errored, the workflow should
fail — a receipt saying "ran clean" for a scan that crashed is the exact defect
this file exists to remove.
"""

import argparse
import hashlib
import json
import sys

# Secrets detection maps to these regardless of which scanner produced it.
SCANNER_TAGS = {
    "trufflehog": ["IA-5(7)", "SA-11"],
    "gitleaks": ["IA-5(7)", "SA-11"],
}
DEFAULT_TAGS = ["SA-11"]


def build(scanner, repo, sha, ref, run_id, findings, version, mode, timestamp):
    detail = (
        f"{scanner}"
        + (f" {version}" if version else "")
        + f" scanned {repo} at commit {sha or 'unknown'}"
        + (f" on {ref}" if ref else "")
        + f" in {mode} mode and reported {findings} finding(s)."
    )

    control = {
        "id": f"{scanner}-executed",
        "title": f"{scanner} executed and reported no findings",
        "desc": (
            f"{detail}\n\n"
            "This records an EXECUTION, not a finding. It is evidence that the "
            "scan ran over this commit and returned clean — the claim a clean "
            "repository can otherwise never make, because a scanner that finds "
            "nothing produces nothing to convert and an empty prefix is "
            "indistinguishable from a broken pipeline.\n\n"
            "There is no API that can answer this after the fact the way a code "
            "scanning dashboard can, so the run is the only witness and the "
            "record has to be written when it is true."
        ),
        "impact": 0.5,
        "refs": [],
        "tags": {
            "nist": SCANNER_TAGS.get(scanner, DEFAULT_TAGS),
            "scanner": scanner,
            "repository": repo,
            "commit": sha,
            "ref": ref,
            "run_id": str(run_id) if run_id else None,
            "scan_mode": mode,
            "findings": findings,
        },
        "code": "",
        "source_location": {"ref": f"tools/scan_receipt.py ({scanner})", "line": 0},
        "results": [
            {
                "status": "passed",
                "code_desc": detail,
                "start_time": timestamp,
                "run_time": 0.0,
            }
        ],
    }
    # Drop unset tags rather than emitting nulls an assessor has to interpret.
    control["tags"] = {k: v for k, v in control["tags"].items() if v not in (None, "")}

    profile = {
        "name": f"{scanner}-execution",
        "title": f"{scanner} execution record",
        "version": "1.0.0",
        "summary": (
            f"Evidence that {scanner} ran over {repo} and found nothing. "
            "Produced by dev-sec-ops-baseline tools/scan_receipt.py."
        ),
        "supports": [],
        "attributes": [],
        "groups": [],
        # Both are required — saf rejects the document without them, with a
        # generic "failed to convert" that names neither.
        "status": "loaded",
        "controls": [control],
    }
    # Digest of the profile's own content, so two receipts for the same run are
    # identical and a tampered one does not match. A constant here would be a
    # field that looks like provenance and carries none.
    profile["sha256"] = hashlib.sha256(
        json.dumps(profile, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()

    return {
        "platform": {"name": "github-actions", "release": "1"},
        "version": "1.0.0",
        "statistics": {},
        "profiles": [profile],
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scanner", required=True)
    ap.add_argument("--repo", required=True)
    ap.add_argument("--sha", default="")
    ap.add_argument("--ref", default="")
    ap.add_argument("--run-id", default="")
    ap.add_argument("--findings", type=int, default=0)
    ap.add_argument("--scanner-version", default="")
    ap.add_argument("--mode", default="filesystem")
    ap.add_argument("--timestamp", required=True,
                    help="ISO-8601 UTC. Passed in rather than read from the clock "
                         "so the record matches the run it describes.")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    if args.findings != 0:
        print("::error::scan_receipt.py records a CLEAN run; convert the "
              "scanner's own output when there are findings", file=sys.stderr)
        return 2

    doc = build(args.scanner, args.repo, args.sha, args.ref, args.run_id,
                args.findings, args.scanner_version, args.mode, args.timestamp)

    with open(args.out, "w") as f:
        json.dump(doc, f, indent=2)

    print(f"wrote {args.out}: 1 passing control recording a clean "
          f"{args.scanner} run over {args.repo}@{args.sha or 'unknown'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
