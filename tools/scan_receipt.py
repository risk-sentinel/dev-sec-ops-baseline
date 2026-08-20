#!/usr/bin/env python3
"""Emit a one-control HDF recording that a scan ran and found nothing.

    scan_receipt.py --scanner trufflehog --repo owner/name --sha abc123 \
                    --ref refs/heads/main --run-id 42 --findings 0 \
                    --out receipt-hdf.json [--base DIR]

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
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from hdf_doc import control as build_control, profile_document  # noqa: E402

# The output path is a CLI argument a workflow assembles, and this tool WRITES
# to it, so a "../.." would let an earlier step choose which file gets
# overwritten. Confined to a base directory — the working directory by default,
# which is what CI wants since the workflow runs from the checkout. `--base`
# widens it deliberately, so working outside the tree is a choice at the call
# site rather than something the guard quietly permits.
#
# Same treatment as tools/apply_dispositions.py; the two behave identically.


def safe_path(value, base):
    """Resolve `value` and refuse anything outside `base`."""
    p = Path(value).resolve()
    if not p.is_relative_to(base):
        raise ValueError(f"path escapes {base}: {value}")
    return p

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

    control = build_control(
        control_id=f"{scanner}-executed",
        title=f"{scanner} executed over this commit and reported no findings",
        desc=(
            f"{detail}\n\n"
            "This records an EXECUTION, not a finding. It is evidence that the "
            "scan ran over this commit and returned clean."
        ),
        rationale=(
            "A clean repository can otherwise never make this claim. A scanner "
            "that finds nothing produces nothing to convert, so an empty "
            "evidence prefix is indistinguishable from a pipeline that broke — "
            "the two leave byte-for-byte identical state. Unlike code scanning "
            "there is no API that can answer this after the fact, so the run is "
            "the only witness and the record has to be written while it is true."
        ),
        check=(
            f"{scanner}"
            + (f" {version}" if version else "")
            + f" ran in {mode} mode over {repo} at commit {sha or 'unknown'}"
            + (f" ({ref})" if ref else "")
            + f" and reported {findings} finding(s)."
            + (f" The run is retrievable as run id {run_id}." if run_id else "")
        ),
        fix=(
            "There is nothing to remediate on this control when it is present. "
            "The actionable case is its ABSENCE: if no execution record exists "
            "for a repository, either the scan did not run or its emit failed. "
            "Check the workflow run for that repository and the evidence prefix "
            "it should have written to — an empty prefix is the finding, not a "
            "clean result."
        ),
        impact=0.5,
        tags={
            "nist": SCANNER_TAGS.get(scanner, DEFAULT_TAGS),
            "scanner": scanner,
            "repository": repo,
            "commit": sha,
            "ref": ref,
            "run_id": str(run_id) if run_id else None,
            "scan_mode": mode,
            "findings": findings,
        },
        results=[
            {
                "status": "passed",
                "code_desc": detail,
                "start_time": timestamp,
                "run_time": 0.0,
            }
        ],
        source_ref=f"tools/scan_receipt.py ({scanner})",
    )
    # Drop unset tags rather than emitting nulls an assessor has to interpret.
    control["tags"] = {k: v for k, v in control["tags"].items() if v not in (None, "")}

    return profile_document(
        f"{scanner}-execution",
        f"{scanner} execution record",
        (f"Evidence that {scanner} ran over {repo} and found nothing. "
         "Produced by dev-sec-ops-baseline tools/scan_receipt.py."),
        [control],
    )


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
    ap.add_argument("--base", default=".",
                    help="directory the output must stay inside (default: cwd)")
    args = ap.parse_args()

    if args.findings != 0:
        print("::error::scan_receipt.py records a CLEAN run; convert the "
              "scanner's own output when there are findings", file=sys.stderr)
        return 2

    try:
        out = safe_path(args.out, Path(args.base).resolve())
    except ValueError as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 2

    doc = build(args.scanner, args.repo, args.sha, args.ref, args.run_id,
                args.findings, args.scanner_version, args.mode, args.timestamp)

    with open(out, "w") as f:
        json.dump(doc, f, indent=2)

    print(f"wrote {out}: 1 passing control recording a clean "
          f"{args.scanner} run over {args.repo}@{args.sha or 'unknown'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
