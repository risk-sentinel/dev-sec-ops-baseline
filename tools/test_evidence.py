#!/usr/bin/env python3
"""Record that the test suites ran, as HDF, for SA-11.

    test_evidence.py --repo owner/name --sha abc --timestamp T --out FILE \
                     [--junit results.xml ...] [--simplecov coverage.json] \
                     [--base DIR]

Why this exists
---------------
NIST SP 800-53r5 **SA-11 (Developer Testing and Evaluation)** and **SSDF PW.8**
are evidenced by tests having *run*, not by a scanner's findings. Pipelines
already produce that evidence — JUnit XML from pytest, Playwright, Jest and
friends; SimpleCov JSON from RSpec — and it expires in build artifacts because
nothing converts it.

This is NOT IAST
----------------
Coverage says which lines executed. A test suite says whether behaviour was
correct. Neither observes untrusted input reaching a dangerous sink, which is
what IAST means, so none of this may be mapped to the `iast` scan type. That
row stays a declared gap. Conflating them would have the profile overstate its
own coverage, which is the one thing the declared-gap model exists to prevent.

Granularity
-----------
One control per suite, not per test case. A few thousand RSpec examples mapped
to controls would swamp Heimdall and tell an assessor nothing. A clean suite is
one control with one passing result; a failing suite additionally gets one
result per failure, so failures stay individually visible where it matters.

Coverage is recorded, never gated
---------------------------------
Coverage percentage is emitted as evidence with `impact 0.0` — Not Applicable
in HDF terms — because turning it into pass/fail invents a threshold nobody
agreed to, and the conversation becomes "is 78% compliant" instead of "was this
tested". A threshold belongs in a declared input, defaulting to off.
"""

import argparse
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from hdf_doc import control, profile_document, result  # noqa: E402

NIST = ["SA-11"]
SSDF = ["PW.8"]


def safe_path(value, base):
    p = Path(value).resolve()
    if not p.is_relative_to(base):
        raise ValueError(f"path escapes {base}: {value}")
    return p


def parse_junit(path):
    """Return one dict per <testsuite>. Handles a <testsuites> wrapper."""
    root = ET.parse(path).getroot()
    suites = [root] if root.tag == "testsuite" else root.findall(".//testsuite")
    out = []
    for s in suites:
        cases = s.findall("testcase")
        failures = []
        skipped = 0
        for c in cases:
            bad = c.find("failure") if c.find("failure") is not None else c.find("error")
            if bad is not None:
                failures.append({
                    "name": f"{c.get('classname', '')}::{c.get('name', '')}".strip(":"),
                    "message": (bad.get("message") or bad.text or "").strip()[:400],
                })
            elif c.find("skipped") is not None:
                skipped += 1
        out.append({
            "name": s.get("name") or Path(path).stem,
            "tests": int(s.get("tests") or len(cases)),
            "failures": failures,
            "skipped": skipped,
            "time": float(s.get("time") or 0.0),
        })
    return out


def parse_simplecov(path):
    d = json.load(open(path))
    lines = (d.get("total") or {}).get("lines") or {}
    meta = d.get("meta") or {}
    return {
        "tool": meta.get("command_name") or "SimpleCov",
        "simplecov_version": meta.get("simplecov_version"),
        "percent": lines.get("percent"),
        "covered": lines.get("covered"),
        "missed": lines.get("missed"),
        "total": lines.get("total"),
        "files": len(d.get("coverage") or {}),
        "measured_at": meta.get("timestamp"),
    }


def suite_control(s, repo, sha, ref, run_id, timestamp):
    passed = s["tests"] - len(s["failures"]) - s["skipped"]
    detail = (f"{s['name']} executed over {repo} at commit {sha or 'unknown'}"
              f"{f' on {ref}' if ref else ''}: {s['tests']} test(s) — "
              f"{passed} passed, {len(s['failures'])} failed, {s['skipped']} skipped.")

    results = [result("passed" if not s["failures"] else "failed",
                      detail, timestamp, run_time=s["time"])]
    # One result per failure so they stay individually visible; the summary
    # above alone would make a suite with one failure look like a suite with
    # forty.
    for f in s["failures"]:
        results.append(result("failed", f["name"], timestamp, message=f["message"]))

    return control(
        control_id=f"test-execution-{s['name']}",
        title=f"Test suite {s['name']} executed over this commit",
        desc=detail + "\n\nRecords that developer testing ran over this commit "
                      "(SA-11, SSDF PW.8). It is not a security scan and does "
                      "not assert anything about vulnerabilities.",
        rationale=(
            "SA-11 asks whether developer testing happens, and a suite that ran "
            "is the only thing that answers it. Coverage says which lines "
            "executed; a suite says whether behaviour was correct. Without this "
            "record a repository with no tests and a repository whose tests "
            "were never run look the same from outside."
        ),
        check=(
            f"Parsed the JUnit XML emitted by {s['name']} for {repo} at commit "
            f"{sha or 'unknown'}: {s['tests']} test(s), {len(s['failures'])} "
            f"failed, {s['skipped']} skipped, in {s['time']}s."
            + (f" The run is retrievable as run id {run_id}." if run_id else "")
        ),
        fix=(
            "If a test fails, fix the behaviour it asserts — the individual "
            "failures are recorded as separate results so each is actionable. "
            "If this control is ABSENT for a repository, the suite did not run "
            "or produced no JUnit output; check the workflow run and the "
            "reporter configuration."
        ),
        results=results,
        tags={"nist": NIST, "ssdf": SSDF, "suite": s["name"], "repository": repo,
              "commit": sha, "ref": ref, "run_id": str(run_id) if run_id else None,
              "tests": s["tests"], "failures": len(s["failures"])},
        impact=0.5,
        source_ref="tools/test_evidence.py (suite)",
    )


def coverage_control(cov, repo, sha, timestamp):
    pct = cov["percent"]
    detail = (f"{cov['tool']} measured line coverage over {repo} at commit "
              f"{sha or 'unknown'}: {pct:.2f}% ({cov['covered']} of "
              f"{cov['total']} lines across {cov['files']} files)."
              if pct is not None else
              f"{cov['tool']} produced no line-coverage total.")

    return control(
        control_id="test-coverage-measured",
        title="Code coverage measured over this commit",
        desc=detail + "\n\nRecorded as EVIDENCE, not as a gate. Impact is 0.0 "
                      "so this renders Not Applicable rather than pass or fail.",
        rationale=(
            "Turning a coverage percentage into a control invents a threshold "
            "nobody agreed to, and a threshold belongs in a declared input where "
            "it can be argued with. The measurement is still worth recording: it "
            "is the difference between a suite whose reach is known and one "
            "whose reach is assumed."
        ),
        check=(
            f"Parsed the {cov['tool']} output for {repo} at commit "
            f"{sha or 'unknown'}: "
            + (f"{pct:.2f}% line coverage ({cov['covered']} of {cov['total']} "
               f"lines across {cov['files']} files)."
               if pct is not None else "no line-coverage total was present.")
        ),
        fix=(
            "Nothing to remediate — this control never fails. If it is ABSENT, "
            "the coverage reporter did not run or wrote no output; check the "
            "workflow run. If the percentage is lower than your team expects, "
            "that is a conversation to have against a declared threshold, not "
            "something this control decides."
        ),
        results=[result("skipped", detail, timestamp,
                        message="Coverage is recorded for evidence; no threshold is asserted.")],
        tags={"nist": NIST, "ssdf": SSDF, "repository": repo, "commit": sha,
              "coverage_percent": round(pct, 2) if pct is not None else None,
              "lines_covered": cov["covered"], "lines_total": cov["total"],
              "files_measured": cov["files"], "tool": cov["tool"]},
        impact=0.0,
        source_ref="tools/test_evidence.py (coverage)",
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--sha", default="")
    ap.add_argument("--ref", default="")
    ap.add_argument("--run-id", default="")
    ap.add_argument("--timestamp", required=True)
    ap.add_argument("--junit", action="append", default=[])
    ap.add_argument("--simplecov")
    ap.add_argument("--out", required=True)
    ap.add_argument("--base", default=".")
    args = ap.parse_args()

    try:
        base = Path(args.base).resolve()
        junits = [safe_path(j, base) for j in args.junit]
        cov_path = safe_path(args.simplecov, base) if args.simplecov else None
        out = safe_path(args.out, base) if Path(args.out).parent.exists() else Path(args.out)
    except ValueError as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 2

    controls = []
    for j in junits:
        for s in parse_junit(j):
            controls.append(suite_control(s, args.repo, args.sha, args.ref,
                                          args.run_id, args.timestamp))
    if cov_path:
        controls.append(coverage_control(parse_simplecov(cov_path), args.repo,
                                         args.sha, args.timestamp))

    if not controls:
        print("::error::no JUnit XML or SimpleCov JSON supplied — nothing to "
              "record. Emitting an empty document would assert that testing "
              "happened while proving nothing.", file=sys.stderr)
        return 1

    doc = profile_document(
        "test-execution",
        "Developer testing execution record",
        f"Evidence that developer testing ran over {args.repo} (SA-11, SSDF PW.8). "
        "Produced by dev-sec-ops-baseline tools/test_evidence.py.",
        controls,
    )
    with open(out, "w") as f:
        json.dump(doc, f, indent=2)

    suites = sum(1 for c in controls if c["id"].startswith("test-execution-"))
    fails = sum(c["tags"].get("failures", 0) for c in controls)
    print(f"wrote {out}: {suites} suite(s), {fails} failing test(s)"
          f"{', coverage recorded' if cov_path else ''}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
