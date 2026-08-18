#!/usr/bin/env python3
"""Fixture test for tools/test_evidence.py.

Plain Python, no framework: `python3 tests/test_evidence_test.py`. The tool is
pure apart from file IO, so this runs anywhere without a token or a network.
"""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIX = ROOT / "tests" / "fixtures"
TOOL = ROOT / "tools" / "test_evidence.py"
TS = "2026-08-18T12:00:00Z"

FAILURES = []


def check(label, ok):
    print(f"  {'ok  ' if ok else 'FAIL'} {label}")
    if not ok:
        FAILURES.append(label)


def run(args, cwd):
    return subprocess.run([sys.executable, str(TOOL), *args], cwd=cwd,
                          capture_output=True, text=True)


def controls(path):
    return {c["id"]: c for c in json.load(open(path))["profiles"][0]["controls"]}


with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    for f in ("junit-results.xml", "junit-clean.xml"):
        (tmp / f).write_text((FIX / f).read_text())

    print("failing suite")
    r = run(["--repo", "o/r", "--sha", "abc", "--timestamp", TS,
             "--junit", "junit-results.xml", "--out", "out.json"], tmp)
    check("exits 0", r.returncode == 0)
    c = controls(tmp / "out.json")
    suite = c["test-execution-ui-smoke"]
    check("suite control present", True)
    check("suite fails when a test fails", suite["results"][0]["status"] == "failed")
    check("each failure gets its own result, not just a count",
          len([x for x in suite["results"] if x["status"] == "failed"]) == 2)
    check("failure message carried through",
          "WCAG" in (suite["results"][1].get("message") or ""))
    check("skipped counted, not treated as passed", suite["tags"]["tests"] == 4)
    check("tagged SA-11", suite["tags"]["nist"] == ["SA-11"])
    check("tagged SSDF PW.8", suite["tags"]["ssdf"] == ["PW.8"])
    check("NOT tagged iast", "iast" not in json.dumps(suite["tags"]).lower())

    print("clean suite")
    r = run(["--repo", "o/r", "--sha", "abc", "--timestamp", TS,
             "--junit", "junit-clean.xml", "--out", "clean.json"], tmp)
    c = controls(tmp / "clean.json")
    clean = c["test-execution-rspec"]
    check("clean suite passes", clean["results"][0]["status"] == "passed")
    check("clean suite emits exactly one result", len(clean["results"]) == 1)
    check("test count taken from the attribute, not the element count",
          clean["tags"]["tests"] == 1284)

    print("coverage")
    cov = {"meta": {"command_name": "RSpec", "simplecov_version": "1.0.3"},
           "total": {"lines": {"covered": 100, "missed": 25, "total": 125,
                               "percent": 80.0}},
           "coverage": {"a.rb": {}, "b.rb": {}}}
    (tmp / "cov.json").write_text(json.dumps(cov))
    r = run(["--repo", "o/r", "--sha", "abc", "--timestamp", TS,
             "--junit", "junit-clean.xml", "--simplecov", "cov.json",
             "--out", "cov-out.json"], tmp)
    c = controls(tmp / "cov-out.json")
    cc = c["test-coverage-measured"]
    check("coverage recorded", cc["tags"]["coverage_percent"] == 80.0)
    check("coverage is NOT gated — impact 0.0 renders Not Applicable",
          cc["impact"] == 0.0)
    check("coverage result is skipped, never failed",
          cc["results"][0]["status"] == "skipped")
    check("coverage says explicitly that no threshold is asserted",
          "no threshold" in (cc["results"][0].get("skip_message") or "").lower())

    print("refusals")
    r = run(["--repo", "o/r", "--sha", "abc", "--timestamp", TS,
             "--out", "empty.json"], tmp)
    check("refuses to emit with no inputs rather than asserting testing happened",
          r.returncode == 1 and not (tmp / "empty.json").exists())
    r = run(["--repo", "o/r", "--sha", "abc", "--timestamp", TS,
             "--junit", "../../../etc/hosts", "--out", "x.json"], tmp)
    check("refuses a path outside the base directory", r.returncode == 2)

print()
if FAILURES:
    print(f"FAIL — {len(FAILURES)} assertion(s): {', '.join(FAILURES)}")
    sys.exit(1)
print("PASS — all test-evidence assertions held")
