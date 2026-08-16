#!/usr/bin/env python3
"""Apply GitHub alert dispositions to an HDF file converted from SARIF.

    apply_dispositions.py --hdf FILE --dispositions FILE --source code_scanning
                          [--out FILE] [--check]

Why this step exists
--------------------
An analysis's SARIF contains every result in that upload, including findings a
maintainer has already triaged. `results_count` counts them all. So converting
the SARIF alone republishes closed triage decisions as live failures on every
run, forever — an evidence package that keeps re-litigating settled reviews is
worse than one that says nothing, because someone has to re-read it each time.

SARIF has a native `suppressions` array for exactly this, and `saf convert
sarif2hdf` ignores it (verified against v0.5.0 of the auditor image: a result
carrying `suppressions[].kind = external` still converts to `failed`). So the
disposition has to be applied to the HDF after conversion rather than expressed
in the SARIF before it.

What it does
------------
Matches each HDF result to its alert on (rule id, path, line) and rewrites the
status:

    open       -> left failed. A live finding.
    dismissed  -> skipped, carrying who dismissed it, when, and why.
    fixed      -> passed. It was found and it was remediated.
    unmatched  -> left untouched, and REPORTED. A silent drop here would be
                  indistinguishable from a finding that was never there.

A control whose results all became skipped also gets impact 0.0, which is what
makes HDF render it as Not Applicable rather than Skipped. Status alone does
not do it; the rollup is computed from both.
"""

import argparse
import json
import re
import sys

# "URL : app/models/user.rb LINE : 391 COLUMN : 13"
CODE_DESC = re.compile(r"URL\s*:\s*(?P<path>\S+)\s+LINE\s*:\s*(?P<line>\d+)")


def parse_location(code_desc):
    m = CODE_DESC.search(code_desc or "")
    if not m:
        return None, None
    return m.group("path"), int(m.group("line"))


def index_dispositions(entries):
    """(ruleId, path, line) -> alert, plus a rule-only fallback.

    The fallback matters: CodeQL reports a result at the location of the sink,
    while the alert's most_recent_instance may sit at a different line after a
    refactor. Falling back to the rule is looser than we would like, so it is
    only consulted when every alert for that rule shares one disposition —
    otherwise we would be guessing which finding was dismissed.
    """
    exact = {}
    by_rule = {}
    for a in entries:
        rule = a.get("ruleId")
        key = (rule, a.get("path"), a.get("startLine"))
        exact[key] = a
        by_rule.setdefault(rule, []).append(a)

    unambiguous = {}
    for rule, alerts in by_rule.items():
        states = {a.get("state") for a in alerts}
        if len(states) == 1:
            unambiguous[rule] = alerts[0]
    return exact, unambiguous


def dismissal_message(alert):
    who = alert.get("dismissedBy") or "unknown"
    when = alert.get("dismissedAt") or "unknown date"
    why = alert.get("dismissedReason") or "no reason recorded"
    note = alert.get("dismissedComment")
    msg = f"Dismissed as '{why}' by {who} on {when}."
    if note:
        msg += f" Comment: {note}"
    msg += (" This is a recorded triage decision, not an unevaluated finding;"
            " it remains in the evidence so the acceptance is auditable.")
    return msg


def apply(hdf, dispositions, source):
    entries = dispositions.get(source) or []
    exact, unambiguous = index_dispositions(entries)

    stats = {"open": 0, "dismissed": 0, "fixed": 0, "unmatched": 0, "controls_na": 0}
    unmatched_detail = []

    for profile in hdf.get("profiles", []):
        for control in profile.get("controls", []):
            rule = control.get("id")
            statuses = []

            for result in control.get("results", []):
                path, line = parse_location(result.get("code_desc"))
                alert = exact.get((rule, path, line)) or unambiguous.get(rule)

                if alert is None:
                    stats["unmatched"] += 1
                    unmatched_detail.append(f"{rule} @ {path}:{line}")
                    statuses.append(result.get("status"))
                    continue

                state = (alert.get("state") or "open").lower()
                if state == "dismissed":
                    result["status"] = "skipped"
                    result["skip_message"] = dismissal_message(alert)
                    result.pop("message", None)
                    stats["dismissed"] += 1
                elif state == "fixed":
                    result["status"] = "passed"
                    result["message"] = (
                        "Reported by code scanning and subsequently remediated;"
                        " no longer present at this location."
                    )
                    stats["fixed"] += 1
                else:
                    stats["open"] += 1
                statuses.append(result["status"])

            # impact 0.0 + all-skipped is what HDF rolls up as Not Applicable.
            # Setting the status without the impact leaves it rendering as
            # Skipped, which reads as "nobody looked".
            if statuses and all(s == "skipped" for s in statuses):
                control["impact"] = 0.0
                stats["controls_na"] += 1

    return stats, unmatched_detail


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hdf", required=True)
    ap.add_argument("--dispositions", required=True)
    ap.add_argument("--source", default="code_scanning")
    ap.add_argument("--out")
    ap.add_argument("--check", action="store_true",
                    help="exit non-zero if any result could not be matched to an alert")
    args = ap.parse_args()

    with open(args.hdf) as f:
        hdf = json.load(f)
    with open(args.dispositions) as f:
        dispositions = json.load(f)

    stats, unmatched = apply(hdf, dispositions, args.source)

    out = args.out or args.hdf
    with open(out, "w") as f:
        json.dump(hdf, f, indent=2)

    print(f"dispositions applied to {out} (source: {args.source})")
    print(f"  open (left failing): {stats['open']}")
    print(f"  dismissed -> skipped: {stats['dismissed']}")
    print(f"  fixed -> passed: {stats['fixed']}")
    print(f"  controls now Not Applicable: {stats['controls_na']}")
    print(f"  unmatched: {stats['unmatched']}")
    for d in unmatched[:20]:
        print(f"    - {d}")
    if len(unmatched) > 20:
        print(f"    ... and {len(unmatched) - 20} more")

    if args.check and stats["unmatched"]:
        print("::error::results could not be matched to an alert; their disposition "
              "is unknown and they are being reported at face value", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
