#!/usr/bin/env python3
"""Fixture test for tools/ksi_resolver.py and the two renderers that use it.

Plain Python, no framework: `python3 tests/ksi_resolver_test.py`. Pure apart
from reading files/ksi_mapping.yml, so it needs no token and no network.

What this is guarding
---------------------
`check` and `json` only PARSE the control files. A `tag ksi:` carrying the wrong
indicator, or silently carrying none, parses perfectly and validates perfectly.
Nothing else in this repository can tell the difference between a correct tag, a
wrong tag, and a tag whose generator was never run — which is why the tiering
rules and the not-silent rule are asserted here rather than trusted.
"""
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

from ksi_resolver import KsiCatalog, normalise, tag_lines  # noqa: E402
from render_ksi import write_control  # noqa: E402

FAILURES = []


def check(label, ok):
    print(f"  {'ok  ' if ok else 'FAIL'} {label}")
    if not ok:
        FAILURES.append(label)


catalog = KsiCatalog()

print("catalog")
check("families loaded", len(catalog.families) == 10)
check("indicators loaded", len(catalog.indicators) == 46)
check("provenance names the source release",
      catalog.source["name"] == "FedRAMP Consolidated Rules for 2026")
check("the published mapping cites enhancements, not just families — this is "
      "the property the whole design rests on",
      any("." in c for c in catalog.by_control))

print("normalisation")
check("plain control", normalise("RA-5") == "ra-5")
check("enhancement", normalise("SA-11(1)") == "sa-11.1")
check("two-digit enhancement", normalise("CM-8(11)") == "cm-8.11")
try:
    normalise("not-a-control")
    check("a malformed tag raises rather than reading as unmapped", False)
except ValueError:
    check("a malformed tag raises rather than reading as unmapped", True)

print("resolution tiers")
# exact: KSI-SCR-MIT cites sa-11 directly.
r = catalog.resolve(["SA-11"])
check("exact match resolves", "KSI-SCR-MIT" in r.ksi)
check("exact match is not reported as broader", r.broader == [])

# narrower: we tag SA-11(1); KSI-SCR-MIT cites sa-11. The enhancement implies
# the base, so the link holds and belongs in `tag ksi:`.
r = catalog.resolve(["SA-11(1)"])
check("an enhancement reaches a KSI citing its base control",
      r.ksi == ["KSI-SCR-MIT"])
check("that link is asserted, not hedged", r.broader == [])

# broader: we tag SA-15; KSI-SCR-MIT cites sa-15.3. Satisfying the base says
# nothing about that enhancement, so this must NOT be asserted.
r = catalog.resolve(["SA-15"])
check("a base control whose enhancement is cited does not enter tag ksi:",
      r.ksi == [])
check("...but is named in ksi_broader rather than dropped",
      r.broader == ["KSI-SCR-MIT"])

# none
r = catalog.resolve(["SR-3"])
check("a control no KSI cites resolves to nothing", r.ksi == [])
check("and is recorded as unmapped rather than left silent",
      r.unmapped == ["sr-3"])

print("mixed tags on one control")
r = catalog.resolve(["SA-11", "SA-15", "SR-3"])
check("sound link survives alongside a weak one and a gap",
      "KSI-SCR-MIT" in r.ksi)
check("a KSI reached soundly is not also listed as broader",
      "KSI-SCR-MIT" not in r.broader)
check("the gap is still reported", r.unmapped == ["sr-3"])

print("order independence (regression)")
# The first version deduplicated `narrower` links against KSIs already reached
# by an EARLIER tag. RA-5 reached KSI-SCR-MON exactly; RA-5(2)'s narrower link
# to the same KSI was then dropped, leaving no links, which fired the `broader`
# fallback and claimed three KSIs citing ra-5.5 — a SIBLING enhancement, not the
# base-of-a-cited-enhancement case `broader` is defined as.
r = catalog.resolve(["RA-5", "RA-5(2)"])
check("a base plus one of its own enhancements claims no sibling-enhancement KSIs",
      r.broader == [])
check("...and the sound link still holds", r.ksi == ["KSI-SCR-MON"])
check("resolution does not depend on tag order",
      catalog.resolve(["RA-5", "RA-5(2)"]) == catalog.resolve(["RA-5(2)", "RA-5"]))
check("the broader fallback still fires for its real case (base, cited enhancement)",
      catalog.resolve(["SA-15"]).broader == ["KSI-SCR-MIT"])

print()
print("no baseline filter")
# ca-2.1 is cited by a KSI and carries an enhancement of the kind reported as
# unresolvable against the FedRAMP High catalog this estate publishes. It must
# resolve here regardless: this wiring does not depend on that question.
r = catalog.resolve(["CA-2(2)"])
check("an enhancement that #40 flags still resolves", r.ksi != [])

print("tag emission")
lines = tag_lines(catalog.resolve(["SA-11"]))
check("tag ksi is always emitted, so its presence proves the generator ran",
      len(lines) == 1 and lines[0].startswith("  tag ksi: ["))
lines = tag_lines(catalog.resolve(["SR-3"]))
check("an all-gap control still emits tag ksi:, empty",
      lines[0] == "  tag ksi: []")
check("and emits the gap", any("ksi_unmapped" in x for x in lines))
lines = tag_lines(catalog.resolve(["SA-11"]))
check("empty tiers are not emitted as noise",
      not any("ksi_broader" in x or "ksi_unmapped" in x for x in lines))

print("literals only")
# A tag value that is not a literal raises at parse time inside InSpec and takes
# `check` down with it, so the emitted form is asserted directly.
for line in tag_lines(catalog.resolve(["SA-11", "SA-15", "SR-3"])):
    check(f"{line.strip()[:40]}... is a literal array",
          re.match(r"^  tag ksi(_broader|_unmapped)?: \[('[^']+'(, )?)*\]$", line)
          is not None)

print("every control file carries the tag")
tagged = 0
for path in sorted((ROOT / "controls").glob("*.rb")):
    text = path.read_text()
    nist = len(re.findall(r"^\s*tag nist:", text, re.M))
    ksi = len(re.findall(r"^\s*tag ksi:", text, re.M))
    check(f"{path.name}: every tag nist: has a tag ksi: ({nist})", nist == ksi)
    tagged += ksi
check("the profile is not silently untagged", tagged > 0)

print("writes stay inside the repository")
# Destinations are rebuilt from module constants plus a name matched against a
# strict allow-list, so a traversal attempt cannot reach the filesystem at all.
for probe in ("../../../tmp/escape.rb", "/tmp/absolute.rb", "Weird Name.rb",
              "no_extension"):
    try:
        write_control(probe, "nope")
        check(f"refuses {probe!r}", False)
    except SystemExit as exc:
        check(f"refuses {probe!r}", "refusing to write" in str(exc))
check("...and created nothing outside the repository",
      not pathlib.Path("/tmp/escape.rb").exists()
      and not pathlib.Path("/tmp/absolute.rb").exists())

print("renderers are idempotent")
for tool in ("render_ksi.py", "render_controls.py"):
    r = subprocess.run([sys.executable, str(ROOT / "tools" / tool), "--check"],
                       capture_output=True, text=True)
    check(f"{tool} --check passes on a freshly rendered tree",
          r.returncode == 0)

print()
if FAILURES:
    print(f"{len(FAILURES)} FAILED:")
    for f in FAILURES:
        print(f"  - {f}")
    raise SystemExit(1)
print("all checks passed")
