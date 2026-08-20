#!/usr/bin/env python3
"""Resolve NIST control tags to FedRAMP Key Security Indicators.

Shared by tools/render_ksi.py (the hand-written control files) and
tools/render_controls.py (the generated coverage controls), so both write the
same answer from the same source. Two independent implementations would
eventually disagree, and the disagreement would be invisible — every control
would still carry a plausible-looking tag.

Direction of resolution
-----------------------
The published mapping runs KSI -> NIST: each indicator lists the controls it
cites. This profile tags controls, so it needs the reverse. Building the reverse
index is mechanical; deciding what a reverse link MEANS is not, and that is what
the tiers below are for.

Why the tiers exist
-------------------
The FedRAMP Consolidated Rules cite enhancements (``sa-15.3``, ``ca-2.1``), and
this profile tags enhancements too. So most links are exact. The two inexact
cases are genuinely different from each other and must not be collapsed:

``narrower``
    We tag ``SA-11(1)``; a KSI cites ``sa-11``. An enhancement cannot be
    satisfied without its base control, so evidence for our tag is evidence for
    what the KSI asked. The link holds and the KSI goes in ``tag ksi:``.

``broader``
    We tag ``SA-15``; a KSI cites ``sa-15.3``. Satisfying the base control says
    nothing about whether that specific enhancement is in place. The link is
    real enough to be worth naming and too weak to assert, so it goes in
    ``tag ksi_broader:`` instead.

Reversing those two would silently overclaim. That is the whole reason this is a
module with tests rather than a dictionary lookup inline in the renderer.

``none`` is recorded rather than dropped
----------------------------------------
A control whose every NIST tag fails to resolve emits ``tag ksi_unmapped:``
naming those controls. An absent tag would be indistinguishable from a control
the generator never visited, which is the failure shape this estate keeps
rediscovering: a step that assessed nothing while reporting not-red.
"""

from __future__ import annotations

import pathlib
import re
from typing import Iterable, NamedTuple

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
MAPPING = ROOT / "files" / "ksi_mapping.yml"

# `SA-11(1)` / `RA-5` as written in `tag nist:`. Anything else is a malformed
# tag rather than an unmapped one, and is raised rather than quietly skipped —
# a typo'd control id would otherwise resolve to nothing and read as a coverage
# gap.
_TAG = re.compile(r"^([A-Za-z]{2})-(\d+)(?:\((\d+)\))?$")


class Resolution(NamedTuple):
    """What one control's NIST tags resolve to."""

    ksi: list[str]  # exact + narrower — the link holds
    broader: list[str]  # our tag is the base of a cited enhancement
    unmapped: list[str]  # normalised ids with no path at all
    detail: dict[str, list[tuple[str, str]]]  # nist id -> [(ksi, tier)]


def normalise(tag: str) -> str:
    """`SA-11(1)` -> `sa-11.1`, matching the published control id form."""
    m = _TAG.match(tag.strip())
    if not m:
        raise ValueError(f"not a NIST control id: {tag!r}")
    family, number, enhancement = m.groups()
    base = f"{family.lower()}-{number}"
    return f"{base}.{enhancement}" if enhancement else base


def _base_of(control: str) -> str:
    return control.split(".", 1)[0]


class KsiCatalog:
    """The published catalog, plus the reverse index this profile needs."""

    def __init__(self, path: pathlib.Path | None = None) -> None:
        doc = yaml.safe_load((path or MAPPING).read_text())
        self.source = doc["source"]
        self.families = doc["families"]
        self.indicators = doc["indicators"]

        # control id -> KSIs citing it, and base control -> KSIs citing any
        # enhancement of it. The second index is what makes `broader` findable;
        # without it a base-control tag looks unmapped.
        self.by_control: dict[str, set[str]] = {}
        self.by_base: dict[str, set[str]] = {}
        for ksi_id, meta in self.indicators.items():
            for control in meta.get("controls") or []:
                self.by_control.setdefault(control, set()).add(ksi_id)
                self.by_base.setdefault(_base_of(control), set()).add(ksi_id)

    def resolve(self, tags: Iterable[str]) -> Resolution:
        holds: set[str] = set()
        broader: set[str] = set()
        unmapped: list[str] = []
        detail: dict[str, list[tuple[str, str]]] = {}

        for tag in tags:
            control = normalise(tag)
            links: list[tuple[str, str]] = []

            for ksi_id in sorted(self.by_control.get(control, ())):
                links.append((ksi_id, "exact"))
                holds.add(ksi_id)

            # Our tag is an enhancement and a KSI cites its base control.
            base = _base_of(control)
            if base != control:
                for ksi_id in sorted(self.by_control.get(base, ())):
                    if ksi_id not in holds:
                        links.append((ksi_id, "narrower"))
                        holds.add(ksi_id)

            # Our tag is a base control and a KSI cites an enhancement of it.
            # Only consulted when nothing stronger was found for this tag —
            # a weak link is not worth recording next to a sound one.
            if not links:
                for ksi_id in sorted(self.by_base.get(base, ())):
                    links.append((ksi_id, "broader"))
                    broader.add(ksi_id)

            if not links:
                unmapped.append(control)
            detail[control] = links

        # A KSI reached soundly by one tag is not also "broader" because a
        # weaker tag on the same control happened to reach it.
        broader -= holds

        return Resolution(
            ksi=sorted(holds),
            broader=sorted(broader),
            unmapped=sorted(set(unmapped)),
            detail=detail,
        )


def ruby_list(values: Iterable[str]) -> str:
    """Render as a Ruby array literal. Tags must be literals — see render_ksi."""
    return "[" + ", ".join(f"'{v}'" for v in values) + "]"


def tag_lines(resolution: Resolution, indent: str = "  ") -> list[str]:
    """The `tag ksi*:` lines a control should carry, in a fixed order.

    `ksi` is always emitted, including empty, so that its presence proves the
    generator visited this control. The other two appear only when they have
    something to say — an empty `ksi_broader` on every control would be noise
    that trains readers to skip the line that matters.
    """
    lines = [f"{indent}tag ksi: {ruby_list(resolution.ksi)}"]
    if resolution.broader:
        lines.append(f"{indent}tag ksi_broader: {ruby_list(resolution.broader)}")
    if resolution.unmapped:
        lines.append(f"{indent}tag ksi_unmapped: {ruby_list(resolution.unmapped)}")
    return lines
