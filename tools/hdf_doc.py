#!/usr/bin/env python3
"""Shared HDF envelope for the evidence-record tools.

Both `scan_receipt.py` and `test_evidence.py` produce HDF that records that
something RAN, rather than converting a scanner's findings. They need the same
envelope, and it has two non-obvious requirements that are worth stating once
here rather than rediscovering:

  * `status` and `sha256` are REQUIRED on the profile. Without them `saf`
    rejects the document with a generic "failed to convert" that names neither
    field.
  * `hdf validate` is NOT a usable check on this shape. hdf 3.4.1 validates the
    newer `baselines[]` schema, while every saf converter — and this envelope —
    emits legacy `profiles[]`. Assert the shape you need instead.
"""

import hashlib
import json


def profile_document(name, title, summary, controls, platform="github-actions"):
    """Wrap controls in a legacy-schema HDF document."""
    profile = {
        "name": name,
        "title": title,
        "version": "1.0.0",
        "summary": summary,
        "supports": [],
        "attributes": [],
        "groups": [],
        "status": "loaded",
        "controls": controls,
    }
    # Digest of the profile's own content, so the same run produces the same
    # document and a tampered one does not match. A constant here would be a
    # field that looks like provenance and carries none.
    profile["sha256"] = hashlib.sha256(
        json.dumps(profile, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()

    return {
        "platform": {"name": platform, "release": "1"},
        "version": "1.0.0",
        "statistics": {},
        "profiles": [profile],
    }


def control(control_id, title, desc, results, tags, rationale, check, fix,
            impact=0.5, source_ref="dev-sec-ops-baseline/tools"):
    """One HDF control, modelled the way a real InSpec control is.

    A control carries four distinct things, and a reader needs all of them:

        title       what this control is for
        desc        what it means            -> descriptions[label=default]
        rationale   why it matters           -> descriptions[label=rationale]
        check       how it was verified      -> descriptions[label=check]
        fix         what to do when it fails -> descriptions[label=fix]

    The estate's CIS and STIG profiles emit all four, because InSpec's
    `desc 'check'` / `desc 'fix'` serialise into `descriptions[]`. Records we
    synthesise here previously emitted a title and one prose blob, so a reader
    opening a scan receipt in Heimdall saw markedly less than one opening a CIS
    control — and the check and fix text is exactly what an assessor uses to
    decide whether to believe a control, and an engineer uses to act on it.

    `rationale`, `check` and `fix` are REQUIRED arguments on purpose. Defaulting
    any of them to "" would let a caller omit it silently, and "nobody wrote one"
    would render identically to "there is nothing to say" — the distinction this
    whole profile exists to preserve. Rationale is required for the same reason
    as the other two: a control whose reason for existing is unstated is one
    nobody can argue with, scope, or retire.

    Schema note, measured rather than assumed: `descriptions` must include a
    `default` entry. `hdf convert` rejects a document whose descriptions carry
    only `check` and `fix` ("At least one of the items must match"), while
    `default` alone, and `default` plus any of the others, both convert and
    validate.
    """
    missing = [n for n, v in (("rationale", rationale), ("check", check), ("fix", fix)) if not v]
    if missing:
        raise ValueError(
            f"{control_id}: {', '.join(missing)} required. A control that cannot "
            "state why it exists, how it was verified, or what to do when it is "
            "absent, is asking to be taken on faith."
        )

    descriptions = [
        {"label": "default", "data": desc},
        {"label": "rationale", "data": rationale},
        {"label": "check", "data": check},
        {"label": "fix", "data": fix},
    ]

    return {
        "id": control_id,
        "title": title,
        "desc": desc,
        "descriptions": descriptions,
        "impact": impact,
        "refs": [],
        "tags": {k: v for k, v in tags.items() if v not in (None, "")},
        "code": "",
        "source_location": {"ref": source_ref, "line": 0},
        "results": results,
    }


def result(status, code_desc, timestamp, message=None, run_time=0.0):
    r = {"status": status, "code_desc": code_desc,
         "start_time": timestamp, "run_time": run_time}
    if message:
        r["skip_message" if status == "skipped" else "message"] = message
    return r
