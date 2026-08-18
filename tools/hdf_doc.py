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


def control(control_id, title, desc, results, tags, impact=0.5):
    """One HDF control. Unset tags are dropped rather than emitted as null."""
    return {
        "id": control_id,
        "title": title,
        "desc": desc,
        "impact": impact,
        "refs": [],
        "tags": {k: v for k, v in tags.items() if v not in (None, "")},
        "code": "",
        "source_location": {"ref": "dev-sec-ops-baseline/tools", "line": 0},
        "results": results,
    }


def result(status, code_desc, timestamp, message=None, run_time=0.0):
    r = {"status": status, "code_desc": code_desc,
         "start_time": timestamp, "run_time": run_time}
    if message:
        r["skip_message" if status == "skipped" else "message"] = message
    return r
