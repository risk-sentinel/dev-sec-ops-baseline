#!/usr/bin/env python3
"""Render the README coverage matrix from files/tool_registry.yml.

The registry is the single source of truth for what this profile can detect.
Hand-maintaining the same information in prose guarantees the two drift, and a
README that overstates coverage is worse than one that says nothing — so the
tables between the generated markers are written by this script and nothing
else.

Usage:
    python3 tools/render_matrix.py            # rewrite README.md in place
    python3 tools/render_matrix.py --check    # exit 1 if README is stale

--check is the drift gate. It is intentionally NOT wired into CI here;
modifying workflows needs explicit approval, so wiring it is a separate change.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
REGISTRY = ROOT / "files" / "tool_registry.yml"
README = ROOT / "README.md"

BEGIN = "<!-- BEGIN GENERATED: coverage-matrix -->"
END = "<!-- END GENERATED: coverage-matrix -->"

SURFACES = ["artifact", "platform_api", "repo_contents"]
SURFACE_LABEL = {
    "artifact": "Artifact",
    "platform_api": "Platform API",
    "repo_contents": "Repo contents",
}

MARK = {
    "implemented": "**yes**",
    "planned": "planned",
    None: "&mdash;",
}


def load_registry() -> dict:
    return yaml.safe_load(REGISTRY.read_text(encoding="utf-8"))


def surface_status(tool: dict, surface: str):
    return (tool.get("surfaces") or {}).get(surface, {}).get("status")


def tools_for(reg: dict, scan_type: str) -> list[str]:
    return sorted(
        key
        for key, tool in (reg.get("tools") or {}).items()
        if scan_type in (tool.get("scan_types") or [])
    )


def render_scan_types(reg: dict) -> list[str]:
    """Scan type x surface. A row with no tools is a declared gap, not an omission."""
    out = [
        "### Coverage by scan type",
        "",
        "| Scan type | SDLC stage | Tools | "
        + " | ".join(SURFACE_LABEL[s] for s in SURFACES)
        + " | NIST 800-53r5 |",
        "|---|---|---|---|---|---|---|",
    ]
    stages = reg.get("sdlc_stages") or {}
    for key, meta in (reg.get("scan_types") or {}).items():
        tools = tools_for(reg, key)
        stage_key = meta.get("sdlc_stage", "")
        stage = stages.get(stage_key, {})
        stage_cell = (
            f"[{stage.get('title', stage_key)}]({stage.get('doc')})"
            if stage.get("doc")
            else stage_key
        )
        cells = []
        for surface in SURFACES:
            statuses = {surface_status(reg["tools"][t], surface) for t in tools}
            if "implemented" in statuses:
                cells.append(MARK["implemented"])
            elif "planned" in statuses:
                cells.append(MARK["planned"])
            else:
                cells.append(MARK[None])
        tool_cell = ", ".join(reg["tools"][t]["name"] for t in tools) or "_none_"
        nist = ", ".join(f"`{c}`" for c in meta.get("nist", []))
        title = meta.get("title", key)
        out.append(
            f"| **{key}** &mdash; {title} | {stage_cell} | {tool_cell} | "
            + " | ".join(cells)
            + f" | {nist} |"
        )
    out.append("")

    uncovered = [k for k in (reg.get("scan_types") or {}) if not tools_for(reg, k)]
    if uncovered:
        names = ", ".join(f"`{u}`" for u in uncovered)
        out += [
            f"> **No tooling anywhere in the organisation for {names}.** The row is "
            "kept deliberately. Dropping it would imply the scan type does not "
            "apply; keeping it empty states that nobody performs it.",
            "",
        ]
    return out


def render_tools(reg: dict) -> list[str]:
    out = [
        "### Coverage by tool",
        "",
        "| Tool | Scan types | "
        + " | ".join(SURFACE_LABEL[s] for s in SURFACES)
        + " |",
        "|---|---|---|---|---|",
    ]
    # sort by display name, not key — the table shows names
    for _, tool in sorted(
        (reg.get("tools") or {}).items(), key=lambda kv: kv[1]["name"].lower()
    ):
        cells = [MARK[surface_status(tool, s)] for s in SURFACES]
        types = ", ".join(f"`{t}`" for t in tool.get("scan_types", []))
        out.append(f"| {tool['name']} | {types} | " + " | ".join(cells) + " |")
    out.append("")
    return out


def binding_sources(reg: dict) -> list[str]:
    """Which sources actually appear in bindings, in registry order.

    Derived rather than hardcoded so adding a source (AWS, for post-deployment
    reads) grows the table without anyone remembering to edit this function.
    """
    seen = []
    for cap in (reg.get("capabilities") or {}).values():
        for source in (cap.get("bindings") or {}):
            if source not in seen:
                seen.append(source)
    order = list((reg.get("sources") or {}).keys())
    return sorted(seen, key=lambda s: order.index(s) if s in order else 99)


def render_api_reference(reg: dict) -> list[str]:
    """Per-capability endpoint + vendor documentation, one column per source."""
    sources = binding_sources(reg)
    names = {k: v.get("name", k) for k, v in (reg.get("sources") or {}).items()}
    out = [
        "### What each check reads, and where it is documented",
        "",
        "| Capability | " + " | ".join(names.get(s, s) for s in sources) + " |",
        "|---" * (len(sources) + 1) + "|",
    ]
    for key, cap in (reg.get("capabilities") or {}).items():
        bindings = cap.get("bindings") or {}
        cells = []
        for source in sources:
            b = bindings.get(source)
            if not b:
                cells.append(MARK[None])
                continue
            endpoint = b.get("endpoint", "")
            docs = b.get("docs")
            cell = f"`{endpoint}`"
            if docs:
                cell += f"<br>[docs]({docs})"
            cells.append(cell)
        out.append(
            f"| **{key}**<br>{cap.get('title', '')} | " + " | ".join(cells) + " |"
        )
    out += [
        "",
        "Full API references: "
        + ", ".join(
            f"[{s['name']}]({s['docs']})"
            for s in (reg.get("sources") or {}).values()
            if s.get("docs")
        )
        + ".",
        "",
    ]
    return out


def render_surfaces(reg: dict) -> list[str]:
    """Surfaces, their access requirement, and — the load-bearing column — role."""
    surfaces = reg.get("surfaces") or {}
    modes = reg.get("run_modes") or {}
    out = [
        "### The detection surfaces",
        "",
        "Every check resolves to exactly one surface. They differ by access "
        "requirement and, critically, by **role**: only *execution* evidence may "
        "satisfy a scan type.",
        "",
        "| Surface | What it reads | Access required | Role |",
        "|---|---|---|---|",
    ]
    for key, meta in surfaces.items():
        role = meta.get("role", "")
        badge = "**execution**" if role == "execution" else "configuration"
        out.append(
            f"| `{key}` | {meta.get('title', '')} | {meta.get('access', '')} | {badge} |"
        )
    out += [
        "",
        "**A workflow file naming a scanner proves somebody wired it up — not that "
        "it ran.** So `repo_contents` is configuration evidence and can never "
        "satisfy a scan type. It still answers questions nothing else can: whether "
        "the scan fires on a merge request (shift-left), and whether CODEOWNERS "
        "covers the security paths (governance). Those are governance controls, "
        "never coverage controls.",
        "",
        "Merge-request rules straddle the split. *Whether reviews are required* is "
        "platform state a token reads; *whether the security scan runs on the merge "
        "request at all* is a fact about a YAML file.",
        "",
        "### What each run mode can read",
        "",
        "| Run mode | Surfaces readable | Can satisfy a scan type |",
        "|---|---|---|",
    ]
    execution = {k for k, m in surfaces.items() if m.get("role") == "execution"}
    for mode, readable in modes.items():
        eligible = [s for s in readable if s in execution]
        out.append(
            f"| `{mode}` | {', '.join(f'`{s}`' for s in readable)} | "
            f"{', '.join(f'`{s}`' for s in eligible) or '&mdash;'} |"
        )
    out.append("")
    return out


def render(reg: dict) -> str:
    body: list[str] = []
    body += render_surfaces(reg)
    body += render_scan_types(reg)
    body += render_tools(reg)
    body += render_api_reference(reg)
    return "\n".join(
        [
            BEGIN,
            "<!-- Generated by tools/render_matrix.py from files/tool_registry.yml.",
            "     Do not edit by hand: edit the registry and re-render. -->",
            "",
            *body,
            END,
        ]
    )


def splice(readme: str, block: str) -> str:
    pattern = re.compile(
        re.escape(BEGIN) + r".*?" + re.escape(END), re.DOTALL
    )
    if not pattern.search(readme):
        raise SystemExit(
            f"README.md is missing the {BEGIN} / {END} markers; add them first."
        )
    return pattern.sub(lambda _: block, readme)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--check",
        action="store_true",
        help="exit 1 if README.md does not match the registry",
    )
    args = ap.parse_args(argv)

    reg = load_registry()
    current = README.read_text(encoding="utf-8")
    updated = splice(current, render(reg))

    if args.check:
        if current != updated:
            print(
                "README.md coverage matrix is stale.\n"
                "Run: python3 tools/render_matrix.py",
                file=sys.stderr,
            )
            return 1
        print("README.md coverage matrix is in sync with the registry.")
        return 0

    if current == updated:
        print("README.md already in sync; nothing written.")
        return 0

    README.write_text(updated, encoding="utf-8")
    print(f"Rendered coverage matrix into {README.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
