#!/usr/bin/env python3
"""Fail on InSpec resource calls made in a `describe` BODY.

A describe body is an RSpec example GROUP, not an example. Calling a resource
there raises at exec time:

    RSpec::Core::ExampleGroup::WrongScopeError
    `aws_ecr_repository` is not available on an example group

Neither `cinc-auditor check` nor `json` evaluates control bodies, so both pass
on the broken code. This shipped in v0.1.4 and broke the consumer's exec leg.

LEGAL, and must not be flagged:
    describe aws_ecr_repository(name: n) do   # resource is an ARGUMENT
    subject { aws_ecr_repository(name: n) }   # deferred into an example
    it { ... }  /  before  /  let

ILLEGAL:
    describe 'x' do
      aws_ecr_repository(name: n).something   # bare call in the group body
    end

Implementation note: a naive depth counter is wrong. Decrementing on every
`end` lets the `end` of an inner `it ... do` block close the describe frame,
after which the rest of the body goes unchecked — that mistake made the first
version of this linter pass the very code it was written to catch. A stack is
required so each `end` pops the frame it actually belongs to.
"""
import re
import sys
from pathlib import Path

RESOURCE = re.compile(r"\baws_[a-z0-9_]+\(")
# A block opener: a trailing `do` (with optional |args|), or a keyword that
# opens a block needing `end`. Anchored at line start so a MODIFIER form
# (`impact 0.0 if repos.empty?`) does not push a frame.
# The optional block-args group absorbs its own leading whitespace, so there
# are never two adjacent variable-length matchers to backtrack between. `[ \t]`
# rather than `\s` because this is matched per-line.
DO_BLOCK = re.compile(r"\bdo\b(?:[ \t]*\|[^|]*\|)?[ \t]*$")
KEYWORD_BLOCK = re.compile(r"^(if|unless|case|begin|def|class|module|while|until)\b")
END = re.compile(r"^end\b")
DESCRIBE = re.compile(r"^(describe|context)\b")
DEFERRED = re.compile(r"^(it|its|subject|before|after|let|let!|specify|example)\b")

DESCRIBE_FRAME = "describe"
DEFERRED_FRAME = "deferred"
OTHER_FRAME = "other"


def _classify(line: str) -> str:
    """Which kind of frame this line would open, if it opens one."""
    if DESCRIBE.match(line):
        return DESCRIBE_FRAME
    if DEFERRED.match(line):
        return DEFERRED_FRAME
    return OTHER_FRAME


def _opens_block(line: str) -> bool:
    return bool(DO_BLOCK.search(line)) or bool(KEYWORD_BLOCK.match(line))


def _in_describe_body(stack) -> bool:
    """True when the innermost enclosing example group is a describe.

    A deferred frame (it/subject/let) between here and the describe means the
    code runs inside an EXAMPLE, where resources are available.
    """
    for frame in reversed(stack):
        if frame == DEFERRED_FRAME:
            return False
        if frame == DESCRIBE_FRAME:
            return True
    return False


def _is_violation(line: str, kind: str, stack) -> bool:
    # A resource on the `describe ... do` line is an ARGUMENT — legal.
    # A resource on an it/subject/let line is deferred — legal.
    return kind == OTHER_FRAME and _in_describe_body(stack) and bool(RESOURCE.search(line))


def violations(path: Path):
    stack = []
    out = []

    for lineno, raw in enumerate(path.read_text().splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        kind = _classify(line)
        if _is_violation(line, kind, stack):
            out.append((lineno, line))

        if END.match(line) and stack:
            stack.pop()
        elif _opens_block(line):
            stack.append(kind)

    return out


def main(argv):
    targets = []
    for root in argv[1:] or ["controls", "libraries"]:
        targets.extend(Path(root).rglob("*.rb"))

    found = []
    for f in sorted(targets):
        for lineno, line in violations(f):
            found.append(f"{f}:{lineno}: {line[:100]}")

    if found:
        print("::error::InSpec resource called in a describe body — raises "
              "WrongScopeError at exec. Resolve it at control scope instead.")
        for f in found:
            print(f"  {f}")
        return 1

    print(f"OK — no resource calls in describe bodies ({len(targets)} file(s) checked)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
