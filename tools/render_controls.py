#!/usr/bin/env python3
"""Generate controls/coverage.rb from files/tool_registry.yml.

Why generated rather than looped
--------------------------------
InSpec collects `tag` values from the AST at PARSE time. A tag whose value is a
method call is a RuboCop::AST::SendNode, and the collector calls `.value` on it:

    undefined method 'value' for an instance of RuboCop::AST::SendNode

That aborts `check` for the entire profile. This repository has been bitten by
it before (see the commit dropping a method-call tag value).

So a loop like

    REGISTRY.scan_types.each do |key, meta|
      control "devsecops-coverage-#{key}" do
        tag nist: Array(meta['nist'])          # <- crashes check
      end
    end

cannot work, however tidy it reads. Tags must be literals.

The alternative to generating would be hand-writing ten controls with the NIST
IDs typed out, duplicating the registry and guaranteeing the two drift. This
repository already generates the README coverage tables from the same registry
with a --check drift gate; the controls follow the same rule.

Usage:
    python3 tools/render_controls.py            # rewrite controls/coverage.rb
    python3 tools/render_controls.py --check    # exit 1 if stale
"""

from __future__ import annotations

import argparse
import pathlib
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
REGISTRY = ROOT / "files" / "tool_registry.yml"
TARGET = ROOT / "controls" / "coverage.rb"

HEADER = '''# encoding: utf-8
# =============================================================================
# Scan-type coverage.  GENERATED FILE — DO NOT EDIT.
#
#   Source:    files/tool_registry.yml
#   Generator: tools/render_controls.py
#   Regenerate after any registry change; `--check` fails on drift.
#
# Generated rather than looped because InSpec reads `tag` values from the AST at
# parse time and crashes on a method call ("undefined method 'value' for an
# instance of RuboCop::AST::SendNode"), taking `check` down with it. Tags must be
# literals, so they are written out here instead of derived at runtime.
#
# One control per scan type, one describe per repository. Control IDs are STATIC
# — derived from the registry, which is version-controlled profile data, never
# from the user's declaration. IDs generated from an input would churn whenever
# the repository list changed, breaking SAR continuity across runs.
#
# ---- The four outcomes, and why they are four -------------------------------
#
#   covered       a declared tool is verifiable on a surface this mode reaches
#   attest        not enabled -> skip, satisfiable by an attestation.
#                 A statement about the REPOSITORY.
#   unverifiable  enabled and detectable, but not on a surface this run mode can
#                 reach -> skip naming the mode that could. A statement about
#                 THIS RUN. Failing it would report red against a repository
#                 doing everything right.
#   gap           we never built the detection -> skip. A statement about the
#                 PROFILE; an attestation must not paper over it.
#
# There is deliberately no "not declared" outcome. Omission would render as Not
# Applicable, which reads as "does not apply" rather than "nobody looked".
# =============================================================================

# ---- Per-file setup ---------------------------------------------------------
# LOCALS, not constants, and repeated in every control file on purpose.
#
# InSpec evaluates each control FILE in its own anonymous eval context, so a
# constant defined in one file is invisible in another:
#
#   uninitialized constant #<Class:#<Inspec::ControlEvalContext>>::REGISTRY
#
# Locals defined above a `control` block are captured by the block's closure and
# work reliably. Sharing across files is what does not work, so each file builds
# its own.
registry    = ::CapabilityMatrix.load(inspec.profile.file('tool_registry.yml'))
declaration = {
  'organization' => input('organization'),
  'targets'      => input('targets'),
  'exclusions'   => input('exclusions'),
  'defaults'     => input('defaults')
}
run_mode = input('run_mode')

# ---- Credentials ------------------------------------------------------------
# Resources cannot call input(), so the control body reads these and passes them
# down through the opts hash. Each also falls back to a conventional environment
# variable inside its resource, so an organisation-level CI secret works with no
# input plumbing at all:
#
#   github_token -> GITHUB_TOKEN / GH_TOKEN
#   sonar_token  -> SONAR_TOKEN / SONARQUBE_TOKEN
gh_token = input('github_token')
gh_api   = input('github_api_base')
org_name = input('organization').to_h['name']

# ---- Live verification ------------------------------------------------------
# coverage() resolves declaration x registry: it says a tool SHOULD be visible
# on a surface. It does not look. Asserting on it alone passes a repository that
# declares SonarQube but has no project, without a single API call — a control
# that reports clean without assessing anything.
#
# So every covered cell is verified against the real source here. Failure to
# reach a source is a FAIL, never an empty pass.
targets_by_repo = Array(input('targets')).each_with_object({}) { |t, h| h[t['repo']] = t }
artifact_dir    = input('artifact_dir')
freshness_days  = input('evidence_freshness_days')


SCOPE_RUN         = 'run-scoped'.freeze
SCOPE_POINT       = 'point-in-time'.freeze
DESC_ATTEST       = 'is not enabled and requires attestation'.freeze
DESC_UNVERIFIABLE = 'is enabled but not reachable from this run mode'.freeze
DESC_GAP          = 'is not yet detectable by this profile'.freeze

verify = lambda do |repo, tool, surface|
  target = targets_by_repo[repo] || {}
  case surface
  when 'artifact'
    pats = registry.surfaces_for(tool).dig('artifact', 'patterns')
    r = ::ArtifactHelper.resolve(artifact_dir, pats)
    next "no artifact matching #{Array(pats).join(', ')} in #{artifact_dir}" unless r[:found]
    'verified'
  when 'platform_api'
    api = registry.surfaces_for(tool)['platform_api']
    cap = api && api['capability']
    if cap == 'issues'
      key = target.dig('evidence_sources', 'sonarqube', 'project_key')
      next 'no sonarqube project_key declared for this repository' if key.to_s.empty?
      sq = sonarqube_project(key, token: input('sonar_token'))
      # readable?, not exists?: readable? populates connection_error with the
      # reason. exists? alone returns a bare false and leaves the message nil,
      # so the failure reads "sonarqube:" with nothing after it.
      next "sonarqube: #{sq.connection_error || 'project not readable'}" unless sq.readable?
      unless sq.analyzed_within?(freshness_days)
        next "sonarqube analysis is #{sq.analysis_age_days.inspect} days old (limit #{freshness_days})"
      end
      'verified'
    else
      gs = ::GithubSecurityHandle.call(repo, org_name, gh_token, gh_api)
      st = gs.capability_status(cap)
      next "#{cap}: #{st} — #{gs.capability_reason(cap)}" unless st == :enabled
      'verified'
    end
  else
    "unsupported surface #{surface}"
  end
end
# ---- Shared coverage body ---------------------------------------------------
# Emitted ONCE and invoked from each control with instance_exec, which rebinds
# self to the Inspec::Rule so `describe` registers against the calling control.
#
# The alternative — generating ten copies of this block — duplicated ~40% of the
# file. Generated duplication is still duplication: it makes every future change
# ten edits and buries the one line that differs between controls.
coverage_body = lambda do |scan_type|
  results = ::CapabilityMatrix.coverage(registry, declaration, run_mode: run_mode)
                              .select { |c| c.scan_type == scan_type }

  if results.empty?
    describe "#{scan_type} coverage" do
      it 'has no declared targets' do
        skip 'No repository declares this scan type. Every scan type must be ' \
             'declared enabled true or false — omission would render as Not ' \
             'Applicable, which reads as "does not apply" rather than "nobody looked".'
      end
    end
  end

  results.each do |c|
    case c.status
    when :covered
      # Verify each satisfying (tool, surface) against the real source. Passing
      # on the registry alone would report a repository as covered without a
      # single API call or file read.
      c.covered_by.each do |hit|
        scope   = hit[:scope] == :run_scoped ? SCOPE_RUN : SCOPE_POINT
        outcome = verify.call(c.repo, hit[:tool], hit[:surface])
        describe "#{c.repo} — #{scan_type} via #{hit[:tool]} (#{hit[:surface]}, #{scope})" do
          subject { outcome }
          it { should cmp 'verified' }
        end
      end
    when :attest
      describe "#{c.repo} — #{scan_type}" do
        it(DESC_ATTEST) { skip ::CapabilityMatrix::ATTEST_RATIONALE }
      end
    when :unverifiable
      describe "#{c.repo} — #{scan_type}" do
        it(DESC_UNVERIFIABLE) { skip "#{::CapabilityMatrix::UNVERIFIABLE_RATIONALE}: #{c.detail}" }
      end
    when :gap
      describe "#{c.repo} — #{scan_type}" do
        it(DESC_GAP) { skip "#{::CapabilityMatrix::GAP_RATIONALE}: #{c.detail}" }
      end
    else
      # An unrecognised status must never vanish. Silently emitting no describe
      # would make the control assess nothing while reporting not-red.
      describe "#{c.repo} — #{scan_type}" do
        subject { "unrecognised coverage status #{c.status.inspect}" }
        it { should cmp 'unreachable' }
      end
    end
  end
end
'''

BODY = '''
control '{key_ctl}' do
  impact {impact}
  title '{title} coverage'
  desc <<~DESC
    {desc}

    Satisfied by any declared tool on any execution surface this run mode can
    reach, then VERIFIED against that source. Configuration evidence does not
    count: a workflow file naming a scanner proves somebody wired it up, not
    that it ran.
  DESC
  tag nist: {nist}
  tag ssdf: {ssdf}
  tag sdlc_stage: '{stage}'
  tag scan_type: '{key}'
  tag layer: 'coverage'

  instance_exec('{key}', &coverage_body)
end
'''


def ruby_list(values) -> str:
    return "[" + ", ".join("'" + str(v).replace("'", "\\'") + "'" for v in values) + "]"


def render(reg: dict) -> str:
    out = [HEADER]
    for key, meta in (reg.get("scan_types") or {}).items():
        desc = " ".join(str(meta.get("description", "")).split())
        out.append(
            BODY.format(
                key=key,
                key_ctl=f"devsecops-coverage-{key}",
                # A scan type with no tooling anywhere cannot be a high-impact
                # assertion; it is a declared gap, and the impact says so.
                impact="0.7" if (reg.get("tools") and any(
                    key in (t.get("scan_types") or [])
                    for t in reg["tools"].values()
                )) else "0.3",
                title=str(meta.get("title", key)).replace("'", "\\'"),
                desc=desc,
                nist=ruby_list(meta.get("nist", [])),
                ssdf=ruby_list(meta.get("ssdf", [])),
                stage=meta.get("sdlc_stage", ""),
            )
        )
    return "".join(out)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true",
                    help="exit 1 if controls/coverage.rb does not match the registry")
    args = ap.parse_args(argv)

    reg = yaml.safe_load(REGISTRY.read_text(encoding="utf-8"))
    generated = render(reg)
    current = TARGET.read_text(encoding="utf-8") if TARGET.exists() else ""

    if args.check:
        if current != generated:
            print("controls/coverage.rb is stale.\n"
                  "Run: python3 tools/render_controls.py", file=sys.stderr)
            return 1
        print("controls/coverage.rb is in sync with the registry.")
        return 0

    if current == generated:
        print("controls/coverage.rb already in sync; nothing written.")
        return 0

    TARGET.write_text(generated, encoding="utf-8")
    print(f"Generated {TARGET.relative_to(ROOT)} "
          f"({len(reg.get('scan_types') or {})} controls)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
