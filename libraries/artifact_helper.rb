# encoding: utf-8
# =============================================================================
# ArtifactHelper — locating pipeline report artifacts.
#
# Keeps controls free of path-joining and glob noise, and makes absolute or
# relative artifact directories work the same way.
#
# ---- Why patterns rather than fixed filenames -------------------------------
#
# Real pipelines stamp report names with a timestamp, a commit SHA, or what was
# scanned:
#
#     trivy-2026-08-15.json
#     grype-api-image.json
#     sast-20260815T1000.sarif
#
# A registry of exact filenames reports every one of those pipelines as having
# produced no scan at all. That is the worst failure direction available: a
# false negative that looks like a real finding, sending someone to fix a scan
# that was running the whole time.
#
# So the registry stores `patterns` (globs) and this module resolves them.
# =============================================================================

require 'pathname'

module ArtifactHelper
  # Join an artifact directory and a filename. Retained for the existing
  # fixed-name controls in controls/artifacts.rb.
  def self.path(artifact_dir, filename)
    Pathname.new(artifact_dir).join(filename).to_s
  end

  # PURE matcher: given a list of names already obtained from somewhere, return
  # those matching any of the patterns.
  #
  # Kept separate from the filesystem so it can be driven from a directory
  # listing obtained however the caller can get one — Dir.glob on a local
  # runner, `command('ls')` output over ssh, or a fixture in a test. The
  # matching rule must not depend on how the listing was fetched.
  #
  # Matching is case-insensitive and ignores any leading directory, because
  # `reports/Trivy-2026.JSON` and `Trivy-2026.json` are the same artifact as
  # far as any pipeline author is concerned.
  def self.match(names, patterns)
    pats = Array(patterns).compact
    return [] if pats.empty?
    Array(names).select do |name|
      base = File.basename(name.to_s)
      pats.any? { |p| File.fnmatch?(p.to_s, base, File::FNM_CASEFOLD) }
    end
  end

  # Convenience for a LOCAL target. Reads the runner's own filesystem via
  # Dir.glob, which is correct for `-t local://` — the only transport that
  # makes sense for an in-pipeline bolt-on, since the artifacts are produced by
  # earlier steps of the same job.
  #
  # It is NOT correct for a remote transport: this would list the machine
  # running InSpec rather than the target. For a remote target, list the
  # directory through the backend and pass the names to `match` instead. The
  # limitation is stated rather than papered over, because a glob that silently
  # searches the wrong host returns zero matches and reads as "the scan never
  # ran".
  def self.glob(artifact_dir, patterns)
    dir = Pathname.new(artifact_dir.to_s)
    return [] unless dir.directory?
    names = dir.children.select(&:file?).map { |c| c.basename.to_s }
    match(names, patterns).map { |n| dir.join(n).to_s }.sort
  end

  # Resolution outcome for one tool's artifact surface.
  #
  # `count` is carried deliberately. A pipeline that emitted six Trivy reports
  # where one was expected is a fact worth surfacing, and collapsing the result
  # to a boolean throws it away.
  #
  # `found: false` while the scan is declared enabled is a FAIL, not a skip —
  # the declaration said the scan runs, and no evidence of it exists.
  #
  # EVERY match is returned, not just the first. A pipeline emitting one valid
  # report and one truncated one has a problem, and asserting on "the first
  # file found" would hide exactly that.
  def self.resolve(artifact_dir, patterns)
    matches = glob(artifact_dir, patterns)
    {
      found:    !matches.empty?,
      count:    matches.size,
      paths:    matches,
      patterns: Array(patterns)
    }
  end
end
