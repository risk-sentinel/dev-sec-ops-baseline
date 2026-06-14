# encoding: utf-8
# Helper to resolve an artifact path from artifact_dir + filename input.
# Keeps controls free of path-joining noise and makes absolute/relative dirs work.

require 'pathname'

module ArtifactHelper
  def self.path(artifact_dir, filename)
    Pathname.new(artifact_dir).join(filename).to_s
  end
end
