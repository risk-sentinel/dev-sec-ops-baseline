# encoding: utf-8
# =============================================================================
# A minimal stand-in for the InSpec DSL, so the profile's resource libraries can
# be loaded by ordinary Ruby outside the runner.
#
# libraries/github_security.rb subclasses `Inspec.resource(1)` and calls the
# class-level DSL (name/supports/desc/example) at definition time. None of that
# does anything useful outside a profile run, but all of it must EXIST or the
# file raises on load.
#
# In its own file so that tools requiring it can keep every `require` at the top
# of the file, ahead of any module definition. Defining the stub inline forces
# the library requires below it, which is both harder to read and a lint
# finding.
# =============================================================================

module Inspec
  # Every method here is intentionally empty: the class-level DSL calls are
  # declarations consumed by the runner, and outside the runner there is nothing
  # to consume them. They exist so the calls resolve rather than raise.
  class FakeBase
    def self.name(*)
      # Declaration only — the runner uses this to register the resource.
    end

    def self.supports(*)
      # Declaration only — platform gating is a runner concern.
    end

    def self.desc(*)
      # Declaration only — documentation surfaced by `inspec doc`.
    end

    def self.example(*)
      # Declaration only — documentation surfaced by `inspec doc`.
    end
  end

  # The version argument selects a resource API generation inside InSpec. There
  # is only one shape to stand in for here, so it is ignored.
  def self.resource(_version)
    FakeBase
  end

  # forge_security raises this to fail one example rather than aborting a whole
  # control. Outside the runner it only needs to EXIST and to be rescuable;
  # inheriting from StandardError matches how the real class behaves at the one
  # point the tests care about.
  module Exceptions
    class ResourceFailed < StandardError; end
  end
end
