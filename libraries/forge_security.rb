# encoding: utf-8
# =============================================================================
# forge_security — pick the right forge resource for a target, and refuse to
# guess.
#
# ---- The bug this closes ----------------------------------------------------
#
# `forge:` has been a declared field on the organisation, on `defaults`, and on
# every target since the declaration schema was written. No Ruby has ever read
# it. Controls construct `github_security` directly, so a target declaring
# `forge: gitlab` was probed against api.github.com — 404 on every call, every
# capability reported as unavailable, and a confident set of findings about a
# project the profile never actually reached.
#
# That is the estate's recurring defect class in a new costume: a step that
# assessed nothing while reporting something.
#
# ---- Refusing to guess ------------------------------------------------------
#
# An unrecognised forge raises rather than falling back to GitHub. A default
# here would mean a typo (`github ` with a trailing space, `Github`, `gitlabs`)
# silently produces GitHub results for a GitLab project — the failure that is
# hardest to notice, because everything downstream looks normal.
#
# ---- Not every control can be dispatched ------------------------------------
#
# Some controls read a capability only one forge has. GitHub's dashboard bridge
# reads code-scanning analyses, Dependabot alerts and secret-scanning alerts,
# which are three endpoints with three enablement states; GitLab funnels the
# equivalents through one vulnerability-findings endpoint with a different
# shape. Those are not the same question asked twice.
#
# For those, `supported?` lets the control SKIP with a named reason. A skip that
# says which forge and which capability is a coverage gap someone can act on. A
# silent pass is a lie, and running the GitHub reader against a GitLab project
# is worse than either.
# =============================================================================

module ForgeSecurity
  SUPPORTED = %w[github gitlab].freeze

  # Capabilities each forge resource actually implements. Consulted by controls
  # before they assert, so an unimplemented pairing produces a named skip rather
  # than a wrong answer.
  # Gaps are recorded as gaps — see docs/gitlab.md.
  #
  # Keys are per-QUESTION, not per-forge-feature. `required_checks` is absent
  # for GitLab not because GitLab cannot gate merges on a pipeline — it can, via
  # only_allow_merge_if_pipeline_succeeds, and gitlab_security reads it — but
  # because that control asserts a DECLARED SECURITY TOOL is among the required
  # contexts, and GitLab exposes no context names to check. Passing it on a
  # weaker fact would be an overclaim wearing a stronger control's id.
  IMPLEMENTED = {
    'github' => %w[
      required_reviews required_checks rulesets signed_commits codeowners
      shift_left enumeration repo_contents capabilities dashboard
    ].freeze,
    'gitlab' => %w[
      required_reviews signed_commits codeowners enumeration repo_contents
    ].freeze
  }.freeze

  class << self
    # Resolution order: the target's own declaration, then `defaults`, then the
    # organisation block. Most specific wins, same as every other field.
    #
    # There is no implicit final fallback: a declaration that names no forge
    # anywhere is a declaration that never said what it is describing.
    def for_target(declaration, repo)
      declaration = declaration.to_h
      target = Array(declaration['targets']).find { |t| t.to_h['repo'] == repo } || {}
      value = target.to_h['forge'] ||
              declaration.dig('defaults', 'forge') ||
              declaration.dig('organization', 'forge')
      normalise(value, repo)
    end

    def organisation_forge(declaration)
      normalise(declaration.to_h.dig('organization', 'forge'), 'the organisation')
    end

    # Non-raising variant, for the one caller that must decide what to emit
    # rather than abort. `for_target` and `organisation_forge` raise on purpose;
    # this exists so a control can turn the same problem into a failing EXAMPLE
    # instead of an aborted control that takes every other target's result with
    # it.
    def declared_forge(declaration)
      organisation_forge(declaration)
    rescue ::Inspec::Exceptions::ResourceFailed
      nil
    end

    def supported?(forge, capability)
      Array(IMPLEMENTED[forge.to_s]).include?(capability.to_s)
    end

    # Why a control is skipping, phrased for the result message. Names the forge
    # AND the capability, because "unsupported" on its own tells nobody whether
    # to wait for us or to change their declaration.
    def unsupported_reason(forge, capability)
      "#{capability} is not implemented for #{forge} — this profile reads it " \
        "on #{SUPPORTED.select { |f| supported?(f, capability) }.join(', ')} only. " \
        'Recorded as a coverage gap in this profile, not as a finding about ' \
        'the project.'
    end

    # Returns a resource for the target, already scoped and credentialled.
    # `creds` is keyed by forge so a control passes both and does not have to
    # know which one it is about to get.
    def handle(repo, forge:, org:, creds:)
      case normalise(forge, repo)
      when 'github'
        cfg = creds.fetch('github', {})
        ::GithubSecurityHandle.call(repo, org, cfg[:token], cfg[:api_base])
      when 'gitlab'
        cfg = creds.fetch('gitlab', {})
        ::GitlabSecurityHandle.call(repo, org, cfg[:token], cfg[:api_base])
      else
        # Unreachable today: `normalise` raises on anything outside SUPPORTED.
        # Present because the failure it guards is the quiet kind — add a forge
        # to SUPPORTED, forget to wire it here, and this returns nil. The caller
        # then gets a NoMethodError somewhere unrelated, or treats nil as "no
        # resource" and reports the target as unreadable. Failing here names the
        # actual mistake.
        raise ::Inspec::Exceptions::ResourceFailed,
              "#{forge} is listed in SUPPORTED but no resource is wired for it " \
              'in ForgeSecurity. Add the branch, or remove it from SUPPORTED.'
      end
    end

    # Organisation scope, for the reconciliation denominator. A separate entry
    # point because the two resources are constructed differently at org scope
    # (GitHub takes `org:`, GitLab takes a group path) while answering the same
    # question through `repo_names`.
    def org_handle(org, forge:, creds:)
      case normalise(forge, 'the organisation')
      when 'github'
        cfg = creds.fetch('github', {})
        ::GithubSecurity.new(org: org, token: cfg[:token], api_base: cfg[:api_base])
      when 'gitlab'
        cfg = creds.fetch('gitlab', {})
        ::GitlabSecurity.new(nil, group: org, token: cfg[:token], api_base: cfg[:api_base])
      else
        # Unreachable today: `normalise` raises on anything outside SUPPORTED.
        # Present because the failure it guards is the quiet kind — add a forge
        # to SUPPORTED, forget to wire it here, and this returns nil. The caller
        # then gets a NoMethodError somewhere unrelated, or treats nil as "no
        # resource" and reports the target as unreadable. Failing here names the
        # actual mistake.
        raise ::Inspec::Exceptions::ResourceFailed,
              "#{forge} is listed in SUPPORTED but no resource is wired for it " \
              'in ForgeSecurity. Add the branch, or remove it from SUPPORTED.'
      end
    end

    private

    def normalise(value, subject)
      forge = value.to_s.strip.downcase
      if forge.empty?
        raise ::Inspec::Exceptions::ResourceFailed,
              "no forge declared for #{subject}. Set `forge:` on the target, " \
              'on `defaults`, or on `organization` — it cannot be inferred, ' \
              'and defaulting it would silently read the wrong platform.'
      end
      unless SUPPORTED.include?(forge)
        raise ::Inspec::Exceptions::ResourceFailed,
              "unknown forge #{value.inspect} for #{subject}. " \
              "Supported: #{SUPPORTED.join(', ')}. Not defaulting, because a " \
              'typo that silently reads the wrong platform is the hardest ' \
              'failure here to notice.'
      end
      forge
    end
  end
end

::Object.const_set(:ForgeSecurity, ForgeSecurity) unless ::Object.const_defined?(:ForgeSecurity)
