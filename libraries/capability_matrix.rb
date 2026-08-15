# encoding: utf-8
# =============================================================================
# CapabilityMatrix — resolves the tool registry against a user declaration.
#
# Registry  (files/tool_registry.yml) = what this profile CAN detect, and where.
# Declaration (inputs/*.yml)          = what a given organisation's pipelines run.
# This module computes the intersection and assigns each cell a verdict.
#
# ---- Deliberately free of I/O -----------------------------------------------
# `load` takes YAML STRINGS, not paths. Two reasons:
#
#   1. Profile files are read with `inspec.profile.file('tool_registry.yml')`,
#      which is only available in control scope. Keeping the read out here means
#      controls do the I/O and this module stays a pure function of its input.
#   2. It makes the whole resolution layer unit-testable without a profile
#      context, which is where the interesting edge cases live.
#
# ---- Not an InSpec resource -------------------------------------------------
# This is a plain module, so it may be required and called from anywhere.
# The related constraint that DOES bite elsewhere: InSpec custom resources
# cannot call `input()` — it raises in resource scope, and `defined?(input)` is
# not a usable guard. github_security therefore takes everything through an
# opts hash passed down from the control body.
# =============================================================================

require 'yaml'
require 'set'

module CapabilityMatrix
  # Verdicts. These map onto the three result semantics agreed for the profile.
  #
  #   :check  enabled, and we can evaluate it -> a real pass/fail assertion
  #   :attest not enabled -> SKIP, "must be manually verified and attested to".
  #           An attestation can satisfy this. It is a statement about the
  #           repository.
  #   :gap    enabled, but this profile cannot see it yet -> SKIP with a
  #           coverage-gap rationale. An attestation must NOT satisfy this: the
  #           finding is about the profile, not the repository. Kept verbally
  #           distinct from :attest for exactly that reason.
  VERDICTS = %i[check attest gap].freeze

  ATTEST_RATIONALE = 'Not enabled and must be manually verified and attested to'.freeze
  GAP_RATIONALE    = 'Enabled, but not yet detectable by this profile — ' \
                     'coverage gap, not a repository finding'.freeze

  class Registry
    attr_reader :scan_types, :tools, :sources, :capabilities, :sdlc_stages,
                :surfaces, :run_modes

    def initialize(data)
      @scan_types   = data['scan_types']   || {}
      @tools        = data['tools']        || {}
      @sources      = data['sources']      || {}
      @capabilities = data['capabilities'] || {}
      @sdlc_stages  = data['sdlc_stages']  || {}
      @surfaces     = data['surfaces']     || {}
      @run_modes    = data['run_modes']    || {}
      @alias_index  = build_alias_index
    end

    # Surfaces that may prove a scan RAN. Configuration-role surfaces are
    # excluded on purpose: a workflow file naming a scanner proves somebody
    # wired it up, not that it executed or produced anything.
    def execution_surfaces
      @surfaces.select { |_, m| m['role'] == 'execution' }.keys
    end

    def configuration_surfaces
      @surfaces.select { |_, m| m['role'] == 'configuration' }.keys
    end

    # Surfaces the given run mode can actually read.
    def surfaces_for_mode(mode)
      Array(@run_modes[mode.to_s])
    end

    # The intersection that matters: readable in this mode AND allowed to prove
    # execution. This is what scan-type coverage is computed over.
    def eligible_surfaces(mode)
      surfaces_for_mode(mode) & execution_surfaces
    end

    # Resolve a vendor spelling to the canonical scan type.
    # GitLab says "dependency scanning"; `sca` is canonical here.
    def canonical_scan_type(name)
      key = name.to_s
      return key if @scan_types.key?(key)
      @alias_index[key]
    end

    def scan_type?(name)
      !canonical_scan_type(name).nil?
    end

    # Tools declaring support for a scan type.
    def tools_for(scan_type)
      canonical = canonical_scan_type(scan_type)
      return {} unless canonical
      @tools.select { |_, t| Array(t['scan_types']).include?(canonical) }
    end

    # Scan types with no tool at all — declared gaps, not omissions.
    # `iast` is the current example: the concept exists organisation-wide, the
    # tooling does not, and an absent row would imply the concept does not.
    def uncovered_scan_types
      @scan_types.keys.reject { |st| tools_for(st).any? }
    end

    # Surfaces a tool can be seen on, with status. Absent key => not detectable
    # that way at all (a forge-native feature leaves nothing on the runner).
    def surfaces_for(tool_key)
      (@tools.dig(tool_key, 'surfaces') || {})
    end

    def surface_status(tool_key, surface)
      surfaces_for(tool_key).dig(surface, 'status')
    end

    def implemented?(tool_key, surface)
      surface_status(tool_key, surface) == 'implemented'
    end

    # Endpoint + documentation for a capability on a given source.
    # Drives both the resource's request construction and the README links,
    # so the two cannot disagree.
    def binding_for(capability, source)
      @capabilities.dig(capability, 'bindings', source)
    end

    def sources_of_kind(kind)
      @sources.select { |_, s| s['kind'] == kind }
    end

    private

    def build_alias_index
      idx = {}
      @scan_types.each do |canonical, meta|
        Array(meta['aliases']).each { |a| idx[a.to_s] = canonical }
      end
      idx
    end
  end

  # A single (repo, scan_type, tool, surface) cell with its verdict.
  # Per-surface detail, used to build the coverage matrix.
  Cell = Struct.new(:repo, :scan_type, :tool, :surface, :verdict, :rationale,
                    keyword_init: true) do
    def check?  = verdict == :check
    def attest? = verdict == :attest
    def gap?    = verdict == :gap
  end

  # A (repo, scan_type) verdict taken across ALL declared tools and ALL
  # eligible surfaces. This is what a control asserts on.
  #
  # `covered_by` carries which tool and surface satisfied it, so the result
  # says "covered by TruffleHog on the artifact surface" rather than a bare
  # pass — an assessor needs to know which mechanism did the work.
  Coverage = Struct.new(:repo, :scan_type, :status, :covered_by, :rationale,
                        :detail, keyword_init: true) do
    def covered? = status == :covered
    def attest?  = status == :attest
    def gap?     = status == :gap

    def summary
      return rationale unless covered?
      covered_by.map { |h| "#{h[:tool]} (#{h[:surface]})" }.join(', ')
    end
  end

  class << self
    # registry_yaml / declaration_yaml are STRINGS.
    def load(registry_yaml)
      Registry.new(YAML.safe_load(registry_yaml) || {})
    end

    def load_declaration(declaration_yaml)
      YAML.safe_load(declaration_yaml) || {}
    end

    # Merge `defaults.scans` under each target's own `scans`.
    # Target values win key-by-key; a target that declares nothing inherits
    # the defaults wholesale.
    def effective_scans(declaration, target)
      defaults = declaration.dig('defaults', 'scans') || {}
      own      = target['scans'] || {}
      defaults.merge(own) do |_key, default_val, own_val|
        (default_val || {}).merge(own_val || {})
      end
    end

    # The core resolution. Returns Cells for every (target, scan_type) pair,
    # expanded per declared tool.
    #
    # Every scan type in the DECLARATION is walked — never only the enabled
    # ones. Silence is the failure mode this whole design exists to prevent, so
    # a disabled scan type still produces a cell, carrying :attest.
    def resolve(registry, declaration, surface: 'platform_api')
      cells = []
      Array(declaration['targets']).each do |target|
        repo  = target['repo']
        scans = effective_scans(declaration, target)

        scans.each do |scan_name, spec|
          canonical = registry.canonical_scan_type(scan_name) || scan_name
          spec    ||= {}
          enabled  = spec['enabled'] ? true : false
          tools    = Array(spec['tools'])

          unless enabled
            cells << Cell.new(repo: repo, scan_type: canonical, tool: nil,
                              surface: surface, verdict: :attest,
                              rationale: ATTEST_RATIONALE)
            next
          end

          # Enabled but naming no tool is a malformed declaration, not a pass.
          if tools.empty?
            cells << Cell.new(repo: repo, scan_type: canonical, tool: nil,
                              surface: surface, verdict: :gap,
                              rationale: 'Declared enabled but names no tool')
            next
          end

          tools.each do |tool|
            implemented = registry.implemented?(tool, surface)
            cells << Cell.new(
              repo: repo, scan_type: canonical, tool: tool, surface: surface,
              verdict:   implemented ? :check : :gap,
              rationale: implemented ? nil : GAP_RATIONALE
            )
          end
        end
      end
      cells
    end

    # ---- Scan-type coverage -------------------------------------------------
    # THE question a control actually asks: "is this scan type covered for this
    # repository, and by what?"
    #
    # `resolve` above answers a narrower one — it walks a SINGLE surface and
    # reports per tool. That is useful for building the coverage matrix, but a
    # control calling it would report SonarQube as a gap on the platform_api
    # surface while its artifact sits on disk. Coverage is the union across
    # every declared tool and every eligible surface.
    #
    # This is what makes the forge-native licensing question mostly moot. A
    # repository whose `secrets` is declared with TruffleHog is covered by
    # TruffleHog's artifact, whether or not the forge's own secret scanning is
    # licensed. The native feature is only relevant when it is itself declared.
    def coverage(registry, declaration, run_mode: 'control-plane')
      eligible = registry.eligible_surfaces(run_mode)
      results  = []

      Array(declaration['targets']).each do |target|
        repo = target['repo']
        effective_scans(declaration, target).each do |scan_name, spec|
          canonical = registry.canonical_scan_type(scan_name) || scan_name
          spec    ||= {}
          tools     = Array(spec['tools'])

          unless spec['enabled']
            results << Coverage.new(repo: repo, scan_type: canonical,
                                    status: :attest, covered_by: [],
                                    rationale: ATTEST_RATIONALE)
            next
          end

          if tools.empty?
            results << Coverage.new(repo: repo, scan_type: canonical,
                                    status: :gap, covered_by: [],
                                    rationale: 'Declared enabled but names no tool')
            next
          end

          hits = tools.flat_map do |tool|
            eligible.filter_map do |surface|
              { tool: tool, surface: surface } if registry.implemented?(tool, surface)
            end
          end

          if hits.any?
            results << Coverage.new(repo: repo, scan_type: canonical,
                                    status: :covered, covered_by: hits,
                                    rationale: nil)
          else
            results << Coverage.new(
              repo: repo, scan_type: canonical, status: :gap, covered_by: [],
              rationale: GAP_RATIONALE,
              detail: "declared #{tools.join(', ')}; " \
                      "no execution surface implemented among #{eligible.join(', ')} " \
                      "in run_mode=#{run_mode}"
            )
          end
        end
      end
      results
    end

    # Forge-native capabilities that MUST be enabled, because a declared tool
    # depends on them.
    #
    # The point of this method is what it LEAVES OUT. If nobody declared the
    # forge's native scanning, then that feature being switched off is not a
    # finding — it is simply not the tool this repository uses. Asserting
    # enablement unconditionally would light up every private repository for
    # failing to buy a product it does not need, and an output like that trains
    # people to ignore it.
    def native_capabilities_required(registry, declaration, run_mode: 'control-plane')
      return {} unless registry.eligible_surfaces(run_mode).include?('platform_api')

      required = Hash.new { |h, k| h[k] = [] }
      Array(declaration['targets']).each do |target|
        repo = target['repo']
        effective_scans(declaration, target).each do |_scan, spec|
          spec ||= {}
          next unless spec['enabled']

          Array(spec['tools']).each do |tool|
            api = registry.surfaces_for(tool)['platform_api']
            next unless api && api['capability']
            required[repo] << {
              tool:       tool,
              capability: api['capability'],
              sources:    Array(api['sources'])
            }
          end
        end
      end
      required.transform_values(&:uniq)
    end

    # ---- Reconciliation — the denominator -----------------------------------
    # `actual` comes from the forge API, never from the declaration. A file
    # cannot be the evidence that it is complete.
    #
    # Archived / fork / template repositories are NOT filtered here. They are
    # excluded only by an explicit entry carrying a reason, so nothing leaves
    # the denominator without someone writing down why.
    def reconcile(declaration, actual_repos)
      declared = Array(declaration['targets']).map { |t| t['repo'] }.compact
      excluded = Array(declaration['exclusions'])

      excluded_names = excluded.map { |e| e['repo'] }.compact
      accounted      = Set.new(declared + excluded_names)
      actual         = Set.new(Array(actual_repos))

      {
        undeclared: (actual - accounted).to_a.sort,
        stale:      (Set.new(declared) - actual).to_a.sort,
        undocumented_exclusions:
          excluded.reject { |e| e['reason'].to_s.strip.empty? }
                  .then { |with_reason| excluded - with_reason }
                  .map { |e| e['repo'] }.compact.sort,
        counts: {
          actual:     actual.size,
          declared:   declared.size,
          excluded:   excluded_names.size,
          accounted:  accounted.size
        }
      }
    end

    def reconciled?(result)
      result[:undeclared].empty? &&
        result[:stale].empty? &&
        result[:undocumented_exclusions].empty?
    end
  end
end
