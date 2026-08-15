# encoding: utf-8
# =============================================================================
# sonarqube_project — reads SonarQube / SonarCloud project state.
#
# SonarQube is an EVIDENCE SOURCE, not a forge: it has an API and no merge-rule
# duties. The registry keeps that distinction because collapsing it makes
# "which forge enforces merge rules?" unanswerable.
#
# Same construction contract as github_security, for the same reasons:
#   - positional opts hash, never kwargs (InSpec dispatches through a *args
#     splat; kwargs raise "given 2, expected 0..1" at exec time)
#   - token from opts, never input() — input() raises in resource scope
#   - transport failure captured in connection_error, never raised, so an
#     unreachable API FAILS instead of passing vacuously
#
# ---- Why last_analysis_at is the important method ---------------------------
#
# The API reports whatever SonarQube LAST analysed. That may be days old. An
# artifact on a runner was produced by the run in progress.
#
# Treating the two as equally strong lets a stale API result mask a scan that
# did not run today — a silent pass of precisely the kind this profile exists
# to prevent. So this resource exposes the analysis timestamp, and callers can
# require freshness rather than mere existence.
#
# A project that has NEVER been analysed is distinguished from one that cannot
# be read: the first is a finding about the project, the second about access.
# =============================================================================

require 'json'
require 'net/http'
require 'time'
require 'uri'

class SonarqubeProject < Inspec.resource(1)
  name 'sonarqube_project'
  supports platform: 'os'
  desc 'Analysis state, freshness and findings for a SonarQube / SonarCloud project.'
  example <<~EXAMPLE
    describe sonarqube_project('risk-sentinel_sparc', token: input('sonar_token')) do
      it { should exist }
      it { should be_analyzed_within(7) }
      its('quality_gate_status') { should cmp 'OK' }
    end
  EXAMPLE

  DEFAULT_API = 'https://sonarcloud.io'.freeze

  attr_reader :project_key, :connection_error

  def initialize(project_key = nil, opts = {})
    if project_key.is_a?(Hash)
      opts        = project_key
      project_key = opts[:project_key] || opts['project_key']
    end
    opts = {} unless opts.is_a?(Hash)

    @project_key = project_key.to_s
    @api_base    = (opts[:api_base] || opts['api_base'] || DEFAULT_API).to_s.chomp('/')
    @token       = opts[:token] || opts['token'] ||
                   ENV.fetch('SONAR_TOKEN', nil) || ENV.fetch('SONARQUBE_TOKEN', nil)
    @timeout     = (opts[:timeout] || opts['timeout'] || 15).to_i
    @authenticated = !@token.to_s.empty?

    @connection_error = nil
    @cache = {}

    return unless @project_key.empty?
    @connection_error = 'no project_key supplied'
  end

  def to_s
    "SonarQube Project '#{@project_key}'"
  end

  # ---- Existence is three-state, and findings are gated on it ---------------
  #
  # Two traps the live API sets, both found by probing rather than reading docs:
  #
  #   1. `issues/search` returns HTTP 200 with `total: 0` for a project that
  #      DOES NOT EXIST. Reading that as an issue count reports a nonexistent
  #      project as clean — the vacuous pass this profile exists to prevent.
  #      So every findings method is gated on `found?`.
  #
  #   2. A PRIVATE project returns 401/403, not 404. Collapsing that into
  #      "does not exist" would let a missing token look like a missing
  #      project, and the remediation for those is completely different.
  #
  # :found | :not_found | :denied | :error
  def component_status
    @cache[:component_status] ||= begin
      resp = component
      case resp[:code]
      when 200      then :found
      when 404      then :not_found
      when 401, 403 then :denied
      else               :error
      end
    end
  end

  def exists?        = component_status == :found
  def access_denied? = component_status == :denied

  def authenticated? = @authenticated

  # Only true when we positively established absence — never when we simply
  # could not look.
  #
  # SonarCloud returns 404 (not 403) for a private project the caller cannot
  # see: it deliberately does not leak existence. So WITHOUT a token, "not
  # found" and "private" are the same response, and claiming absence would
  # manufacture findings against every private project in the estate. Absence
  # is only assertable when a token was supplied.
  def absent?
    component_status == :not_found && @authenticated
  end

  # The honest state for an unauthenticated 404: we cannot tell.
  def indeterminate?
    component_status == :not_found && !@authenticated
  end

  def readable?
    return true if exists?
    @connection_error ||= case component_status
                          when :denied
                            "project #{@project_key} exists or not — access denied " \
                            '(missing or unscoped token)'
                          when :not_found
                            if @authenticated
                              "project #{@project_key} not found"
                            else
                              "project #{@project_key} not readable without a token — " \
                              'SonarCloud returns 404 for private projects, so absence ' \
                              'and privacy are indistinguishable here'
                            end
                          else
                            "project #{@project_key} unreadable (HTTP #{component[:code]})"
                          end
    false
  end

  # ---- Freshness ------------------------------------------------------------
  # nil means "never analysed" OR "could not read" — the two are separated by
  # connection_error, which callers must check. Returning a bare nil that could
  # mean either would be the vacuous-pass trap again.
  def last_analysis_at
    return nil unless readable?
    @cache[:analysis] ||= begin
      resp = get("/api/project_analyses/search?project=#{u(@project_key)}&ps=1")
      if resp[:code] == 200
        date = resp[:body].to_h['analyses']&.first&.dig('date')
        date ? safe_time(date) : nil
      else
        note_error(resp, 'project_analyses')
        nil
      end
    end
  end

  def analysis_age_days
    t = last_analysis_at
    return nil if t.nil?
    ((Time.now - t) / 86_400).floor
  end

  # The predicate a control should assert on when API evidence is being used to
  # satisfy a scan type. `exist?` alone would accept an analysis from last year.
  def analyzed_within?(days)
    age = analysis_age_days
    return false if age.nil?
    age <= days.to_i
  end

  # ---- Findings -------------------------------------------------------------
  # nil, never 0, when the project cannot be read. A zero here would read as
  # "clean" for a project nobody can see.
  def open_issue_count
    # Gated: a 200/total:0 from a nonexistent project must never read as clean.
    return nil unless readable?
    @cache[:issues] ||= begin
      resp = get("/api/issues/search?componentKeys=#{u(@project_key)}&resolved=false&ps=1")
      if resp[:code] == 200
        resp[:body].to_h['total']
      else
        note_error(resp, 'issues')
        nil
      end
    end
  end

  def quality_gate_status
    return nil unless readable?
    @cache[:gate] ||= begin
      resp = get("/api/qualitygates/project_status?projectKey=#{u(@project_key)}")
      if resp[:code] == 200
        resp[:body].to_h.dig('projectStatus', 'status')
      else
        note_error(resp, 'quality gate')
        nil
      end
    end
  end

  private

  def component
    @cache[:component] ||= get("/api/components/show?component=#{u(@project_key)}")
  end

  def u(str)
    URI.encode_www_form_component(str.to_s)
  end

  def safe_time(str)
    Time.parse(str.to_s)
  rescue ArgumentError, TypeError
    @connection_error ||= "unparseable analysis date: #{str.inspect}"
    nil
  end

  def note_error(resp, what)
    msg = Array(resp[:body].to_h['errors']).map { |e| e['msg'] }.compact.join('; ')
    detail = "#{what}: HTTP #{resp[:code]}#{msg.empty? ? '' : " (#{msg})"}"
    # Guard against recording a blank string: "" is not nil, so a control
    # asserting `connection_error should be_nil` would fail with nothing useful
    # to show for it.
    return if detail.strip.empty?
    @connection_error ||= detail
  end

  def headers
    h = { 'Accept' => 'application/json', 'User-Agent' => 'dev-sec-ops-baseline' }
    # SonarCloud accepts a bearer token; public projects need none at all,
    # which is why an absent token is not itself an error.
    h['Authorization'] = "Bearer #{@token}" if @token && !@token.to_s.empty?
    h
  end

  def get(path)
    uri = URI.parse("#{@api_base}#{path}")
    resp = Net::HTTP.start(uri.host, uri.port,
                           use_ssl: uri.scheme == 'https',
                           open_timeout: @timeout, read_timeout: @timeout) do |http|
      http.get(uri.request_uri, headers)
    end
    parsed = begin
      resp.body.to_s.empty? ? nil : JSON.parse(resp.body)
    rescue JSON::ParserError
      nil
    end
    { code: resp.code.to_i, body: parsed }
  rescue StandardError => e
    @connection_error = "GET #{path} failed: #{e.class}: #{e.message}"
    { code: 0, body: nil }
  end
end
