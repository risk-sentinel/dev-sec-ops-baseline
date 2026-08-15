# encoding: utf-8
# =============================================================================
# evidence_store — reads converted HDF evidence out of the S3 evidence bucket.
#
# The fourth detection surface (#10). The other three answer "can I see the scan
# from where I am standing"; this one answers "did the scan run at some point
# and leave evidence behind", which is the only surface that works for a tool
# with no API when you are not inside its pipeline.
#
# TruffleHog is the standing example: it has no platform API, so a control-plane
# run cannot see it however well the pipeline runs it. Its HDF in the evidence
# bucket is the only out-of-band proof it ran.
#
# ---- Canonical layout -------------------------------------------------------
#
#   <boundary>/<date|latest>/<repo>/<source>/<source>-hdf.json
#
# `latest` is overwritten every emit; the dated slots accumulate. Both are
# written by the same step, so a dated object without a matching `latest` means
# the pointer write broke rather than the scan.
#
# ---- Why credential failures RAISE ------------------------------------------
#
# Every other resource here captures transport failure in `connection_error` and
# lets the control FAIL. This one deliberately raises.
#
# A missing or unusable AWS credential is not a finding about the repository —
# it says nothing about whether the scan ran. Failing would assert something
# untrue; passing would be worse; skipping would read as "not applicable". An
# exception makes InSpec emit `status: failed` WITH a backtrace, which Heimdall's
# rollup renders as Profile Error: no credit, and visibly not an assessment.
#
# Verified: raising from a subject yields failed+backtrace in the InSpec JSON.
# The Profile Error rendering is Heimdall's documented render-time rollup, not
# something stored in the file.
#
# NOTE this is inconsistent with github_security and sonarqube_project, which
# capture and fail. Whether those should also raise on credential problems is a
# real question, deliberately not answered here.
# =============================================================================

require 'time'

class EvidenceStore < Inspec.resource(1)
  name 'evidence_store'
  supports platform: 'os'
  desc 'Presence, freshness and attribution of converted HDF evidence in the S3 evidence bucket.'
  example <<~EXAMPLE
    describe evidence_store('dev-sec-ops-baseline', source: 'trufflehog',
                            bucket: input('evidence_bucket'),
                            boundary: input('evidence_boundary'),
                            lookback_days: input('evidence_lookback_days')) do
      it { should exist }
      it { should be_within_window }
      it { should be_attributed }
    end
  EXAMPLE

  # Our canonical layout. Overridable because a team that already aggregates
  # evidence has their own, and telling them to re-file it is not "meeting them
  # where they are" — it is asking them to move.
  DEFAULT_TEMPLATE = '{boundary}/{slot}/{repo}/{source}/{source}-hdf.json'.freeze

  attr_reader :repo, :source, :bucket, :boundary, :lookback_days, :template

  def initialize(repo = nil, opts = {})
    if repo.is_a?(Hash)
      opts = repo
      repo = opts[:repo] || opts['repo']
    end
    opts = {} unless opts.is_a?(Hash)

    @repo          = repo.to_s
    @source        = (opts[:source] || opts['source']).to_s
    @bucket        = (opts[:bucket] || opts['bucket']).to_s
    @boundary      = (opts[:boundary] || opts['boundary'] || 'sparc').to_s
    @lookback_days = (opts[:lookback_days] || opts['lookback_days'] || 7).to_i
    @template      = (opts[:key_template] || opts['key_template'] || DEFAULT_TEMPLATE).to_s
    # 'hdf' | 'native' | 'auto'. Mature teams aggregate HDF; less mature ones
    # aggregate whatever their scanners emit. Refusing the second group would
    # make this surface useful only to teams who least need help.
    @format        = (opts[:format] || opts['format'] || 'auto').to_s
    # Structural marker for the native form, taken from the registry so the
    # artifact surface and this one cannot disagree about what a valid Trivy or
    # Grype file looks like.
    @marker        = (opts[:marker] || opts['marker']).to_s
    @require_labels = opts.key?(:require_labels) ? opts[:require_labels] : opts['require_labels']
    @cache         = {}
  end

  def to_s
    "Evidence Store '#{@boundary}/<slot>/#{@repo}/#{@source}'"
  end

  # ---- Location -------------------------------------------------------------
  # Placeholders: {boundary} {slot} {repo} {source}
  #
  # {slot} is required. It is what distinguishes the `latest` pointer from a
  # dated object, and without it the lookback walk has nothing to vary — every
  # candidate would resolve to the same key and a stale object would read as
  # current. A template missing it is rejected rather than quietly degraded.
  def key_for(slot)
    @template
      .gsub('{boundary}', @boundary)
      .gsub('{slot}', slot.to_s)
      .gsub('{repo}', @repo)
      .gsub('{source}', @source)
  end

  # latest first, then walk the dated slots backwards through the window.
  #
  # `latest` alone is one request and carries the age in its LastModified, so it
  # is the cheap common case. The fallback exists because `latest` and the dated
  # object are written by separate copies of the same step: if the pointer write
  # breaks while dated writes continue, reading only `latest` would report a
  # repository as having no evidence while a month of it sits in the bucket.
  # Those are different failures with different owners and must not collapse.
  def resolve
    @cache[:resolve] ||= begin
      require_config!
      found = head(key_for('latest'))
      if found
        { slot: 'latest', key: key_for('latest'), last_modified: found.last_modified,
          size: found.content_length, via: :pointer }
      else
        scan_dated_slots
      end
    end
  end

  def exists?  = !resolve.nil?
  def found?   = exists?
  def slot     = resolve && resolve[:slot]
  def via      = resolve && resolve[:via]

  # True only when the pointer was missing and a dated object answered instead —
  # evidence exists, but the `latest` write is broken.
  def pointer_broken?
    r = resolve
    !r.nil? && r[:via] == :dated
  end

  # ---- Freshness ------------------------------------------------------------
  def last_modified = resolve && resolve[:last_modified]

  def age_days
    t = last_modified
    return nil if t.nil?
    ((Time.now.utc - t.utc) / 86_400).floor
  end

  # The assessment question: is this evidence recent enough to count?
  #
  # Absent evidence is NOT within the window — but it is also not the same
  # finding as stale evidence, and callers should distinguish them. `exists?`
  # answers one, this answers the other.
  def within_window?
    a = age_days
    return false if a.nil?
    a <= @lookback_days
  end

  # ---- Attribution ----------------------------------------------------------
  # The key path says which repository this evidence belongs to. The HDF's own
  # labels say the same thing independently, because the emit step stamps
  # repo/commit/ref/run_id into the file.
  #
  # Path alone is a CONVENTION — anything with write access to the bucket can
  # put a file at any prefix. Labels alone cannot prove the object is filed
  # where a reader will look for it. Agreement between the two is what makes the
  # attribution trustworthy, and disagreement is a real finding: evidence filed
  # under the wrong repository is worse than absent, because it credits the
  # wrong thing.
  def labels
    @cache[:labels] ||= begin
      r = resolve
      return {} if r.nil?
      body = get_body(r[:key])
      extract_labels(body)
    end
  end

  # Three states, not two. Collapsing them was a defect: a team pointing at
  # their own aggregation has no labels (we did not write the file), and that is
  # NOT the same event as evidence labelled for a different repository.
  #
  #   :corroborated  labels present and agree with the key path
  #   :path_only     no labels — attribution rests on the path convention alone
  #   :contradicted  labels name a different repository
  def attribution_state
    l = labels
    return :path_only if l.empty? || l['repo'].to_s.empty?
    l['repo'].to_s.split('/').last == @repo ? :corroborated : :contradicted
  end

  # A CONTRADICTION always fails, whatever the policy: evidence filed under the
  # wrong repository is worse than absent, because it credits the wrong thing.
  # Only the treatment of ABSENT labels is configurable, and it defaults to
  # accepting path-only attribution so a foreign store works out of the box.
  def attributed?
    case attribution_state
    when :contradicted then false
    when :path_only    then !require_labels?
    else                    true
    end
  end

  def require_labels?
    @require_labels.nil? ? false : @require_labels
  end

  def attribution_detail
    l = labels
    case attribution_state
    when :corroborated
      "path and labels agree (repo=#{l['repo']}, commit=#{l['commit'].to_s[0, 8]})"
    when :contradicted
      "MISMATCH: filed under #{@repo} but labelled repo=#{l['repo']} — " \
        'evidence attributed to the wrong repository'
    else
      'path-only: the evidence carries no repo label, so attribution rests on ' \
        'the key path convention rather than the file itself'
    end
  end

  # ---- Shape ----------------------------------------------------------------
  # HDF has baselines[] (native) or profiles[] (legacy). A native scanner file
  # is identified by the registry's own marker for that tool. TruffleHog is
  # JSONL rather than a JSON document, so it is detected by parsing the first
  # line rather than the whole file.
  def document
    @cache[:document] ||= begin
      r = resolve
      return nil if r.nil?
      raw = get_body(r[:key])
      parse_permissive(raw)
    end
  end

  def hdf?
    d = document
    d.is_a?(Hash) && (d.key?('baselines') || d.key?('profiles'))
  end

  def native?
    d = document
    return false unless d.is_a?(Hash)
    return true if @marker.empty? && !hdf?
    dig_marker(d, @marker) ? true : false
  end

  def valid_shape?
    case @format
    when 'hdf'    then hdf?
    when 'native' then native?
    else               hdf? || native?
    end
  end

  def shape_detail
    return 'unreadable' if document.nil?
    return "HDF (#{document.key?('baselines') ? 'native schema' : 'legacy profiles[]'})" if hdf?
    if native?
      return "native #{@source} output" if @marker.empty?
      return "native #{@source} output (marker #{@marker.inspect} present)"
    end
    "unrecognised shape — expected #{@format == 'native' ? "native #{@source}" : 'HDF'}" \
      "#{@marker.empty? ? '' : " or marker #{@marker.inspect}"}"
  end

  private

  def require_config!
    missing = []
    missing << 'repo'   if @repo.empty?
    missing << 'source' if @source.empty?
    missing << 'bucket' if @bucket.empty?
    unless @template.include?('{slot}')
      raise Inspec::Exceptions::ResourceFailed,
            "evidence_key_template must contain {slot} (got #{@template.inspect}) — " \
            'without it the freshness window cannot distinguish latest from a dated object'
    end
    return if missing.empty?
    # Raise, not capture: an unconfigured resource has assessed nothing, and a
    # result that says so is more useful than a false negative.
    raise Inspec::Exceptions::ResourceFailed,
          "evidence_store is not configured: missing #{missing.join(', ')}"
  end

  def s3
    @s3 ||= begin
      # Lazy-require: aws-sdk-s3 is heavy and only this surface needs it, so a
      # token-only run never pays for it. Same pattern as document_attestation.
      require 'aws-sdk-s3'
      Aws::S3::Client.new
    rescue LoadError => e
      raise Inspec::Exceptions::ResourceFailed,
            "aws-sdk-s3 is unavailable in this runtime: #{e.message}"
    end
  end

  def head(key)
    s3.head_object(bucket: @bucket, key: key)
  rescue Aws::S3::Errors::NotFound, Aws::S3::Errors::NoSuchKey
    nil
  rescue StandardError => e
    # Access denied, no credentials, wrong region, bucket missing — none of
    # these are statements about the repository being assessed. Raise so the
    # control errors rather than reporting a repository as unevidenced because
    # we could not look.
    raise Inspec::Exceptions::ResourceFailed,
          "S3 head_object failed for s3://#{@bucket}/#{key} " \
          "(#{e.class.name.split('::').last}): #{e.message}"
  end

  def get_body(key)
    s3.get_object(bucket: @bucket, key: key).body.read
  rescue StandardError => e
    raise Inspec::Exceptions::ResourceFailed,
          "S3 get_object failed for s3://#{@bucket}/#{key} " \
          "(#{e.class.name.split('::').last}): #{e.message}"
  end

  def scan_dated_slots
    today = Time.now.utc.to_date
    (0..@lookback_days).each do |back|
      slot = (today - back).strftime('%Y-%m-%d')
      obj = head(key_for(slot))
      next if obj.nil?
      return { slot: slot, key: key_for(slot), last_modified: obj.last_modified,
               size: obj.content_length, via: :dated }
    end
    nil
  end

  # Parses a JSON document, or the first record of a JSONL stream. TruffleHog
  # emits JSONL, so a whole-file parse fails on exactly the evidence this
  # surface most needs to read.
  def parse_permissive(raw)
    require 'json'
    JSON.parse(raw)
  rescue JSON::ParserError
    first = raw.to_s.each_line.find { |l| !l.strip.empty? }
    return nil if first.nil?
    begin
      JSON.parse(first)
    rescue JSON::ParserError
      nil
    end
  end

  def dig_marker(doc, marker)
    return nil if marker.to_s.empty?
    marker.split('.').reduce(doc) { |acc, k| acc.is_a?(Hash) ? acc[k] : nil }
  end

  # Labels live in the HDF passthrough. Read defensively: an unlabelled or
  # differently-shaped file is a weaker attribution story, not a crash.
  # A native scanner file has no labels by construction — we did not write it —
  # so an empty hash here is the expected answer for that case, not a failure.
  # parse_permissive already absorbed any parse error, so there is nothing left
  # to rescue.
  def extract_labels(body)
    doc = parse_permissive(body)
    return {} unless doc.is_a?(Hash)
    [
      doc.dig('passthrough', 'labels'),
      doc.dig('passthrough', 'raw', 'labels'),
      doc['labels'],
      doc.dig('profiles', 0, 'passthrough', 'labels')
    ].compact.find { |c| c.is_a?(Hash) } || {}
  end
end

# Promote to top level — InSpec evaluates libraries in an anonymous context, so
# a plain constant never reaches Object and control files fail at exec with
# "uninitialized constant". Custom resources self-register, but the require-time
# constant lookup below still needs it.
::Object.const_set(:EvidenceStore, EvidenceStore) unless ::Object.const_defined?(:EvidenceStore)
