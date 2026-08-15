# Plan and Design

**Scan types:** none automated.

## What is expected

Threat modelling, security requirements, and an architecture review before code is
written. NIST 800-53r5 anchors this at `SA-11(2)` (threat modelling and vulnerability
analyses) and `PL-8` (security architecture); SSDF places it in PO and PW.1.

## Why nothing is automated here

Threat modelling produces a *document and a conversation*, not a scanner artifact.
There is no API to interrogate and no report format to validate. Attempting to
automate it would produce a control that passes whenever a file exists, which
measures filing rather than thinking.

## How it is evidenced instead

Through the attestation path: a signed statement referencing the threat model, its
date, and its reviewers. The consumer repo's `document_attestation` resource reads
such documents over `github://`, `gitlab://`, `s3://` or `https://` and asserts both
existence and freshness, so a stale threat model fails rather than passes.

This is the correct use of attestation — a genuinely manual, API-invisible activity.
It is *not* a fallback for things we could automate but have not yet.
