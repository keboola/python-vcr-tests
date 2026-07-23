# Scrub-before-read response sanitization — design

- **Date:** 2026-07-23
- **Status:** Approved (design), pending implementation plan
- **Package:** `keboola.vcr` (`src/keboola/vcr/`)
- **Branch:** `feat/scrub-before-read-sanitization`

## Problem

When recording cassettes against real customer data, the **cassette** is
sanitized but the component's **output** is not.
A response containing `{"customer_name": "Bob"}` is redacted to `REDACTED` in the
saved cassette, yet the component's output table still contains the real `Bob`.

### Root cause (confirmed)

During recording, sanitization runs on a *copy* of the response that is written to
the cassette; the *original* response is handed unchanged to the component.

- In [`recorder.py`](../../../src/keboola/vcr/recorder.py) `_append_interaction`
  makes a shallow copy of the response and sanitizes only that copy. Its own
  comment states this is deliberate: *"Shallow copy prevents our sanitizer from
  mutating the response dict that VCRHTTPResponse will return to the component."*
- Verified against the installed **vcrpy 8.1.1**: in `vcr/stubs/__init__.py`
  `getresponse()`, vcrpy calls `cassette.append(request, response)` and then
  `VCRHTTPResponse(response)` **on the same `response` dict object**, one line
  apart. Whatever `append` does to that dict in place is what the component reads.

So today: the component reads the real value → writes real customer data to
`out/tables/*.csv` (or Parquet, or straight to Storage) → those artifacts become
committed test fixtures containing real PII. There is no output/CSV sanitization
anywhere in the package (the validator only hashes output files, it does not
scrub them).

## Goal

The component must **never receive real customer data** during a recording run.
Redaction happens in-flight, on the HTTP response, before the component reads it.

This is deliberately chosen over scrubbing outputs after the run, because
scrubbing outputs is output-format-dependent and fragile: a component may emit
CSV, Parquet, or write directly to Storage. Sanitizing once at the HTTP boundary
is format-agnostic — whatever the component does downstream is clean by
construction.

### Success criteria

1. With the feature enabled, a value redacted before-read never appears in the
   component's outputs, in any format, nor in the cassette.
2. Values the component must *reuse* against the live API during recording
   (OAuth tokens, async job IDs, pagination cursors) remain **real** for the
   component, so OAuth and async-poll flows still record correctly.
3. Zero behaviour change when the feature is not enabled.

## Non-goals / scope

- **Responses only.** Outbound requests to the real server stay real — sanitizing
  them would fetch the wrong data. Request *recording* sanitization is unchanged.
- **No new PII-detection sanitizers** in this change (no allowlist / regex-PII
  sanitizer). The feature works with the existing sanitizer classes; any future
  sanitizer inherits the flag for free.
- **CF Claude Kit documentation** (telling component authors this exists and how
  to use it) is a **separate follow-up PR** after this lands.

## Approaches considered

| Approach | Verdict |
|---|---|
| **A. Scrub outputs after the run** | Rejected. Format-dependent; cannot cover direct-to-Storage writes; component still processes real data in memory. |
| **B. Feed the *whole* sanitizer chain's output to the component** | Rejected. The default chain redacts `access_token`; feeding that to the component breaks OAuth (component would send `Bearer REDACTED` to the live API). Same problem for any round-tripped ID/cursor — silent recording corruption. |
| **C. In-flight response scrub, opt-in per sanitizer (chosen)** | Reuses existing sanitizer classes. A per-sanitizer flag marks which sanitizers also apply to what the component reads. Tokens/IDs stay cassette-only by default, so OAuth/async keep working. |

## Design

### The flag

A new boolean, **`scrub_before_read`** (default `False`), on `BaseSanitizer`,
inherited by every sanitizer.

- `scrub_before_read=True` → this sanitizer's redaction is applied to the
  response **before the component reads it**, and (as before) to the cassette.
- `scrub_before_read=False` (default) → cassette-only, exactly as today.

### Data flow (record run)

```
response from real API:
  {name: "Bob", access_token: "T", next_cursor: "c1", data: [...]}
        │
        ▼  (only if any scrub_before_read sanitizer exists)
     decode gzip in place + strip Content-Encoding
     run scrub_before_read sanitizers in place
        │
   ┌────┴───────────────────────────────┐
   ▼                                     ▼
 COMPONENT reads                     cassette copy → full chain
 {name:"REDACTED",                   (adds token redaction, header whitelist)
  access_token:"T",                        │
  next_cursor:"c1"}                         ▼
   │  real token + real cursor →      cassette: {name:"REDACTED",
   │  live follow-up calls work        access_token:"REDACTED", ...}
   ▼
 writes REDACTED → CSV / Parquet / Storage (clean by construction)
```

The component sees **redacted PII but real tokens/cursors/IDs**. Because the
before-read transform (decode + strip encoding) is exactly what replay already
does, the component receives replay-equivalent data — anything that would break
under it generally also breaks on replay, so we are not introducing a new class
of failure (with one exception: round-tripped redacted values, see Risks).

### Recorder mechanism

The recorder partitions its sanitizer chain into two views:

- **pre-read view** = sanitizers with `scrub_before_read=True`.
- **cassette view** = the full chain (all sanitizers), unchanged from today.

In `_append_interaction` (bound as `cassette.append`, invoked on the shared
`response` dict immediately before `VCRHTTPResponse(response)`), when the
pre-read view is non-empty:

1. **Decode the body in place** using vcrpy's own decompression filter and strip
   `Content-Encoding` — a gzipped body must be decompressed or the sanitizer
   cannot match `"Bob"` inside it. This is the same transform replay performs.
2. **Run the pre-read sanitizers in place** on the shared `response` dict → the
   component inherits the redaction (via the existing `_zero_copy_vcr_response_init`
   patch, which wraps the now-scrubbed `body["string"]`).
3. **Copy and run the full chain** for the cassette, as today. Re-running decode
   on the copy is a no-op (encoding already stripped); re-running the pre-read
   sanitizers is idempotent (`REDACTED` stays `REDACTED`); the cassette-only
   sanitizers add token redaction and header whitelisting.

This whole path is **gated on the pre-read view being non-empty**. When no
sanitizer is tagged, `_append_interaction` behaves byte-for-byte as it does now
(no decode-in-place; the component gets the raw body). The zero-copy reader and
the pool-reuse / shared-SSLContext OOM patches are untouched.

### Public API / author contract

A component's `tests/.../sanitizers.py`:

```python
from keboola.vcr import BodyFieldSanitizer

def get_sanitizers(config):
    return [
        # PII the component only reads and emits → scrub before the component reads it
        BodyFieldSanitizer(fields=["customer_name", "email", "phone"], scrub_before_read=True),
        # tokens / job-ids / cursors → leave untagged: they stay real for the
        # component during recording, and the default chain still scrubs them
        # from the cassette exactly as before.
    ]
```

The framework's built-in default sanitizers (token/secret redaction) stay
`scrub_before_read=False`. `record_debug_run` honours the flag if flagged
sanitizers are passed to it; no special handling is required.

### The hard rule for authors

**Never tag a sanitizer that touches a value the component sends back to the live
API** — pagination cursors, async job IDs, OAuth tokens. Those must stay real
during recording. Tag only terminal/leaf PII (names, emails, free-text
verbatims). This is enforced defensively by the safety net below.

### Safety net (fail-fast)

With pre-read scrubbing active, if the component issues a request to the **live**
API whose URL or body contains a pre-read sanitizer's replacement placeholder
(e.g. `REDACTED`), the recorder raises a clear, actionable error:

> A `scrub_before_read` sanitizer redacted a value that the component sent back
> to the live API (likely a pagination cursor, ID, or token). Remove that field
> from `scrub_before_read`.

This converts the async-job / round-tripped-value footgun into a diagnosable
message instead of a confusing 4xx buried in the recording. Detection point:
the request filter (`_before_record_request`), which sees the outgoing request;
it is best-effort (the bad live request has already been sent) but produces a
clear diagnosis. The check runs only when the pre-read view is non-empty.

## Backward compatibility

- No sanitizer tagged → the feature is inert; recording behaves exactly as today.
- `BaseSanitizer` gains a class-level default `scrub_before_read = False`, so any
  sanitizer (including third-party subclasses that never heard of the flag) is
  safely treated as cassette-only via `getattr(s, "scrub_before_read", False)`.

## Risks and edge cases

1. **Round-tripped redacted values** (the core risk). Redacting a value the
   component reuses in a later live request breaks recording. Mitigated by: the
   safe default (tokens/IDs untagged), the author rule, and the fail-fast net.
2. **`_dedup_sanitizers` merging.** `_dedup_sanitizers` (used by
   `record_debug_run`) merges same-class sanitizers. It must treat
   `scrub_before_read` as part of the merge key, so a `scrub_before_read=True`
   `DefaultSanitizer` is never merged with a cassette-only one. `merge()`
   implementations must carry the flag through.
3. **Compression.** Decode-in-place allocates a decompressed copy of the body;
   unavoidable (you cannot scrub compressed bytes). Bounded by the sanitizers'
   existing pre-scan — the transform only runs for responses that actually
   contain a tagged field/value. Must not double-decode (strip
   `Content-Encoding` after decoding).
4. **Headers.** Only tagged sanitizers run before-read; a body-only PII sanitizer
   leaves response headers untouched for the component, so the component still
   sees real pagination/rate-limit headers during recording. Header whitelisting
   remains a cassette-only concern (and a pre-existing replay concern), unchanged.
5. **Binary / non-UTF-8 bodies.** Sanitizers already no-op when they find no
   match; a decoded image passes through unredacted, matching replay behaviour.
6. **Memory / OOM.** The extra transform is gated on tagged sanitizers and on the
   pre-scan hit; the zero-copy reader and pool-reuse patches are preserved.

## Testing plan

- **Component-visible redaction:** a `scrub_before_read=True` sanitizer → a fake
  runner reading the response observes `REDACTED`; the cassette also has
  `REDACTED`.
- **Isolation:** an untagged token sanitizer → the component reads the **real**
  token; the cassette has `REDACTED` (OAuth stays intact).
- **Regression:** no flag anywhere → the component reads real data (today's
  behaviour, unchanged); existing tests still pass.
- **Compression:** a gzipped response with a PII field → the component sees
  decoded + redacted body; no double-decode.
- **Guardrail:** a tagged sanitizer redacts a cursor the fake runner reuses in a
  follow-up request → the recorder raises the actionable error.
- **Dedup:** `record_debug_run` with both a tagged and an untagged
  `DefaultSanitizer` → they are not merged; the partition is preserved.
- **Two-call integration:** a token call + a data call, token sanitizer untagged,
  PII sanitizer tagged → recording completes and the data-call output is redacted.

## Follow-ups (out of scope for this PR)

- Separate PR to CF Claude Kit (`component-developer` plugin) documenting the
  `scrub_before_read` flag and the author rule, so component authors know to
  reach for it when recording against real customer data.
