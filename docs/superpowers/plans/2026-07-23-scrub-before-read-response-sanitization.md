# Scrub-before-read Response Sanitization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** During a VCR recording run, redact tagged response fields *before the
component reads them*, so the component never processes real customer data and
its outputs (CSV/Parquet/Storage) are clean by construction.

**Architecture:** Add a per-sanitizer `scrub_before_read` flag. The recorder
partitions its sanitizer chain into a *pre-read* subset (tagged sanitizers) and
the full *cassette* chain (unchanged). In `_append_interaction` — which vcrpy
calls on the same `response` dict it immediately hands to the component via
`VCRHTTPResponse(response)` — the pre-read subset is applied to that dict *in
place* (after decompressing the body), so the redaction reaches both the
component and the cassette. A fail-fast guardrail aborts recording if the
component sends a redacted placeholder back to the live API.

**Tech Stack:** Python 3.11–3.13, vcrpy 8.3.0, pytest, uv, ruff, ty.

## Global Constraints

- **vcrpy pin:** `vcrpy>=8.3.0,<9` (already bumped — see Prerequisite). Never
  rely on stock `Cassette.append`; we override it and must keep the shallow-copy
  path (no `deepcopy`) to preserve the OOM fix.
- **Backward compatibility:** with no sanitizer tagged `scrub_before_read=True`,
  recording behaviour is byte-for-byte unchanged. The pre-read path must be
  gated on `self._pre_read_sanitizer is not None`.
- **Default replacement string:** `"REDACTED"`.
- **Memory:** only decompress the response in the pre-read path when a
  `Content-Encoding` header is actually present (avoid a full-body deepcopy on
  the common uncompressed path). Do not disturb `_VCRRecordingReader` /
  `_zero_copy_vcr_response_init` / `_pool_reuse_patch`.
- **No customer names or engagement names** in code, tests, commits, or docs.
- **Tooling:** run tests with `uv run pytest`. Pre-commit runs ruff-format,
  ruff, ty, and pytest on commit; commits must pass.
- **Commit trailer:** end every commit message with
  `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.

---

## Prerequisite (DONE)

vcrpy floor bumped `>=8.1.1,<9` → `>=8.3.0,<9` in `pyproject.toml`, `uv.lock`
regenerated (vcrpy 8.3.0), full suite verified green. Committed as
`build: bump vcrpy floor to >=8.3.0` (957a2b0). No action needed.

---

### Task 1: `scrub_before_read` flag on sanitizers + dedup key

**Files:**
- Modify: `src/keboola/vcr/sanitizers.py`
- Test: `tests/test_sanitizers.py`

**Interfaces:**
- Produces: every `BaseSanitizer` subclass accepts `scrub_before_read: bool = False`
  and exposes it as the attribute `self.scrub_before_read`. `BaseSanitizer` has a
  class-level default `scrub_before_read = False` so any sanitizer (including
  third-party) is safely readable via `getattr(s, "scrub_before_read", False)`.
  `_dedup_sanitizers` treats `(type(s), s.scrub_before_read)` as the merge key.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_sanitizers.py` (imports `DefaultSanitizer`,
`BodyFieldSanitizer`, `_dedup_sanitizers` — `DefaultSanitizer` and
`BodyFieldSanitizer` are already imported in this file; add `_dedup_sanitizers`
to the existing `from keboola.vcr.sanitizers import ...` line):

```python
class TestScrubBeforeReadFlag:
    def test_defaults_false(self):
        assert DefaultSanitizer().scrub_before_read is False
        assert BodyFieldSanitizer(fields=["x"]).scrub_before_read is False

    def test_flag_set_true(self):
        s = BodyFieldSanitizer(fields=["name"], scrub_before_read=True)
        assert s.scrub_before_read is True

    def test_merge_preserves_flag(self):
        a = DefaultSanitizer(additional_sensitive_fields=["a"], scrub_before_read=True)
        b = DefaultSanitizer(additional_sensitive_fields=["b"], scrub_before_read=True)
        assert a.merge(b).scrub_before_read is True

    def test_dedup_keeps_different_flag_values_separate(self):
        tagged = DefaultSanitizer(additional_sensitive_fields=["pii"], scrub_before_read=True)
        cassette_only = DefaultSanitizer(additional_sensitive_fields=["tok"])
        result = _dedup_sanitizers([tagged, cassette_only])
        assert len(result) == 2

    def test_dedup_merges_same_flag_values(self):
        a = DefaultSanitizer(additional_sensitive_fields=["a"], scrub_before_read=True)
        b = DefaultSanitizer(additional_sensitive_fields=["b"], scrub_before_read=True)
        result = _dedup_sanitizers([a, b])
        assert len(result) == 1
        assert result[0].scrub_before_read is True
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_sanitizers.py::TestScrubBeforeReadFlag -v`
Expected: FAIL — `TypeError: __init__() got an unexpected keyword argument 'scrub_before_read'`.

- [ ] **Step 3: Add the class default to `BaseSanitizer`**

In `src/keboola/vcr/sanitizers.py`, add a class attribute to `BaseSanitizer`
(right under the docstring, before `before_record_request`):

```python
class BaseSanitizer(ABC):
    """..."""

    # When True, the recorder applies this sanitizer to the response BEFORE the
    # component reads it (and to the cassette). Default False = cassette-only.
    scrub_before_read: bool = False
```

- [ ] **Step 4: Add the kwarg to every leaf sanitizer `__init__`**

For each sanitizer below, add `scrub_before_read: bool = False` as the **last**
constructor parameter and add `self.scrub_before_read = scrub_before_read` as the
**last** line of `__init__`. Apply to all nine leaf classes:
`DefaultSanitizer`, `TokenSanitizer`, `HeaderSanitizer`, `BodyFieldSanitizer`,
`QueryParamSanitizer`, `ResponseUrlSanitizer`, `UrlPatternSanitizer`,
`CallbackSanitizer`, `ConfigSecretsSanitizer`.

Two worked examples (apply the identical pattern to the other seven):

`DefaultSanitizer.__init__` — signature and body:

```python
    def __init__(
        self,
        sensitive_fields: list[str] | None = None,
        additional_sensitive_fields: list[str] | None = None,
        sensitive_values: list[str] | None = None,
        safe_headers: list[str] | None = None,
        additional_safe_headers: list[str] | None = None,
        replacement: str = "REDACTED",
        config: dict[str, Any] | None = None,
        scrub_before_read: bool = False,
    ):
        # ... existing body unchanged ...
        self.scrub_before_read = scrub_before_read
```

`BodyFieldSanitizer.__init__`:

```python
    def __init__(
        self,
        fields: list[str],
        replacement: str = "REDACTED",
        nested: bool = True,
        scrub_before_read: bool = False,
    ):
        self.fields = set(fields)
        self.replacement = replacement
        self.nested = nested
        self.scrub_before_read = scrub_before_read
```

(`CompositeSanitizer` is intentionally **not** given the kwarg — the recorder
flattens composites and reads the leaf flags; it keeps the inherited default.)

- [ ] **Step 5: Propagate the flag through every `merge()`**

Six sanitizers define `merge()`: `DefaultSanitizer`, `TokenSanitizer`,
`HeaderSanitizer`, `QueryParamSanitizer`, `UrlPatternSanitizer`,
`ResponseUrlSanitizer`. In each, add `scrub_before_read=self.scrub_before_read`
to the constructor call it returns. Example (`DefaultSanitizer.merge`):

```python
    def merge(self, other: DefaultSanitizer) -> DefaultSanitizer:
        merged_values = list(dict.fromkeys(self.sensitive_values + other.sensitive_values))
        return DefaultSanitizer(
            sensitive_fields=list(self.sensitive_fields | other.sensitive_fields),
            safe_headers=list(self.safe_headers | other.safe_headers),
            sensitive_values=merged_values,
            replacement=self.replacement,
            scrub_before_read=self.scrub_before_read,
        )
```

- [ ] **Step 6: Make `_dedup_sanitizers` flag-aware**

Change the merge key from the class to `(class, scrub_before_read)`:

```python
def _dedup_sanitizers(sanitizers: list[BaseSanitizer]) -> list[BaseSanitizer]:
    """Merge same-class sanitizers to avoid redundant processing passes.

    Sanitizers with differing ``scrub_before_read`` are never merged, so a
    pre-read (PII) sanitizer is kept distinct from a cassette-only one.
    """
    result: list[BaseSanitizer] = []
    by_key: dict[tuple, int] = {}  # (class, scrub_before_read) -> index in result
    for s in sanitizers:
        key = (type(s), getattr(s, "scrub_before_read", False))
        if key in by_key and hasattr(result[by_key[key]], "merge"):
            result[by_key[key]] = result[by_key[key]].merge(s)  # ty: ignore[unresolved-attribute]
        else:
            by_key[key] = len(result)
            result.append(s)
    return result
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `uv run pytest tests/test_sanitizers.py -v`
Expected: PASS (the new `TestScrubBeforeReadFlag` class and all pre-existing
sanitizer tests).

- [ ] **Step 8: Commit**

```bash
git add src/keboola/vcr/sanitizers.py tests/test_sanitizers.py
git commit -m "feat(sanitizers): add scrub_before_read flag

Adds an opt-in per-sanitizer flag marking sanitizers whose redaction must reach
the component (not only the cassette). merge() propagates it and
_dedup_sanitizers keys on it so tagged and cassette-only sanitizers stay
distinct.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: Recorder partitions the pre-read sanitizers

**Files:**
- Modify: `src/keboola/vcr/recorder.py` (`VCRRecorder.__init__`, new static
  `_flatten_sanitizers`)
- Test: `tests/test_recorder.py`

**Interfaces:**
- Consumes: `s.scrub_before_read` (Task 1), `CompositeSanitizer` (already
  imported in `recorder.py`).
- Produces: on every `VCRRecorder` instance —
  `self._pre_read_sanitizer: CompositeSanitizer | None` (None when nothing is
  tagged), `self._pre_read_sanitizers: list[BaseSanitizer]`, and
  `self._pre_read_placeholders: set[str]` (the `.replacement` strings of tagged
  sanitizers, for the Task 4 guardrail).

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_recorder.py`:

```python
class TestPreReadPartition:
    def test_no_tagged_sanitizer_means_none(self, tmp_cassette_dir):
        r = VCRRecorder(cassette_dir=tmp_cassette_dir, sanitizers=[DefaultSanitizer()])
        assert r._pre_read_sanitizer is None
        assert r._pre_read_placeholders == set()

    def test_tagged_sanitizer_detected(self, tmp_cassette_dir):
        from keboola.vcr.sanitizers import BodyFieldSanitizer

        s = BodyFieldSanitizer(fields=["name"], scrub_before_read=True)
        r = VCRRecorder(cassette_dir=tmp_cassette_dir, sanitizers=[s])
        assert r._pre_read_sanitizer is not None
        assert "REDACTED" in r._pre_read_placeholders

    def test_tagged_inside_composite_is_flattened(self, tmp_cassette_dir):
        from keboola.vcr.sanitizers import BodyFieldSanitizer, CompositeSanitizer

        s = BodyFieldSanitizer(fields=["name"], scrub_before_read=True)
        r = VCRRecorder(cassette_dir=tmp_cassette_dir, sanitizers=[CompositeSanitizer([s])])
        assert r._pre_read_sanitizer is not None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_recorder.py::TestPreReadPartition -v`
Expected: FAIL — `AttributeError: 'VCRRecorder' object has no attribute '_pre_read_sanitizer'`.

- [ ] **Step 3: Add the partition to `__init__`**

In `src/keboola/vcr/recorder.py`, immediately **after** the existing sanitizer
setup block (the `default = create_default_sanitizer(...)` / `self.sanitizer = ...`
lines, ending around line 261) and **before** `self._is_replaying = False`, add:

```python
        # Partition: sanitizers tagged scrub_before_read=True are applied to the
        # response BEFORE the component reads it (see _append_interaction), in
        # addition to the cassette. The rest stay cassette-only.
        all_sanitizers = self._flatten_sanitizers([default, *(sanitizers or [])])
        self._pre_read_sanitizers = [s for s in all_sanitizers if getattr(s, "scrub_before_read", False)]
        self._pre_read_sanitizer = (
            CompositeSanitizer(self._pre_read_sanitizers) if self._pre_read_sanitizers else None
        )
        self._pre_read_placeholders = {
            p for p in (getattr(s, "replacement", "") for s in self._pre_read_sanitizers) if p
        }
```

- [ ] **Step 4: Add the `_flatten_sanitizers` static helper**

Add this static method to `VCRRecorder` (place it near the other static helpers,
e.g. just before `_load_custom_sanitizers`):

```python
    @staticmethod
    def _flatten_sanitizers(sanitizers: list[BaseSanitizer]) -> list[BaseSanitizer]:
        """Flatten nested CompositeSanitizers into a flat list of leaf sanitizers."""
        flat: list[BaseSanitizer] = []
        for s in sanitizers:
            if isinstance(s, CompositeSanitizer):
                flat.extend(VCRRecorder._flatten_sanitizers(s.sanitizers))
            else:
                flat.append(s)
        return flat
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_recorder.py::TestPreReadPartition -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/keboola/vcr/recorder.py tests/test_recorder.py
git commit -m "feat(recorder): partition scrub_before_read sanitizers

Splits the chain into a pre-read subset (tagged sanitizers, flattened out of any
composites) and the full cassette chain. Collects their replacement placeholders
for the fail-fast guardrail.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: Apply pre-read sanitizers to the component-visible response

**Files:**
- Modify: `src/keboola/vcr/recorder.py` (`_append_interaction`; new
  `_apply_pre_read_sanitizers`, `_decode_response_inplace`)
- Test: `tests/test_recorder.py`

**Interfaces:**
- Consumes: `self._pre_read_sanitizer` (Task 2), `vcr.filters.decode_response`.
- Produces: when `self._pre_read_sanitizer` is set, `_append_interaction` mutates
  the shared `response` dict in place (decoded + PII-redacted) so
  `VCRHTTPResponse(response)` hands the redacted data to the component; the
  cassette copy still runs the full chain. When it is `None`, behaviour is
  unchanged.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_recorder.py` (this helper builds a vcrpy-style request stub
with the `_to_dict()` method `_append_interaction` calls):

```python
def _make_request(uri="https://api.example.com/v1/customers", body=None):
    from types import SimpleNamespace

    req = SimpleNamespace(
        uri=uri, method="GET", headers={"Content-Type": "application/json"}, body=body
    )
    req._to_dict = lambda: {
        "uri": req.uri, "method": req.method, "headers": dict(req.headers), "body": req.body
    }
    return req


class TestPreReadAppliedInAppend:
    def test_component_visible_response_is_redacted(self, tmp_cassette_dir):
        from keboola.vcr.sanitizers import BodyFieldSanitizer

        s = BodyFieldSanitizer(fields=["name"], scrub_before_read=True)
        r = VCRRecorder(cassette_dir=tmp_cassette_dir, sanitizers=[s])
        temp = tmp_cassette_dir / "t.jsonl"
        response = {
            "status": {"code": 200, "message": "OK"},
            "headers": {"Content-Type": ["application/json"]},
            "body": {"string": b'{"name": "Bob", "id": 7}'},
        }
        r._append_interaction(temp, r._before_record_response, _make_request(), response)
        # the component reads this exact dict via VCRHTTPResponse -> must be redacted
        assert b"Bob" not in response["body"]["string"]
        assert b"REDACTED" in response["body"]["string"]
        assert b'"id": 7' in response["body"]["string"]  # untagged field preserved
        # cassette line is redacted too
        line = temp.read_text()
        assert "Bob" not in line and "REDACTED" in line

    def test_no_tag_leaves_component_response_untouched(self, tmp_cassette_dir):
        from keboola.vcr.sanitizers import BodyFieldSanitizer

        s = BodyFieldSanitizer(fields=["name"])  # NOT tagged -> cassette-only
        r = VCRRecorder(cassette_dir=tmp_cassette_dir, sanitizers=[s])
        temp = tmp_cassette_dir / "t.jsonl"
        response = {
            "status": {"code": 200, "message": "OK"},
            "headers": {},
            "body": {"string": b'{"name": "Bob"}'},
        }
        r._append_interaction(temp, r._before_record_response, _make_request(), response)
        assert response["body"]["string"] == b'{"name": "Bob"}'  # untouched for component
        assert "REDACTED" in temp.read_text()  # cassette still sanitized

    def test_untagged_token_stays_real_for_component_but_redacted_in_cassette(self, tmp_cassette_dir):
        from keboola.vcr.sanitizers import BodyFieldSanitizer, TokenSanitizer

        pii = BodyFieldSanitizer(fields=["name"], scrub_before_read=True)
        tok = TokenSanitizer(tokens=["SECRET_TOKEN"])  # untagged -> cassette-only
        r = VCRRecorder(cassette_dir=tmp_cassette_dir, sanitizers=[pii, tok])
        temp = tmp_cassette_dir / "t.jsonl"
        response = {
            "status": {"code": 200, "message": "OK"},
            "headers": {},
            "body": {"string": b'{"name": "Bob", "access_token": "SECRET_TOKEN"}'},
        }
        r._append_interaction(temp, r._before_record_response, _make_request(), response)
        # component: PII redacted, token REAL (needed for follow-up live calls)
        assert b"Bob" not in response["body"]["string"]
        assert b"SECRET_TOKEN" in response["body"]["string"]
        # cassette: both redacted
        line = temp.read_text()
        assert "SECRET_TOKEN" not in line
        assert "Bob" not in line

    def test_gzip_body_decoded_and_redacted_for_component(self, tmp_cassette_dir):
        import gzip

        from keboola.vcr.sanitizers import BodyFieldSanitizer

        s = BodyFieldSanitizer(fields=["name"], scrub_before_read=True)
        r = VCRRecorder(cassette_dir=tmp_cassette_dir, sanitizers=[s])
        temp = tmp_cassette_dir / "t.jsonl"
        response = {
            "status": {"code": 200, "message": "OK"},
            "headers": {"Content-Encoding": ["gzip"]},
            "body": {"string": gzip.compress(b'{"name": "Bob"}')},
        }
        r._append_interaction(temp, r._before_record_response, _make_request(), response)
        assert b"REDACTED" in response["body"]["string"]
        # encoding stripped so the component's HTTP stack won't try to gunzip plaintext
        assert "Content-Encoding" not in response["headers"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_recorder.py::TestPreReadAppliedInAppend -v`
Expected: FAIL — `test_component_visible_response_is_redacted` fails
(`b"Bob"` still present) because the shared response is not yet mutated.

- [ ] **Step 3: Add the pre-read helpers**

In `src/keboola/vcr/recorder.py`, add these two methods to `VCRRecorder` (place
them next to `_append_interaction`):

```python
    def _decode_response_inplace(self, response: dict) -> None:
        """Decompress the response body in place, but only when encoded.

        vcrpy's decode_response deep-copies and returns a new dict; we copy the
        decoded body/headers back onto the shared ``response`` so the component
        reads decompressed content. Skipped when no Content-Encoding is present,
        which keeps the common uncompressed path allocation-free.
        """
        headers = response.get("headers", {})
        if not any(str(k).lower() == "content-encoding" for k in headers):
            return
        from vcr.filters import decode_response

        decoded = decode_response(response)
        response["body"] = decoded["body"]
        response["headers"] = decoded["headers"]

    def _apply_pre_read_sanitizers(self, response: dict) -> None:
        """Redact the shared response in place so the component sees redacted data.

        Runs only the scrub_before_read sanitizers (PII), after decompressing the
        body so they can match. This same dict is handed to the component by
        vcrpy's VCRHTTPResponse(response) one call after cassette.append.
        """
        self._decode_response_inplace(response)
        self._pre_read_sanitizer.before_record_response(response)
```

- [ ] **Step 4: Wire the pre-read pass into `_append_interaction`**

Modify `_append_interaction` so it mutates the shared `response` before building
the cassette copy. The new body (guardrail call is added in Task 4 — leave it out
for now):

```python
    def _append_interaction(self, temp_path: Path, cassette_before_record_response, request, response) -> None:
        """Serialize a single recorded interaction to the JSONL temp file."""
        # Apply request filter directly — avoids copy.deepcopy inside original_append
        filtered_request = self._before_record_request(request)
        if not filtered_request:
            return

        # scrub_before_read: redact the shared response IN PLACE so the component,
        # which reads this same dict via VCRHTTPResponse(response), sees the
        # redacted data. Gated on a pre-read sanitizer being configured.
        if self._pre_read_sanitizer is not None:
            self._apply_pre_read_sanitizers(response)

        # Shallow copy prevents the cassette-only sanitizers from mutating the
        # response dict the component reads. The bytes object referenced by
        # body["string"] is immutable, so sharing it is safe.
        response_copy = {
            **response,
            "body": {**response.get("body", {})},
            "headers": dict(response.get("headers", {})),
        }
        filtered_response = cassette_before_record_response(response_copy)
        if filtered_response is None:
            return

        with open(temp_path, "a") as f:
            _write_interaction(f, filtered_request._to_dict(), filtered_response)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_recorder.py::TestPreReadAppliedInAppend -v`
Expected: PASS (all four tests).

- [ ] **Step 6: Run the full suite (regression check)**

Run: `uv run pytest -q`
Expected: PASS — all pre-existing tests still green (confirms the no-tag path is
unchanged).

- [ ] **Step 7: Commit**

```bash
git add src/keboola/vcr/recorder.py tests/test_recorder.py
git commit -m "feat(recorder): redact tagged fields before the component reads them

When scrub_before_read sanitizers are configured, _append_interaction decodes and
redacts the shared response dict in place before vcrpy hands it to the component
via VCRHTTPResponse. Untagged sanitizers (tokens/IDs) stay cassette-only, so the
component keeps real values it round-trips to the live API.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: Fail-fast guardrail for redacted values sent to the live API

**Files:**
- Modify: `src/keboola/vcr/recorder.py` (`_append_interaction`, new
  `_check_no_redacted_value_sent`)
- Test: `tests/test_recorder.py`

**Interfaces:**
- Consumes: `self._pre_read_sanitizer`, `self._pre_read_placeholders` (Task 2),
  `VCRRecorderError` (already defined in `recorder.py`).
- Produces: `_append_interaction` raises `VCRRecorderError` when a pre-read
  placeholder appears in an outgoing live request (checked on the raw request,
  before request-sanitization, to avoid false positives from legitimately
  redacted request fields).

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_recorder.py` (reuses `_make_request` from Task 3):

```python
class TestRedactedValueGuardrail:
    def test_raises_when_redacted_value_sent_to_live_api(self, tmp_cassette_dir):
        from keboola.vcr.recorder import VCRRecorderError
        from keboola.vcr.sanitizers import BodyFieldSanitizer

        s = BodyFieldSanitizer(fields=["cursor"], scrub_before_read=True)
        r = VCRRecorder(cassette_dir=tmp_cassette_dir, sanitizers=[s])
        temp = tmp_cassette_dir / "t.jsonl"
        response = {"status": {"code": 200, "message": "OK"}, "headers": {}, "body": {"string": b"{}"}}
        req = _make_request(uri="https://api.example.com/v1/data?cursor=REDACTED")
        with pytest.raises(VCRRecorderError, match="scrub_before_read"):
            r._append_interaction(temp, r._before_record_response, req, response)

    def test_no_raise_without_tagged_sanitizer(self, tmp_cassette_dir):
        r = VCRRecorder(cassette_dir=tmp_cassette_dir, sanitizers=[DefaultSanitizer()])
        temp = tmp_cassette_dir / "t.jsonl"
        response = {"status": {"code": 200, "message": "OK"}, "headers": {}, "body": {"string": b"{}"}}
        req = _make_request(uri="https://api.example.com/data?cursor=REDACTED")
        r._append_interaction(temp, r._before_record_response, req, response)  # no raise
        assert temp.exists()

    def test_no_false_positive_on_real_token_in_request(self, tmp_cassette_dir):
        from keboola.vcr.sanitizers import BodyFieldSanitizer

        s = BodyFieldSanitizer(fields=["name"], scrub_before_read=True)
        r = VCRRecorder(cassette_dir=tmp_cassette_dir, sanitizers=[s])
        temp = tmp_cassette_dir / "t.jsonl"
        response = {"status": {"code": 200, "message": "OK"}, "headers": {}, "body": {"string": b'{"name": "Bob"}'}}
        req = _make_request(uri="https://api.example.com/data?access_token=REALTOKEN123")
        r._append_interaction(temp, r._before_record_response, req, response)  # no raise
        assert "REDACTED" in temp.read_text()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_recorder.py::TestRedactedValueGuardrail -v`
Expected: FAIL — `test_raises_when_redacted_value_sent_to_live_api` does not
raise (guardrail not implemented).

- [ ] **Step 3: Add the guardrail method**

Add to `VCRRecorder` (next to `_append_interaction`):

```python
    def _check_no_redacted_value_sent(self, request: Any) -> None:
        """Fail fast if the component sent a scrub_before_read placeholder to the live API.

        A placeholder in an outgoing request means a tagged sanitizer redacted a
        value the component round-trips (a cursor, ID, or token) — which breaks
        the live follow-up call. Checked on the raw request (before request
        sanitization) so a legitimately redacted request field is not a false hit.
        """
        if not self._pre_read_placeholders:
            return
        parts: list[str] = []
        uri = getattr(request, "uri", None)
        if isinstance(uri, str):
            parts.append(uri)
        body = getattr(request, "body", None)
        if isinstance(body, bytes):
            parts.append(body.decode("utf-8", errors="ignore"))
        elif isinstance(body, str):
            parts.append(body)
        haystack = "\n".join(parts)
        for placeholder in self._pre_read_placeholders:
            if placeholder and placeholder in haystack:
                raise VCRRecorderError(
                    f"A scrub_before_read sanitizer redacted a value that the component "
                    f"sent back to the live API (found placeholder {placeholder!r} in an "
                    f"outgoing request). This usually means a tagged field is round-tripped "
                    f"by the component — a pagination cursor, ID, or token. Remove that field "
                    f"from scrub_before_read so it stays real during recording."
                )
```

- [ ] **Step 4: Call the guardrail first in `_append_interaction`**

Add the check as the very first statement of `_append_interaction`, before
`filtered_request = self._before_record_request(request)`:

```python
    def _append_interaction(self, temp_path: Path, cassette_before_record_response, request, response) -> None:
        """Serialize a single recorded interaction to the JSONL temp file."""
        # Fail fast if the component round-tripped a redacted value to the live API.
        if self._pre_read_sanitizer is not None:
            self._check_no_redacted_value_sent(request)

        # Apply request filter directly — avoids copy.deepcopy inside original_append
        filtered_request = self._before_record_request(request)
        # ... rest of the method unchanged (from Task 3) ...
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_recorder.py::TestRedactedValueGuardrail -v`
Expected: PASS (all three tests).

- [ ] **Step 6: Commit**

```bash
git add src/keboola/vcr/recorder.py tests/test_recorder.py
git commit -m "feat(recorder): fail fast when a redacted value is sent to the live API

Guards the async-job / pagination-cursor footgun: if a scrub_before_read
sanitizer redacts a value the component round-trips into a later live request,
recording aborts with an actionable error instead of silently corrupting the
cassette. Checked on the raw request to avoid false positives.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 5: Document `scrub_before_read` in the package README

**Files:**
- Modify: `README.md`

**Interfaces:**
- Consumes: the finished feature (Tasks 1–4).

- [ ] **Step 1: Add a usage section to `README.md`**

Insert this section after the existing `## Features` section:

````markdown
## Sanitizing data before the component reads it

By default, sanitizers scrub the **cassette** only — during recording the
component still receives the real API response, so real values can end up in the
component's output tables. To stop real customer data from ever reaching the
component, tag a sanitizer with `scrub_before_read=True`. The recorder then
redacts those fields in the response *before the component reads them*, so the
output is clean regardless of format (CSV, Parquet, or direct-to-Storage).

```python
# tests/.../sanitizers.py
from keboola.vcr import BodyFieldSanitizer

def get_sanitizers(config):
    return [
        # PII the component only reads and emits → redacted before the component reads it
        BodyFieldSanitizer(fields=["customer_name", "email", "phone"], scrub_before_read=True),
    ]
```

**Rule:** only tag fields the component *consumes and emits*. Never tag a value
the component sends back to the live API during recording — a pagination cursor,
an async job ID, or an OAuth token — because it must stay real for the follow-up
request to succeed. Token/secret sanitizers stay untagged (cassette-only) for
exactly this reason. If a redacted value is sent to the live API, recording
aborts with an error telling you which field to untag.
````

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: document scrub_before_read in README

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Follow-ups (separate PR, out of scope)

- CF Claude Kit (`component-developer` plugin): document the `scrub_before_read`
  flag and the author rule so component authors reach for it when recording
  against real customer data.

## Self-Review

**Spec coverage**

| Spec item | Task |
|---|---|
| `scrub_before_read` flag on `BaseSanitizer` + all sanitizers | Task 1 |
| `merge()` propagates flag; `_dedup_sanitizers` merge-key includes flag | Task 1 |
| Recorder partitions pre-read vs cassette views | Task 2 |
| In-place decode + redact in `_append_interaction` (component-visible) | Task 3 |
| Backward compatible when no sanitizer tagged | Task 3 (regression test + gating) |
| Compression handled (decode, strip Content-Encoding, no double-decode) | Task 3 |
| Token/round-trip isolation (component keeps real token) | Task 3 |
| Fail-fast guardrail for redacted round-tripped values | Task 4 |
| vcrpy dependency bump to `>=8.3.0` | Prerequisite (done) |
| README documents the flag + rule | Task 5 |
| CF Claude Kit docs | Follow-up (out of scope) |

**Placeholder scan:** none — every code and test step contains complete code.

**Type consistency:** `scrub_before_read: bool` (attribute), `_pre_read_sanitizer:
CompositeSanitizer | None`, `_pre_read_sanitizers: list[BaseSanitizer]`,
`_pre_read_placeholders: set[str]`, `_flatten_sanitizers`,
`_apply_pre_read_sanitizers`, `_decode_response_inplace`,
`_check_no_redacted_value_sent` — names used consistently across Tasks 2–4.
