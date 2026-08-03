# Cassette Performance Metadata Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Record per-cassette performance metrics (HTTP request pairs, DB query pairs, data-collection window, whole-run duration) into the cassette's `_metadata` block during `record()`.

**Architecture:** Purely additive to the `_metadata` dict written only on `record()`. A module-level real-clock reference captured before any `freeze_time()` is applied lets durations be measured correctly even though the component runs inside a frozen clock. `_append_interaction()` stamps count + window anchors; a new pure `_build_perf_metadata()` helper turns the anchors into fields; `record()` sets the run-timing anchors and merges everything in.

**Tech Stack:** Python 3.14, `vcrpy` (>=8.3.0,<9), `freezegun`, `pytest`.

## Global Constraints

- Changes are confined to `src/keboola/vcr/recorder.py`; tests go in `tests/test_recorder.py`.
- Only the `record()` path is affected. Replay behavior, cassette `version` (`1`), the interaction schema, and all existing `_metadata` fields are unchanged.
- `_metadata` is a flat dict serialized with `sort_keys=True` — field order does not matter.
- All durations use the module-level `_REAL_MONOTONIC` reference (never a bare `time.monotonic()` call inside the run) and are rounded to 3 decimal places.
- ISO timestamps are UTC via `datetime.now(timezone.utc).isoformat()`, matching the existing `recorded_at` field.
- Follow existing code style (type hints, no new dependencies). Run `ruff` via the repo's pre-commit before each commit.

---

### Task 1: Real-clock reference + interaction counting/anchors

Add the module-level real clock, the per-recording perf state (initialized in `__init__` so it can be exercised without calling `record()`), and the counting/anchor stamping inside `_append_interaction()`. Proven by a direct unit test and the load-bearing freeze-gotcha regression test.

**Files:**
- Modify: `src/keboola/vcr/recorder.py` (imports; new module constant; `__init__`; new `_reset_perf_state`; `_append_interaction`)
- Test: `tests/test_recorder.py`

**Interfaces:**
- Produces (used by Tasks 2 and 3):
  - Module constant `_REAL_MONOTONIC` — `Callable[[], float]`, the genuine `time.monotonic`.
  - `VCRRecorder._reset_perf_state() -> None` — sets `_perf_request_pairs: int`, `_perf_first_interaction_mono: float | None`, `_perf_last_interaction_mono: float | None`, `_perf_run_start_wall: datetime | None`, `_perf_run_start_mono: float | None`, `_perf_run_end_mono: float | None`.
  - `_append_interaction` increments `_perf_request_pairs` and stamps `_perf_first_interaction_mono` / `_perf_last_interaction_mono` for every interaction actually written.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_recorder.py` (top-level imports `time`, `pytest`, and `from freezegun import freeze_time` if not already present; `from keboola.vcr.recorder import VCRRecorder`):

```python
class TestAppendInteractionPerf:
    def test_counts_and_anchors_each_written_interaction(self, tmp_cassette_dir, mock_request, mock_response):
        r = VCRRecorder(cassette_dir=tmp_cassette_dir)
        temp_path = tmp_cassette_dir / "interactions.jsonl.tmp"

        # cassette_before_record_response passthrough (no vcrpy machinery needed here)
        passthrough = lambda resp: resp

        r._append_interaction(temp_path, passthrough, mock_request, mock_response)
        r._append_interaction(temp_path, passthrough, mock_request, mock_response)

        assert r._perf_request_pairs == 2
        assert r._perf_first_interaction_mono is not None
        assert r._perf_last_interaction_mono is not None
        assert r._perf_last_interaction_mono >= r._perf_first_interaction_mono

    def test_anchors_advance_under_frozen_clock(self, tmp_cassette_dir, mock_request, mock_response):
        # Load-bearing regression: freezegun freezes time.monotonic. If _append_interaction
        # used a bare time.monotonic() the two anchors would be identical. The pre-freeze
        # _REAL_MONOTONIC reference must still advance.
        r = VCRRecorder(cassette_dir=tmp_cassette_dir)
        temp_path = tmp_cassette_dir / "interactions.jsonl.tmp"
        passthrough = lambda resp: resp

        with freeze_time("2020-01-01T00:00:00Z"):
            r._append_interaction(temp_path, passthrough, mock_request, mock_response)
            first = r._perf_first_interaction_mono
            time.sleep(0.01)
            r._append_interaction(temp_path, passthrough, mock_request, mock_response)
            last = r._perf_last_interaction_mono

        assert first is not None and last is not None
        assert last > first
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/bin/pytest tests/test_recorder.py::TestAppendInteractionPerf -v`
Expected: FAIL — `AttributeError: 'VCRRecorder' object has no attribute '_perf_request_pairs'`.

- [ ] **Step 3: Add imports and the module-level real-clock reference**

In `src/keboola/vcr/recorder.py`:

Change the datetime import (line 21) to add `timedelta`:

```python
from datetime import datetime, timedelta, timezone
```

Add `import time` in the stdlib import block (alphabetically, after `import re` at line 19):

```python
import re
import time
```

Add the module-level constant just after the import block ends (near the other module-level constants such as `DEFAULT_CASSETTE_FILE`, before the first class):

```python
# Captured at import — before any freeze_time() is ever applied. A bare
# `_REAL_MONOTONIC = time.monotonic` would be swapped too: freezegun's identity scan
# rebinds it right along with time.monotonic. Wrapping it in a closure (shipped form,
# per the freezegun reason in recorder.py) keeps the genuine clock in a cell variable
# the scan never reaches.
def _make_real_monotonic() -> Callable[[], float]:
    real = time.monotonic

    def _real_monotonic() -> float:
        return real()

    return _real_monotonic


_REAL_MONOTONIC: Callable[[], float] = _make_real_monotonic()
```

- [ ] **Step 4: Add `_reset_perf_state` and call it from `__init__`**

Add the method to `VCRRecorder` (place it near the other small helpers, e.g. just below `__init__`):

```python
def _reset_perf_state(self) -> None:
    """Reset per-recording performance counters and timing anchors."""
    self._perf_request_pairs = 0
    self._perf_first_interaction_mono: float | None = None
    self._perf_last_interaction_mono: float | None = None
    self._perf_run_start_wall: datetime | None = None
    self._perf_run_start_mono: float | None = None
    self._perf_run_end_mono: float | None = None
```

In `__init__`, immediately after `self._db_interaction_log` is initialized (line 250), call it:

```python
        self._db_interaction_log: _StreamingDBLog | list[dict] | None = []
        self._reset_perf_state()
```

- [ ] **Step 5: Stamp count + anchors in `_append_interaction`**

In `_append_interaction` (line 854), add the stamping block immediately before the final write (before `with open(temp_path, "a") as f:` at line 884), so only interactions that pass the request/response filters are counted:

```python
        # Performance accounting — count pairs and stamp the data-collection window.
        # Uses the pre-freeze real clock so the window is correct even under freeze_time.
        now_mono = _REAL_MONOTONIC()
        if self._perf_first_interaction_mono is None:
            self._perf_first_interaction_mono = now_mono
        self._perf_last_interaction_mono = now_mono
        self._perf_request_pairs += 1

        with open(temp_path, "a") as f:
            _write_interaction(f, filtered_request._to_dict(), filtered_response)
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `.venv/bin/pytest tests/test_recorder.py::TestAppendInteractionPerf -v`
Expected: PASS (both tests).

- [ ] **Step 7: Commit**

```bash
git add src/keboola/vcr/recorder.py tests/test_recorder.py
git commit -m "feat: count request pairs and stamp recording window in _append_interaction"
```

---

### Task 2: `_build_perf_metadata()` helper

Add the pure helper that converts the captured anchors into the metadata fields, including the no-interactions null path. Testable in isolation by setting the `_perf_*` attributes directly.

**Files:**
- Modify: `src/keboola/vcr/recorder.py` (new `_build_perf_metadata` method)
- Test: `tests/test_recorder.py`

**Interfaces:**
- Consumes: the `_perf_*` attributes set by `_reset_perf_state` / `_append_interaction` / `record()` (Task 1, Task 3).
- Produces (used by Task 3): `VCRRecorder._build_perf_metadata() -> dict` returning keys `request_pairs`, `component_run_started_at`, `component_run_ended_at`, `component_run_duration_seconds`, `recording_started_at`, `recording_ended_at`, `recording_duration_seconds`. Does **not** include `db_query_pairs` (added by the caller).

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_recorder.py`:

```python
from datetime import datetime, timezone


class TestBuildPerfMetadata:
    def _recorder(self, tmp_cassette_dir):
        return VCRRecorder(cassette_dir=tmp_cassette_dir)

    def test_window_is_subset_of_run_and_durations_match(self, tmp_cassette_dir):
        r = self._recorder(tmp_cassette_dir)
        r._perf_run_start_wall = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        r._perf_run_start_mono = 100.0
        r._perf_run_end_mono = 110.0          # 10.0s whole run
        r._perf_first_interaction_mono = 102.0  # +2.0s
        r._perf_last_interaction_mono = 107.5   # +7.5s
        r._perf_request_pairs = 3

        meta = r._build_perf_metadata()

        assert meta["request_pairs"] == 3
        assert meta["component_run_started_at"] == "2026-01-01T12:00:00+00:00"
        assert meta["component_run_ended_at"] == "2026-01-01T12:00:10+00:00"
        assert meta["component_run_duration_seconds"] == 10.0
        assert meta["recording_started_at"] == "2026-01-01T12:00:02+00:00"
        assert meta["recording_ended_at"] == "2026-01-01T12:00:07.500000+00:00"
        assert meta["recording_duration_seconds"] == 5.5
        # window within run
        assert meta["recording_started_at"] >= meta["component_run_started_at"]
        assert meta["recording_ended_at"] <= meta["component_run_ended_at"]

    def test_no_interactions_yields_null_recording_fields(self, tmp_cassette_dir):
        r = self._recorder(tmp_cassette_dir)
        r._perf_run_start_wall = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        r._perf_run_start_mono = 100.0
        r._perf_run_end_mono = 104.25
        # no interactions -> anchors stay None, request_pairs stays 0

        meta = r._build_perf_metadata()

        assert meta["request_pairs"] == 0
        assert meta["component_run_duration_seconds"] == 4.25
        assert meta["recording_started_at"] is None
        assert meta["recording_ended_at"] is None
        assert meta["recording_duration_seconds"] is None
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/bin/pytest tests/test_recorder.py::TestBuildPerfMetadata -v`
Expected: FAIL — `AttributeError: 'VCRRecorder' object has no attribute '_build_perf_metadata'`.

- [ ] **Step 3: Implement `_build_perf_metadata`**

Add the method to `VCRRecorder` (next to `_reset_perf_state`):

```python
def _build_perf_metadata(self) -> dict:
    """Assemble performance fields for the cassette _metadata from captured anchors.

    Durations come from the real monotonic clock; wall-clock ISO anchors are derived
    from the single real start reading plus monotonic offsets, so they stay consistent
    and immune to clock adjustments during the run. Does not include db_query_pairs.
    """
    run_dur = self._perf_run_end_mono - self._perf_run_start_mono
    start_wall = self._perf_run_start_wall
    meta: dict = {
        "request_pairs": self._perf_request_pairs,
        "component_run_started_at": start_wall.isoformat(),
        "component_run_ended_at": (start_wall + timedelta(seconds=run_dur)).isoformat(),
        "component_run_duration_seconds": round(run_dur, 3),
    }
    if self._perf_first_interaction_mono is not None:
        first_off = self._perf_first_interaction_mono - self._perf_run_start_mono
        last_off = self._perf_last_interaction_mono - self._perf_run_start_mono
        meta["recording_started_at"] = (start_wall + timedelta(seconds=first_off)).isoformat()
        meta["recording_ended_at"] = (start_wall + timedelta(seconds=last_off)).isoformat()
        meta["recording_duration_seconds"] = round(
            self._perf_last_interaction_mono - self._perf_first_interaction_mono, 3
        )
    else:
        meta["recording_started_at"] = None
        meta["recording_ended_at"] = None
        meta["recording_duration_seconds"] = None
    return meta
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `.venv/bin/pytest tests/test_recorder.py::TestBuildPerfMetadata -v`
Expected: PASS (both tests).

- [ ] **Step 5: Commit**

```bash
git add src/keboola/vcr/recorder.py tests/test_recorder.py
git commit -m "feat: add _build_perf_metadata helper for cassette timing fields"
```

---

### Task 3: Wire timing anchors and perf fields into `record()`

Reset perf state at the start of `record()`, capture the run-start/-end anchors around the component invocation in `_run_in_vcr`, and merge the perf fields (plus `db_query_pairs` when a DB adapter is active) into the `_metadata` dict. Proven by an end-to-end `record()` smoke test.

**Files:**
- Modify: `src/keboola/vcr/recorder.py` (`record()` body, its inner `_run_in_vcr`, and the metadata assembly block)
- Test: `tests/test_recorder.py`

**Interfaces:**
- Consumes: `_reset_perf_state`, `_build_perf_metadata`, `_REAL_MONOTONIC` (Tasks 1–2); `self._db_interaction_log` (a `_StreamingDBLog` supporting `len()`); `self.db_adapters`.
- Produces: cassette `_metadata` containing the seven perf fields always, plus `db_query_pairs` when `self.db_adapters` is truthy.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_recorder.py` (`import json`, `import time` if not already imported):

```python
class TestRecordPerfMetadata:
    def test_no_http_run_writes_perf_fields(self, tmp_cassette_dir):
        r = VCRRecorder(cassette_dir=tmp_cassette_dir, capture_logs=False, freeze_time_at=None)

        def runner():
            time.sleep(0.02)  # ensure a measurable, non-negative duration

        r.record(runner)

        meta = VCRRecorder.load_metadata(r.cassette_path)
        assert meta["request_pairs"] == 0
        assert meta["component_run_duration_seconds"] >= 0.0
        assert meta["component_run_started_at"] is not None
        assert meta["component_run_ended_at"] is not None
        assert meta["recording_started_at"] is None
        assert meta["recording_ended_at"] is None
        assert meta["recording_duration_seconds"] is None
        # db_query_pairs only present when a DB adapter is configured
        assert "db_query_pairs" not in meta
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `.venv/bin/pytest tests/test_recorder.py::TestRecordPerfMetadata -v`
Expected: FAIL — `KeyError: 'request_pairs'` (metadata does not yet contain the perf fields).

- [ ] **Step 3: Reset perf state at the top of `record()`**

In `record()`, immediately after the opening log line (`logger.info(f"Recording HTTP interactions to {self.cassette_path}")`, line 442), add:

```python
        self._reset_perf_state()
```

- [ ] **Step 4: Capture run anchors in `_run_in_vcr`**

Replace the run block inside `_run_in_vcr` (lines 487-492) so the anchors bracket the component invocation. The start wall-clock is read here, outside `_run_with_freeze` (which is where the freeze is entered), so it is real; the `finally` guarantees the end anchor even if the component raises:

```python
                with _pool_reuse_patch():
                    self._perf_run_start_wall = datetime.now(timezone.utc)
                    self._perf_run_start_mono = _REAL_MONOTONIC()
                    try:
                        if stdout_capture is not None:
                            with contextlib.redirect_stdout(stdout_capture):
                                self._run_with_freeze(component_runner)
                        else:
                            self._run_with_freeze(component_runner)
                    finally:
                        self._perf_run_end_mono = _REAL_MONOTONIC()
```

- [ ] **Step 5: Merge perf fields into the metadata dict**

In the metadata assembly block (lines 521-529), merge in the perf fields and add `db_query_pairs` inside the existing DB block:

```python
        metadata = {
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "freeze_time": self.freeze_time_at,
            "keboola_vcr_version": self._get_version(),
        }
        metadata.update(self._build_perf_metadata())
        # Add DB adapter metadata
        if self.db_adapters:
            metadata["db_driver"] = self.db_adapters[0].driver_name
            metadata["keboola_db_vcr_version"] = self._get_version()
            metadata["db_query_pairs"] = len(self._db_interaction_log)
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `.venv/bin/pytest tests/test_recorder.py::TestRecordPerfMetadata -v`
Expected: PASS.

- [ ] **Step 7: Run the full recorder test module**

Run: `.venv/bin/pytest tests/test_recorder.py -v`
Expected: PASS (no regressions in existing metadata/append tests).

- [ ] **Step 8: Commit**

```bash
git add src/keboola/vcr/recorder.py tests/test_recorder.py
git commit -m "feat: write performance metrics into cassette _metadata on record"
```

---

### Task 4: DB query-pair count coverage

Confirm `db_query_pairs` reflects recorded DB interactions. Reuse the existing DB test scaffolding in `tests/test_db_recorder.py` to record a run with a fake DB adapter and assert the count.

**Files:**
- Test: `tests/test_db_recorder.py` (or `tests/test_recorder.py` if the fake-adapter fixtures live there)

**Interfaces:**
- Consumes: the existing fake/stub DB adapter used by current DB recorder tests, and `VCRRecorder.load_metadata`.

- [ ] **Step 1: Locate the existing DB adapter test scaffolding**

Run: `.venv/bin/grep -n "db_adapters\|driver_name\|def.*adapter\|record(" tests/test_db_recorder.py`
Read the file to find how a recorder is currently driven with a DB adapter and how DB interactions are produced (the same adapter/fixture is reused below rather than inventing a new one).

- [ ] **Step 2: Write the test**

Using the same DB-adapter setup the existing tests use, record a run that produces a known number `N` of DB interactions, then assert:

```python
def test_db_query_pairs_matches_recorded_db_interactions(...):
    # ... arrange the recorder with the existing fake DB adapter and a runner
    #     that triggers N DB interactions (mirror the existing DB recorder test) ...
    recorder.record(runner)

    meta = VCRRecorder.load_metadata(recorder.cassette_path)
    assert meta["db_query_pairs"] == N
```

Replace `N` and the arrange block with the concrete values/fixtures found in Step 1 (do not invent a new adapter — reuse the one already exercised by the DB recorder tests).

- [ ] **Step 3: Run the test to verify it passes**

Run: `.venv/bin/pytest tests/test_db_recorder.py -k db_query_pairs -v`
Expected: PASS.

- [ ] **Step 4: Run the full test suite**

Run: `.venv/bin/pytest -q`
Expected: PASS (whole suite green).

- [ ] **Step 5: Commit**

```bash
git add tests/test_db_recorder.py
git commit -m "test: assert db_query_pairs reflects recorded DB interactions"
```

---

## Self-Review

**Spec coverage:**
- `request_pairs` → Task 1 (count) + Task 3 (written to metadata).
- `component_run_*` (started/ended/duration) → Task 3 anchors + Task 2 assembly.
- `recording_*` (started/ended/duration, incl. null path) → Task 1 anchors + Task 2 assembly.
- `db_query_pairs` (conditional) → Task 3 (write) + Task 4 (coverage).
- Freeze-time gotcha → `_REAL_MONOTONIC` (Task 1) + regression test `test_anchors_advance_under_frozen_clock` (Task 1).
- Edge cases: no interactions → Task 2 null-path test + Task 3 smoke test; component raises → `finally` in Task 3 Step 4; `record()` twice → `_reset_perf_state` at top of `record()` (Task 3 Step 3); DB absent → `assert "db_query_pairs" not in meta` (Task 3 test).
- Non-goals (no extra files/logs, replay untouched, version unchanged) → honored: all edits are additive to the `record()` metadata dict.

**Placeholder scan:** Task 4's arrange block intentionally defers to the existing DB fixtures (Step 1 discovers them) rather than duplicating unknown scaffolding — its steps still specify the exact assertion and command. No `TBD`/`TODO`/"add error handling" placeholders elsewhere.

**Type consistency:** `_perf_*` attribute names and types are identical across Tasks 1–3; `_build_perf_metadata()` and `_reset_perf_state()` names match their definitions and call sites; `len(self._db_interaction_log)` relies on `_StreamingDBLog.__len__`, which exists.
