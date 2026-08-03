# Cassette performance metadata

**Date:** 2026-08-02
**Status:** Approved (design)
**Package:** `keboola.vcr` (`src/keboola/vcr/recorder.py`)

## Problem

When a component is recorded, the cassette captures the HTTP/DB interactions but
nothing about the *performance shape* of the run. There is no record of how many
request/response pairs were exchanged, how long data collection took, or how long
the whole component run took (including processing and saving). This information is
useful for tracking a component's performance profile over time straight from its
recorded cassette.

## Goal

Extend the cassette's existing `_metadata` block (written only during `record()`)
with additive performance fields:

1. Number of HTTP request/response pairs recorded.
2. Number of DB query pairs recorded (when a DB adapter is active).
3. The **data-collection window** — first to last recorded interaction.
4. The **whole component-run duration** — the full `component_runner()` wall-clock,
   which includes fetching, processing, and saving.

Purely additive: existing fields, the cassette `version` (`1`), replay behavior, and
`load_metadata()` consumers are all unchanged.

## Key architectural facts

- The component under test runs via a single `component_runner()` callable invoked
  inside the VCR context in `record()` → `_run_in_vcr()` → `_run_with_freeze()`
  ([recorder.py:490](../../../src/keboola/vcr/recorder.py)). That callable **is** the
  whole component run — fetch, process, and save all happen inside it, and HTTP
  interactions are captured throughout.
- Because HTTP is captured across the entire run, the **recording window** (first→last
  interaction) is a strict subset of the **component run**. The difference
  (`component_run − recording`) approximates setup before the first API call plus
  processing/saving after the last one.
- Interactions are streamed one at a time through `_append_interaction()`
  ([recorder.py:854](../../../src/keboola/vcr/recorder.py)); the count and window
  anchors are captured there. Only interactions that pass the request/response filters
  (i.e. those actually written to the cassette) are counted.
- DB interactions are streamed through `_StreamingDBLog`, which already tracks a count
  via `__len__` ([db_recorder.py:155](../../../src/keboola/vcr/db_recorder.py)).
- `_metadata` is a flat dict written with `sort_keys=True`
  ([recorder.py:521](../../../src/keboola/vcr/recorder.py),
  [recorder.py:914](../../../src/keboola/vcr/recorder.py)), so new fields can be added
  in any order.

### The freeze-time gotcha (central design constraint)

The component runs inside `freeze_time()`
([recorder.py:670](../../../src/keboola/vcr/recorder.py)). freezegun rebinds
`time.monotonic`, `time.perf_counter`, `time.time`, and `datetime.now` for the duration
of the freeze, so **any duration measured naively inside the run reads as zero** and any
wall-clock read inside the run returns the frozen instant.

Fix: wrap a reference to the real clock in a **closure**, captured before any freeze is
applied:

```python
import time
from typing import Callable

def _make_real_monotonic() -> Callable[[], float]:
    real = time.monotonic

    def _real_monotonic() -> float:
        return real()

    return _real_monotonic

_REAL_MONOTONIC: Callable[[], float] = _make_real_monotonic()
```

A bare `_REAL_MONOTONIC = time.monotonic` is **not** enough: freezegun's
`freeze_time().start()` walks every already-imported module's attributes and rebinds any
value that `is time.monotonic` (a plain identity check) to its fake — specifically to close
the "stash a reference before freezing" loophole. Since `keboola.vcr.recorder` is already
imported by the time a test enters `freeze_time()`, a bare module-level alias would be
swapped right along with `time.monotonic` itself.

The closure sidesteps this: the module-level name `_REAL_MONOTONIC` is bound to a distinct
function object (the closure), never to `time.monotonic` itself, so freezegun's identity
scan never matches it. The genuine clock lives in the closure's `real` cell variable, which
is not a module attribute and so is invisible to the scan — `_REAL_MONOTONIC()` keeps
returning real time even inside the freeze. All durations use `_REAL_MONOTONIC`. Wall-clock
ISO anchors come from **one** real `datetime.now(timezone.utc)` read taken outside the freeze
(just before `component_runner()` is invoked), with per-interaction offsets derived from
monotonic deltas.

Rejected alternatives: reading wall-clock at each boundary (zeroed/frozen inside the run, so
it cannot measure the recording window); a bare module-level alias (swapped by freezegun's
attribute scan, as above).

## New `_metadata` fields

Flat, alongside the existing `recorded_at` / `freeze_time` / `keboola_vcr_version`
(and, when a DB adapter is active, `db_driver` / `keboola_db_vcr_version`):

| Field | Type | Meaning |
|---|---|---|
| `request_pairs` | int | HTTP interactions written to the cassette (post-filter) |
| `component_run_started_at` | ISO-8601 UTC string | Real wall-clock when `component_runner()` began |
| `component_run_ended_at` | ISO-8601 UTC string | Derived: `started_at + measured monotonic duration` |
| `component_run_duration_seconds` | float, 3dp | Full `component_runner()` wall-clock (fetch + process + save) |
| `recording_started_at` | ISO-8601 UTC string \| null | First recorded interaction; null if none |
| `recording_ended_at` | ISO-8601 UTC string \| null | Last recorded interaction; null if none |
| `recording_duration_seconds` | float, 3dp \| null | Span first→last recorded interaction; null if none |
| `db_query_pairs` | int | DB interactions recorded — **only present when a DB adapter is active** (mirrors how `db_driver` is added conditionally) |

Notes on semantics (to be documented in the field-producing code):

- The recording window is stamped at the point each interaction is appended, which is
  approximately when its response was received. So the window spans first→last recorded
  **response**, and is always a subset of the component run.
- `component_run_ended_at` is derived from `component_run_started_at` plus the monotonic
  duration rather than read separately — immune to wall-clock/NTP adjustments during the
  run and consistent with the duration field.
- Durations are rounded to 3 decimal places (millisecond resolution).

## Implementation

All changes are in `recorder.py` and affect the `record()` path only. Replay is
untouched (metadata is written only when recording).

### Imports

- Add `timedelta` to `from datetime import datetime, timezone` → `datetime, timedelta, timezone`.
- Add `import time`.
- Add module-level `_REAL_MONOTONIC`, a closure over the real `time.monotonic` (see the
  freeze-time gotcha above — a bare alias would be swapped by freezegun too).

### `record()` — state and anchors

1. At the top of `record()`, reset per-run performance state (so an instance calling
   `record()` twice starts clean):
   - `self._perf_request_pairs = 0`
   - `self._perf_first_interaction_mono = None`
   - `self._perf_last_interaction_mono = None`
   - `self._perf_run_start_wall = None`
   - `self._perf_run_start_mono = None`
   - `self._perf_run_end_mono = None`
2. Inside `_run_in_vcr()`, immediately before invoking the component (both the
   stdout-redirect and non-redirect branches), set the run-start anchors — outside the
   freeze, so the wall-clock read is real:
   - `self._perf_run_start_wall = datetime.now(timezone.utc)`
   - `self._perf_run_start_mono = _REAL_MONOTONIC()`
   and in a `finally` around the run, set `self._perf_run_end_mono = _REAL_MONOTONIC()`.
   (Wrap the two existing branches in a single `try/finally` so the end anchor is always
   captured, even if the component raises.)
3. When assembling `metadata` (before `_write_cassette`), merge in the perf fields via
   the new helper and, when `self.db_adapters`, add
   `metadata["db_query_pairs"] = len(self._db_interaction_log)`.

### `_append_interaction()` — count + window anchors

At the point an interaction is confirmed for writing (after the request/response filters
pass, right around the `open(temp_path, "a")` write), record the anchors using the real
clock:

```python
now_mono = _REAL_MONOTONIC()
if self._perf_first_interaction_mono is None:
    self._perf_first_interaction_mono = now_mono
self._perf_last_interaction_mono = now_mono
self._perf_request_pairs += 1
```

Filtered-out interactions (early `return` paths) are not counted and do not move the
window — consistent with `request_pairs` meaning "what is in the cassette".

### `_build_perf_metadata()` — new helper (pure arithmetic)

A small method that turns the captured anchors into the metadata fields, isolating the
arithmetic and the null (no-interactions) case so it is directly unit-testable:

```python
def _build_perf_metadata(self) -> dict:
    run_dur = self._perf_run_end_mono - self._perf_run_start_mono
    start_wall = self._perf_run_start_wall
    meta = {
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

`db_query_pairs` is added by the caller (it needs `self.db_adapters` / the DB log), not by
this helper, keeping the helper independent of DB state.

## Edge cases

- **No interactions** (sync action without HTTP, DB-only run): `request_pairs == 0` and the
  three `recording_*` fields are `null`; component-run timing is still emitted.
- **Freeze active:** durations remain real via `_REAL_MONOTONIC`; ISO anchors are real via
  the single outside-freeze wall-clock read.
- **Component raises:** the `finally` still captures `run_end_mono`, so timing is written
  even for a failed run (which is the existing behavior for other metadata / logs).
- **`record()` called twice on one instance:** state is reset at the top of `record()`.
- **DB-only / mixed:** `db_query_pairs` appears only when `self.db_adapters` is truthy.

## Testing

No end-to-end `record()` tests exist today (tests are unit-level over
`_append_interaction`, `load_metadata`, and sanitizers), so this adds focused coverage in
`tests/test_recorder.py`:

1. **Counting + anchors** — call `_append_interaction()` twice on a recorder (using the
   existing `mock_request` / `mock_response` fixtures and a temp file); assert
   `request_pairs == 2` and that first/last monotonic anchors are set with
   `last >= first`.
2. **`_build_perf_metadata()` arithmetic** — feed synthetic anchors; assert the recording
   window lies within the component run (`recording_started_at >= component_run_started_at`,
   `recording_ended_at <= component_run_ended_at`), durations match, and rounding is applied.
3. **`_build_perf_metadata()` null path** — no interactions → all three `recording_*`
   fields are `None`, `request_pairs == 0`, run timing present.
4. **Freeze-gotcha regression** — call `_append_interaction()` twice inside
   `with freeze_time("2020-01-01"):` with a small real `time.sleep()` between them; assert
   the two captured monotonic anchors **differ** (proves the pre-freeze `_REAL_MONOTONIC`
   reference is used, not the frozen clock). This is the load-bearing test.
5. **Integration smoke** — drive `record()` with a trivial no-HTTP `component_runner`
   (e.g. one that sleeps briefly); assert the written cassette's `_metadata` has
   `request_pairs == 0`, `component_run_duration_seconds >= 0`, and `recording_*` null.
6. **DB count** — with a DB adapter active, assert `db_query_pairs` is present and matches
   the number of recorded DB interactions; assert it is **absent** when no DB adapter is
   configured.

## Non-goals

- No separate metrics file and no log output — metrics live in `_metadata` only.
- No change to replay, cassette `version`, existing metadata fields, or the interaction
  schema.
- No per-interaction timing stored in the cassette body (only the aggregate window).
- No cross-cassette aggregation — each cassette carries its own metrics.
