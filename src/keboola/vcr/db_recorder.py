"""DB VCR — record and replay database interactions for Keboola component tests.

Works alongside the HTTP VCR recorder. DB interactions are stored in the shared
``cassettes/requests.json`` file under a ``db_interactions`` key, next to the
existing HTTP ``interactions`` key.

Supported drivers (modular adapter system):
- ``oracledb`` — Oracle Database via thin driver

To add a new driver, subclass ``DBAdapter`` and implement ``patch_for_record``,
``patch_for_replay``, and ``unpatch``.  The recording/replay proxies
(``_RecordingConnection``, ``_ReplayCursor``, etc.) are DB-API 2.0 generic and
shared across all adapters.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from abc import ABC, abstractmethod
from contextlib import contextmanager
from datetime import date, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Default cassette file — same as HTTP VCR so both live in one file.
DEFAULT_CASSETTE_FILE = "requests.json"


# ── JSON serialization helpers ───────────────────────────────────


class _DBEncoder(json.JSONEncoder):
    """JSON encoder that handles DB-specific Python types."""

    def default(self, o: object) -> Any:
        if isinstance(o, datetime):
            return {"__type__": "datetime", "value": o.isoformat()}
        if isinstance(o, date):
            return {"__type__": "date", "value": o.isoformat()}
        if isinstance(o, Decimal):
            return {"__type__": "decimal", "value": str(o)}
        if isinstance(o, bytes):
            return {"__type__": "bytes", "value": o.hex()}
        # Handle DB-specific type objects (oracledb.DbType, psycopg2 type codes, etc.)
        type_name = type(o).__name__
        if "Type" in type_name or "DbType" in type_name:
            return str(o)
        return super().default(o)


def _db_decode_hook(obj: dict) -> Any:
    """JSON object_hook that restores typed values from cassette."""
    if "__type__" in obj:
        t = obj["__type__"]
        v = obj["value"]
        if t == "datetime":
            return datetime.fromisoformat(v)
        if t == "date":
            return date.fromisoformat(v)
        if t == "decimal":
            return Decimal(v)
        if t == "bytes":
            return bytes.fromhex(v)
    return obj


def _normalize_sql(sql: str) -> str:
    """Normalize SQL for cassette matching (collapse whitespace, uppercase)."""
    return re.sub(r"\s+", " ", sql.strip()).upper()


def _params_hash(params: Any) -> str:
    """Stable hash of query parameters for cassette lookup."""
    serialized = json.dumps(params, sort_keys=True, cls=_DBEncoder)
    return hashlib.md5(serialized.encode()).hexdigest()  # noqa: S324


def _slim_description(description: Any) -> list[list] | None:
    """Extract only (name, type_string) from cursor.description.

    DB-API 2.0 description is a sequence of 7-item tuples:
      (name, type_code, display_size, internal_size, precision, scale, null_ok)

    We store [name, str(type_code)] to keep cassettes small and driver-agnostic.
    The full tuple is reconstructed on replay with None placeholders.
    """
    if not description:
        return None
    return [[col[0], str(col[1])] for col in description]


def _expand_description(slim: list[list] | None) -> list[tuple] | None:
    """Reconstruct cursor.description tuples from slim [name, type_str] pairs."""
    if not slim:
        return None
    return [(col[0], col[1], None, None, None, None, None) for col in slim]


# ── Streaming DB interaction log ─────────────────────────────────


class _StreamingDBLog:
    """A list-like object that streams DB interactions to a JSONL temp file.

    Each ``append(entry)`` serializes the interaction to a single JSON line
    and writes it immediately, keeping memory constant regardless of result
    set size.  Used by ``_RecordingCursor.close()`` which calls ``self._log.append(entry)``.

    When *secrets* are provided, string values in rows that match any secret
    value are replaced with ``[REDACTED]`` before writing.
    """

    def __init__(self, temp_path: Path, secrets: dict | None = None) -> None:
        self._path = temp_path
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._count = 0
        # Flatten nested secret values into a set of strings to redact
        self._secret_values: set[str] = set()
        if secrets:
            self._collect_secret_values(secrets, self._secret_values)

    @staticmethod
    def _collect_secret_values(obj: Any, values: set[str]) -> None:
        """Recursively collect all string values from a nested dict/list."""
        if isinstance(obj, str) and len(obj) > 2:
            values.add(obj)
        elif isinstance(obj, dict):
            for v in obj.values():
                _StreamingDBLog._collect_secret_values(v, values)
        elif isinstance(obj, list):
            for v in obj:
                _StreamingDBLog._collect_secret_values(v, values)

    def _sanitize_rows(self, rows: list[list]) -> list[list]:
        """Replace secret values in row data with [REDACTED]."""
        if not self._secret_values:
            return rows
        sanitized = []
        for row in rows:
            sanitized.append([
                "[REDACTED]" if isinstance(v, str) and v in self._secret_values else v
                for v in row
            ])
        return sanitized

    def append(self, entry: dict) -> None:
        if self._secret_values and "rows" in entry:
            entry = {**entry, "rows": self._sanitize_rows(entry["rows"])}
        with open(self._path, "a") as f:
            f.write(json.dumps(entry, cls=_DBEncoder))
            f.write("\n")
        self._count += 1

    def __len__(self) -> int:
        return self._count


# ── DB Adapter interface ─────────────────────────────────────────


class DBAdapter(ABC):
    """Base class for database driver adapters.

    Each adapter knows how to monkey-patch a specific driver's ``connect()``
    function and restore the original.  The recording/replay proxy classes
    are shared — only the patching logic is driver-specific.
    """

    @property
    @abstractmethod
    def driver_name(self) -> str:
        """Human-readable driver name for cassette metadata."""

    @abstractmethod
    def patch_for_record(self, interaction_log: list[dict]) -> None:
        """Monkey-patch the driver so real connections are proxied and all
        interactions (execute + fetch) are appended to *interaction_log*."""

    @abstractmethod
    def patch_for_replay(self, interactions: list[dict]) -> None:
        """Monkey-patch the driver so ``connect()`` returns a mock that
        serves data from *interactions* without any network access."""

    @abstractmethod
    def unpatch(self) -> None:
        """Restore the original driver ``connect()``."""


# ── Oracle DB Adapter ────────────────────────────────────────────


class OracleDBAdapter(DBAdapter):
    """Adapter for the ``oracledb`` Python driver (thin mode)."""

    _original_connect: Any = None

    @property
    def driver_name(self) -> str:
        return "oracledb"

    def patch_for_record(self, interaction_log: list[dict]) -> None:
        import oracledb

        self._original_connect = oracledb.connect

        def recording_connect(**kwargs: Any) -> Any:
            real_conn = self._original_connect(**kwargs)
            return _RecordingConnection(real_conn, interaction_log)

        oracledb.connect = recording_connect

    def patch_for_replay(self, interactions: list[dict]) -> None:
        import oracledb

        self._original_connect = oracledb.connect
        replay_store = _ReplayStore(interactions)

        def replaying_connect(**kwargs: Any) -> Any:
            return _ReplayConnection(replay_store)

        oracledb.connect = replaying_connect

    def unpatch(self) -> None:
        if self._original_connect is not None:
            import oracledb

            oracledb.connect = self._original_connect
            self._original_connect = None


# ── Recording proxy objects ──────────────────────────────────────


class _RecordingConnection:
    """Wraps a real DB connection and logs all cursor interactions."""

    def __init__(self, real_conn: Any, interaction_log: list[dict]) -> None:
        self._conn = real_conn
        self._log = interaction_log

    def cursor(self) -> _RecordingCursor:
        return _RecordingCursor(self._conn.cursor(), self._log)

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> _RecordingConnection:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


class _RecordingCursor:
    """Wraps a real cursor and records execute + fetch calls."""

    def __init__(self, real_cursor: Any, interaction_log: list[dict]) -> None:
        self._cursor = real_cursor
        self._log = interaction_log
        self._current_entry: dict | None = None

    @property
    def description(self) -> Any:
        return self._cursor.description

    @property
    def arraysize(self) -> int:
        return self._cursor.arraysize

    @arraysize.setter
    def arraysize(self, value: int) -> None:
        self._cursor.arraysize = value

    def execute(self, sql: str, parameters: Any = None, **kwargs: Any) -> Any:
        try:
            result = self._cursor.execute(sql, parameters=parameters, **kwargs)
        except Exception as e:
            # Record the error so replay can reproduce it
            self._current_entry = {
                "sql_normalized": _normalize_sql(sql),
                "params_hash": _params_hash(parameters),
                "description": None,
                "rows": [],
                "error": str(e),
            }
            self._log.append(self._current_entry)
            self._current_entry = None
            raise
        self._current_entry = {
            "sql_normalized": _normalize_sql(sql),
            "params_hash": _params_hash(parameters),
            "description": _slim_description(self._cursor.description),
            "rows": [],
        }
        return result

    def fetchone(self) -> Any:
        row = self._cursor.fetchone()
        if row is not None and self._current_entry is not None:
            self._current_entry["rows"].append(list(row))
        return row

    def fetchmany(self, size: int | None = None) -> list:
        rows = self._cursor.fetchmany(size)
        if rows and self._current_entry is not None:
            self._current_entry["rows"].extend([list(r) for r in rows])
        return rows

    def fetchall(self) -> list:
        rows = self._cursor.fetchall()
        if rows and self._current_entry is not None:
            self._current_entry["rows"].extend([list(r) for r in rows])
        return rows

    def close(self) -> None:
        if self._current_entry is not None:
            self._log.append(self._current_entry)
            self._current_entry = None
        self._cursor.close()

    def __enter__(self) -> _RecordingCursor:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


# ── Replay mock objects ──────────────────────────────────────────


class _ReplayStore:
    """Lookup store for replaying DB interactions from cassette."""

    def __init__(self, interactions: list[dict]) -> None:
        self._entries = interactions
        self._used: list[bool] = [False] * len(interactions)

    def lookup(self, sql: str, params: Any) -> dict:
        """Find a matching interaction by normalized SQL + params hash."""
        norm = _normalize_sql(sql)
        phash = _params_hash(params)
        for i, entry in enumerate(self._entries):
            if entry["sql_normalized"] == norm and entry["params_hash"] == phash and not self._used[i]:
                self._used[i] = True
                return entry
        # Fallback: match by SQL only (params may differ slightly due to serialization)
        for i, entry in enumerate(self._entries):
            if entry["sql_normalized"] == norm and not self._used[i]:
                self._used[i] = True
                logger.warning("DB VCR: params hash mismatch for %s, using SQL-only match", norm[:80])
                return entry
        raise RuntimeError(
            f"DB VCR replay: no matching cassette entry for query: {norm[:120]}\n"
            f"  params_hash: {phash}\n"
            f"  Available entries: {[e['sql_normalized'][:60] for e in self._entries]}"
        )


class _ReplayConnection:
    """Mock connection that returns replay cursors."""

    def __init__(self, store: _ReplayStore) -> None:
        self._store = store

    def cursor(self) -> _ReplayCursor:
        return _ReplayCursor(self._store)

    def close(self) -> None:
        pass

    def __enter__(self) -> _ReplayConnection:
        return self

    def __exit__(self, *args: Any) -> None:
        pass


class _ReplayCursor:
    """Mock cursor that serves data from a cassette entry."""

    def __init__(self, store: _ReplayStore) -> None:
        self._store = store
        self._description: Any = None
        self._rows: list[list] = []
        self._offset: int = 0
        self.arraysize: int = 100

    @property
    def description(self) -> list[tuple] | None:
        return self._description

    def execute(self, sql: str, parameters: Any = None, **kwargs: Any) -> None:
        entry = self._store.lookup(sql, parameters)
        # Replay recorded errors — raise the original driver exception type
        # so the component's error handling catches it correctly.
        if "error" in entry:
            try:
                import oracledb

                raise oracledb.DatabaseError(entry["error"])
            except ImportError:
                raise Exception(entry["error"])
        self._description = _expand_description(entry.get("description"))
        self._rows = entry.get("rows", [])
        self._offset = 0

    def fetchone(self) -> tuple | None:
        if self._offset >= len(self._rows):
            return None
        row = tuple(self._rows[self._offset])
        self._offset += 1
        return row

    def fetchmany(self, size: int | None = None) -> list[tuple]:
        n = size or self.arraysize
        batch = self._rows[self._offset : self._offset + n]
        self._offset += len(batch)
        return [tuple(r) for r in batch]

    def fetchall(self) -> list[tuple]:
        remaining = self._rows[self._offset :]
        self._offset = len(self._rows)
        return [tuple(r) for r in remaining]

    def close(self) -> None:
        pass

    def __enter__(self) -> _ReplayCursor:
        return self

    def __exit__(self, *args: Any) -> None:
        pass


# ── DBVCRRecorder ────────────────────────────────────────────────


class DBVCRRecorder:
    """Record and replay database interactions.

    Designed to work alongside ``VCRRecorder`` for HTTP interactions.
    DB interactions are stored in the shared ``requests.json`` cassette
    under the ``db_interactions`` key.

    When recording, the DB interactions are merged into the existing
    cassette file (preserving HTTP interactions). When replaying,
    only the ``db_interactions`` key is read.
    """

    def __init__(
        self,
        cassette_dir: Path,
        adapter: DBAdapter,
        cassette_file: str = DEFAULT_CASSETTE_FILE,
    ) -> None:
        self.cassette_dir = cassette_dir
        self.cassette_path = cassette_dir / cassette_file
        self.adapter = adapter

    @classmethod
    def from_test_dir(cls, test_data_dir: Path, adapter: DBAdapter) -> DBVCRRecorder:
        """Create recorder from a datadirtest source/data directory."""
        cassette_dir = test_data_dir / "cassettes"
        return cls(cassette_dir=cassette_dir, adapter=adapter)

    def has_cassette(self) -> bool:
        """Check if cassette file exists and contains db_interactions."""
        if not self.cassette_path.exists():
            return False
        try:
            with open(self.cassette_path) as f:
                data = json.load(f)
            return bool(data.get("db_interactions"))
        except (json.JSONDecodeError, OSError):
            return False

    @contextmanager
    def recording_context(self):
        """Context manager that patches the DB driver for recording.

        Yields the interaction log list which will be populated during recording.
        """
        interaction_log: list[dict] = []
        self.adapter.patch_for_record(interaction_log)
        try:
            yield interaction_log
        finally:
            self.adapter.unpatch()

    @contextmanager
    def replay_context(self):
        """Context manager that patches the DB driver for replay."""
        interactions = self._load_db_interactions()
        self.adapter.patch_for_replay(interactions)
        try:
            yield
        finally:
            self.adapter.unpatch()

    def record(self, component_runner: callable) -> None:
        """Record DB interactions while running the component.

        The interactions are held in memory until ``flush()`` is called.
        This allows the HTTP VCR recorder to write ``requests.json`` first,
        after which ``flush()`` merges ``db_interactions`` into the same file
        without being overwritten.
        """
        self.cassette_dir.mkdir(parents=True, exist_ok=True)
        logger.info("Recording DB interactions to %s", self.cassette_path)

        with self.recording_context() as interaction_log:
            component_runner()

        self._pending_interactions = interaction_log
        logger.info("Captured %d DB interactions (pending flush)", len(interaction_log))

    def flush(self) -> None:
        """Merge pending DB interactions into the cassette file.

        Call this AFTER the HTTP VCR recorder has written ``requests.json``
        so that ``db_interactions`` are added without being overwritten.
        """
        if not hasattr(self, "_pending_interactions") or not self._pending_interactions:
            return
        self._merge_into_cassette(self._pending_interactions)
        logger.info("Flushed %d DB interactions to %s", len(self._pending_interactions), self.cassette_path)
        self._pending_interactions = []

    def replay(self, component_runner: callable) -> None:
        """Replay DB interactions from cassette."""
        if not self.has_cassette():
            logger.info("No DB cassette found — running without DB replay")
            component_runner()
            return

        logger.info("Replaying DB interactions from %s", self.cassette_path)
        with self.replay_context():
            component_runner()
        logger.info("DB replay completed successfully")

    def _merge_into_cassette(self, interactions: list[dict]) -> None:
        """Merge DB interactions into the shared cassette file.

        If the cassette already exists (e.g. HTTP interactions recorded by VCRRecorder),
        the db_interactions key is added/updated. If not, a new cassette is created.
        """
        cassette: dict = {}
        if self.cassette_path.exists():
            try:
                with open(self.cassette_path) as f:
                    cassette = json.load(f)
            except (json.JSONDecodeError, OSError):
                cassette = {}

        # Ensure metadata exists
        if "_metadata" not in cassette:
            cassette["_metadata"] = {}
        cassette["_metadata"]["db_driver"] = self.adapter.driver_name
        cassette["_metadata"]["keboola_db_vcr_version"] = "0.1.0"
        if "recorded_at" not in cassette["_metadata"]:
            cassette["_metadata"]["recorded_at"] = datetime.now().isoformat()

        # Ensure vcrpy-compatible structure exists
        if "interactions" not in cassette:
            cassette["interactions"] = []
        if "version" not in cassette:
            cassette["version"] = 1

        # Add/replace DB interactions
        cassette["db_interactions"] = interactions

        with open(self.cassette_path, "w") as f:
            json.dump(cassette, f, indent=2, cls=_DBEncoder)

    def _load_db_interactions(self) -> list[dict]:
        """Load DB interactions from the shared cassette file."""
        with open(self.cassette_path) as f:
            data = json.load(f, object_hook=_db_decode_hook)
        return data.get("db_interactions", [])
