"""Unit tests for keboola.vcr.db_recorder."""

from __future__ import annotations

import json
from datetime import date, datetime
from decimal import Decimal
from unittest.mock import MagicMock

import pytest

from keboola.vcr.db_recorder import (
    _db_decode_hook,
    _DBEncoder,
    _expand_description,
    _normalize_sql,
    _params_hash,
    _RecordingCursor,
    _ReplayCursor,
    _ReplayStore,
    _slim_description,
    _StreamingDBLog,
)

# ---------------------------------------------------------------------------
# _DBEncoder + _db_decode_hook — round-trip serialization
# ---------------------------------------------------------------------------


def _roundtrip(value):
    """Serialize with _DBEncoder, deserialize with _db_decode_hook."""
    serialized = json.dumps(value, cls=_DBEncoder)
    return json.loads(serialized, object_hook=_db_decode_hook)


class TestDBEncoder:
    def test_datetime_roundtrip(self):
        dt = datetime(2024, 3, 15, 10, 30, 0)
        assert _roundtrip(dt) == dt

    def test_date_roundtrip(self):
        d = date(2024, 3, 15)
        assert _roundtrip(d) == d

    def test_decimal_roundtrip(self):
        dec = Decimal("123.456")
        assert _roundtrip(dec) == dec

    def test_bytes_roundtrip(self):
        b = b"\x00\xff\xab"
        assert _roundtrip(b) == b

    def test_plain_string_unchanged(self):
        assert _roundtrip("hello") == "hello"

    def test_plain_int_unchanged(self):
        assert _roundtrip(42) == 42

    def test_none_unchanged(self):
        assert _roundtrip(None) is None

    def test_list_with_mixed_types(self):
        value = [datetime(2024, 1, 1), Decimal("1.5"), "text", 99]
        result = _roundtrip(value)
        assert result[0] == datetime(2024, 1, 1)
        assert result[1] == Decimal("1.5")
        assert result[2] == "text"
        assert result[3] == 99

    def test_unknown_type_raises(self):
        class _Unknown:
            pass

        with pytest.raises(TypeError):
            json.dumps(_Unknown(), cls=_DBEncoder)

    def test_db_type_object_serialized_as_string(self):
        """Objects whose class name contains 'Type' are serialized as str."""

        class DbType:
            def __str__(self):
                return "DB_TYPE_VARCHAR"

        result = json.loads(json.dumps(DbType(), cls=_DBEncoder))
        assert result == "DB_TYPE_VARCHAR"


class TestDBDecodeHook:
    def test_unknown_type_tag_passes_through(self):
        obj = {"__type__": "unknown", "value": "x"}
        assert _db_decode_hook(obj) == obj

    def test_no_type_tag_passes_through(self):
        obj = {"key": "value"}
        assert _db_decode_hook(obj) == obj


# ---------------------------------------------------------------------------
# _normalize_sql
# ---------------------------------------------------------------------------


class TestNormalizeSQL:
    def test_collapses_whitespace(self):
        assert _normalize_sql("SELECT  *  FROM  t") == "SELECT * FROM T"

    def test_uppercases(self):
        assert _normalize_sql("select * from t") == "SELECT * FROM T"

    def test_strips_leading_trailing(self):
        assert _normalize_sql("  SELECT 1  ") == "SELECT 1"

    def test_newlines_collapsed(self):
        sql = "SELECT\n  id,\n  name\nFROM\n  users"
        assert _normalize_sql(sql) == "SELECT ID, NAME FROM USERS"

    def test_tabs_collapsed(self):
        assert _normalize_sql("SELECT\t*\tFROM\tt") == "SELECT * FROM T"

    def test_already_normalized(self):
        assert _normalize_sql("SELECT * FROM T") == "SELECT * FROM T"


# ---------------------------------------------------------------------------
# _params_hash
# ---------------------------------------------------------------------------


class TestParamsHash:
    def test_deterministic(self):
        params = {"id": 1, "name": "alice"}
        assert _params_hash(params) == _params_hash(params)

    def test_none_is_hashable(self):
        result = _params_hash(None)
        assert isinstance(result, str)
        assert len(result) == 64  # sha256 hex digest

    def test_different_params_give_different_hashes(self):
        assert _params_hash({"id": 1}) != _params_hash({"id": 2})

    def test_key_order_independent(self):
        a = _params_hash({"a": 1, "b": 2})
        b = _params_hash({"b": 2, "a": 1})
        assert a == b

    def test_list_params(self):
        result = _params_hash([1, 2, 3])
        assert isinstance(result, str)


# ---------------------------------------------------------------------------
# _slim_description / _expand_description
# ---------------------------------------------------------------------------


class TestDescriptionHelpers:
    def test_slim_extracts_name_and_type(self):
        description = [("id", "DB_TYPE_NUMBER", None, None, 10, 0, False)]
        result = _slim_description(description)
        assert result == [["id", "DB_TYPE_NUMBER"]]

    def test_slim_multiple_columns(self):
        description = [
            ("id", "NUMBER", None, None, None, None, False),
            ("name", "VARCHAR2", None, None, None, None, True),
        ]
        result = _slim_description(description)
        assert result == [["id", "NUMBER"], ["name", "VARCHAR2"]]

    def test_slim_none_returns_none(self):
        assert _slim_description(None) is None

    def test_slim_empty_returns_none(self):
        assert _slim_description([]) is None

    def test_expand_reconstructs_7_tuple(self):
        slim = [["id", "NUMBER"], ["name", "VARCHAR2"]]
        result = _expand_description(slim)
        assert result is not None
        assert len(result) == 2
        assert result[0] == ("id", "NUMBER", None, None, None, None, None)
        assert result[1] == ("name", "VARCHAR2", None, None, None, None, None)

    def test_expand_none_returns_none(self):
        assert _expand_description(None) is None

    def test_expand_empty_returns_none(self):
        assert _expand_description([]) is None

    def test_slim_expand_roundtrip(self):
        description = [("col", "DB_TYPE_VARCHAR", 50, 50, None, None, True)]
        slim = _slim_description(description)
        expanded = _expand_description(slim)
        assert expanded is not None
        assert expanded[0][0] == "col"
        assert expanded[0][1] == "DB_TYPE_VARCHAR"


# ---------------------------------------------------------------------------
# _StreamingDBLog._sanitize_rows
# ---------------------------------------------------------------------------


class TestStreamingDBLogSanitize:
    def _make_log(self, secrets, tmp_path):
        return _StreamingDBLog(tmp_path / "db.jsonl", secrets=secrets)

    def test_no_secrets_returns_rows_unchanged(self, tmp_path):
        log = _StreamingDBLog(tmp_path / "db.jsonl", secrets=None)
        rows = [["alice", "pass123"]]
        assert log._sanitize_rows(rows) == rows

    def test_exact_match_redacted(self, tmp_path):
        log = self._make_log({"#password": "s3cret"}, tmp_path)
        rows = [["alice", "s3cret"]]
        result = log._sanitize_rows(rows)
        assert result == [["alice", "[REDACTED]"]]

    def test_substring_match_redacted(self, tmp_path):
        log = self._make_log({"#token": "abc123"}, tmp_path)
        rows = [["prefix_abc123_suffix"]]
        result = log._sanitize_rows(rows)
        assert result[0][0] == "prefix_[REDACTED]_suffix"

    def test_non_string_values_untouched(self, tmp_path):
        log = self._make_log({"#password": "s3cret"}, tmp_path)
        rows = [[42, None, 3.14, date(2024, 1, 1)]]
        result = log._sanitize_rows(rows)
        assert result == [[42, None, 3.14, date(2024, 1, 1)]]

    def test_longer_secret_replaced_first(self, tmp_path):
        """Longer secrets must be replaced before shorter ones to avoid partial redaction."""
        log = self._make_log({"#a": "pass", "#b": "password"}, tmp_path)
        rows = [["my_password_is_pass"]]
        result = log._sanitize_rows(rows)
        # "password" should be replaced first (longer), then "pass" in remaining text
        assert "[REDACTED]" in result[0][0]
        assert "password" not in result[0][0]

    def test_multiple_secrets_in_one_cell(self, tmp_path):
        log = self._make_log({"#a": "foo", "#b": "bar"}, tmp_path)
        rows = [["foo and bar"]]
        result = log._sanitize_rows(rows)
        assert "foo" not in result[0][0]
        assert "bar" not in result[0][0]

    def test_append_writes_to_file_and_sanitizes(self, tmp_path):
        log = self._make_log({"#password": "s3cret"}, tmp_path)
        entry = {
            "sql_normalized": "SELECT * FROM T",
            "params_hash": "abc",
            "description": None,
            "rows": [["alice", "s3cret"]],
        }
        log.append(entry)
        lines = (tmp_path / "db.jsonl").read_text().strip().splitlines()
        assert len(lines) == 1
        written = json.loads(lines[0])
        assert written["rows"][0][1] == "[REDACTED]"

    def test_append_increments_count(self, tmp_path):
        log = _StreamingDBLog(tmp_path / "db.jsonl")
        log.append({"sql_normalized": "X", "params_hash": "y", "rows": []})
        log.append({"sql_normalized": "X", "params_hash": "z", "rows": []})
        assert len(log) == 2


# ---------------------------------------------------------------------------
# _ReplayStore.lookup
# ---------------------------------------------------------------------------


def _make_store(*sqls, error_class=RuntimeError):
    """Build a _ReplayStore with one entry per SQL string."""
    interactions = [
        {
            "sql_normalized": _normalize_sql(sql),
            "params_hash": _params_hash(None),
            "description": None,
            "rows": [["row1"], ["row2"]],
        }
        for sql in sqls
    ]
    return _ReplayStore(interactions, error_class=error_class)


class TestReplayStore:
    def test_exact_match_returned(self):
        store = _make_store("SELECT 1 FROM DUAL")
        entry = store.lookup("SELECT 1 FROM DUAL", None)
        assert entry["rows"] == [["row1"], ["row2"]]

    def test_sql_normalized_on_lookup(self):
        store = _make_store("SELECT 1 FROM DUAL")
        entry = store.lookup("select  1  from  dual", None)
        assert entry is not None

    def test_entry_marked_used_after_lookup(self):
        store = _make_store("SELECT 1 FROM DUAL")
        store.lookup("SELECT 1 FROM DUAL", None)
        with pytest.raises(RuntimeError):
            store.lookup("SELECT 1 FROM DUAL", None)

    def test_two_identical_sqls_served_in_order(self):
        interactions = [
            {
                "sql_normalized": "SELECT 1 FROM DUAL",
                "params_hash": _params_hash(None),
                "rows": [["first"]],
            },
            {
                "sql_normalized": "SELECT 1 FROM DUAL",
                "params_hash": _params_hash(None),
                "rows": [["second"]],
            },
        ]
        store = _ReplayStore(interactions)
        assert store.lookup("SELECT 1 FROM DUAL", None)["rows"] == [["first"]]
        assert store.lookup("SELECT 1 FROM DUAL", None)["rows"] == [["second"]]

    def test_no_match_raises_runtime_error(self):
        store = _make_store("SELECT 1 FROM DUAL")
        with pytest.raises(RuntimeError, match="no matching cassette entry"):
            store.lookup("SELECT 2 FROM DUAL", None)

    def test_sql_only_fallback_on_param_mismatch(self):
        interactions = [
            {
                "sql_normalized": "SELECT * FROM T WHERE ID = :1",
                "params_hash": _params_hash({"id": 99}),
                "rows": [["x"]],
            }
        ]
        store = _ReplayStore(interactions)
        # Different param — should fall back to SQL-only match
        entry = store.lookup("SELECT * FROM T WHERE ID = :1", {"id": 1})
        assert entry["rows"] == [["x"]]

    def test_error_class_stored(self):
        store = _ReplayStore([], error_class=ValueError)
        assert store.error_class is ValueError


# ---------------------------------------------------------------------------
# _ReplayCursor — fetch methods and error replay
# ---------------------------------------------------------------------------


def _store_with_rows(sql, rows, description=None):
    return _ReplayStore(
        [
            {
                "sql_normalized": _normalize_sql(sql),
                "params_hash": _params_hash(None),
                "description": description,
                "rows": rows,
            }
        ]
    )


class TestReplayCursor:
    def test_fetchall_returns_all_rows(self):
        store = _store_with_rows("SELECT * FROM T", [[1, "a"], [2, "b"]])
        cursor = _ReplayCursor(store)
        cursor.execute("SELECT * FROM T")
        assert cursor.fetchall() == [(1, "a"), (2, "b")]

    def test_fetchone_iterates(self):
        store = _store_with_rows("SELECT * FROM T", [[1], [2], [3]])
        cursor = _ReplayCursor(store)
        cursor.execute("SELECT * FROM T")
        assert cursor.fetchone() == (1,)
        assert cursor.fetchone() == (2,)
        assert cursor.fetchone() == (3,)
        assert cursor.fetchone() is None

    def test_fetchmany_returns_batch(self):
        store = _store_with_rows("SELECT * FROM T", [[i] for i in range(10)])
        cursor = _ReplayCursor(store)
        cursor.execute("SELECT * FROM T")
        batch = cursor.fetchmany(3)
        assert len(batch) == 3
        assert batch[0] == (0,)

    def test_fetchmany_uses_arraysize_default(self):
        store = _store_with_rows("SELECT * FROM T", [[i] for i in range(200)])
        cursor = _ReplayCursor(store)
        cursor.arraysize = 50
        cursor.execute("SELECT * FROM T")
        batch = cursor.fetchmany()
        assert len(batch) == 50

    def test_description_set_after_execute(self):
        desc = [["id", "NUMBER"], ["name", "VARCHAR2"]]
        store = _store_with_rows("SELECT * FROM T", [], description=desc)
        cursor = _ReplayCursor(store)
        cursor.execute("SELECT * FROM T")
        assert cursor.description is not None
        assert cursor.description[0][0] == "id"

    def test_error_entry_raises_error_class(self):
        interactions = [
            {
                "sql_normalized": _normalize_sql("SELECT * FROM MISSING"),
                "params_hash": _params_hash(None),
                "error": "ORA-00942: table or view does not exist",
            }
        ]
        store = _ReplayStore(interactions, error_class=ValueError)
        cursor = _ReplayCursor(store)
        with pytest.raises(ValueError, match="ORA-00942"):
            cursor.execute("SELECT * FROM MISSING")

    def test_context_manager(self):
        store = _store_with_rows("SELECT 1 FROM DUAL", [[1]])
        with _ReplayCursor(store) as cursor:
            cursor.execute("SELECT 1 FROM DUAL")
            assert cursor.fetchone() == (1,)


# ---------------------------------------------------------------------------
# _RecordingCursor — recording execute/fetch and __del__ flush
# ---------------------------------------------------------------------------


def _make_recording_cursor(rows=None, description=None, raise_on_execute=None):
    """Build a _RecordingCursor backed by a MagicMock real cursor."""
    log: list[dict] = []
    mock_cursor = MagicMock()
    mock_cursor.description = description
    if raise_on_execute:
        mock_cursor.execute.side_effect = raise_on_execute
    else:
        mock_cursor.execute.return_value = None
    mock_cursor.fetchall.return_value = rows or []
    mock_cursor.fetchone.side_effect = (rows or []) + [None]
    mock_cursor.fetchmany.return_value = rows or []
    mock_cursor.arraysize = 100
    return _RecordingCursor(mock_cursor, log), log


class TestRecordingCursor:
    def test_execute_creates_entry(self):
        cursor, log = _make_recording_cursor(rows=[[1, "alice"]])
        cursor.execute("SELECT * FROM users")
        cursor.close()
        assert len(log) == 1
        assert log[0]["sql_normalized"] == "SELECT * FROM USERS"

    def test_fetchall_captured(self):
        cursor, log = _make_recording_cursor(rows=[[1, "alice"], [2, "bob"]])
        cursor.execute("SELECT * FROM users")
        cursor.fetchall()
        cursor.close()
        assert log[0]["rows"] == [[1, "alice"], [2, "bob"]]

    def test_fetchone_captured(self):
        cursor, log = _make_recording_cursor(rows=[[42]])
        cursor.execute("SELECT id FROM t")
        cursor.fetchone()
        cursor.close()
        assert log[0]["rows"] == [[42]]

    def test_fetchmany_captured(self):
        cursor, log = _make_recording_cursor(rows=[[1], [2]])
        cursor.execute("SELECT id FROM t")
        cursor.fetchmany(2)
        cursor.close()
        assert log[0]["rows"] == [[1], [2]]

    def test_execute_error_recorded_and_reraised(self):
        exc = RuntimeError("connection failed")
        cursor, log = _make_recording_cursor(raise_on_execute=exc)
        with pytest.raises(RuntimeError, match="connection failed"):
            cursor.execute("SELECT * FROM t")
        assert len(log) == 1
        assert "error" in log[0]
        assert log[0]["error"] == "connection failed"

    def test_del_flushes_pending_entry(self):
        cursor, log = _make_recording_cursor(rows=[[99]])
        cursor.execute("SELECT * FROM t")
        # Do NOT call close() — simulate GC via __del__
        cursor.__del__()
        assert len(log) == 1

    def test_del_idempotent(self):
        cursor, log = _make_recording_cursor(rows=[[99]])
        cursor.execute("SELECT * FROM t")
        cursor.__del__()
        cursor.__del__()  # second call should not double-append
        assert len(log) == 1

    def test_context_manager_calls_close(self):
        cursor, log = _make_recording_cursor(rows=[[1]])
        with cursor:
            cursor.execute("SELECT 1 FROM DUAL")
        assert len(log) == 1
