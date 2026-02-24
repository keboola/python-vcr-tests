"""Unit tests for keboola.vcr.validator."""

from __future__ import annotations

from pathlib import Path

from keboola.vcr.validator import (
    OutputSnapshot,
    ValidationDiff,
    ValidationResult,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_file(path: Path, content: bytes | str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content)


def _make_output_dir(tmp_path: Path, tables: dict[str, str] | None = None, files: dict[str, str] | None = None) -> Path:
    """Create a mock output directory with tables/ and files/ subdirs."""
    out = tmp_path / "out"
    if tables:
        for name, content in tables.items():
            _write_file(out / "tables" / name, content)
    if files:
        for name, content in files.items():
            _write_file(out / "files" / name, content)
    return out


# ---------------------------------------------------------------------------
# OutputSnapshot.capture
# ---------------------------------------------------------------------------


class TestOutputSnapshotCapture:
    def test_hashes_files_in_tables_and_files(self, tmp_path):
        out = _make_output_dir(tmp_path, tables={"data.csv": "col\nval\n"}, files={"report.txt": "hello"})
        snap = OutputSnapshot()
        result = snap.capture(out)
        assert "data.csv" in result["tables"]
        assert "report.txt" in result["files"]
        assert result["tables"]["data.csv"]["hash"].startswith("sha256:")

    def test_ignores_ds_store(self, tmp_path):
        out = _make_output_dir(tmp_path, files={".DS_Store": "junk", "ok.txt": "data"})
        snap = OutputSnapshot()
        result = snap.capture(out)
        assert ".DS_Store" not in result["files"]
        assert "ok.txt" in result["files"]

    def test_csv_metadata_row_count_and_columns(self, tmp_path):
        csv_content = "id,name\n1,Alice\n2,Bob\n"
        out = _make_output_dir(tmp_path, tables={"data.csv": csv_content})
        snap = OutputSnapshot()
        result = snap.capture(out)
        meta = result["tables"]["data.csv"]
        assert meta["columns"] == ["id", "name"]
        assert meta["row_count"] == 3  # header + 2 data rows

    def test_empty_output_dir_returns_empty_sections(self, tmp_path):
        out = tmp_path / "out"
        out.mkdir()
        snap = OutputSnapshot()
        result = snap.capture(out)
        assert result["tables"] == {}
        assert result["files"] == {}


# ---------------------------------------------------------------------------
# OutputSnapshot.validate
# ---------------------------------------------------------------------------


class TestOutputSnapshotValidate:
    def _capture_and_validate(self, out: Path, expected_out: Path | None = None) -> tuple:
        snap = OutputSnapshot()
        expected = snap.capture(out)
        # Optionally mutate files to trigger failures
        return snap, expected

    def test_all_matching_returns_success(self, tmp_path):
        out = _make_output_dir(tmp_path, tables={"data.csv": "a,b\n1,2\n"})
        snap = OutputSnapshot()
        expected = snap.capture(out)
        result = snap.validate(out, expected)
        assert result.success is True
        assert "match" in result.summary.lower()

    def test_missing_file_returns_missing_diff(self, tmp_path):
        out = _make_output_dir(tmp_path, tables={"data.csv": "a\n1\n"})
        snap = OutputSnapshot()
        expected = snap.capture(out)
        # Remove the file to simulate missing output
        (out / "tables" / "data.csv").unlink()
        result = snap.validate(out, expected)
        assert result.success is False
        assert any(d.diff_type == "missing" for d in result.diffs)

    def test_unexpected_file_returns_unexpected_diff(self, tmp_path):
        out = _make_output_dir(tmp_path, tables={"data.csv": "a\n1\n"})
        snap = OutputSnapshot()
        expected = snap.capture(out)
        # Add an extra file not in expected
        _write_file(out / "tables" / "extra.csv", "x\n1\n")
        result = snap.validate(out, expected)
        assert result.success is False
        assert any(d.diff_type == "unexpected" for d in result.diffs)

    def test_hash_mismatch_returns_hash_mismatch_diff(self, tmp_path):
        out = _make_output_dir(tmp_path, tables={"data.csv": "a\n1\n"})
        snap = OutputSnapshot()
        expected = snap.capture(out)
        # Overwrite with different content
        _write_file(out / "tables" / "data.csv", "a\n999\n")
        result = snap.validate(out, expected)
        assert result.success is False
        assert any(d.diff_type == "hash_mismatch" for d in result.diffs)


# ---------------------------------------------------------------------------
# OutputSnapshot.save / load
# ---------------------------------------------------------------------------


class TestOutputSnapshotSaveLoad:
    def test_round_trips_snapshot_dict(self, tmp_path):
        data = {
            "version": "1.0",
            "hash_algorithm": "sha256",
            "tables": {"t.csv": {"hash": "sha256:abc", "size_bytes": 10, "row_count": 2, "columns": ["a"]}},
            "files": {},
        }
        snap = OutputSnapshot()
        snap_path = tmp_path / "snap.json"
        snap.save(data, snap_path)
        loaded = snap.load(snap_path)
        assert loaded == data


# ---------------------------------------------------------------------------
# ValidationResult.format_output
# ---------------------------------------------------------------------------


class TestValidationResultFormatOutput:
    def test_non_verbose_lists_summary(self):
        result = ValidationResult(success=True, summary="All outputs match expected snapshot")
        output = result.format_output(verbose=False)
        assert "All outputs match" in output

    def test_verbose_includes_per_file_details(self):
        diff = ValidationDiff(
            file_path="tables/data.csv",
            diff_type="hash_mismatch",
            expected={"hash": "sha256:aaa", "size_bytes": 10},
            actual={"hash": "sha256:bbb", "size_bytes": 20},
            unified_diff="--- old\n+++ new\n@@ ...",
        )
        result = ValidationResult(success=False, summary="Validation failed: 1 file changed", diffs=[diff])
        output = result.format_output(verbose=True)
        assert "tables/data.csv" in output
        assert "--- old" in output

    def test_missing_diff_in_output(self):
        diff = ValidationDiff(
            file_path="tables/missing.csv",
            diff_type="missing",
            expected={"hash": "sha256:abc"},
            actual=None,
        )
        result = ValidationResult(success=False, summary="Validation failed: 1 file missing", diffs=[diff])
        output = result.format_output()
        assert "MISSING" in output

    def test_unexpected_diff_in_output(self):
        diff = ValidationDiff(
            file_path="tables/extra.csv",
            diff_type="unexpected",
            expected=None,
            actual={"hash": "sha256:xyz"},
        )
        result = ValidationResult(success=False, summary="Validation failed: 1 unexpected file", diffs=[diff])
        output = result.format_output()
        assert "UNEXPECTED" in output


# ---------------------------------------------------------------------------
# _get_csv_metadata (via OutputSnapshot._get_csv_metadata)
# ---------------------------------------------------------------------------


class TestGetCsvMetadata:
    def test_returns_row_count_and_columns(self, tmp_path):
        f = tmp_path / "data.csv"
        f.write_text("col1,col2\nval1,val2\nval3,val4\n")
        snap = OutputSnapshot()
        row_count, columns = snap._get_csv_metadata(f)
        assert columns == ["col1", "col2"]
        assert row_count == 3  # header + 2 rows

    def test_returns_none_for_non_csv(self, tmp_path):
        f = tmp_path / "data.txt"
        f.write_text("not csv at all!!!")
        snap = OutputSnapshot()
        # _get_csv_metadata doesn't check extension; it tries to parse
        # A plain text file that fails CSV parsing returns (None, None)
        # but actually csv.reader won't fail on plain text — it'll parse it
        # So let's test with binary content that causes an exception
        f2 = tmp_path / "data.bin"
        f2.write_bytes(bytes(range(256)))
        row_count, columns = snap._get_csv_metadata(f2)
        # binary file causes UnicodeDecodeError → (None, None)
        assert row_count is None
        assert columns is None

    def test_empty_csv_returns_zero_rows(self, tmp_path):
        f = tmp_path / "empty.csv"
        f.write_text("")
        snap = OutputSnapshot()
        row_count, columns = snap._get_csv_metadata(f)
        assert row_count == 0
        assert columns == []
