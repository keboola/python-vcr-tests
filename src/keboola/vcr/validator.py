"""
Output validation for VCR tests.

This module provides hash-based output validation with diff output
on failure, allowing for efficient comparison of test outputs without
storing full expected files.
"""

import csv
import difflib
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class FileSnapshot:
    """Snapshot information for a single file."""

    path: str
    hash: str
    size_bytes: int
    row_count: Optional[int] = None  # For CSV files
    columns: Optional[List[str]] = None  # For CSV files


@dataclass
class ValidationDiff:
    """Diff information for a single file validation failure."""

    file_path: str
    diff_type: str  # 'hash_mismatch', 'missing', 'unexpected', 'row_count', 'columns'
    expected: Any
    actual: Any
    unified_diff: Optional[str] = None


@dataclass
class ValidationResult:
    """Result of output validation."""

    success: bool
    summary: str
    diffs: List[ValidationDiff] = field(default_factory=list)

    def format_output(self, verbose: bool = False) -> str:
        """
        Format validation result for display.

        Args:
            verbose: If True, include full unified diffs

        Returns:
            Formatted string describing validation result
        """
        lines = [self.summary]

        if not self.success and self.diffs:
            lines.append("")
            lines.append("Differences:")

            for diff in self.diffs:
                if diff.diff_type == "missing":
                    lines.append(f"  - {diff.file_path}: MISSING (expected to exist)")
                elif diff.diff_type == "unexpected":
                    lines.append(f"  + {diff.file_path}: UNEXPECTED (not in snapshot)")
                elif diff.diff_type == "hash_mismatch":
                    lines.append(f"  ~ {diff.file_path}: content changed")
                    if diff.expected.get("row_count") and diff.actual.get("row_count"):
                        lines.append(f"      rows: {diff.expected.get('row_count')} -> {diff.actual.get('row_count')}")
                    lines.append(
                        f"      size: {diff.expected.get('size_bytes', 0)} -> {diff.actual.get('size_bytes', 0)} bytes"
                    )

                if verbose and diff.unified_diff:
                    lines.append("")
                    lines.append(f"    Diff for {diff.file_path}:")
                    for line in diff.unified_diff.split("\n"):
                        lines.append(f"    {line}")

        return "\n".join(lines)


class OutputSnapshot:
    """
    Captures and validates output state using hash-based comparison.

    This class provides functionality to:
    - Capture a snapshot of output files (hashes and metadata)
    - Save snapshots to JSON for later comparison
    - Validate current output against a saved snapshot
    - Generate diffs for debugging failures
    """

    SNAPSHOT_FILE = "output_snapshot.json"

    def __init__(
        self,
        hash_algorithm: str = "sha256",
        ignore_patterns: Optional[List[str]] = None,
    ):
        """
        Initialize output snapshot.

        Args:
            hash_algorithm: Hash algorithm to use (sha256, md5, etc.)
            ignore_patterns: List of filename patterns to ignore
        """
        self.hash_algorithm = hash_algorithm
        self.ignore_patterns = ignore_patterns or [".DS_Store", ".gitkeep"]

    def _should_ignore(self, filename: str) -> bool:
        """Check if a file should be ignored based on patterns."""
        import fnmatch

        for pattern in self.ignore_patterns:
            if fnmatch.fnmatch(filename, pattern):
                return True
        return False

    def _hash_file(self, file_path: Path) -> str:
        """Compute hash of a file."""
        hasher = hashlib.new(self.hash_algorithm)
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hasher.update(chunk)
        return f"{self.hash_algorithm}:{hasher.hexdigest()}"

    def _get_csv_metadata(self, file_path: Path) -> Tuple[Optional[int], Optional[List[str]]]:
        """Extract metadata from a CSV file."""
        try:
            with open(file_path, "r", newline="", encoding="utf-8") as f:
                reader = csv.reader(f)
                try:
                    header = next(reader)
                except StopIteration:
                    return 0, []

                row_count = sum(1 for _ in reader) + 1  # +1 for header
                return row_count, header
        except Exception:
            return None, None

    def _snapshot_file(self, file_path: Path, base_dir: Path) -> FileSnapshot:
        """Create snapshot for a single file."""
        rel_path = str(file_path.relative_to(base_dir))
        stat = file_path.stat()

        snapshot = FileSnapshot(
            path=rel_path,
            hash=self._hash_file(file_path),
            size_bytes=stat.st_size,
        )

        # Add CSV-specific metadata
        if file_path.suffix.lower() == ".csv":
            row_count, columns = self._get_csv_metadata(file_path)
            snapshot.row_count = row_count
            snapshot.columns = columns

        return snapshot

    def capture(self, output_dir: Path) -> Dict[str, Any]:
        """
        Capture snapshot of outputs (hashes + metadata).

        Args:
            output_dir: Directory containing output files to snapshot

        Returns:
            Dictionary containing snapshot data
        """
        output_dir = Path(output_dir)
        tables_dir = output_dir / "tables"
        files_dir = output_dir / "files"

        snapshot = {
            "version": "1.0",
            "hash_algorithm": self.hash_algorithm,
            "tables": {},
            "files": {},
        }

        # Capture tables
        if tables_dir.exists():
            for file_path in sorted(tables_dir.rglob("*")):
                if file_path.is_file() and not self._should_ignore(file_path.name):
                    file_snapshot = self._snapshot_file(file_path, tables_dir)
                    snapshot["tables"][file_snapshot.path] = {
                        "hash": file_snapshot.hash,
                        "size_bytes": file_snapshot.size_bytes,
                        "row_count": file_snapshot.row_count,
                        "columns": file_snapshot.columns,
                    }

        # Capture files
        if files_dir.exists():
            for file_path in sorted(files_dir.rglob("*")):
                if file_path.is_file() and not self._should_ignore(file_path.name):
                    file_snapshot = self._snapshot_file(file_path, files_dir)
                    snapshot["files"][file_snapshot.path] = {
                        "hash": file_snapshot.hash,
                        "size_bytes": file_snapshot.size_bytes,
                    }

        return snapshot

    def save(self, snapshot: Dict[str, Any], snapshot_path: Path) -> None:
        """
        Save snapshot to JSON file.

        Args:
            snapshot: Snapshot dictionary to save
            snapshot_path: Path to save the snapshot file
        """
        with open(snapshot_path, "w") as f:
            json.dump(snapshot, f, indent=2, sort_keys=True)

    def load(self, snapshot_path: Path) -> Dict[str, Any]:
        """
        Load snapshot from JSON file.

        Args:
            snapshot_path: Path to the snapshot file

        Returns:
            Snapshot dictionary

        Raises:
            FileNotFoundError: If snapshot file doesn't exist
        """
        with open(snapshot_path, "r") as f:
            return json.load(f)

    def _generate_file_diff(
        self,
        expected_path: Path,
        actual_path: Path,
    ) -> Optional[str]:
        """Generate unified diff between two files."""
        try:
            with open(expected_path, "r", encoding="utf-8") as f:
                expected_lines = f.readlines()
            with open(actual_path, "r", encoding="utf-8") as f:
                actual_lines = f.readlines()

            diff = list(
                difflib.unified_diff(
                    expected_lines,
                    actual_lines,
                    fromfile=str(expected_path),
                    tofile=str(actual_path),
                    lineterm="",
                )
            )

            if diff:
                return "\n".join(diff)
        except Exception:
            pass

        return None

    def validate(
        self,
        output_dir: Path,
        expected: Dict[str, Any],
        expected_dir: Optional[Path] = None,
        verbose: bool = False,
    ) -> ValidationResult:
        """
        Validate outputs against snapshot.

        Args:
            output_dir: Directory containing actual output files
            expected: Expected snapshot dictionary
            expected_dir: Directory containing expected files (for diff generation)
            verbose: If True, generate detailed diffs

        Returns:
            ValidationResult with success status and any differences
        """
        actual = self.capture(output_dir)
        diffs: List[ValidationDiff] = []

        # Compare tables
        tables_diff = self._compare_section(
            expected.get("tables", {}),
            actual.get("tables", {}),
            "tables",
            output_dir / "tables",
            expected_dir / "tables" if expected_dir else None,
            verbose,
        )
        diffs.extend(tables_diff)

        # Compare files
        files_diff = self._compare_section(
            expected.get("files", {}),
            actual.get("files", {}),
            "files",
            output_dir / "files",
            expected_dir / "files" if expected_dir else None,
            verbose,
        )
        diffs.extend(files_diff)

        # Generate summary
        if not diffs:
            return ValidationResult(success=True, summary="All outputs match expected snapshot")

        missing = len([d for d in diffs if d.diff_type == "missing"])
        unexpected = len([d for d in diffs if d.diff_type == "unexpected"])
        changed = len([d for d in diffs if d.diff_type == "hash_mismatch"])

        parts = []
        if changed:
            parts.append(f"{changed} file{'s' if changed != 1 else ''} changed")
        if missing:
            parts.append(f"{missing} file{'s' if missing != 1 else ''} missing")
        if unexpected:
            parts.append(f"{unexpected} unexpected file{'s' if unexpected != 1 else ''}")

        summary = "Validation failed: " + ", ".join(parts)

        return ValidationResult(success=False, summary=summary, diffs=diffs)

    def _compare_section(
        self,
        expected: Dict[str, Any],
        actual: Dict[str, Any],
        section_name: str,
        actual_base_dir: Path,
        expected_base_dir: Optional[Path],
        verbose: bool,
    ) -> List[ValidationDiff]:
        """Compare a section (tables or files) of the snapshot."""
        diffs: List[ValidationDiff] = []

        expected_paths = set(expected.keys())
        actual_paths = set(actual.keys())

        # Missing files (in expected but not in actual)
        for path in expected_paths - actual_paths:
            diffs.append(
                ValidationDiff(
                    file_path=f"{section_name}/{path}",
                    diff_type="missing",
                    expected=expected[path],
                    actual=None,
                )
            )

        # Unexpected files (in actual but not in expected)
        for path in actual_paths - expected_paths:
            diffs.append(
                ValidationDiff(
                    file_path=f"{section_name}/{path}",
                    diff_type="unexpected",
                    expected=None,
                    actual=actual[path],
                )
            )

        # Changed files (in both but different)
        for path in expected_paths & actual_paths:
            exp_data = expected[path]
            act_data = actual[path]

            if exp_data.get("hash") != act_data.get("hash"):
                unified_diff = None
                if verbose and expected_base_dir:
                    unified_diff = self._generate_file_diff(
                        expected_base_dir / path,
                        actual_base_dir / path,
                    )

                diffs.append(
                    ValidationDiff(
                        file_path=f"{section_name}/{path}",
                        diff_type="hash_mismatch",
                        expected=exp_data,
                        actual=act_data,
                        unified_diff=unified_diff,
                    )
                )

        return diffs


def capture_output_snapshot(
    test_data_dir: Path,
    output_subdir: str = "out",
) -> Dict[str, Any]:
    """
    Convenience function to capture and return output snapshot.

    Args:
        test_data_dir: Path to test's data directory
        output_subdir: Subdirectory containing outputs (default: 'out')

    Returns:
        Snapshot dictionary
    """
    output_dir = Path(test_data_dir) / output_subdir
    snapshot = OutputSnapshot()
    return snapshot.capture(output_dir)


def save_output_snapshot(
    test_data_dir: Path,
    output_subdir: str = "out",
    snapshot_file: str = OutputSnapshot.SNAPSHOT_FILE,
) -> Path:
    """
    Convenience function to capture and save output snapshot.

    Args:
        test_data_dir: Path to test's data directory
        output_subdir: Subdirectory containing outputs (default: 'out')
        snapshot_file: Name of snapshot file to create

    Returns:
        Path to saved snapshot file
    """
    test_data_dir = Path(test_data_dir)
    output_dir = test_data_dir / output_subdir

    snapshot = OutputSnapshot()
    data = snapshot.capture(output_dir)

    snapshot_path = test_data_dir / snapshot_file
    snapshot.save(data, snapshot_path)

    return snapshot_path


def validate_output_snapshot(
    test_data_dir: Path,
    output_subdir: str = "out",
    snapshot_file: str = OutputSnapshot.SNAPSHOT_FILE,
    expected_dir: Optional[Path] = None,
    verbose: bool = False,
) -> ValidationResult:
    """
    Convenience function to validate outputs against saved snapshot.

    Args:
        test_data_dir: Path to test's data directory
        output_subdir: Subdirectory containing outputs
        snapshot_file: Name of snapshot file to load
        expected_dir: Directory with expected files for diff generation
        verbose: Include detailed diffs in result

    Returns:
        ValidationResult
    """
    test_data_dir = Path(test_data_dir)
    output_dir = test_data_dir / output_subdir
    snapshot_path = test_data_dir / snapshot_file

    snapshot = OutputSnapshot()
    expected = snapshot.load(snapshot_path)

    return snapshot.validate(output_dir, expected, expected_dir, verbose)
