"""
Log capture and comparison for VCR component runs.

Captures Python logging output and SystemExit codes while running a component,
stores them alongside HTTP cassettes, and compares recorded vs replayed logs
to detect behavioural regressions.
"""

from __future__ import annotations

import contextlib
import difflib
import io
import json
import logging
import re
import warnings
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from logging import LogRecord
from pathlib import Path
from typing import Any

DEFAULT_IGNORED_LOGGERS: frozenset[str] = frozenset(
    {"vcr", "keboola.vcr", "urllib3", "freezegun", "datadirtest", "filelock"}
)
DEFAULT_LOG_LEVEL = logging.DEBUG

DEFAULT_NORMALIZERS: list[tuple[str, str]] = [
    (r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "<UUID>"),
    # Unix epoch timestamps: 10 digits (seconds) to 13 digits (milliseconds).
    (r"\b\d{10,13}\b", "<EPOCH>"),
    # Normalize "File ..." lines in tracebacks to strip directory paths.
    # Tracebacks contain absolute paths that differ between environments
    # (recording vs replay, local vs CI, real driver vs VCR mock).
    (r'File "(?:[^"]*[/\\])([^"]+)"', r'File "\1"'),
]


@dataclass
class CapturedLog:
    level: str          # "INFO", "ERROR", etc.
    logger_name: str    # e.g. "src.component"
    message: str        # formatted log message (exc_text appended if present)
    timestamp: str      # ISO8601 UTC timestamp, e.g. "2025-01-01T12:00:01.234Z"


@dataclass
class ComponentRunResult:
    exit_code: int | None   # None = clean exit (treated as 0), 1 = UserException, 2 = AppError
    logs: list[CapturedLog] = field(default_factory=list)
    stderr: str = ""        # raw stderr output (e.g. sync action error messages, tracebacks)

    def to_dict(self) -> dict:
        return {
            "exit_code": self.exit_code,
            "stderr": self.stderr,
            "logs": [
                {
                    "level": log.level,
                    "logger": log.logger_name,
                    "message": log.message,
                    "timestamp": log.timestamp,
                }
                for log in self.logs
            ],
        }

    @classmethod
    def from_dict(cls, data: dict) -> ComponentRunResult:
        logs = [
            CapturedLog(
                level=entry["level"],
                logger_name=entry["logger"],
                message=entry["message"],
                timestamp=entry.get("timestamp", ""),
            )
            for entry in data.get("logs", [])
        ]
        return cls(exit_code=data.get("exit_code"), logs=logs, stderr=data.get("stderr", ""))


@dataclass
class LogComparisonResult:
    success: bool
    diffs: list[str]    # unified_diff lines for log messages and stderr combined
    summary: str

    def format_output(self, verbose: bool = False) -> str:
        lines = [self.summary]
        if self.diffs and (verbose or not self.success):
            lines.extend(self.diffs)
        return "\n".join(lines)


@dataclass
class SyncActionComparisonResult:
    success: bool
    diff: str   # unified_diff string, empty when success=True


class LogCaptureHandler(logging.Handler):
    """
    Attaches to root logger; filters ignored loggers by prefix match.

    Captures log records as CapturedLog dataclasses, stripping out
    infrastructure noise (vcr, urllib3, freezegun, etc.) by default.
    """

    def __init__(
        self,
        ignored_loggers: frozenset[str] | set[str] = DEFAULT_IGNORED_LOGGERS,
        level: int = DEFAULT_LOG_LEVEL,
    ) -> None:
        super().__init__(level=level)
        self._ignored_loggers = frozenset(ignored_loggers)
        self._records: list[CapturedLog] = []
        self._formatter = logging.Formatter("%(message)s")

    def emit(self, record: LogRecord) -> None:
        for prefix in self._ignored_loggers:
            if record.name == prefix or record.name.startswith(prefix + "."):
                return
        try:
            message = record.getMessage()
            if record.exc_info and not record.exc_text:
                record.exc_text = self._formatter.formatException(record.exc_info)
            if record.exc_text:
                message = f"{message}\n{record.exc_text}"
            timestamp = datetime.fromtimestamp(record.created, tz=timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.%f"
            )[:-3] + "Z"
            self._records.append(
                CapturedLog(
                    level=record.levelname,
                    logger_name=record.name,
                    message=message,
                    timestamp=timestamp,
                )
            )
        except Exception:
            self.handleError(record)

    @property
    def records(self) -> list[CapturedLog]:
        return self._records


class LogSanitizer:
    """
    Replaces secret values in log messages.

    Uses the same secrets dict as VCR sanitizers — secret values extracted
    from config.secrets.json are substituted with '***' before the logs
    are persisted to disk.
    """

    def __init__(self, secrets: dict[str, Any]) -> None:
        from keboola.vcr.sanitizers import extract_values

        self._secret_values = sorted(
            [str(v) for v in extract_values(secrets) if v], key=len, reverse=True
        )

    def sanitize_string(self, text: str) -> str:
        """Replace secret values in an arbitrary string."""
        for secret in self._secret_values:
            text = text.replace(secret, "***")
        return text

    def sanitize(self, result: ComponentRunResult) -> ComponentRunResult:
        if not self._secret_values:
            return result
        sanitized_logs = []
        for log in result.logs:
            message = log.message
            for secret in self._secret_values:
                message = message.replace(secret, "***")
            sanitized_logs.append(
                CapturedLog(
                    level=log.level,
                    logger_name=log.logger_name,
                    message=message,
                    timestamp=log.timestamp,
                )
            )
        stderr = result.stderr
        for secret in self._secret_values:
            stderr = stderr.replace(secret, "***")
        return ComponentRunResult(exit_code=result.exit_code, logs=sanitized_logs, stderr=stderr)


def run_with_log_capture(
    fn: Callable,
    ignored_loggers: set[str] | None = None,
    log_level: int = DEFAULT_LOG_LEVEL,
) -> ComponentRunResult:
    """
    Attach handler to root logger, run fn(), catch SystemExit, detach handler.

    Temporarily lowers the root logger level to log_level so that DEBUG/INFO
    messages emitted by component loggers (whose effective level is derived
    from the root) are not filtered before reaching the handler.

    Does NOT re-raise SystemExit — callers (record/replay) handle the exit code.
    """
    effective_ignored = ignored_loggers if ignored_loggers is not None else DEFAULT_IGNORED_LOGGERS
    handler = LogCaptureHandler(ignored_loggers=effective_ignored, level=log_level)
    root_logger = logging.getLogger()
    previous_level = root_logger.level
    # Lower the root level so records at log_level reach the handler.
    # Only lower — never raise, to avoid suppressing messages that were
    # already flowing through other handlers.
    if previous_level == logging.NOTSET or previous_level > log_level:
        root_logger.setLevel(log_level)

    root_logger.addHandler(handler)
    exit_code: int | None = None
    stderr_buf = io.StringIO()
    try:
        with contextlib.redirect_stderr(stderr_buf):
            with warnings.catch_warnings():
                # Prevent Python's warnings.warn() output from reaching stderr.
                # These are library-level notices (deprecations, tz mismatches, etc.)
                # that vary between a fresh-process recording and an in-process replay
                # (due to per-module __warningregistry__ dedup), causing false diffs.
                # Real component stderr output (sys.stderr.write / print) is still captured.
                warnings.showwarning = lambda *_a, **_kw: None
                fn()
    except SystemExit as e:
        if e.code is None:
            exit_code = None  # sys.exit() / sys.exit(None) — clean exit, treated as 0
        elif isinstance(e.code, int):
            exit_code = e.code
        else:
            # sys.exit("message") — Python prints the message to stderr and exits 1
            stderr_buf.write(str(e.code) + "\n")
            exit_code = 1
    finally:
        root_logger.removeHandler(handler)
        root_logger.setLevel(previous_level)
    return ComponentRunResult(exit_code=exit_code, logs=handler.records, stderr=stderr_buf.getvalue())


def _collapse_tracebacks(text: str) -> str:
    """Collapse Python tracebacks to just the final exception line.

    Tracebacks differ between environments (different intermediate frames
    for DB VCR mocks vs real drivers, absolute vs relative paths).
    Keeps the error type + message, strips all frame details.

    Handles chained exceptions (``The above exception was the direct cause...``).
    """
    lines = text.split("\n")
    result: list[str] = []
    in_traceback = False
    for line in lines:
        if line.strip() == "Traceback (most recent call last):":
            in_traceback = True
            continue
        if in_traceback:
            # Frame lines start with "  File " or whitespace
            if line.startswith("  ") or line.strip() == "":
                continue
            if line.strip().startswith("The above exception"):
                continue
            if line.strip().startswith("During handling of"):
                continue
            # This is the exception line — keep it, exit traceback
            in_traceback = False
            result.append(line)
        else:
            result.append(line)
    return "\n".join(result)


def normalize_message(message: str, normalizers: list[tuple[str, str]]) -> str:
    """Apply regex normalizers and traceback collapsing to a log message."""
    message = _collapse_tracebacks(message)
    for pattern, replacement in normalizers:
        message = re.sub(pattern, replacement, message)
    return message


def save_logs(result: ComponentRunResult, logs_path: Path) -> None:
    """Persist a ComponentRunResult to a JSON file."""
    with open(logs_path, "w") as f:
        json.dump(result.to_dict(), f, indent=2)


def load_logs(logs_path: Path) -> ComponentRunResult:
    """Load a ComponentRunResult from a JSON file."""
    with open(logs_path) as f:
        data = json.load(f)
    return ComponentRunResult.from_dict(data)


def compare_logs(
    recorded: ComponentRunResult,
    replayed: ComponentRunResult,
    normalizers: list[tuple[str, str]] | None = None,
) -> LogComparisonResult:
    """
    Compare recorded vs replayed logs.

    Log messages: normalize both sides then compare lists with unified_diff.
    Stderr: normalize and compare as multiline text.
    Timestamps are not compared — they are informational only.
    Exit code is not compared here; that is the responsibility of the caller
    (see VCRRecorder._assert_replay_result).
    """
    if normalizers is None:
        normalizers = DEFAULT_NORMALIZERS

    def _normalize_messages(logs: list[CapturedLog]) -> list[str]:
        return [normalize_message(log.message, normalizers) for log in logs]

    recorded_messages = _normalize_messages(recorded.logs)
    replayed_messages = _normalize_messages(replayed.logs)

    message_diffs = list(
        difflib.unified_diff(
            recorded_messages,
            replayed_messages,
            fromfile="recorded",
            tofile="replayed",
            lineterm="",
        )
    )

    recorded_stderr = normalize_message(recorded.stderr, normalizers)
    replayed_stderr = normalize_message(replayed.stderr, normalizers)
    stderr_match = recorded_stderr == replayed_stderr
    stderr_diffs = list(
        difflib.unified_diff(
            recorded_stderr.splitlines(),
            replayed_stderr.splitlines(),
            fromfile="recorded stderr",
            tofile="replayed stderr",
            lineterm="",
        )
    ) if not stderr_match else []

    success = not message_diffs and stderr_match

    parts = []
    if message_diffs:
        parts.append(f"Log messages differ ({len(message_diffs)} diff lines)")
    if stderr_diffs:
        parts.append(f"Stderr differs ({len(stderr_diffs)} diff lines)")
    summary = "; ".join(parts) if parts else "Logs match"

    return LogComparisonResult(
        success=success,
        diffs=message_diffs + stderr_diffs,
        summary=summary,
    )
