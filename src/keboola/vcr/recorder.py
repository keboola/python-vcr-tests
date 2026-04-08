"""
VCR Recorder for HTTP interaction recording and replay.

This module provides the VCRRecorder class that handles recording
HTTP interactions during component execution and replaying them
for deterministic testing.
"""

from __future__ import annotations

import base64
import contextlib
import difflib
import functools
import io
import json
import logging
import os
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import IO, Any

try:
    import vcr
    from vcr.stubs import VCRHTTPResponse as _VCRHTTPResponse

    # --- urllib3 connection-reuse fix ---
    # urllib3's pool calls is_connection_dropped(conn) → not conn.is_connected before
    # reusing a connection.  VCRConnection doesn't define is_connected, so __getattr__
    # delegates to real_connection.is_connected, which checks real_connection.sock.
    #
    # During VCR RECORDING, APIs like Facebook respond with Connection: close, which
    # closes real_connection.sock.  urllib3 then sees is_connected=False and calls
    # _new_conn(), creating a NEW VCRHTTPConnection + real_connection + ssl_context
    # per interaction.  Each ssl_context loads the system CA trust store into OpenSSL
    # C-heap (~480 KB), so 1.6 Connection-close responses per interaction × ~480 KB
    # ≈ 770 KB/interaction of C-heap growth — matching the observed RSS growth rate.
    # This C-heap growth does NOT appear in tracemalloc (Python-only) and is not
    # released by gc.collect() + malloc_trim because jemalloc manages it differently.
    #
    # During VCR REPLAY, VCRFakeSocket replaces the real socket, so is_connected on
    # the real_connection is always False even though the VCR stub is perfectly usable.
    #
    # Fix: always return True when real_connection exists (recording) or a VCRFakeSocket
    # is present (replay).  http.client.HTTPConnection auto-reconnects on its next
    # send() if the socket has been closed — so reusing the VCRHTTPConnection is safe
    # and reuses the existing ssl_context instead of loading the CA store again.
    try:
        from vcr.stubs import VCRFakeSocket as _VCRFakeSocket

        _VCRConnection = _VCRHTTPResponse  # sentinel — replaced below

        # Walk to VCRConnection (shared base of VCRHTTPConnection / VCRHTTPSConnection)
        from vcr.stubs import VCRHTTPConnection as _VCRHTTPConnection

        _VCRConnection = _VCRHTTPConnection.__bases__[0]

        @property  # type: ignore[misc]
        def _vcr_is_connected(self) -> bool:
            sock = getattr(self, "_sock", None)
            if isinstance(sock, _VCRFakeSocket):
                return True  # VCR replay: fake socket is always "connected"
            rc = getattr(self, "real_connection", None)
            if rc is not None:
                # VCR recording: always claim connected so urllib3 reuses this
                # VCRHTTPConnection and its ssl_context instead of calling _new_conn().
                # http.client.HTTPConnection.send() calls connect() automatically when
                # the socket has been closed (Connection: close), so the real connection
                # is re-established transparently on the next request.
                return True
            return False

        _VCRConnection.is_connected = _vcr_is_connected  # type: ignore[attr-defined]
        del _vcr_is_connected, _VCRHTTPConnection, _VCRConnection
    except Exception:
        pass
    # --- end urllib3 connection-reuse fix ---

    # --- VCRHTTPResponse.release_conn fix ---
    # urllib3 2.x returns VCRHTTPResponse *directly* from _make_request() (it is
    # duck-typed as BaseHTTPResponse).  urllib3 then stamps
    #   response._connection = VCRHTTPConnection
    #   response._pool       = HTTPConnectionPool
    # on the VCRHTTPResponse instance and returns it straight to requests as
    # response.raw.  When requests finishes reading the body it calls
    #   response.raw.release_conn()
    # which hits VCRHTTPResponse — NOT urllib3.response.HTTPResponse — so urllib3's
    # own release_conn() machinery is bypassed entirely.
    #
    # Without a working release_conn(), _put_conn() is never called, the pool queue
    # stays empty (q=0), and _new_conn() fires for every request.  Each _new_conn()
    # creates a new VCRHTTPConnection + real urllib3 HTTPSConnection + SSLContext
    # (~480 KB of OpenSSL C-heap loaded from the system CA store).  That adds up to
    # ~8 MB per 10 interactions and causes OOM for jobs with 500+ interactions.
    #
    # The fix: implement release_conn() to return _connection to the pool, exactly
    # mirroring what urllib3.response.HTTPResponse.release_conn() does.  This is safe
    # because VCRHTTPConnection is just a stub — _put_conn() merely places it back in
    # the pool queue so it can be reused on the next request, where vcrpy replaces the
    # socket with a VCRFakeSocket / real_connection reconnect as usual.
    if not hasattr(_VCRHTTPResponse, "release_conn"):

        def _vcr_release_conn(self) -> None:  # noqa: E306
            pool = getattr(self, "_pool", None)
            conn = getattr(self, "_connection", None)
            if pool is not None and conn is not None:
                pool._put_conn(conn)
                self._connection = None

        _VCRHTTPResponse.release_conn = _vcr_release_conn  # type: ignore[attr-defined]
    # --- end VCRHTTPResponse.release_conn fix ---

except ImportError:
    vcr = None  # type: ignore
    _VCRHTTPResponse = None  # type: ignore

try:
    from freezegun import freeze_time
except ImportError:
    freeze_time = None  # type: ignore

from .log_capture import (
    ComponentRunResult,
    LogComparisonResult,
    LogSanitizer,
    SyncActionComparisonResult,
    compare_logs,
    load_logs,
    run_with_log_capture,
    save_logs,
)
from .sanitizers import (
    BaseSanitizer,
    CompositeSanitizer,
    DefaultSanitizer,
    _dedup_sanitizers,
    create_default_sanitizer,
    extract_values,
)

logger = logging.getLogger(__name__)


class VCRRecorderError(Exception):
    """Base exception for VCR recorder errors."""

    pass


class CassetteMissingError(VCRRecorderError):
    """Raised when attempting replay without a cassette."""

    pass


class SecretsLoadError(VCRRecorderError):
    """Raised when secrets file cannot be loaded."""

    pass


class VCRRecorder:
    """
    Records and replays HTTP interactions for component tests.

    This class wraps vcrpy to provide:
    - Recording HTTP interactions during component execution
    - Replaying recorded interactions for deterministic tests
    - Automatic sanitization of sensitive data
    - Time freezing for consistent recordings

    Example usage:
        recorder = VCRRecorder.from_test_dir(test_data_dir)
        if recorder.has_cassette():
            recorder.replay(component_runner)
        else:
            recorder.record(component_runner)
    """

    DEFAULT_CASSETTE_FILE = "requests.json"
    DEFAULT_SECRETS_FILE = "config.secrets.json"
    DEFAULT_FREEZE_TIME = "2025-01-01T12:00:00"

    def __init__(
        self,
        cassette_dir: Path,
        secrets: dict[str, Any] | None = None,
        sanitizers: list[BaseSanitizer] | None = None,
        freeze_time_at: str | None = "auto",
        record_mode: str = "new_episodes",
        match_on: list[str] | None = None,
        cassette_file: str = DEFAULT_CASSETTE_FILE,
        decode_compressed_response: bool = True,
        capture_logs: bool = True,
        log_normalizers: list[tuple[str, str]] | None = None,
        ignored_loggers: set[str] | None = None,
    ):
        """
        Initialize VCR recorder.

        Args:
            cassette_dir: Directory to store cassette files
            secrets: Dictionary of secret values to sanitize from recordings
            sanitizers: List of sanitizers to apply (uses defaults if None)
            freeze_time_at: ISO timestamp to freeze time at during recording/replay.
                           Set to 'auto' (default) to read from cassette metadata on replay.
                           Set to None to disable time freezing.
            record_mode: VCR record mode ('new_episodes', 'none', 'all', 'once')
            match_on: Request matching criteria (default: ['method', 'scheme', 'host', 'port', 'path', 'query'])
            cassette_file: Name of the cassette file (default: 'requests.json')
            decode_compressed_response: Decompress gzip/deflate response bodies before
                storing in cassettes. Enabled by default — this ensures cassettes contain
                readable text and avoids replay failures with libraries that parse raw
                response bodies (e.g. Zeep/SOAP WSDL parsing). Disable for APIs that
                return intentionally compressed binary payloads.
            capture_logs: Capture Python logging output during record/replay (default: True).
                         Logs are saved to cassettes/logs.json and compared on replay.
            log_normalizers: Regex replacement pairs applied to log messages before comparison.
                            Defaults to normalizing UUIDs and epoch timestamps.
            ignored_loggers: Logger name prefixes to exclude from capture.
                            Defaults to vcr, urllib3, freezegun, datadirtest, filelock.
        """
        self._check_dependencies()

        self.cassette_dir = Path(cassette_dir)
        self.cassette_file = cassette_file
        self.cassette_path = self.cassette_dir / cassette_file
        self.secrets = secrets or {}
        self.decode_compressed_response = decode_compressed_response
        self.freeze_time_at = freeze_time_at
        self.record_mode = record_mode
        self.match_on = match_on or ["method", "scheme", "host", "port", "path", "query"]
        self.capture_logs = capture_logs
        self.log_normalizers = log_normalizers
        self.ignored_loggers = ignored_loggers

        # Paths for artefacts stored alongside the cassette
        self.logs_path = self.cassette_dir / "logs.json"
        self.sync_action_result_path = self.cassette_dir / "sync_action_result.json"
        self.expected_status_path = self.cassette_dir / "expected_status.json"

        # Set after replay — can be checked by callers (e.g. VCRTestDataDir)
        self.last_log_comparison: LogComparisonResult | None = None
        self.last_sync_action_comparison: SyncActionComparisonResult | None = None

        # Set up sanitizers — always include DefaultSanitizer so secrets from
        # config.secrets.json are redacted even when component sanitizers are provided.
        default = create_default_sanitizer(self.secrets)
        if sanitizers is not None:
            self.sanitizer = CompositeSanitizer([default, *sanitizers])
        else:
            self.sanitizer = default

        # Response sanitization is skipped during replay — cassettes already
        # contain sanitized data from when they were recorded.  Only request
        # sanitization runs during replay (needed for matching).
        self._is_replaying = False

        # Configure VCR
        self._vcr = self._create_vcr_instance()

    @classmethod
    def from_test_dir(
        cls,
        test_data_dir: Path,
        cassette_subdir: str = "cassettes",
        secrets_file: str | None = None,
        secrets_override: dict[str, Any] | None = None,
        **kwargs,
    ) -> VCRRecorder:
        """
        Create recorder from test directory structure.

        Expects the standard test directory structure:
            test_data_dir/
            ├── config.json
            ├── config.secrets.json (optional)
            └── cassettes/
                └── requests.json

        Args:
            test_data_dir: Path to the test's data directory (source/data)
            cassette_subdir: Subdirectory name for cassettes
            secrets_file: Path to secrets file (default: config.secrets.json in test_data_dir)
            secrets_override: Optional dict of secrets to use instead of loading from file.
                             When provided, these values are used for sanitizer construction.
            **kwargs: Additional arguments passed to VCRRecorder constructor

        Returns:
            Configured VCRRecorder instance
        """
        test_data_dir = Path(test_data_dir)
        cassette_dir = test_data_dir / cassette_subdir

        # Load secrets — prefer override, then file
        if secrets_override is not None:
            secrets = secrets_override
        else:
            secrets_path = Path(secrets_file) if secrets_file else test_data_dir / cls.DEFAULT_SECRETS_FILE
            secrets = cls._load_secrets_file(secrets_path)

        # Load custom sanitizers if defined
        sanitizers = kwargs.pop("sanitizers", None)
        if sanitizers is None:
            custom_sanitizers = cls._load_custom_sanitizers(test_data_dir)
            if custom_sanitizers:
                sanitizers = custom_sanitizers

        return cls(
            cassette_dir=cassette_dir,
            secrets=secrets,
            sanitizers=sanitizers,
            **kwargs,
        )

    @classmethod
    def record_debug_run(
        cls,
        component_runner: Callable[[], None],
        sanitizers: list[BaseSanitizer] | None = None,
    ) -> None:
        """
        Record HTTP interactions during a Keboola platform debug run.

        Reads KBC_DATADIR, KBC_CONFIGID, KBC_COMPONENTID from environment,
        suppresses verbose logging that leaks tokens, and records a cassette
        to /data/out/files/ for download as an artifact.

        The default sanitizer chain always includes:
        - ConfigSecretsSanitizer (auto-detects #-prefixed secrets from config.json)
        - DefaultSanitizer (handles common sensitive fields)

        Args:
            component_runner: Callable that runs the component
            sanitizers: Additional sanitizers to extend the default chain
        """
        # Suppress loggers that print full URIs (including access tokens) at DEBUG level
        for name in ("vcr", "urllib3"):
            logging.getLogger(name).setLevel(logging.WARNING)

        data_dir = os.environ.get("KBC_DATADIR", "/data")
        output_dir = Path(data_dir) / "out" / "files"
        config_id = os.environ.get("KBC_CONFIGID", "unknown")
        component_id = os.environ.get("KBC_COMPONENTID", "component").replace(".", "-")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Build sanitizer chain
        config_path = Path(data_dir) / "config.json"
        config = json.loads(config_path.read_text()) if config_path.exists() else None
        secrets_path = Path(data_dir) / cls.DEFAULT_SECRETS_FILE
        secrets = cls._load_secrets_file(secrets_path)
        secret_values = extract_values(secrets)
        chain: list[BaseSanitizer] = [DefaultSanitizer(config=config, sensitive_values=secret_values)]
        if sanitizers:
            chain.extend(sanitizers)
        chain = _dedup_sanitizers(chain)

        recorder = cls(
            cassette_dir=output_dir,
            sanitizers=chain,
            secrets=secrets,
            record_mode="all",
            freeze_time_at=datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
            cassette_file=f"vcr_debug_{component_id}_{config_id}_{timestamp}.json",
        )

        recorder.record(component_runner)

    def run(
        self,
        component_runner: Callable[[], None],
        mode: str = "auto",
    ) -> None:
        """
        Run component with VCR in specified mode.

        Args:
            component_runner: Callable that runs the component
            mode: One of:
                - 'record': Always record (requires credentials)
                - 'replay': Always replay. If no cassette exists, runs against
                  the live network (useful for sync actions with no HTTP mocking).
                - 'auto': Replay if cassette exists, otherwise record

        Raises:
            ValueError: If mode is invalid
        """
        if mode == "record":
            self.record(component_runner)
        elif mode == "replay":
            self.replay(component_runner)
        elif mode == "auto":
            if self.has_cassette():
                self.replay(component_runner)
            else:
                self.record(component_runner)
        else:
            raise ValueError(f"Invalid VCR mode: {mode}. Must be 'record', 'replay', or 'auto'")

    def record(self, component_runner: Callable[[], None]) -> None:
        """
        Record HTTP interactions while running component.

        Each interaction is serialized and streamed to a temporary JSONL file
        immediately after being captured, then removed from vcrpy's in-memory
        buffer. This keeps memory usage constant regardless of job size.
        The final cassette JSON is reconstructed from the temp file at the end.

        Also captures Python logging output (saved to cassettes/logs.json),
        sync action stdout output (saved to cassettes/sync_action_result.json),
        and auto-saves cassettes/expected_status.json when the component exits
        with a non-zero code.

        Args:
            component_runner: Callable that runs the component
        """
        self.cassette_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Recording HTTP interactions to {self.cassette_path}")

        action = self._get_action_name()
        stdout_capture = io.StringIO() if action != "run" else None

        temp_path = self.cassette_path.with_suffix(".jsonl.tmp")
        temp_path.unlink(missing_ok=True)

        # Patch VCRHTTPResponse to use a zero-copy reader instead of BytesIO.
        # BytesIO(data) always copies the bytes into its own buffer, creating a
        # second in-memory copy of every response body.  _VCRRecordingReader wraps
        # the original bytes without copying.  The patch is scoped to recording only
        # (replay cassettes may reuse the same recorded_response dict multiple times,
        # so we must not mutate it there).
        # NOTE: this patch is global (class-level), not instance-level.  Two
        # VCRRecorder instances calling record() concurrently would race here.
        # Single-threaded component execution is assumed; do not call record()
        # from multiple threads simultaneously.
        _original_vcr_init = _VCRHTTPResponse.__init__
        _VCRHTTPResponse.__init__ = functools.partialmethod(
            _zero_copy_vcr_response_init, original_init=_original_vcr_init
        )

        vcr_context = self._vcr.use_cassette(str(self.cassette_path), record_mode="all")

        def _run_in_vcr():
            with vcr_context as cassette:
                # Capture the cassette's full filter chain so that vcrpy's built-in
                # decode_compressed_response hook (and our sanitizer) both run inside
                # _append_interaction.  Without this, patching cassette.append would
                # bypass the chain, leaving gzip response bodies un-decompressed in
                # the cassette.
                cassette.append = functools.partial(
                    self._append_interaction, temp_path, cassette._before_record_response
                )
                # Suppress the context-exit _save() — we write directly to temp_path
                cassette._save = lambda force=False: None

                with _pool_reuse_patch():
                    if stdout_capture is not None:
                        with contextlib.redirect_stdout(stdout_capture):
                            self._run_with_freeze(component_runner)
                    else:
                        self._run_with_freeze(component_runner)

        run_result: ComponentRunResult | None = None
        try:
            if self.capture_logs:
                run_result = run_with_log_capture(_run_in_vcr, self.ignored_loggers)
            else:
                _run_in_vcr()
        finally:
            _VCRHTTPResponse.__init__ = _original_vcr_init

        if stdout_capture is not None:
            self._remove_leaked_stdout_handlers(stdout_capture)

        if run_result is not None:
            self._save_log_artefacts(run_result, is_recording=True)

        if stdout_capture is not None:
            raw = stdout_capture.getvalue().strip()
            if self.secrets:
                raw = LogSanitizer(self.secrets).sanitize_string(raw)
            if raw:
                self.sync_action_result_path.write_text(raw)
            else:
                self.sync_action_result_path.unlink(missing_ok=True)

        metadata = {
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "freeze_time": self.freeze_time_at,
            "keboola_vcr_version": self._get_version(),
        }
        try:
            self._write_cassette(temp_path, metadata)
        finally:
            temp_path.unlink(missing_ok=True)
        logger.info(f"Recorded cassette to {self.cassette_path}")

    def replay(self, component_runner: Callable[[], None]) -> None:
        """
        Replay recorded HTTP interactions.

        This will:
        1. If a cassette exists, freeze time and replay recorded HTTP interactions.
           If no cassette exists, the component runs against the real network (useful
           for sync actions that hit a live DB/Docker instance with no HTTP mocking).
        2. Compare captured logs against cassettes/logs.json (if present)
        3. Compare sync action stdout against cassettes/sync_action_result.json (if present)
        4. Assert exit code matches cassettes/expected_status.json (if present)

        Args:
            component_runner: Callable that runs the component

        Raises:
            RuntimeError: If exit code does not match expected_status.json
        """
        self.last_log_comparison = None
        self.last_sync_action_comparison = None

        action = self._get_action_name()
        stdout_capture = io.StringIO() if action != "run" else None

        if self.has_cassette():
            logger.info(f"Replaying HTTP interactions from {self.cassette_path}")
            vcr_context: Any = self._vcr.use_cassette(
                str(self.cassette_path),
                record_mode="none",
            )
            effective_freeze_time = self._resolve_freeze_time()
        else:
            logger.info("No cassette found — running without HTTP replay (log/sync-action capture only)")
            vcr_context = contextlib.nullcontext()
            # No cassette metadata to read from — honour an explicit freeze time but
            # don't fall back to DEFAULT_FREEZE_TIME for live-network runs.
            ft = self.freeze_time_at
            effective_freeze_time = ft if ft and ft != "auto" else None

        def _run_in_vcr():
            self._is_replaying = True
            try:
                with vcr_context:
                    if stdout_capture is not None:
                        with contextlib.redirect_stdout(stdout_capture):
                            self._run_with_freeze(component_runner, effective_freeze_time)
                    else:
                        self._run_with_freeze(component_runner, effective_freeze_time)
            finally:
                self._is_replaying = False

        run_result: ComponentRunResult | None = None
        if self.capture_logs:
            run_result = run_with_log_capture(_run_in_vcr, self.ignored_loggers)
        else:
            _run_in_vcr()

        if stdout_capture is not None:
            self._remove_leaked_stdout_handlers(stdout_capture)

        self._assert_replay_result(run_result, stdout_capture)

        logger.info("Replay completed successfully")

    def has_cassette(self) -> bool:
        """Check if cassette exists for replay."""
        return self.cassette_path.exists()

    def clear_cassette(self) -> bool:
        """
        Delete the cassette file if it exists.

        Returns:
            True if cassette was deleted, False if it didn't exist
        """
        if self.has_cassette():
            self.cassette_path.unlink()
            logger.info(f"Deleted cassette at {self.cassette_path}")
            return True
        return False

    @staticmethod
    def load_metadata(cassette_path: Path) -> dict[str, Any]:
        """Load _metadata from a cassette file. Returns empty dict if missing."""
        cassette_path = Path(cassette_path)
        if not cassette_path.exists():
            return {}
        with open(cassette_path) as f:
            data = json.load(f)
        return data.get("_metadata", {})

    def _get_action_name(self) -> str:
        """Read the 'action' field from config.json adjacent to cassette_dir."""
        config_path = self.cassette_dir.parent / "config.json"
        if not config_path.exists():
            return "run"
        try:
            with open(config_path) as f:
                config = json.load(f)
            return config.get("action", "run") or "run"
        except Exception:
            return "run"

    def _run_with_freeze(self, runner: Callable[[], None], freeze_time_val: str | None = None) -> None:
        """Run runner inside optional freeze_time context."""
        ft = freeze_time_val if freeze_time_val is not None else self.freeze_time_at
        if ft and ft != "auto":
            with freeze_time(ft):
                runner()
        else:
            runner()

    def _save_log_artefacts(self, run_result: ComponentRunResult, is_recording: bool) -> None:
        """Sanitize and persist logs.json; auto-save expected_status.json on recording failure."""
        if self.secrets:
            run_result = LogSanitizer(self.secrets).sanitize(run_result)
        save_logs(run_result, self.logs_path)

        if is_recording:
            actual_exit = run_result.exit_code if run_result.exit_code is not None else 0
            if actual_exit != 0:
                expected_status = {"exit_code": actual_exit}
                self.expected_status_path.write_text(json.dumps(expected_status, indent=2))
            else:
                self.expected_status_path.unlink(missing_ok=True)

    def _load_expected_status(self) -> dict | None:
        """Load expected_status.json if it exists."""
        if self.expected_status_path.exists():
            try:
                return json.loads(self.expected_status_path.read_text())
            except Exception:
                pass
        return None

    @staticmethod
    def _remove_leaked_stdout_handlers(stdout_capture: io.StringIO) -> None:
        """Remove any StreamHandlers pointing to stdout_capture from the root logger.

        keboola.component's CommonInterface.__init__ adds StreamHandler(sys.stdout) to
        the root logger. When the component runs inside redirect_stdout(stdout_capture),
        that handler captures stdout_capture. It persists after the component returns,
        causing subsequent logger calls (e.g. "Replay completed successfully") to write
        into stdout_capture and contaminate the sync action JSON output.
        """
        root = logging.getLogger()
        root.handlers = [
            h for h in root.handlers
            if not (isinstance(h, logging.StreamHandler) and getattr(h, "stream", None) is stdout_capture)
        ]

    def _compare_sync_action_result(self, recorded_raw: str, replayed_raw: str) -> SyncActionComparisonResult:
        """Compare two sync action stdout JSON strings."""
        try:
            recorded_json = json.loads(recorded_raw) if recorded_raw else None
            replayed_json = json.loads(replayed_raw) if replayed_raw else None
            if recorded_json == replayed_json:
                return SyncActionComparisonResult(success=True, diff="")
            diff = "\n".join(
                difflib.unified_diff(
                    json.dumps(recorded_json, indent=2).splitlines(),
                    json.dumps(replayed_json, indent=2).splitlines(),
                    fromfile="recorded",
                    tofile="replayed",
                    lineterm="",
                )
            )
            return SyncActionComparisonResult(success=False, diff=diff)
        except json.JSONDecodeError:
            success = recorded_raw == replayed_raw
            diff = f"recorded: {recorded_raw!r}\nreplayed: {replayed_raw!r}" if not success else ""
            return SyncActionComparisonResult(success=success, diff=diff)

    def _assert_replay_result(
        self,
        run_result: ComponentRunResult | None,
        stdout_capture: io.StringIO | None,
    ) -> None:
        """Check exit code, compare logs and sync action output after replay."""
        actual_exit = 0
        if run_result is not None:
            actual_exit = run_result.exit_code if run_result.exit_code is not None else 0

        expected_status = self._load_expected_status()
        expected_exit = expected_status.get("exit_code", 0) if expected_status else 0

        # Compute comparisons before raising so callers always have full context.
        if run_result is not None and self.logs_path.exists():
            if self.secrets:
                run_result = LogSanitizer(self.secrets).sanitize(run_result)
            recorded = load_logs(self.logs_path)
            self.last_log_comparison = compare_logs(recorded, run_result, self.log_normalizers)

        if stdout_capture is not None and self.sync_action_result_path.exists():
            recorded_raw = self.sync_action_result_path.read_text().strip()
            replayed_raw = stdout_capture.getvalue().strip()
            if self.secrets:
                replayed_raw = LogSanitizer(self.secrets).sanitize_string(replayed_raw)
            self.last_sync_action_comparison = self._compare_sync_action_result(
                recorded_raw, replayed_raw
            )

        if actual_exit != expected_exit:
            if actual_exit != 0:
                raise RuntimeError(
                    f"Component exited with unexpected exit code {actual_exit} (expected {expected_exit}). "
                    f"If this is an intentional failure test, create {self.expected_status_path} "
                    f"with the expected exit code, or re-record the cassette."
                )
            else:
                raise RuntimeError(
                    f"Component succeeded (exit code 0) but expected exit code {expected_exit}. "
                    f"The component behaviour has changed since the cassette was recorded."
                )

    def _append_interaction(self, temp_path: Path, cassette_before_record_response, request, response) -> None:
        """Serialize a single recorded interaction to the JSONL temp file."""
        # Apply request filter directly — avoids copy.deepcopy inside original_append
        filtered_request = self._before_record_request(request)
        if not filtered_request:
            return

        # Shallow copy prevents our sanitizer from mutating the response dict
        # that VCRHTTPResponse will return to the component.  The bytes object
        # referenced by body["string"] is immutable, so sharing it is safe.
        response_copy = {
            **response,
            "body": {**response.get("body", {})},
            "headers": dict(response.get("headers", {})),
        }
        # Run the cassette's full before_record_response chain, which includes
        # vcrpy's built-in decode_compressed_response hook followed by our
        # sanitizer.  Calling our _before_record_response alone would skip the
        # decompression step, leaving gzip bodies un-decompressed in cassettes.
        filtered_response = cassette_before_record_response(response_copy)
        if filtered_response is None:
            return

        with open(temp_path, "a") as f:
            _write_interaction(f, filtered_request._to_dict(), filtered_response)

    def _resolve_freeze_time(self) -> str | None:
        """Resolve effective freeze_time, reading from metadata if 'auto'."""
        if self.freeze_time_at != "auto":
            return self.freeze_time_at

        metadata = self.load_metadata(self.cassette_path)
        if not metadata:
            logger.warning("No metadata in cassette, falling back to default freeze time")
            return self.DEFAULT_FREEZE_TIME

        # Prefer freeze_time (the value used during recording), fall back to recorded_at.
        # Treat the literal "auto" as unresolved — it means auto-mode was active during
        # recording and the actual freeze time should come from recorded_at.
        ft = metadata.get("freeze_time")
        resolved = ft if (ft and ft != "auto") else metadata.get("recorded_at", self.DEFAULT_FREEZE_TIME)
        logger.info(f"Auto-resolved freeze_time from cassette metadata: {resolved}")
        return resolved

    def _write_cassette(self, temp_path: Path, metadata: dict) -> None:
        """Stream-write the cassette JSON from the JSONL temp file with inline metadata.

        Writes the output file line-by-line to avoid loading all interactions into
        memory at once (avoids a secondary OOM spike after recording finishes).
        """
        with open(self.cassette_path, "w") as out:
            out.write("{\n")
            out.write('  "_metadata": ' + json.dumps(metadata, sort_keys=True) + ",\n")
            out.write('  "interactions": [\n')
            first = True
            if temp_path.exists():
                with open(temp_path) as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        if not first:
                            out.write(",\n")
                        out.write("    ")
                        out.write(line)
                        first = False
            out.write('\n  ],\n  "version": 1\n}\n')

    def _before_record_request(self, request: Any) -> Any:
        """Apply sanitizers before recording request."""
        return self.sanitizer.before_record_request(request)

    def _before_record_response(self, response: dict) -> dict:
        """Apply sanitizers before recording response.

        Skipped during replay — cassettes already contain sanitized data
        from recording time.  Re-sanitizing during replay would cause
        output drift whenever sanitizers change.
        """
        if self._is_replaying:
            return response
        return self.sanitizer.before_record_response(response)

    def _create_vcr_instance(self) -> Any:
        """Create and configure the VCR instance."""
        my_vcr = vcr.VCR(
            serializer="json",
            cassette_library_dir=str(self.cassette_dir),
            record_mode=self.record_mode,
            match_on=self.match_on,
            decode_compressed_response=self.decode_compressed_response,
            before_record_request=self._before_record_request,
            before_record_response=self._before_record_response,
        )

        # Register JSON serializer with indentation for readability
        my_vcr.register_serializer("json", JsonIndentedSerializer())

        return my_vcr

    @staticmethod
    def _load_custom_sanitizers(test_data_dir: Path) -> list[BaseSanitizer] | None:
        """
        Load custom sanitizers from test directory if defined.

        Looks for a sanitizers.py file with a get_sanitizers() function.
        """
        sanitizers_path = test_data_dir / "sanitizers.py"
        if not sanitizers_path.exists():
            return None

        import importlib.util

        try:
            spec = importlib.util.spec_from_file_location("custom_sanitizers", sanitizers_path)
            if spec is None or spec.loader is None:
                return None

            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            if hasattr(module, "get_sanitizers"):
                config_path = test_data_dir / "config.json"
                config = {}
                if config_path.exists():
                    with open(config_path) as f:
                        config = json.load(f)
                return module.get_sanitizers(config)
        except Exception as e:
            logger.warning(f"Failed to load custom sanitizers from {sanitizers_path}: {e}")

        return None

    @staticmethod
    def _load_secrets_file(secrets_path: Path) -> dict[str, Any]:
        """Load secrets from JSON file if it exists."""
        if secrets_path.exists():
            try:
                with open(secrets_path) as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError) as e:
                raise SecretsLoadError(f"Failed to load secrets from {secrets_path}: {e}")
        return {}

    @staticmethod
    def _get_version() -> str:
        """Get keboola.vcr package version."""
        try:
            from importlib.metadata import version

            return version("keboola.vcr")
        except Exception:
            return "unknown"

    @staticmethod
    def _check_dependencies():
        """Check that required dependencies are installed."""
        if vcr is None:
            raise ImportError("vcrpy is required for VCR functionality. Install it with: pip install vcrpy")
        if freeze_time is None:
            raise ImportError("freezegun is required for VCR functionality. Install it with: pip install freezegun")


class JsonIndentedSerializer:
    """Custom VCR serializer that produces indented JSON for readability."""

    @staticmethod
    def serialize(cassette_dict: dict) -> str:
        """Serialize cassette to indented JSON string."""
        return json.dumps(cassette_dict, indent=2, sort_keys=True)

    @staticmethod
    def deserialize(cassette_string: str) -> dict:
        """Deserialize JSON string to cassette dict."""
        return json.loads(cassette_string)


class _BytesEncoder(json.JSONEncoder):
    """
    JSON encoder that serialises bytes inline without a separate unicode copy.

    Standard approach (compat.convert_to_unicode + json.dumps) creates two
    extra allocations per response body:
      1. convert_to_unicode mutates the body str in the response dict (new str object)
      2. json.dumps builds the full JSON string in memory before writing

    This encoder instead calls json.dump() directly so the output is streamed
    to the file object chunk-by-chunk.  When it encounters bytes it decodes them
    inline (UTF-8 or base64), matching what compat.convert_to_unicode produces,
    so the cassette format is byte-for-byte identical.
    """

    def default(self, obj):
        if isinstance(obj, bytes):
            try:
                return obj.decode("utf-8")
            except UnicodeDecodeError:
                return base64.b64encode(obj).decode("ascii")
        return super().default(obj)


class _VCRRecordingReader:
    """
    Zero-copy BytesIO replacement for VCRHTTPResponse during recording.

    Standard BytesIO(data) copies bytes into its own internal buffer, creating
    a second in-memory copy of every response body.  This class wraps the
    original bytes directly: a full read() returns the same bytes object
    (CPython slice optimisation: b[0:] is b), so no additional allocation occurs.
    """

    __slots__ = ("_data", "_pos")

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    def read(self, n: int = -1) -> bytes:
        if n is None or n < 0:
            chunk = self._data[self._pos :]
            self._pos = len(self._data)
            self._data = b""  # release: caller (urllib3/requests) now owns the only copy
        else:
            chunk = self._data[self._pos : self._pos + n]
            self._pos += len(chunk)
            if self._pos >= len(self._data):
                self._data = b""  # release after chunked reads reach the end
        return chunk

    def read1(self, n: int = -1) -> bytes:
        return self.read(n)

    def readall(self) -> bytes:
        return self.read()

    def readinto(self, b) -> int:
        data = self.read(len(b))
        n = len(data)
        b[:n] = data
        return n

    def readline(self, size: int = -1) -> bytes:
        nl = self._data.find(b"\n", self._pos)
        end = (nl + 1) if nl != -1 else len(self._data)
        if size is not None and size >= 0:
            end = min(end, self._pos + size)
        chunk = self._data[self._pos : end]
        self._pos = end
        return chunk

    def readlines(self, hint: int = -1) -> list:
        lines, total = [], 0
        while self._pos < len(self._data):
            line = self.readline()
            lines.append(line)
            total += len(line)
            if hint is not None and hint > 0 and total >= hint:
                break
        return lines

    def seekable(self) -> bool:
        return True

    def readable(self) -> bool:
        return True

    def isatty(self) -> bool:
        return False

    def tell(self) -> int:
        return self._pos

    def seek(self, pos: int, whence: int = 0) -> int:
        if whence == 0:
            self._pos = pos
        elif whence == 1:
            self._pos += pos
        elif whence == 2:
            self._pos = len(self._data) + pos
        else:
            raise ValueError(f"Invalid whence value {whence!r}; must be 0, 1, or 2")
        self._pos = max(0, min(self._pos, len(self._data)))
        return self._pos

    def getbuffer(self):
        """Return zero-copy memoryview (used by VCRHTTPResponse.length_remaining and .data).

        After ``read()`` completes, ``self._data`` is cleared to ``b""`` and this
        method returns an empty memoryview.  This is intentional and differs from
        ``io.BytesIO`` which preserves data after reading; the early release is
        necessary to avoid holding the response body in memory after urllib3 has
        assembled ``response._content``.
        """
        return memoryview(self._data)


def _write_interaction(f: IO[str], req_dict: dict, response: dict) -> None:
    """Serialize a VCR interaction to f as a JSONL record."""
    json.dump({"request": req_dict, "response": response}, f, cls=_BytesEncoder, sort_keys=True)
    f.write("\n")


@contextlib.contextmanager
def _pool_reuse_patch():
    """Prevent urllib3 connection pool proliferation during VCR recording.

    When the component creates a new requests.Session per API query (common with
    Facebook Graph API batch requests), each session creates its own
    urllib3.PoolManager which creates a fresh HTTPSConnectionPool for
    graph.facebook.com:443.  For N interactions this results in N pools, each
    with its own SSLContext (~480 KB of C-heap loaded from the system CA store).

    This C-heap growth does NOT appear in Python tracemalloc, is NOT collected
    by gc.collect(), and adds ~8 MB per 10 interactions — causing OOM for
    Facebook Ads jobs with 500–2000 interactions.

    Fix 1 (pool reuse): intercept PoolManager.connection_from_host at the class
    level and return the first pool for any given (scheme, host, port) instead of
    letting each new PoolManager create its own.

    Fix 2 (ssl_context reuse): inject a single shared ssl.SSLContext into each
    pool's conn_kw so that ALL connections created by _new_conn() for that pool
    share the same SSLContext.  Without this, each _new_conn() + _validate_conn()
    sequence calls real_connection.connect() → _ssl_wrap_socket_and_match_hostname
    with ssl_context=None → create_urllib3_context() + load_default_certs() for
    EVERY interaction.  load_default_certs() loads ~480 KB of CA cert data into
    OpenSSL's C-heap; jemalloc never returns this to the OS even after the
    SSLContext is freed, so RSS grows ~480 KB per interaction.

    With a shared SSLContext, load_default_certs() runs once per host and all
    subsequent connect() calls reuse the already-loaded context.

    IMPORTANT: must be applied INSIDE the vcrpy cassette context so that pools
    created (and cached) here already carry vcrpy's patched connection stubs.
    """
    try:
        from urllib3.poolmanager import PoolManager
    except ImportError:
        yield
        return

    _shared_pools: dict = {}
    _original_cfh = PoolManager.connection_from_host

    def _inject_shared_ssl_context(pool, scheme: str) -> None:
        """Inject a single shared SSLContext into the pool's conn_kw.

        This ensures all connections created by pool._new_conn() reuse one
        SSLContext instead of creating a new one (and calling load_default_certs)
        on every connect().
        """
        if scheme != "https":
            return
        if pool.conn_kw.get("ssl_context") is not None:
            return
        try:
            from urllib3.util.ssl_ import create_urllib3_context

            ctx = create_urllib3_context()
            # load_default_certs() is only called by urllib3 when it creates its own
            # context (default_ssl_context=True).  Since we supply one, we must call
            # it ourselves so that certificate verification works correctly.
            ctx.load_default_certs()
            pool.conn_kw["ssl_context"] = ctx
        except Exception as exc:
            logger.warning("VCR: could not inject shared ssl_context into pool for %s: %s", pool.host, exc)

    def _reusing_cfh(self, host, port=None, scheme="http", pool_kwargs=None, **kw):
        key = (scheme, host, port)
        if key not in _shared_pools:
            pool = _original_cfh(self, host, port=port, scheme=scheme, pool_kwargs=pool_kwargs, **kw)
            _inject_shared_ssl_context(pool, scheme)
            _shared_pools[key] = pool
        return _shared_pools[key]

    PoolManager.connection_from_host = _reusing_cfh
    try:
        yield
    finally:
        PoolManager.connection_from_host = _original_cfh
        for pool in _shared_pools.values():
            try:
                pool.close()
            except Exception:
                pass
        _shared_pools.clear()


def _zero_copy_vcr_response_init(self_resp, recorded_response, *, original_init) -> None:
    """Patch target for VCRHTTPResponse.__init__ during recording.

    Swaps BytesIO for a _VCRRecordingReader so the response body bytes are
    not copied into a second buffer.  ``original_init`` is passed via
    functools.partial so this can live at module level without a closure.
    """
    body = recorded_response.get("body", {})
    original_bytes = body.pop("string", b"")
    # CRITICAL — memory overhead guard: do not change this to the original bytes.
    # We give vcrpy an empty placeholder so that original_init() wraps b"" in
    # BytesIO (a zero-byte allocation) rather than BytesIO(original_bytes) which
    # would copy every response body into a second buffer.  After init completes
    # we replace _content with a _VCRRecordingReader that wraps original_bytes
    # directly.  Removing or reordering these three lines re-introduces the 2×
    # memory overhead that this function was created to eliminate.
    body["string"] = b""
    original_init(self_resp, recorded_response)
    self_resp._content = _VCRRecordingReader(original_bytes)
    del body["string"]
