"""
VCR Recorder for HTTP interaction recording and replay.

This module provides the VCRRecorder class that handles recording
HTTP interactions during component execution and replaying them
for deterministic testing.
"""

from __future__ import annotations

import base64
import contextlib
import functools
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

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
        del _vcr_is_connected, _VCRHTTPConnection, _VCRConnection, _VCRFakeSocket
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

        # Set up sanitizers
        if sanitizers is not None:
            self.sanitizer = CompositeSanitizer(sanitizers)
        else:
            self.sanitizer = create_default_sanitizer(self.secrets)

        # Response sanitization is skipped during replay — cassettes already
        # contain sanitized data from when they were recorded.  Only request
        # sanitization runs during replay (needed for matching).
        self._is_replaying = False

        # Profiling counters (always-on during recording, zero cost during replay)
        self._prof_skip_count = 0
        self._prof_parse_count = 0

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
                - 'replay': Always replay (fails if no cassette)
                - 'auto': Replay if cassette exists, otherwise record

        Raises:
            ValueError: If mode is invalid
            CassetteMissingError: If mode is 'replay' and no cassette exists
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

        Args:
            component_runner: Callable that runs the component
        """
        self.cassette_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Recording HTTP interactions to {self.cassette_path}")

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

        try:
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
                    if self.freeze_time_at and self.freeze_time_at != "auto":
                        with freeze_time(self.freeze_time_at):
                            component_runner()
                    else:
                        component_runner()
        finally:
            _VCRHTTPResponse.__init__ = _original_vcr_init

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
        1. Check that a cassette exists
        2. Freeze time to the configured timestamp
        3. Run the component while replaying recorded HTTP interactions

        Args:
            component_runner: Callable that runs the component

        Raises:
            CassetteMissingError: If no cassette exists for replay
        """
        if not self.has_cassette():
            raise CassetteMissingError(
                f"No cassette found at {self.cassette_path}. Run with --record flag to create one."
            )

        logger.info(f"Replaying HTTP interactions from {self.cassette_path}")

        effective_freeze_time = self._resolve_freeze_time()

        vcr_context = self._vcr.use_cassette(
            str(self.cassette_path),
            record_mode="none",
        )

        self._is_replaying = True
        try:
            if effective_freeze_time:
                with freeze_time(effective_freeze_time):
                    with vcr_context:
                        component_runner()
            else:
                with vcr_context:
                    component_runner()
        finally:
            self._is_replaying = False

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
        with open(cassette_path, "r") as f:
            data = json.load(f)
        return data.get("_metadata", {})

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
            _write_interaction_chunked(f, filtered_request._to_dict(), filtered_response)

    def _resolve_freeze_time(self) -> str | None:
        """Resolve effective freeze_time, reading from metadata if 'auto'."""
        if self.freeze_time_at != "auto":
            return self.freeze_time_at

        metadata = self.load_metadata(self.cassette_path)
        if not metadata:
            logger.warning("No metadata in cassette, falling back to default freeze time")
            return self.DEFAULT_FREEZE_TIME

        # Prefer freeze_time (the value used during recording), fall back to recorded_at
        resolved = metadata.get("freeze_time") or metadata.get("recorded_at", self.DEFAULT_FREEZE_TIME)
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
                    with open(config_path, "r") as f:
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
                with open(secrets_path, "r") as f:
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


def _write_json_string_chunked(f, s: str, chunk_size: int = 65536) -> None:
    """Write a JSON-encoded string to f in 64 KB chunks.

    json.dumps(large_string) allocates the entire escaped form at once, which
    for multi-MB bodies creates a transient allocation large enough to fragment
    glibc's heap.  Chunking keeps each escaped piece ≤ ~130 KB so it falls
    just above glibc's mmap threshold and the allocator returns it to the OS
    immediately on free rather than leaving it stranded on the heap.
    """
    f.write('"')
    for i in range(0, len(s), chunk_size):
        f.write(json.dumps(s[i : i + chunk_size])[1:-1])  # strip enclosing quotes
    f.write('"')


def _write_interaction_chunked(f, req_dict: dict, response: dict) -> None:
    """Serialize a VCR interaction to f as a JSONL record.

    The response body string is written in 64 KB chunks (see _write_json_string_chunked)
    to prevent large transient allocations from fragmenting glibc's heap.
    All other fields are small and serialized normally.
    """
    body_dict = response.get("body", {})
    resp_rest = {k: v for k, v in response.items() if k != "body"}

    f.write('{"request": ')
    json.dump(req_dict, f, cls=_BytesEncoder, sort_keys=True)
    f.write(', "response": {"body": ')
    if "string" in body_dict:
        body_string = body_dict["string"]
        if isinstance(body_string, bytes):
            try:
                body_str = body_string.decode("utf-8")
            except UnicodeDecodeError:
                body_str = base64.b64encode(body_string).decode("ascii")
        else:
            body_str = body_string if body_string is not None else ""
        body_rest = {k: v for k, v in body_dict.items() if k != "string"}
        f.write('{"string": ')
        _write_json_string_chunked(f, body_str)
        if body_rest:
            f.write(", ")
            f.write(json.dumps(body_rest, cls=_BytesEncoder, sort_keys=True)[1:-1])
        f.write("}")
    else:
        json.dump(body_dict, f, cls=_BytesEncoder, sort_keys=True)
    if resp_rest:
        f.write(", ")
        f.write(json.dumps(resp_rest, cls=_BytesEncoder, sort_keys=True)[1:-1])
    f.write("}}\n")


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
