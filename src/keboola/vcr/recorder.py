"""
VCR Recorder for HTTP interaction recording and replay.

This module provides the VCRRecorder class that handles recording
HTTP interactions during component execution and replaying them
for deterministic testing.
"""

import json
import logging
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

try:
    import vcr
except ImportError:
    vcr = None  # type: ignore

try:
    from freezegun import freeze_time
except ImportError:
    freeze_time = None  # type: ignore

from .sanitizers import BaseSanitizer, CompositeSanitizer, DefaultSanitizer, create_default_sanitizer

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
        secrets: Optional[Dict[str, Any]] = None,
        sanitizers: Optional[List[BaseSanitizer]] = None,
        freeze_time_at: Optional[str] = "auto",
        record_mode: str = "new_episodes",
        match_on: Optional[List[str]] = None,
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

        # Configure VCR
        self._vcr = self._create_vcr_instance()

    @staticmethod
    def _check_dependencies():
        """Check that required dependencies are installed."""
        if vcr is None:
            raise ImportError("vcrpy is required for VCR functionality. Install it with: pip install vcrpy")
        if freeze_time is None:
            raise ImportError("freezegun is required for VCR functionality. Install it with: pip install freezegun")

    @classmethod
    def from_test_dir(
        cls,
        test_data_dir: Path,
        cassette_subdir: str = "cassettes",
        secrets_file: Optional[str] = None,
        secrets_override: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> "VCRRecorder":
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

    @staticmethod
    def _load_secrets_file(secrets_path: Path) -> Dict[str, Any]:
        """Load secrets from JSON file if it exists."""
        if secrets_path.exists():
            try:
                with open(secrets_path, "r") as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError) as e:
                raise SecretsLoadError(f"Failed to load secrets from {secrets_path}: {e}")
        return {}

    @staticmethod
    def _load_custom_sanitizers(test_data_dir: Path) -> Optional[List[BaseSanitizer]]:
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

    def _before_record_request(self, request: Any) -> Any:
        """Apply sanitizers before recording request."""
        return self.sanitizer.before_record_request(request)

    def _before_record_response(self, response: Dict) -> Dict:
        """Apply sanitizers before recording response.

        Skipped during replay — cassettes already contain sanitized data
        from recording time.  Re-sanitizing during replay would cause
        output drift whenever sanitizers change.
        """
        if self._is_replaying:
            return response
        return self.sanitizer.before_record_response(response)

    def has_cassette(self) -> bool:
        """Check if cassette exists for replay."""
        return self.cassette_path.exists()

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
        from vcr.serializers import compat

        self.cassette_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Recording HTTP interactions to {self.cassette_path}")

        temp_path = self.cassette_path.with_suffix(".jsonl.tmp")
        temp_path.unlink(missing_ok=True)

        vcr_context = self._vcr.use_cassette(str(self.cassette_path), record_mode="all")

        with vcr_context as cassette:
            original_append = cassette.append

            def streaming_append(request, response):
                # Let vcrpy apply sanitizers and deepcopy as normal
                original_append(request, response)
                # If the interaction passed all filters, it was added to cassette.data
                if cassette.data:
                    req, resp = cassette.data.pop()
                    cassette.dirty = False
                    interaction = {
                        "request": compat.convert_to_unicode(req._to_dict()),
                        "response": compat.convert_to_unicode(resp),
                    }
                    with open(temp_path, "a") as f:
                        f.write(json.dumps(interaction) + "\n")

            cassette.append = streaming_append
            # Suppress the context-exit _save() — cassette.data is empty by design
            cassette._save = lambda force=False: None

            if self.freeze_time_at and self.freeze_time_at != "auto":
                with freeze_time(self.freeze_time_at):
                    component_runner()
            else:
                component_runner()

        self._build_cassette_from_jsonl(temp_path)
        temp_path.unlink(missing_ok=True)

        self._inject_metadata()
        logger.info(f"Recorded cassette to {self.cassette_path}")

    def _build_cassette_from_jsonl(self, temp_path: Path) -> None:
        """Reconstruct the cassette JSON from the streaming JSONL temp file."""
        interactions = []
        if temp_path.exists():
            with open(temp_path) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        interactions.append(json.loads(line))

        cassette_data = {"version": 1, "interactions": interactions}
        with open(self.cassette_path, "w") as f:
            json.dump(cassette_data, f, indent=2, sort_keys=True)

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

    @classmethod
    def record_debug_run(
        cls,
        component_runner: Callable[[], None],
        sanitizers: Optional[List["BaseSanitizer"]] = None,
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
        import os
        from datetime import datetime

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
        chain: List[BaseSanitizer] = [DefaultSanitizer(config=config)]
        if sanitizers:
            chain.extend(sanitizers)

        recorder = cls(
            cassette_dir=output_dir,
            sanitizers=chain,
            record_mode="all",
            freeze_time_at=datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
            cassette_file=f"vcr_debug_{component_id}_{config_id}_{timestamp}.json",
        )
        recorder.record(component_runner)

    def _inject_metadata(self) -> None:
        """Inject _metadata into cassette file after recording."""
        from datetime import datetime, timezone

        if not self.cassette_path.exists():
            return

        with open(self.cassette_path, "r") as f:
            cassette = json.load(f)

        cassette["_metadata"] = {
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "freeze_time": self.freeze_time_at,
            "keboola_vcr_version": self._get_version(),
        }

        with open(self.cassette_path, "w") as f:
            json.dump(cassette, f, indent=2, sort_keys=True)

    @staticmethod
    def load_metadata(cassette_path: Path) -> Dict[str, Any]:
        """Load _metadata from a cassette file. Returns empty dict if missing."""
        cassette_path = Path(cassette_path)
        if not cassette_path.exists():
            return {}
        with open(cassette_path, "r") as f:
            data = json.load(f)
        return data.get("_metadata", {})

    @staticmethod
    def _get_version() -> str:
        """Get keboola.vcr package version."""
        try:
            from importlib.metadata import version

            return version("keboola.vcr")
        except Exception:
            return "unknown"

    def _resolve_freeze_time(self) -> Optional[str]:
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


class JsonIndentedSerializer:
    """Custom VCR serializer that produces indented JSON for readability."""

    @staticmethod
    def serialize(cassette_dict: Dict) -> str:
        """Serialize cassette to indented JSON string."""
        return json.dumps(cassette_dict, indent=2, sort_keys=True)

    @staticmethod
    def deserialize(cassette_string: str) -> Dict:
        """Deserialize JSON string to cassette dict."""
        return json.loads(cassette_string)
