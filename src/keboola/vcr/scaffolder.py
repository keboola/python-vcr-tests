"""
Test scaffolder for creating test folder structures.

This module provides functionality to generate test folder structures
from configuration definitions, optionally recording HTTP cassettes.

Supports two input formats:

1. **Wrapped format** (original) — each entry has ``name`` and ``config``:
   ``[{"name": "test_foo", "config": {...}, "secrets": {...}}]``

2. **Raw Keboola config format** — plain Keboola config objects without
   a ``name``/``config`` wrapper.  The scaffolder auto-detects this and
   generates test names from ``parameters.reports[0].report_type`` (or
   falls back to a numbered index).  An optional *secrets file* can be
   provided to deep-merge real credentials at recording time while
   keeping only dummy values in the committed ``config.json``.
"""

import json
import logging
import os
import re
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class ScaffolderError(Exception):
    """Base exception for scaffolder errors."""

    pass


class TestScaffolder:
    """
    Creates test folder structure from config definitions.

    This class generates the standard datadirtest folder structure
    from a JSON file containing test definitions. It can optionally
    run the component and record HTTP cassettes for each test.

    Supports both wrapped definitions (``{name, config}``) and raw
    Keboola configs.  When a ``secrets_file`` is provided, its contents
    are deep-merged into each config **in memory only** during recording;
    the on-disk ``config.json`` always retains the original dummy values.
    """

    SECRET_PLACEHOLDER_PATTERN = re.compile(r"\{\{secret\.([^}]+)\}\}")

    def __init__(self):
        """Initialize test scaffolder."""
        pass

    # ------------------------------------------------------------------
    # Raw-config detection & transformation
    # ------------------------------------------------------------------

    @staticmethod
    def _is_raw_keboola_config(entry: Dict[str, Any]) -> bool:
        """Return True if *entry* looks like a plain Keboola config (no name/config wrapper)."""
        return "name" not in entry and "config" not in entry and "parameters" in entry

    @staticmethod
    def _generate_test_name(config: Dict[str, Any], index: int) -> str:
        """Derive a human-readable test name from a Keboola config.

        Tries ``parameters.reports[0].report_type`` first, then falls back
        to a zero-padded index.
        """
        try:
            report_type = config["parameters"]["reports"][0]["report_type"]
            return f"{index + 1:02d}_{report_type}"
        except (KeyError, IndexError, TypeError):
            return f"{index + 1:02d}_test"

    @classmethod
    def _detect_and_transform_raw_configs(
        cls,
        definitions: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Convert a list of raw Keboola configs into the ``[{name, config}]`` format.

        If the entries already have ``name``/``config`` keys they are returned
        unchanged.
        """
        if not definitions:
            return definitions

        # Check first entry to decide format
        if not cls._is_raw_keboola_config(definitions[0]):
            return definitions

        logger.info("Detected raw Keboola config format — auto-generating test names")
        transformed = []
        for idx, raw_config in enumerate(definitions):
            transformed.append(
                {
                    "name": cls._generate_test_name(raw_config, idx),
                    "config": raw_config,
                }
            )
        return transformed

    # ------------------------------------------------------------------
    # Deep merge helper
    # ------------------------------------------------------------------

    @staticmethod
    def _deep_merge(base: Dict, override: Dict) -> Dict:
        """Deep-merge *override* into *base*, returning a new dict."""
        result = base.copy()
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = TestScaffolder._deep_merge(result[key], value)
            else:
                result[key] = value
        return result

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scaffold_from_json(
        self,
        definitions_file: Path,
        output_dir: Path,
        component_script: Optional[Path] = None,
        record: bool = True,
        freeze_time_at: Optional[str] = "2025-01-01T12:00:00",
        secrets_file: Optional[Path] = None,
        chain_state: bool = False,
    ) -> List[Path]:
        """
        Create test folders from definitions file.

        Args:
            definitions_file: JSON file with list of test configs
            output_dir: Directory to create test folders in
            component_script: Path to component script (required if record=True)
            record: Whether to run component and record cassettes
            freeze_time_at: ISO timestamp for time freezing during recording
            secrets_file: Optional JSON file with real credentials to merge
                during recording.  The file should contain a single object
                whose keys are deep-merged into each config.
            chain_state: Forward out/state.json from each test as
                in/state.json for the next test (for ERP token refresh).

        Returns:
            List of created test folder paths

        Raises:
            ScaffolderError: If definitions file is invalid or recording fails
        """
        definitions_file = Path(definitions_file)
        output_dir = Path(output_dir)

        if not definitions_file.exists():
            raise ScaffolderError(f"Definitions file not found: {definitions_file}")

        try:
            with open(definitions_file, "r") as f:
                definitions = json.load(f)
        except json.JSONDecodeError as e:
            raise ScaffolderError(f"Invalid JSON in definitions file: {e}")

        if not isinstance(definitions, list):
            raise ScaffolderError("Definitions file must contain a JSON array")

        if record and component_script is None:
            raise ScaffolderError("component_script is required when record=True")

        # Auto-detect raw Keboola configs and transform
        definitions = self._detect_and_transform_raw_configs(definitions)

        # Load external secrets file if provided
        secrets_override: Optional[Dict[str, Any]] = None
        if secrets_file is not None:
            secrets_file = Path(secrets_file)
            if not secrets_file.exists():
                raise ScaffolderError(f"Secrets file not found: {secrets_file}")
            try:
                with open(secrets_file, "r") as f:
                    secrets_override = json.load(f)
            except json.JSONDecodeError as e:
                raise ScaffolderError(f"Invalid JSON in secrets file: {e}")

        created_paths = []
        chained_state = None
        for definition in definitions:
            test_path = self._scaffold_single_test(
                definition=definition,
                output_dir=output_dir,
                component_script=component_script,
                record=record,
                freeze_time_at=freeze_time_at,
                secrets_override=secrets_override,
                input_state=chained_state,
            )
            created_paths.append(test_path)

            if chain_state and record:
                state_path = test_path / "source" / "data" / "out" / "state.json"
                if state_path.exists():
                    with open(state_path, "r") as f:
                        chained_state = json.load(f)
                    logger.info(f"Chained state from {test_path.name} for next test")

        return created_paths

    def scaffold_from_dict(
        self,
        definition: Dict[str, Any],
        output_dir: Path,
        component_script: Optional[Path] = None,
        record: bool = True,
        freeze_time_at: Optional[str] = "2025-01-01T12:00:00",
        secrets_override: Optional[Dict[str, Any]] = None,
    ) -> Path:
        """
        Create a single test folder from a definition dict.

        Args:
            definition: Test definition dictionary
            output_dir: Directory to create test folder in
            component_script: Path to component script
            record: Whether to run component and record cassette
            freeze_time_at: ISO timestamp for time freezing
            secrets_override: Optional dict of secrets to deep-merge at recording time

        Returns:
            Path to created test folder
        """
        return self._scaffold_single_test(
            definition=definition,
            output_dir=Path(output_dir),
            component_script=Path(component_script) if component_script else None,
            record=record,
            freeze_time_at=freeze_time_at,
            secrets_override=secrets_override,
        )

    def _scaffold_single_test(
        self,
        definition: Dict[str, Any],
        output_dir: Path,
        component_script: Optional[Path],
        record: bool,
        freeze_time_at: Optional[str],
        secrets_override: Optional[Dict[str, Any]] = None,
        input_state: Optional[Dict[str, Any]] = None,
    ) -> Path:
        """Create folder structure for a single test."""
        # Validate definition
        if "name" not in definition:
            raise ScaffolderError("Test definition missing required 'name' field")
        if "config" not in definition:
            raise ScaffolderError(f"Test '{definition['name']}' missing required 'config' field")

        test_name = definition["name"]
        config = definition["config"]
        secrets = definition.get("secrets", {})
        _ = definition.get("description", "")  # Reserved for future use

        # Create directory structure
        test_dir = output_dir / test_name
        source_data_dir = test_dir / "source" / "data"
        expected_out_dir = test_dir / "expected" / "data" / "out"

        # Create directories
        source_data_dir.mkdir(parents=True, exist_ok=True)
        (source_data_dir / "in").mkdir(exist_ok=True)
        (source_data_dir / "out" / "tables").mkdir(parents=True, exist_ok=True)
        (source_data_dir / "out" / "files").mkdir(parents=True, exist_ok=True)
        expected_out_dir.mkdir(parents=True, exist_ok=True)
        (expected_out_dir / "tables").mkdir(exist_ok=True)
        (expected_out_dir / "files").mkdir(exist_ok=True)

        # Create config.json with placeholders (or original dummy values)
        config_with_placeholders = self._replace_secrets_with_placeholders(config, secrets)
        with open(source_data_dir / "config.json", "w") as f:
            json.dump(config_with_placeholders, f, indent=2)

        # Create config.secrets.json if there are inline secrets
        if secrets:
            with open(source_data_dir / "config.secrets.json", "w") as f:
                json.dump(secrets, f, indent=2)

        # Create input state (chained from previous test or empty)
        input_state_data = input_state if input_state else {}
        with open(source_data_dir / "in" / "state.json", "w") as f:
            json.dump(input_state_data, f, indent=2)

        logger.info(f"Created test folder structure: {test_dir}")

        # Record cassette if requested
        if record and component_script:
            self._record_test(
                test_dir=test_dir,
                source_data_dir=source_data_dir,
                expected_out_dir=expected_out_dir,
                component_script=component_script,
                config=config,
                freeze_time_at=freeze_time_at,
                secrets_override=secrets_override,
            )

        return test_dir

    def _replace_secrets_with_placeholders(
        self,
        config: Dict[str, Any],
        secrets: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Replace secret values in config with placeholders.

        Looks for values matching secrets and replaces them with
        {{secret.key}} placeholders.
        """
        if not secrets:
            return config

        def replace_in_value(value: Any, secrets: Dict[str, Any]) -> Any:
            if isinstance(value, str):
                # Check if this value matches any secret
                for secret_key, secret_value in secrets.items():
                    if isinstance(secret_value, str) and value == secret_value:
                        return f"{{{{secret.{secret_key}}}}}"
                return value
            elif isinstance(value, dict):
                return {k: replace_in_value(v, secrets) for k, v in value.items()}
            elif isinstance(value, list):
                return [replace_in_value(item, secrets) for item in value]
            else:
                return value

        return replace_in_value(config, secrets)

    @staticmethod
    def _pretty_print_manifest(path: Path) -> None:
        """Re-serialize a .manifest file as indented JSON."""
        with open(path, "r") as f:
            data = json.load(f)
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
            f.write("\n")

    def _record_test(
        self,
        test_dir: Path,
        source_data_dir: Path,
        expected_out_dir: Path,
        component_script: Path,
        config: Dict[str, Any],
        freeze_time_at: Optional[str],
        secrets_override: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Run component and record cassette.

        When *secrets_override* is provided (from an external secrets file),
        it is deep-merged into *config* **in memory** for recording.  After
        recording finishes the on-disk ``config.json`` is restored to the
        original dummy values so that real credentials are never committed.
        """
        from .recorder import VCRRecorder
        from .validator import save_output_snapshot

        # Build the config that will actually be used during recording.
        # If an external secrets override is provided, deep-merge it in.
        if secrets_override:
            recording_config = self._deep_merge(config, secrets_override)
        else:
            recording_config = config

        # Write recording config (with real secrets) temporarily
        with open(source_data_dir / "config.json", "w") as f:
            json.dump(recording_config, f, indent=2)

        # Create recorder — pass secrets_override so the sanitizer knows
        # about the real credential values even though config.json on disk
        # may contain dummy placeholders.
        recorder = VCRRecorder.from_test_dir(
            test_data_dir=source_data_dir,
            freeze_time_at=freeze_time_at,
            secrets_override=secrets_override,
        )

        # Run component with recording
        def run_component():
            import sys
            from runpy import run_path

            os.environ["KBC_DATADIR"] = str(source_data_dir)
            # Add the component script's directory to sys.path so that
            # sibling imports (e.g. ``from configuration import ...``) resolve.
            script_dir = str(Path(component_script).resolve().parent)
            if script_dir not in sys.path:
                sys.path.insert(0, script_dir)
            run_path(str(component_script), run_name="__main__")

        try:
            recorder.record(run_component)
            logger.info(f"Recorded cassette for {test_dir.name}")
        except Exception as e:
            logger.error(f"Failed to record cassette for {test_dir.name}: {e}")
            raise ScaffolderError(f"Recording failed for {test_dir.name}: {e}")

        # Pretty-print manifests in-place in source/data/out/
        source_out = source_data_dir / "out"
        if source_out.exists():
            for subdir in ["tables", "files"]:
                src = source_out / subdir
                if src.exists():
                    for item in src.iterdir():
                        if item.is_file() and item.suffix == ".manifest":
                            self._pretty_print_manifest(item)

        # Copy outputs to expected folder
        if source_out.exists():
            for subdir in ["tables", "files"]:
                src = source_out / subdir
                dst = expected_out_dir / subdir
                if src.exists():
                    for item in src.iterdir():
                        if item.is_file():
                            shutil.copy2(item, dst / item.name)

        # Capture output snapshot
        try:
            save_output_snapshot(source_data_dir, output_subdir="out")
            logger.info(f"Saved output snapshot for {test_dir.name}")
        except Exception as e:
            logger.warning(f"Failed to save snapshot for {test_dir.name}: {e}")

        # Restore config.json to the original dummy values
        # Priority: inline secrets → external secrets override → raw config
        secrets_path = source_data_dir / "config.secrets.json"
        if secrets_path.exists():
            with open(secrets_path, "r") as f:
                secrets = json.load(f)
            config_with_placeholders = self._replace_secrets_with_placeholders(config, secrets)
            with open(source_data_dir / "config.json", "w") as f:
                json.dump(config_with_placeholders, f, indent=2)
        elif secrets_override:
            # External secrets were used — restore the original dummy config
            with open(source_data_dir / "config.json", "w") as f:
                json.dump(config, f, indent=2)


def scaffold_tests(
    definitions: List[Dict[str, Any]],
    output_dir: Path,
    component_script: Optional[Path] = None,
    record: bool = True,
    freeze_time_at: Optional[str] = "2025-01-01T12:00:00",
    secrets_override: Optional[Dict[str, Any]] = None,
) -> List[Path]:
    """
    Convenience function to scaffold multiple tests.

    Args:
        definitions: List of test definition dictionaries
        output_dir: Directory to create test folders in
        component_script: Path to component script
        record: Whether to run component and record cassettes
        freeze_time_at: ISO timestamp for time freezing
        secrets_override: Optional dict of secrets to deep-merge at recording time

    Returns:
        List of created test folder paths
    """
    scaffolder = TestScaffolder()
    created_paths = []

    for definition in definitions:
        path = scaffolder.scaffold_from_dict(
            definition=definition,
            output_dir=output_dir,
            component_script=component_script,
            record=record,
            freeze_time_at=freeze_time_at,
            secrets_override=secrets_override,
        )
        created_paths.append(path)

    return created_paths
