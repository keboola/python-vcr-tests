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

## Standard repo layout (used by the CLI defaults)

``tests/setup/`` is the conventional home for scaffold inputs:

- ``tests/setup/configs.json``     — test definitions (wrapped or raw format)
- ``tests/setup/input_files/``     — CSV/files for writer components

When ``input_files_dir`` is provided (default: ``tests/setup/input_files``),
the scaffolder reads each test's ``config.json`` after folder creation and
copies matching files into the test's ``in/tables/`` or ``in/files/`` based
on the ``storage.input.tables[].destination`` / ``storage.input.files[].destination``
entries.  This is the mechanism used to supply writer components with their
input data during recording without bundling large CSVs in the test tree.

Example ``configs.json`` entry for a writer::

    {
      "name": "01_write_data",
      "config": {
        "parameters": {"#api_key": "DUMMY"},
        "storage": {
          "input": {
            "tables": [{"destination": "my_input_table.csv"}]
          }
        }
      }
    }

Place ``tests/setup/input_files/my_input_table.csv`` and run scaffold — the
file is copied into each test's ``source/data/in/tables/`` automatically.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import sys
from datetime import datetime
from pathlib import Path
from runpy import run_path
from typing import Any

from .db_recorder import DBAdapter, OracleDBAdapter
from .recorder import VCRRecorder
from .validator import save_output_snapshot

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

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scaffold_from_json(
        self,
        definitions_file: Path,
        output_dir: Path,
        component_script: Path | None = None,
        record: bool = True,
        freeze_time_at: str | None = None,
        secrets_file: Path | None = None,
        chain_state: bool = False,
        regenerate: bool = False,
        input_files_dir: Path | None = None,
        db_adapter: DBAdapter | None = None,
    ) -> list[Path]:
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
            regenerate: Delete existing cassettes before recording so fresh
                interactions are captured from the live API.  When False,
                tests that already have a cassette are skipped.
            input_files_dir: Optional directory containing CSV/files for writer
                components.  After scaffolding each test folder the contents are
                copied into ``in/tables/`` or ``in/files/`` based on the
                ``storage.input`` mappings in each test's ``config.json``.
                Defaults to ``tests/setup/input_files`` when called via the CLI.
                If the directory does not exist it is silently skipped.

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
            with open(definitions_file) as f:
                definitions = json.load(f)
        except json.JSONDecodeError as e:
            raise ScaffolderError(f"Invalid JSON in definitions file: {e}")

        if not isinstance(definitions, list):
            raise ScaffolderError("Definitions file must contain a JSON array")

        if record and component_script is None:
            raise ScaffolderError("component_script is required when record=True")

        # Auto-detect DB adapter from component imports if not explicitly provided
        if db_adapter is None and record and component_script:
            db_adapter = self._auto_detect_db_adapter(component_script)

        # Default freeze time to the current moment so replays match recording conditions.
        # Skip freeze_time when a DB adapter is active — freezegun conflicts with
        # most database drivers' internal timezone/datetime handling during recording.
        # (Replay still uses freeze_time since DB VCR mocks are pure Python.)
        if freeze_time_at is None and db_adapter is None:
            freeze_time_at = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

        # Auto-detect raw Keboola configs and transform
        definitions = self._normalize_definitions(definitions)

        # Load external secrets file if provided
        secrets_override: dict[str, Any] | None = None
        if secrets_file is not None:
            secrets_file = Path(secrets_file)
            if not secrets_file.exists():
                raise ScaffolderError(f"Secrets file not found: {secrets_file}")
            try:
                with open(secrets_file) as f:
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
                regenerate=regenerate,
                input_files_dir=Path(input_files_dir) if input_files_dir is not None else None,
                db_adapter=db_adapter,
            )
            created_paths.append(test_path)

            if chain_state and record:
                state_path = test_path / "source" / "data" / "out" / "state.json"
                if state_path.exists():
                    with open(state_path) as f:
                        chained_state = json.load(f)
                    logger.info(f"Chained state from {test_path.name} for next test")

        return created_paths

    def scaffold_from_dict(
        self,
        definition: dict[str, Any],
        output_dir: Path,
        component_script: Path | None = None,
        record: bool = True,
        freeze_time_at: str | None = None,
        secrets_override: dict[str, Any] | None = None,
        regenerate: bool = False,
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
            regenerate: Delete existing cassette before recording; when False,
                existing cassettes are skipped.

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
            regenerate=regenerate,
        )

    # ------------------------------------------------------------------
    # Primary private methods
    # ------------------------------------------------------------------

    def _scaffold_single_test(
        self,
        definition: dict[str, Any],
        output_dir: Path,
        component_script: Path | None,
        record: bool,
        freeze_time_at: str | None,
        secrets_override: dict[str, Any] | None = None,
        input_state: dict[str, Any] | None = None,
        regenerate: bool = False,
        input_files_dir: Path | None = None,
        db_adapter: DBAdapter | None = None,
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
        config_with_placeholders = self._mask_secrets(config, secrets)
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

        # Copy input files before running the component so the writer can find them
        if input_files_dir is not None:
            self._copy_input_files([test_dir], input_files_dir)

        # Record cassette if requested
        if record and component_script:
            cassette_path = source_data_dir / "cassettes" / VCRRecorder.DEFAULT_CASSETTE_FILE
            if not regenerate and cassette_path.exists():
                logger.info(f"Skipping {test_name} — cassette exists (use --regenerate to force)")
            else:
                self._record_test(
                    test_dir=test_dir,
                    source_data_dir=source_data_dir,
                    expected_out_dir=expected_out_dir,
                    component_script=component_script,
                    config=config,
                    freeze_time_at=freeze_time_at,
                    secrets_override=secrets_override,
                    regenerate=regenerate,
                    db_adapter=db_adapter,
                )

        return test_dir

    def _record_test(
        self,
        test_dir: Path,
        source_data_dir: Path,
        expected_out_dir: Path,
        component_script: Path,
        config: dict[str, Any],
        freeze_time_at: str | None,
        secrets_override: dict[str, Any] | None = None,
        regenerate: bool = False,
        db_adapter: DBAdapter | None = None,
    ) -> None:
        """Run component and record cassette.

        When *secrets_override* is provided (from an external secrets file),
        it is deep-merged into *config* **in memory** for recording.  After
        recording finishes the on-disk ``config.json`` is restored to the
        original dummy values so that real credentials are never committed.
        """
        # Build the config that will actually be used during recording.
        # If an external secrets override is provided, deep-merge it in.
        if secrets_override:
            recording_config = self._deep_merge(config, secrets_override)
        else:
            recording_config = config

        # Write recording config (with real secrets) temporarily
        with open(source_data_dir / "config.json", "w") as f:
            json.dump(recording_config, f, indent=2)

        # Load component-defined sanitizers (e.g. GCS signed URL redaction) so
        # that scaffold recording applies the same sanitizers as test replay.
        from keboola.datadirtest.vcr.tester import _load_vcr_sanitizers_from_script  # ty: ignore[unresolved-import]

        component_sanitizers = _load_vcr_sanitizers_from_script(str(component_script))

        # Create HTTP VCR recorder — always used for log capture, sync action
        # capture, and exit code tracking.  When a DB adapter is active,
        # freeze_time is disabled during recording (freezegun conflicts with
        # most DB drivers' internal timezone handling).  Replay still uses
        # freeze_time since DB VCR replay mocks are pure Python.
        # Create VCR recorder with DB adapters integrated (flat architecture).
        # When DB adapter is active, skip freeze_time during recording
        # (freezegun conflicts with real DB driver connections).
        effective_freeze = None if db_adapter is not None else freeze_time_at
        db_adapters = [db_adapter] if db_adapter else []
        recorder = VCRRecorder.from_test_dir(
            test_data_dir=source_data_dir,
            freeze_time_at=effective_freeze,
            secrets_override=secrets_override,
            sanitizers=component_sanitizers or None,
            db_adapters=db_adapters,
        )

        if regenerate:
            recorder.clear_cassette()

        # Component runner — disables the component SDK's auto-VCR detection
        # to prevent a conflicting second VCR layer during recording.
        # ComponentBase._should_vcr_replay detects cassettes/requests.json and
        # wraps the action with its own VCR replay, which would serve old responses
        # instead of hitting the real API on re-recording runs.
        # TODO: move this suppression into the component SDK itself (e.g. check
        # for a _keboola_vcr_managed attribute or similar) so this monkeypatch
        # is no longer needed.
        def run_component():
            os.environ["KBC_DATADIR"] = str(source_data_dir)
            script_dir = str(Path(component_script).resolve().parent)
            if script_dir not in sys.path:
                sys.path.insert(0, script_dir)
            try:
                from keboola.component.base import ComponentBase  # ty: ignore[unresolved-import]

                original = ComponentBase._should_vcr_replay
                ComponentBase._should_vcr_replay = staticmethod(lambda: False)
            except ImportError:
                original = None
            try:
                run_path(str(component_script), run_name="__main__")
            finally:
                if original is not None:
                    from keboola.component.base import ComponentBase  # ty: ignore[unresolved-import]

                    ComponentBase._should_vcr_replay = original

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
            with open(secrets_path) as f:
                secrets = json.load(f)
            config_with_placeholders = self._mask_secrets(config, secrets)
            with open(source_data_dir / "config.json", "w") as f:
                json.dump(config_with_placeholders, f, indent=2)
        elif secrets_override:
            # External secrets were used — restore the original dummy config
            with open(source_data_dir / "config.json", "w") as f:
                json.dump(config, f, indent=2)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _copy_input_files(created_paths: list[Path], input_files_dir: Path) -> None:
        """Copy input CSV/files into scaffolded test dirs from a shared input_files directory.

        Reads each test's ``config.json`` and copies files listed under
        ``storage.input.tables[].destination`` into ``in/tables/`` and
        ``storage.input.files[].destination`` into ``in/files/``.

        Silently skips if *input_files_dir* does not exist or a referenced
        source file is missing — the user will get a clear runtime error from
        the component if a required input is absent.
        """
        if not input_files_dir.exists():
            return

        for test_dir in created_paths:
            config_path = test_dir / "source" / "data" / "config.json"
            if not config_path.exists():
                continue

            try:
                config = json.loads(config_path.read_text())
            except (json.JSONDecodeError, OSError):
                continue

            storage = config.get("storage", {})

            for entry in storage.get("input", {}).get("tables", []):
                dest = entry.get("destination", "")
                if not dest:
                    continue
                src = input_files_dir / dest
                if src.exists():
                    target_dir = test_dir / "source" / "data" / "in" / "tables"
                    target_dir.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(src, target_dir / dest)
                    logger.info(f"Copied {src} -> {target_dir / dest}")

            for entry in storage.get("input", {}).get("files", []):
                dest = entry.get("destination", "")
                if not dest:
                    continue
                src = input_files_dir / dest
                if src.exists():
                    target_dir = test_dir / "source" / "data" / "in" / "files"
                    target_dir.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(src, target_dir / dest)
                    logger.info(f"Copied {src} -> {target_dir / dest}")

    def _mask_secrets(
        self,
        config: dict[str, Any],
        secrets: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Replace secret values in config with placeholders.

        Looks for values matching secrets and replaces them with
        {{secret.key}} placeholders.
        """
        if not secrets:
            return config
        return self._replace_value(config, secrets)

    @staticmethod
    def _replace_value(value: Any, secrets: dict[str, Any]) -> Any:
        """Recursively replace secret values with {{secret.key}} placeholders."""
        if isinstance(value, str):
            for secret_key, secret_value in secrets.items():
                if isinstance(secret_value, str) and value == secret_value:
                    return f"{{{{secret.{secret_key}}}}}"
            return value
        elif isinstance(value, dict):
            return {k: TestScaffolder._replace_value(v, secrets) for k, v in value.items()}
        elif isinstance(value, list):
            return [TestScaffolder._replace_value(item, secrets) for item in value]
        else:
            return value

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _auto_detect_db_adapter(component_script: Path) -> DBAdapter | None:
        """Auto-detect DB adapter by scanning the component's dependencies.

        Checks the component's pyproject.toml or source files for known DB driver
        imports. Returns the appropriate adapter or None if no DB driver is found.
        """
        # Known DB drivers and their adapters
        driver_map: dict[str, type[DBAdapter]] = {
            "oracledb": OracleDBAdapter,
            # Future: "psycopg2": Psycopg2Adapter, "mysql.connector": MySQLAdapter
        }

        # Strategy 1: Check pyproject.toml dependencies
        project_dir = Path(component_script).resolve().parent.parent
        pyproject = project_dir / "pyproject.toml"
        if pyproject.exists():
            content = pyproject.read_text()
            for driver_name, adapter_cls in driver_map.items():
                if driver_name in content:
                    logger.info(f"Auto-detected DB driver '{driver_name}' from pyproject.toml")
                    return adapter_cls()

        # Strategy 2: Scan source files for import statements
        src_dir = Path(component_script).resolve().parent
        for py_file in src_dir.glob("*.py"):
            try:
                content = py_file.read_text()
                for driver_name, adapter_cls in driver_map.items():
                    if f"import {driver_name}" in content:
                        logger.info(f"Auto-detected DB driver '{driver_name}' from {py_file.name}")
                        return adapter_cls()
            except OSError:
                continue

        return None

    @staticmethod
    def _pretty_print_manifest(path: Path) -> None:
        """Re-serialize a .manifest file as indented JSON."""
        with open(path) as f:
            data = json.load(f)
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
            f.write("\n")

    @classmethod
    def _normalize_definitions(
        cls,
        definitions: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
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

    @staticmethod
    def _is_raw_keboola_config(entry: dict[str, Any]) -> bool:
        """Return True if *entry* looks like a plain Keboola config (no name/config wrapper)."""
        return "name" not in entry and "config" not in entry and "parameters" in entry

    @staticmethod
    def _generate_test_name(config: dict[str, Any], index: int) -> str:
        """Derive a human-readable test name from a Keboola config.

        Tries ``parameters.reports[0].report_type`` first, then falls back
        to a zero-padded index.
        """
        try:
            report_type = config["parameters"]["reports"][0]["report_type"]
            return f"{index + 1:02d}_{report_type}"
        except (KeyError, IndexError, TypeError):
            return f"{index + 1:02d}_test"

    @staticmethod
    def _deep_merge(base: dict, override: dict) -> dict:
        """Deep-merge *override* into *base*, returning a new dict."""
        result = base.copy()
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = TestScaffolder._deep_merge(result[key], value)
            else:
                result[key] = value
        return result


def scaffold_tests(
    definitions: list[dict[str, Any]],
    output_dir: Path,
    component_script: Path | None = None,
    record: bool = True,
    freeze_time_at: str | None = None,
    secrets_override: dict[str, Any] | None = None,
) -> list[Path]:
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
