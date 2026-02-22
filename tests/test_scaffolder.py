"""Unit tests for keboola.vcr.scaffolder."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from keboola.vcr.scaffolder import ScaffolderError, TestScaffolder, scaffold_tests


# ---------------------------------------------------------------------------
# TestScaffolder._generate_test_name
# ---------------------------------------------------------------------------


class TestGenerateTestName:
    def test_uses_report_type_when_present(self):
        config = {"parameters": {"reports": [{"report_type": "sales_summary"}]}}
        name = TestScaffolder._generate_test_name(config, 0)
        assert name == "01_sales_summary"

    def test_falls_back_to_numbered_index(self):
        config = {"parameters": {}}
        name = TestScaffolder._generate_test_name(config, 0)
        assert name == "01_test"

    def test_falls_back_when_reports_key_missing(self):
        config = {}
        name = TestScaffolder._generate_test_name(config, 2)
        assert name == "03_test"

    def test_falls_back_when_reports_list_empty(self):
        config = {"parameters": {"reports": []}}
        name = TestScaffolder._generate_test_name(config, 0)
        assert name == "01_test"


# ---------------------------------------------------------------------------
# TestScaffolder._mask_secrets
# ---------------------------------------------------------------------------


class TestMaskSecrets:
    def setup_method(self):
        self.scaffolder = TestScaffolder()

    def test_replaces_secret_values_with_placeholders(self):
        config = {"parameters": {"api_key": "real-secret"}}
        secrets = {"api_key": "real-secret"}
        result = self.scaffolder._mask_secrets(config, secrets)
        assert result["parameters"]["api_key"] == "{{secret.api_key}}"

    def test_no_secrets_returns_config_unchanged(self):
        config = {"parameters": {"field": "value"}}
        result = self.scaffolder._mask_secrets(config, {})
        assert result == config

    def test_nested_values_replaced(self):
        config = {"outer": {"inner": "my-token"}}
        secrets = {"token": "my-token"}
        result = self.scaffolder._mask_secrets(config, secrets)
        assert result["outer"]["inner"] == "{{secret.token}}"

    def test_non_matching_values_unchanged(self):
        config = {"parameters": {"safe_field": "not-a-secret"}}
        secrets = {"token": "real-secret"}
        result = self.scaffolder._mask_secrets(config, secrets)
        assert result["parameters"]["safe_field"] == "not-a-secret"


# ---------------------------------------------------------------------------
# TestScaffolder._deep_merge
# ---------------------------------------------------------------------------


class TestDeepMerge:
    def test_merges_override_into_base(self):
        base = {"a": 1, "b": {"c": 2}}
        override = {"b": {"d": 3}, "e": 4}
        result = TestScaffolder._deep_merge(base, override)
        assert result == {"a": 1, "b": {"c": 2, "d": 3}, "e": 4}

    def test_override_replaces_non_dict_values(self):
        base = {"a": 1}
        override = {"a": 99}
        result = TestScaffolder._deep_merge(base, override)
        assert result["a"] == 99

    def test_does_not_mutate_base(self):
        base = {"a": {"b": 1}}
        TestScaffolder._deep_merge(base, {"a": {"c": 2}})
        assert "c" not in base["a"]

    def test_new_keys_in_override_added(self):
        result = TestScaffolder._deep_merge({"x": 1}, {"y": 2})
        assert result == {"x": 1, "y": 2}


# ---------------------------------------------------------------------------
# TestScaffolder._normalize_definitions
# ---------------------------------------------------------------------------


class TestNormalizeDefinitions:
    def test_detects_raw_keboola_config(self):
        raw = [{"parameters": {"api_key": "abc"}, "storage": {}}]
        result = TestScaffolder._normalize_definitions(raw)
        assert "name" in result[0]
        assert "config" in result[0]
        assert result[0]["config"] == raw[0]

    def test_passes_through_wrapped_format(self):
        wrapped = [{"name": "test_one", "config": {"parameters": {}}}]
        result = TestScaffolder._normalize_definitions(wrapped)
        assert result == wrapped

    def test_empty_list_returned_unchanged(self):
        assert TestScaffolder._normalize_definitions([]) == []


# ---------------------------------------------------------------------------
# scaffold_tests (module-level)
# ---------------------------------------------------------------------------


class TestScaffoldTests:
    def test_creates_output_directories_for_each_definition(self, tmp_path):
        definitions = [
            {"name": "test_alpha", "config": {"parameters": {"field": "value"}}},
            {"name": "test_beta", "config": {"parameters": {"field": "other"}}},
        ]
        paths = scaffold_tests(
            definitions=definitions,
            output_dir=tmp_path,
            component_script=None,
            record=False,  # skip actual recording
        )
        assert len(paths) == 2
        assert (tmp_path / "test_alpha").exists()
        assert (tmp_path / "test_beta").exists()

    def test_creates_config_json_in_each_test_dir(self, tmp_path):
        definitions = [{"name": "my_test", "config": {"parameters": {"x": 1}}}]
        scaffold_tests(definitions=definitions, output_dir=tmp_path, record=False)
        config_path = tmp_path / "my_test" / "source" / "data" / "config.json"
        assert config_path.exists()
        data = json.loads(config_path.read_text())
        assert data == {"parameters": {"x": 1}}

    def test_raises_on_missing_definitions_file(self, tmp_path):
        scaffolder = TestScaffolder()
        with pytest.raises(ScaffolderError, match="not found"):
            scaffolder.scaffold_from_json(
                definitions_file=tmp_path / "nonexistent.json",
                output_dir=tmp_path,
                record=False,
            )

    def test_creates_secrets_file_when_inline_secrets_present(self, tmp_path):
        definitions = [
            {
                "name": "with_secrets",
                "config": {"parameters": {"api_key": "{{secret.api_key}}"}},
                "secrets": {"api_key": "real-secret"},
            }
        ]
        scaffold_tests(definitions=definitions, output_dir=tmp_path, record=False)
        secrets_path = tmp_path / "with_secrets" / "source" / "data" / "config.secrets.json"
        assert secrets_path.exists()
        data = json.loads(secrets_path.read_text())
        assert data == {"api_key": "real-secret"}
