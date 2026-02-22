"""Shared pytest fixtures for keboola.vcr tests."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest


@pytest.fixture()
def mock_request():
    """Return a mock vcrpy request with uri, headers, and body attributes."""
    req = SimpleNamespace(
        uri="https://example.com/api/endpoint?param=value",
        headers={"Authorization": "Bearer secret-token", "Content-Type": "application/json"},
        body=None,
    )
    return req


@pytest.fixture()
def mock_response():
    """Return a mock vcrpy response dict."""
    return {
        "body": {"string": b'{"result": "ok"}'},
        "headers": {"Content-Type": ["application/json"], "Authorization": ["Bearer secret"]},
        "status": {"code": 200, "message": "OK"},
        "url": "https://example.com/api/endpoint",
    }


@pytest.fixture()
def tmp_cassette_dir(tmp_path):
    """Return a temporary directory for cassette files."""
    cassette_dir = tmp_path / "cassettes"
    cassette_dir.mkdir()
    return cassette_dir
