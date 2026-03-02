"""Unit tests for keboola.vcr.recorder."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from keboola.vcr.recorder import (
    JsonIndentedSerializer,
    SecretsLoadError,
    VCRRecorder,
    _BytesEncoder,
    _VCRRecordingReader,
)
from keboola.vcr.sanitizers import CompositeSanitizer, DefaultSanitizer

# ---------------------------------------------------------------------------
# _VCRRecordingReader
# ---------------------------------------------------------------------------


class TestVCRRecordingReader:
    def test_read_returns_all_data(self):
        r = _VCRRecordingReader(b"hello world")
        assert r.read() == b"hello world"

    def test_read_n_returns_n_bytes(self):
        r = _VCRRecordingReader(b"hello world")
        assert r.read(5) == b"hello"

    def test_full_read_releases_data(self):
        r = _VCRRecordingReader(b"hello")
        r.read()
        assert r._data == b""

    def test_partial_reads_eventually_release_data(self):
        r = _VCRRecordingReader(b"abc")
        r.read(2)
        assert r._data == b"abc"  # not yet released
        r.read(1)  # now at end
        assert r._data == b""

    def test_tell_tracks_position(self):
        r = _VCRRecordingReader(b"abcde")
        r.read(3)
        assert r.tell() == 3

    def test_seek_absolute(self):
        r = _VCRRecordingReader(b"hello")
        r.read(3)
        pos = r.seek(0, 0)
        assert pos == 0

    def test_seek_relative(self):
        r = _VCRRecordingReader(b"hello")
        r.seek(2, 0)
        pos = r.seek(2, 1)
        assert pos == 4

    def test_seek_from_end(self):
        r = _VCRRecordingReader(b"hello")
        pos = r.seek(-1, 2)
        assert pos == 4

    def test_seek_invalid_whence_raises_value_error(self):
        """Fix 4: invalid whence raises ValueError."""
        r = _VCRRecordingReader(b"hello")
        with pytest.raises(ValueError, match="Invalid whence value"):
            r.seek(0, 3)

    def test_readline_reads_to_newline(self):
        r = _VCRRecordingReader(b"line1\nline2\n")
        assert r.readline() == b"line1\n"
        assert r.readline() == b"line2\n"

    def test_readlines_returns_list(self):
        r = _VCRRecordingReader(b"a\nb\nc\n")
        lines = r.readlines()
        assert lines == [b"a\n", b"b\n", b"c\n"]

    def test_readinto_fills_buffer(self):
        r = _VCRRecordingReader(b"hello")
        buf = bytearray(5)
        n = r.readinto(buf)
        assert n == 5
        assert buf == b"hello"

    def test_getbuffer_returns_memoryview_before_release(self):
        r = _VCRRecordingReader(b"hello")
        mv = r.getbuffer()
        assert isinstance(mv, memoryview)
        assert bytes(mv) == b"hello"

    def test_getbuffer_after_release_returns_empty_memoryview(self):
        """Fix 5 (documented behaviour): after read(), getbuffer() is empty."""
        r = _VCRRecordingReader(b"hello")
        r.read()
        mv = r.getbuffer()
        assert bytes(mv) == b""

    def test_seekable_returns_true(self):
        assert _VCRRecordingReader(b"").seekable() is True

    def test_readable_returns_true(self):
        assert _VCRRecordingReader(b"").readable() is True

    def test_isatty_returns_false(self):
        assert _VCRRecordingReader(b"").isatty() is False

    def test_seek_clamps_below_zero(self):
        r = _VCRRecordingReader(b"hello")
        pos = r.seek(-100, 0)
        assert pos == 0

    def test_seek_clamps_above_length(self):
        r = _VCRRecordingReader(b"hello")
        pos = r.seek(100, 0)
        assert pos == 5


# ---------------------------------------------------------------------------
# JsonIndentedSerializer
# ---------------------------------------------------------------------------


class TestJsonIndentedSerializer:
    def test_serialize_produces_indented_json(self):
        d = {"interactions": [], "_metadata": {"version": "1.0"}}
        result = JsonIndentedSerializer.serialize(d)
        assert "  " in result  # indented
        loaded = json.loads(result)
        assert loaded == d

    def test_deserialize_round_trips(self):
        original = {"key": "value", "num": 42}
        serialized = JsonIndentedSerializer.serialize(original)
        restored = JsonIndentedSerializer.deserialize(serialized)
        assert restored == original

    def test_bytes_encoder_handles_utf8_bytes(self):
        enc = _BytesEncoder()
        assert enc.default(b"hello") == "hello"

    def test_bytes_encoder_handles_non_utf8_bytes(self):
        enc = _BytesEncoder()
        raw = bytes([0xFF, 0xFE])
        result = enc.default(raw)
        import base64

        assert result == base64.b64encode(raw).decode("ascii")


# ---------------------------------------------------------------------------
# VCRRecorder.__init__ and basic attributes
# ---------------------------------------------------------------------------


class TestVCRRecorderInit:
    def test_default_freeze_time_stored(self, tmp_cassette_dir):
        with patch("keboola.vcr.recorder.vcr") as mock_vcr:
            mock_vcr.VCR.return_value = MagicMock()
            r = VCRRecorder(cassette_dir=tmp_cassette_dir)
        assert r.freeze_time_at == "auto"

    def test_custom_sanitizers_stored_in_composite(self, tmp_cassette_dir):
        s = DefaultSanitizer()
        with patch("keboola.vcr.recorder.vcr") as mock_vcr:
            mock_vcr.VCR.return_value = MagicMock()
            r = VCRRecorder(cassette_dir=tmp_cassette_dir, sanitizers=[s])
        assert isinstance(r.sanitizer, CompositeSanitizer)

    def test_no_sanitizers_uses_create_default_sanitizer(self, tmp_cassette_dir):
        with patch("keboola.vcr.recorder.vcr") as mock_vcr:
            mock_vcr.VCR.return_value = MagicMock()
            r = VCRRecorder(cassette_dir=tmp_cassette_dir, secrets={"#k": "v"})
        assert isinstance(r.sanitizer, DefaultSanitizer)
        assert "v" in r.sanitizer.sensitive_values


# ---------------------------------------------------------------------------
# VCRRecorder.has_cassette
# ---------------------------------------------------------------------------


class TestVCRRecorderHasCassette:
    def test_returns_false_when_cassette_dir_missing(self, tmp_path):
        with patch("keboola.vcr.recorder.vcr") as mock_vcr:
            mock_vcr.VCR.return_value = MagicMock()
            r = VCRRecorder(cassette_dir=tmp_path / "nonexistent")
        assert r.has_cassette() is False

    def test_returns_true_when_cassette_file_exists(self, tmp_cassette_dir):
        cassette = tmp_cassette_dir / "requests.json"
        cassette.write_text('{"interactions": []}')
        with patch("keboola.vcr.recorder.vcr") as mock_vcr:
            mock_vcr.VCR.return_value = MagicMock()
            r = VCRRecorder(cassette_dir=tmp_cassette_dir)
        assert r.has_cassette() is True


# ---------------------------------------------------------------------------
# VCRRecorder.load_metadata
# ---------------------------------------------------------------------------


class TestVCRRecorderLoadMetadata:
    def test_returns_metadata_dict(self, tmp_cassette_dir):
        meta = {"recorded_at": "2025-01-01T12:00:00", "version": "1.0"}
        cassette_data = {"interactions": [], "_metadata": meta}
        cassette_path = tmp_cassette_dir / "requests.json"
        cassette_path.write_text(json.dumps(cassette_data))
        assert VCRRecorder.load_metadata(cassette_path) == meta

    def test_returns_empty_dict_when_no_metadata_key(self, tmp_cassette_dir):
        cassette_path = tmp_cassette_dir / "requests.json"
        cassette_path.write_text('{"interactions": []}')
        assert VCRRecorder.load_metadata(cassette_path) == {}

    def test_returns_empty_dict_for_missing_file(self, tmp_cassette_dir):
        assert VCRRecorder.load_metadata(tmp_cassette_dir / "nonexistent.json") == {}


# ---------------------------------------------------------------------------
# VCRRecorder._load_secrets_file
# ---------------------------------------------------------------------------


class TestVCRRecorderLoadSecretsFile:
    def test_returns_empty_dict_for_nonexistent_path(self, tmp_path):
        result = VCRRecorder._load_secrets_file(tmp_path / "missing.json")
        assert result == {}

    def test_returns_parsed_dict_for_valid_file(self, tmp_path):
        f = tmp_path / "secrets.json"
        f.write_text('{"api_key": "secret123"}')
        result = VCRRecorder._load_secrets_file(f)
        assert result == {"api_key": "secret123"}

    def test_raises_secrets_load_error_for_malformed_json(self, tmp_path):
        f = tmp_path / "secrets.json"
        f.write_text("{not valid json}")
        with pytest.raises(SecretsLoadError):
            VCRRecorder._load_secrets_file(f)
