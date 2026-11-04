"""Tests for keboola.vcr.proxy: config loading, cassette record/replay logic, and a real mitmproxy round trip."""

from __future__ import annotations

import asyncio
import json
import socket
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from vcr.request import Request

from keboola.vcr.proxy import CassetteSession, ProxyConfig, ProxyConfigError, RecordingError, SecretLeakError
from keboola.vcr.proxy.cassette import response_parts
from keboola.vcr.sanitizers import DefaultSanitizer

SECRET = "s3cr3t-refresh-token-value"


def _session(tmp_path: Path, mode: str, config: ProxyConfig | None = None, secrets: list[str] | None = None):
    config = config or ProxyConfig.from_dict({})
    secrets = secrets or []
    return CassetteSession(
        path=tmp_path / "cassettes" / "requests.json",
        mode=mode,
        sanitizers=config.build_sanitizers(secrets),
        match=config.match,
        secret_values=secrets,
    )


def _resp(body: bytes | str, code: int = 200, ctype: str = "application/json") -> dict:
    return {
        "status": {"code": code, "message": "OK"},
        "headers": {"Content-Type": [ctype], "Set-Cookie": ["sid=abc"], "Content-Length": ["999"]},
        "body": {"string": body},
    }


# -- config ---------------------------------------------------------------------------------------------------


def test_config_defaults_keep_token_endpoints_ignored(tmp_path):
    path = tmp_path / "vcr.json"
    path.write_text(json.dumps({"match": {"ignore_body": ["api.example.com/upload"]}}))
    cfg = ProxyConfig.load(path)
    assert cfg.match.body_ignored_for("login.microsoftonline.com", "/common/oauth2/v2.0/token")
    assert cfg.match.body_ignored_for("api.example.com", "/upload")
    assert not cfg.match.body_ignored_for("graph.microsoft.com", "/v1.0/$batch")


def test_config_missing_file_is_empty_config(tmp_path):
    cfg = ProxyConfig.load(tmp_path / "nope.json")
    assert cfg.secret_env == []
    assert len(cfg.build_sanitizers([])) == 1


@pytest.mark.parametrize(
    "raw",
    [
        {"sanitizers": [{"class": "CallbackSanitizer"}]},
        {"sanitizers": [{"class": "DefaultSanitizer"}, {"class": "DefaultSanitizer"}]},
        {"unknown": 1},
        {"match": {"bodies": False}},
    ],
)
def test_config_rejects_invalid(raw):
    with pytest.raises(ProxyConfigError):
        ProxyConfig.from_dict(raw)


def test_config_reads_secret_values_from_env_only_when_set():
    cfg = ProxyConfig.from_dict({"secret_env": ["A", "B", "C"]})
    assert cfg.secret_values({"A": "x", "B": ""}) == ["x"]


def test_config_builds_declared_sanitizers_after_default():
    cfg = ProxyConfig.from_dict(
        {
            "sanitizers": [
                {"class": "BodyFieldSanitizer", "fields": ["email"]},
                {"class": "DefaultSanitizer", "additional_sensitive_fields": ["sessionId"]},
                {"class": "UrlPatternSanitizer", "patterns": [["/users/\\d+", "/users/0"]]},
            ]
        }
    )
    chain = cfg.build_sanitizers(["v"])
    assert [type(s).__name__ for s in chain] == ["DefaultSanitizer", "BodyFieldSanitizer", "UrlPatternSanitizer"]
    default = chain[0]
    assert isinstance(default, DefaultSanitizer)
    assert "sessionId" in default.sensitive_fields
    assert default.sensitive_values == ["v"]


# -- record ---------------------------------------------------------------------------------------------------


def test_record_writes_sanitized_cassette_in_vcr_format(tmp_path):
    s = _session(tmp_path, "record", secrets=[SECRET])
    req = Request(
        "POST",
        "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        f"grant_type=refresh_token&refresh_token={SECRET}".encode(),
        {"Content-Type": "application/x-www-form-urlencoded", "Authorization": "Basic abc"},
    )
    s.record(req, _resp(json.dumps({"access_token": "live-access", "refresh_token": SECRET, "expires_in": 3600})))
    assert s.write("test") == 1

    data = json.loads(s.path.read_text())
    assert data["version"] == 1
    assert data["_metadata"]["recorder"] == "keboola.vcr.proxy"
    assert data["_metadata"]["request_pairs"] == 1
    text = s.path.read_text()
    assert SECRET not in text
    assert "live-access" not in text
    assert "Basic abc" not in text
    assert "sid=abc" not in text  # response headers are whitelisted
    interaction = data["interactions"][0]
    assert interaction["request"]["method"] == "POST"
    assert interaction["response"]["status"]["code"] == 200
    assert isinstance(interaction["response"]["body"]["string"], str)


def test_record_refuses_to_write_a_leaked_secret(tmp_path):
    # The secret sits in a field no sanitizer knows, and the DefaultSanitizer is not told the value.
    cfg = ProxyConfig.from_dict({})
    s = CassetteSession(
        path=tmp_path / "requests.json",
        mode="record",
        sanitizers=cfg.build_sanitizers([]),
        match=cfg.match,
        secret_values=[SECRET],
    )
    s.record(Request("GET", "https://api.example.com/x", b"", {}), _resp(json.dumps({"opaque": SECRET})))
    with pytest.raises(SecretLeakError) as e:
        s.write("test")
    assert SECRET not in str(e.value)
    assert not s.path.exists()


def test_record_keeps_binary_body_as_base64(tmp_path):
    s = _session(tmp_path, "record")
    blob = bytes(range(256))
    s.record(Request("GET", "https://api.example.com/file", b"", {}), _resp(blob, ctype="application/octet-stream"))
    s.write("test")
    replay = _session(tmp_path, "replay")
    recorded = replay.replay(Request("GET", "https://api.example.com/file", b"", {}))
    assert recorded is not None
    assert response_parts(recorded)[3] == blob


def test_scrub_before_read_redacts_client_copy(tmp_path):
    cfg = ProxyConfig.from_dict(
        {"sanitizers": [{"class": "BodyFieldSanitizer", "fields": ["email"], "scrub_before_read": True}]}
    )
    s = _session(tmp_path, "record", config=cfg)
    scrubbed = s.scrub_for_client(_resp(json.dumps({"email": "a@b.c", "id": 1})))
    assert scrubbed is not None
    assert "a@b.c" not in str(scrubbed["body"]["string"])
    assert _session(tmp_path, "record").scrub_for_client(_resp("{}")) is None


# -- replay ---------------------------------------------------------------------------------------------------


def _recorded(tmp_path: Path, pairs: list[tuple[Request, dict]], config: ProxyConfig | None = None) -> None:
    s = _session(tmp_path, "record", config=config, secrets=[SECRET])
    for req, resp in pairs:
        s.record(req, resp)
    s.write("test")


def test_replay_matches_on_sorted_query_and_ignores_headers(tmp_path):
    _recorded(
        tmp_path,
        [
            (
                Request("GET", "https://graph.microsoft.com/v1.0/me?b=2&a=1", b"", {"Authorization": "Bearer real"}),
                _resp('{"id": "me"}'),
            )
        ],
    )
    s = _session(tmp_path, "replay")
    got = s.replay(
        Request("GET", "https://graph.microsoft.com/v1.0/me?a=1&b=2", b"", {"Authorization": "Bearer REDACTED"})
    )
    assert got is not None
    status, _, headers, body = response_parts(got)
    assert status == 200
    assert json.loads(body) == {"id": "me"}
    assert all(k.lower() != b"content-length" for k, _ in headers)


def test_replay_ignores_token_endpoint_body(tmp_path):
    token_url = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
    _recorded(
        tmp_path,
        [
            (
                Request(
                    "POST",
                    token_url,
                    f"refresh_token={SECRET}&client_id=real".encode(),
                    {"Content-Type": "application/x-www-form-urlencoded"},
                ),
                _resp('{"access_token": "t"}'),
            )
        ],
    )
    s = _session(tmp_path, "replay")
    got = s.replay(
        Request(
            "POST",
            token_url,
            b"refresh_token=dummy&client_id=dummy&extra=1",
            {"Content-Type": "application/x-www-form-urlencoded"},
        )
    )
    assert got is not None
    # the recorded token was redacted, so the component gets a placeholder, never the live value
    assert json.loads(response_parts(got)[3]) == {"access_token": "REDACTED"}


def test_replay_matches_json_body_and_picks_the_right_interaction(tmp_path):
    url = "https://graph.microsoft.com/v1.0/$batch"
    ctype = {"Content-Type": "application/json"}
    _recorded(
        tmp_path,
        [
            (Request("POST", url, b'{"requests": [{"id": "1", "url": "/a"}]}', ctype), _resp('{"r": "a"}')),
            (Request("POST", url, b'{"requests": [{"id": "1", "url": "/b"}]}', ctype), _resp('{"r": "b"}')),
        ],
    )
    s = _session(tmp_path, "replay")
    got = s.replay(Request("POST", url, b'{"requests":[{"url":"/b","id":"1"}]}', ctype))
    assert json.loads(response_parts(got)[3]) == {"r": "b"}
    assert s.replay(Request("POST", url, b'{"requests": [{"id": "1", "url": "/c"}]}', ctype)) is None
    assert "no recorded interaction matches" in s.unmatched[0]
    assert s.unused_count() == 1


def test_replay_ignore_body_fields(tmp_path):
    url = "https://api.example.com/search"
    ctype = {"Content-Type": "application/json"}
    cfg = ProxyConfig.from_dict({"match": {"ignore_body_fields": ["requestId"]}})
    _recorded(tmp_path, [(Request("POST", url, b'{"q": "x", "requestId": "r1"}', ctype), _resp("{}"))], config=cfg)
    s = _session(tmp_path, "replay", config=cfg)
    assert s.replay(Request("POST", url, b'{"q": "x", "requestId": "r2"}', ctype)) is not None


def test_replay_plays_each_interaction_once_unless_repeats_allowed(tmp_path):
    req = Request("GET", "https://api.example.com/x", b"", {})
    _recorded(tmp_path, [(req, _resp('{"n": 1}')), (req, _resp('{"n": 2}'))])
    s = _session(tmp_path, "replay")
    assert json.loads(response_parts(s.replay(req))[3]) == {"n": 1}
    assert json.loads(response_parts(s.replay(req))[3]) == {"n": 2}
    assert s.replay(req) is None
    assert "already played" in s.unmatched[0]

    cfg = ProxyConfig.from_dict({"match": {"allow_playback_repeats": True}})
    s = _session(tmp_path, "replay", config=cfg)
    s.replay(req)
    s.replay(req)
    assert json.loads(response_parts(s.replay(req))[3]) == {"n": 2}


def test_replay_masks_multipart_boundaries(tmp_path):
    url = "https://api.example.com/upload"

    def multipart(boundary: str) -> Request:
        body = f'--{boundary}\r\nContent-Disposition: form-data; name="f"\r\n\r\nhello\r\n--{boundary}--\r\n'
        return Request("POST", url, body.encode(), {"Content-Type": f"multipart/form-data; boundary={boundary}"})

    _recorded(tmp_path, [(multipart("aaa111"), _resp("{}"))])
    assert _session(tmp_path, "replay").replay(multipart("bbb222")) is not None


def test_replay_without_cassette_fails_clearly(tmp_path):
    with pytest.raises(FileNotFoundError, match="Record it first"):
        _session(tmp_path, "replay")


# -- real mitmproxy round trip ----------------------------------------------------------------------------------

import importlib.util

HAS_MITMPROXY = importlib.util.find_spec("mitmproxy") is not None  # optional extra, Python 3.12+


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class _Upstream(BaseHTTPRequestHandler):
    hits = 0

    def log_message(self, format, *args):
        return

    def do_GET(self):
        type(self).hits += 1
        body = json.dumps({"path": self.path, "token": SECRET}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _Proxy:
    """mitmproxy with the VCR addon, running in a background thread."""

    def __init__(self, mode: str, config: ProxyConfig, confdir: Path):
        self.master: Any = None
        self.loop: Any = None
        self.port, self.control = _free_port(), _free_port()
        self._ready = threading.Event()
        self._thread = threading.Thread(target=self._run, args=(mode, config, confdir), daemon=True)
        self._thread.start()
        deadline = time.time() + 20
        while time.time() < deadline:
            try:
                self.control_call("GET", "/health")
                return
            except OSError:
                time.sleep(0.1)
        raise RuntimeError("proxy did not start")

    def _run(self, mode, config, confdir):
        from mitmproxy.options import Options
        from mitmproxy.tools.dump import DumpMaster

        from keboola.vcr.proxy.addon import VcrProxyAddon

        async def main():
            opts = Options(listen_host="127.0.0.1", listen_port=self.port, confdir=str(confdir))
            self.master = DumpMaster(opts, with_termlog=False, with_dumper=False)
            self.master.addons.add(VcrProxyAddon(mode, config, control_port=self.control, control_host="127.0.0.1"))
            if mode == "replay":
                self.master.options.update(upstream_cert=False, connection_strategy="lazy")
            self.loop = asyncio.get_running_loop()
            await self.master.run()

        asyncio.run(main())

    def control_call(self, method: str, path: str, payload: dict | None = None) -> dict:
        data = json.dumps(payload or {}).encode() if method == "POST" else None
        req = urllib.request.Request(f"http://127.0.0.1:{self.control}{path}", data=data, method=method)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(req, timeout=5) as r:
            return json.loads(r.read())

    def get(self, url: str) -> tuple[int, bytes]:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{self.port}"}))
        try:
            with opener.open(url, timeout=10) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def stop(self):
        self.loop.call_soon_threadsafe(self.master.shutdown)
        self._thread.join(timeout=10)


@pytest.mark.skipif(not HAS_MITMPROXY, reason="needs the proxy extra (mitmproxy, Python 3.12+)")
def test_mitmproxy_record_then_offline_replay(tmp_path, monkeypatch):
    monkeypatch.setenv("TEST_REFRESH_TOKEN", SECRET)
    config = ProxyConfig.from_dict({"secret_env": ["TEST_REFRESH_TOKEN"]})
    cassette = tmp_path / "case" / "source" / "data" / "cassettes" / "requests.json"

    upstream = ThreadingHTTPServer(("127.0.0.1", 0), _Upstream)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{upstream.server_address[1]}/items?page=1"

    recorder = _Proxy("record", config, tmp_path / "ca")
    try:
        assert recorder.get(url)[0] == 200  # outside a case: passes through, not recorded
        assert recorder.control_call("POST", "/start", {"cassette": str(cassette)})["mode"] == "record"
        status, body = recorder.get(url)
        assert status == 200
        assert json.loads(body)["token"] == SECRET  # the component sees the live answer while recording
        result = recorder.control_call("POST", "/stop")
        assert result["recorded"] == 1, result
    finally:
        recorder.stop()
    upstream.shutdown()
    upstream.server_close()
    hits_after_record = _Upstream.hits
    assert SECRET not in cassette.read_text()

    replayer = _Proxy("replay", ProxyConfig.from_dict({}), tmp_path / "ca")
    try:
        replayer.control_call("POST", "/start", {"cassette": str(cassette)})
        status, body = replayer.get(url)
        assert status == 200
        assert json.loads(body) == {"path": "/items?page=1", "token": "REDACTED"}
        status, body = replayer.get(url.replace("page=1", "page=2"))
        assert status == 418
        assert b"no recorded interaction matches" in body
        assert len(replayer.control_call("GET", "/status")["unmatched"]) == 1
        result = replayer.control_call("POST", "/stop")
        assert len(result["unmatched"]) == 1
        assert result["unused"] == 0
    finally:
        replayer.stop()
    assert _Upstream.hits == hits_after_record  # replay never reached the (stopped) upstream


def test_secret_values_include_url_encoded_forms():
    cfg = ProxyConfig.from_dict({"secret_env": ["T"]})
    assert cfg.secret_values({"T": "a/b+c=="}) == ["a/b+c==", "a%2Fb%2Bc%3D%3D"]


def test_url_encoded_secret_is_redacted(tmp_path):
    raw = "0.AXs/abc+def=="
    cfg = ProxyConfig.from_dict({"secret_env": ["T"]})
    secrets = cfg.secret_values({"T": raw})
    s = _session(tmp_path, "record", secrets=secrets)
    s.record(Request("GET", "https://api.example.com/x?opaque=0.AXs%2Fabc%2Bdef%3D%3D", b"", {}), _resp("{}"))
    s.write("test")
    assert "abc%2Bdef" not in s.path.read_text()


def test_placeholder_sent_back_fails_the_recording(tmp_path):
    cfg = ProxyConfig.from_dict(
        {"sanitizers": [{"class": "BodyFieldSanitizer", "fields": ["cursor"], "scrub_before_read": True}]}
    )
    s = _session(tmp_path, "record", config=cfg)
    s.check_no_placeholder_sent(Request("GET", "https://api.example.com/items?cursor=REDACTED", b"", {}))
    s.record(Request("GET", "https://api.example.com/items?cursor=REDACTED", b"", {}), _resp("{}"))
    with pytest.raises(RecordingError, match="round-tripped"):
        s.write("test")
    assert not s.path.exists()
