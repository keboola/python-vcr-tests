"""Tests for keboola.vcr.proxy: config loading, cassette record/replay logic, and a real mitmproxy round trip."""

from __future__ import annotations

import asyncio
import base64
import gzip
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
from keboola.vcr.proxy.cassette import bodyless_content_length, response_parts
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
    scrubbed = s.scrub_for_client(_resp(json.dumps({"email": "a@b.c", "id": 1})), "https://api.example.com/u")
    assert scrubbed is not None
    assert "a@b.c" not in str(scrubbed["body"]["string"])
    assert _session(tmp_path, "record").scrub_for_client(_resp("{}"), "https://api.example.com/u") is None


# -- replay ---------------------------------------------------------------------------------------------------


def _recorded(tmp_path: Path, pairs: list[tuple[Request, dict]], config: ProxyConfig | None = None) -> None:
    s = _session(tmp_path, "record", config=config, secrets=[SECRET])
    for req, resp in pairs:
        s.record(req, resp)
    s.write("test")


def test_replay_matches_on_sorted_query_and_ignore_recorded_header_names(tmp_path):
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


QUERY_PLAN = "x-ms-cosmos-is-query-plan-request"
MATCH_PLAN_HEADER = {
    "match": {"headers": ["X-MS-Cosmos-Is-Query-Plan-Request"]},
    "sanitizers": [{"class": "DefaultSanitizer", "additional_safe_headers": [QUERY_PLAN]}],
}


def _query(plan: bool) -> Request:
    headers = {"Content-Type": "application/query+json", "Authorization": "signed-per-request"}
    if plan:
        headers["x-ms-cosmos-is-query-plan-request"] = "True"
    return Request(
        "POST", "https://acc.documents.azure.com/dbs/d/colls/c/docs", b'{"query": "SELECT * FROM c"}', headers
    )


def test_config_match_headers_are_lower_cased_and_validated():
    assert ProxyConfig.from_dict(MATCH_PLAN_HEADER).match.headers == [QUERY_PLAN]
    assert ProxyConfig.from_dict({}).match.headers == []
    with pytest.raises(ProxyConfigError, match="match.headers"):
        ProxyConfig.from_dict({"match": {"headers": "x-a"}})
    with pytest.raises(ProxyConfigError, match="match.headers"):
        ProxyConfig.from_dict({"match": {"headers": [""]}})


def test_replay_match_headers_tell_concurrent_identical_requests_apart(tmp_path):
    # A client sends both at the same time; the recording keeps them in the order the answers came back, and replay
    # sees them in the order they arrive, which can be the other way round.
    cfg = ProxyConfig.from_dict(MATCH_PLAN_HEADER)
    _recorded(
        tmp_path,
        [(_query(plan=False), _resp('{"Documents": [1]}')), (_query(plan=True), _resp('{"plan": 1}'))],
        config=cfg,
    )
    assert QUERY_PLAN in _recorded_header_names(tmp_path, 1)
    assert QUERY_PLAN not in _recorded_header_names(tmp_path, 0)
    s = _session(tmp_path, "replay", config=cfg)
    assert json.loads(response_parts(s.replay(_query(plan=True)))[3]) == {"plan": 1}
    assert json.loads(response_parts(s.replay(_query(plan=False)))[3]) == {"Documents": [1]}
    assert s.unused_count() == 0
    assert s.replay(_query(plan=True)) is None
    assert f"[{QUERY_PLAN}: True]" in s.unmatched[0]
    assert "already played" in s.unmatched[0]


def test_replay_without_match_headers_still_ignore_recorded_header_names(tmp_path):
    # The default is unchanged: equal requests replay in recorded order, whatever their headers.
    cfg = ProxyConfig.from_dict({"sanitizers": MATCH_PLAN_HEADER["sanitizers"]})
    _recorded(
        tmp_path,
        [(_query(plan=False), _resp('{"Documents": [1]}')), (_query(plan=True), _resp('{"plan": 1}'))],
        config=cfg,
    )
    s = _session(tmp_path, "replay", config=cfg)
    assert json.loads(response_parts(s.replay(_query(plan=True)))[3]) == {"Documents": [1]}


def test_replay_match_header_missing_on_both_sides_matches(tmp_path):
    cfg = ProxyConfig.from_dict(MATCH_PLAN_HEADER)
    _recorded(tmp_path, [(_query(plan=False), _resp('{"Documents": []}'))], config=cfg)
    s = _session(tmp_path, "replay", config=cfg)
    assert s.replay(_query(plan=True)) is None
    assert "no recorded interaction matches" in s.unmatched[0]
    assert s.replay(_query(plan=False)) is not None


def test_record_fails_when_a_sanitizer_drops_a_match_header(tmp_path):
    cfg = ProxyConfig.from_dict({"match": MATCH_PLAN_HEADER["match"]})
    s = _session(tmp_path, "record", config=cfg)
    s.record(_query(plan=False), _resp("{}"))
    assert not s.errors  # the header was not sent, so nothing was lost
    s.record(_query(plan=True), _resp("{}"))
    with pytest.raises(RecordingError, match="additional_safe_headers"):
        s.write("test")
    assert not s.path.exists()


def _recorded_header_names(tmp_path: Path, index: int) -> list[str]:
    data = json.loads((tmp_path / "cassettes" / "requests.json").read_text())
    return [k.lower() for k in data["interactions"][index]["request"]["headers"]]


def test_replay_masks_multipart_boundaries(tmp_path):
    url = "https://api.example.com/upload"

    def multipart(boundary: str) -> Request:
        body = f'--{boundary}\r\nContent-Disposition: form-data; name="f"\r\n\r\nhello\r\n--{boundary}--\r\n'
        return Request("POST", url, body.encode(), {"Content-Type": f"multipart/form-data; boundary={boundary}"})

    _recorded(tmp_path, [(multipart("aaa111"), _resp("{}"))])
    assert _session(tmp_path, "replay").replay(multipart("bbb222")) is not None


def test_replay_masks_mixed_case_multipart_boundaries(tmp_path):
    url = "https://api.example.com/upload"

    def multipart(boundary: str) -> Request:
        body = f"--{boundary}\r\n\r\nhello\r\n--{boundary}--\r\n"
        return Request("POST", url, body.encode(), {"Content-Type": f"multipart/form-data; boundary={boundary}"})

    _recorded(tmp_path, [(multipart("----FormBoundaryAbC"), _resp("{}"))])
    assert _session(tmp_path, "replay").replay(multipart("----FormBoundaryXyZ")) is not None


GZIP_CHUNK = gzip.compress(b"col1,col2\n" + bytes(range(256)) * 8, mtime=0)
UPLOAD_URL = "https://tenant.sharepoint.com/sites/x/_api/v2.0/drive/items/1/uploadSession?guid=abc"
OCTET = {"Content-Type": "application/octet-stream", "Content-Range": "bytes 0-99/100"}


def test_replay_matches_identical_binary_body(tmp_path):
    other = gzip.compress(b"another chunk" + bytes(range(256)), mtime=0)
    _recorded(
        tmp_path,
        [
            (Request("PUT", UPLOAD_URL, GZIP_CHUNK, OCTET), _resp('{"part": 1}')),
            (Request("PUT", UPLOAD_URL, other, OCTET), _resp('{"part": 2}')),
        ],
    )
    recorded = json.loads((tmp_path / "cassettes" / "requests.json").read_text())["interactions"][0]["request"]
    assert recorded["body_encoding"] == "base64"
    assert base64.b64decode(recorded["body"]) == GZIP_CHUNK
    s = _session(tmp_path, "replay")
    assert json.loads(response_parts(s.replay(Request("PUT", UPLOAD_URL, other, OCTET)))[3]) == {"part": 2}
    assert json.loads(response_parts(s.replay(Request("PUT", UPLOAD_URL, GZIP_CHUNK, OCTET)))[3]) == {"part": 1}
    assert s.unmatched == []


def test_replay_rejects_different_binary_body(tmp_path):
    _recorded(tmp_path, [(Request("PUT", UPLOAD_URL, GZIP_CHUNK, OCTET), _resp("{}"))])
    s = _session(tmp_path, "replay")
    changed = GZIP_CHUNK[:-1] + bytes([GZIP_CHUNK[-1] ^ 0xFF])
    assert s.replay(Request("PUT", UPLOAD_URL, changed, OCTET)) is None
    # a text body that spells the recorded base64 is still not the recorded bytes
    as_text = base64.b64encode(GZIP_CHUNK)
    assert s.replay(Request("PUT", UPLOAD_URL, as_text, {"Content-Type": "text/plain"})) is None
    assert len(s.unmatched) == 2


def test_replay_binary_body_still_sanitizes_the_url(tmp_path):
    url = f"{UPLOAD_URL}&access_token={SECRET}"
    _recorded(tmp_path, [(Request("PUT", url, GZIP_CHUNK, OCTET), _resp("{}"))])
    assert SECRET not in (tmp_path / "cassettes" / "requests.json").read_text()
    replayed = Request("PUT", f"{UPLOAD_URL}&access_token=dummy", GZIP_CHUNK, OCTET)
    assert _session(tmp_path, "replay").replay(replayed) is not None


def test_replay_masks_boundaries_in_binary_multipart(tmp_path):
    url = "https://api.example.com/upload"

    def multipart(boundary: str) -> Request:
        body = f"--{boundary}\r\nContent-Type: application/gzip\r\n\r\n".encode() + GZIP_CHUNK
        body += f"\r\n--{boundary}--\r\n".encode()
        return Request("POST", url, body, {"Content-Type": f"multipart/form-data; boundary={boundary}"})

    _recorded(tmp_path, [(multipart("aaa111"), _resp("{}"))])
    assert _session(tmp_path, "replay").replay(multipart("bbb222")) is not None


def test_replay_reads_existing_text_and_base64_cassettes(tmp_path):
    """Cassettes written before the fix (text and base64 request bodies) replay unchanged."""
    path = tmp_path / "cassettes" / "requests.json"
    path.parent.mkdir(parents=True)
    ok = {"status": {"code": 200, "message": "OK"}, "headers": {}, "body": {"string": "{}"}}
    path.write_text(
        json.dumps(
            {
                "_metadata": {"recorder": "keboola.vcr.proxy"},
                "version": 1,
                "interactions": [
                    {
                        "request": {
                            "method": "PUT",
                            "uri": UPLOAD_URL,
                            "body": base64.b64encode(GZIP_CHUNK).decode(),
                            "body_encoding": "base64",
                            "headers": {"Content-Type": ["application/octet-stream"]},
                        },
                        "response": ok,
                    },
                    {
                        "request": {
                            "method": "POST",
                            "uri": "https://api.example.com/q",
                            "body": '{"q": 1}',
                            "headers": {"Content-Type": ["application/json"]},
                        },
                        "response": ok,
                    },
                ],
            }
        )
    )
    s = _session(tmp_path, "replay")
    assert s.replay(Request("PUT", UPLOAD_URL, GZIP_CHUNK, OCTET)) is not None
    assert s.replay(Request("POST", "https://api.example.com/q", b'{"q":1}', {"Content-Type": "application/json"}))
    assert s.unused_count() == 0


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

    def do_HEAD(self):
        type(self).hits += 1
        self.send_response(200)
        self.send_header("Content-Type", "text/csv")
        self.send_header("Content-Length", "97")
        self.end_headers()

    def do_GET(self):
        type(self).hits += 1
        body = json.dumps({"path": self.path, "token": SECRET}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        type(self).hits += 1
        self.rfile.read(int(self.headers["Content-Length"]))
        plan = self.headers.get("x-ms-cosmos-is-query-plan-request") == "True"
        if not plan:
            time.sleep(0.3)  # the plain query answers last, so it is recorded after the plan request
        body = json.dumps({"kind": "plan" if plan else "docs"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_PUT(self):
        type(self).hits += 1
        size = len(self.rfile.read(int(self.headers["Content-Length"])))
        body = json.dumps({"received": size}).encode()
        self.send_response(202)
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

    def put(self, url: str, body: bytes) -> tuple[int, bytes]:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{self.port}"}))
        req = urllib.request.Request(url, data=body, method="PUT", headers=OCTET)
        try:
            with opener.open(req, timeout=10) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def post(self, url: str, body: bytes, headers: dict[str, str]) -> tuple[int, bytes]:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{self.port}"}))
        req = urllib.request.Request(url, data=body, method="POST", headers=headers)
        try:
            with opener.open(req, timeout=10) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def head_length(self, url: str) -> str | None:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{self.port}"}))
        with opener.open(urllib.request.Request(url, method="HEAD"), timeout=10) as r:
            return r.headers.get("Content-Length")

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
        assert recorder.head_length(url.replace("/items", "/file.csv")) == "97"
        assert recorder.put(url.replace("/items", "/uploadSession"), GZIP_CHUNK)[0] == 202
        result = recorder.control_call("POST", "/stop")
        assert result["recorded"] == 3, result
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
        assert replayer.head_length(url.replace("/items", "/file.csv")) == "97"  # not 0: HEAD has no body
        upload = url.replace("/items", "/uploadSession")
        assert replayer.put(upload, GZIP_CHUNK) == (202, json.dumps({"received": len(GZIP_CHUNK)}).encode())
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


@pytest.mark.skipif(not HAS_MITMPROXY, reason="needs the proxy extra (mitmproxy, Python 3.12+)")
def test_mitmproxy_concurrent_requests_that_differ_only_in_a_match_header(tmp_path):
    config = ProxyConfig.from_dict(MATCH_PLAN_HEADER)
    cassette = tmp_path / "case" / "cassettes" / "requests.json"
    upstream = ThreadingHTTPServer(("127.0.0.1", 0), _Upstream)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{upstream.server_address[1]}/dbs/d/colls/c/docs"
    body = b'{"query": "SELECT * FROM c"}'
    plain = {"Content-Type": "application/query+json"}
    plan = {**plain, "x-ms-cosmos-is-query-plan-request": "True"}

    def both_at_once(proxy: _Proxy) -> dict[str, Any]:
        results: dict[str, Any] = {}
        threads = [
            threading.Thread(target=lambda: results.__setitem__("plain", proxy.post(url, body, plain))),
            threading.Thread(target=lambda: results.__setitem__("plan", proxy.post(url, body, plan))),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15)
        return results

    recorder = _Proxy("record", config, tmp_path / "ca")
    try:
        recorder.control_call("POST", "/start", {"cassette": str(cassette)})
        recorded = both_at_once(recorder)
        assert recorder.control_call("POST", "/stop")["recorded"] == 2
    finally:
        recorder.stop()
    upstream.shutdown()
    upstream.server_close()
    assert json.loads(recorded["plan"][1]) == {"kind": "plan"}
    # the slower plain query was recorded second, after the plan request
    order = [i["response"]["body"]["string"] for i in json.loads(cassette.read_text())["interactions"]]
    assert [json.loads(o)["kind"] for o in order] == ["plan", "docs"]

    replayer = _Proxy("replay", config, tmp_path / "ca")
    try:
        for _ in range(5):
            replayer.control_call("POST", "/start", {"cassette": str(cassette)})
            got = both_at_once(replayer)
            assert got["plain"] == (200, json.dumps({"kind": "docs"}).encode())
            assert got["plan"] == (200, json.dumps({"kind": "plan"}).encode())
            result = replayer.control_call("POST", "/stop")
            assert result["unmatched"] == [] and result["unused"] == 0
    finally:
        replayer.stop()


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


def test_url_scoped_sanitizer_applies_only_to_matching_urls(tmp_path):
    cfg = ProxyConfig.from_dict(
        {
            "sanitizers": [
                {"class": "BodyFieldSanitizer", "fields": ["name"], "urls": ["graph.microsoft.com/v1.0/sites"]}
            ]
        }
    )
    s = _session(tmp_path, "record", config=cfg)
    sites = Request("GET", "https://graph.microsoft.com/v1.0/sites?search=&$select=id,name", b"", {})
    files = Request("GET", "https://graph.microsoft.com/v1.0/me/drive/root/children", b"", {})
    s.record(sites, _resp(json.dumps({"value": [{"id": "s1", "name": "Some Site"}]})))
    s.record(files, _resp(json.dumps({"value": [{"id": "f1", "name": "book.xlsx"}]})))
    s.write("test")
    text = s.path.read_text()
    assert "Some Site" not in text
    assert "book.xlsx" in text


def test_url_scoped_sanitizer_config_errors():
    with pytest.raises(ProxyConfigError):
        ProxyConfig.from_dict({"sanitizers": [{"class": "BodyFieldSanitizer", "fields": ["x"], "urls": []}]})
    with pytest.raises(ProxyConfigError):
        ProxyConfig.from_dict({"sanitizers": [{"class": "DefaultSanitizer", "urls": ["a/b"]}]})


def test_body_pattern_sanitizer_from_config_redacts_xml(tmp_path):
    cfg = ProxyConfig.from_dict(
        {
            "sanitizers": [
                {
                    "class": "BodyPatternSanitizer",
                    "patterns": [["<SessionToken>[^<]*</SessionToken>", "<SessionToken>REDACTED</SessionToken>"]],
                }
            ]
        }
    )
    s = _session(tmp_path, "record", config=cfg)
    sts = "<Credentials><SessionToken>live-session-token</SessionToken></Credentials>"
    s.record(Request("POST", "https://sts.amazonaws.com/", b"Action=AssumeRole", {}), _resp(sts, ctype="text/xml"))
    s.write("test")
    assert "live-session-token" not in s.path.read_text()


def test_bodyless_content_length_kept_for_head_204_304_only():
    recorded = {"status": {"code": 200}, "headers": {"Content-Length": ["97"]}, "body": {"string": ""}}
    assert bodyless_content_length(recorded, "HEAD") == "97"
    assert bodyless_content_length(recorded, "GET") is None
    not_modified = {"status": {"code": 304}, "headers": {"content-length": ["12"]}, "body": {"string": ""}}
    assert bodyless_content_length(not_modified, "GET") == "12"
    assert bodyless_content_length({"status": {"code": 200}, "headers": {}, "body": {}}, "HEAD") is None
