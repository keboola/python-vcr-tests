"""mitmproxy addon: record live HTTPS traffic into keboola.vcr cassettes, or replay it offline.

The test harness switches the active cassette through a small control server (plain HTTP, its own port):

- ``POST /start`` with ``{"cassette": "<absolute path to requests.json>"}`` starts a case.
- ``GET /status`` reports the active case so far (unmatched requests, recording errors) without ending it.
- ``POST /stop`` ends it. Record mode writes the cassette. The answer lists unmatched requests (replay).
- ``GET /health`` answers ``ok`` once the proxy runs (for a compose healthcheck).

The mode (``record`` or ``replay``) is fixed for the whole proxy run.
"""

from __future__ import annotations

import json
import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from mitmproxy import http

from vcr.request import Request

from .cassette import CassetteSession, RecordingError, response_parts
from .config import ProxyConfig

logger = logging.getLogger("keboola.vcr.proxy")

MODES = ("record", "replay")


def _version() -> str:
    try:
        from importlib.metadata import version

        return version("keboola.vcr")
    except Exception:  # noqa: BLE001  # metadata missing in a source checkout; the version is informational only
        return "unknown"


def flow_to_request(flow: http.HTTPFlow) -> Request:
    req = flow.request
    headers: dict[str, str] = {}
    for k, v in req.headers.items(multi=True):
        headers[k] = v
    return Request(req.method, req.pretty_url, req.get_content(strict=False) or b"", headers)


def flow_to_response(flow: http.HTTPFlow) -> dict[str, Any]:
    resp = flow.response
    assert resp is not None
    headers: dict[str, list[str]] = {}
    for k, v in resp.headers.items(multi=True):
        if k.lower() == "content-encoding":
            continue  # the body below is already decoded
        headers.setdefault(k, []).append(v)
    return {
        "status": {"code": resp.status_code, "message": resp.reason},
        "headers": headers,
        "body": {"string": resp.get_content(strict=False) or b""},
    }


class VcrProxyAddon:
    def __init__(self, mode: str, config: ProxyConfig, control_port: int = 8081, control_host: str = "0.0.0.0"):
        if mode not in MODES:
            raise ValueError(f"mode must be one of {MODES}, got {mode!r}")
        self.mode = mode
        self.config = config
        self.control_port = control_port
        self.control_host = control_host
        self._lock = threading.Lock()
        self._session: CassetteSession | None = None
        self._server: ThreadingHTTPServer | None = None
        # Secret values are read once, used only for redaction and the leak check, and never logged.
        self._secret_values = config.secret_values() if mode == "record" else []

    # -- control API (called from the control server thread) -----------------------------------------------

    def start_case(self, cassette: str) -> dict[str, Any]:
        path = Path(cassette)
        if not path.is_absolute():
            raise ValueError(f"cassette path must be absolute, got {cassette!r}")
        session = CassetteSession(
            path=path,
            mode=self.mode,
            sanitizers=self.config.build_sanitizers(self._secret_values),
            match=self.config.match,
            secret_values=self._secret_values,
        )
        with self._lock:
            self._session = session
        return {"mode": self.mode, "cassette": str(path), "interactions": len(session.interactions)}

    def status(self) -> dict[str, Any]:
        """The active case so far, without ending it (a test may run the component more than once per case)."""
        with self._lock:
            session = self._session
            if session is None:
                return {"mode": self.mode, "active": False, "unmatched": [], "errors": []}
            return {
                "mode": self.mode,
                "active": True,
                "cassette": str(session.path),
                "unmatched": list(session.unmatched),
                "errors": list(session.errors),
            }

    def stop_case(self) -> dict[str, Any]:
        with self._lock:
            session, self._session = self._session, None
        if session is None:
            return {"mode": self.mode, "error": "no active cassette"}
        result: dict[str, Any] = {"mode": self.mode, "cassette": str(session.path), "unmatched": session.unmatched}
        if self.mode == "record":
            try:
                result["recorded"] = session.write(_version())
            except RecordingError as e:
                result["error"] = str(e)
        else:
            result["unused"] = session.unused_count()
        return result

    # -- mitmproxy hooks ------------------------------------------------------------------------------------

    def running(self) -> None:
        self._start_control_server()

    def done(self) -> None:
        if self._server is not None:
            self._server.shutdown()

    def request(self, flow: http.HTTPFlow) -> None:
        if self.mode != "replay":
            return
        with self._lock:
            session = self._session
            recorded = session.replay(flow_to_request(flow)) if session is not None else None
        if recorded is None:
            what = "no active cassette" if session is None else "no recorded interaction matches"
            message = (
                f"keboola.vcr.proxy replay: {what} for {flow.request.method} "
                f"{flow.request.pretty_host}{flow.request.path.split('?')[0]}. Re-record the case or fix the "
                f"matching rules in vcr.json.\n"
            )
            if session is None:
                logger.warning(message.strip())
            flow.response = http.Response.make(self.config.unmatched_status, message, {"Content-Type": "text/plain"})
            return
        status, reason, headers, content = response_parts(recorded)
        response = http.Response.make(status, content, http.Headers(headers))
        response.reason = reason
        flow.response = response

    def response(self, flow: http.HTTPFlow) -> None:
        if self.mode != "record" or flow.response is None:
            return
        with self._lock:
            session = self._session
        if session is None:
            return  # traffic outside a test case (fixture set-up) passes through unrecorded
        try:
            request = flow_to_request(flow)
            session.check_no_placeholder_sent(request)
            live = flow_to_response(flow)
            scrubbed = session.scrub_for_client(live)
            if scrubbed is not None:
                content = response_parts(scrubbed)[3]
                flow.response.headers.pop("content-encoding", None)
                flow.response.content = content
                live = scrubbed
            with self._lock:
                if self._session is session:
                    session.record(request, live)
        except Exception as e:  # noqa: BLE001  # a lost interaction must fail the case at /stop, not vanish in a log
            session.errors.append(f"recording {flow.request.method} {flow.request.pretty_host} failed: {e!r}")

    # -- control server -------------------------------------------------------------------------------------

    def _start_control_server(self) -> None:
        addon = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:  # silence default stderr access log
                return

            def _reply(self, code: int, payload: Any) -> None:
                body = json.dumps(payload).encode() if not isinstance(payload, bytes) else payload
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:  # http.server naming
                if self.path == "/health":
                    self._reply(200, {"status": "ok", "mode": addon.mode})
                elif self.path == "/status":
                    self._reply(200, addon.status())
                else:
                    self._reply(404, {"error": "unknown endpoint"})

            def do_POST(self) -> None:  # http.server naming
                length = int(self.headers.get("Content-Length") or 0)
                try:
                    payload = json.loads(self.rfile.read(length) or b"{}")
                    if self.path == "/start":
                        self._reply(200, addon.start_case(str(payload["cassette"])))
                    elif self.path == "/stop":
                        self._reply(200, addon.stop_case())
                    else:
                        self._reply(404, {"error": "unknown endpoint"})
                except (KeyError, ValueError, FileNotFoundError) as e:
                    self._reply(400, {"error": str(e)})

        self._server = ThreadingHTTPServer((self.control_host, self.control_port), Handler)
        threading.Thread(target=self._server.serve_forever, name="vcr-control", daemon=True).start()
        logger.info("keboola.vcr.proxy: mode=%s, control on :%s", self.mode, self.control_port)
