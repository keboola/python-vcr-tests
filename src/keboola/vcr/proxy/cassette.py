"""Record and replay one cassette in the keboola.vcr format, independent of mitmproxy.

The format is the one ``VCRRecorder`` writes (``{"_metadata", "interactions", "version": 1}``), so the cassette
validator, ``tools/component cassettes`` and a later Python port can read proxy recordings unchanged.
"""

from __future__ import annotations

import base64
import copy
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from vcr.request import Request

from ..sanitizers import BaseSanitizer, CompositeSanitizer
from .config import MatchOptions

RECORDER_NAME = "keboola.vcr.proxy"

# Hop-by-hop and framing headers: mitmproxy recomputes them for the replayed body (which sanitizers may have
# changed), so a stale recorded value must never reach the client.
_FRAMING_HEADERS = {"content-length", "transfer-encoding", "content-encoding", "connection"}


class RecordingError(RuntimeError):
    """The recording of a case is not trustworthy; the cassette is not written."""


class SecretLeakError(RecordingError):
    """A declared secret value is still present in the sanitized cassette."""


def body_to_text(body: bytes | str | None) -> tuple[str | None, bool]:
    """Return (text, is_base64). UTF-8 bodies stay readable; binary bodies are base64-encoded."""
    if body is None or body == b"" or body == "":
        return (None if body is None else ""), False
    if isinstance(body, str):
        return body, False
    try:
        return body.decode("utf-8"), False
    except UnicodeDecodeError:
        return base64.b64encode(body).decode("ascii"), True


def _is_binary(body: bytes | str | None) -> bool:
    if not isinstance(body, bytes) or not body:
        return False
    try:
        body.decode("utf-8")
    except UnicodeDecodeError:
        return True
    return False


def text_to_body(text: str | None, is_base64: bool) -> bytes:
    if not text:
        return b""
    return base64.b64decode(text) if is_base64 else text.encode("utf-8")


def _header_lists(headers: dict[str, Any]) -> dict[str, list[str]]:
    return {k: ([str(x) for x in v] if isinstance(v, list) else [str(v)]) for k, v in headers.items()}


def _first_header(headers: dict[str, Any], name: str) -> str:
    for k, v in headers.items():
        if k.lower() == name:
            return v[0] if isinstance(v, list) and v else str(v)
    return ""


@dataclass
class Interaction:
    """One request/response pair as the cassette stores it (sanitized)."""

    request: dict[str, Any]
    response: dict[str, Any]
    played: bool = False

    def to_json(self) -> dict[str, Any]:
        return {"request": self.request, "response": self.response}


class RequestKey:
    """The parts of a request that decide a match."""

    def __init__(self, method: str, uri: str, body: str | None, content_type: str):
        parts = urlsplit(uri)
        self.method = method.upper()
        self.scheme = parts.scheme.lower()
        self.host = (parts.hostname or "").lower()
        self.port = parts.port or (443 if self.scheme == "https" else 80)
        self.path = parts.path or "/"
        self.query = sorted(parse_qsl(parts.query, keep_blank_values=True))
        self.body = body
        self.content_type = content_type.lower()

    def describe(self) -> str:
        query = "&".join(f"{k}={v}" for k, v in self.query)
        return f"{self.method} {self.scheme}://{self.host}{self.path}{'?' + query if query else ''}"

    def same_target(self, other: RequestKey) -> bool:
        return (self.method, self.scheme, self.host, self.port, self.path, self.query) == (
            other.method,
            other.scheme,
            other.host,
            other.port,
            other.path,
            other.query,
        )


def _drop_fields(data: Any, names: set[str]) -> Any:
    if isinstance(data, dict):
        return {k: _drop_fields(v, names) for k, v in data.items() if k not in names}
    if isinstance(data, list):
        return [_drop_fields(v, names) for v in data]
    return data


_BOUNDARY_RE = re.compile(r"boundary=\"?([^\";]+)\"?", re.IGNORECASE)


def normalized_body(key: RequestKey, ignore_fields: list[str]) -> Any:
    """A comparable form of the body: parsed JSON, sorted form pairs, or the text with multipart boundaries masked."""
    body = key.body or ""
    if not body:
        return ""
    if "json" in key.content_type or body[:1] in "{[":
        try:
            return ("json", _drop_fields(json.loads(body), set(ignore_fields)))
        except ValueError:
            pass
    if "x-www-form-urlencoded" in key.content_type:
        pairs = parse_qsl(body, keep_blank_values=True)
        return ("form", sorted((k, v) for k, v in pairs if k not in ignore_fields))
    m = _BOUNDARY_RE.search(key.content_type)
    if m:
        return ("text", body.replace(m.group(1), "BOUNDARY"))
    return ("text", body)


def request_key(req: Request) -> RequestKey:
    text, _ = body_to_text(req.body)
    return RequestKey(req.method, req.uri, text, _first_header(dict(req.headers), "content-type"))


@dataclass
class CassetteSession:
    """The active cassette of one datadir test case."""

    path: Path
    mode: str  # "record" | "replay"
    sanitizers: list[BaseSanitizer]
    match: MatchOptions
    secret_values: list[str] = field(default_factory=list)
    interactions: list[Interaction] = field(default_factory=list)
    unmatched: list[str] = field(default_factory=list)
    # Problems found while recording; /stop reports them and the PHP hook fails the case.
    errors: list[str] = field(default_factory=list)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        self._chain = CompositeSanitizer(self.sanitizers)
        self._pre_read = CompositeSanitizer([s for s in self.sanitizers if getattr(s, "scrub_before_read", False)])
        self._has_pre_read = bool(self._pre_read.sanitizers)
        self._pre_read_placeholders = {
            p for p in (getattr(x, "replacement", "") for x in self._pre_read.sanitizers) if isinstance(p, str) and p
        }
        if self.mode == "replay":
            self._load()

    # -- replay ---------------------------------------------------------------------------------------------

    def _load(self) -> None:
        if not self.path.exists():
            raise FileNotFoundError(
                f"No cassette at {self.path}. Record it first (VCR_MODE=record) or remove the case."
            )
        data = json.loads(self.path.read_text())
        self.interactions = [Interaction(i["request"], i["response"]) for i in data.get("interactions", [])]

    def _sanitized_key(self, req: Request) -> RequestKey:
        """Run the request sanitizers on a copy so the incoming request looks like the recorded (sanitized) one."""
        clean = self._chain.before_record_request(copy.deepcopy(req))
        return request_key(clean)

    @staticmethod
    def _recorded_key(interaction: Interaction) -> RequestKey:
        req = interaction.request
        body = req.get("body")
        return RequestKey(
            req["method"],
            req["uri"],
            body if isinstance(body, str) or body is None else str(body),
            _first_header(req.get("headers", {}), "content-type"),
        )

    def _bodies_match(self, incoming: RequestKey, recorded: RequestKey) -> bool:
        if not self.match.body or self.match.body_ignored_for(incoming.host, incoming.path):
            return True
        fields = self.match.ignore_body_fields
        return normalized_body(incoming, fields) == normalized_body(recorded, fields)

    def replay(self, req: Request) -> dict[str, Any] | None:
        """Return the recorded response for ``req``, or None (and remember the miss)."""
        incoming = self._sanitized_key(req)
        candidates = [
            i
            for i in self.interactions
            if incoming.same_target(rk := self._recorded_key(i)) and self._bodies_match(incoming, rk)
        ]
        chosen = next((i for i in candidates if not i.played), None)
        if chosen is None and candidates and self.match.allow_playback_repeats:
            chosen = candidates[-1]
        if chosen is None:
            reason = "all matching interactions already played" if candidates else "no recorded interaction matches"
            self.unmatched.append(f"{incoming.describe()} ({reason})")
            return None
        chosen.played = True
        return chosen.response

    # -- record ---------------------------------------------------------------------------------------------

    def scrub_for_client(self, response: dict[str, Any]) -> dict[str, Any] | None:
        """Apply scrub_before_read sanitizers to the live response before the component reads it."""
        if not self._has_pre_read:
            return None
        return self._pre_read.before_record_response(copy.deepcopy(response))

    def check_no_placeholder_sent(self, req: Request) -> None:
        """Remember an error when the client sends a scrub_before_read placeholder back to the live API.

        Same rule as VCRRecorder: a tagged field that the component round-trips (a cursor, an id, a token) breaks the
        live follow-up request, so the recording would be wrong.
        """
        if not self._pre_read_placeholders:
            return
        text, _ = body_to_text(req.body)
        haystack = f"{req.uri}\n{text or ''}"
        for placeholder in self._pre_read_placeholders:
            esc = re.escape(placeholder)
            if re.search(rf"=\s*{esc}(?=[&\s\"']|$)", haystack) or re.search(rf'"{esc}"', haystack):
                self.errors.append(
                    f"a scrub_before_read sanitizer redacted a value that the client sent back to the API "
                    f"({request_key(req).describe()}); untag the round-tripped field in vcr.json"
                )
                return

    def record(self, req: Request, response: dict[str, Any]) -> None:
        # Sanitizers work on text and would corrupt binary bodies (file downloads, uploads), so a binary body
        # bypasses them and is stored base64-encoded as it is. The leak check in write() still covers the text.
        req = copy.deepcopy(req)
        req_binary = _is_binary(req.body)
        raw_req_body = req.body
        if req_binary:
            req.body = b""
        clean_req = self._chain.before_record_request(req)
        if clean_req is None:
            return
        if req_binary:
            clean_req.body = raw_req_body
        response = copy.deepcopy(response)
        raw_resp_body = response.get("body", {}).get("string")
        resp_binary = _is_binary(raw_resp_body)
        if resp_binary:
            response["body"]["string"] = b""
        clean_resp = self._chain.before_record_response(response)
        if clean_resp is None:
            return
        if resp_binary:
            clean_resp.setdefault("body", {})["string"] = raw_resp_body
        req_dict = clean_req._to_dict()
        req_text, req_b64 = body_to_text(req_dict.get("body"))
        req_dict["body"] = req_text
        if req_b64:
            req_dict["body_encoding"] = "base64"
        body = clean_resp.get("body", {})
        resp_text, resp_b64 = body_to_text(body.get("string"))
        clean_resp["body"] = {"string": resp_text or ""}
        if resp_b64:
            clean_resp["body"]["encoding"] = "base64"
        clean_resp["headers"] = _header_lists(clean_resp.get("headers", {}))
        self.interactions.append(Interaction(req_dict, clean_resp))

    def serialize(self, version: str) -> str:
        metadata = {
            "recorded_at": self.started_at.isoformat(),
            "freeze_time": None,
            "keboola_vcr_version": version,
            "recorder": RECORDER_NAME,
            "request_pairs": len(self.interactions),
        }
        doc = {"_metadata": metadata, "interactions": [i.to_json() for i in self.interactions], "version": 1}
        return json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n"

    def write(self, version: str) -> int:
        """Write the cassette. Refuses (SecretLeakError) if a declared secret value survived sanitizing."""
        if self.errors:
            raise RecordingError(f"Refusing to write {self.path}: " + "; ".join(self.errors))
        text = self.serialize(version)
        leaked = [i for i, value in enumerate(self.secret_values) if value and value in text]
        if leaked:
            # Name the env var position only: never the value.
            raise SecretLeakError(
                f"Refusing to write {self.path}: {len(leaked)} declared secret value(s) are still in the cassette "
                f"after sanitizing. Add a sanitizer for them in vcr.json."
            )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(text)
        return len(self.interactions)

    def unused_count(self) -> int:
        return sum(1 for i in self.interactions if not i.played)


def response_parts(response: dict[str, Any]) -> tuple[int, str, list[tuple[bytes, bytes]], bytes]:
    """Split a cassette response into (status, reason, headers, body) for mitmproxy."""
    status = response.get("status", {})
    body = response.get("body", {})
    content = text_to_body(body.get("string"), body.get("encoding") == "base64")
    headers = [
        (k.encode("latin-1"), v.encode("latin-1"))
        for k, values in _header_lists(response.get("headers", {})).items()
        if k.lower() not in _FRAMING_HEADERS
        for v in values
    ]
    return int(status.get("code", 200)), str(status.get("message", "")), headers, content
