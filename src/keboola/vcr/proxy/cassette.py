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
from .config import MatchOptions, UrlScopedSanitizer

RECORDER_NAME = "keboola.vcr.proxy"

# Hop-by-hop and framing headers: mitmproxy recomputes them for the replayed body (which sanitizers may have
# changed), so a stale recorded value must never reach the client.
_FRAMING_HEADERS = {"content-length", "transfer-encoding", "content-encoding", "connection"}

_BOUNDARY_RE = re.compile(r"boundary=\"?([^\";]+)\"?", re.IGNORECASE)


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


def _match_header_values(headers: Any, names: list[str]) -> tuple[str, ...]:
    """The values of the ``match.headers`` names (lower-case) in order; a missing header is empty."""
    return tuple(_first_header(dict(headers or {}), name) for name in names)


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

    def __init__(self, method: str, uri: str, body: str | None, content_type: str, binary: bool = False):
        parts = urlsplit(uri)
        self.method = method.upper()
        self.scheme = parts.scheme.lower()
        self.host = (parts.hostname or "").lower()
        self.port = parts.port or (443 if self.scheme == "https" else 80)
        self.path = parts.path or "/"
        self.query = sorted(parse_qsl(parts.query, keep_blank_values=True))
        self.body = body
        # A binary body is held base64-encoded, the way the cassette stores it.
        self.binary = binary
        self.content_type = content_type.lower()
        # The multipart boundary is case-sensitive, so it is read from the header as sent.
        boundary = _BOUNDARY_RE.search(content_type)
        self.boundary = boundary.group(1) if boundary else None

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


def normalized_body(key: RequestKey, ignore_fields: list[str]) -> Any:
    """A comparable form of the body: parsed JSON, sorted form pairs, or the text with multipart boundaries masked.

    A binary body compares as its exact bytes (multipart boundary masked), never equal to a text body.
    """
    body = key.body or ""
    if not body:
        return ""
    if key.binary:
        raw = base64.b64decode(body)
        if key.boundary:
            raw = raw.replace(key.boundary.encode("latin-1"), b"BOUNDARY")
        return ("binary", raw)
    if "json" in key.content_type or body[:1] in "{[":
        try:
            return ("json", _drop_fields(json.loads(body), set(ignore_fields)))
        except ValueError:
            pass
    if "x-www-form-urlencoded" in key.content_type:
        pairs = parse_qsl(body, keep_blank_values=True)
        return ("form", sorted((k, v) for k, v in pairs if k not in ignore_fields))
    if key.boundary:
        return ("text", body.replace(key.boundary, "BOUNDARY"))
    return ("text", body)


def request_key(req: Request) -> RequestKey:
    text, is_base64 = body_to_text(req.body)
    return RequestKey(req.method, req.uri, text, _first_header(dict(req.headers), "content-type"), binary=is_base64)


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
        pre_read = [s for s in self.sanitizers if getattr(s, "scrub_before_read", False)]
        self._has_pre_read = bool(pre_read)
        self._pre_read_placeholders = {
            p for p in (getattr(x, "replacement", "") for x in pre_read) if isinstance(p, str) and p
        }
        if self.mode == "replay":
            self._load()

    def _chain(self, uri: str, pre_read_only: bool = False) -> CompositeSanitizer:
        """The sanitizers for one request URL: URL-scoped ones only where they apply."""
        return CompositeSanitizer(
            [
                s
                for s in self.sanitizers
                if (not isinstance(s, UrlScopedSanitizer) or s.applies_to(uri))
                and (not pre_read_only or getattr(s, "scrub_before_read", False))
            ]
        )

    # -- replay ---------------------------------------------------------------------------------------------

    def _load(self) -> None:
        if not self.path.exists():
            raise FileNotFoundError(
                f"No cassette at {self.path}. Record it first (VCR_MODE=record) or remove the case."
            )
        data = json.loads(self.path.read_text())
        self.interactions = [Interaction(i["request"], i["response"]) for i in data.get("interactions", [])]

    def _sanitize_request(self, req: Request) -> Request | None:
        """Run the request sanitizers on a copy of ``req``.

        Sanitizers work on text and would corrupt a binary body (file uploads), so a binary body bypasses them and is
        kept as it is. Recording and replay both go through here, so an incoming request is sanitized exactly like
        the recorded one was.
        """
        req = copy.deepcopy(req)
        raw_body = req.body
        binary = _is_binary(raw_body)
        if binary:
            req.body = b""
        clean = self._chain(req.uri).before_record_request(req)
        if clean is not None and binary:
            clean.body = raw_body
        return clean

    @staticmethod
    def _recorded_key(interaction: Interaction) -> RequestKey:
        req = interaction.request
        body = req.get("body")
        return RequestKey(
            req["method"],
            req["uri"],
            body if isinstance(body, str) or body is None else str(body),
            _first_header(req.get("headers", {}), "content-type"),
            binary=req.get("body_encoding") == "base64",
        )

    def _bodies_match(self, incoming: RequestKey, recorded: RequestKey) -> bool:
        if not self.match.body or self.match.body_ignored_for(incoming.host, incoming.path):
            return True
        fields = self.match.ignore_body_fields
        return normalized_body(incoming, fields) == normalized_body(recorded, fields)

    def replay(self, req: Request) -> dict[str, Any] | None:
        """Return the recorded response for ``req``, or None (and remember the miss)."""
        # Sanitize a copy so the incoming request looks like the recorded (sanitized) one.
        clean = self._sanitize_request(req)
        if clean is None:  # a sanitizer drops this request, so it was never recorded
            self.unmatched.append(f"{request_key(req).describe()} (not recorded: a sanitizer drops it)")
            return None
        incoming = request_key(clean)
        names = self.match.headers
        incoming_headers = _match_header_values(clean.headers, names)
        candidates = [
            i
            for i in self.interactions
            if incoming.same_target(rk := self._recorded_key(i))
            and self._bodies_match(incoming, rk)
            and _match_header_values(i.request.get("headers"), names) == incoming_headers
        ]
        chosen = next((i for i in candidates if not i.played), None)
        if chosen is None and candidates and self.match.allow_playback_repeats:
            chosen = candidates[-1]
        if chosen is None:
            reason = "all matching interactions already played" if candidates else "no recorded interaction matches"
            shown = "".join(f" [{n}: {v}]" for n, v in zip(names, incoming_headers, strict=True) if v)
            self.unmatched.append(f"{incoming.describe()}{shown} ({reason})")
            return None
        chosen.played = True
        return chosen.response

    # -- record ---------------------------------------------------------------------------------------------

    def scrub_for_client(self, response: dict[str, Any], uri: str) -> dict[str, Any] | None:
        """Apply scrub_before_read sanitizers to the live response before the component reads it."""
        chain = self._chain(uri, pre_read_only=True) if self._has_pre_read else None
        if chain is None or not chain.sanitizers:
            return None
        return chain.before_record_response(copy.deepcopy(response))

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
        clean_req = self._sanitize_request(req)
        if clean_req is None:
            return
        names = self.match.headers
        for name, sent, kept in zip(
            names,
            _match_header_values(req.headers, names),
            _match_header_values(clean_req.headers, names),
            strict=True,
        ):
            if sent and not kept:
                self.errors.append(
                    f"match header {name} was removed by a sanitizer, so replay could never match "
                    f"{request_key(req).describe()}; add it to DefaultSanitizer additional_safe_headers in vcr.json"
                )
        chain = self._chain(req.uri)
        response = copy.deepcopy(response)
        raw_resp_body = response.get("body", {}).get("string")
        resp_binary = _is_binary(raw_resp_body)
        if resp_binary:
            response["body"]["string"] = b""
        clean_resp = chain.before_record_response(response)
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


def bodyless_content_length(response: dict[str, Any], method: str) -> str | None:
    """The recorded Content-Length to send with a replayed answer that has no body by definition.

    A HEAD answer (and a 204 or 304) carries the size of the resource without its body. On replay mitmproxy would set
    Content-Length to the length of the empty body, 0, and clients that read the size from a HEAD (S3 `headObject`)
    would see 0 bytes. Returns None when the recorded value should not be kept.
    """
    status = int(response.get("status", {}).get("code", 200))
    if method.upper() != "HEAD" and status not in (204, 304):
        return None
    for name, values in _header_lists(response.get("headers", {})).items():
        if name.lower() == "content-length" and values:
            return values[0]
    return None
