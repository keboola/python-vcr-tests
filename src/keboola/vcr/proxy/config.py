"""Per-folder configuration of the recording proxy (``tests/vcr.json``).

A PHP (or any non-Python) component cannot declare ``VCR_SANITIZERS`` in its code, so the proxy reads the same
sanitizers from a JSON file next to the tests. Example::

    {
      "secret_env": ["OAUTH_APP_SECRET", "OAUTH_REFRESH_TOKEN"],
      "sanitizers": [
        {"class": "DefaultSanitizer", "additional_sensitive_fields": ["sessionId"]},
        {"class": "BodyFieldSanitizer", "fields": ["email"]}
      ],
      "match": {"ignore_body": ["login.microsoftonline.com/*"], "ignore_body_fields": ["requestId"]}
    }
"""

from __future__ import annotations

import fnmatch
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote, quote_plus, urlsplit

from .. import sanitizers as _san

# Token endpoints send the refresh token or a client assertion in the body. Those values differ between recording
# (real) and replay (dummy), so the body never takes part in matching on these URLs.
DEFAULT_IGNORE_BODY = [
    "oauth2.googleapis.com/token",
    "accounts.google.com/o/oauth2/token",
    "www.googleapis.com/oauth2/*/token",
    "login.microsoftonline.com/*/token",
    "id.app.firebolt.io/oauth/token",
]

# Sanitizers that can be built from plain JSON. CallbackSanitizer needs code, so it is not offered.
_SANITIZER_FACTORIES: dict[str, Any] = {
    "DefaultSanitizer": _san.DefaultSanitizer,
    "TokenSanitizer": _san.TokenSanitizer,
    "HeaderSanitizer": _san.HeaderSanitizer,
    "BodyFieldSanitizer": _san.BodyFieldSanitizer,
    "QueryParamSanitizer": _san.QueryParamSanitizer,
    "UrlPatternSanitizer": _san.UrlPatternSanitizer,
    "BodyPatternSanitizer": _san.BodyPatternSanitizer,
    "IPv4UrlSanitizer": _san.IPv4UrlSanitizer,
    "ResponseUrlSanitizer": _san.ResponseUrlSanitizer,
}


class ProxyConfigError(ValueError):
    """Raised for an invalid ``vcr.json``."""


class UrlScopedSanitizer(_san.BaseSanitizer):
    """Applies ``inner`` only to interactions whose request ``host/path`` matches one of ``urls`` (fnmatch globs).

    For a field name that is personal data on one endpoint but a value the component needs on others (``name`` of a
    SharePoint site vs. ``name`` of a file).
    """

    def __init__(self, inner: _san.BaseSanitizer, urls: list[str]):
        self.inner = inner
        self.urls = list(urls)
        self.scrub_before_read = getattr(inner, "scrub_before_read", False)
        self.replacement = getattr(inner, "replacement", "")

    def applies_to(self, uri: str) -> bool:
        parts = urlsplit(uri)
        target = f"{(parts.hostname or '').lower()}{parts.path or '/'}"
        return any(fnmatch.fnmatchcase(target, pattern) for pattern in self.urls)

    def before_record_request(self, request: Any) -> Any:
        return self.inner.before_record_request(request)

    def before_record_response(self, response: dict) -> dict:
        return self.inner.before_record_response(response)


@dataclass
class MatchOptions:
    """How a replayed request is matched to a recorded one.

    Method, scheme, host, port, path and the sorted query always take part. Headers do not by default: they carry
    authorization and signatures that differ between recording and replay. ``headers`` names request headers that
    do take part (case-insensitive; a missing header compares as empty), for a client that sends requests which differ
    only in a header, possibly at the same time (Azure Cosmos DB marks its query-plan request with
    ``x-ms-cosmos-is-query-plan-request``). The recording must keep them: list them in ``additional_safe_headers``.
    """

    body: bool = True
    ignore_body: list[str] = field(default_factory=lambda: list(DEFAULT_IGNORE_BODY))
    ignore_body_fields: list[str] = field(default_factory=list)
    allow_playback_repeats: bool = False
    headers: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.headers = [h.lower() for h in self.headers]

    def body_ignored_for(self, host: str, path: str) -> bool:
        target = f"{host}{path}"
        return any(fnmatch.fnmatchcase(target, pattern) for pattern in self.ignore_body)


@dataclass
class ProxyConfig:
    secret_env: list[str] = field(default_factory=list)
    sanitizer_specs: list[dict[str, Any]] = field(default_factory=list)
    match: MatchOptions = field(default_factory=MatchOptions)
    unmatched_status: int = 418

    @classmethod
    def load(cls, path: str | Path | None) -> ProxyConfig:
        if path is None or not Path(path).exists():
            return cls()
        try:
            raw = json.loads(Path(path).read_text())
        except json.JSONDecodeError as e:
            raise ProxyConfigError(f"{path}: not valid JSON: {e}") from e
        return cls.from_dict(raw, source=str(path))

    @classmethod
    def from_dict(cls, raw: dict[str, Any], source: str = "vcr.json") -> ProxyConfig:
        unknown = set(raw) - {"secret_env", "sanitizers", "match", "unmatched_status", "$comment"}
        if unknown:
            raise ProxyConfigError(f"{source}: unknown keys {sorted(unknown)}")
        match_raw = dict(raw.get("match") or {})
        unknown_match = set(match_raw) - {
            "body",
            "ignore_body",
            "ignore_body_fields",
            "allow_playback_repeats",
            "headers",
        }
        if unknown_match:
            raise ProxyConfigError(f"{source}: unknown keys in 'match': {sorted(unknown_match)}")
        match_headers = match_raw.get("headers", [])
        if not isinstance(match_headers, list) or not all(isinstance(h, str) and h.strip() for h in match_headers):
            raise ProxyConfigError(f"{source}: 'match.headers' must be a list of header names")
        # Extra ignore_body patterns add to the defaults; they never silently drop the token endpoints.
        match_raw["ignore_body"] = DEFAULT_IGNORE_BODY + list(match_raw.get("ignore_body", []))
        specs = list(raw.get("sanitizers") or [])
        for spec in specs:
            if not isinstance(spec, dict) or spec.get("class") not in _SANITIZER_FACTORIES:
                raise ProxyConfigError(
                    f"{source}: each sanitizer needs a 'class' from {sorted(_SANITIZER_FACTORIES)}, got {spec!r}"
                )
        for spec in specs:
            urls = spec.get("urls")
            if urls is not None and (spec["class"] == "DefaultSanitizer" or not isinstance(urls, list) or not urls):
                raise ProxyConfigError(f"{source}: 'urls' must be a non-empty list, and not on DefaultSanitizer")
        if sum(1 for s in specs if s["class"] == "DefaultSanitizer") > 1:
            raise ProxyConfigError(f"{source}: declare DefaultSanitizer at most once")
        return cls(
            secret_env=list(raw.get("secret_env") or []),
            sanitizer_specs=specs,
            match=MatchOptions(**match_raw),
            unmatched_status=int(raw.get("unmatched_status", 418)),
        )

    def secret_values(self, environ: dict[str, str] | None = None) -> list[str]:
        """Values of the declared secret env vars that are set, plus their URL-encoded forms. Never logged.

        A token often travels URL-encoded (a form body, a query string), where the raw value does not occur.
        """
        env = os.environ if environ is None else environ
        values: list[str] = []
        for name in self.secret_env:
            raw = env.get(name)
            if not raw:
                continue
            for variant in (raw, quote(raw, safe=""), quote_plus(raw, safe="")):
                if variant not in values:
                    values.append(variant)
        return values

    def build_sanitizers(self, secret_values: list[str]) -> list[_san.BaseSanitizer]:
        """DefaultSanitizer first (with the secret values), then the declared ones in order."""
        default_kwargs: dict[str, Any] = {}
        rest: list[_san.BaseSanitizer] = []
        for spec in self.sanitizer_specs:
            kwargs = {k: v for k, v in spec.items() if k != "class"}
            if spec["class"] == "DefaultSanitizer":
                default_kwargs = kwargs
                continue
            urls = kwargs.pop("urls", None)
            if spec["class"] in ("UrlPatternSanitizer", "BodyPatternSanitizer"):
                kwargs["patterns"] = [tuple(p) for p in kwargs.get("patterns", [])]
            sanitizer = _SANITIZER_FACTORIES[spec["class"]](**kwargs)
            rest.append(UrlScopedSanitizer(sanitizer, urls) if urls else sanitizer)
        values = list(default_kwargs.pop("sensitive_values", [])) + list(secret_values)
        return [_san.DefaultSanitizer(sensitive_values=values, **default_kwargs), *rest]
