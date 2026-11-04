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
    "IPv4UrlSanitizer": _san.IPv4UrlSanitizer,
    "ResponseUrlSanitizer": _san.ResponseUrlSanitizer,
}


class ProxyConfigError(ValueError):
    """Raised for an invalid ``vcr.json``."""


@dataclass
class MatchOptions:
    """How a replayed request is matched to a recorded one.

    Method, scheme, host, port, path and the sorted query always take part. Headers never do: they carry
    authorization and signatures that differ between recording and replay.
    """

    body: bool = True
    ignore_body: list[str] = field(default_factory=lambda: list(DEFAULT_IGNORE_BODY))
    ignore_body_fields: list[str] = field(default_factory=list)
    allow_playback_repeats: bool = False

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
        unknown_match = set(match_raw) - {"body", "ignore_body", "ignore_body_fields", "allow_playback_repeats"}
        if unknown_match:
            raise ProxyConfigError(f"{source}: unknown keys in 'match': {sorted(unknown_match)}")
        # Extra ignore_body patterns add to the defaults; they never silently drop the token endpoints.
        match_raw["ignore_body"] = DEFAULT_IGNORE_BODY + list(match_raw.get("ignore_body", []))
        specs = list(raw.get("sanitizers") or [])
        for spec in specs:
            if not isinstance(spec, dict) or spec.get("class") not in _SANITIZER_FACTORIES:
                raise ProxyConfigError(
                    f"{source}: each sanitizer needs a 'class' from {sorted(_SANITIZER_FACTORIES)}, got {spec!r}"
                )
        if sum(1 for s in specs if s["class"] == "DefaultSanitizer") > 1:
            raise ProxyConfigError(f"{source}: declare DefaultSanitizer at most once")
        return cls(
            secret_env=list(raw.get("secret_env") or []),
            sanitizer_specs=specs,
            match=MatchOptions(**match_raw),
            unmatched_status=int(raw.get("unmatched_status", 418)),
        )

    def secret_values(self, environ: dict[str, str] | None = None) -> list[str]:
        """Values of the declared secret env vars that are set. Never logged."""
        env = os.environ if environ is None else environ
        return [env[name] for name in self.secret_env if env.get(name)]

    def build_sanitizers(self, secret_values: list[str]) -> list[_san.BaseSanitizer]:
        """DefaultSanitizer first (with the secret values), then the declared ones in order."""
        default_kwargs: dict[str, Any] = {}
        rest: list[_san.BaseSanitizer] = []
        for spec in self.sanitizer_specs:
            kwargs = {k: v for k, v in spec.items() if k != "class"}
            if spec["class"] == "DefaultSanitizer":
                default_kwargs = kwargs
                continue
            if spec["class"] == "UrlPatternSanitizer":
                kwargs["patterns"] = [tuple(p) for p in kwargs.get("patterns", [])]
            rest.append(_SANITIZER_FACTORIES[spec["class"]](**kwargs))
        values = list(default_kwargs.pop("sensitive_values", [])) + list(secret_values)
        return [_san.DefaultSanitizer(sensitive_values=values, **default_kwargs), *rest]
