"""Record/replay HTTPS proxy that writes keboola.vcr cassettes, for components that are not Python.

Install with the ``proxy`` extra (``pip install "keboola.vcr[proxy]"``) and run ``python -m keboola.vcr.proxy``.
The cassette logic (:mod:`.cassette`, :mod:`.config`) does not need mitmproxy; only :mod:`.addon` does.
"""

from .cassette import CassetteSession, RecordingError, SecretLeakError
from .config import DEFAULT_IGNORE_BODY, MatchOptions, ProxyConfig, ProxyConfigError

__all__ = [
    "DEFAULT_IGNORE_BODY",
    "CassetteSession",
    "MatchOptions",
    "ProxyConfig",
    "ProxyConfigError",
    "RecordingError",
    "SecretLeakError",
]
