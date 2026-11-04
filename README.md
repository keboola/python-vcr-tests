# keboola.vcr

VCR recording, sanitization, and validation for Keboola component HTTP interactions.

## Installation
 
```bash
pip install keboola.vcr
```

## Usage

```python
from keboola.vcr.recorder import VCRRecorder
from keboola.vcr.sanitizers import DefaultSanitizer

recorder = VCRRecorder(
    cassette_dir="tests/cassettes/my_test",
    secrets={"api_key": "secret"},
)
```

## Features

- **Recording**: Captures real HTTP interactions via vcrpy and stores them as JSON cassettes
- **Sanitization**: Redacts secrets, tokens, and sensitive fields before saving cassettes
- **Scaffolding**: Generates test directory structures from component config definitions
- **Validation**: Compares output snapshots to detect regressions

## Sanitizing data before the component reads it

By default, sanitizers scrub the **cassette** only — during recording the
component still receives the real API response, so real values can end up in the
component's output tables. To stop real customer data from ever reaching the
component, tag a sanitizer with `scrub_before_read=True`. The recorder then
redacts those fields in the response *before the component reads them*, so the
output is clean regardless of format (CSV, Parquet, or direct-to-Storage).

```python
# tests/.../sanitizers.py
from keboola.vcr import BodyFieldSanitizer

def get_sanitizers(config):
    return [
        # PII the component only reads and emits → redacted before the component reads it
        BodyFieldSanitizer(fields=["customer_name", "email", "phone"], scrub_before_read=True),
    ]
```

**Rule:** only tag fields the component *consumes and emits*. Never tag a value
the component sends back to the live API during recording — a pagination cursor,
an async job ID, or an OAuth token — because it must stay real for the follow-up
request to succeed. Token/secret sanitizers stay untagged (cassette-only) for
exactly this reason. If a redacted value is sent to the live API, recording
aborts with an error naming the tagged sanitizer(s) so you can find and untag
the offending field.

**Caution:** only tag field-scoped body sanitizers (e.g. `BodyFieldSanitizer`)
with `scrub_before_read`. Do not tag whole-response sanitizers like
`DefaultSanitizer` or `HeaderSanitizer` — their header whitelisting would also
apply to the component-visible response during recording, and can strip
pagination or rate-limit headers the component needs to keep working.

## Recording proxy (PHP and other non-Python components)

A component that is not written in Python cannot run inside `VCRRecorder`. For those, `keboola.vcr.proxy` is a
[mitmproxy](https://mitmproxy.org) addon that records the component's HTTPS traffic into the same cassette format,
runs the same sanitizers, and replays it offline. The component code does not change: its HTTP client only needs to
honour `HTTPS_PROXY` (Guzzle does) and trust the proxy CA.

```bash
pip install "keboola.vcr[proxy]"        # mitmproxy 12, Python 3.12+
python -m keboola.vcr.proxy --mode replay --config tests/vcr.json --confdir /vcr-ca
```

- **Ports:** `8080` is the proxy. `8081` is the control port: `POST /start {"cassette": "<abs path>"}` starts a
  test case, `GET /status` reports it so far without ending it, `POST /stop` ends it (record mode writes the
  cassette; the answer lists `unmatched` requests in replay), `GET /health` answers once the proxy runs.
- **Network:** both ports listen on `0.0.0.0` (`--listen-host`, `--control-host`) so the test container reaches them
  over the compose network. The control port has no authentication: never publish it to the host or run the proxy
  outside a test or CI network.
- **Record** (`--mode record` or `VCR_MODE=record`): live traffic, sanitized before it is written. Traffic outside a
  started case (test fixture set-up) passes through and is not recorded. If a value of a `secret_env` variable is
  still in the cassette after sanitizing, the proxy refuses to write it and `/stop` returns an `error`.
- **Replay** (default): no upstream connection at all (`upstream_cert=false`, lazy connect). A request with no
  recorded answer gets HTTP 418 with an explanation and is listed in the `/stop` answer.
- **Matching:** method, scheme, host, port, path and the sorted query, plus the JSON or form body (multipart
  boundaries masked); never headers. The body is ignored on OAuth token endpoints (Google, Microsoft, Firebolt by
  default). Each interaction plays once, in recorded order among equal requests.
- **Binary bodies** (file downloads, uploads) bypass the text sanitizers and are stored base64-encoded, with
  `"encoding": "base64"` next to the body.
- **Check what the component reads before you sanitize.** `DefaultSanitizer` keeps only the `content-type`,
  `content-length` and `accept` response headers, and it redacts any body field named `code`. A component that polls
  an async operation needs `"additional_safe_headers": ["location", "retry-after"]`; one that branches on an API
  error code (`{"error": {"code": ...}}`) needs `sensitive_fields` without `code`. Otherwise replay takes a
  different branch than the recording did.
- **No time freezing:** a request whose URL or body carries the current date will not match on replay. Pin such
  values in the test config.
- **Where it runs:** wherever the component's tests run, usually its local Docker Compose stack, with the
  credentials in the folder's `.env`. CI can run the same stack. It cannot record a platform debug job: the platform
  runs only the component image, without the proxy container (use `VCRRecorder.record_debug_run` in Python).

`tests/vcr.json` replaces the `VCR_SANITIZERS` list of a Python component:

```json
{
  "secret_env": ["OAUTH_APP_SECRET", "OAUTH_REFRESH_TOKEN"],
  "sanitizers": [
    {"class": "DefaultSanitizer", "additional_sensitive_fields": ["sessionId"]},
    {"class": "BodyFieldSanitizer", "fields": ["email"], "scrub_before_read": true},
    {"class": "UrlPatternSanitizer", "patterns": [["/users/[0-9]+", "/users/0"]]},
    {"class": "BodyFieldSanitizer", "fields": ["name"], "urls": ["graph.microsoft.com/v1.0/sites"]}
  ],
  "match": {"ignore_body": ["api.example.com/upload/*"], "ignore_body_fields": ["requestId"],
            "allow_playback_repeats": false},
  "unmatched_status": 418
}
```

| Key | Meaning |
|---|---|
| `secret_env` | Env var names whose values (record mode only) are redacted everywhere and checked before writing |
| `sanitizers` | Sanitizer classes from `keboola.vcr.sanitizers` with their keyword arguments. `DefaultSanitizer` always runs first; declare it at most once to extend it. `CallbackSanitizer` is not available (it needs code) |
| `sanitizers[].urls` | Optional `host/path` globs: the sanitizer applies only to those requests and their answers (a field that is personal data on one endpoint but needed on others) |
| `match.body` | `false` turns body matching off |
| `match.ignore_body` | Extra `host/path` globs whose body is not matched (added to the token endpoint defaults) |
| `match.ignore_body_fields` | JSON or form fields left out of the body comparison (request ids, timestamps) |
| `match.allow_playback_repeats` | Reuse the last matching interaction once all are played |

The PHP side (one trait for `keboola/datadir-tests`, a CA helper and a compose example) is
[keboola/php-vcr-tests](https://github.com/keboola/php-vcr-tests). Validate recordings with the
`component-developer:vcr-cassette-validator` agent like any other cassette.

## Development

```bash
uv sync --all-groups
uv run pytest tests/
```
