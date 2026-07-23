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
aborts with an error telling you which field to untag.

## Development

```bash
uv sync --all-groups
uv run pytest tests/
```
