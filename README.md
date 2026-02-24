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

## Development

```bash
uv sync --all-groups
uv run pytest tests/
```
