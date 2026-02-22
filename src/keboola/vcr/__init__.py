"""
keboola.vcr — VCR recording, sanitization, and validation for Keboola components.

This package provides the core VCR functionality extracted from datadirtest:
- VCRRecorder: Record and replay HTTP interactions
- Sanitizers: Redact sensitive data from cassettes
- Validator: Hash-based output validation
- Scaffolder: Generate test folder structures

Usage:
    from keboola.vcr import VCRRecorder, DefaultSanitizer
    from keboola.vcr.sanitizers import ConfigSecretsSanitizer
"""

from .recorder import (
    VCRRecorder,
    VCRRecorderError,
    CassetteMissingError,
    SecretsLoadError,
    JsonIndentedSerializer,
)
from .sanitizers import (
    BaseSanitizer,
    DefaultSanitizer,
    TokenSanitizer,
    HeaderSanitizer,
    UrlPatternSanitizer,
    BodyFieldSanitizer,
    QueryParamSanitizer,
    ResponseUrlSanitizer,
    CallbackSanitizer,
    CompositeSanitizer,
    ConfigSecretsSanitizer,
    create_default_sanitizer,
    extract_values,
)
from .validator import (
    OutputSnapshot,
    ValidationResult,
    ValidationDiff,
    FileSnapshot,
    capture_output_snapshot,
    save_output_snapshot,
    validate_output_snapshot,
)
from .scaffolder import (
    TestScaffolder,
    ScaffolderError,
    scaffold_tests,
)

__all__ = [
    # Recorder
    "VCRRecorder",
    "VCRRecorderError",
    "CassetteMissingError",
    "SecretsLoadError",
    "JsonIndentedSerializer",
    # Sanitizers
    "BaseSanitizer",
    "DefaultSanitizer",
    "TokenSanitizer",
    "HeaderSanitizer",
    "UrlPatternSanitizer",
    "BodyFieldSanitizer",
    "QueryParamSanitizer",
    "ResponseUrlSanitizer",
    "CallbackSanitizer",
    "CompositeSanitizer",
    "ConfigSecretsSanitizer",
    "create_default_sanitizer",
    "extract_values",
    # Validator
    "OutputSnapshot",
    "ValidationResult",
    "ValidationDiff",
    "FileSnapshot",
    "capture_output_snapshot",
    "save_output_snapshot",
    "validate_output_snapshot",
    # Scaffolder
    "TestScaffolder",
    "ScaffolderError",
    "scaffold_tests",
]
