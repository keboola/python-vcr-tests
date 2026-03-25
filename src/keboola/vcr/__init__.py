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
    CassetteMissingError,
    JsonIndentedSerializer,
    SecretsLoadError,
    VCRRecorder,
    VCRRecorderError,
)
from .sanitizers import (
    BaseSanitizer,
    BodyFieldSanitizer,
    CallbackSanitizer,
    CompositeSanitizer,
    ConfigSecretsSanitizer,
    DefaultSanitizer,
    HeaderSanitizer,
    IPv4UrlSanitizer,
    QueryParamSanitizer,
    ResponseUrlSanitizer,
    TokenSanitizer,
    UrlPatternSanitizer,
    create_default_sanitizer,
    extract_values,
)
from .scaffolder import (
    ScaffolderError,
    TestScaffolder,
    scaffold_tests,
)
from .validator import (
    FileSnapshot,
    OutputSnapshot,
    ValidationDiff,
    ValidationResult,
    capture_output_snapshot,
    save_output_snapshot,
    validate_output_snapshot,
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
    "IPv4UrlSanitizer",
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
