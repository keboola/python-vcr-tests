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

from .db_recorder import (
    DBAdapter,
    OracleDBAdapter,
)
from .log_capture import (
    CapturedLog,
    ComponentRunResult,
    LogComparisonResult,
    SyncActionComparisonResult,
    compare_logs,
    load_logs,
    run_with_log_capture,
    save_logs,
)
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
    "BaseSanitizer",
    "BodyFieldSanitizer",
    "CallbackSanitizer",
    "CapturedLog",
    "CassetteMissingError",
    "ComponentRunResult",
    "CompositeSanitizer",
    "ConfigSecretsSanitizer",
    "DBAdapter",
    "DefaultSanitizer",
    "FileSnapshot",
    "HeaderSanitizer",
    "IPv4UrlSanitizer",
    "JsonIndentedSerializer",
    "LogComparisonResult",
    "OracleDBAdapter",
    "OutputSnapshot",
    "QueryParamSanitizer",
    "ResponseUrlSanitizer",
    "ScaffolderError",
    "SecretsLoadError",
    "SyncActionComparisonResult",
    "TestScaffolder",
    "TokenSanitizer",
    "UrlPatternSanitizer",
    "VCRRecorder",
    "VCRRecorderError",
    "ValidationDiff",
    "ValidationResult",
    "capture_output_snapshot",
    "compare_logs",
    "create_default_sanitizer",
    "extract_values",
    "load_logs",
    "run_with_log_capture",
    "save_logs",
    "save_output_snapshot",
    "scaffold_tests",
    "validate_output_snapshot",
]
