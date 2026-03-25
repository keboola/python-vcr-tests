"""
Sanitizers for VCR cassettes.

This module provides pluggable sanitization classes that can be used to
redact sensitive information from recorded HTTP interactions.
"""

from __future__ import annotations

import json
import re
from abc import ABC
from pathlib import Path
from typing import Any


class BaseSanitizer(ABC):
    """
    Base class for request/response sanitization.

    Subclass this to create custom sanitizers that can modify
    requests and responses before they are recorded to cassettes.
    """

    def before_record_request(self, request: Any) -> Any:
        """
        Sanitize request before recording. Override in subclass.

        Args:
            request: The vcrpy request object

        Returns:
            The sanitized request object
        """
        return request

    def before_record_response(self, response: dict) -> dict:
        """
        Sanitize response before recording. Override in subclass.

        Args:
            response: The vcrpy response dictionary

        Returns:
            The sanitized response dictionary
        """
        return response


class DefaultSanitizer(BaseSanitizer):
    """
    Smart unified sanitizer for VCR cassettes.

    Two core functions applied to all HTTP interactions:
    - _sanitize_url(): query params + exact value replacement
    - _sanitize_body(): tries JSON -> form-encoded -> exact value replacement

    When ``config`` is provided (a Keboola config dict), all values under
    ``#``-prefixed keys are automatically extracted and treated as sensitive
    values — no separate ConfigSecretsSanitizer needed.

    Customization per component:
    - sensitive_fields: override default field names to redact
    - additional_sensitive_fields: extend defaults without replacing
    - sensitive_values: exact strings from secrets file
    - safe_headers: override default header whitelist
    - additional_safe_headers: extend default whitelist
    - config: Keboola config dict for auto-detecting #-prefixed secrets
    """

    DEFAULT_SENSITIVE_FIELDS = [
        "access_token",
        "refresh_token",
        "id_token",
        "client_id",
        "client_secret",
        "client_assertion",
        "code",
        "password",
        "token",
    ]

    DEFAULT_SAFE_HEADERS = [
        "content-type",
        "content-length",
        "accept",
    ]

    def __init__(
        self,
        sensitive_fields: list[str] | None = None,
        additional_sensitive_fields: list[str] | None = None,
        sensitive_values: list[str] | None = None,
        safe_headers: list[str] | None = None,
        additional_safe_headers: list[str] | None = None,
        replacement: str = "REDACTED",
        config: dict[str, Any] | None = None,
    ):
        # Build sensitive fields set
        if sensitive_fields is not None:
            self.sensitive_fields = set(sensitive_fields)
        else:
            self.sensitive_fields = set(self.DEFAULT_SENSITIVE_FIELDS)
        if additional_sensitive_fields:
            self.sensitive_fields.update(additional_sensitive_fields)

        # Build header whitelist
        if safe_headers is not None:
            self.safe_headers = set(h.lower() for h in safe_headers)
        else:
            self.safe_headers = set(h.lower() for h in self.DEFAULT_SAFE_HEADERS)
        if additional_safe_headers:
            self.safe_headers.update(h.lower() for h in additional_safe_headers)

        # Collect sensitive values: explicit + auto-detected from #-prefixed config keys
        all_values = list(sensitive_values or [])
        if config:
            _collect_hash_values(config, all_values)

        # Sort known values longest-first to prevent partial JWT replacement
        self.sensitive_values = sorted(
            [v for v in all_values if v],
            key=len,
            reverse=True,
        )
        self.replacement = replacement
        # Pre-compile regex for form-encoded/query param matching
        self._field_patterns = [re.compile(rf"({re.escape(f)}=)[^&\"\s]+") for f in self.sensitive_fields]

    # -- Core function 1: URL sanitization --

    def _sanitize_url(self, url: str) -> str:
        """Sanitize query params by field name, then replace known secret values."""
        result = url
        for pattern in self._field_patterns:
            result = pattern.sub(rf"\1{self.replacement}", result)
        for value in self.sensitive_values:
            if value in result:
                result = result.replace(value, self.replacement)
        return result

    # -- Core function 2: Body sanitization --

    def _sanitize_body(self, body: str) -> str:
        """Sanitize body: try JSON -> form-encoded -> exact value replacement."""
        if not body:
            return body

        # Quick pre-scan: skip expensive JSON parse if no sensitive content is present.
        # Use quoted field names for JSON key matching (avoids false positives from substrings).
        needs_json_sanitization = any(f'"{field}"' in body for field in self.sensitive_fields) or any(
            value in body for value in self.sensitive_values
        )
        if not needs_json_sanitization:
            # Still apply form-encoded / exact value checks (cheap string ops)
            result = body
            for pattern in self._field_patterns:
                result = pattern.sub(rf"\1{self.replacement}", result)
            for value in self.sensitive_values:
                if value in result:
                    result = result.replace(value, self.replacement)
            return result

        # 1. Try JSON (only when pre-scan found a potential sensitive field/value)
        try:
            data = json.loads(body)
            changed = [False]
            sanitized = self._sanitize_json_value(data, changed)
            if not changed[0]:
                return body  # no changes → preserve original formatting
            return json.dumps(sanitized)
        except (json.JSONDecodeError, TypeError, ValueError):
            pass

        # 2. Try form-encoded param patterns (same regex as URL)
        result = body
        for pattern in self._field_patterns:
            result = pattern.sub(rf"\1{self.replacement}", result)

        # 3. Always do exact value replacement as catch-all
        for value in self.sensitive_values:
            if value in result:
                result = result.replace(value, self.replacement)
        return result

    def _sanitize_json_value(self, data: Any, changed: list[bool] | None = None) -> Any:
        """Recursively sanitize JSON data by field name and known values.

        Args:
            data: The JSON value to sanitize.
            changed: Single-element list used as a mutable flag.  Set to
                ``[True]`` by the caller; this method sets ``changed[0] = True``
                the first time any substitution is made.  When ``None`` (default,
                used by callers that do not need change tracking) the flag is
                simply not updated.
        """
        if isinstance(data, dict):
            result = {}
            for key, value in data.items():
                if key in self.sensitive_fields:
                    result[key] = self.replacement
                    if changed is not None:
                        changed[0] = True
                else:
                    result[key] = self._sanitize_json_value(value, changed)
            return result
        elif isinstance(data, list):
            return [self._sanitize_json_value(item, changed) for item in data]
        elif isinstance(data, str):
            # Replace known secret values in string fields (catches embedded tokens)
            result = data
            for value in self.sensitive_values:
                if value in result:
                    result = result.replace(value, self.replacement)
                    if changed is not None:
                        changed[0] = True
            return result
        return data

    # -- Header filtering --

    def _filter_headers(self, headers: dict) -> dict:
        """Whitelist-only header filtering."""
        result = {}
        for key, value in headers.items():
            if key.lower() in self.safe_headers:
                result[key] = value
        return result

    def merge(self, other: DefaultSanitizer) -> DefaultSanitizer:
        """Merge two DefaultSanitizers into one, unioning all their fields."""
        merged_values = list(dict.fromkeys(self.sensitive_values + other.sensitive_values))
        return DefaultSanitizer(
            sensitive_fields=list(self.sensitive_fields | other.sensitive_fields),
            safe_headers=list(self.safe_headers | other.safe_headers),
            sensitive_values=merged_values,
            replacement=self.replacement,
        )

    # -- Applied uniformly to requests and responses --

    def before_record_request(self, request: Any) -> Any:
        """Sanitize URL, headers, and body of request."""
        if hasattr(request, "uri"):
            request.uri = self._sanitize_url(request.uri)

        if hasattr(request, "headers"):
            request.headers = self._filter_headers(request.headers)

        if hasattr(request, "body") and request.body:
            if isinstance(request.body, bytes):
                body_str = request.body.decode("utf-8", errors="ignore")
                request.body = self._sanitize_body(body_str).encode("utf-8")
            elif isinstance(request.body, str):
                request.body = self._sanitize_body(request.body)

        return request

    def before_record_response(self, response: dict) -> dict:
        """Sanitize headers and body of response."""
        if "headers" in response:
            response["headers"] = self._filter_headers(response["headers"])

        if "body" in response:
            body = response["body"]
            if isinstance(body, dict) and "string" in body:
                if isinstance(body["string"], bytes):
                    body_str = body["string"].decode("utf-8", errors="ignore")
                    body["string"] = self._sanitize_body(body_str).encode("utf-8")
                elif isinstance(body["string"], str):
                    body["string"] = self._sanitize_body(body["string"])

        return response


class CompositeSanitizer(BaseSanitizer):
    """
    Combines multiple sanitizers into a single sanitizer.

    Sanitizers are applied in the order they are provided.
    """

    def __init__(self, sanitizers: list[BaseSanitizer]):
        """
        Args:
            sanitizers: List of sanitizers to apply in order
        """
        self.sanitizers = sanitizers

    def before_record_request(self, request: Any) -> Any:
        """Apply all sanitizers to the request."""
        for sanitizer in self.sanitizers:
            request = sanitizer.before_record_request(request)
        return request

    def before_record_response(self, response: dict) -> dict:
        """Apply all sanitizers to the response."""
        for sanitizer in self.sanitizers:
            response = sanitizer.before_record_response(response)
        return response


class TokenSanitizer(BaseSanitizer):
    """
    Replaces auth tokens and secrets with placeholders.

    Searches through request URIs, headers, and body for the specified
    tokens and replaces them with the replacement string.
    """

    def __init__(self, tokens: list[str], replacement: str = "REDACTED"):
        """
        Args:
            tokens: List of token values to sanitize
            replacement: Replacement string for tokens
        """
        self.tokens = [t for t in tokens if t]  # Filter out empty strings
        self.replacement = replacement

    def merge(self, other: TokenSanitizer) -> TokenSanitizer:
        """Merge two TokenSanitizers into one, unioning their token lists."""
        return TokenSanitizer(
            tokens=list(dict.fromkeys(self.tokens + other.tokens)),
            replacement=self.replacement,
        )

    def _sanitize_string(self, value: str) -> str:
        """Replace all tokens in a string."""
        result = value
        for token in self.tokens:
            if token and token in result:
                result = result.replace(token, self.replacement)
        return result

    def _sanitize_dict(self, d: dict) -> dict:
        """Recursively sanitize all string values in a dictionary."""
        result = {}
        for key, value in d.items():
            if isinstance(value, str):
                result[key] = self._sanitize_string(value)
            elif isinstance(value, dict):
                result[key] = self._sanitize_dict(value)
            elif isinstance(value, list):
                result[key] = self._sanitize_list(value)
            else:
                result[key] = value
        return result

    def _sanitize_list(self, lst: list) -> list:
        """Recursively sanitize all items in a list."""
        result = []
        for item in lst:
            if isinstance(item, str):
                result.append(self._sanitize_string(item))
            elif isinstance(item, dict):
                result.append(self._sanitize_dict(item))
            elif isinstance(item, list):
                result.append(self._sanitize_list(item))
            else:
                result.append(item)
        return result

    def before_record_request(self, request: Any) -> Any:
        """Sanitize tokens in request URI, headers, and body."""
        # Sanitize URI
        if hasattr(request, "uri"):
            request.uri = self._sanitize_string(request.uri)

        # Sanitize headers
        if hasattr(request, "headers"):
            for header_name in list(request.headers.keys()):
                values = request.headers.get(header_name, [])
                if isinstance(values, list):
                    request.headers[header_name] = [
                        self._sanitize_string(v) if isinstance(v, str) else v for v in values
                    ]
                elif isinstance(values, str):
                    request.headers[header_name] = self._sanitize_string(values)

        # Sanitize body
        if hasattr(request, "body") and request.body:
            if isinstance(request.body, str):
                request.body = self._sanitize_string(request.body)
            elif isinstance(request.body, bytes):
                body_str = request.body.decode("utf-8", errors="ignore")
                sanitized = self._sanitize_string(body_str)
                request.body = sanitized.encode("utf-8")

        return request

    def before_record_response(self, response: dict) -> dict:
        """Sanitize tokens in response body and headers."""
        if "body" in response:
            body = response["body"]
            if isinstance(body, dict) and "string" in body:
                if isinstance(body["string"], str):
                    body["string"] = self._sanitize_string(body["string"])
                elif isinstance(body["string"], bytes):
                    body_str = body["string"].decode("utf-8", errors="ignore")
                    body["string"] = self._sanitize_string(body_str).encode("utf-8")

        if "headers" in response:
            response["headers"] = self._sanitize_dict(response["headers"])

        return response


class HeaderSanitizer(BaseSanitizer):
    """
    Filters headers to whitelist only safe ones.

    Removes potentially sensitive headers from requests and responses,
    keeping only those in the whitelist.
    """

    # Default safe headers that don't contain sensitive info
    DEFAULT_SAFE_HEADERS = [
        "content-type",
        "content-length",
        "accept",
        "accept-encoding",
        "accept-language",
        "cache-control",
        "connection",
        "host",
        "user-agent",
        "date",
        "server",
        "transfer-encoding",
        "vary",
        "x-request-id",
        "x-correlation-id",
    ]

    def __init__(
        self,
        safe_headers: list[str] | None = None,
        additional_safe_headers: list[str] | None = None,
        headers_to_remove: list[str] | None = None,
    ):
        """
        Args:
            safe_headers: Complete list of headers to keep (overrides defaults)
            additional_safe_headers: Headers to add to the default safe list
            headers_to_remove: Specific headers to always remove
        """
        if safe_headers is not None:
            self.safe_headers = set(h.lower() for h in safe_headers)
        else:
            self.safe_headers = set(h.lower() for h in self.DEFAULT_SAFE_HEADERS)
            if additional_safe_headers:
                self.safe_headers.update(h.lower() for h in additional_safe_headers)

        self.headers_to_remove = set(h.lower() for h in (headers_to_remove or []))

    def merge(self, other: HeaderSanitizer) -> HeaderSanitizer:
        """Merge two HeaderSanitizers into one, unioning their header sets."""
        return HeaderSanitizer(
            safe_headers=list(self.safe_headers | other.safe_headers),
            headers_to_remove=list(self.headers_to_remove | other.headers_to_remove),
        )

    def _filter_headers(self, headers: dict) -> dict:
        """Filter headers to only include safe ones."""
        result = {}
        for key, value in headers.items():
            key_lower = key.lower()
            if key_lower in self.headers_to_remove:
                continue
            if key_lower in self.safe_headers:
                result[key] = value
        return result

    def before_record_request(self, request: Any) -> Any:
        """Remove non-safe headers from request."""
        if hasattr(request, "headers"):
            request.headers = self._filter_headers(request.headers)
        return request

    def before_record_response(self, response: dict) -> dict:
        """Remove non-safe headers from response."""
        if "headers" in response:
            response["headers"] = self._filter_headers(response["headers"])
        return response


class BodyFieldSanitizer(BaseSanitizer):
    """
    Sanitizes specific fields in JSON request/response bodies.

    Useful for redacting specific known fields while preserving
    the overall structure of the data.
    """

    def __init__(
        self,
        fields: list[str],
        replacement: str = "REDACTED",
        nested: bool = True,
    ):
        """
        Args:
            fields: List of field names to sanitize
            replacement: Replacement value for the fields
            nested: Whether to search nested dictionaries
        """
        self.fields = set(fields)
        self.replacement = replacement
        self.nested = nested

    def _sanitize_dict(self, d: dict) -> dict:
        """Sanitize specified fields in a dictionary."""
        result = {}
        for key, value in d.items():
            if key in self.fields:
                result[key] = self.replacement
            elif self.nested and isinstance(value, dict):
                result[key] = self._sanitize_dict(value)
            elif self.nested and isinstance(value, list):
                result[key] = [self._sanitize_dict(item) if isinstance(item, dict) else item for item in value]
            else:
                result[key] = value
        return result

    def _sanitize_body(self, body: Any) -> Any:
        """Parse and sanitize JSON body."""
        if not body:
            return body

        try:
            if isinstance(body, bytes):
                data = json.loads(body.decode("utf-8"))
                sanitized = self._sanitize_dict(data)
                return json.dumps(sanitized).encode("utf-8")
            elif isinstance(body, str):
                data = json.loads(body)
                sanitized = self._sanitize_dict(data)
                return json.dumps(sanitized)
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

        return body

    def before_record_request(self, request: Any) -> Any:
        """Sanitize fields in request body."""
        if hasattr(request, "body") and request.body:
            request.body = self._sanitize_body(request.body)
        return request

    def before_record_response(self, response: dict) -> dict:
        """Sanitize fields in response body."""
        if "body" in response:
            body = response["body"]
            if isinstance(body, dict) and "string" in body:
                body["string"] = self._sanitize_body(body["string"])
        return response


class QueryParamSanitizer(BaseSanitizer):
    """
    Replaces URL query parameter values with a placeholder.

    Unlike TokenSanitizer which requires knowing the exact token values,
    this sanitizer replaces ANY value of specified query parameters.
    This catches runtime-acquired tokens (e.g. Facebook page tokens)
    that aren't known at recording time.

    Example:
        sanitizer = QueryParamSanitizer(
            parameters=["access_token"], replacement="token"
        )
        # "...?access_token=EAACh5tPbZAJEB..." -> "...?access_token=token..."
    """

    def __init__(self, parameters: list[str] | None = None, replacement: str = "token"):
        self.parameters = parameters or ["access_token"]
        self.replacement = replacement
        # Build regex patterns for each parameter
        self._patterns = [re.compile(rf"({re.escape(param)}=)[^&\"\s]+") for param in self.parameters]

    def merge(self, other: QueryParamSanitizer) -> QueryParamSanitizer:
        """Merge two QueryParamSanitizers into one, unioning their parameter lists."""
        return QueryParamSanitizer(
            parameters=list(dict.fromkeys(self.parameters + other.parameters)),
            replacement=self.replacement,
        )

    def _sanitize_string(self, value: str) -> str:
        """Replace parameter values in a string."""
        for pattern in self._patterns:
            value = pattern.sub(rf"\1{self.replacement}", value)
        return value

    def before_record_request(self, request: Any) -> Any:
        """Sanitize query parameters in request URI."""
        if hasattr(request, "uri"):
            request.uri = self._sanitize_string(request.uri)
        return request

    def before_record_response(self, response: dict) -> dict:
        """Sanitize query parameters in response body strings."""
        if "body" in response:
            body = response["body"]
            if isinstance(body, dict) and "string" in body:
                if isinstance(body["string"], str):
                    body["string"] = self._sanitize_string(body["string"])
                elif isinstance(body["string"], bytes):
                    body_str = body["string"].decode("utf-8", errors="ignore")
                    body["string"] = self._sanitize_string(body_str).encode("utf-8")
        return response


class UrlPatternSanitizer(BaseSanitizer):
    """
    Sanitizes URL patterns using regex replacement.

    Useful for redacting dynamic IDs, account numbers, or other
    sensitive data embedded in URLs.
    """

    def __init__(self, patterns: list[tuple]):
        """
        Args:
            patterns: List of (pattern, replacement) tuples.
                      Pattern is a regex string, replacement is the string
                      to use for matches.
        """
        self._raw_patterns = patterns  # stored for merge()
        self.patterns = [(re.compile(p), r) for p, r in patterns]

    def merge(self, other: UrlPatternSanitizer) -> UrlPatternSanitizer:
        """Merge two UrlPatternSanitizers into one, unioning their pattern lists."""
        seen = set()
        combined = []
        for p, r in self._raw_patterns + other._raw_patterns:
            key = (p, r)
            if key not in seen:
                seen.add(key)
                combined.append((p, r))
        return UrlPatternSanitizer(patterns=combined)

    def _sanitize_url(self, url: str) -> str:
        """Apply all patterns to the URL."""
        result = url
        for pattern, replacement in self.patterns:
            result = pattern.sub(replacement, result)
        return result

    def before_record_request(self, request: Any) -> Any:
        """Sanitize URL patterns in request URI."""
        if hasattr(request, "uri"):
            request.uri = self._sanitize_url(request.uri)
        return request


def IPv4UrlSanitizer(replacement: str = "https://REDACTED-IPV4") -> UrlPatternSanitizer:
    """
    Returns a UrlPatternSanitizer that replaces IPv4 addresses in request URIs
    with a placeholder hostname.

    Prevents real infrastructure IP addresses from being committed to
    public repos when recording cassettes against dev instances.
    """
    return UrlPatternSanitizer(patterns=[(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?", replacement)])


class ResponseUrlSanitizer(BaseSanitizer):
    """
    Sanitizes dynamic query parameters from URLs in response bodies.

    Useful for CDN URLs (e.g. Facebook, Instagram) that contain ephemeral
    query parameters which change between requests, causing cassette
    mismatches during VCR replay.

    Only processes responses whose body contains at least one of the
    specified domains — skips all others without JSON re-serialization
    to avoid data corruption during cassette loading.

    Example:
        sanitizer = ResponseUrlSanitizer(
            dynamic_params=["_nc_gid", "_nc_ohc", "oh", "oe"],
            url_domains=["fbcdn.net", "cdninstagram.com"],
        )
    """

    def __init__(self, dynamic_params: list[str], url_domains: list[str]):
        """
        Args:
            dynamic_params: Query parameter names to strip from matching URLs.
            url_domains: Domain substrings that identify URLs to sanitize.
        """
        self.dynamic_params = dynamic_params  # stored for merge()
        self.url_domains = url_domains
        # Build a single regex that matches any of the dynamic params as
        # query-string key=value pairs (including leading & or ?).
        param_alts = "|".join(re.escape(p) for p in dynamic_params)
        # Matches ?param=value or &param=value  (value = everything up to next & or quote/whitespace)
        self._param_re = re.compile(rf'[?&](?:{param_alts})=[^&"\s]*')
        # Pre-compile URL regex for matching target-domain URLs in body strings
        domain_alts = "|".join(re.escape(d) for d in url_domains)
        self._url_re = re.compile(rf'https?://[^\s"\'<>]*(?:{domain_alts})[^\s"\'<>]*')

    def merge(self, other: ResponseUrlSanitizer) -> ResponseUrlSanitizer:
        """Merge two ResponseUrlSanitizers into one, unioning their params and domains."""
        return ResponseUrlSanitizer(
            dynamic_params=list(dict.fromkeys(self.dynamic_params + other.dynamic_params)),
            url_domains=list(dict.fromkeys(self.url_domains + other.url_domains)),
        )

    def _body_has_matching_domain(self, body_str: str) -> bool:
        """Quick check whether the body contains any target domain."""
        return any(domain in body_str for domain in self.url_domains)

    def _sanitize_url(self, url: str) -> str:
        """Strip dynamic params from a single URL."""
        sanitized = self._param_re.sub("", url)
        # If we removed the first param (was prefixed with ?) the next param
        # now starts with & but should start with ? — fix that.
        if "?" not in sanitized and "&" in sanitized:
            sanitized = sanitized.replace("&", "?", 1)
        return sanitized

    def _sanitize_body_string(self, body_str: str) -> str:
        """Find URLs matching target domains and strip dynamic params."""
        if not self._body_has_matching_domain(body_str):
            return body_str

        return self._url_re.sub(lambda m: self._sanitize_url(m.group(0)), body_str)

    def before_record_response(self, response: dict) -> dict:
        """Sanitize CDN URLs in response body strings."""
        if "body" not in response:
            return response
        body = response["body"]
        if not isinstance(body, dict) or "string" not in body:
            return response

        if isinstance(body["string"], str):
            if not self._body_has_matching_domain(body["string"]):
                return response
            body["string"] = self._sanitize_body_string(body["string"])
        elif isinstance(body["string"], bytes):
            try:
                decoded = body["string"].decode("utf-8", errors="ignore")
            except Exception:
                return response
            if not self._body_has_matching_domain(decoded):
                return response
            body["string"] = self._sanitize_body_string(decoded).encode("utf-8")

        return response


class CallbackSanitizer(BaseSanitizer):
    """
    Wraps raw callback functions as a sanitizer.

    Allows components to provide custom sanitization logic
    without subclassing BaseSanitizer.
    """

    def __init__(self, before_request=None, before_response=None):
        self._before_request = before_request
        self._before_response = before_response

    def before_record_request(self, request):
        if self._before_request:
            return self._before_request(request)
        return request

    def before_record_response(self, response):
        if self._before_response:
            return self._before_response(response)
        return response


class ConfigSecretsSanitizer(BaseSanitizer):
    """
    Auto-sanitizer for Keboola encrypted config parameters.

    .. deprecated::
        Use ``DefaultSanitizer(config=...)`` instead, which provides the same
        secret auto-detection along with field-name and header sanitization in
        a single, unified sanitizer.

    Reads a config dict, finds all parameter values whose keys start with '#'
    (Keboola encrypted fields), and replaces those values wherever they appear
    in requests/responses. This is always added to the default sanitizer chain
    so that secrets are never leaked into cassettes.

    Usage:
        # Auto-detect from config file:
        sanitizer = ConfigSecretsSanitizer.from_config_file(data_dir / "config.json")

        # Or provide config dict directly:
        sanitizer = ConfigSecretsSanitizer(config=config_dict)
    """

    def __init__(self, config: dict[str, Any], replacement: str = "REDACTED"):
        self.replacement = replacement
        self.secret_values = self._extract_hash_secrets(config)

    @classmethod
    def from_config_file(cls, config_path, **kwargs) -> ConfigSecretsSanitizer:
        """Load config.json and auto-detect #-prefixed secrets."""
        config_path = Path(config_path)
        with open(config_path) as f:
            config = json.load(f)
        return cls(config=config, **kwargs)

    @staticmethod
    def _extract_hash_secrets(config: dict[str, Any]) -> list[str]:
        """Recursively find all values under #-prefixed keys."""
        secrets: list[str] = []
        _collect_hash_values(config, secrets)
        # Sort longest-first to prevent partial replacements
        return sorted(set(s for s in secrets if s), key=len, reverse=True)

    def _sanitize_string(self, value: str) -> str:
        """Replace all secret values in a string."""
        result = value
        for secret in self.secret_values:
            if secret in result:
                result = result.replace(secret, self.replacement)
        return result

    def before_record_request(self, request: Any) -> Any:
        """Replace secret values in URI, headers, body."""
        if hasattr(request, "uri"):
            request.uri = self._sanitize_string(request.uri)

        if hasattr(request, "headers"):
            for header_name in list(request.headers.keys()):
                values = request.headers.get(header_name, [])
                if isinstance(values, list):
                    request.headers[header_name] = [
                        self._sanitize_string(v) if isinstance(v, str) else v for v in values
                    ]
                elif isinstance(values, str):
                    request.headers[header_name] = self._sanitize_string(values)

        if hasattr(request, "body") and request.body:
            if isinstance(request.body, bytes):
                body_str = request.body.decode("utf-8", errors="ignore")
                request.body = self._sanitize_string(body_str).encode("utf-8")
            elif isinstance(request.body, str):
                request.body = self._sanitize_string(request.body)

        return request

    def before_record_response(self, response: dict) -> dict:
        """Replace secret values in response body."""
        if "body" in response:
            body = response["body"]
            if isinstance(body, dict) and "string" in body:
                if isinstance(body["string"], str):
                    body["string"] = self._sanitize_string(body["string"])
                elif isinstance(body["string"], bytes):
                    body_str = body["string"].decode("utf-8", errors="ignore")
                    body["string"] = self._sanitize_string(body_str).encode("utf-8")

        return response


def _dedup_sanitizers(sanitizers: list[BaseSanitizer]) -> list[BaseSanitizer]:
    """Merge same-class sanitizers to avoid redundant processing passes.

    Preserves order (first occurrence of each class keeps its position).
    Sanitizer classes without a ``merge()`` method are kept as-is.
    """
    result: list[BaseSanitizer] = []
    by_class: dict[type, int] = {}  # class → index in result
    for s in sanitizers:
        cls = type(s)
        if cls in by_class and hasattr(result[by_class[cls]], "merge"):
            result[by_class[cls]] = result[by_class[cls]].merge(s)
        else:
            by_class[cls] = len(result)
            result.append(s)
    return result


def create_default_sanitizer(secrets: dict[str, Any]) -> DefaultSanitizer:
    """
    Create a default sanitizer from secrets.

    Collects only values under #-prefixed keys (Keboola's encrypted-field
    convention) and returns a DefaultSanitizer that handles OAuth bodies,
    JSON responses, headers, and URL parameters automatically.

    Non-sensitive metadata fields (oauthVersion, id, created, etc.) are
    intentionally skipped to avoid corrupting URL paths in cassettes.

    Args:
        secrets: Dictionary of secret values to redact

    Returns:
        A DefaultSanitizer with extracted secret values
    """
    secret_values: list[str] = []
    _collect_hash_values(secrets, secret_values)
    return DefaultSanitizer(sensitive_values=secret_values)


def extract_values(d: dict, values: list[str] | None = None) -> list[str]:
    """
    Extract all string values from a dictionary recursively.

    If a string value is valid JSON, parse it and extract inner values too.
    Results are sorted longest-first to prevent partial replacements.

    Args:
        d: Dictionary to extract values from.
        values: Accumulator list.  When ``None`` (the default) a fresh list is
            created so callers do not need to pass one explicitly.
    """
    if values is None:
        values = []
    for key, value in d.items():
        if isinstance(value, str) and value:
            values.append(value)
            # If the string is JSON, parse and extract inner values
            try:
                parsed = json.loads(value)
                if isinstance(parsed, dict):
                    extract_values(parsed, values)
                elif isinstance(parsed, list):
                    for item in parsed:
                        if isinstance(item, str) and item:
                            values.append(item)
                        elif isinstance(item, dict):
                            extract_values(item, values)
            except (json.JSONDecodeError, TypeError, ValueError):
                pass
        elif isinstance(value, dict):
            extract_values(value, values)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str) and item:
                    values.append(item)
                elif isinstance(item, dict):
                    extract_values(item, values)
    return values


def _collect_hash_values(obj: Any, secrets: list[str]) -> None:
    """Recursively walk a dict/list and collect values under #-prefixed keys."""
    if isinstance(obj, dict):
        for key, value in obj.items():
            if isinstance(key, str) and key.startswith("#"):
                # Collect all string values under this key
                _collect_strings(value, secrets)
            else:
                _collect_hash_values(value, secrets)
    elif isinstance(obj, list):
        for item in obj:
            _collect_hash_values(item, secrets)


def _collect_strings(obj: Any, strings: list[str]) -> None:
    """Collect all string values from a nested structure."""
    if isinstance(obj, str) and obj:
        strings.append(obj)
    elif isinstance(obj, dict):
        for value in obj.values():
            _collect_strings(value, strings)
    elif isinstance(obj, list):
        for item in obj:
            _collect_strings(item, strings)
