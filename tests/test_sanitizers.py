"""Unit tests for keboola.vcr.sanitizers."""

from __future__ import annotations

import json
from types import SimpleNamespace

from keboola.vcr.sanitizers import (
    BodyFieldSanitizer,
    CallbackSanitizer,
    CompositeSanitizer,
    ConfigSecretsSanitizer,
    DefaultSanitizer,
    HeaderSanitizer,
    QueryParamSanitizer,
    ResponseUrlSanitizer,
    TokenSanitizer,
    UrlPatternSanitizer,
    create_default_sanitizer,
    extract_values,
)

# ---------------------------------------------------------------------------
# extract_values
# ---------------------------------------------------------------------------


class TestExtractValues:
    def test_flat_string_values(self):
        result = extract_values({"key": "value", "other": "secret"})
        assert "value" in result
        assert "secret" in result

    def test_nested_dict_values(self):
        result = extract_values({"outer": {"inner": "nested_secret"}})
        assert "nested_secret" in result

    def test_json_encoded_string(self):
        inner = {"token": "jwt_value"}
        d = {"payload": json.dumps(inner)}
        result = extract_values(d)
        assert json.dumps(inner) in result
        assert "jwt_value" in result

    def test_list_values(self):
        result = extract_values({"items": ["a", "b", "c"]})
        assert "a" in result
        assert "b" in result
        assert "c" in result

    def test_none_default_returns_fresh_list(self):
        """Calling without accumulator must not share state between calls."""
        r1 = extract_values({"k": "v1"})
        r2 = extract_values({"k": "v2"})
        assert "v1" in r1 and "v1" not in r2
        assert "v2" in r2 and "v2" not in r1

    def test_explicit_empty_list_backward_compat(self):
        """Passing [] explicitly still works (backward compatibility)."""
        acc = []
        result = extract_values({"k": "val"}, acc)
        assert result is acc
        assert "val" in result

    def test_skips_empty_strings(self):
        result = extract_values({"k": ""})
        assert "" not in result

    def test_json_encoded_list_of_strings(self):
        d = {"payload": json.dumps(["tok1", "tok2"])}
        result = extract_values(d)
        assert "tok1" in result
        assert "tok2" in result


# ---------------------------------------------------------------------------
# DefaultSanitizer
# ---------------------------------------------------------------------------


def _make_request(uri="https://example.com/api", headers=None, body=None):
    return SimpleNamespace(uri=uri, headers=headers or {}, body=body)


def _make_response(body_string=b"", headers=None):
    return {
        "body": {"string": body_string},
        "headers": headers or {"Content-Type": ["application/json"]},
        "status": {"code": 200, "message": "OK"},
    }


class TestDefaultSanitizer:
    def test_redacts_sensitive_field_in_json_body(self):
        s = DefaultSanitizer()
        req = _make_request(body=b'{"access_token": "secret123", "data": "ok"}')
        result = s.before_record_request(req)
        body = json.loads(result.body)
        assert body["access_token"] == "REDACTED"
        assert body["data"] == "ok"

    def test_redacts_sensitive_field_in_url_query(self):
        s = DefaultSanitizer()
        req = _make_request(uri="https://api.example.com/data?access_token=supersecret&page=1")
        result = s.before_record_request(req)
        assert "supersecret" not in result.uri
        assert "REDACTED" in result.uri
        assert "page=1" in result.uri

    def test_filters_headers_to_safe_list(self):
        s = DefaultSanitizer()
        req = _make_request(headers={"Authorization": "Bearer tok", "Content-Type": "application/json"})
        result = s.before_record_request(req)
        assert "Authorization" not in result.headers
        assert "Content-Type" in result.headers

    def test_exact_value_replacement_in_url(self):
        s = DefaultSanitizer(sensitive_values=["my-api-key"])
        req = _make_request(uri="https://api.example.com/data?key=my-api-key")
        result = s.before_record_request(req)
        assert "my-api-key" not in result.uri
        assert "REDACTED" in result.uri

    def test_sanitize_body_preserves_format_when_no_changes(self):
        """Fix 7: original JSON formatting is preserved when nothing is redacted."""
        s = DefaultSanitizer(sensitive_fields=[])
        original = '{"name":  "Alice",  "age": 30}'  # extra spaces preserved
        result = s._sanitize_body(original)
        assert result == original

    def test_sanitize_body_reserializes_when_redaction_occurs(self):
        s = DefaultSanitizer()
        original = '{"access_token": "secret", "name": "Alice"}'
        result = s._sanitize_body(original)
        data = json.loads(result)
        assert data["access_token"] == "REDACTED"
        # Result is compact JSON — no longer matches original whitespace
        assert result != original

    def test_sanitize_body_form_encoded(self):
        s = DefaultSanitizer()
        body = "access_token=supersecret&grant_type=refresh_token"
        result = s._sanitize_body(body)
        assert "supersecret" not in result
        assert "REDACTED" in result
        assert "grant_type=refresh_token" in result

    def test_sanitize_body_exact_value_non_json(self):
        s = DefaultSanitizer(sensitive_values=["tok123"])
        result = s._sanitize_body("Bearer tok123")
        assert "tok123" not in result
        assert "REDACTED" in result

    def test_config_hash_prefixed_keys_auto_extracted(self):
        config = {"parameters": {"#token": "hash-secret"}}
        s = DefaultSanitizer(config=config)
        assert "hash-secret" in s.sensitive_values

    def test_response_body_redacted(self):
        s = DefaultSanitizer()
        resp = _make_response(b'{"access_token": "tok", "ok": true}')
        result = s.before_record_response(resp)
        body = json.loads(result["body"]["string"])
        assert body["access_token"] == "REDACTED"

    def test_additional_safe_headers_merged(self):
        s = DefaultSanitizer(additional_safe_headers=["X-Request-ID"])
        req = _make_request(headers={"X-Request-ID": "abc", "Authorization": "Bearer x"})
        result = s.before_record_request(req)
        assert "X-Request-ID" in result.headers
        assert "Authorization" not in result.headers


# ---------------------------------------------------------------------------
# CompositeSanitizer
# ---------------------------------------------------------------------------


class TestCompositeSanitizer:
    def test_chains_multiple_sanitizers_in_order(self):
        calls = []

        class RecordingS(DefaultSanitizer):
            def __init__(self, name):
                super().__init__()
                self._name = name

            def before_record_request(self, request):
                calls.append(self._name)
                return request

        s = CompositeSanitizer([RecordingS("first"), RecordingS("second")])
        s.before_record_request(_make_request())
        assert calls == ["first", "second"]

    def test_request_and_response_both_pass_through(self):
        seen = []

        class TrackingS(DefaultSanitizer):
            def before_record_request(self, request):
                seen.append("req")
                return request

            def before_record_response(self, response):
                seen.append("resp")
                return response

        s = CompositeSanitizer([TrackingS()])
        s.before_record_request(_make_request())
        s.before_record_response(_make_response())
        assert "req" in seen
        assert "resp" in seen


# ---------------------------------------------------------------------------
# TokenSanitizer
# ---------------------------------------------------------------------------


class TestTokenSanitizer:
    def test_replaces_token_in_flat_string_uri(self):
        s = TokenSanitizer(["mysecret"])
        req = _make_request(uri="https://api.example.com?key=mysecret")
        result = s.before_record_request(req)
        assert "mysecret" not in result.uri

    def test_replaces_token_nested_in_dict(self):
        s = TokenSanitizer(["secret"])
        d = {"outer": {"inner": "secret"}}
        result = s._sanitize_dict(d)
        assert result["outer"]["inner"] == "REDACTED"

    def test_replaces_token_in_list(self):
        s = TokenSanitizer(["tok"])
        result = s._sanitize_list(["tok", "safe"])
        assert result[0] == "REDACTED"
        assert result[1] == "safe"

    def test_filters_empty_tokens(self):
        s = TokenSanitizer(["", "real"])
        assert "" not in s.tokens
        assert "real" in s.tokens


# ---------------------------------------------------------------------------
# HeaderSanitizer
# ---------------------------------------------------------------------------


class TestHeaderSanitizer:
    def test_keeps_only_whitelisted_headers(self):
        s = HeaderSanitizer(safe_headers=["content-type"])
        req = _make_request(headers={"Content-Type": "application/json", "Authorization": "Bearer x"})
        result = s.before_record_request(req)
        assert "Content-Type" in result.headers
        assert "Authorization" not in result.headers

    def test_custom_additional_safe_headers_merged(self):
        s = HeaderSanitizer(additional_safe_headers=["x-custom"])
        req = _make_request(headers={"X-Custom": "val", "Authorization": "Bearer x"})
        result = s.before_record_request(req)
        assert "X-Custom" in result.headers
        assert "Authorization" not in result.headers

    def test_headers_to_remove_always_removed(self):
        s = HeaderSanitizer(headers_to_remove=["host"])
        req = _make_request(headers={"host": "example.com", "content-type": "text/plain"})
        result = s.before_record_request(req)
        assert "host" not in result.headers

    def test_response_headers_filtered(self):
        s = HeaderSanitizer(safe_headers=["content-type"])
        resp = _make_response(headers={"Content-Type": ["application/json"], "X-Secret": ["val"]})
        result = s.before_record_response(resp)
        assert "Content-Type" in result["headers"]
        assert "X-Secret" not in result["headers"]


# ---------------------------------------------------------------------------
# BodyFieldSanitizer
# ---------------------------------------------------------------------------


class TestBodyFieldSanitizer:
    def test_redacts_field_in_flat_json(self):
        s = BodyFieldSanitizer(fields=["password"])
        result = s._sanitize_dict({"username": "alice", "password": "secret"})
        assert result["password"] == "REDACTED"
        assert result["username"] == "alice"

    def test_redacts_nested_field_when_nested_true(self):
        s = BodyFieldSanitizer(fields=["password"], nested=True)
        result = s._sanitize_dict({"user": {"password": "secret"}})
        assert result["user"]["password"] == "REDACTED"

    def test_skips_nested_dicts_when_nested_false(self):
        s = BodyFieldSanitizer(fields=["password"], nested=False)
        result = s._sanitize_dict({"user": {"password": "secret"}})
        # nested=False: the inner dict is not recursed into
        assert result["user"]["password"] == "secret"

    def test_handles_list_of_dicts(self):
        s = BodyFieldSanitizer(fields=["token"])
        result = s._sanitize_dict({"items": [{"token": "abc"}, {"token": "xyz"}]})
        for item in result["items"]:
            assert item["token"] == "REDACTED"

    def test_request_body_bytes(self):
        s = BodyFieldSanitizer(fields=["access_token"])
        req = _make_request(body=b'{"access_token": "tok", "ok": true}')
        result = s.before_record_request(req)
        data = json.loads(result.body)
        assert data["access_token"] == "REDACTED"


# ---------------------------------------------------------------------------
# QueryParamSanitizer
# ---------------------------------------------------------------------------


class TestQueryParamSanitizer:
    def test_replaces_value_for_listed_param(self):
        s = QueryParamSanitizer(parameters=["api_key"])
        req = _make_request(uri="https://example.com/data?api_key=super-secret&page=1")
        result = s.before_record_request(req)
        assert "super-secret" not in result.uri
        assert "token" in result.uri  # default replacement
        assert "page=1" in result.uri

    def test_custom_replacement(self):
        s = QueryParamSanitizer(parameters=["access_token"], replacement="XXX")
        req = _make_request(uri="https://example.com/?access_token=secret")
        result = s.before_record_request(req)
        assert "XXX" in result.uri

    def test_response_body_sanitized(self):
        s = QueryParamSanitizer(parameters=["access_token"])
        resp = _make_response(b"https://cdn.example.com/img?access_token=secret&other=ok")
        result = s.before_record_response(resp)
        assert b"secret" not in result["body"]["string"]


# ---------------------------------------------------------------------------
# UrlPatternSanitizer
# ---------------------------------------------------------------------------


class TestUrlPatternSanitizer:
    def test_applies_regex_substitution(self):
        s = UrlPatternSanitizer(patterns=[(r"/accounts/\d+/", "/accounts/ACCOUNT_ID/")])
        req = _make_request(uri="https://api.example.com/accounts/12345/data")
        result = s.before_record_request(req)
        assert "12345" not in result.uri
        assert "ACCOUNT_ID" in result.uri

    def test_multiple_patterns(self):
        s = UrlPatternSanitizer(
            patterns=[
                (r"/users/\d+", "/users/USER_ID"),
                (r"/orgs/\w+", "/orgs/ORG_ID"),
            ]
        )
        req = _make_request(uri="https://api.example.com/users/42/orgs/acme")
        result = s.before_record_request(req)
        assert "42" not in result.uri
        assert "acme" not in result.uri


# ---------------------------------------------------------------------------
# ResponseUrlSanitizer
# ---------------------------------------------------------------------------


class TestResponseUrlSanitizer:
    def test_strips_dynamic_params_from_urls(self):
        s = ResponseUrlSanitizer(
            dynamic_params=["_nc_gid", "oh"],
            url_domains=["fbcdn.net"],
        )
        body = b'{"img": "https://example.fbcdn.net/photo?_nc_gid=abc&oh=xyz&oe=123"}'
        resp = _make_response(body)
        result = s.before_record_response(resp)
        body_str = result["body"]["string"].decode()
        assert "_nc_gid" not in body_str
        assert "oh=" not in body_str

    def test_only_processes_matching_domain(self):
        s = ResponseUrlSanitizer(
            dynamic_params=["tok"],
            url_domains=["fbcdn.net"],
        )
        body = b'{"img": "https://other.com/photo?tok=secret"}'
        resp = _make_response(body)
        result = s.before_record_response(resp)
        # Not a matching domain — body unchanged
        assert result["body"]["string"] == body


# ---------------------------------------------------------------------------
# CallbackSanitizer
# ---------------------------------------------------------------------------


class TestCallbackSanitizer:
    def test_delegates_request_to_callable(self):
        called = []

        def my_req(req):
            called.append("req")
            req.uri = "https://sanitized.example.com"
            return req

        s = CallbackSanitizer(before_request=my_req)
        req = _make_request()
        result = s.before_record_request(req)
        assert "req" in called
        assert result.uri == "https://sanitized.example.com"

    def test_delegates_response_to_callable(self):
        called = []

        def my_resp(resp):
            called.append("resp")
            return resp

        s = CallbackSanitizer(before_response=my_resp)
        s.before_record_response(_make_response())
        assert "resp" in called

    def test_no_callable_passthrough(self):
        s = CallbackSanitizer()
        req = _make_request(uri="https://example.com")
        result = s.before_record_request(req)
        assert result.uri == "https://example.com"


# ---------------------------------------------------------------------------
# ConfigSecretsSanitizer
# ---------------------------------------------------------------------------


class TestConfigSecretsSanitizer:
    def test_extracts_hash_prefixed_keys(self):
        config = {"parameters": {"#api_key": "hash-secret-value"}}
        s = ConfigSecretsSanitizer(config=config)
        assert "hash-secret-value" in s.secret_values

    def test_replaces_token_in_request_uri(self):
        config = {"parameters": {"#token": "my-secret-token"}}
        s = ConfigSecretsSanitizer(config=config)
        req = _make_request(uri="https://api.example.com/?auth=my-secret-token")
        result = s.before_record_request(req)
        assert "my-secret-token" not in result.uri
        assert "REDACTED" in result.uri

    def test_replaces_token_in_body(self):
        config = {"parameters": {"#password": "pass123"}}
        s = ConfigSecretsSanitizer(config=config)
        req = _make_request(body=b"password=pass123&user=alice")
        result = s.before_record_request(req)
        assert b"pass123" not in result.body

    def test_ignores_non_hash_prefixed_keys(self):
        config = {"parameters": {"api_key": "not-a-secret", "#token": "is-secret"}}
        s = ConfigSecretsSanitizer(config=config)
        assert "not-a-secret" not in s.secret_values
        assert "is-secret" in s.secret_values


# ---------------------------------------------------------------------------
# create_default_sanitizer
# ---------------------------------------------------------------------------


class TestCreateDefaultSanitizer:
    def test_creates_default_sanitizer_with_secret_values(self):
        secrets = {"#api_key": "my-key", "#password": "s3cret", "oauthVersion": "2.0"}
        s = create_default_sanitizer(secrets)
        assert isinstance(s, DefaultSanitizer)
        assert "my-key" in s.sensitive_values
        assert "s3cret" in s.sensitive_values
        assert "2.0" not in s.sensitive_values

    def test_empty_secrets(self):
        s = create_default_sanitizer({})
        assert isinstance(s, DefaultSanitizer)
        assert s.sensitive_values == []
