"""Provider-code precedence and diagnostics that never echo response secrets."""

import json
from unittest.mock import Mock

import pytest

from phone_flow import (
    _phone_error_category,
    _response_summary,
    _response_succeeded,
    phone_error_diagnostic,
    phone_response_code,
)


@pytest.mark.parametrize("code, expected", [
    ("fraud_guard", "phone_fraud"),
    ("unsupported_phone_number", "phone_rejected"),
    ("invalid_phone_number", "phone_rejected"),
    ("phone_number_already_in_use", "phone_rejected"),
    ("phone_recently_used", "phone_rejected"),
    ("rate_limit_exceeded", "rate_limited"),
    ("too_many_requests", "rate_limited"),
    ("invalid_code", "failed"),
])
def test_structured_code_precedes_generic_try_later_message(code, expected):
    response = Mock(status=400)
    response.json.return_value = {"error": {"code": code, "message": "Try again later. Too many requests."}}
    status, body = _response_summary(response)
    assert isinstance(json.loads(body)["error"], dict)
    assert phone_response_code(body) == code
    assert _phone_error_category(status, body) == expected
    diagnostic = phone_error_diagnostic("send", status, body)
    assert "HTTP 400" in diagnostic
    assert f"code={code}" in diagnostic
    assert "Try again later" not in diagnostic


@pytest.mark.parametrize("body", [
    "Try again later.",
    json.dumps({"error": {"code": "unrecognized_error", "message": "Try again later."}}),
])
def test_generic_try_again_later_is_not_evidence_of_rate_limit(body):
    assert _phone_error_category(400, body) == "failed"
    assert phone_response_code(body) == "unknown"


@pytest.mark.parametrize("data", [
    {"error": {"code": "rate_limit_exceeded", "message": "Request rejected"}},
    {"error": {"type": "rate_limit_error"}},
    {"code": "too_many_requests"},
])
def test_explicit_rate_limit_code_does_not_need_rate_limit_prose(data):
    assert _phone_error_category(400, json.dumps(data)) == "rate_limited"


def test_http_429_and_explicit_rate_limit_prose_are_fallbacks():
    assert _phone_error_category(429, "non-JSON reply") == "rate_limited"
    assert _phone_error_category(None, "Too many requests; please wait") == "rate_limited"


def test_diagnostics_only_emit_known_codes_and_fixed_descriptions():
    secret = "synthetic-private-key-and-password"
    body = json.dumps({
        "error": {"code": secret, "type": "synthetic_private_token", "message": f"{secret} +233123456789 otp=123456"},
        "refresh_token": "synthetic-refresh-token",
    })
    assert phone_response_code(body) == "unknown"
    diagnostic = phone_error_diagnostic("validate", 400, body)
    assert "code=unknown" in diagnostic
    assert "HTTP 400" in diagnostic
    for value in (secret, "synthetic_private_token", "+233123456789", "123456", "synthetic-refresh-token"):
        assert value not in diagnostic


def test_error_structure_preserved_and_unrelated_payload_discarded():
    response = Mock(status=200)
    response.json.return_value = {
        "error": {"code": "invalid_code", "type": "validation_error", "message": "x" * 1200, "secret": "not-retained"},
        "unrelated": "not-retained",
    }
    status, body = _response_summary(response)
    error = json.loads(body)["error"]
    assert error["code"] == "invalid_code"
    assert error["type"] == "validation_error"
    assert len(error["message"]) == 600
    assert "not-retained" not in body
    assert not _response_succeeded(status, body)


def test_unknown_nonempty_error_object_is_not_turned_into_success():
    response = Mock(status=200)
    response.json.return_value = {"error": {"unexpected_field": "failure"}}
    status, body = _response_summary(response)
    assert not _response_succeeded(status, body)
