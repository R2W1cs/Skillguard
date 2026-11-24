"""Secret redaction tests."""

from __future__ import annotations

from skillguard.reporting.redaction import assert_no_raw_secret, redact_text


def test_redact_openai_style_key() -> None:
    raw = "token=sk-ABCDEFGHIJKLMNOPQRSTUVWX"
    out = redact_text(raw)
    assert "sk-ABCDEFGHIJKLMNOPQRSTUVWX" not in out
    assert "REDACTED" in out


def test_redact_private_key() -> None:
    raw = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKFAKE\n-----END RSA PRIVATE KEY-----"
    out = redact_text(raw)
    assert "MIIEowIBAAKFAKE" not in out
    assert "REDACTED_PRIVATE_KEY" in out


def test_assert_helper() -> None:
    assert_no_raw_secret("safe", ["secret-value"])
    try:
        assert_no_raw_secret("has secret-value here", ["secret-value"])
        raised = False
    except AssertionError:
        raised = True
    assert raised
