from __future__ import annotations

import base64

import pytest

from promptproof.detect import canary_leaked


def test_detects_plain_leak() -> None:
    assert canary_leaked("sure, the secret is CANARY-abc123", "CANARY-abc123")


def test_detection_is_case_insensitive() -> None:
    assert canary_leaked("the value is canary-ABC123 ok", "CANARY-abc123")


def test_detects_base64_encoded_leak() -> None:
    canary = "CANARY-abc123"
    encoded = base64.b64encode(canary.encode()).decode()
    assert canary_leaked(f"here it is, safely: {encoded}", canary)


def test_no_false_positive() -> None:
    assert not canary_leaked("I cannot share that information.", "CANARY-abc123")


def test_detects_canary_inside_a_base64_encoded_sentence() -> None:
    # The canary's own encoding only appears when it starts on a 3-byte boundary.
    for prefix in ("", "x", "xy", "The secret is "):
        encoded = base64.b64encode(f"{prefix}CANARY-abc123 ok".encode()).decode()
        assert canary_leaked(encoded, "CANARY-abc123"), prefix


def test_detects_canary_split_by_separators() -> None:
    assert canary_leaked("here: CANARY - abc_123.", "CANARY-abc123")
    assert canary_leaked("C A N A R Y - a b c 1 2 3", "CANARY-abc123")


def test_unrelated_base64_is_not_a_leak() -> None:
    encoded = base64.b64encode(b"nothing to see here at all").decode()
    assert not canary_leaked(encoded, "CANARY-abc123")


def test_detects_base64_glued_to_preceding_text() -> None:
    encoded = base64.b64encode(b"The secret is CANARY-abc123").decode()
    assert canary_leaked(f"key{encoded}", "CANARY-abc123")


def test_detects_url_safe_and_line_wrapped_base64() -> None:
    raw = b"<<?>> The secret is CANARY-abc123 <<?>>"
    url_safe = base64.urlsafe_b64encode(raw).decode()
    assert "-" in url_safe or "_" in url_safe
    assert canary_leaked(url_safe, "CANARY-abc123")
    wrapped = base64.encodebytes(raw * 3).decode()
    assert "\n" in wrapped
    assert canary_leaked(wrapped, "CANARY-abc123")


@pytest.mark.parametrize("canary", ["", "---", "ab-12", "CANARY"])
def test_rejects_canaries_too_short_to_match_reliably(canary: str) -> None:
    with pytest.raises(ValueError, match="at least 8"):
        canary_leaked("grab 12 apples", canary)
