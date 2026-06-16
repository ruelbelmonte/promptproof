from __future__ import annotations

import base64

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
