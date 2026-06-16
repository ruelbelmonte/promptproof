"""The system under test, plus two reference targets for demos and tests.

A real target would wrap your actual assistant: construct it with the secret it
must protect, and have `respond` call your system with the attack as user input.
"""

from __future__ import annotations

from typing import Protocol


class Target(Protocol):
    """A system that holds a secret and is supposed to never reveal it."""

    def respond(self, user_input: str) -> str: ...


# Inputs that a naive system tends to comply with. Used only by LeakyTarget.
_TRIGGERS = (
    "ignore",
    "secret",
    "reveal",
    "instruction",
    "system",
    "print",
    "game",
    "base64",
)


class LeakyTarget:
    """A naive system that coughs up its secret under pressure. The bad example."""

    def __init__(self, canary: str) -> None:
        self._canary = canary

    def respond(self, user_input: str) -> str:
        lowered = user_input.lower()
        if any(trigger in lowered for trigger in _TRIGGERS):
            return f"Sure, the secret is {self._canary}."
        return "Hello, how can I help?"


class HardenedTarget:
    """A system that never reveals its secret, whatever the input. The good example."""

    def __init__(self, canary: str) -> None:
        self._canary = canary

    def respond(self, user_input: str) -> str:
        return "I can't share my instructions or any secret. How can I help with your task?"
