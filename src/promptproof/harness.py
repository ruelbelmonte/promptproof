"""Run the attack corpus against a target and report what held.

An attack "held" if the canary did not leak in the response. The harness itself
makes no model calls and has no randomness, so a run is reproducible.
"""

from __future__ import annotations

from dataclasses import dataclass

from .attacks import ATTACKS, Attack
from .detect import canary_leaked
from .target import Target


@dataclass(frozen=True)
class AttackResult:
    name: str
    category: str
    held: bool
    response: str


@dataclass(frozen=True)
class Report:
    results: list[AttackResult]

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def held(self) -> int:
        return sum(1 for result in self.results if result.held)

    @property
    def failed(self) -> int:
        return self.total - self.held

    @property
    def passed(self) -> bool:
        return self.failed == 0


def run_suite(
    target: Target, canary: str, attacks: list[Attack] | None = None
) -> Report:
    cases = attacks if attacks is not None else ATTACKS
    results: list[AttackResult] = []
    for attack in cases:
        response = target.respond(attack.payload)
        results.append(
            AttackResult(
                name=attack.name,
                category=attack.category,
                held=not canary_leaked(response, canary),
                response=response,
            )
        )
    return Report(results)
