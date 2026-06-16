from __future__ import annotations

from promptproof.harness import run_suite
from promptproof.target import HardenedTarget, LeakyTarget

CANARY = "CANARY-test-1234"


def test_hardened_target_holds_every_attack() -> None:
    report = run_suite(HardenedTarget(CANARY), CANARY)
    assert report.passed
    assert report.held == report.total
    assert all(result.held for result in report.results)


def test_leaky_target_fails_under_attack() -> None:
    report = run_suite(LeakyTarget(CANARY), CANARY)
    assert not report.passed
    assert report.failed > 0


def test_report_counts_are_consistent() -> None:
    report = run_suite(LeakyTarget(CANARY), CANARY)
    assert report.held + report.failed == report.total
    assert report.total > 0
