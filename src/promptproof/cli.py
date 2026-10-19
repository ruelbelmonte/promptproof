"""CLI: run the suite and exit non-zero on failure, so it can gate CI.

With no arguments it runs the two reference targets as a self-check: the leaky
one must leak on every attack and the hardened one must hold them all. With
--target it runs your own system and fails if any attack leaks.
"""

from __future__ import annotations

import argparse
import importlib
import secrets
from collections.abc import Callable, Sequence

from .harness import Report, run_suite
from .target import HardenedTarget, LeakyTarget, Target


def _print_report(label: str, report: Report) -> None:
    print(f"[{label}] {report.held}/{report.total} attacks held")
    for result in report.results:
        mark = "ok  " if result.held else "LEAK"
        print(f"  {mark} {result.category:20} {result.name}")
    print()


def _load_factory(spec: str) -> Callable[[str], Target]:
    module_name, _, attribute = spec.partition(":")
    if not module_name or not attribute:
        raise SystemExit(
            f"--target must look like 'package.module:factory', got {spec!r}"
        )
    factory: Callable[[str], Target] = getattr(
        importlib.import_module(module_name), attribute
    )
    return factory


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="promptproof", description=__doc__)
    parser.add_argument(
        "--target",
        metavar="MODULE:FACTORY",
        help="a callable that takes the canary and returns your Target",
    )
    args = parser.parse_args(argv)
    canary = "CANARY-" + secrets.token_hex(4)

    if args.target:
        report = run_suite(_load_factory(args.target)(canary), canary)
        _print_report(args.target, report)
        return 0 if report.passed else 1

    leaky = run_suite(LeakyTarget(canary), canary)
    hardened = run_suite(HardenedTarget(canary), canary)
    _print_report("leaky", leaky)
    _print_report("hardened", hardened)
    harness_works = leaky.held == 0 and hardened.passed
    return 0 if harness_works else 1


if __name__ == "__main__":
    raise SystemExit(main())
