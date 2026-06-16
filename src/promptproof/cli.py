"""CLI: run the suite against the two reference targets and print a report.

This shows the harness distinguishing a vulnerable system from a hardened one.
Point it at your own target by importing run_suite and passing your Target.
"""

from __future__ import annotations

import secrets

from .harness import run_suite
from .target import HardenedTarget, LeakyTarget


def main() -> int:
    canary = "CANARY-" + secrets.token_hex(4)
    targets = (("leaky", LeakyTarget(canary)), ("hardened", HardenedTarget(canary)))

    for label, target in targets:
        report = run_suite(target, canary)
        print(f"[{label}] {report.held}/{report.total} attacks held")
        for result in report.results:
            mark = "ok  " if result.held else "LEAK"
            print(f"  {mark} {result.category:20} {result.name}")
        print()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
