from __future__ import annotations

import sys
import types

import pytest

from promptproof.cli import main
from promptproof.target import HardenedTarget, LeakyTarget


@pytest.fixture
def targets_module(monkeypatch: pytest.MonkeyPatch) -> str:
    module = types.ModuleType("fake_targets")
    module.leaky = LeakyTarget  # type: ignore[attr-defined]
    module.hardened = HardenedTarget  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "fake_targets", module)
    return "fake_targets"


def test_self_check_passes_with_the_reference_targets() -> None:
    assert main([]) == 0


def test_exits_1_when_your_target_leaks(targets_module: str) -> None:
    assert main(["--target", f"{targets_module}:leaky"]) == 1


def test_exits_0_when_your_target_holds(targets_module: str) -> None:
    assert main(["--target", f"{targets_module}:hardened"]) == 0


def test_rejects_a_malformed_target_spec() -> None:
    with pytest.raises(SystemExit, match="package.module:factory"):
        main(["--target", "no_colon"])
