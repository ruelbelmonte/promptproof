from __future__ import annotations

from promptproof.attacks import ATTACKS


def test_attack_names_are_unique() -> None:
    names = [attack.name for attack in ATTACKS]
    assert len(names) == len(set(names))


def test_attacks_have_nonempty_payloads() -> None:
    assert ATTACKS
    assert all(attack.payload.strip() for attack in ATTACKS)


def test_attacks_are_categorised() -> None:
    assert all(attack.category.strip() for attack in ATTACKS)
