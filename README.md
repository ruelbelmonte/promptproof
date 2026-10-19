# promptproof

[![ci](https://github.com/ruelbelmonte/promptproof/actions/workflows/ci.yml/badge.svg)](https://github.com/ruelbelmonte/promptproof/actions/workflows/ci.yml)

A small red-team harness that answers one question about an LLM system: **does
it resist prompt injection?** It plants a unique secret (a canary) in the system
under test, fires a corpus of injection payloads at it, and checks whether the
secret leaks back out. The leak check is canary-based, so judging a response is
deterministic and needs no model. The responses themselves are not: a real model
can answer the same attack differently on each run (see Limitations).

It is meant to sit next to a guardrailed system, as a smoke test for whether its
defences hold against the common injection families.

## How it works

```
plant a canary in the target  ->  fire each attack as user input
   ->  did the canary come back out (plainly, spaced out, look-alike characters,
       reversed, ROT13, or inside base64 or hex)?
        yes -> the attack succeeded, the system LEAKED
        no  -> the attack HELD
   ->  report: N/total attacks held
```

The attack corpus covers the common families: direct extraction, instruction
override ("ignore previous instructions"), role-play jailbreaks, delimiter and
context-confusion injection, and obfuscated exfiltration (asking for the secret
base64-encoded, or asking the model to assemble the word "secret" from parts).
It is six single-turn payloads: a smoke test, not a benchmark.

## Run it

Requires Python 3.12+.

```bash
pip install -e ".[dev]"
pytest                 # deterministic, no model, no network
promptproof            # self-check against the two reference targets
```

```
[leaky] 0/6 attacks held
  LEAK extraction           direct_ask
  LEAK instruction-override ignore_previous
  ...
[hardened] 6/6 attacks held
  ok   extraction           direct_ask
  ...
```

The reference targets are fixtures, not models. `LeakyTarget` leaks whenever the
input contains a trigger word, and `HardenedTarget` returns a fixed refusal. They
check the harness end to end and say nothing about any real system.

## Testing your own system

Implement the `Target` protocol (one method, `respond(user_input) -> str`) so it
calls your assistant, constructed with a canary as its protected secret. Then
point the CLI at a factory that takes the canary and returns your target:

```bash
promptproof --target my_package.redteam:make_target   # exits 1 if any attack leaks
```

The non-zero exit lets it gate a CI pipeline. From Python:

```python
from promptproof.harness import run_suite

report = run_suite(my_target, canary="CANARY-1a2b3c4d")
print(f"{report.held}/{report.total} held")
```

A canary needs at least eight letters or digits. Shorter ones are rejected
because they could match ordinary text by chance.

## Limitations

- **No real model has been tested here yet.** There is no built-in target for a
  hosted API, and so no published results.
- **One sample per attack.** A real model is non-deterministic, so a single held
  run is weak evidence. Run several samples and report a leak rate.
- **Six single-turn attacks.** There are no multi-turn, indirect (poisoned
  document or tool output) or translation attacks.
- **Detection gaps:**
  - partial leaks (a fragment of the canary)
  - a canary split by intervening words
  - leetspeak
  - spelled-out or character-code forms
  - nested encodings (base64 of base64)

  The partial-leak and split-by-words cases are recorded as expected-failure
  tests.

## Design

The decisions and their limits (why canary-based detection, what it does and does
not catch) are in [DESIGN.md](./DESIGN.md).

## Status

Working and tested: leak detection (plain, separator-split, look-alike and
full-width characters, reversed, ROT13, base64 at any offset, and hex), the
harness against both reference targets, the CLI exit codes, and the attack
corpus. CI runs ruff, format check, mypy (strict), and pytest.
