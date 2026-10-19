# promptproof

A small red-team harness that answers one question about an LLM system: **does
it resist prompt injection?** It plants a unique secret (a canary) in the system
under test, fires a corpus of injection payloads at it, and checks whether the
secret leaks back out. Because the check is canary-based, the result is
deterministic: no model is needed to judge the outcome.

This is the testing tool that sits next to a guardrailed system. Guardrails that
are never attacked are just hopes; this is how you find out whether they hold.

## How it works

```
plant a canary in the target  ->  fire each attack as user input
   ->  did the canary come back out (plainly, spaced out, or inside base64)?
        yes -> the attack succeeded, the system LEAKED
        no  -> the attack HELD
   ->  report: N/total attacks held
```

The attack corpus covers the common families: direct extraction, instruction
override ("ignore previous instructions"), role-play jailbreaks, delimiter and
context-confusion injection, and obfuscated exfiltration (base64, payload
splitting).

## Run it

```bash
pip install -e ".[dev]"
pytest                 # deterministic, no model, no network
promptproof            # runs the suite against a leaky and a hardened reference target
```

Expected: the leaky reference target leaks on every attack, the hardened one
holds them all. That contrast is the harness proving it can tell the difference.

## Testing your own system

Implement the `Target` protocol (one method, `respond(user_input) -> str`) so it
calls your assistant, constructed with a canary as its protected secret, then:

```python
from promptproof.harness import run_suite

report = run_suite(my_target, canary="CANARY-...")
print(f"{report.held}/{report.total} held")
```

## Design

The decisions and their limits (why canary-based detection, what it does and does
not catch) are in [DESIGN.md](./DESIGN.md).

## Status

Working and tested: leak detection (plain, separator-split, and base64 at any
offset), the harness against both reference targets, and the attack corpus are
covered by tests. CI runs ruff,
format check, mypy (strict), and pytest.
