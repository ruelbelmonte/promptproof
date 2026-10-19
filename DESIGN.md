# Design decisions

## 1. Canary-based, deterministic detection

**Decision.** Plant a unique secret in the target and judge an attack purely by
whether that secret leaks back out. No LLM-as-judge in the core.

**Rejected.** Using a model to grade whether a response "complied". That is
slower, costs money, is non-deterministic, and is itself promptable. A canary is
a hard, binary signal: the exact secret either came back or it did not.

**Cost / honest limit.** It detects *secret exfiltration*. It does not, on its
own, judge subtler harms like the model being steered into a wrong-but-secretless
answer. Those want a behavioural eval; this tool is the deterministic first line,
and it says so rather than overclaiming.

## 2. Obfuscation-aware leak check

**Decision.** The detector ignores case and non-alphanumeric characters, so a
canary spelled out with spaces or dashes still counts. It also decodes every
base64-looking run in the response and searches the decoded text.

**Why.** "Reveal it but base64-encode it so it's safe" is a real and effective
exfiltration trick. Comparing against the canary's own encoding is not enough:
when a model encodes a whole sentence, the canary's bytes start at an arbitrary
offset and encode differently. Each run is decoded at all four alignments,
with whitespace removed and URL-safe characters mapped, so the canary is found
wherever it sits, including when the base64 is glued to a preceding word or
wrapped across lines.

**Cost.** It is not a full decoder. Other encodings (hex, rot13, leetspeak) would
each need adding, and a canary split by intervening words is not caught. The point is to model the obfuscation arms race honestly, not
to claim it is finished.

## 3. The target is a one-method protocol

**Decision.** `Target` has a single method, `respond(user_input) -> str`. Two
reference targets (leaky, hardened) ship for demos and tests.

**Why.** Anything that turns a string into a string can be tested: a local
model, a hosted API, a whole agent. The reference targets let the harness prove
itself with no external dependency, and make the tests deterministic.

## 4. A small, readable corpus over a giant one

**Decision.** A handful of categorised, hand-written payloads rather than a
sprawling list.

**Why.** For a smoke test you want coverage of the families (override, jailbreak,
context confusion, obfuscation) and payloads a reader can actually understand and
extend. Quantity here is easy to fake and hard to trust; the structure is the
value, and adding payloads is a one-line change.
