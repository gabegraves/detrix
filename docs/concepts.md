# Concepts

## What a gate is, and isn't

A **gate** looks at a finished trace and decides one thing: is this trace,
and the failure mode it's checking for, present or not. Gates never touch
the running agent. They don't see the trace until after the agent is done
and the trace has been recorded. There is no "blocking" an action mid-flight
— by the time a gate runs, the action already happened. What a gate blocks
is the *trace* from being treated as trustworthy: it can keep a bad trace
out of a report, out of a downstream training set, out of "this agent run
is fine" dashboards. It cannot stop the agent from doing the thing in the
first place.

This is deliberate. Wrapping or intercepting agent actions couples you to
one harness's action space and breaks the moment that harness changes.
Scoring finished traces works against any agent, any framework, any
language — the trace is the interface.

## The four verdicts

Every scored trace gets exactly one of these:

| Verdict | Meaning |
|---|---|
| **ADMIT** | Every authoritative gate passed. Nothing flagged. |
| **REJECT** | At least one authoritative (deterministic or structural) gate failed. |
| **QUARANTINE** | A gate couldn't be evaluated — missing evidence, unjoinable observations, an ambiguous result. Not a failure finding, an "I don't know" finding. |
| **SUPPORT_ONLY** | Advisory gates flagged something, but no authoritative gate failed. Informational — surfaced in reports, never used to reject. |

The verdict always carries **typed reason codes** — one per gate that
contributed to it — not a free-text explanation. A REJECT from
`claims-done-no-tests` always carries that gate's id, so a report can group
by failure mode instead of re-reading prose.

## The deterministic-first hierarchy

Gates are checked in this order of authority, and the order is the point —
it's what keeps human judgment (which is expensive and inconsistent) out of
the hot path wherever a cheaper check will do:

```
1. Deterministic rule on trace content   →  authoritative, always decides
   (regex present/absent, error left unhandled, ...)
        │
        ▼ only if no deterministic rule applies
2. Structural check (schema/type/range)  →  authoritative, always decides
   (a numeric field within bounds, a required field present, ...)
        │
        ▼ only if no structural rule applies
3. Semantic-only judgment                →  advisory, NEVER decides
   (an LLM asked "does this look fabricated?")
        │
        ▼ if nothing above can evaluate the trace
4. Unverifiable                          →  QUARANTINE, flagged for a human
```

In practice: write the deterministic rule if you possibly can. `absent_pattern`
catches "claims done, no test command in the trace" perfectly — no judgment
call needed. Reach for `advisory` only for things that genuinely require
reading intent, like "does this final answer reference a file path that was
never in any tool output" — and even then, expect to harden it into a
deterministic rule once you see what the advisory pass actually catches (see
[failures-reference.md](failures-reference.md) for the markdown-import
workflow that pushes you toward exactly this).

## Fail-closed

A trace only reaches ADMIT if every authoritative gate ran and passed.
Anything that stops a gate from running cleanly — a missing field, an
observation that can't be joined to its trace, a gate that raises an error
— produces QUARANTINE, not ADMIT. `detrix` never guesses in your favor.
This is the same posture as a null result in an experiment: absence of
evidence against a trace is not evidence for it.

Advisory (LLM-backed) gates follow the same discipline in reverse: they can
never push a trace *out* of ADMIT on their own. Their signal is visible in
`SUPPORT_ONLY` and in reports, but the authoritative gates are the only ones
with veto power. If you never configure an LLM endpoint at all, `detrix`
degrades gracefully — deterministic and structural gates still run, `pull`
and `push` still work, only the advisory rows go empty.

## Config versioning and staleness

`failures.yaml` is content-hashed. Every verdict row stored in
`.detrix/store.db` records the hash of the config that produced it. Edit a
rule — tighten a regex, add a new failure — and the hash changes. Verdicts
scored under the old hash are not silently kept, and they are not rewritten
either: `detrix` appends a `stale` event to the trace's history and marks it
replay-required. Re-run `detrix score` and it re-evaluates under the new
config, appending a fresh verdict event. History is append-only end to end —
you can always answer "what verdict did this trace have, under which
config, and when" without losing the earlier answer.

This matters because reward and evidence contamination from a stale gate
config is silent by default: nothing crashes, the numbers just quietly stop
meaning what you think they mean. Content-hashing plus append-only history
makes staleness a visible, queryable state instead of a debugging session.

## Advisory judgment, if you use it

Advisory gates route through an OpenAI-compatible endpoint configured
purely by environment variable name (`OPENAI_BASE_URL`, `OPENAI_API_KEY`
style) — bring your own provider, local or hosted. `detrix` never imports
or calls a proprietary SDK directly, and the package is fully functional
with zero LLM configured at all: deterministic and structural gates don't
need one.
