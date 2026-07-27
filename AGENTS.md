# Agent Instructions

Instructions for AI coding agents working on this repository. Human contributors
should read `README.md` first.

## What this project is

Detrix scores completed AI-agent traces against deterministic, user-authored rules
and records admission verdicts that can be independently re-derived. It is post-hoc:
it does not wrap, intercept, or constrain a running agent.

Read `docs/concepts.md` for the vocabulary (admission, gate, verdict, evidence
pointer, replay, shadow mode) before changing behavior.

## Build & test

```bash
uv sync                 # install deps (never pip)
uv run pytest           # full suite
uv run ruff check .     # lint (line-length 100)
uv run detrix demo      # offline three-trace proof; no network or credentials
```

`uv run detrix demo` is the fastest end-to-end check that a change did not break the
core path. It must print one ADMIT, one REJECT, and one QUARANTINE.

## Conventions

- Click for the CLI, Pydantic v2 for data models, pytest for tests.
- Deterministic first: a rule decidable from structure or content is code, never a
  model call.
- Fail closed. An unresolvable evidence pointer, a digest mismatch, or a missing
  snapshot quarantines the row — it never silently passes.
- Stored rows are versioned and dispatched per row. Never break or retroactively
  re-label an existing `schema_version`; add a new one and dispatch on it.
- Verdict language stays inside what post-hoc scoring proves. Results are shadow mode
  ("would have been rejected"), and the report states its coverage boundary.

## Non-interactive shell commands

Always use non-interactive flags — `cp`, `mv`, and `rm` are aliased to `-i` on some
systems and will hang an agent waiting for input.

```bash
cp -f source dest
mv -f source dest
rm -rf directory
```

Also: `ssh`/`scp` need `-o BatchMode=yes`, `apt-get` needs `-y`.
