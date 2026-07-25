# Detrix

Detrix turns your documented AI-agent trace failures into reproducible, post-hoc admission
decisions over your own Langfuse project. It does not wrap, intercept, or constrain an agent.

## 15-minute quickstart

You need Python 3.11+ and [uv](https://docs.astral.sh/uv/). From this repository:

```bash
uv tool install .
detrix demo
```

The demo needs no network, credentials, or LLM. It scores three bundled synthetic traces and
prints one clean admission, one deterministic rejection, and one fail-closed quarantine.

```text
Detrix offline demo
CONFIG <full SHA-256>
clean ADMIT reasons=NONE
reject REJECT reasons=GATE_FAILED
quarantine QUARANTINE reasons=EVIDENCE_MISSING
```

Create a small working directory and initialize a gate document:

```bash
mkdir my-agent-governance
cd my-agent-governance
detrix init
```

Edit `failures.yaml` so it describes failures found in your trace audits. Then connect your
Langfuse project using the standard environment variables; secrets are never written to config:

```bash
export LANGFUSE_PUBLIC_KEY="pk-lf-..."
export LANGFUSE_SECRET_KEY="sk-lf-..."
export LANGFUSE_HOST="https://cloud.langfuse.com"

detrix pull --limit 100
detrix score
detrix report
detrix push
```

The efficacy ladder is would-have-rejected → issued → obeyed → outcome-measured. Detrix operates
at the first rung: scoring and reports describe post-hoc decisions, not verified enforcement or
measured outcomes.

Use filters when you want a narrower replay set:

```bash
detrix pull --since 2026-07-01T00:00:00Z --limit 50 --tag production --session session-123
```

If you already have a Markdown trace-failure audit, initialize from it:

```bash
detrix init --from audit.md
```

The table header must be exactly:

```markdown
| Pattern | Mechanism | Project-goal impact | Evidence traces | Next gate/check |
|---|---|---|---|---|
```

Markdown conversion creates advisory stubs and prints a prominent warning. Advisory stubs never
make an authoritative admission decision; harden them into deterministic rules.

## Failure configuration

`failures.yaml` is the canonical source:

```yaml
failures:
  - id: claims-done-no-tests
    description: Agent claims completion without a test run in the trace
    severity: high
    detection:
      kind: deterministic
      rule: absent_pattern
      field: observations[*].input
      pattern: "(pytest|npm test|go test)"
      when_pattern: "(done|complete|finished|passing)"
  - id: fabricated-path
    description: Agent may reference paths never seen in tool output
    severity: high
    detection:
      kind: advisory
      prompt: Does the final answer reference file paths never seen in tool outputs?
```

Rules describe failure conditions. `present_pattern` fires when its regex appears.
`absent_pattern` fires when its regex does not appear; `when_pattern` can restrict that check to
traces that make a completion claim. The closed authoritative rule set is:

- `present_pattern`
- `absent_pattern`
- `json_field_range` with inclusive `min` and `max`
- `json_field_required`
- `observation_error_unhandled`

The last rule fires when an observation has `level=ERROR` and no later observation references its
observation id. Detrix intentionally provides no general rule language.

Regexes use Python syntax, are capped at 512 characters, and reject quantified groups containing
nested repetition or alternation to prevent unbounded backtracking during scoring.

Field addressing is deliberately small:

- `trace.input`, `trace.output`, `trace.metadata.X`
- `observations[*].input`, `.output`, `.name`, `.level`, `.metadata.X`

## Verdicts

- `ADMIT`: every authoritative gate evaluated and passed.
- `REJECT`: at least one authoritative gate found the documented failure.
- `SUPPORT_ONLY`: the config has advisory evidence but no authoritative gate. Harden the config
  before treating it as admission evidence.
- `QUARANTINE`: evidence is missing, observations cannot be joined, a gate errored, or the result
  is ambiguous.

Detrix evaluates completed traces only. “Reject” means the trace is rejected from the post-hoc
admission set; it never means Detrix blocked an agent action.

## Deterministic-first hierarchy

1. Deterministic rules over trace content are authoritative.
2. Structural schema, type, required-field, and range checks are authoritative.
3. Semantic-only judgments are advisory and cannot change the verdict.
4. Unverifiable evidence is quarantined for human review.

Version 0.1 makes no LLM calls. Advisory entries remain visible evidence and produce
`SUPPORT_ONLY` when no authoritative rules exist.

## Storage and replay

`detrix pull` stores canonical raw trace packets in `.detrix/store.db`. The directory is mode 0700
and the database is mode 0600. Treat it as sensitive plaintext: it contains the inputs, outputs,
and metadata returned by your Langfuse project. Backups and retention remain the operator's
responsibility.

The semantic gate config and canonical trace packet each have a full SHA-256 hash. Every verdict
records both identities. A config or trace-content change appends a schema-versioned
`REPLAY_REQUIRED` event and a new verdict; the old verdict row is never rewritten. Config history
also records promotion, invalidation, and reversion events. Read projections mark each superseded
row stale. Config activation happens before replay begins, so an interrupted rescore leaves every
unfinished trace stale; `report` treats it as quarantined and `push` refuses it until replay ends.

## Langfuse boundary

This release supports Langfuse Python SDK major version 4 (`langfuse>=4.14.1,<5`). Pull uses the
public `client.api.trace.list(...)`, `client.api.trace.get(...)`, and
`client.api.observations.get_many(...)` APIs. Observation metadata keys referenced by the active
config are explicitly expanded; provenance prevents a later gate from accepting truncated
metadata. Push uses the synchronous public `client.api.ingestion.batch(...)` API and records
receipts only for explicitly acknowledged score events.

Each current trace/config pair receives:

- categorical `detrix.verdict` with `ADMIT`, `REJECT`, `SUPPORT_ONLY`, or `QUARANTINE`;
- numeric `detrix.gate.<failure-id>` for each authoritative gate (`1` pass, `0` fail);
- a comment with typed reason codes and the full config hash.

Score ids are deterministic, and successful ids are recorded locally by trace, config hash, and
score name. Re-running `detrix push` skips recorded scores. Pull and push are explicit network
commands: missing variables, SDK failures, and HTTP status failures exit loudly without printing
credential values or raw response bodies.

## Development proof

The repository's verification commands are:

```bash
uv sync
uv run pytest -q
uv run ruff check .
uv run detrix demo
```

Tests exercise real config files and temporary SQLite databases. The Langfuse system boundary is
covered by an injected recording client; application modules are not mocked.

## License

MIT

## Documentation

- [Concepts](docs/concepts.md) — verdicts, deterministic-first hierarchy, fail-closed admission, config versioning.
- [failures.yaml reference](docs/failures-reference.md) — every detection rule kind, field addressing, and the audit-table import format.
- [Langfuse guide](docs/langfuse-guide.md) — credentials, the pull/score/push loop, and what appears in your Langfuse UI.
