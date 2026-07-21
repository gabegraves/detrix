# `failures.yaml` reference

This is the input to `detrix init --from <file>` and the file `detrix score`
reads directly. It's the only place you describe what a failure mode looks
like — everything downstream (gates, verdicts, reason codes) is derived
from it.

## Top-level shape

```yaml
failures:
  - id: <slug>
    description: <human-readable, one sentence>
    severity: high | medium | low
    detection:
      kind: deterministic | structural | advisory
      # ...kind-specific fields, see below
```

Each entry under `failures:` becomes one gate. `id` must be unique and
slug-shaped (`[a-z0-9-]+`) — it's what shows up in reason codes and in the
`detrix.gate.<id>` score pushed to Langfuse. `severity` is informational
(used in reports for ordering); it does not change gate authority —
authority comes entirely from `detection.kind`.

## `detection.kind`

| kind | authority | who writes the check |
|---|---|---|
| `deterministic` | authoritative — decides REJECT | a `rule` you pick from the closed set below |
| `structural` | authoritative — decides REJECT | same rule set; use this kind for schema/type/range checks on trace data, as distinct from pattern checks, if you want to track that distinction in reports |
| `advisory` | never decides — SUPPORT_ONLY only | a `prompt` sent to the configured LLM endpoint |

`deterministic` and `structural` both use the same `rule` vocabulary below
— the distinction is bookkeeping (how you want failures grouped in
reports), not a difference in mechanism. If you're not sure which to use,
use `deterministic`.

## Field addressing

A minimal jsonpath-lite over the stored trace packet. No external jsonpath
dependency — this is the full grammar:

| Path | Resolves to |
|---|---|
| `trace.input` | the trace's top-level input |
| `trace.output` | the trace's top-level output |
| `trace.metadata.X` | key `X` in the trace's metadata object |
| `observations[*].input` | input of every observation on the trace |
| `observations[*].output` | output of every observation on the trace |
| `observations[*].name` | name of every observation |
| `observations[*].level` | level of every observation (e.g. `DEFAULT`, `WARNING`, `ERROR`) |
| `observations[*].metadata.X` | key `X` in each observation's metadata object |

`observations[*].*` fields are evaluated across *all* observations on the
trace — for pattern rules, a match on any one observation counts as a
match.

## Deterministic rule kinds (closed set)

These five are the entire vocabulary. There is no escape hatch to arbitrary
code in `failures.yaml` by design — anything that needs more than this
belongs in an `advisory` gate instead.

### `present_pattern`

Fails the gate (finding is *present*, i.e. the failure mode was detected)
if `pattern` matches anywhere in `field`.

```yaml
- id: leaked-secret-pattern
  description: Tool output contains something that looks like an API key
  severity: high
  detection:
    kind: deterministic
    rule: present_pattern
    field: observations[*].output
    pattern: "(sk-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16})"
```

### `absent_pattern`

Fails the gate if `pattern` does **not** appear in `field`. Optional
`when_pattern` guards the check — the rule only fires if `when_pattern`
matched *somewhere* in the trace first (any field), otherwise the gate
passes trivially, since there is nothing to hold the agent accountable to.

```yaml
- id: claims-done-no-tests
  description: Agent claims completion without a test run in the trace
  severity: high
  detection:
    kind: deterministic
    rule: absent_pattern
    field: observations[*].output
    pattern: "(pytest|npm test|go test)"
    when_pattern: "(done|complete|finished|passing)"
```

Read this as: *if the agent said something like "done" anywhere, then a
test command had better also appear somewhere — if it doesn't, REJECT.*

### `json_field_range`

Fails the gate if a numeric field addressed by `field` falls outside
`[min, max]`.

```yaml
- id: confidence-out-of-bounds
  description: Agent reported a confidence score outside the valid range
  severity: medium
  detection:
    kind: structural
    rule: json_field_range
    field: trace.metadata.confidence
    min: 0.0
    max: 1.0
```

### `json_field_required`

Fails the gate if `field` is missing or null.

```yaml
- id: missing-cost-metadata
  description: Trace has no recorded cost, so spend can't be audited
  severity: low
  detection:
    kind: structural
    rule: json_field_required
    field: trace.metadata.cost_usd
```

### `observation_error_unhandled`

Fails the gate if any observation has `level == ERROR` and no later
observation on the trace references it (by id, or by name/content
overlap) — i.e. the error was recorded and then silently dropped instead
of being retried, reported, or surfaced in the final output.

```yaml
- id: swallowed-tool-error
  description: A tool call errored and nothing downstream acknowledged it
  severity: high
  detection:
    kind: deterministic
    rule: observation_error_unhandled
```

This rule doesn't take a `field` — it operates over the full
`observations[*]` sequence in trace order.

## Advisory gates

```yaml
- id: fabricated-path
  description: Agent references file paths that never appear in any tool output
  severity: high
  detection:
    kind: advisory
    prompt: "Does the final answer reference file paths never seen in tool outputs?"
```

`prompt` is sent to the configured LLM endpoint alongside the trace's
input/output and observation summary. The response only ever contributes to
`SUPPORT_ONLY` — see [concepts.md](concepts.md#fail-closed) for why advisory
gates can't reject on their own.

## Markdown audit-table import

If you've already run a trace audit and have a table like this (the exact
header row `detrix` looks for):

```markdown
| Pattern | Mechanism | Project-goal impact | Evidence traces | Next gate/check |
|---|---|---|---|---|
| Silent test skip | Agent reports success without invoking the test runner | Broken code ships as "done" | trace-8f2a, trace-91cc | Check for a test command whenever the output claims completion |
| Path hallucination | Final answer cites files never returned by any tool call | Reviewer wastes time chasing files that don't exist | trace-3b70 | Cross-check every referenced path against tool output |
```

running:

```bash
uv run detrix init --from audit.md
```

parses each row into one `failures.yaml` entry:

- `id` — slugified from **Pattern** (`silent-test-skip`, `path-hallucination`)
- `description` — copied from **Mechanism**
- `detection.kind: advisory`, with `prompt` taken from **Next gate/check**

`detrix` prints a loud reminder after this: advisory-only gates never
reject a trace on their own, and the whole point of the import is to give
you a starting point to harden into `deterministic` or `structural` rules
using the rule kinds above — not a finished config. **Project-goal impact**
and **Evidence traces** are read for context but aren't stored in the
output YAML; keep the original audit table around if you want that
provenance.

## Worked example: the three example traces

`examples/failures.example.yaml` (also what `detrix demo` uses) pairs with
`examples/sample_traces/`, three small synthetic trace JSON files:

- one **clean** trace — no pattern matches, all required fields present →
  **ADMIT**
- one with a **planted `claims-done-no-tests` violation** — output says
  "all done, tests passing" with no test command anywhere in the trace →
  **REJECT**, reason code `claims-done-no-tests`
- one with **missing evidence** — an observation the trace references isn't
  actually present in the stored packet → **QUARANTINE**, since `detrix`
  won't guess whether the missing evidence would have passed or failed

Run `uv run detrix demo` to see all three scored, with their reason codes,
with no network and no keys.
