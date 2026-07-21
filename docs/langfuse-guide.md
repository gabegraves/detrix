# Langfuse integration guide

`detrix` reads and writes directly against your own Langfuse project. There
is no intermediate trace store, no vendor-hosted service, and no data
leaves your Langfuse instance except to your own machine's local SQLite
file (`.detrix/store.db`).

## Environment variables

`detrix` never stores secrets in a file — `detrix.yaml` records only which
environment variable *names* to read at runtime, never their values.

| Variable | Required for | Notes |
|---|---|---|
| `LANGFUSE_PUBLIC_KEY` | `pull`, `push` | from your Langfuse project settings |
| `LANGFUSE_SECRET_KEY` | `pull`, `push` | same |
| `LANGFUSE_HOST` | `pull`, `push` | e.g. `https://cloud.langfuse.com`, or your self-hosted URL |
| `OPENAI_BASE_URL` | advisory gates only | any OpenAI-compatible endpoint |
| `OPENAI_API_KEY` | advisory gates only | matching key |

If a Langfuse variable is missing when you run `pull` or `push`, `detrix`
fails loudly and names the missing variable — it does not silently no-op.
`pull` and `push` are explicit user-invoked commands operating on your data;
silent failure there would be worse than a crash. (Contrast this with any
internal, automatic score-emission path, which is designed to degrade
gracefully if Langfuse isn't configured — that graceful-optional behavior
does not apply to `pull`/`push`, which you run on purpose.)

If an advisory gate is configured in `failures.yaml` but no `OPENAI_*`
variables are set, `detrix` does not fail the whole run — advisory rows are
simply left unscored, and deterministic/structural gates are unaffected.

## `detrix pull`

```bash
uv run detrix pull [--since ISO8601] [--limit N] [--tag T] [--session S]
```

Fetches traces and their full observation I/O from your Langfuse project
via its public API client, and stores the raw JSON per trace in
`.detrix/store.db` (one row per trace: `trace_id` primary key, `fetched_at`,
raw JSON payload).

- `--since 2026-01-01` — only traces created on or after this ISO 8601
  timestamp/date.
- `--limit 500` — cap how many traces are fetched in this call.
- `--tag T` — only traces carrying tag `T` in Langfuse.
- `--session S` — only traces belonging to Langfuse session `S`.

**Idempotent by design.** Running `pull` again — with the same filters or
different ones — upserts: traces already in the store get their raw JSON
refreshed if it changed, new traces get inserted, nothing is duplicated.
You can run `pull` on a cron with a rolling `--since` window and it will
just keep the local store current.

## `detrix score`

```bash
uv run detrix score
```

Reads every trace currently in `.detrix/store.db`, runs the gates defined
in `failures.yaml` against each one, and writes a verdict (with reason
codes) tagged with the content hash of the config that produced it. Traces
already scored under the *current* config hash are skipped on re-run; if
you've edited `failures.yaml` since the last score, that config's traces
are marked stale first (see
[concepts.md#config-versioning-and-staleness](concepts.md#config-versioning-and-staleness))
and rescored fresh.

## `detrix push`

```bash
uv run detrix push
```

For each scored trace, writes back to Langfuse:

- one **categorical score** named `detrix.verdict`, value one of `ADMIT` /
  `REJECT` / `SUPPORT_ONLY` / `QUARANTINE`
- one **numeric score** per gate that ran, named `detrix.gate.<id>` (e.g.
  `detrix.gate.claims-done-no-tests`), value `1` for pass / `0` for fail
- a **comment** on the trace containing the typed reason codes that drove
  the verdict, plus the config hash used

**Idempotent and config-hash aware.** `detrix` records locally which score
ids it has already pushed for which config hash. Re-running `push`:

- skips traces already pushed under the *current* config hash (no
  duplicate scores pile up in Langfuse)
- re-pushes a trace if it was rescored under a *new* config hash (the old
  scores stay in Langfuse as history; a new set is attached reflecting the
  current config)

## What you'll see in the Langfuse UI

Open any trace that's been through `pull → score → push` and its **Scores**
panel will show:

- `detrix.verdict` — a categorical tag: `ADMIT`, `REJECT`, `SUPPORT_ONLY`,
  or `QUARANTINE`. Filterable/sortable in the Langfuse trace table like any
  other score, so "show me every REJECT this week" is a Langfuse query, not
  a separate tool.
- `detrix.gate.<id>` — one row per gate that evaluated on this trace,
  `1`/`0`. Useful for building a Langfuse-side dashboard of per-gate hit
  rate over time without touching `detrix` at all.
- A comment with the reason codes and config hash, so anyone reading the
  trace in the UI — not just someone running `detrix report` — can see why
  it landed where it did.

## `detrix report`

```bash
uv run detrix report
```

Reads the local store (no network call needed — this summarizes what's
already been pulled and scored) and prints:

- verdict counts (how many ADMIT / REJECT / SUPPORT_ONLY / QUARANTINE)
- per-failure-mode hit rate (which gate ids are firing, and how often)
- your worst-offending traces, so you know where to look first

Run it any time after `score` — you don't need to have run `push` yet to
see the report locally.
