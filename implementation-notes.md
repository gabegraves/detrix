# Implementation Notes

## Deviations

1. Added PyYAML as a direct lightweight dependency because Python has no standard-library YAML
   parser and `failures.yaml` is a required public input format. Safe loading remains mandatory.
2. Conservatively reject quantified regex groups containing nested repetition or alternation.
   Python's standard regex engine has no portable match timeout, and fail-closed scoring must not
   hang on a user-supplied gate pattern.

## Langfuse SDK inspection

- Installed and supported version: `langfuse==4.14.1` (`langfuse>=4.14.1,<5`).
- Pull: public `client.api.trace.list(...)` plus per-trace `client.api.trace.get(...)` and
  `client.api.observations.get_many(...)` with full I/O; configured observation metadata keys use
  `expand_metadata` and their expansion provenance is stored with the packet.
- Push: synchronous public `client.api.ingestion.batch(...)` with deterministic score/event ids;
  local receipts are written only for response successes.

## Environment blockers

- The session exposes repository files as writable but mounts `.git` read-only. Every attempted
  local commit fails while creating `.git/index.lock`; repository history cannot be written from
  this environment.
