"""Click commands for the local post-hoc governance workflow."""

from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import click
import yaml
from pydantic import ValidationError

from detrix.admission import ADMISSION_PACKET_SCHEMA_VERSION, verify_evidence_pointers
from detrix.canonical import canonical_json
from detrix.engine import score_trace
from detrix.failures import (
    FailureDocumentError,
    config_snapshot_content,
    load_failures,
    markdown_to_failures,
    write_failures,
)
from detrix.gates import GateConfig
from detrix.langfuse_io import LangfuseBoundaryError, pull_traces, push_scores
from detrix.store import Store, StoreError

MATCH = "MATCH"
DRIFT = "DRIFT"
STORE_INTEGRITY_VIOLATION = "STORE_INTEGRITY_VIOLATION"
UNREPLAYABLE = "UNREPLAYABLE"
LEGACY = "LEGACY"
REPLAY_OUTCOMES = (MATCH, DRIFT, STORE_INTEGRITY_VIOLATION, UNREPLAYABLE, LEGACY)
REPLAY_FAILURES = frozenset({DRIFT, STORE_INTEGRITY_VIOLATION, UNREPLAYABLE})

CONFIG_EXAMPLE = """# Detrix stores environment-variable names, never secret values.
langfuse:
  public_key_env: LANGFUSE_PUBLIC_KEY
  secret_key_env: LANGFUSE_SECRET_KEY
  host_env: LANGFUSE_HOST
failures: failures.yaml
store: .detrix/store.db
"""

FAILURES_EXAMPLE = """# Rules describe documented failure conditions.
# Advisory entries never decide admission.
failures:
  - id: claims-done-no-tests
    description: Agent claims completion without a recorded test command
    severity: high
    detection:
      kind: deterministic
      rule: absent_pattern
      field: observations[*].input
      pattern: "(pytest|npm test|go test)"
      when_pattern: "(done|complete|finished|passing)"
"""


@click.group()
@click.pass_context
def main(context: click.Context) -> None:
    """Govern AI agents from documented trace failures, after the trace is complete."""

    context.ensure_object(dict)


@main.command("init")
@click.option("source", "--from", type=click.Path(path_type=Path, exists=True, dir_okay=False))
def init_command(source: Path | None) -> None:
    """Create failures.yaml and detrix.yaml in the current directory."""

    failures_path = Path("failures.yaml")
    config_path = Path("detrix.yaml")
    _require_absent(config_path)
    try:
        if source is None:
            _require_absent(failures_path)
            failures_path.write_text(FAILURES_EXAMPLE, encoding="utf-8")
            message = "Wrote commented failures.yaml example and detrix.yaml."
        elif source.suffix.lower() in {".yaml", ".yml"}:
            loaded = load_failures(source)
            if source.resolve() != failures_path.resolve():
                _require_absent(failures_path)
                write_failures(loaded, failures_path)
            message = f"Validated {source}; failures.yaml is ready."
        elif source.suffix.lower() in {".md", ".markdown"}:
            _require_absent(failures_path)
            markdown_to_failures(source, failures_path)
            message = (
                "ADVISORY-ONLY CONFIG CREATED: advisory gates never decide admission. "
                "Harden these stubs into deterministic rules."
            )
        else:
            raise click.ClickException("--from supports only YAML or Markdown files")
        config_path.write_text(CONFIG_EXAMPLE, encoding="utf-8")
    except FailureDocumentError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(message)


@main.command()
@click.option("--since", help="Only traces at or after this ISO8601 timestamp.")
@click.option("--limit", type=click.IntRange(min=1), default=100, show_default=True)
@click.option("--tag")
@click.option("--session")
@click.pass_context
def pull(
    context: click.Context,
    since: str | None,
    limit: int,
    tag: str | None,
    session: str | None,
) -> None:
    """Fetch traces and full observations from the configured Langfuse project."""

    try:
        failures_path, store_path = _configured_paths()
        config = load_failures(failures_path)
        count = pull_traces(
            Store(store_path),
            since=since,
            limit=limit,
            tag=tag,
            session=session,
            metadata_keys=_observation_metadata_keys(config),
            client=context.obj.get("langfuse_client"),
        )
    except (FailureDocumentError, LangfuseBoundaryError, StoreError) as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"Pulled {count} trace(s) into .detrix/store.db")


@main.command()
def score() -> None:
    """Score every locally stored trace against failures.yaml."""

    try:
        failures_path, store_path = _configured_paths()
        config = load_failures(failures_path)
        store = Store(store_path)
        store.save_config_snapshot(config.content_hash, config_snapshot_content(config))
        store.activate_config(config.content_hash)
        rows = store.list_traces()
        for row in rows:
            packet = score_trace(json.loads(row["raw_json"]), config)
            store.save_verdict(packet)
            reasons = ",".join(code.value for code in packet.reason_codes) or "NONE"
            click.echo(f"{packet.run_id} {packet.admission_decision.value} reasons={reasons}")
    except (FailureDocumentError, StoreError) as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"Scored {len(rows)} trace(s) with config {config.content_hash}")


@main.command()
@click.pass_context
def push(context: click.Context) -> None:
    """Write current verdict and gate scores back to Langfuse."""

    try:
        failures_path, store_path = _configured_paths()
        config = load_failures(failures_path)
        store = Store(store_path)
        store.save_config_snapshot(config.content_hash, config_snapshot_content(config))
        store.activate_config(config.content_hash)
        count = push_scores(store, client=context.obj.get("langfuse_client"))
    except (FailureDocumentError, LangfuseBoundaryError, StoreError) as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"Pushed {count} new score(s)")


@main.command()
def report() -> None:
    """Print verdict counts, gate hit rates, and top offending trace ids."""

    try:
        failures_path, store_path = _configured_paths()
        config = load_failures(failures_path)
        store = Store(store_path)
        store.save_config_snapshot(config.content_hash, config_snapshot_content(config))
        store.activate_config(config.content_hash)
        rows = store.list_verdicts(latest_only=True)
    except (FailureDocumentError, StoreError) as exc:
        raise click.ClickException(str(exc)) from exc
    packets = []
    for row in rows:
        packet = json.loads(row["packet_json"])
        if row["stale"]:
            packet["admission_decision"] = "QUARANTINE"
            packet["reason_codes"] = sorted({*packet["reason_codes"], "REPLAY_REQUIRED"})
        packets.append(packet)
    counts = Counter(packet["admission_decision"] for packet in packets)
    click.echo(
        "Shadow mode: post-hoc scoring only - decisions below are what WOULD have been "
        "applied; no consumer enforcement is verified."
    )
    click.echo("Would-have verdict counts")
    for decision in ("ADMIT", "REJECT", "SUPPORT_ONLY", "QUARANTINE"):
        click.echo(f"  {decision}: {counts[decision]}")
    covered = counts["ADMIT"] + counts["REJECT"]
    abstained = counts["SUPPORT_ONLY"] + counts["QUARANTINE"]
    abstained_share = abstained / len(packets) if packets else 0
    click.echo("Coverage boundary")
    click.echo(f"  covered (ADMIT+REJECT): {covered}")
    click.echo(f"  abstained (SUPPORT_ONLY+QUARANTINE): {abstained}")
    click.echo(f"  abstained share: {abstained_share:.1%} of {len(packets)} scored traces")
    hits: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    offenders: list[tuple[int, str]] = []
    for packet in packets:
        trace_hits = 0
        for result in packet["gate_results"]:
            if result["decision"] not in {"accept", "reject"}:
                continue
            hits[result["gate_id"]][1] += 1
            if result["decision"] == "reject":
                hits[result["gate_id"]][0] += 1
                trace_hits += 1
        if packet["admission_decision"] == "QUARANTINE":
            trace_hits += 1
        if trace_hits:
            offenders.append((trace_hits, packet["run_id"]))
    click.echo("Failure-mode hit rates")
    for gate_id in sorted(hits):
        hit, total = hits[gate_id]
        click.echo(f"  {gate_id}: {hit}/{total} ({hit / total:.1%})")
    click.echo("Top offending traces")
    for hit, trace_id in sorted(offenders, key=lambda item: (-item[0], item[1]))[:5]:
        click.echo(f"  {trace_id}: {hit}")


@main.command()
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable rows and summary.")
@click.pass_context
def replay(context: click.Context, as_json: bool) -> None:
    """Recompute stored verdicts from store snapshots with an integrity-first taxonomy."""

    try:
        failures_path, store_path = _configured_paths()
        store = Store(store_path)
        rows = store.list_verdicts(latest_only=False)
        _rescue_current_config(store, failures_path, rows)
        results = [_replay_verdict(store, row) for row in rows]
    except StoreError as exc:
        raise click.ClickException(str(exc)) from exc
    summary = Counter(result["outcome"] for result in results)
    exit_code = 1 if any(result["outcome"] in REPLAY_FAILURES for result in results) else 0
    if as_json:
        payload = {
            "rows": results,
            "summary": {outcome: summary[outcome] for outcome in REPLAY_OUTCOMES}
            | {"total": len(results)},
            "exit_code": exit_code,
        }
        click.echo(json.dumps(payload, indent=2, sort_keys=True))
    else:
        for result in results:
            note = f" ({result['note']})" if result["note"] else ""
            head = f"{result['trace_id']} {result['config_hash'][:12]} {result['outcome']}"
            click.echo(f"{head}{note}")
        click.echo("Replay summary")
        for name in REPLAY_OUTCOMES:
            click.echo(f"  {name}: {summary[name]}")
        click.echo(f"  total: {len(results)}")
        if summary[LEGACY]:
            click.echo(f"WARNING: {summary[LEGACY]} legacy row(s) outside the replay guarantee")
    if exit_code:
        context.exit(1)


def _rescue_current_config(
    store: Store, failures_path: Path, rows: list[dict[str, Any]]
) -> None:
    """Snapshot the current config if it reconstructs an un-snapshotted verdict config.

    Rescues the config-never-changed case: pre-migration verdicts have a config_hash but
    no stored content. If the live failures.yaml still hashes to it, its content is
    recoverable and the row becomes fully replayable. Best-effort: an absent or unreadable
    current config simply leaves those rows LEGACY.
    """

    if not failures_path.exists():
        return
    try:
        config = load_failures(failures_path)
    except (FailureDocumentError, OSError, UnicodeError):
        return
    verdict_config_hashes = {row["config_hash"] for row in rows}
    if (
        config.content_hash in verdict_config_hashes
        and store.get_config_snapshot(config.content_hash) is None
    ):
        store.save_config_snapshot(config.content_hash, config_snapshot_content(config))


def _replay_verdict(store: Store, row: dict[str, Any]) -> dict[str, Any]:
    stored = json.loads(row["packet_json"])
    version = int(stored.get("schema_version", 1))
    config_hash = row["config_hash"]
    trace_hash = row["trace_hash"]

    def outcome(name: str, note: str | None = None) -> dict[str, Any]:
        return {
            "verdict_id": row["id"],
            "trace_id": row["trace_id"],
            "config_hash": config_hash,
            "schema_version": version,
            "outcome": name,
            "note": note,
        }

    trace_snapshot = store.get_trace_snapshot(trace_hash)
    config_snapshot = store.get_config_snapshot(config_hash)

    # 1. Integrity first: any present snapshot must hash to its content-address key.
    trace_dict: dict[str, Any] | None = None
    if trace_snapshot is not None:
        if hashlib.sha256(trace_snapshot.encode()).hexdigest() != trace_hash:
            return outcome(STORE_INTEGRITY_VIOLATION, "trace snapshot digest mismatch")
        try:
            trace_dict = json.loads(trace_snapshot)
        except json.JSONDecodeError:
            return outcome(STORE_INTEGRITY_VIOLATION, "trace snapshot is not JSON")
    if config_snapshot is not None and (
        hashlib.sha256(config_snapshot.encode()).hexdigest() != config_hash
    ):
        return outcome(STORE_INTEGRITY_VIOLATION, "config snapshot digest mismatch")

    if version not in {1, ADMISSION_PACKET_SCHEMA_VERSION}:
        return outcome(UNREPLAYABLE, f"unsupported schema_version {version}")

    # 2. Availability: a missing input is a bug post-migration, an honest LEGACY before it.
    if trace_snapshot is None or config_snapshot is None:
        if version >= ADMISSION_PACKET_SCHEMA_VERSION:
            return outcome(UNREPLAYABLE, "missing snapshot for a post-migration verdict")
        return outcome(LEGACY, "no snapshot; pre-migration verdict")

    try:
        config = GateConfig.model_validate(json.loads(config_snapshot))
    except (json.JSONDecodeError, ValidationError) as exc:  # unreachable once the hash matches
        return outcome(STORE_INTEGRITY_VIOLATION, f"config snapshot unusable: {exc}")
    if config.content_hash != config_hash:  # round-trip guard
        return outcome(STORE_INTEGRITY_VIOLATION, "config snapshot does not reconstruct its hash")

    assert trace_dict is not None  # both snapshots present here
    recomputed = score_trace(trace_dict, config)
    # score_trace already ran this; repeated per the hardened procedure (no-op on a clean snapshot).
    verify_evidence_pointers(recomputed, trace_dict)

    # 3 + 4. Version dispatch, then compare. Only the current engine reproduces its own bytes.
    if version == ADMISSION_PACKET_SCHEMA_VERSION:
        if _replay_comparable(recomputed.model_dump(mode="json")) == _replay_comparable(stored):
            return outcome(MATCH)
        return outcome(DRIFT, "recomputed packet differs from stored")
    recomputed_decision = (
        recomputed.admission_decision.value,
        frozenset(code.value for code in recomputed.reason_codes),
        recomputed.failure_label,
    )
    stored_decision = (
        stored.get("admission_decision"),
        frozenset(stored.get("reason_codes", [])),
        stored.get("failure_label"),
    )
    note = "decision match" if recomputed_decision == stored_decision else "decision mismatch"
    return outcome(LEGACY, note)


def _replay_comparable(dump: dict[str, Any]) -> str:
    # ponytail: score_trace stamps a wall-clock timestamp into every VerdictContract
    # (gates.py, outside this unit's fence), so packets are never byte-identical across runs.
    # Strip that clock artifact — never verdict content — from both sides before comparing;
    # real decision/evidence drift still differs. Upgrade path: make VerdictContract.timestamp
    # deterministic in gates.py, then delete this normalizer.
    for key in ("verifier_verdicts", "gate_results"):
        for entry in dump.get(key, []):
            if isinstance(entry, dict):
                entry.pop("timestamp", None)
    return canonical_json(dump)


@main.command()
def demo() -> None:
    """Run the bundled three-trace proof without network or credentials."""

    package_examples = Path(__file__).resolve().parent / "examples"
    repo_examples = Path(__file__).resolve().parents[2] / "examples"
    examples = package_examples if package_examples.exists() else repo_examples
    config = load_failures(examples / "failures.example.yaml")
    click.echo("Detrix offline demo")
    click.echo(f"CONFIG {config.content_hash}")
    for name in ("clean", "reject", "quarantine"):
        raw = json.loads((examples / "sample_traces" / f"{name}.json").read_text())
        packet = score_trace(raw, config, source="demo")
        reasons = ",".join(code.value for code in packet.reason_codes) or "NONE"
        click.echo(f"{name} {packet.admission_decision.value} reasons={reasons}")


def _require_absent(path: Path) -> None:
    if path.exists():
        raise click.ClickException(f"refusing to overwrite existing {path}")


def _configured_paths() -> tuple[Path, Path]:
    config_path = Path("detrix.yaml")
    if not config_path.exists():
        return Path("failures.yaml"), Path(".detrix/store.db")
    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise click.ClickException(f"cannot read detrix.yaml: {exc}") from exc
    if not isinstance(raw, dict):
        raise click.ClickException("detrix.yaml must contain a mapping")
    failures = raw.get("failures", "failures.yaml")
    store = raw.get("store", ".detrix/store.db")
    if not isinstance(failures, str) or not failures.strip():
        raise click.ClickException("detrix.yaml failures must be a non-empty path")
    if not isinstance(store, str) or not store.strip():
        raise click.ClickException("detrix.yaml store must be a non-empty path")
    return Path(failures), Path(store)


def _observation_metadata_keys(config: GateConfig) -> list[str]:
    prefix = "observations[*].metadata."
    keys = {
        failure.detection.field.removeprefix(prefix)
        for failure in config.failures
        if failure.detection.field and failure.detection.field.startswith(prefix)
    }
    return sorted(keys)


if __name__ == "__main__":
    main()
