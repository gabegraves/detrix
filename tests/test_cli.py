from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from click.testing import CliRunner

from detrix.admission import ADMISSION_PACKET_SCHEMA_VERSION
from detrix.canonical import canonical_digest
from detrix.cli import main
from detrix.failures import load_failures
from detrix.store import Store

REJECT_ON_OUTPUT = """failures:
  - id: bad-output
    description: bad output appears
    severity: high
    detection:
      kind: deterministic
      rule: present_pattern
      field: trace.output
      pattern: bad
"""


def _trace(trace_id: str, output: str) -> dict:
    return {
        "trace": {"id": trace_id, "input": "", "output": output, "metadata": {}},
        "observations": [],
    }


def _insert_v1_verdict(
    db_path: str,
    *,
    trace_id: str,
    config_hash: str,
    trace_hash: str,
    packet: dict,
) -> None:
    """Insert a hand-crafted pre-migration (schema_version 1) verdict row."""

    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """INSERT INTO verdicts
               (trace_id, config_hash, config_event_id, trace_hash,
                evaluated_at, decision, packet_json)
               VALUES (?, ?, 1, ?, '2026-01-01T00:00:00Z', ?, ?)""",
            (
                trace_id,
                config_hash,
                trace_hash,
                packet["admission_decision"],
                json.dumps(packet),
            ),
        )


def test_demo_end_to_end() -> None:
    result = CliRunner().invoke(main, ["demo"])
    assert result.exit_code == 0, result.output
    lines = result.output.splitlines()
    assert lines[0] == "Detrix offline demo"
    assert lines[2] == "clean ADMIT reasons=NONE"
    assert lines[3] == "reject REJECT reasons=GATE_FAILED"
    assert lines[4] == "quarantine QUARANTINE reasons=EVIDENCE_MISSING"


def test_init_without_source_writes_both_files() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(main, ["init"])
        assert result.exit_code == 0, result.output
        assert Path("failures.yaml").exists()
        config = Path("detrix.yaml").read_text()
        assert "LANGFUSE_PUBLIC_KEY" in config
        assert "secret-key" not in config


def test_markdown_init_prints_advisory_hardening_warning() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("audit.md").write_text(
            """| Pattern | Mechanism | Project-goal impact | Evidence traces | Next gate/check |
|---|---|---|---|---|
| Fabricated path | Claims unseen paths | Bad answer | trace-1 | Compare tool outputs |
"""
        )
        result = runner.invoke(main, ["init", "--from", "audit.md"])
        assert result.exit_code == 0, result.output
        assert "ADVISORY-ONLY" in result.output
        assert "never decide admission" in result.output


def test_init_validates_an_existing_canonical_failures_file() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        source = Path("failures.yaml")
        source.write_text(
            """failures:
  - id: bad-output
    description: bad output
    severity: high
    detection:
      kind: deterministic
      rule: present_pattern
      field: trace.output
      pattern: bad
"""
        )
        before = source.read_text()
        result = runner.invoke(main, ["init", "--from", "failures.yaml"])
        assert result.exit_code == 0, result.output
        assert source.read_text() == before
        assert Path("detrix.yaml").exists()


def test_score_and_report_use_real_sqlite_store() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("failures.yaml").write_text(
            """failures:
  - id: bad-output
    description: bad output appears
    severity: high
    detection:
      kind: deterministic
      rule: present_pattern
      field: trace.output
      pattern: bad
"""
        )
        store = Store()
        for trace_id, output in (("clean", "good"), ("bad", "bad result")):
            store.upsert_trace(
                {
                    "trace": {"id": trace_id, "input": "", "output": output, "metadata": {}},
                    "observations": [],
                }
            )
        score_result = runner.invoke(main, ["score"])
        assert score_result.exit_code == 0, score_result.output
        assert "clean ADMIT" in score_result.output
        assert "bad REJECT" in score_result.output
        report_result = runner.invoke(main, ["report"])
        assert report_result.exit_code == 0, report_result.output
        assert "ADMIT: 1" in report_result.output
        assert "REJECT: 1" in report_result.output
        assert "bad-output: 1/2 (50.0%)" in report_result.output
        assert "bad: 1" in report_result.output


def test_commands_honor_configured_failure_and_store_paths() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("settings").mkdir()
        Path("settings/failures.yaml").write_text(
            """failures:
  - id: bad-output
    description: bad output appears
    severity: high
    detection:
      kind: deterministic
      rule: present_pattern
      field: trace.output
      pattern: bad
"""
        )
        Path("detrix.yaml").write_text(
            "failures: settings/failures.yaml\nstore: private/store.db\n"
        )
        Store("private/store.db").upsert_trace(
            {
                "trace": {"id": "clean", "input": "", "output": "good", "metadata": {}},
                "observations": [],
            }
        )
        result = runner.invoke(main, ["score"])
        assert result.exit_code == 0, result.output
        assert "clean ADMIT" in result.output
        assert len(Store("private/store.db").list_verdicts()) == 1
        assert not Path(".detrix/store.db").exists()


def test_score_rescore_marks_old_config_replay_required() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("failures.yaml").write_text(
            """failures:
  - id: bad-output
    description: bad output appears
    severity: high
    detection:
      kind: deterministic
      rule: present_pattern
      field: trace.output
      pattern: first
"""
        )
        Store().upsert_trace(
            {
                "trace": {"id": "trace-1", "input": "", "output": "ok", "metadata": {}},
                "observations": [],
            }
        )
        assert runner.invoke(main, ["score"]).exit_code == 0
        changed = Path("failures.yaml").read_text().replace("first", "second")
        Path("failures.yaml").write_text(changed)
        assert runner.invoke(main, ["score"]).exit_code == 0
        assert len(Store().list_verdicts()) == 2
        assert Store().list_events()[0]["event_type"] == "REPLAY_REQUIRED"


def test_sample_trace_files_are_valid_json() -> None:
    sample_dir = Path(__file__).parents[1] / "examples" / "sample_traces"
    assert {json.loads(path.read_text())["trace"]["id"] for path in sample_dir.glob("*.json")} == {
        "clean",
        "reject",
        "quarantine",
    }


def test_replay_clean_path_all_match() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("failures.yaml").write_text(REJECT_ON_OUTPUT)
        store = Store()
        store.upsert_trace(_trace("clean", "good"))
        store.upsert_trace(_trace("bad", "bad result"))
        assert runner.invoke(main, ["score"]).exit_code == 0
        result = runner.invoke(main, ["replay"])
        assert result.exit_code == 0, result.output
        assert "clean" in result.output
        assert "MATCH: 2" in result.output
        assert "DRIFT: 0" in result.output
        for line in result.output.splitlines():
            if line.startswith(("clean ", "bad ")):
                assert line.split()[2] == "MATCH", line


def test_replay_tampered_trace_snapshot_is_integrity_violation() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("failures.yaml").write_text(REJECT_ON_OUTPUT)
        store = Store()
        store.upsert_trace(_trace("clean", "good"))
        store.upsert_trace(_trace("bad", "bad result"))
        assert runner.invoke(main, ["score"]).exit_code == 0
        clean_hash = next(
            row["trace_hash"] for row in store.list_verdicts() if row["trace_id"] == "clean"
        )
        db = ".detrix/store.db"
        with sqlite3.connect(db) as connection:
            raw = connection.execute(
                "SELECT raw_json FROM trace_snapshots WHERE trace_hash = ?", (clean_hash,)
            ).fetchone()[0]
            packet = json.loads(raw)
            packet["trace"]["output"] = "tampered"
            connection.execute(
                "UPDATE trace_snapshots SET raw_json = ? WHERE trace_hash = ?",
                (json.dumps(packet), clean_hash),
            )
        result = runner.invoke(main, ["replay"])
        assert result.exit_code == 1, result.output
        clean_line = next(
            line for line in result.output.splitlines() if line.startswith("clean ")
        )
        assert clean_line.split()[2] == "STORE_INTEGRITY_VIOLATION", clean_line
        bad_line = next(line for line in result.output.splitlines() if line.startswith("bad "))
        assert bad_line.split()[2] == "MATCH", bad_line
        assert "DRIFT: 0" in result.output


def test_replay_missing_config_snapshot_is_unreplayable() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("failures.yaml").write_text(REJECT_ON_OUTPUT.replace("pattern: bad", "pattern: first"))
        hash_a = load_failures("failures.yaml").content_hash
        Store().upsert_trace(_trace("t1", "ok"))
        assert runner.invoke(main, ["score"]).exit_code == 0
        Path("failures.yaml").write_text(
            REJECT_ON_OUTPUT.replace("pattern: bad", "pattern: second")
        )
        assert runner.invoke(main, ["score"]).exit_code == 0
        # current failures.yaml now hashes to config B, so deleting A's snapshot is not
        # undone by the rescue path (which only restores the current config).
        with sqlite3.connect(".detrix/store.db") as connection:
            connection.execute("DELETE FROM config_snapshots WHERE config_hash = ?", (hash_a,))
        result = runner.invoke(main, ["replay"])
        assert result.exit_code == 1, result.output
        outcomes = {
            (line.split()[1], line.split()[2])
            for line in result.output.splitlines()
            if line.startswith("t1 ")
        }
        assert (hash_a[:12], "UNREPLAYABLE") in outcomes, result.output
        assert any(outcome == "MATCH" for _, outcome in outcomes), result.output


def test_replay_pre_migration_v1_row_without_snapshot_is_legacy() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        Store()  # create the schema; no failures.yaml -> no rescue
        _insert_v1_verdict(
            ".detrix/store.db",
            trace_id="old",
            config_hash="a" * 64,
            trace_hash="b" * 64,
            packet={
                "schema_version": 1,
                "admission_decision": "ADMIT",
                "reason_codes": [],
                "failure_label": None,
            },
        )
        result = runner.invoke(main, ["replay"])
        assert result.exit_code == 0, result.output
        old_line = next(line for line in result.output.splitlines() if line.startswith("old "))
        assert old_line.split()[2] == "LEGACY", old_line
        assert "no snapshot" in old_line
        assert "LEGACY: 1" in result.output
        assert "WARNING" in result.output


def test_replay_rescues_current_config_for_v1_decision_comparison() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("failures.yaml").write_text(REJECT_ON_OUTPUT)
        config_hash = load_failures("failures.yaml").content_hash
        trace = _trace("old", "good")
        store = Store()
        store.upsert_trace(trace)  # writes the trace snapshot
        assert store.get_config_snapshot(config_hash) is None
        _insert_v1_verdict(
            ".detrix/store.db",
            trace_id="old",
            config_hash=config_hash,
            trace_hash=canonical_digest(trace),
            packet={
                "schema_version": 1,
                "admission_decision": "ADMIT",
                "reason_codes": [],
                "failure_label": None,
            },
        )
        result = runner.invoke(main, ["replay"])
        assert result.exit_code == 0, result.output
        old_line = next(line for line in result.output.splitlines() if line.startswith("old "))
        assert old_line.split()[2] == "LEGACY", old_line
        # a decision-level comparison ran (not the "no snapshot" LEGACY path)
        assert "decision" in old_line, old_line
        # rescue persisted the current config so the (trace, config) pair is reconstructible
        assert Store().get_config_snapshot(config_hash) is not None


def test_replay_mixed_v1_and_v2_never_drifts_v1() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("failures.yaml").write_text(REJECT_ON_OUTPUT)
        config_hash = load_failures("failures.yaml").content_hash
        store = Store()
        store.upsert_trace(_trace("v2trace", "good"))
        assert runner.invoke(main, ["score"]).exit_code == 0  # v2 verdict + snapshots
        legacy_trace = _trace("v1trace", "good")
        store.upsert_trace(legacy_trace)  # trace snapshot present; config snapshot already present
        _insert_v1_verdict(
            ".detrix/store.db",
            trace_id="v1trace",
            config_hash=config_hash,
            trace_hash=canonical_digest(legacy_trace),
            packet={
                "schema_version": 1,
                "admission_decision": "REJECT",  # deliberately wrong vs the v2 recompute
                "reason_codes": ["GATE_FAILED"],
                "failure_label": "bad-output",
            },
        )
        result = runner.invoke(main, ["replay"])
        assert result.exit_code == 0, result.output
        v1_line = next(line for line in result.output.splitlines() if line.startswith("v1trace "))
        v2_line = next(line for line in result.output.splitlines() if line.startswith("v2trace "))
        assert v1_line.split()[2] == "LEGACY", v1_line
        assert v2_line.split()[2] == "MATCH", v2_line
        assert "DRIFT: 0" in result.output


def test_replay_uses_each_verdicts_own_config_snapshot() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("failures.yaml").write_text(REJECT_ON_OUTPUT.replace("pattern: bad", "pattern: first"))
        Store().upsert_trace(_trace("t1", "first thing"))
        assert runner.invoke(main, ["score"]).exit_code == 0  # REJECT under config A
        Path("failures.yaml").write_text(
            REJECT_ON_OUTPUT.replace("pattern: bad", "pattern: second")
        )
        assert runner.invoke(main, ["score"]).exit_code == 0  # ADMIT under config B
        assert len(Store().list_verdicts()) == 2
        result = runner.invoke(main, ["replay"])
        # If replay scored both verdicts against the current file (config B) instead of
        # each verdict's own snapshot, the config-A verdict would DRIFT.
        assert result.exit_code == 0, result.output
        assert "MATCH: 2" in result.output
        assert "DRIFT: 0" in result.output


def test_replay_json_matches_text_output() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("failures.yaml").write_text(REJECT_ON_OUTPUT)
        store = Store()
        store.upsert_trace(_trace("clean", "good"))
        store.upsert_trace(_trace("bad", "bad result"))
        assert runner.invoke(main, ["score"]).exit_code == 0
        text = runner.invoke(main, ["replay"])
        payload = runner.invoke(main, ["replay", "--json"])
        assert text.exit_code == 0
        assert payload.exit_code == 0
        parsed = json.loads(payload.output)
        assert parsed["summary"]["MATCH"] == 2
        assert parsed["exit_code"] == 0
        assert {row["outcome"] for row in parsed["rows"]} == {"MATCH"}
        for row in parsed["rows"]:
            prefix = f"{row['trace_id']} {row['config_hash'][:12]} {row['outcome']}"
            assert prefix in text.output, prefix


def test_replay_json_signals_failure_exit_code() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        Store()
        _insert_v1_verdict(
            ".detrix/store.db",
            trace_id="post",
            config_hash="a" * 64,
            trace_hash="b" * 64,
            packet={
                "schema_version": ADMISSION_PACKET_SCHEMA_VERSION,
                "admission_decision": "ADMIT",
                "reason_codes": [],
                "failure_label": None,
            },
        )
        result = runner.invoke(main, ["replay", "--json"])
        assert result.exit_code == 1, result.output
        parsed = json.loads(result.output)
        assert parsed["rows"][0]["outcome"] == "UNREPLAYABLE"
        assert parsed["exit_code"] == 1
