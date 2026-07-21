from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from detrix.cli import main
from detrix.store import Store


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
