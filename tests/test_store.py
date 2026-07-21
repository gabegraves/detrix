from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from detrix.engine import score_trace
from detrix.gates import DetectionConfig, FailureConfig, GateConfig
from detrix.store import Store, StoreError


def trace(trace_id: str = "trace-1", output: str = "done") -> dict:
    return {
        "trace": {"id": trace_id, "input": "task", "output": output, "metadata": {}},
        "observations": [
            {
                "id": "obs-1",
                "trace_id": trace_id,
                "name": "shell",
                "level": "DEFAULT",
                "input": "pytest -q",
                "output": "passed",
                "metadata": {},
            }
        ],
    }


def gate(pattern: str) -> GateConfig:
    return GateConfig(
        failures=[
            FailureConfig(
                id="bad-output",
                description="bad output appears",
                severity="high",
                detection=DetectionConfig(
                    kind="deterministic",
                    rule="present_pattern",
                    field="trace.output",
                    pattern=pattern,
                ),
            )
        ]
    )


def test_raw_trace_upsert_is_idempotent_and_secure(tmp_path: Path) -> None:
    db_path = tmp_path / ".detrix" / "store.db"
    store = Store(db_path)
    store.upsert_trace(trace())
    store.upsert_trace(trace(output="finished"))
    rows = store.list_traces()
    assert len(rows) == 1
    assert json.loads(rows[0]["raw_json"])["trace"]["output"] == "finished"
    assert db_path.parent.stat().st_mode & 0o777 == 0o700
    assert db_path.stat().st_mode & 0o777 == 0o600


def test_store_rejects_symlinked_parent_without_chmod_follow(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir(mode=0o755)
    linked = tmp_path / "linked"
    os.symlink(real, linked)
    with pytest.raises(StoreError, match="symlinked directory"):
        Store(linked / "store.db")
    assert real.stat().st_mode & 0o777 == 0o755


def test_config_change_appends_replay_event_without_rewriting_verdict(tmp_path: Path) -> None:
    store = Store(tmp_path / ".detrix" / "store.db")
    raw = trace()
    old = score_trace(raw, gate("secret"))
    new = score_trace(raw, gate("forbidden"))
    assert store.save_verdict(old) is True
    old_json = store.get_verdict("trace-1", old.config_hash)["packet_json"]
    assert store.save_verdict(new) is True
    assert store.get_verdict("trace-1", old.config_hash)["packet_json"] == old_json
    assert store.get_verdict("trace-1", old.config_hash)["stale"] == 1
    events = store.list_events()
    assert events == [
        {
            "schema_version": 1,
            "event_type": "REPLAY_REQUIRED",
            "trace_id": "trace-1",
            "old_config_hash": old.config_hash,
            "new_config_hash": new.config_hash,
        }
    ]
    assert store.save_verdict(new) is False
    assert store.list_events() == events


def test_changed_trace_content_supersedes_same_config_verdict(tmp_path: Path) -> None:
    store = Store(tmp_path / ".detrix" / "store.db")
    config = gate("bad")
    first = score_trace(trace(output="good"), config)
    second = score_trace(trace(output="bad"), config)
    assert store.save_verdict(first) is True
    assert store.save_verdict(second) is True
    assert first.packet_id != second.packet_id
    rows = store.list_verdicts()
    assert [row["decision"] for row in rows] == ["ADMIT", "REJECT"]
    assert rows[0]["stale"] == 1
    assert rows[1]["stale"] == 0
    assert store.list_verdicts(latest_only=True)[0]["decision"] == "REJECT"


def test_config_reversion_becomes_current_without_rewriting_history(tmp_path: Path) -> None:
    store = Store(tmp_path / ".detrix" / "store.db")
    raw = trace(output="secret")
    config_a = gate("secret")
    config_b = gate("forbidden")
    assert store.save_verdict(score_trace(raw, config_a)) is True
    assert store.save_verdict(score_trace(raw, config_b)) is True
    assert store.save_verdict(score_trace(raw, config_a)) is True
    assert [row["decision"] for row in store.list_verdicts()] == [
        "REJECT",
        "ADMIT",
        "REJECT",
    ]
    assert store.list_verdicts(latest_only=True)[0]["config_hash"] == config_a.content_hash
    assert [event["event_type"] for event in store.list_config_events()] == [
        "CONFIG_PROMOTED",
        "CONFIG_INVALIDATED",
        "CONFIG_PROMOTED",
        "CONFIG_INVALIDATED",
        "CONFIG_REVERTED",
    ]


def test_interrupted_config_replay_stales_unrescored_traces(tmp_path: Path) -> None:
    store = Store(tmp_path / ".detrix" / "store.db")
    config_a = gate("secret")
    config_b = gate("forbidden")
    for trace_id in ("trace-1", "trace-2"):
        store.save_verdict(score_trace(trace(trace_id, "clean"), config_a))

    store.activate_config(config_b.content_hash)
    store.save_verdict(score_trace(trace("trace-1", "clean"), config_b))

    rows = {row["trace_id"]: row for row in store.list_verdicts(latest_only=True)}
    assert rows["trace-1"]["config_hash"] == config_b.content_hash
    assert rows["trace-1"]["stale"] == 0
    assert rows["trace-2"]["config_hash"] == config_a.content_hash
    assert rows["trace-2"]["stale"] == 1


def test_push_receipts_are_config_and_score_aware(tmp_path: Path) -> None:
    store = Store(tmp_path / ".detrix" / "store.db")
    assert store.was_pushed("trace-1", "hash-1", "raw-1", "detrix.verdict") is False
    store.record_push("trace-1", "hash-1", "raw-1", "detrix.verdict", "score-1")
    assert store.was_pushed("trace-1", "hash-1", "raw-1", "detrix.verdict") is True
    assert store.was_pushed("trace-1", "hash-2", "raw-1", "detrix.verdict") is False
    assert store.was_pushed("trace-1", "hash-1", "raw-2", "detrix.verdict") is False
    assert store.was_pushed("trace-1", "hash-1", "raw-1", "detrix.gate.one") is False
