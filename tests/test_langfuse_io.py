from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from detrix.engine import score_trace
from detrix.gates import DetectionConfig, FailureConfig, GateConfig
from detrix.langfuse_io import (
    LangfuseBoundaryError,
    build_client,
    pull_traces,
    push_scores,
)
from detrix.store import Store


class Model:
    def __init__(self, **values: object) -> None:
        self.values = values

    def model_dump(self, **_: object) -> dict:
        return self.values


class FakeTraceAPI:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def list(self, **kwargs: object) -> SimpleNamespace:
        self.calls.append(kwargs)
        return SimpleNamespace(
            data=[
                Model(
                    id="trace-1",
                    timestamp="2026-07-20T00:00:00Z",
                    input={"task": "test"},
                    output="done",
                    metadata={"team": "demo"},
                    tags=["prod"],
                    session_id="session-1",
                )
            ],
            meta=SimpleNamespace(total_pages=1),
        )

    def get(self, trace_id: str, **kwargs: object) -> Model:
        self.calls.append({"get": trace_id, **kwargs})
        return Model(
            id=trace_id,
            input={"task": "test"},
            output="done",
            metadata={"team": "demo"},
        )


class FakeObservationAPI:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def get_many(self, **kwargs: object) -> SimpleNamespace:
        self.calls.append(kwargs)
        return SimpleNamespace(
            data=[
                Model(
                    id="obs-1",
                    trace_id="trace-1",
                    name="shell",
                    level="DEFAULT",
                    input="pytest -q",
                    output="1 passed",
                    metadata={"exit_code": 0},
                    start_time="2026-07-20T00:00:01Z",
                )
            ],
            meta=SimpleNamespace(cursor=None),
        )


class FakeIngestionAPI:
    def __init__(self) -> None:
        self.batches: list[list[object]] = []

    def batch(self, *, batch: list[object]) -> SimpleNamespace:
        self.batches.append(batch)
        return SimpleNamespace(
            successes=[SimpleNamespace(id=item.id, status=201) for item in batch],
            errors=[],
        )


class FakeClient:
    def __init__(self) -> None:
        self.trace_api = FakeTraceAPI()
        self.observation_api = FakeObservationAPI()
        self.ingestion_api = FakeIngestionAPI()
        self.api = SimpleNamespace(
            trace=self.trace_api,
            observations=self.observation_api,
            ingestion=self.ingestion_api,
        )


def gate() -> GateConfig:
    return GateConfig(
        failures=[
            FailureConfig(
                id="claims-done-no-tests",
                description="claims done without tests",
                severity="high",
                detection=DetectionConfig(
                    kind="deterministic",
                    rule="absent_pattern",
                    field="observations[*].input",
                    pattern="pytest",
                    when_pattern="done",
                ),
            )
        ]
    )


def test_pull_uses_public_trace_and_observation_apis(tmp_path: Path) -> None:
    store = Store(tmp_path / ".detrix" / "store.db")
    client = FakeClient()
    count = pull_traces(
        store,
        client=client,
        since="2026-07-01T00:00:00Z",
        limit=5,
        tag="prod",
        session="session-1",
        metadata_keys=["score"],
    )
    assert count == 1
    assert client.trace_api.calls[0] == (
        {
            "page": 1,
            "limit": 5,
            "from_timestamp": datetime(2026, 7, 1, tzinfo=UTC),
            "tags": "prod",
            "session_id": "session-1",
            "order_by": "timestamp.desc",
            "fields": "core,io",
        }
    )
    assert client.trace_api.calls[1] == {"get": "trace-1", "fields": "core,io"}
    assert client.observation_api.calls[0]["trace_id"] == "trace-1"
    assert client.observation_api.calls[0]["fields"] == "core,basic,time,io,metadata"
    assert client.observation_api.calls[0]["expand_metadata"] == "score"
    assert store.list_traces()[0]["trace_id"] == "trace-1"


def test_missing_environment_names_are_actionable(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("LANGFUSE_PUBLIC_KEY", "LANGFUSE_SECRET_KEY", "LANGFUSE_HOST"):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(LangfuseBoundaryError, match="LANGFUSE_PUBLIC_KEY"):
        build_client()


def test_push_is_idempotent_and_records_deterministic_score_ids(tmp_path: Path) -> None:
    store = Store(tmp_path / ".detrix" / "store.db")
    raw = {
        "trace": {"id": "trace-1", "input": "task", "output": "done", "metadata": {}},
        "observations": [
            {
                "id": "obs-1",
                "trace_id": "trace-1",
                "name": "shell",
                "level": "DEFAULT",
                "input": "pytest -q",
                "output": "passed",
                "metadata": {},
            }
        ],
    }
    packet = score_trace(raw, gate())
    store.save_verdict(packet)
    first = FakeClient()
    assert push_scores(store, client=first) == 2
    events = first.ingestion_api.batches[0]
    assert [event.body.name for event in events] == [
        "detrix.verdict",
        "detrix.gate.claims-done-no-tests",
    ]
    assert events[0].body.value == "ADMIT"
    assert events[0].body.data_type == "CATEGORICAL"
    assert events[1].body.value == 1.0
    assert events[1].body.data_type == "NUMERIC"
    assert packet.config_hash in events[0].body.comment
    assert all(event.id == event.body.id for event in events)
    assert len(store.push_receipts()) == 2

    second = FakeClient()
    assert push_scores(store, client=second) == 0
    assert second.ingestion_api.batches == []


def test_boundary_error_does_not_echo_secret(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret = "sentinel-secret-never-print"
    monkeypatch.setenv("LANGFUSE_SECRET_KEY", secret)
    store = Store(tmp_path / ".detrix" / "store.db")

    class BrokenClient(FakeClient):
        def __init__(self) -> None:
            super().__init__()

            class BrokenIngestion:
                def batch(self, *, batch: list[object]) -> SimpleNamespace:
                    raise RuntimeError(
                        f"Authorization: Bearer {secret}; response body private"
                    )

            self.api.ingestion = BrokenIngestion()

    raw = {
        "trace": {"id": "trace-1", "input": "", "output": "", "metadata": {}},
        "observations": [],
    }
    store.save_verdict(score_trace(raw, gate()))
    with pytest.raises(LangfuseBoundaryError) as error:
        push_scores(store, client=BrokenClient())
    assert secret not in str(error.value)
    assert "response body" not in str(error.value)


def test_push_rejection_is_not_recorded_as_success(tmp_path: Path) -> None:
    store = Store(tmp_path / ".detrix" / "store.db")
    raw = {
        "trace": {"id": "trace-1", "input": "", "output": "", "metadata": {}},
        "observations": [],
    }
    store.save_verdict(score_trace(raw, gate()))
    client = FakeClient()

    class RejectingIngestion:
        def batch(self, *, batch: list[object]) -> SimpleNamespace:
            return SimpleNamespace(
                successes=[],
                errors=[SimpleNamespace(id=item.id, status=400) for item in batch],
            )

    client.api.ingestion = RejectingIngestion()
    with pytest.raises(LangfuseBoundaryError, match=r"HTTP statuses=\[400\]"):
        push_scores(store, client=client)
    assert store.push_receipts() == []


def test_push_refuses_stale_verdicts_before_network_call(tmp_path: Path) -> None:
    store = Store(tmp_path / ".detrix" / "store.db")
    raw = {
        "trace": {"id": "trace-1", "input": "", "output": "", "metadata": {}},
        "observations": [],
    }
    current = gate()
    store.save_verdict(score_trace(raw, current))
    changed = GateConfig(
        failures=[
            FailureConfig(
                id="different",
                description="different config",
                severity="high",
                detection=DetectionConfig(
                    kind="deterministic",
                    rule="present_pattern",
                    field="trace.output",
                    pattern="bad",
                ),
            )
        ]
    )
    store.activate_config(changed.content_hash)
    client = FakeClient()
    with pytest.raises(LangfuseBoundaryError, match="stale verdicts require detrix score"):
        push_scores(store, client=client)
    assert client.ingestion_api.batches == []
