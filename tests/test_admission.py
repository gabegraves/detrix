from __future__ import annotations

from importlib.metadata import version

import pytest
from pydantic import ValidationError

from detrix.admission import (
    AdmissionDecision,
    ConsequenceDecision,
    EvidencePointer,
    ReasonCode,
    verify_evidence_pointers,
)
from detrix.canonical import canonical_digest
from detrix.engine import score_trace
from detrix.gates import (
    DetectionConfig,
    DetectionKind,
    FailureConfig,
    GateConfig,
    RuleKind,
)


def packet() -> dict:
    return {
        "trace": {
            "id": "trace-1",
            "input": "task",
            "output": "finished",
            "metadata": {},
        },
        "observations": [
            {
                "id": "obs-1",
                "trace_id": "trace-1",
                "name": "shell",
                "level": "DEFAULT",
                "input": "pytest -q",
                "output": "2 passed",
                "metadata": {},
            }
        ],
    }


def config() -> GateConfig:
    return GateConfig(
        failures=[
            FailureConfig(
                id="secret-output",
                description="output must not contain a secret",
                severity="high",
                detection=DetectionConfig(
                    kind=DetectionKind.DETERMINISTIC,
                    rule=RuleKind.PRESENT_PATTERN,
                    field="trace.output",
                    pattern="secret",
                ),
            )
        ]
    )


def test_scored_evidence_pointers_round_trip() -> None:
    raw = packet()
    result = score_trace(raw, config())

    assert [pointer.pointer for pointer in result.evidence_pointers] == [
        "/trace",
        "/observations",
    ]
    assert verify_evidence_pointers(result, raw) == []


def test_tampered_trace_digest_fails_closed() -> None:
    raw = packet()
    result = score_trace(raw, config())
    assert result.admission_decision is AdmissionDecision.ADMIT
    raw["trace"]["output"] = "tampered"

    assert verify_evidence_pointers(result, raw) == ["digest_mismatch:/trace"]
    assert result.joinable is False
    assert result.admission_decision is AdmissionDecision.QUARANTINE
    assert result.consequence is ConsequenceDecision.QUARANTINE
    assert result.terminal_verdict == "QUARANTINE"
    assert result.joinability["evidence_pointer_failures"] == ["digest_mismatch:/trace"]
    assert result.reason_codes.count(ReasonCode.EVIDENCE_INTEGRITY) == 1


def test_missing_pointer_is_unresolvable() -> None:
    raw = packet()
    result = score_trace(raw, config())
    result.evidence_pointers[0].pointer = "/missing"

    assert verify_evidence_pointers(result, raw) == ["unresolvable_pointer:/missing"]


def test_nested_dict_and_list_pointer_resolves() -> None:
    result = score_trace(packet(), config())
    result.evidence_pointers = [
        EvidencePointer(
            kind="nested",
            pointer="/a/0/b",
            content_digest=canonical_digest("value"),
        )
    ]

    assert verify_evidence_pointers(result, {"a": [{"b": "value"}]}) == []


@pytest.mark.parametrize("pointer", ["trace", "/"])
def test_invalid_pointer_format_is_unresolvable(pointer: str) -> None:
    raw = packet()
    result = score_trace(raw, config())
    result.evidence_pointers[0].pointer = pointer

    assert verify_evidence_pointers(result, raw) == [f"unresolvable_pointer:{pointer}"]


def test_engine_quarantines_unresolvable_scored_pointer() -> None:
    raw = packet()
    del raw["observations"]

    result = score_trace(raw, config())

    assert result.admission_decision is AdmissionDecision.QUARANTINE
    assert result.joinability["evidence_pointer_failures"] == [
        "unresolvable_pointer:/observations"
    ]
    assert ReasonCode.EVIDENCE_INTEGRITY in result.reason_codes


def test_content_digest_must_be_sha256() -> None:
    with pytest.raises(ValidationError):
        EvidencePointer(kind="trace", pointer="/trace", content_digest="xyz")


def test_packet_schema_and_execution_identity() -> None:
    result = score_trace(packet(), config())

    assert result.schema_version == 2
    assert result.execution_identity == {
        "detrix_version": version("detrix"),
        "python_version": __import__("platform").python_version(),
        "config_hash": config().content_hash,
    }


def test_demo_equivalence_admission_decision_is_unchanged() -> None:
    assert score_trace(packet(), config()).admission_decision is AdmissionDecision.ADMIT
