from __future__ import annotations

import pytest
from pydantic import ValidationError

from detrix.admission import AdmissionDecision, ReasonCode
from detrix.engine import score_trace
from detrix.gates import (
    DetectionConfig,
    DetectionKind,
    FailureConfig,
    GateConfig,
    RuleKind,
)


def packet(*, output: object = "finished", observations: list[dict] | None = None) -> dict:
    return {
        "trace": {"id": "trace-1", "input": "task", "output": output, "metadata": {}},
        "observations": observations
        if observations is not None
        else [
            {
                "id": "obs-1",
                "trace_id": "trace-1",
                "name": "shell",
                "level": "DEFAULT",
                "input": "pytest -q",
                "output": "2 passed",
                "metadata": {"score": 0.8, "artifact": "report.json"},
            }
        ],
    }


def config(rule: RuleKind, **values: object) -> GateConfig:
    return GateConfig(
        failures=[
            FailureConfig(
                id=f"failure-{rule.value.replace('_', '-')}",
                description="test failure",
                severity="high",
                detection=DetectionConfig(
                    kind=DetectionKind.DETERMINISTIC,
                    rule=rule,
                    **values,
                ),
            )
        ]
    )


@pytest.mark.parametrize(
    ("gate_config", "passing", "failing"),
    [
        (
            config(RuleKind.PRESENT_PATTERN, field="trace.output", pattern="secret"),
            packet(output="all clear"),
            packet(output="leaked secret"),
        ),
        (
            config(
                RuleKind.ABSENT_PATTERN,
                field="observations[*].input",
                pattern="pytest",
                when_pattern="finished",
            ),
            packet(),
            packet(observations=[]),
        ),
        (
            config(
                RuleKind.JSON_FIELD_RANGE,
                field="observations[*].metadata.score",
                min=0.5,
                max=1.0,
            ),
            packet(),
            packet(
                observations=[
                    {
                        "id": "obs-1",
                        "trace_id": "trace-1",
                        "name": "judge",
                        "level": "DEFAULT",
                        "input": "",
                        "output": "",
                        "metadata": {"score": 0.2},
                    }
                ]
            ),
        ),
        (
            config(
                RuleKind.JSON_FIELD_REQUIRED,
                field="observations[*].metadata.artifact",
            ),
            packet(),
            packet(
                observations=[
                    {
                        "id": "obs-1",
                        "trace_id": "trace-1",
                        "name": "shell",
                        "level": "DEFAULT",
                        "input": "pytest",
                        "output": "passed",
                        "metadata": {},
                    }
                ]
            ),
        ),
        (
            config(RuleKind.OBSERVATION_ERROR_UNHANDLED),
            packet(
                observations=[
                    {
                        "id": "err-1",
                        "trace_id": "trace-1",
                        "name": "tool",
                        "level": "ERROR",
                        "input": "run",
                        "output": "failed",
                        "metadata": {},
                    },
                    {
                        "id": "obs-2",
                        "trace_id": "trace-1",
                        "name": "recovery",
                        "level": "DEFAULT",
                        "input": "handle err-1",
                        "output": "recovered",
                        "metadata": {},
                    },
                ]
            ),
            packet(
                observations=[
                    {
                        "id": "err-1",
                        "trace_id": "trace-1",
                        "name": "tool",
                        "level": "ERROR",
                        "input": "run",
                        "output": "failed",
                        "metadata": {},
                    }
                ]
            ),
        ),
    ],
)
def test_each_authoritative_rule_passes_and_fails(
    gate_config: GateConfig, passing: dict, failing: dict
) -> None:
    assert score_trace(passing, gate_config).admission_decision is AdmissionDecision.ADMIT
    rejected = score_trace(failing, gate_config)
    assert rejected.admission_decision is AdmissionDecision.REJECT
    assert ReasonCode.GATE_FAILED in rejected.reason_codes


def test_missing_evidence_fails_closed() -> None:
    result = score_trace(
        packet(observations=[]),
        config(RuleKind.JSON_FIELD_REQUIRED, field="observations[*].metadata.artifact"),
    )
    assert result.admission_decision is AdmissionDecision.QUARANTINE
    assert ReasonCode.EVIDENCE_MISSING in result.reason_codes


def test_observation_without_trace_ownership_is_unjoinable() -> None:
    raw = packet()
    raw["observations"][0].pop("trace_id")
    result = score_trace(raw, config(RuleKind.PRESENT_PATTERN, field="trace.output", pattern="x"))
    assert result.admission_decision is AdmissionDecision.QUARANTINE
    assert ReasonCode.OBSERVATIONS_UNJOINABLE in result.reason_codes


def test_advisory_gate_never_changes_authoritative_verdict() -> None:
    gate_config = GateConfig(
        failures=[
            config(RuleKind.PRESENT_PATTERN, field="trace.output", pattern="secret").failures[0],
            FailureConfig(
                id="fabricated-path",
                description="may fabricate paths",
                severity="high",
                detection=DetectionConfig(
                    kind=DetectionKind.ADVISORY,
                    prompt="Does the answer fabricate paths?",
                ),
            ),
        ]
    )
    result = score_trace(packet(), gate_config)
    assert result.admission_decision is AdmissionDecision.ADMIT
    assert result.support_only is False
    assert any(item["decision"] == "caution" for item in result.verifier_verdicts)


def test_advisory_only_config_is_support_only() -> None:
    gate_config = GateConfig(
        failures=[
            FailureConfig(
                id="manual-review",
                description="review needed",
                severity="medium",
                detection=DetectionConfig(kind="advisory", prompt="Review this trace"),
            )
        ]
    )
    assert score_trace(packet(), gate_config).admission_decision is AdmissionDecision.SUPPORT_ONLY


def test_empty_config_quarantines_instead_of_admitting() -> None:
    result = score_trace(packet(), GateConfig(failures=[]))
    assert result.admission_decision is AdmissionDecision.QUARANTINE
    assert ReasonCode.NO_AUTHORITATIVE_GATES in result.reason_codes


def test_null_pattern_evidence_quarantines() -> None:
    result = score_trace(
        packet(output=None),
        config(RuleKind.PRESENT_PATTERN, field="trace.output", pattern="secret"),
    )
    assert result.admission_decision is AdmissionDecision.QUARANTINE
    assert ReasonCode.EVIDENCE_MISSING in result.reason_codes


def test_unexpanded_langfuse_metadata_quarantines() -> None:
    raw = packet()
    raw["_detrix"] = {"observation_metadata_expanded": []}
    result = score_trace(
        raw,
        config(
            RuleKind.JSON_FIELD_RANGE,
            field="observations[*].metadata.score",
            min=0,
            max=1,
        ),
    )
    assert result.admission_decision is AdmissionDecision.QUARANTINE
    assert ReasonCode.EVIDENCE_MISSING in result.reason_codes


@pytest.mark.parametrize("bound", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_range_bounds_are_rejected(bound: float) -> None:
    with pytest.raises(ValidationError):
        DetectionConfig(
            kind="deterministic",
            rule="json_field_range",
            field="trace.metadata.score",
            min=bound,
            max=1,
        )


def test_non_finite_observed_value_quarantines() -> None:
    raw = packet()
    raw["trace"]["metadata"]["score"] = float("nan")
    result = score_trace(
        raw,
        config(RuleKind.JSON_FIELD_RANGE, field="trace.metadata.score", min=0, max=1),
    )
    assert result.admission_decision is AdmissionDecision.QUARANTINE
    assert ReasonCode.EVIDENCE_MISSING in result.reason_codes


def test_absent_pattern_missing_field_quarantines() -> None:
    raw = packet()
    del raw["observations"][0]["input"]
    result = score_trace(
        raw,
        config(
            RuleKind.ABSENT_PATTERN,
            field="observations[*].input",
            pattern="pytest",
            when_pattern="finished",
        ),
    )
    assert result.admission_decision is AdmissionDecision.QUARANTINE
    assert ReasonCode.EVIDENCE_MISSING in result.reason_codes


def test_error_id_in_later_observation_name_does_not_count_as_handled() -> None:
    raw = packet(
        observations=[
            {
                "id": "err-1",
                "trace_id": "trace-1",
                "name": "tool",
                "level": "ERROR",
                "input": "run",
                "output": "failed",
                "metadata": {},
            },
            {
                "id": "obs-2",
                "trace_id": "trace-1",
                "name": "coincidental err-1",
                "level": "DEFAULT",
                "input": "unrelated",
                "output": "unrelated",
                "metadata": {},
            },
        ]
    )
    result = score_trace(raw, config(RuleKind.OBSERVATION_ERROR_UNHANDLED))
    assert result.admission_decision is AdmissionDecision.REJECT


def test_error_id_prefix_collision_does_not_count_as_handled() -> None:
    raw = packet(
        observations=[
            {
                "id": "err-1",
                "trace_id": "trace-1",
                "name": "tool",
                "level": "ERROR",
                "input": "run",
                "output": "failed",
                "metadata": {},
            },
            {
                "id": "obs-2",
                "trace_id": "trace-1",
                "name": "recovery",
                "level": "DEFAULT",
                "input": "handled err-10",
                "output": "unrelated",
                "metadata": {},
            },
        ]
    )
    result = score_trace(raw, config(RuleKind.OBSERVATION_ERROR_UNHANDLED))
    assert result.admission_decision is AdmissionDecision.REJECT


def test_nested_quantifier_pattern_is_rejected_before_scoring() -> None:
    with pytest.raises(ValidationError, match="unsafe pattern"):
        DetectionConfig(
            kind="deterministic",
            rule="present_pattern",
            field="trace.output",
            pattern="(a+)+$",
        )


@pytest.mark.parametrize(
    "detection",
    [
        {"kind": "deterministic", "rule": "present_pattern", "field": "trace.output"},
        {
            "kind": "deterministic",
            "rule": "json_field_range",
            "field": "trace.metadata.score",
            "min": 2,
            "max": 1,
        },
        {"kind": "deterministic", "rule": "json_field_required", "field": "trace.id"},
    ],
)
def test_invalid_gate_configuration_is_rejected(detection: dict) -> None:
    with pytest.raises(ValidationError):
        DetectionConfig.model_validate(detection)
