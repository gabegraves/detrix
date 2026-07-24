"""Typed admission packets emitted by post-hoc scoring."""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field

from detrix.canonical import canonical_digest

ADMISSION_PACKET_SCHEMA_VERSION = 2
EvidenceClass = Literal["observed", "model_inferred", "prior_inferred", "unidentifiable"]


class AdmissionDecision(StrEnum):
    ADMIT = "ADMIT"
    REJECT = "REJECT"
    SUPPORT_ONLY = "SUPPORT_ONLY"
    QUARANTINE = "QUARANTINE"


class ConsequenceDecision(StrEnum):
    EVIDENCE_ACCEPTED = "evidence_accepted"
    EVIDENCE_REJECTED = "evidence_rejected"
    SUPPORT_ONLY = "support_only"
    QUARANTINE = "quarantine"


class TrainingEligibility(BaseModel):
    """Retained packet field; this post-hoc package never exports training data."""

    sft: bool = False
    dpo: bool = False
    grpo: bool = False
    echo: bool = False
    reason: str = "post_hoc_only"


class EvidencePointer(BaseModel):
    kind: str
    pointer: str
    content_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    sample_id: str | None = None
    file_id: str | None = None
    endpoint: str | None = None
    summary: str | None = None
    evidence_class: EvidenceClass = "observed"


class ReasonCode(StrEnum):
    GATE_FAILED = "GATE_FAILED"
    EVIDENCE_MISSING = "EVIDENCE_MISSING"
    OBSERVATIONS_UNJOINABLE = "OBSERVATIONS_UNJOINABLE"
    GATE_ERROR = "GATE_ERROR"
    AMBIGUOUS_VERDICT = "AMBIGUOUS_VERDICT"
    ADVISORY_ONLY = "ADVISORY_ONLY"
    NO_AUTHORITATIVE_GATES = "NO_AUTHORITATIVE_GATES"
    REPLAY_REQUIRED = "REPLAY_REQUIRED"
    EVIDENCE_INTEGRITY = "EVIDENCE_INTEGRITY"


class AdmissionPacket(BaseModel):
    """Stable public envelope for one trace/config evaluation."""

    schema_version: int = ADMISSION_PACKET_SCHEMA_VERSION
    packet_id: str
    run_id: str
    sample_id: str
    domain: str = "agent_trace"
    source: str = "langfuse"
    joinable: bool
    joinability: dict[str, Any] = Field(default_factory=dict)
    stale: bool = False
    support_only: bool = False
    verifier_verdicts: list[dict[str, Any]] = Field(default_factory=list)
    verifier_outputs: list[dict[str, Any]] = Field(default_factory=list)
    evidence_pointers: list[EvidencePointer] = Field(default_factory=list)
    terminal_route: dict[str, Any] | None = None
    terminal_verdict: str | None = None
    failure_label: str | None = None
    admission_decision: AdmissionDecision
    consequence: ConsequenceDecision
    training_eligibility: TrainingEligibility = Field(default_factory=TrainingEligibility)
    reward_components: list[dict[str, Any]] = Field(default_factory=list)
    trace_informativeness: dict[str, float] = Field(default_factory=dict)
    replay_status: str = "not_run"
    promotion_decisions: list[dict[str, Any]] = Field(default_factory=list)
    reason_codes: list[ReasonCode] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)
    execution_identity: dict[str, Any] = Field(default_factory=dict)
    arm: str | None = None
    sealed_label_ref: str | None = None
    raw_trace_ref: str = ""
    supersedes_packet_id: str | None = None
    claims: list[dict[str, Any]] = Field(default_factory=list)
    config_hash: str
    gate_results: list[dict[str, Any]] = Field(default_factory=list)


def verify_evidence_pointers(packet: AdmissionPacket, trace: dict) -> list[str]:
    """Verify packet evidence pointers against the scored trace."""

    failures: list[str] = []
    for evidence_pointer in packet.evidence_pointers:
        pointer = evidence_pointer.pointer
        try:
            value = _resolve_pointer(trace, pointer)
        except (IndexError, KeyError, TypeError, ValueError):
            failures.append(f"unresolvable_pointer:{pointer}")
            continue
        if canonical_digest(value) != evidence_pointer.content_digest:
            failures.append(f"digest_mismatch:{pointer}")

    if failures:
        packet.joinable = False
        packet.joinability = {
            **packet.joinability,
            "joinable": False,
            "evidence_pointer_failures": failures,
        }
        if ReasonCode.EVIDENCE_INTEGRITY not in packet.reason_codes:
            packet.reason_codes.append(ReasonCode.EVIDENCE_INTEGRITY)
    return failures


def _resolve_pointer(value: Any, pointer: str) -> Any:
    if not pointer.startswith("/") or pointer == "/":
        raise ValueError(pointer)
    current = value
    for raw_token in pointer[1:].split("/"):
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict):
            current = current[token]
        elif isinstance(current, list):
            if not token.isdigit():
                raise ValueError(pointer)
            current = current[int(token)]
        else:
            raise TypeError(pointer)
    return current
