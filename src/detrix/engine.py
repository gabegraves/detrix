"""Deterministic-first reduction from gate verdicts to admission packets."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from detrix.admission import (
    AdmissionDecision,
    AdmissionPacket,
    ConsequenceDecision,
    EvidencePointer,
    ReasonCode,
)
from detrix.gates import (
    Decision,
    DetectionKind,
    EvidenceMissingError,
    GateConfig,
    GateContext,
    RuleGate,
    VerdictContract,
)


def score_trace(
    packet: dict[str, Any], config: GateConfig, *, source: str = "langfuse"
) -> AdmissionPacket:
    trace_id, joinable, joinability = _joinability(packet)
    verdicts: list[VerdictContract] = []
    reasons: list[ReasonCode] = []
    authoritative_count = 0

    if not joinable:
        reasons.append(ReasonCode.OBSERVATIONS_UNJOINABLE)
    else:
        context = GateContext(run_id=trace_id, config={"config_hash": config.content_hash})
        for failure in config.failures:
            if failure.detection.kind is not DetectionKind.ADVISORY:
                authoritative_count += 1
            try:
                verdict = RuleGate(failure).evaluate(packet, context)
            except EvidenceMissingError as exc:
                reasons.append(ReasonCode.EVIDENCE_MISSING)
                verdict = VerdictContract(
                    decision=Decision.REQUEST_MORE_DATA,
                    gate_id=failure.id,
                    evidence={"error": str(exc)},
                    reason_codes=[ReasonCode.EVIDENCE_MISSING],
                )
            except Exception:
                reasons.append(ReasonCode.GATE_ERROR)
                verdict = VerdictContract(
                    decision=Decision.UNKNOWN,
                    gate_id=failure.id,
                    evidence={"error": "gate evaluation failed"},
                    reason_codes=[ReasonCode.GATE_ERROR],
                )
            verdicts.append(verdict)

    decision, consequence = _reduce(joinable, verdicts, authoritative_count, reasons)
    for verdict in verdicts:
        for code in verdict.reason_codes:
            try:
                typed = ReasonCode(code)
            except ValueError:
                continue
            if typed is ReasonCode.ADVISORY_ONLY and authoritative_count:
                continue
            if typed not in reasons:
                reasons.append(typed)
    trace_hash = _hash_json(packet)
    packet_id = hashlib.sha256(
        f"{trace_id}:{config.content_hash}:{trace_hash}".encode()
    ).hexdigest()
    evidence_pointers = [
        EvidencePointer(kind="trace", pointer=f"trace:{trace_id}", sample_id=trace_id)
    ]
    return AdmissionPacket(
        packet_id=packet_id,
        run_id=trace_id,
        sample_id=trace_id,
        source=source,
        joinable=joinable,
        joinability=joinability,
        support_only=decision is AdmissionDecision.SUPPORT_ONLY,
        verifier_verdicts=[verdict.model_dump(mode="json") for verdict in verdicts],
        evidence_pointers=evidence_pointers,
        terminal_verdict=decision.value,
        failure_label=next(
            (verdict.gate_id for verdict in verdicts if verdict.decision is Decision.REJECT), None
        ),
        admission_decision=decision,
        consequence=consequence,
        reason_codes=reasons,
        recommended_actions=_actions(decision),
        evidence={"trace_sha256": trace_hash},
        raw_trace_ref=f"trace:{trace_id}",
        config_hash=config.content_hash,
        gate_results=[verdict.model_dump(mode="json") for verdict in verdicts],
    )


def _reduce(
    joinable: bool,
    verdicts: list[VerdictContract],
    authoritative_count: int,
    reasons: list[ReasonCode],
) -> tuple[AdmissionDecision, ConsequenceDecision]:
    if not joinable or any(
        verdict.decision in {Decision.REQUEST_MORE_DATA, Decision.UNKNOWN} for verdict in verdicts
    ):
        return AdmissionDecision.QUARANTINE, ConsequenceDecision.QUARANTINE
    authoritative = [verdict for verdict in verdicts if verdict.decision is not Decision.CAUTION]
    if any(verdict.decision is Decision.REJECT for verdict in authoritative):
        return AdmissionDecision.REJECT, ConsequenceDecision.EVIDENCE_REJECTED
    if authoritative_count == 0:
        if ReasonCode.NO_AUTHORITATIVE_GATES not in reasons:
            reasons.append(ReasonCode.NO_AUTHORITATIVE_GATES)
        if any(verdict.decision is Decision.CAUTION for verdict in verdicts):
            return AdmissionDecision.SUPPORT_ONLY, ConsequenceDecision.SUPPORT_ONLY
        reasons.append(ReasonCode.AMBIGUOUS_VERDICT)
        return AdmissionDecision.QUARANTINE, ConsequenceDecision.QUARANTINE
    if len(authoritative) != authoritative_count:
        reasons.append(ReasonCode.AMBIGUOUS_VERDICT)
        return AdmissionDecision.QUARANTINE, ConsequenceDecision.QUARANTINE
    return AdmissionDecision.ADMIT, ConsequenceDecision.EVIDENCE_ACCEPTED


def _joinability(packet: dict[str, Any]) -> tuple[str, bool, dict[str, Any]]:
    trace = packet.get("trace")
    observations = packet.get("observations")
    trace_id = trace.get("id") if isinstance(trace, dict) else None
    if not isinstance(trace_id, str) or not trace_id:
        return "unknown", False, {"error": "trace.id is missing"}
    if not isinstance(observations, list):
        return trace_id, False, {"error": "observations must be a list"}
    mismatches = [
        item.get("id", f"index:{index}")
        for index, item in enumerate(observations)
        if not isinstance(item, dict) or item.get("trace_id") != trace_id
    ]
    return trace_id, not mismatches, {
        "observation_count": len(observations),
        "mismatches": mismatches,
    }


def _actions(decision: AdmissionDecision) -> list[str]:
    if decision is AdmissionDecision.QUARANTINE:
        return ["repair or supply trace evidence, then rescore"]
    if decision is AdmissionDecision.REJECT:
        return ["inspect the failed deterministic gate"]
    if decision is AdmissionDecision.SUPPORT_ONLY:
        return ["harden advisory failures into deterministic rules"]
    return []


def _hash_json(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()
