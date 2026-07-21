"""Governance contracts and the closed set of post-hoc trace rules."""

from __future__ import annotations

import hashlib
import json
import math
import re
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, computed_field, model_validator

MAX_PATTERN_LENGTH = 512
MAX_TARGET_TEXT = 1_000_000


class Decision(StrEnum):
    ACCEPT = "accept"
    REJECT = "reject"
    CAUTION = "caution"
    REQUEST_MORE_DATA = "request_more_data"
    UNKNOWN = "unknown"


class DetectionKind(StrEnum):
    DETERMINISTIC = "deterministic"
    STRUCTURAL = "structural"
    ADVISORY = "advisory"


class RuleKind(StrEnum):
    PRESENT_PATTERN = "present_pattern"
    ABSENT_PATTERN = "absent_pattern"
    JSON_FIELD_RANGE = "json_field_range"
    JSON_FIELD_REQUIRED = "json_field_required"
    OBSERVATION_ERROR_UNHANDLED = "observation_error_unhandled"


class GateIdentity(BaseModel):
    model_config = ConfigDict(frozen=True)

    gate_id: str
    code_version: str
    config_hash: str

    def as_tuple(self) -> tuple[str, str, str]:
        return self.gate_id, self.code_version, self.config_hash

    @property
    def evaluator_version(self) -> str:
        return f"{self.code_version}:{self.config_hash}"


class VerdictContract(BaseModel):
    model_config = ConfigDict(frozen=True)

    decision: Decision
    gate_id: str
    evidence: dict[str, Any]
    reason_codes: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    confidence: float | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    input_hash: str = ""
    evaluator_version: str = ""
    human_override: bool = False
    override_reason: str = ""
    rejection_type: str | None = None
    is_labeled: bool = False
    expert_decision: Decision | None = None
    source: str = "detrix"


class GateContext(BaseModel):
    run_id: str
    step_index: int = 0
    prior_verdicts: list[VerdictContract] = Field(default_factory=list)
    config: dict[str, Any] = Field(default_factory=dict)
    goal_mode: str = "post_hoc"


class EvaluatorResult(BaseModel):
    metrics: dict[str, float]
    passed_checks: list[str] = Field(default_factory=list)
    failed_checks: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    raw_output: Any = None


class GovernanceGate(ABC):
    @property
    @abstractmethod
    def gate_id(self) -> str: ...

    @property
    @abstractmethod
    def version(self) -> str: ...

    @abstractmethod
    def evaluate(self, inputs: dict[str, Any], context: GateContext) -> VerdictContract: ...

    def can_evaluate(self, inputs: dict[str, Any]) -> bool:
        return True


class DomainEvaluator(ABC):
    @property
    @abstractmethod
    def domain(self) -> str: ...

    @property
    @abstractmethod
    def evaluator_id(self) -> str: ...

    @property
    @abstractmethod
    def version(self) -> str: ...

    @abstractmethod
    def evaluate(self, data: Any, **kwargs: Any) -> EvaluatorResult: ...


class DetectionConfig(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: DetectionKind
    rule: RuleKind | None = None
    field: str | None = None
    pattern: str | None = None
    when_pattern: str | None = None
    min: float | None = None
    max: float | None = None
    prompt: str | None = None

    @model_validator(mode="after")
    def validate_contract(self) -> DetectionConfig:
        if self.kind is DetectionKind.ADVISORY:
            if not self.prompt or self.rule is not None:
                raise ValueError("advisory detection requires prompt and cannot define rule")
            return self
        if self.rule is None:
            raise ValueError("authoritative detection requires rule")
        if self.rule is not RuleKind.OBSERVATION_ERROR_UNHANDLED:
            _validate_field(self.field)
        if self.rule in {RuleKind.PRESENT_PATTERN, RuleKind.ABSENT_PATTERN}:
            _compile_pattern(self.pattern, "pattern")
        if self.when_pattern is not None:
            if self.rule is not RuleKind.ABSENT_PATTERN:
                raise ValueError("when_pattern is supported only by absent_pattern")
            _compile_pattern(self.when_pattern, "when_pattern")
        if self.rule is RuleKind.JSON_FIELD_RANGE and (
            self.min is None
            or self.max is None
            or not math.isfinite(self.min)
            or not math.isfinite(self.max)
            or self.min > self.max
        ):
            raise ValueError("json_field_range requires finite min <= max")
        return self


class FailureConfig(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
    description: str = Field(min_length=1)
    severity: Literal["high", "medium", "low"]
    detection: DetectionConfig


class GateConfig(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    failures: list[FailureConfig]

    @model_validator(mode="after")
    def unique_ids(self) -> GateConfig:
        ids = [failure.id for failure in self.failures]
        if len(ids) != len(set(ids)):
            raise ValueError("failure ids must be unique")
        return self

    @computed_field
    @property
    def content_hash(self) -> str:
        payload = self.model_dump(mode="json", exclude={"content_hash"})
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(encoded).hexdigest()


class EvidenceMissingError(ValueError):
    pass


class RuleGate(GovernanceGate):
    """One configured failure mode. Rules detect failures, not desired behavior."""

    def __init__(self, failure: FailureConfig) -> None:
        self.failure = failure

    @property
    def gate_id(self) -> str:
        return self.failure.id

    @property
    def version(self) -> str:
        return "1"

    @property
    def identity(self) -> GateIdentity:
        encoded = json.dumps(
            self.failure.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
        ).encode()
        return GateIdentity(
            gate_id=self.gate_id,
            code_version=self.version,
            config_hash=hashlib.sha256(encoded).hexdigest(),
        )

    def evaluate(self, inputs: dict[str, Any], context: GateContext) -> VerdictContract:
        del context
        detection = self.failure.detection
        input_hash = _hash_json(inputs)
        if detection.kind is DetectionKind.ADVISORY:
            return self._verdict(
                Decision.CAUTION,
                {"prompt": detection.prompt, "authoritative": False},
                ["ADVISORY_ONLY"],
                input_hash,
            )
        hit, evidence = _evaluate_rule(detection, inputs)
        return self._verdict(
            Decision.REJECT if hit else Decision.ACCEPT,
            evidence,
            ["GATE_FAILED"] if hit else [],
            input_hash,
        )

    def _verdict(
        self,
        decision: Decision,
        evidence: dict[str, Any],
        reasons: list[str],
        input_hash: str,
    ) -> VerdictContract:
        return VerdictContract(
            decision=decision,
            gate_id=self.gate_id,
            evidence=evidence,
            reason_codes=reasons,
            input_hash=input_hash,
            evaluator_version=self.identity.evaluator_version,
            rejection_type=self.failure.id if decision is Decision.REJECT else None,
        )


def _evaluate_rule(detection: DetectionConfig, packet: dict[str, Any]) -> tuple[bool, dict]:
    rule = detection.rule
    if rule is RuleKind.OBSERVATION_ERROR_UNHANDLED:
        return _unhandled_error(packet)

    _require_expanded_metadata(detection.field, packet)

    values, addressed = _resolve_field(packet, detection.field or "")
    if rule is RuleKind.ABSENT_PATTERN:
        if detection.when_pattern and not _compile_pattern(
            detection.when_pattern, "when_pattern"
        ).search(_as_text(packet)):
            return False, {"field": detection.field, "guard_matched": False}
        empty_observation_set = (
            bool(detection.field and detection.field.startswith("observations[*]."))
            and packet.get("observations") == []
        )
        if (not addressed or not values) and not empty_observation_set:
            raise EvidenceMissingError(f"field has no evidence: {detection.field}")
        if any(value is None for value in values):
            raise EvidenceMissingError(f"field contains null evidence: {detection.field}")
        regex = _compile_pattern(detection.pattern, "pattern")
        matched = any(regex.search(_as_text(value)) for value in values)
        return not matched, {
            "field": detection.field,
            "matched": matched,
            "values_seen": len(values),
        }
    if rule is RuleKind.JSON_FIELD_REQUIRED:
        if detection.field and detection.field.startswith("observations[*].") and not packet.get(
            "observations"
        ):
            raise EvidenceMissingError(f"field has no evidence: {detection.field}")
        missing = not addressed or not values or any(value is None for value in values)
        return missing, {"field": detection.field, "missing": missing}
    if not addressed or not values:
        raise EvidenceMissingError(f"field has no evidence: {detection.field}")
    if rule is RuleKind.PRESENT_PATTERN:
        if any(value is None for value in values):
            raise EvidenceMissingError(f"field contains null evidence: {detection.field}")
        regex = _compile_pattern(detection.pattern, "pattern")
        matched = any(regex.search(_as_text(value)) for value in values)
        return matched, {"field": detection.field, "matched": matched}
    if rule is RuleKind.JSON_FIELD_RANGE:
        if any(isinstance(value, bool) or not isinstance(value, (int, float)) for value in values):
            raise EvidenceMissingError(f"field is not numeric: {detection.field}")
        if any(not math.isfinite(value) for value in values):
            raise EvidenceMissingError(f"field is not finite: {detection.field}")
        minimum, maximum = detection.min, detection.max
        if minimum is None or maximum is None:  # protected by config validation
            raise ValueError("json_field_range bounds are missing")
        out = [value for value in values if value < minimum or value > maximum]
        return bool(out), {"field": detection.field, "out_of_range": out}
    raise ValueError(f"unsupported rule: {rule}")


def _resolve_field(packet: dict[str, Any], address: str) -> tuple[list[Any], bool]:
    if address.startswith("trace."):
        current: Any = packet.get("trace")
        for part in address.split(".")[1:]:
            if not isinstance(current, dict) or part not in current:
                return [], False
            current = current[part]
        return [current], True
    prefix = "observations[*]."
    if address.startswith(prefix) and isinstance(packet.get("observations"), list):
        parts = address[len(prefix) :].split(".")
        values: list[Any] = []
        addressed = True
        for observation in packet["observations"]:
            current = observation
            for part in parts:
                if not isinstance(current, dict) or part not in current:
                    addressed = False
                    break
                current = current[part]
            else:
                values.append(current)
        return values, addressed
    return [], False


def _require_expanded_metadata(field: str | None, packet: dict[str, Any]) -> None:
    prefix = "observations[*].metadata."
    provenance = packet.get("_detrix")
    if not field or not field.startswith(prefix) or not isinstance(provenance, dict):
        return
    expanded = provenance.get("observation_metadata_expanded")
    key = field.removeprefix(prefix)
    if not isinstance(expanded, list) or key not in expanded:
        raise EvidenceMissingError(f"metadata field was not collected in full: {field}")


def _unhandled_error(packet: dict[str, Any]) -> tuple[bool, dict]:
    observations = packet.get("observations")
    if not isinstance(observations, list):
        raise EvidenceMissingError("observations are missing")
    unhandled: list[str] = []
    for index, observation in enumerate(observations):
        if not isinstance(observation, dict):
            raise EvidenceMissingError("observation is malformed")
        if str(observation.get("level", "")).upper() != "ERROR":
            continue
        error_id = observation.get("id")
        if not isinstance(error_id, str) or not error_id:
            raise EvidenceMissingError("error observation has no id")
        later_references = []
        for later in observations[index + 1 :]:
            if not isinstance(later, dict):
                raise EvidenceMissingError("observation is malformed")
            later_references.append(
                {
                    "input": later.get("input"),
                    "output": later.get("output"),
                    "metadata": later.get("metadata"),
                }
            )
        reference_pattern = re.compile(
            rf"(?<![A-Za-z0-9_-]){re.escape(error_id)}(?![A-Za-z0-9_-])"
        )
        if not any(reference_pattern.search(_as_text(reference)) for reference in later_references):
            unhandled.append(error_id)
    return bool(unhandled), {"unhandled_observation_ids": unhandled}


def _validate_field(field: str | None) -> None:
    allowed = {"trace.input", "trace.output"}
    wildcard = {"input", "output", "name", "level"}
    valid = field in allowed
    valid |= bool(field and field.startswith("trace.metadata.") and len(field.split(".")) == 3)
    if field and field.startswith("observations[*]."):
        suffix = field.removeprefix("observations[*].")
        valid |= suffix in wildcard or (
            suffix.startswith("metadata.") and len(suffix.split(".")) == 2
        )
    if not valid:
        raise ValueError(f"unsupported field address: {field}")


def _compile_pattern(pattern: str | None, name: str) -> re.Pattern[str]:
    if not pattern:
        raise ValueError(f"{name} is required")
    if len(pattern) > MAX_PATTERN_LENGTH:
        raise ValueError(f"{name} exceeds {MAX_PATTERN_LENGTH} characters")
    _reject_unsafe_pattern(pattern, name)
    try:
        return re.compile(pattern, re.IGNORECASE | re.DOTALL)
    except re.error as exc:
        raise ValueError(f"invalid {name}: {exc}") from exc


def _reject_unsafe_pattern(pattern: str, name: str) -> None:
    """Reject quantified groups whose nested repetition or alternation can backtrack badly."""

    groups: list[list[bool]] = []  # [contains_quantifier, contains_alternation]
    escaped = False
    in_character_class = False
    last_closed_group_risky = False
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if escaped:
            escaped = False
            last_closed_group_risky = False
        elif char == "\\":
            escaped = True
            last_closed_group_risky = False
        elif in_character_class:
            if char == "]":
                in_character_class = False
            last_closed_group_risky = False
        elif char == "[":
            in_character_class = True
            last_closed_group_risky = False
        elif char == "(":
            groups.append([False, False])
            last_closed_group_risky = False
        elif char == ")" and groups:
            contains_quantifier, contains_alternation = groups.pop()
            last_closed_group_risky = contains_quantifier or contains_alternation
            if groups and contains_quantifier:
                groups[-1][0] = True
        elif char == "|":
            if groups:
                groups[-1][1] = True
            last_closed_group_risky = False
        elif _is_quantifier(pattern, index):
            is_group_extension = char == "?" and index > 0 and pattern[index - 1] == "("
            if not is_group_extension:
                if last_closed_group_risky:
                    raise ValueError(
                        f"unsafe {name}: quantified groups cannot contain repetition or alternation"
                    )
                if groups:
                    groups[-1][0] = True
            last_closed_group_risky = False
        else:
            last_closed_group_risky = False
        index += 1


def _is_quantifier(pattern: str, index: int) -> bool:
    if pattern[index] in "*+?":
        return True
    if pattern[index] != "{":
        return False
    return re.match(r"\{\d+(?:,\d*)?\}", pattern[index:]) is not None


def _as_text(value: Any) -> str:
    text = value if isinstance(value, str) else json.dumps(value, sort_keys=True)
    if len(text) > MAX_TARGET_TEXT:
        raise EvidenceMissingError("addressed evidence exceeds safe evaluation size")
    return text


def _hash_json(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()
