"""Langfuse v4 collector and score-push boundary."""

from __future__ import annotations

import json
import os
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime
from importlib.metadata import version
from typing import Any

from detrix.admission import AdmissionPacket
from detrix.gates import Decision
from detrix.store import Store

SUPPORTED_LANGFUSE_MAJOR = 4
MAX_OBSERVATIONS_PER_TRACE = 10_000
MAX_TRACE_PACKET_BYTES = 10_000_000


class LangfuseBoundaryError(RuntimeError):
    pass


def build_client() -> Any:
    names = ("LANGFUSE_PUBLIC_KEY", "LANGFUSE_SECRET_KEY", "LANGFUSE_HOST")
    missing = [name for name in names if not os.getenv(name, "").strip()]
    if missing:
        raise LangfuseBoundaryError("missing Langfuse configuration: " + ", ".join(missing))
    installed = version("langfuse")
    if int(installed.split(".", 1)[0]) != SUPPORTED_LANGFUSE_MAJOR:
        raise LangfuseBoundaryError(
            f"unsupported langfuse {installed}; detrix requires major {SUPPORTED_LANGFUSE_MAJOR}"
        )
    try:
        from langfuse import Langfuse

        return Langfuse(
            public_key=os.environ["LANGFUSE_PUBLIC_KEY"],
            secret_key=os.environ["LANGFUSE_SECRET_KEY"],
            host=os.environ["LANGFUSE_HOST"],
        )
    except Exception as exc:
        raise _safe_error("client initialization", exc) from None


def pull_traces(
    store: Store,
    *,
    since: str | None = None,
    limit: int = 100,
    tag: str | None = None,
    session: str | None = None,
    metadata_keys: Sequence[str] = (),
    client: Any | None = None,
) -> int:
    if limit < 1:
        raise LangfuseBoundaryError("--limit must be at least 1")
    active_client = client or build_client()
    from_timestamp = _parse_since(since) if since else None
    collected = 0
    page = 1
    try:
        while collected < limit:
            page_limit = min(limit - collected, 100)
            response = active_client.api.trace.list(
                page=page,
                limit=page_limit,
                from_timestamp=from_timestamp,
                tags=tag,
                session_id=session,
                order_by="timestamp.desc",
                fields="core,io",
            )
            traces = list(response.data)
            for trace_model in traces[: limit - collected]:
                trace_summary = _model_dict(trace_model)
                trace_id = trace_summary.get("id")
                if not isinstance(trace_id, str) or not trace_id:
                    raise LangfuseBoundaryError("Langfuse returned a trace without an id")
                trace = {
                    **trace_summary,
                    **_model_dict(active_client.api.trace.get(trace_id, fields="core,io")),
                }
                observations = _fetch_observations(active_client, trace_id, metadata_keys)
                packet = {
                    "trace": trace,
                    "observations": observations,
                    "_detrix": {
                        "observation_metadata_expanded": sorted(set(metadata_keys)),
                    },
                }
                encoded = json.dumps(packet, sort_keys=True, separators=(",", ":")).encode()
                if len(encoded) > MAX_TRACE_PACKET_BYTES:
                    raise LangfuseBoundaryError(
                        f"trace {trace_id} exceeds the {MAX_TRACE_PACKET_BYTES}-byte safety limit"
                    )
                store.upsert_trace(packet)
                collected += 1
            total_pages = int(getattr(response.meta, "total_pages", page))
            if not traces or page >= total_pages:
                break
            page += 1
    except LangfuseBoundaryError:
        raise
    except Exception as exc:
        raise _safe_error("pull", exc) from None
    return collected


def push_scores(store: Store, *, client: Any | None = None) -> int:
    active_client = client or build_client()
    from langfuse.api import IngestionEvent_ScoreCreate, ScoreBody

    pending: list[tuple[Any, tuple[str, str, str, str, str]]] = []
    try:
        rows = store.list_verdicts(latest_only=True)
        stale_trace_ids = [row["trace_id"] for row in rows if row["stale"]]
        if stale_trace_ids:
            raise LangfuseBoundaryError(
                "stale verdicts require detrix score before push: "
                + ", ".join(stale_trace_ids[:5])
            )
        for row in rows:
            packet = AdmissionPacket.model_validate_json(row["packet_json"])
            trace_hash = _trace_hash(packet)
            comment = _score_comment(packet)
            scores: list[tuple[str, str | float, str]] = [
                ("detrix.verdict", packet.admission_decision.value, "CATEGORICAL")
            ]
            for result in packet.gate_results:
                decision = result.get("decision")
                if decision not in {Decision.ACCEPT.value, Decision.REJECT.value}:
                    continue
                scores.append(
                    (
                        f"detrix.gate.{result['gate_id']}",
                        1.0 if decision == Decision.ACCEPT.value else 0.0,
                        "NUMERIC",
                    )
                )
            for name, value, data_type in scores:
                if store.was_pushed(packet.run_id, packet.config_hash, trace_hash, name):
                    continue
                score_id = _score_id(packet.run_id, packet.config_hash, trace_hash, name)
                body = ScoreBody(
                    id=score_id,
                    trace_id=packet.run_id,
                    name=name,
                    value=value,
                    data_type=data_type,
                    comment=comment,
                )
                event = IngestionEvent_ScoreCreate(
                    id=score_id,
                    timestamp=datetime.now(UTC).isoformat(),
                    body=body,
                )
                pending.append(
                    (
                        event,
                        (packet.run_id, packet.config_hash, trace_hash, name, score_id),
                    )
                )
        pushed = 0
        for offset in range(0, len(pending), 100):
            chunk = pending[offset : offset + 100]
            response = active_client.api.ingestion.batch(batch=[item[0] for item in chunk])
            receipts = {item[0].id: item[1] for item in chunk}
            success_ids = {item.id for item in response.successes}
            expected_ids = set(receipts)
            for score_id in success_ids & expected_ids:
                store.record_push(*receipts[score_id])
                pushed += 1
            if response.errors:
                statuses = sorted({item.status for item in response.errors})
                raise LangfuseBoundaryError(
                    "Langfuse push failed for "
                    f"{len(response.errors)} score(s), HTTP statuses={statuses}"
                )
            if success_ids != expected_ids:
                raise LangfuseBoundaryError(
                    "Langfuse push response did not acknowledge every submitted score"
                )
    except LangfuseBoundaryError:
        raise
    except Exception as exc:
        raise _safe_error("push", exc) from None
    return pushed


def _fetch_observations(
    client: Any, trace_id: str, metadata_keys: Sequence[str]
) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []
    cursor: str | None = None
    while True:
        response = client.api.observations.get_many(
            trace_id=trace_id,
            fields="core,basic,time,io,metadata",
            expand_metadata=",".join(sorted(set(metadata_keys))) or None,
            limit=1000,
            cursor=cursor,
        )
        observations.extend(_model_dict(item) for item in response.data)
        if len(observations) > MAX_OBSERVATIONS_PER_TRACE:
            raise LangfuseBoundaryError(
                f"trace {trace_id} exceeds the "
                f"{MAX_OBSERVATIONS_PER_TRACE}-observation safety limit"
            )
        cursor = getattr(response.meta, "cursor", None)
        if not cursor:
            break
    observations.sort(key=lambda item: str(item.get("start_time", "")))
    return observations


def _model_dict(model: Any) -> dict[str, Any]:
    if hasattr(model, "model_dump"):
        value = model.model_dump(mode="json")
    elif isinstance(model, dict):
        value = model
    else:
        raise LangfuseBoundaryError("Langfuse returned an unsupported response model")
    if not isinstance(value, dict):
        raise LangfuseBoundaryError("Langfuse response model did not serialize to an object")
    json.dumps(value, sort_keys=True, separators=(",", ":"))
    return value


def _parse_since(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise LangfuseBoundaryError(f"invalid --since ISO8601 value: {value}") from exc
    if parsed.tzinfo is None:
        raise LangfuseBoundaryError("--since must include a timezone")
    return parsed


def _score_id(trace_id: str, config_hash: str, trace_hash: str, score_name: str) -> str:
    return str(
        uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"detrix:{trace_id}:{config_hash}:{trace_hash}:{score_name}",
        )
    )


def _score_comment(packet: AdmissionPacket) -> str:
    codes = ",".join(code.value for code in packet.reason_codes) or "NONE"
    return f"detrix reason_codes={codes}; config_hash={packet.config_hash}"


def _trace_hash(packet: AdmissionPacket) -> str:
    value = packet.evidence.get("trace_sha256")
    if not isinstance(value, str) or not value:
        raise LangfuseBoundaryError("stored verdict is missing its trace content hash")
    return value


def _safe_error(operation: str, exc: Exception) -> LangfuseBoundaryError:
    status = getattr(exc, "status_code", None)
    suffix = f", HTTP {status}" if isinstance(status, int) else ""
    return LangfuseBoundaryError(
        f"Langfuse {operation} failed ({type(exc).__name__}{suffix}); "
        "verify LANGFUSE_PUBLIC_KEY, LANGFUSE_SECRET_KEY, LANGFUSE_HOST, and project access"
    )
