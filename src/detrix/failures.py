"""Failure-document loading and exact Markdown audit conversion."""

from __future__ import annotations

import re
from pathlib import Path

import yaml
from pydantic import ValidationError
from yaml.tokens import AliasToken, AnchorToken

from detrix.gates import GateConfig

MAX_DOCUMENT_BYTES = 1_000_000
AUDIT_COLUMNS = [
    "Pattern",
    "Mechanism",
    "Project-goal impact",
    "Evidence traces",
    "Next gate/check",
]


class FailureDocumentError(ValueError):
    pass


def load_failures(path: str | Path) -> GateConfig:
    source = Path(path)
    raw = source.read_bytes()
    if len(raw) > MAX_DOCUMENT_BYTES:
        raise FailureDocumentError(f"{source}: failure document exceeds {MAX_DOCUMENT_BYTES} bytes")
    text = raw.decode("utf-8")
    try:
        if any(isinstance(token, (AliasToken, AnchorToken)) for token in yaml.scan(text)):
            raise FailureDocumentError(f"{source}: YAML aliases and anchors are not allowed")
        data = yaml.safe_load(text)
        return GateConfig.model_validate(data)
    except FailureDocumentError:
        raise
    except (yaml.YAMLError, ValidationError, UnicodeError) as exc:
        raise FailureDocumentError(f"{source}: invalid failure document: {exc}") from exc


def write_failures(config: GateConfig, path: str | Path) -> None:
    payload = config.model_dump(mode="json", exclude={"content_hash"}, exclude_none=True)
    Path(path).write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")


def markdown_to_failures(source: str | Path, destination: str | Path) -> GateConfig:
    lines = [line.strip() for line in Path(source).read_text(encoding="utf-8").splitlines()]
    table = [line for line in lines if line.startswith("|") and line.endswith("|")]
    if len(table) < 3:
        raise FailureDocumentError("Markdown audit must contain a header and at least one row")
    header = _cells(table[0])
    if header != AUDIT_COLUMNS:
        columns = " | ".join(AUDIT_COLUMNS)
        raise FailureDocumentError(
            f"Markdown audit table must contain the exact columns: {columns}"
        )
    if len(_cells(table[1])) != len(AUDIT_COLUMNS) or not all(
        re.fullmatch(r":?-{3,}:?", cell) for cell in _cells(table[1])
    ):
        raise FailureDocumentError("Markdown audit table separator is invalid")

    failures = []
    ids: set[str] = set()
    for row_number, line in enumerate(table[2:], start=3):
        cells = _cells(line)
        if len(cells) != len(AUDIT_COLUMNS):
            raise FailureDocumentError(
                f"Markdown audit row {row_number} has the wrong column count"
            )
        gate_id = _slugify(cells[0])
        if not gate_id or gate_id in ids:
            raise FailureDocumentError(
                f"Markdown audit row {row_number} has an empty or duplicate id"
            )
        ids.add(gate_id)
        failures.append(
            {
                "id": gate_id,
                "description": cells[1],
                "severity": "medium",
                "detection": {"kind": "advisory", "prompt": cells[4]},
            }
        )
    try:
        config = GateConfig.model_validate({"failures": failures})
    except ValidationError as exc:
        raise FailureDocumentError(f"Markdown audit produced invalid gates: {exc}") from exc
    write_failures(config, destination)
    return config


def _cells(line: str) -> list[str]:
    return [cell.strip() for cell in line[1:-1].split("|")]


def _slugify(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
