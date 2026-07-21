from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from detrix.failures import FailureDocumentError, load_failures, markdown_to_failures
from detrix.gates import DetectionKind, RuleKind


def test_loads_canonical_yaml_and_hash_is_semantic(tmp_path: Path) -> None:
    first = tmp_path / "first.yaml"
    second = tmp_path / "second.yaml"
    first.write_text(
        """failures:
  - id: claims-done-no-tests
    description: Agent claims completion without a test run
    severity: high
    detection:
      kind: deterministic
      rule: absent_pattern
      field: observations[*].output
      pattern: pytest
      when_pattern: done
"""
    )
    second.write_text(first.read_text().replace("failures:\n", "failures:  \n\n"))
    loaded = load_failures(first)
    assert loaded.failures[0].detection.rule is RuleKind.ABSENT_PATTERN
    assert loaded.content_hash == load_failures(second).content_hash


def test_exact_markdown_table_converts_to_advisory_yaml(tmp_path: Path) -> None:
    audit = tmp_path / "audit.md"
    output = tmp_path / "failures.yaml"
    audit.write_text(
        """| Pattern | Mechanism | Project-goal impact | Evidence traces | Next gate/check |
|---|---|---|---|---|
| Fabricated path | Claims unseen paths | Misleads users | trace-1 | Check paths in tools |
"""
    )
    converted = markdown_to_failures(audit, output)
    assert converted.failures[0].id == "fabricated-path"
    assert converted.failures[0].description == "Claims unseen paths"
    assert converted.failures[0].detection.kind is DetectionKind.ADVISORY
    assert converted.failures[0].detection.prompt == "Check paths in tools"
    assert yaml.safe_load(output.read_text())["failures"][0]["id"] == "fabricated-path"


def test_markdown_requires_exact_columns(tmp_path: Path) -> None:
    audit = tmp_path / "audit.md"
    audit.write_text("| Pattern | Mechanism | Next gate/check |\n|---|---|---|\n| X | Y | Z |\n")
    with pytest.raises(FailureDocumentError, match="exact columns"):
        markdown_to_failures(audit, tmp_path / "out.yaml")


def test_yaml_rejects_aliases(tmp_path: Path) -> None:
    source = tmp_path / "failures.yaml"
    source.write_text("failures: &items\n  - id: one\ncopy: *items\n")
    with pytest.raises(FailureDocumentError, match="aliases"):
        load_failures(source)
