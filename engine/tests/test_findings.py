"""Tests for security finding evidence."""

from datetime import UTC, datetime
from typing import Any

import pytest
from engine.core.findings import FindingCategory, FindingSeverity, SecurityFinding
from pydantic import ValidationError

DETECTED_AT = datetime(2026, 9, 27, 12, 0, 0, tzinfo=UTC)


def build_finding(**overrides: Any) -> SecurityFinding:
    defaults: dict[str, Any] = {
        "capture_id": "capture123",
        "session_id": "session123",
        "title": "TLS 1.0 accepted by mail server",
        "description": "The observed session negotiated the deprecated TLS 1.0 protocol.",
        "severity": FindingSeverity.HIGH,
        "category": FindingCategory.PROTOCOL_VERSION,
        "rule_id": "protocol.deprecated-tls1.0",
        "detected_at": DETECTED_AT,
    }
    defaults.update(overrides)
    return SecurityFinding(**defaults)


def test_finding_builds_with_defaults() -> None:
    finding = build_finding()

    assert finding.evidence_refs == []
    assert finding.details == {}
    assert finding.detected_at == DETECTED_AT
    assert finding.rule_id == "protocol.deprecated-tls1.0"


def test_severity_and_category_values_round_trip() -> None:
    finding = build_finding(severity=FindingSeverity.CRITICAL, category=FindingCategory.ANOMALY)

    assert finding.severity.value == "critical"
    assert finding.category.value == "anomaly"


def test_title_length_is_bounded() -> None:
    with pytest.raises(ValidationError):
        build_finding(title="x" * 201)
    with pytest.raises(ValidationError):
        build_finding(title="")


def test_finding_without_capture_or_session_is_allowed() -> None:
    finding = build_finding(capture_id=None, session_id=None)

    assert finding.capture_id is None
    assert finding.session_id is None


def test_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        build_finding(confidence_score=0.9)
