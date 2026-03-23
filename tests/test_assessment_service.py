from __future__ import annotations

import pytest

from scanner.assessment import AssessmentService


def _sample_finding_bundle() -> dict:
    return {
        "schema_version": "1.0",
        "target": "http://example.com/",
        "findings": [
            {
                "id": "f-1",
                "plugin": "sqli_basic",
                "category": "sqli",
                "title": "Potential SQLi",
                "severity_hint": "high",
                "confidence": 0.9,
                "location": {
                    "url": "http://example.com/search",
                    "method": "GET",
                    "param": "q",
                },
                "evidence": {
                    "payload": "' OR 1=1 --",
                    "response_snippet": "SQL syntax error",
                },
                "created_at": "2026-03-23T14:05:00Z",
            },
            {
                "id": "f-2",
                "plugin": "csrf_missing_token",
                "category": "csrf",
                "title": "Missing CSRF token",
                "severity_hint": "medium",
                "confidence": 0.7,
                "location": {
                    "url": "http://example.com/profile/update",
                    "method": "POST",
                    "param": "email",
                },
                "evidence": {"form": "profile_update"},
                "created_at": "2026-03-23T14:06:00Z",
            },
        ],
        "plugin_stats": {"total": 2, "success": 2, "failed": 0, "skipped": 0},
        "errors": [],
    }


def test_assessment_service_builds_sorted_risk_items() -> None:
    service = AssessmentService()

    result = service.assess({"findings": _sample_finding_bundle()})

    assert result["schema_version"] == "1.0"
    assert result["target"] == "http://example.com/"
    assert len(result["risk_items"]) == 2

    scores = [item["score"] for item in result["risk_items"]]
    assert scores == sorted(scores, reverse=True)

    assert result["risk_items"][0]["finding_id"] == "f-1"
    assert result["risk_items"][0]["level"] in {"High", "Critical"}

    summary_total = sum(result["summary"].values())
    assert summary_total == 2


def test_assessment_service_applies_custom_weights() -> None:
    service = AssessmentService()

    default_result = service.assess({"findings": _sample_finding_bundle()})
    weighted_result = service.assess(
        {
            "findings": _sample_finding_bundle(),
            "weights": {
                "impact": 1.2,
                "likelihood": 1.1,
                "confidence": 1.0,
                "exposure": 1.0,
            },
        }
    )

    assert weighted_result["risk_items"][0]["score"] > default_result["risk_items"][0]["score"]


def test_assessment_service_requires_findings_bundle() -> None:
    service = AssessmentService()

    with pytest.raises(ValueError, match="findings"):
        service.assess({"weights": {"impact": 1.0}})
