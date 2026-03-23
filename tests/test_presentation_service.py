from __future__ import annotations

import json
from pathlib import Path

from scanner.presentation import PresentationService


def _sample_collection() -> dict:
    return {
        "schema_version": "1.0",
        "target": "http://example.com/",
        "network_assets": [
            {"host": "example.com", "port": 80, "status": "open", "service_guess": "http"},
            {"host": "example.com", "port": 22, "status": "closed", "service_guess": "ssh"},
        ],
        "web_assets": {
            "visited_count": 3,
            "urls": [{"url": "http://example.com/"}],
            "forms": [{"action": "http://example.com/login"}],
            "suspicious_endpoints": [],
        },
        "errors": [],
    }


def _sample_findings() -> dict:
    return {
        "schema_version": "1.0",
        "target": "http://example.com/",
        "findings": [
            {
                "id": "f-1",
                "plugin": "xss_reflected",
                "category": "xss",
                "title": "Reflected XSS suspected",
                "severity_hint": "medium",
                "confidence": 0.8,
                "location": {"url": "http://example.com/search", "param": "q"},
                "evidence": {"payload": "<script>alert(1)</script>"},
                "created_at": "2026-03-23T14:05:00Z",
            }
        ],
        "plugin_stats": {"total": 1, "success": 1, "failed": 0, "skipped": 0},
        "errors": [],
    }


def _sample_risks() -> dict:
    return {
        "schema_version": "1.0",
        "target": "http://example.com/",
        "risk_items": [
            {
                "finding_id": "f-1",
                "plugin": "xss_reflected",
                "category": "xss",
                "title": "Reflected XSS suspected",
                "score": 10.2,
                "level": "High",
                "impact": 4,
                "likelihood": 4,
                "confidence": 0.8,
                "exposure_weight": 1.0,
                "recommendation": "Encode output",
                "retest": "Payload should not be reflected",
                "location": {"url": "http://example.com/search", "param": "q"},
                "evidence": {"payload": "<script>alert(1)</script>"},
            }
        ],
        "summary": {"critical": 0, "high": 1, "medium": 0, "low": 0},
        "errors": [],
    }


def test_presentation_service_renders_json_and_markdown(tmp_path: Path) -> None:
    service = PresentationService()
    json_path = tmp_path / "report.json"
    markdown_path = tmp_path / "report.md"

    result = service.render(
        {
            "collection": _sample_collection(),
            "findings": _sample_findings(),
            "risks": _sample_risks(),
            "output": {
                "json_path": str(json_path),
                "markdown_path": str(markdown_path),
            },
            "metadata": {
                "mode": "test",
                "tool_version": "0.1.0",
            },
        }
    )

    assert result["json_path"] == str(json_path)
    assert result["markdown_path"] == str(markdown_path)
    assert json_path.exists()
    assert markdown_path.exists()

    report = json.loads(json_path.read_text(encoding="utf-8"))
    assert report["schema_version"] == "1.0"
    assert report["assets"]["network_summary"]["open_ports"] == 1
    assert report["vulnerabilities"]["total"] == 1
    assert report["risks"]["summary"]["high"] == 1
    assert report["recommendations"][0]["category"] == "xss"

    markdown = markdown_path.read_text(encoding="utf-8")
    assert "# VMP-Scanner Risk Report" in markdown
    assert "## 3. Risk Summary" in markdown
    assert "Reflected XSS suspected" in markdown
