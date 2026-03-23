from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


class PresentationService:
    schema_version = "1.0"

    def render(self, request: dict) -> dict:
        collection_bundle = request.get("collection") or {}
        finding_bundle = request.get("findings") or {}
        risk_bundle = request.get("risks") or {}
        output = request.get("output") or {}
        metadata = request.get("metadata") or {}

        report = self._build_report(
            collection_bundle=collection_bundle,
            finding_bundle=finding_bundle,
            risk_bundle=risk_bundle,
            metadata=metadata,
        )

        result: dict[str, str] = {}
        json_path = output.get("json_path")
        markdown_path = output.get("markdown_path")

        if json_path:
            path = _write_text(json_path, json.dumps(report, ensure_ascii=False, indent=2))
            result["json_path"] = str(path)

        if markdown_path:
            markdown = self._render_markdown(report)
            path = _write_text(markdown_path, markdown)
            result["markdown_path"] = str(path)

        return result

    def _build_report(
        self,
        collection_bundle: dict,
        finding_bundle: dict,
        risk_bundle: dict,
        metadata: dict,
    ) -> dict:
        findings = list(finding_bundle.get("findings") or [])
        risks = list(risk_bundle.get("risk_items") or [])

        severity_counter = Counter(
            str(item.get("severity_hint", "unknown")).strip().lower() for item in findings
        )
        category_counter = Counter(str(item.get("category", "unknown")).strip().lower() for item in findings)

        recommendation_counter = Counter(
            (
                str(item.get("category", "unknown")),
                str(item.get("recommendation", "")),
                str(item.get("retest", "")),
            )
            for item in risks
        )

        recommendations = []
        for (category, recommendation, retest), count in recommendation_counter.items():
            recommendations.append(
                {
                    "category": category,
                    "recommendation": recommendation,
                    "retest": retest,
                    "count": count,
                }
            )
        recommendations.sort(key=lambda item: item["count"], reverse=True)

        web_assets = collection_bundle.get("web_assets") or {}
        network_assets = list(collection_bundle.get("network_assets") or [])
        open_ports = [asset for asset in network_assets if asset.get("status") == "open"]

        return {
            "schema_version": self.schema_version,
            "generated_at": _utc_now_iso(),
            "target": risk_bundle.get("target") or finding_bundle.get("target") or collection_bundle.get("target"),
            "metadata": metadata,
            "assets": {
                "network_summary": {
                    "total_ports": len(network_assets),
                    "open_ports": len(open_ports),
                },
                "web_summary": {
                    "visited_count": int(web_assets.get("visited_count", 0) or 0),
                    "urls": len(web_assets.get("urls") or []),
                    "forms": len(web_assets.get("forms") or []),
                    "suspicious_endpoints": len(web_assets.get("suspicious_endpoints") or []),
                },
                "network_assets": network_assets,
                "web_assets": web_assets,
            },
            "vulnerabilities": {
                "total": len(findings),
                "by_category": dict(category_counter),
                "by_severity_hint": dict(severity_counter),
                "findings": findings,
            },
            "risks": {
                "summary": risk_bundle.get("summary")
                or {"critical": 0, "high": 0, "medium": 0, "low": 0},
                "items": risks,
            },
            "recommendations": recommendations,
            "errors": {
                "collection": list(collection_bundle.get("errors") or []),
                "detection": list(finding_bundle.get("errors") or []),
                "assessment": list(risk_bundle.get("errors") or []),
            },
        }

    def _render_markdown(self, report: dict) -> str:
        lines: list[str] = []

        lines.append("# VMP-Scanner Risk Report")
        lines.append("")
        lines.append("## 1. Basic Information")
        lines.append("")
        lines.append(f"- Target: {report.get('target', '-')}")
        lines.append(f"- Generated At (UTC): {report.get('generated_at', '-')}")

        metadata = report.get("metadata") or {}
        lines.append(f"- Mode: {metadata.get('mode', '-')}")
        lines.append(f"- Tool Version: {metadata.get('tool_version', '-')}")
        lines.append("")

        lines.append("## 2. Asset Summary")
        lines.append("")
        network_summary = (report.get("assets") or {}).get("network_summary") or {}
        web_summary = (report.get("assets") or {}).get("web_summary") or {}
        lines.append(f"- Network Ports: {network_summary.get('total_ports', 0)}")
        lines.append(f"- Open Ports: {network_summary.get('open_ports', 0)}")
        lines.append(f"- Visited Pages: {web_summary.get('visited_count', 0)}")
        lines.append(f"- URLs: {web_summary.get('urls', 0)}")
        lines.append(f"- Forms: {web_summary.get('forms', 0)}")
        lines.append("")

        lines.append("## 3. Risk Summary")
        lines.append("")
        summary = (report.get("risks") or {}).get("summary") or {}
        lines.append("| Critical | High | Medium | Low |")
        lines.append("| --- | --- | --- | --- |")
        lines.append(
            f"| {summary.get('critical', 0)} | {summary.get('high', 0)} | {summary.get('medium', 0)} | {summary.get('low', 0)} |"
        )
        lines.append("")

        lines.append("## 4. Top Risks")
        lines.append("")
        lines.append("| Finding ID | Category | Level | Score | Title |")
        lines.append("| --- | --- | --- | --- | --- |")
        for item in (report.get("risks") or {}).get("items", [])[:20]:
            lines.append(
                "| "
                + f"{item.get('finding_id', '-')} | {item.get('category', '-')} | {item.get('level', '-')} | {item.get('score', '-')} | {item.get('title', '-')}"
                + " |"
            )
        lines.append("")

        lines.append("## 5. Recommendations")
        lines.append("")
        for idx, item in enumerate(report.get("recommendations") or [], start=1):
            lines.append(f"### 5.{idx} {item.get('category', 'unknown')}")
            lines.append(f"- Recommendation: {item.get('recommendation', '-')}")
            lines.append(f"- Retest: {item.get('retest', '-')}")
            lines.append(f"- Related Findings: {item.get('count', 0)}")
            lines.append("")

        lines.append("## 6. Errors")
        lines.append("")
        errors = report.get("errors") or {}
        lines.append(f"- Collection: {len(errors.get('collection', []))}")
        lines.append(f"- Detection: {len(errors.get('detection', []))}")
        lines.append(f"- Assessment: {len(errors.get('assessment', []))}")
        lines.append("")

        return "\n".join(lines)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _write_text(path_like: str, content: str) -> Path:
    path = Path(path_like)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path
