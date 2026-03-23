from __future__ import annotations

import html
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

        report = self._build_report(collection_bundle, finding_bundle, risk_bundle, metadata)

        result: dict[str, str] = {}
        json_path = output.get("json_path")
        markdown_path = output.get("markdown_path")
        html_path = output.get("html_path")

        if json_path:
            path = _write_text(json_path, json.dumps(report, ensure_ascii=False, indent=2))
            result["json_path"] = str(path)
        if markdown_path:
            path = _write_text(markdown_path, self._render_markdown(report))
            result["markdown_path"] = str(path)
        if html_path:
            path = _write_text(html_path, self._render_html(report))
            result["html_path"] = str(path)

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

        severity_counter = Counter(str(item.get("severity_hint", "unknown")).strip().lower() for item in findings)
        category_counter = Counter(str(item.get("category", "unknown")).strip().lower() for item in findings)
        recommendation_counter = Counter(
            (str(item.get("category", "unknown")), str(item.get("recommendation", "")), str(item.get("retest", "")))
            for item in risks
        )

        recommendations = [
            {
                "category": category,
                "recommendation": recommendation,
                "retest": retest,
                "count": count,
            }
            for (category, recommendation, retest), count in recommendation_counter.items()
        ]
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
                "summary": risk_bundle.get("summary") or {"critical": 0, "high": 0, "medium": 0, "low": 0},
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
        summary = (report.get("risks") or {}).get("summary") or {}
        network_summary = (report.get("assets") or {}).get("network_summary") or {}
        web_summary = (report.get("assets") or {}).get("web_summary") or {}

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
        lines.append(f"- Network Ports: {network_summary.get('total_ports', 0)}")
        lines.append(f"- Open Ports: {network_summary.get('open_ports', 0)}")
        lines.append(f"- Visited Pages: {web_summary.get('visited_count', 0)}")
        lines.append(f"- URLs: {web_summary.get('urls', 0)}")
        lines.append(f"- Forms: {web_summary.get('forms', 0)}")
        lines.append("")
        lines.append("## 3. Risk Summary")
        lines.append("")
        lines.append("| Critical | High | Medium | Low |")
        lines.append("| --- | --- | --- | --- |")
        lines.append(f"| {summary.get('critical', 0)} | {summary.get('high', 0)} | {summary.get('medium', 0)} | {summary.get('low', 0)} |")
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

    def _render_html(self, report: dict) -> str:
        target = html.escape(str(report.get("target", "-")))
        generated_at = html.escape(str(report.get("generated_at", "-")))
        metadata = report.get("metadata") or {}
        mode = html.escape(str(metadata.get("mode", "-")))
        tool_version = html.escape(str(metadata.get("tool_version", "-")))
        summary = (report.get("risks") or {}).get("summary") or {}
        risks = (report.get("risks") or {}).get("items") or []
        vulnerabilities = report.get("vulnerabilities") or {}
        assets = report.get("assets") or {}
        network_summary = assets.get("network_summary") or {}
        web_summary = assets.get("web_summary") or {}

        return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>VMP 安全风险报告</title>
  <style>
    :root {{
      --bg: #f5f5f7;
      --card: rgba(255,255,255,0.78);
      --ink: #111113;
      --muted: #6e6e73;
      --line: rgba(10,10,10,.08);
      --critical: #c81e1e;
      --high: #e46f2a;
      --medium: #c99700;
      --low: #2f8f4e;
      --accent: #0071e3;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      color: var(--ink);
      font-family: "SF Pro Display", "SF Pro Text", "Avenir Next", "Segoe UI", sans-serif;
      background: radial-gradient(circle at 0 0, rgba(0,113,227,.15), transparent 38%), var(--bg);
    }}
    .wrap {{ width: min(96vw, 1680px); margin: 0 auto; padding: 28px 18px 40px; }}
    .hero {{
      border: 1px solid var(--line);
      border-radius: 22px;
      background: linear-gradient(145deg, rgba(255,255,255,.95), rgba(246,246,248,.86));
      box-shadow: 0 16px 46px rgba(0,0,0,.08);
      padding: 24px;
    }}
    h1 {{ margin: 0; font-size: clamp(30px, 3.8vw, 44px); }}
    .sub {{ margin-top: 8px; color: var(--muted); }}
    .chips {{ margin-top: 14px; display: flex; flex-wrap: wrap; gap: 8px; }}
    .chip {{ border: 1px solid var(--line); border-radius: 999px; padding: 7px 10px; font-size: 12px; background: #fff; }}
    .metrics {{ margin-top: 14px; display: grid; gap: 10px; grid-template-columns: repeat(4, minmax(0,1fr)); }}
    .metric {{ border: 1px solid var(--line); border-radius: 14px; background: var(--card); padding: 12px; }}
    .metric-card {{ cursor: pointer; transition: transform .12s ease, box-shadow .12s ease, border-color .12s ease; }}
    .metric-card:hover {{ transform: translateY(-1px); box-shadow: 0 10px 24px rgba(0,0,0,.08); }}
    .metric-card.active {{ border-color: rgba(0,113,227,.6); box-shadow: 0 0 0 2px rgba(0,113,227,.14); }}
    .metric .k {{ font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: .06em; }}
    .metric .v {{ margin-top: 4px; font-size: 26px; font-weight: 640; }}
    .quick-nav {{ margin-top: 12px; display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }}
    .quick-nav a, .quick-nav button {{ text-decoration: none; border: 1px solid var(--line); background: #fff; color: var(--ink); border-radius: 999px; padding: 7px 10px; font-size: 12px; cursor: pointer; }}
    .controls {{
      margin-top: 14px;
      display: grid;
      gap: 10px;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      align-items: center;
    }}
    .control-search {{ grid-column: span 2; }}
    .input, .select {{ width: 100%; border: 1px solid var(--line); border-radius: 12px; background: #fff; padding: 11px 12px; }}
    .num {{ width: 100%; border: 1px solid var(--line); border-radius: 12px; background: #fff; padding: 11px 12px; }}
    .grid {{ margin-top: 14px; display: grid; gap: 12px; grid-template-columns: 1.35fr .95fr; }}
    .panel {{ border: 1px solid var(--line); border-radius: 20px; background: var(--card); box-shadow: 0 10px 30px rgba(0,0,0,.06); overflow: hidden; }}
    .panel-head {{ padding: 14px 16px; border-bottom: 1px solid var(--line); font-weight: 600; display: flex; justify-content: space-between; }}
    .table-wrap {{ max-height: 560px; overflow: auto; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
    th, td {{ text-align: left; padding: 12px 12px; border-bottom: 1px solid rgba(10,10,10,.06); }}
    thead th {{ position: sticky; top: 0; background: #fafafc; z-index: 1; color: #56565b; }}
    tbody tr {{ cursor: pointer; }}
    tbody tr:hover {{ background: rgba(0,113,227,.06); }}
    .badge {{ border-radius: 999px; padding: 5px 9px; font-size: 11px; color: #fff; text-transform: uppercase; font-weight: 700; }}
    .critical {{ background: var(--critical); }}
    .high {{ background: var(--high); }}
    .medium {{ background: var(--medium); }}
    .low {{ background: var(--low); }}
    .plot {{ padding: 16px; }}
    .ring {{ width: min(280px, 72%); aspect-ratio: 1; margin: 0 auto; border-radius: 50%; position: relative; }}
    .ring::after {{ content: ""; position: absolute; inset: 20%; background: #fff; border-radius: 50%; box-shadow: 0 0 0 1px var(--line); }}
    .ring-t {{ position: absolute; inset: 0; display: grid; place-items: center; z-index: 2; text-align: center; font-size: 12px; color: var(--muted); }}
    .ring-t strong {{ display: block; color: var(--ink); font-size: 28px; }}
    .legend {{ margin-top: 14px; display: grid; gap: 7px; }}
    .legend div {{ display: flex; justify-content: space-between; }}
    .dot {{ width: 10px; height: 10px; border-radius: 50%; display: inline-block; margin-right: 8px; }}
    .btn {{ margin-top: 14px; width: 100%; border: none; border-radius: 10px; background: var(--accent); color: #fff; padding: 10px; cursor: pointer; }}
    .stack-actions {{ display: flex; gap: 8px; flex-wrap: wrap; padding: 12px 16px 0; }}
    .stack-actions button {{ border: 1px solid var(--line); background: #fff; border-radius: 10px; padding: 8px 10px; cursor: pointer; }}
    .recommendation-list {{ padding: 12px 16px 16px; display: grid; gap: 10px; }}
    .rec-item {{ border: 1px solid var(--line); border-radius: 12px; background: #fff; overflow: hidden; }}
    .rec-item > summary {{ cursor: pointer; list-style: none; padding: 10px 12px; display: flex; justify-content: space-between; gap: 8px; }}
    .rec-item > summary::-webkit-details-marker {{ display: none; }}
    .rec-body {{ border-top: 1px solid var(--line); padding: 10px 12px; color: #3a3a3c; font-size: 13px; }}
    .drawer {{ position: fixed; right: -560px; top: 0; width: min(560px, 92vw); height: 100vh; background: rgba(255,255,255,.96); border-left: 1px solid var(--line); transition: right .22s; padding: 16px; overflow: auto; z-index: 30; }}
    .drawer.open {{ right: 0; }}
    .kv {{ border: 1px solid var(--line); border-radius: 10px; background: #fafafc; white-space: pre-wrap; word-break: break-word; padding: 10px; font-size: 12px; max-height: 220px; overflow: auto; }}
    @media (max-width: 1040px) {{ .metrics {{ grid-template-columns: repeat(2, minmax(0,1fr)); }} .controls {{ grid-template-columns: 1fr 1fr; }} .control-search {{ grid-column: span 2; }} .grid {{ grid-template-columns: 1fr; }} }}
    @media (max-width: 640px) {{ .metrics {{ grid-template-columns: 1fr; }} .controls {{ grid-template-columns: 1fr; }} .control-search {{ grid-column: span 1; }} }}
  </style>
</head>
<body>
  <div class="wrap">
    <section class="hero" id="overview">
      <h1>安全风险总览 <span style="font-weight:500;color:#6e6e73;">Security Intelligence</span></h1>
      <div class="sub">目标 Target: {target}</div>
      <div class="chips">
        <span class="chip">生成时间 Generated: {generated_at}</span>
        <span class="chip">模式 Mode: {mode}</span>
        <span class="chip">版本 Version: {tool_version}</span>
      </div>
      <div class="metrics">
        <div class="metric metric-card" data-level=""><div class="k">发现 Findings</div><div class="v" id="metric-findings">{int(vulnerabilities.get('total', 0))}</div></div>
        <div class="metric metric-card" data-level=""><div class="k">风险 Risks</div><div class="v" id="metric-risks">{len(risks)}</div></div>
        <div class="metric metric-card" data-level="Critical"><div class="k">Critical</div><div class="v">{int(summary.get('critical', 0))}</div></div>
        <div class="metric metric-card" data-level="High"><div class="k">High</div><div class="v">{int(summary.get('high', 0))}</div></div>
        <div class="metric metric-card" data-level="Medium"><div class="k">Medium</div><div class="v">{int(summary.get('medium', 0))}</div></div>
        <div class="metric metric-card" data-level="Low"><div class="k">Low</div><div class="v">{int(summary.get('low', 0))}</div></div>
        <div class="metric"><div class="k">开放端口 Open Ports</div><div class="v">{int(network_summary.get('open_ports', 0))}</div></div>
        <div class="metric"><div class="k">页面 URL</div><div class="v">{int(web_summary.get('urls', 0))}</div></div>
      </div>
      <div class="quick-nav">
        <a href="#overview">总览</a>
        <a href="#filters">筛选区</a>
        <a href="#risk-table">风险表</a>
        <a href="#distribution">分布图</a>
        <a href="#recommendations">建议区</a>
        <button id="backToTopBtn" type="button">回到顶部</button>
      </div>
    </section>

    <section class="controls" id="filters">
      <input id="searchInput" class="input control-search" placeholder="搜索标题、分类、插件或 URL" />
      <select id="levelSelect" class="select"><option value="">全部等级</option><option value="Critical">Critical</option><option value="High">High</option><option value="Medium">Medium</option><option value="Low">Low</option></select>
      <select id="categorySelect" class="select"><option value="">全部分类</option></select>
      <select id="pluginSelect" class="select"><option value="">全部插件</option></select>
      <select id="assetSelect" class="select"><option value="">全部目标资产</option></select>
      <input id="statusMinInput" class="num" type="number" min="100" max="599" placeholder="状态码最小值(如 200)" />
      <input id="statusMaxInput" class="num" type="number" min="100" max="599" placeholder="状态码最大值(如 399)" />
    </section>

    <section class="grid">
      <article class="panel" id="risk-table">
        <div class="panel-head"><span>风险条目 Risk Items</span><span id="rowCounter">0 条</span></div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>等级 Level</th><th>分数 Score</th><th>分类 Category</th><th>插件 Plugin</th><th>状态码</th><th>标题 Title</th><th>位置 URL</th></tr></thead>
            <tbody id="riskBody"></tbody>
          </table>
        </div>
      </article>

      <aside class="panel" id="distribution">
        <div class="panel-head">风险分布 Risk Distribution</div>
        <div class="plot">
          <div class="ring" id="ring"><div class="ring-t"><div><strong id="ringTotal">0</strong>总风险数</div></div></div>
          <div class="legend" id="legend"></div>
          <button class="btn" id="exportBtn">导出筛选结果 JSON</button>
        </div>
      </aside>
    </section>

    <section class="panel" id="recommendations" style="margin-top:12px;">
      <div class="panel-head"><span>修复建议 Recommendations</span><span id="recCounter">0 组</span></div>
      <div class="stack-actions">
        <button id="expandAllRecsBtn" type="button">全部展开</button>
        <button id="collapseAllRecsBtn" type="button">全部折叠</button>
      </div>
      <div class="recommendation-list" id="recommendationList"></div>
    </section>
  </div>

  <aside id="drawer" class="drawer">
    <button id="closeDrawer">关闭</button>
    <h2 id="detailTitle">风险详情</h2>
    <p id="detailMeta"></p>
    <h4>修复建议 Recommendation</h4>
    <div id="detailRecommendation" class="kv"></div>
    <h4>复测建议 Retest</h4>
    <div id="detailRetest" class="kv"></div>
    <h4>证据 Evidence</h4>
    <div id="detailEvidence" class="kv"></div>
  </aside>

  <script id="report-data" type="application/json">{_safe_json_for_html(report)}</script>
  <script>
    const report = JSON.parse(document.getElementById('report-data').textContent);
    const allItems = Array.isArray(report?.risks?.items) ? report.risks.items : [];

    const riskBody = document.getElementById('riskBody');
    const rowCounter = document.getElementById('rowCounter');
    const metricFindings = document.getElementById('metric-findings');
    const metricRisks = document.getElementById('metric-risks');
    const ring = document.getElementById('ring');
    const ringTotal = document.getElementById('ringTotal');
    const legend = document.getElementById('legend');
    const drawer = document.getElementById('drawer');

    const searchInput = document.getElementById('searchInput');
    const levelSelect = document.getElementById('levelSelect');
    const categorySelect = document.getElementById('categorySelect');
    const pluginSelect = document.getElementById('pluginSelect');
    const assetSelect = document.getElementById('assetSelect');
    const statusMinInput = document.getElementById('statusMinInput');
    const statusMaxInput = document.getElementById('statusMaxInput');
    const recommendationList = document.getElementById('recommendationList');
    const recCounter = document.getElementById('recCounter');
    const metricCards = Array.from(document.querySelectorAll('.metric-card'));

    const webUrls = Array.isArray(report?.assets?.web_assets?.urls) ? report.assets.web_assets.urls : [];
    const urlStatusMap = new Map();

    function normalizeUrl(url) {{
      return String(url || '').trim().replace(/\\/+$/, '').toLowerCase();
    }}

    for (const entry of webUrls) {{
      const raw = String(entry?.url || '').trim();
      const key = normalizeUrl(raw);
      const code = Number(entry?.status_code);
      if (!key || Number.isNaN(code)) continue;
      urlStatusMap.set(key, code);
      urlStatusMap.set(raw.toLowerCase(), code);
    }}

    function uniqueValues(key) {{
      return [...new Set(allItems.map(item => String(item?.[key] || '').trim()).filter(Boolean))].sort();
    }}

    function fillSelect(select, values) {{
      for (const value of values) {{
        const option = document.createElement('option');
        option.value = value;
        option.textContent = value;
        select.appendChild(option);
      }}
    }}

    fillSelect(categorySelect, uniqueValues('category'));
    fillSelect(pluginSelect, uniqueValues('plugin'));

    function uniqueHosts() {{
      const hosts = new Set();
      for (const item of allItems) {{
        const url = String(item?.location?.url || '');
        if (!url) continue;
        try {{
          hosts.add(new URL(url).host);
        }} catch (_err) {{
          continue;
        }}
      }}
      return [...hosts].sort();
    }}

    fillSelect(assetSelect, uniqueHosts());

    function normalizedLevel(level) {{
      return String(level || 'low').toLowerCase();
    }}

    function itemText(item) {{
      const url = String(item?.location?.url || '');
      const param = String(item?.location?.param || '');
      return [item?.title, item?.category, item?.plugin, url, param].join(' ').toLowerCase();
    }}

    function getStatusCode(item) {{
      const url = String(item?.location?.url || '');
      if (!url) return null;
      const normalized = normalizeUrl(url);
      if (urlStatusMap.has(normalized)) return urlStatusMap.get(normalized);
      if (urlStatusMap.has(url.toLowerCase())) return urlStatusMap.get(url.toLowerCase());
      return null;
    }}

    function getHost(item) {{
      const url = String(item?.location?.url || '');
      if (!url) return '';
      try {{
        return new URL(url).host;
      }} catch (_err) {{
        return '';
      }}
    }}

    function getFilteredItems() {{
      const keyword = searchInput.value.trim().toLowerCase();
      const level = levelSelect.value;
      const category = categorySelect.value;
      const plugin = pluginSelect.value;
      const asset = assetSelect.value;
      const statusMin = Number(statusMinInput.value);
      const statusMax = Number(statusMaxInput.value);
      const hasStatusMin = !Number.isNaN(statusMin);
      const hasStatusMax = !Number.isNaN(statusMax);

      return allItems
        .filter(item => !keyword || itemText(item).includes(keyword))
        .filter(item => !level || item.level === level)
        .filter(item => !category || item.category === category)
        .filter(item => !plugin || item.plugin === plugin)
        .filter(item => !asset || getHost(item) === asset)
        .filter(item => {{
          if (!hasStatusMin && !hasStatusMax) return true;
          const status = getStatusCode(item);
          if (status === null) return false;
          if (hasStatusMin && status < statusMin) return false;
          if (hasStatusMax && status > statusMax) return false;
          return true;
        }})
        .sort((a, b) => Number(b.score || 0) - Number(a.score || 0));
    }}

    function showDetail(item) {{
      document.getElementById('detailTitle').textContent = item?.title || '风险详情';
      document.getElementById('detailMeta').textContent = `${{item?.level || '-'}} · ${{item?.category || '-'}} · score=${{Number(item?.score || 0).toFixed(2)}}`;
      document.getElementById('detailRecommendation').textContent = item?.recommendation || '-';
      document.getElementById('detailRetest').textContent = item?.retest || '-';
      document.getElementById('detailEvidence').textContent = JSON.stringify(item?.evidence || {{}}, null, 2);
      drawer.classList.add('open');
    }}

    function renderTable(items) {{
      riskBody.innerHTML = '';
      for (const item of items) {{
        const row = document.createElement('tr');
        const url = String(item?.location?.url || '-');
        const status = getStatusCode(item);
        row.innerHTML = `
          <td><span class="badge ${{normalizedLevel(item.level)}}">${{item.level || 'Low'}}</span></td>
          <td>${{Number(item.score || 0).toFixed(2)}}</td>
          <td>${{item.category || '-'}}</td>
          <td>${{item.plugin || '-'}}</td>
          <td>${{status === null ? '-' : status}}</td>
          <td>${{item.title || '-'}}</td>
          <td title="${{url}}">${{url.length > 54 ? url.slice(0, 51) + '...' : url}}</td>
        `;
        row.addEventListener('click', () => showDetail(item));
        riskBody.appendChild(row);
      }}
      rowCounter.textContent = `${{items.length}} 条`;
      metricFindings.textContent = String(items.length);
      metricRisks.textContent = String(items.length);
    }}

    function renderRecommendations(items) {{
      const grouped = new Map();
      for (const item of items) {{
        const category = String(item?.category || 'unknown');
        const recommendation = String(item?.recommendation || '-');
        const retest = String(item?.retest || '-');
        const key = `${{category}}||${{recommendation}}||${{retest}}`;
        const count = grouped.get(key)?.count || 0;
        grouped.set(key, {{ category, recommendation, retest, count: count + 1 }});
      }}

      const rows = Array.from(grouped.values()).sort((a, b) => b.count - a.count);
      recommendationList.innerHTML = '';
      recCounter.textContent = `${{rows.length}} 组`;

      for (const row of rows) {{
        const item = document.createElement('details');
        item.className = 'rec-item';
        item.innerHTML = `
          <summary><span>${{row.category}}</span><strong>${{row.count}} 条</strong></summary>
          <div class="rec-body">
            <div><strong>Recommendation:</strong> ${{row.recommendation}}</div>
            <div style="margin-top:8px;"><strong>Retest:</strong> ${{row.retest}}</div>
          </div>
        `;
        recommendationList.appendChild(item);
      }}
    }}

    function renderRing(items) {{
      const counts = {{ Critical: 0, High: 0, Medium: 0, Low: 0 }};
      for (const item of items) {{
        const level = String(item?.level || 'Low');
        if (counts[level] !== undefined) counts[level] += 1;
      }}
      const total = items.length || 1;
      const c = counts.Critical / total * 360;
      const h = c + counts.High / total * 360;
      const m = h + counts.Medium / total * 360;

      ring.style.background = `conic-gradient(var(--critical) 0deg ${{c}}deg, var(--high) ${{c}}deg ${{h}}deg, var(--medium) ${{h}}deg ${{m}}deg, var(--low) ${{m}}deg 360deg)`;
      ringTotal.textContent = String(items.length);
      legend.innerHTML = `
        <div><span><span class="dot" style="background:var(--critical)"></span>Critical</span><strong>${{counts.Critical}}</strong></div>
        <div><span><span class="dot" style="background:var(--high)"></span>High</span><strong>${{counts.High}}</strong></div>
        <div><span><span class="dot" style="background:var(--medium)"></span>Medium</span><strong>${{counts.Medium}}</strong></div>
        <div><span><span class="dot" style="background:var(--low)"></span>Low</span><strong>${{counts.Low}}</strong></div>
      `;
    }}

    function renderAll() {{
      const items = getFilteredItems();
      renderTable(items);
      renderRing(items);
      renderRecommendations(items);
      syncMetricCardState();
    }}

    function syncMetricCardState() {{
      for (const card of metricCards) {{
        const cardLevel = String(card.dataset.level || '');
        const active = cardLevel && levelSelect.value === cardLevel;
        card.classList.toggle('active', active);
      }}
    }}

    [searchInput, levelSelect, categorySelect, pluginSelect, assetSelect, statusMinInput, statusMaxInput].forEach(el => {{
      el.addEventListener('input', renderAll);
      el.addEventListener('change', renderAll);
    }});

    for (const card of metricCards) {{
      card.addEventListener('click', () => {{
        const cardLevel = String(card.dataset.level || '');
        if (!cardLevel) {{
          levelSelect.value = '';
          renderAll();
          return;
        }}
        levelSelect.value = levelSelect.value === cardLevel ? '' : cardLevel;
        renderAll();
        document.getElementById('risk-table').scrollIntoView({{ behavior: 'smooth', block: 'start' }});
      }});
    }}

    document.getElementById('closeDrawer').addEventListener('click', () => drawer.classList.remove('open'));
    document.getElementById('backToTopBtn').addEventListener('click', () => window.scrollTo({{ top: 0, behavior: 'smooth' }}));

    document.getElementById('expandAllRecsBtn').addEventListener('click', () => {{
      recommendationList.querySelectorAll('details').forEach(node => node.open = true);
    }});
    document.getElementById('collapseAllRecsBtn').addEventListener('click', () => {{
      recommendationList.querySelectorAll('details').forEach(node => node.open = false);
    }});

    document.getElementById('exportBtn').addEventListener('click', () => {{
      const items = getFilteredItems();
      const blob = new Blob([JSON.stringify(items, null, 2)], {{ type: 'application/json' }});
      const link = document.createElement('a');
      link.href = URL.createObjectURL(blob);
      link.download = '筛选后的风险条目.json';
      link.click();
      URL.revokeObjectURL(link.href);
    }});

    renderAll();
  </script>
</body>
</html>
"""


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _write_text(path_like: str, content: str) -> Path:
    path = Path(path_like)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _safe_json_for_html(value: object) -> str:
    return json.dumps(value, ensure_ascii=False).replace("</", "<\\/")
