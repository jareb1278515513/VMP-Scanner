from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

import requests

CATEGORY_SOURCE_TEMPLATES = {
    "sqli": [
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/{ref}/SQL%20Injection/README.md"
    ],
    "xss": [
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/{ref}/XSS%20Injection/README.md"
    ],
    "csrf": [
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/{ref}/Cross-Site%20Request%20Forgery/README.md"
    ],
    "path_traversal": [
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/{ref}/Directory%20Traversal/README.md"
    ],
}

HIGH_RISK_MARKERS = (
    "sleep(",
    "waitfor",
    "benchmark(",
    "load_file(",
    "into outfile",
    "xp_cmdshell",
    "powershell",
    "fetch(",
    "curl ",
    "wget ",
    "/etc/shadow",
)


def sync_from_open_source(
    base_dir: str | Path,
    sources: dict[str, list[str]] | None = None,
    repo_ref: str = "master",
    timeout: float = 20.0,
    max_per_category: int = 200,
    incremental: bool = False,
    fetcher: Callable[[str, float], str] | None = None,
) -> dict[str, int]:
    """从开源仓库同步 payload 字典。

    Args:
        base_dir: 本地 payload 目录。
        sources: 分类到来源 URL 的映射。
        repo_ref: 上游仓库分支/标签/提交。
        timeout: 下载超时（秒）。
        max_per_category: 每类最多导入数量。
        incremental: 是否增量合并到现有字典。
        fetcher: 可注入下载函数（便于测试）。

    Returns:
        dict[str, int]: 各分类导入条目数。
    """

    payload_dir = Path(base_dir)
    payload_dir.mkdir(parents=True, exist_ok=True)

    source_map = sources or _build_default_sources(repo_ref)
    counts: dict[str, int] = {}

    for category, urls in source_map.items():
        raw_payloads: list[str] = []
        for url in urls:
            text = (fetcher(url, timeout) if fetcher else _fetch_text(url, timeout)).strip()
            raw_payloads.extend(_extract_payload_candidates(text))

        normalized = _normalize_payloads(raw_payloads)
        selected = normalized[:max_per_category]
        imported_entries = [
            _build_payload_entry(category, idx + 1, payload, source_ref=repo_ref)
            for idx, payload in enumerate(selected)
        ]

        target_file = payload_dir / f"{category}.json"
        existing_entries: list[dict] = []
        if incremental and target_file.exists():
            with target_file.open("r", encoding="utf-8") as fp:
                loaded = json.load(fp)
                if isinstance(loaded, list):
                    existing_entries = loaded

        entries = (
            _merge_incremental(existing_entries, imported_entries)
            if incremental
            else imported_entries
        )

        with target_file.open("w", encoding="utf-8") as fp:
            json.dump(entries, fp, ensure_ascii=False, indent=2)

        counts[category] = len(entries)

    _update_catalog(payload_dir, counts, repo_ref=repo_ref, incremental=incremental)
    return counts


def _build_default_sources(repo_ref: str) -> dict[str, list[str]]:
    """构建默认上游来源列表。"""

    return {
        category: [template.format(ref=repo_ref) for template in templates]
        for category, templates in CATEGORY_SOURCE_TEMPLATES.items()
    }


def _fetch_text(url: str, timeout: float) -> str:
    """下载文本内容。"""

    response = requests.get(url, timeout=timeout)
    response.raise_for_status()
    return response.text


def _extract_payload_candidates(markdown_text: str) -> list[str]:
    """从 Markdown 中提取 payload 候选。"""

    payloads: list[str] = []

    fenced_blocks = re.findall(r"```(?:[a-zA-Z0-9_+-]+)?\n(.*?)```", markdown_text, flags=re.DOTALL)
    for block in fenced_blocks:
        for line in block.splitlines():
            candidate = _clean_candidate(line)
            if candidate:
                payloads.append(candidate)

    for line in markdown_text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("- `") and line.endswith("`"):
            candidate = _clean_candidate(line[3:-1])
            if candidate:
                payloads.append(candidate)
        elif line.startswith("*") and "`" in line:
            inline = re.findall(r"`([^`]+)`", line)
            for item in inline:
                candidate = _clean_candidate(item)
                if candidate:
                    payloads.append(candidate)

    return payloads


def _clean_candidate(raw: str) -> str | None:
    """清洗并过滤无效 payload 候选。"""

    text = raw.strip().strip("`")
    if not text:
        return None
    if len(text) < 3:
        return None
    if text.startswith("#"):
        return None
    if text.lower().startswith(("http://", "https://")):
        return None
    return text


def _normalize_payloads(candidates: list[str]) -> list[str]:
    """去重并规范化 payload 列表。"""

    seen: set[str] = set()
    normalized: list[str] = []
    for item in candidates:
        key = " ".join(item.split())
        if key in seen:
            continue
        seen.add(key)
        normalized.append(item)
    return normalized


def _build_payload_entry(category: str, seq: int, payload: str, source_ref: str) -> dict:
    """构造单条 payload 记录。"""

    high_risk = _is_high_risk(payload)
    mode = "attack" if high_risk else "test"
    risk_level = "high" if high_risk else "low"
    enabled = not high_risk

    return {
        "id": f"{_category_id_prefix(category)}-{seq:04d}",
        "payload": payload,
        "mode": mode,
        "risk_level": risk_level,
        "enabled_by_default": enabled,
        "purpose": f"{category} payload imported from open-source source",
        "expected_feature": "Potential vulnerable behavior should be observable and verifiable",
        "source": f"PayloadsAllTheThings@{source_ref} (imported)",
    }


def _category_id_prefix(category: str) -> str:
    """返回分类对应的 ID 前缀。"""

    mapping = {
        "sqli": "sqli",
        "xss": "xss",
        "csrf": "csrf",
        "path_traversal": "pt",
    }
    return mapping.get(category, category)


def _is_high_risk(payload: str) -> bool:
    """判断 payload 是否包含高风险特征。"""

    low = payload.lower()
    return any(marker in low for marker in HIGH_RISK_MARKERS)


def _merge_incremental(existing_entries: list[dict], imported_entries: list[dict]) -> list[dict]:
    """按 payload 键合并增量字典并保留本地策略字段。"""

    existing_by_payload = {
        _payload_key(item.get("payload", "")): dict(item)
        for item in existing_entries
        if item.get("payload")
    }

    merged: list[dict] = []
    for imported in imported_entries:
        key = _payload_key(imported["payload"])
        old = existing_by_payload.pop(key, None)
        if old:
            preserved = dict(imported)
            # Keep explicit local policy and annotation fields if already present.
            for field in ("enabled_by_default", "risk_level", "mode", "purpose", "expected_feature"):
                if field in old:
                    preserved[field] = old[field]
            if "source" in old and "PayloadsAllTheThings" not in str(old["source"]):
                preserved["source"] = old["source"]
            merged.append(preserved)
        else:
            merged.append(imported)

    # Preserve local-only payloads that are no longer in upstream source.
    merged.extend(existing_by_payload.values())
    return merged


def _payload_key(payload: str) -> str:
    """生成 payload 去重键。"""

    return " ".join(str(payload).split())


def _update_catalog(payload_dir: Path, counts: dict[str, int], repo_ref: str, incremental: bool) -> None:
    """更新本地 payload 目录索引文件。"""

    catalog_file = payload_dir / "catalog.json"
    catalog: dict = {}
    if catalog_file.exists():
        with catalog_file.open("r", encoding="utf-8") as fp:
            catalog = json.load(fp)

    now = datetime.now(timezone.utc)
    version = now.strftime("%Y.%m.%d")
    updated_at = now.isoformat().replace("+00:00", "Z")

    catalog.setdefault("schema_version", "1.0")
    catalog["dictionary_version"] = version
    catalog["updated_at"] = updated_at
    catalog.setdefault("categories", {})
    for category in counts:
        catalog["categories"][category] = f"{category}.json"

    changelog = catalog.setdefault("changelog", [])
    changelog.insert(
        0,
        {
            "version": version,
            "date": now.strftime("%Y-%m-%d"),
            "changes": [
                (
                    f"Incremental sync payload dictionaries from PayloadsAllTheThings@{repo_ref}"
                    if incremental
                    else f"Sync payload dictionaries from PayloadsAllTheThings@{repo_ref}"
                ),
                f"Imported payload counts: {counts}",
            ],
        },
    )

    with catalog_file.open("w", encoding="utf-8") as fp:
        json.dump(catalog, fp, ensure_ascii=False, indent=2)
