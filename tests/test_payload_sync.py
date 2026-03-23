from __future__ import annotations

import json
from pathlib import Path

from scanner.detection.payloads.sync import _extract_payload_candidates, sync_from_open_source


def test_extract_payload_candidates_from_markdown() -> None:
    text = """
# Demo

- `' OR '1'='1`

```txt
<script>alert(1)</script>
' AND 1=2 --
```

* `../../../../etc/passwd`
"""

    payloads = _extract_payload_candidates(text)
    assert "' OR '1'='1" in payloads
    assert "<script>alert(1)</script>" in payloads
    assert "' AND 1=2 --" in payloads
    assert "../../../../etc/passwd" in payloads


def test_sync_from_open_source_with_fake_fetcher(tmp_path: Path) -> None:
    base_dir = tmp_path / "payloads"
    base_dir.mkdir(parents=True, exist_ok=True)

    # Seed a minimal catalog to verify update behavior.
    (base_dir / "catalog.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "dictionary_version": "old",
                "updated_at": "2026-01-01T00:00:00Z",
                "changelog": [],
                "categories": {},
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    markdown = """
```txt
' OR '1'='1
<script>alert(1)</script>
../../../../etc/passwd
'; WAITFOR DELAY '0:0:5' --
```
"""

    seen_urls: list[str] = []

    def fake_fetcher(url: str, timeout: float) -> str:
        seen_urls.append(url)
        return markdown

    sources = {
        "sqli": ["mock://sqli"],
        "xss": ["mock://xss"],
        "csrf": ["mock://csrf"],
        "path_traversal": ["mock://pt"],
    }

    counts = sync_from_open_source(
        base_dir=base_dir,
        repo_ref="v1.2.3",
        sources=sources,
        fetcher=fake_fetcher,
        max_per_category=20,
    )

    assert counts["sqli"] >= 1
    assert counts["xss"] >= 1
    assert len(seen_urls) == 4

    sqli_data = json.loads((base_dir / "sqli.json").read_text(encoding="utf-8"))
    assert any(item["source"] == "PayloadsAllTheThings@v1.2.3 (imported)" for item in sqli_data)
    assert any(item["risk_level"] == "high" for item in sqli_data)

    catalog = json.loads((base_dir / "catalog.json").read_text(encoding="utf-8"))
    assert catalog["dictionary_version"] != "old"
    assert len(catalog["changelog"]) >= 1


def test_sync_uses_default_source_templates_with_repo_ref(tmp_path: Path) -> None:
    base_dir = tmp_path / "payloads"
    base_dir.mkdir(parents=True, exist_ok=True)

    seen_urls: list[str] = []

    def fake_fetcher(url: str, timeout: float) -> str:
        seen_urls.append(url)
        return "```txt\n' OR '1'='1\n```"

    counts = sync_from_open_source(
        base_dir=base_dir,
        repo_ref="release-2026",
        fetcher=fake_fetcher,
        max_per_category=1,
    )

    assert counts["sqli"] == 1
    assert len(seen_urls) == 4
    assert all("release-2026" in url for url in seen_urls)


def test_incremental_sync_preserves_local_fields_and_local_only_records(tmp_path: Path) -> None:
    base_dir = tmp_path / "payloads"
    base_dir.mkdir(parents=True, exist_ok=True)

    (base_dir / "catalog.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "dictionary_version": "old",
                "updated_at": "2026-01-01T00:00:00Z",
                "changelog": [],
                "categories": {"sqli": "sqli.json"},
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    existing = [
        {
            "id": "sqli-local-1",
            "payload": "' OR '1'='1",
            "mode": "test",
            "risk_level": "medium",
            "enabled_by_default": False,
            "purpose": "custom local purpose",
            "expected_feature": "custom expected",
            "source": "local-manual",
        },
        {
            "id": "sqli-local-only",
            "payload": "local-only-payload",
            "mode": "test",
            "risk_level": "low",
            "enabled_by_default": True,
            "purpose": "local only",
            "expected_feature": "local only",
            "source": "local-manual",
        },
    ]
    (base_dir / "sqli.json").write_text(json.dumps(existing, ensure_ascii=False, indent=2), encoding="utf-8")

    markdown = "```txt\n' OR '1'='1\n' AND 1=2 --\n```"

    def fake_fetcher(url: str, timeout: float) -> str:
        return markdown

    counts = sync_from_open_source(
        base_dir=base_dir,
        sources={"sqli": ["mock://sqli"]},
        repo_ref="v2",
        fetcher=fake_fetcher,
        incremental=True,
        max_per_category=20,
    )

    assert counts["sqli"] >= 2

    sqli_data = json.loads((base_dir / "sqli.json").read_text(encoding="utf-8"))
    by_payload = {item["payload"]: item for item in sqli_data}

    # Existing overlapping record keeps local policy/annotations.
    assert by_payload["' OR '1'='1"]["enabled_by_default"] is False
    assert by_payload["' OR '1'='1"]["risk_level"] == "medium"
    assert by_payload["' OR '1'='1"]["source"] == "local-manual"

    # Local-only record should be preserved.
    assert "local-only-payload" in by_payload

    catalog = json.loads((base_dir / "catalog.json").read_text(encoding="utf-8"))
    assert "Incremental sync payload dictionaries" in catalog["changelog"][0]["changes"][0]
