# Payload Dictionary 管理

## 1. 功能

该模块用于管理漏洞探测层的 payload 字典，支持：

1. 按漏洞分类加载 payload（sqli/xss/csrf/path_traversal）。
2. 区分 test 与 attack 模式。
3. 基于风险等级做默认安全过滤（高风险默认禁用）。
4. 提供字典版本号与更新记录查询。
5. 支持从开源仓库（PayloadsAllTheThings）同步并转换为本地标准字典。

## 2. 字典结构

目录文件：

1. `catalog.json`: 字典版本、changelog、分类文件映射。
2. `sqli.json`
3. `xss.json`
4. `csrf.json`
5. `path_traversal.json`

每条 payload 记录字段：

1. `id`
2. `payload`
3. `mode` (`test` or `attack`)
4. `risk_level` (`low`/`medium`/`high`)
5. `enabled_by_default`
6. `purpose`
7. `expected_feature`
8. `source`

## 3. Python 接口

```python
from scanner.detection.payloads import PayloadDictionaryManager, load_payloads

manager = PayloadDictionaryManager()
print(manager.get_dictionary_version())

safe_test_sqli = manager.load_payloads("sqli", mode="test")
attack_sqli = manager.load_payloads(
    "sqli",
    mode="attack",
    include_high_risk=True,
    include_disabled=True,
)

xss_payloads = load_payloads("xss", mode="test")
```

## 4. 安全策略

1. 默认只返回 `enabled_by_default=true` 的 payload。
2. 默认不返回 `risk_level=high` 的 payload。
3. 若要使用高风险 payload，必须显式设置：
   1. `include_high_risk=True`
   2. `include_disabled=True`

## 5. 开源同步

默认同步源：PayloadsAllTheThings（GitHub raw 文本）。

同步命令：

```bash
uv run python tools/sync_payloads.py --payload-dir scanner/detection/payloads --repo-ref master --max-per-category 200
```

增量同步（保留本地人工维护字段与本地自定义 payload）：

```bash
uv run python tools/sync_payloads.py --payload-dir scanner/detection/payloads --repo-ref master --incremental
```

固定版本示例（tag/commit）：

```bash
uv run python tools/sync_payloads.py --payload-dir scanner/detection/payloads --repo-ref v0.4.0 --max-per-category 200
```

同步后行为：

1. 覆盖对应分类字典文件。
2. 自动更新 `catalog.json` 的 `dictionary_version`、`updated_at`、`changelog`。
3. 根据风险关键字自动标记高风险 payload，并默认禁用。

主流程可选同步：

```bash
uv run main.py --target http://127.0.0.1/dvwa/ --sync-payloads --payload-sync-ref master
```

主流程增量同步：

```bash
uv run main.py --target http://127.0.0.1/dvwa/ --sync-payloads --payload-sync-ref master --payload-sync-incremental
```
