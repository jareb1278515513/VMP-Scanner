# VMP-Scanner 层次间服务接口说明书

## 1. 文档目标

定义 VMP-Scanner 四层架构之间的服务接口、数据契约和调用顺序，保证各层可独立开发、可替换实现、可稳定联调。

适用层次：

1. 采集层（Collection Layer）
2. 漏洞探测层（Detection Layer）
3. 风险评估层（Assessment Layer）
4. 表现层（Presentation Layer）

---

## 2. 分层职责与边界

### 2.1 采集层

职责：对目标进行网络资产发现和 Web 攻击面发现，输出标准化资产对象。

不负责：漏洞判断、风险分级、报告渲染。

### 2.2 探测层

职责：基于采集层资产执行插件探测，输出 Finding 列表。

不负责：端口扫描与爬虫细节实现、最终风险评分。

### 2.3 评估层

职责：将 Finding 映射为 RiskItem 并计算分数与等级。

不负责：探测请求细节与报告排版。

### 2.4 表现层

职责：输出 CLI/JSON/Markdown 报告，包含元数据、资产、漏洞、风险、建议。

不负责：扫描与评分算法本身。

---

## 3. 顶层调用链

统一调用顺序：

1. `CollectionService.collect` 产出 `CollectionBundle`
2. `DetectionService.detect` 读取 `CollectionBundle`，产出 `FindingBundle`
3. `AssessmentService.assess` 读取 `FindingBundle`，产出 `RiskBundle`
4. `PresentationService.render` 读取前三层结果并输出报告

建议由 `main.py` 仅作为编排入口，不直接耦合各层内部细节。

---

## 4. 层间接口定义

### 4.1 采集层 -> 探测层

接口名称：`CollectionService.collect`

输入契约：`CollectionRequest`

```json
{
  "target": "http://127.0.0.1/dvwa/",
  "mode": "test",
  "timeout": 3.0,
  "concurrency": 20,
  "network": {
    "ports": "80,443,3306",
    "port_range": null,
    "grab_banner": false
  },
  "crawler": {
    "max_depth": 2,
    "allowed_domains": ["127.0.0.1"],
    "cookies": {
      "PHPSESSID": "xxxx",
      "security": "low"
    }
  },
  "metadata": {
    "request_id": "uuid",
    "tool_version": "0.1.0"
  }
}
```

输出契约：`CollectionBundle`

```json
{
  "schema_version": "1.0",
  "target": "http://127.0.0.1/dvwa/",
  "started_at": "2026-03-23T14:00:00Z",
  "finished_at": "2026-03-23T14:00:10Z",
  "network_assets": [
    {
      "host": "127.0.0.1",
      "port": 80,
      "status": "open",
      "service_guess": "http",
      "service_version": "2.4",
      "confidence": "high",
      "response_time_ms": 1.5,
      "banner": null
    }
  ],
  "web_assets": {
    "visited_count": 12,
    "status_code_stats": {
      "200": 10,
      "302": 2
    },
    "urls": [
      {
        "url": "http://127.0.0.1/dvwa/login.php",
        "method": "GET",
        "params": [],
        "source_url": "http://127.0.0.1/dvwa/",
        "depth": 1,
        "status_code": 200
      }
    ],
    "forms": [
      {
        "page_url": "http://127.0.0.1/dvwa/login.php",
        "action": "http://127.0.0.1/dvwa/login.php",
        "method": "POST",
        "fields": [
          {"name": "username", "input_type": "text", "required": false},
          {"name": "password", "input_type": "password", "required": false}
        ],
        "has_csrf_token": true,
        "depth": 1
      }
    ],
    "suspicious_endpoints": [],
    "errors": []
  },
  "errors": []
}
```

探测层最少依赖字段：

1. `network_assets[].port/status/service_guess`
2. `web_assets.urls[]`
3. `web_assets.forms[]`

---

### 4.2 探测层 -> 评估层

接口名称：`DetectionService.detect`

输入契约：`DetectionRequest`

```json
{
  "mode": "test",
  "collection": "CollectionBundle",
  "plugin_policy": {
    "enabled_plugins": ["sqli", "xss", "csrf"],
    "safe_only": true
  }
}
```

输出契约：`FindingBundle`

```json
{
  "schema_version": "1.0",
  "target": "http://127.0.0.1/dvwa/",
  "findings": [
    {
      "id": "finding-001",
      "plugin": "xss",
      "category": "xss",
      "title": "Reflected XSS suspected",
      "severity_hint": "medium",
      "confidence": 0.8,
      "location": {
        "url": "http://127.0.0.1/dvwa/vulnerabilities/xss_r/",
        "method": "GET",
        "param": "name"
      },
      "evidence": {
        "request": "GET ...",
        "response_snippet": "<pre>Hello <script>alert(1)</script></pre>",
        "payload": "<script>alert(1)</script>"
      },
      "created_at": "2026-03-23T14:05:00Z"
    }
  ],
  "plugin_stats": {
    "total": 3,
    "success": 3,
    "failed": 0
  },
  "errors": []
}
```

评估层最少依赖字段：

1. `findings[].category`
2. `findings[].confidence`
3. `findings[].severity_hint`
4. `findings[].location`
5. `findings[].evidence`

---

### 4.3 评估层 -> 表现层

接口名称：`AssessmentService.assess`

输入契约：`AssessmentRequest`

```json
{
  "findings": "FindingBundle",
  "weights": {
    "impact": 1.0,
    "likelihood": 1.0,
    "confidence": 1.0,
    "exposure": 1.0
  }
}
```

输出契约：`RiskBundle`

```json
{
  "schema_version": "1.0",
  "target": "http://127.0.0.1/dvwa/",
  "risk_items": [
    {
      "finding_id": "finding-001",
      "score": 15.2,
      "level": "High",
      "impact": 4,
      "likelihood": 4,
      "confidence": 0.95,
      "exposure_weight": 1.0,
      "recommendation": "对输出进行 HTML 编码并启用 CSP",
      "retest": "提交 payload 后页面不应原样回显脚本"
    }
  ],
  "summary": {
    "critical": 0,
    "high": 1,
    "medium": 0,
    "low": 0
  },
  "errors": []
}
```

表现层最少依赖字段：

1. `risk_items[]`
2. `summary`
3. `target`

---

### 4.4 表现层输出

接口名称：`PresentationService.render`

输入契约：`PresentationRequest`

```json
{
  "collection": "CollectionBundle",
  "findings": "FindingBundle",
  "risks": "RiskBundle",
  "output": {
    "formats": ["cli", "json", "markdown"],
    "json_path": "reports/report.json",
    "markdown_path": "reports/report.md"
  },
  "metadata": {
    "mode": "test",
    "tool_version": "0.1.0",
    "args": {}
  }
}
```

输出行为：

1. CLI 实时摘要（进度、统计、错误）
2. JSON 报告（结构化二次处理）
3. Markdown 报告（归档与汇报）

---

### 4.5 字段映射表（Detection/Assessment -> Presentation）

以下映射基于当前实现：`scanner/presentation/reporting/service.py` 的 `_build_report` 逻辑。

#### 4.5.1 Detection（FindingBundle）-> Presentation

| Detection 字段 | Presentation 字段 | 转换规则 | 备注 |
| --- | --- | --- | --- |
| `target` | `target` | 当 `risks.target` 为空时，回退到 `findings.target` | `collection.target` 为最终回退 |
| `findings` | `vulnerabilities.findings` | 原样透传 | 列表元素结构保持不变 |
| `findings[].category` | `vulnerabilities.by_category` | 小写归一化后计数 | `Counter` 聚合 |
| `findings[].severity_hint` | `vulnerabilities.by_severity_hint` | 小写归一化后计数 | `Counter` 聚合 |
| `findings` | `vulnerabilities.total` | `len(findings)` | 统计字段 |
| `errors` | `errors.detection` | 原样透传（缺失时空数组） | 错误隔离展示 |
| `plugin_stats` | - | 当前不进入 Presentation Report 主结构 | 可作为后续扩展字段 |

#### 4.5.2 Assessment（RiskBundle）-> Presentation

| Assessment 字段 | Presentation 字段 | 转换规则 | 备注 |
| --- | --- | --- | --- |
| `target` | `target` | 优先级最高，直接覆盖报告目标 | 若为空则回退到 Detection/Collection |
| `risk_items` | `risks.items` | 原样透传 | 列表元素结构保持不变 |
| `summary` | `risks.summary` | 原样透传；为空时默认 `{critical:0,high:0,medium:0,low:0}` | 风险总览卡片来源 |
| `risk_items[].category + recommendation + retest` | `recommendations[]` | 按三元组分组计数，生成 `{category,recommendation,retest,count}` | 按 `count` 降序排序 |
| `errors` | `errors.assessment` | 原样透传（缺失时空数组） | 错误隔离展示 |

#### 4.5.3 Presentation 派生与兜底规则

| Presentation 字段 | 数据来源 | 规则 |
| --- | --- | --- |
| `schema_version` | `PresentationService.schema_version` | 当前固定为 `1.0` |
| `generated_at` | 系统时间 | UTC ISO 8601 |
| `metadata` | `PresentationRequest.metadata` | 原样透传（缺失时空对象） |
| `errors.collection` | `CollectionBundle.errors` | 缺失时空数组 |
| `errors.detection` | `FindingBundle.errors` | 缺失时空数组 |
| `errors.assessment` | `RiskBundle.errors` | 缺失时空数组 |

实现建议：第三方接入 Presentation 时，至少保证 `findings.findings` 与 `risks.risk_items/summary` 字段完整，以确保风险统计、详情展示、建议聚合可用。

---

## 5. 通用字段规范

### 5.1 必填元数据

所有 Bundle 均应包含：

1. `schema_version`
2. `target`
3. `errors`（即使为空数组）

### 5.2 时间与时区

1. 时间字段统一 ISO 8601 格式，建议 UTC。
2. 示例：`2026-03-23T14:05:00Z`。

### 5.3 错误处理

1. 任何层出现可恢复异常时，不中断全局流程，写入本层 `errors`。
2. 不可恢复异常由上层编排器统一捕获并终止任务。

### 5.4 版本兼容

1. 新增字段保持向后兼容。
2. 删除或重命名字段需升级 `schema_version`。

---

## 6. 建议代码接口（Python）

```python
class CollectionService:
    def collect(self, request: dict) -> dict: ...


class DetectionService:
    def detect(self, request: dict) -> dict: ...


class AssessmentService:
    def assess(self, request: dict) -> dict: ...


class PresentationService:
    def render(self, request: dict) -> None: ...
```

建议在 `scanner/` 下新增 `contracts/` 存放 Bundle dataclass 或 TypedDict，作为跨层唯一数据契约来源。

---

## 7. MVP 对接建议（当前代码基线）

1. 先把 `main.py` 中网络扫描和爬虫结果封装成 `CollectionBundle`。
2. 探测层执行器先做空实现，返回空 `findings` 与插件统计。
3. 评估层先做占位打分（可配置权重）。
4. 表现层先输出 JSON，再补 Markdown 模板。

这样可以先打通端到端链路，再逐层增强算法与插件能力。
