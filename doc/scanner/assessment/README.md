# 风险评估层说明（Assessment Layer）

## 1. 目标与职责

风险评估层负责把探测层输出的 FindingBundle 转换成可排序、可决策的 RiskBundle。

本层核心目标：

1. 将漏洞发现项映射为统一风险项（RiskItem）。
2. 计算风险分值并进行风险分级。
3. 自动补充修复建议与复测建议。
4. 对异常进行隔离并在 errors 中透传，不中断整体流程。

职责边界：

1. 负责评分、分级、建议模板生成。
2. 不负责漏洞探测执行。
3. 不负责报告排版和页面渲染。

---

## 2. 代码结构

1. contracts: scanner/assessment/contracts.py
2. service: scanner/assessment/service.py
3. 导出入口: scanner/assessment/__init__.py

关键数据结构：

1. AssessmentRequest: 输入请求（findings、weights、metadata）
2. RiskItem: 单条风险项
3. RiskBundle: 输出风险包（risk_items、summary、errors）

---

## 3. 输入输出契约

### 3.1 输入

AssessmentService.assess 接受：

1. AssessmentRequest 实例
2. 或 dict（会被 _coerce_request 归一化）

最小输入示例：

```json
{
  "findings": {
    "schema_version": "1.0",
    "target": "http://127.0.0.1/dvwa/",
    "findings": [
      {
        "id": "finding-001",
        "plugin": "xss_reflected",
        "category": "xss",
        "title": "Potential reflected XSS behavior",
        "severity_hint": "medium",
        "confidence": 0.8,
        "location": {"url": "http://127.0.0.1/dvwa/vulnerabilities/xss_r/", "param": "name"},
        "evidence": {"probe_url": "..."}
      }
    ],
    "errors": []
  },
  "weights": {
    "impact": 1.0,
    "likelihood": 1.0,
    "confidence": 1.0,
    "exposure": 1.0
  }
}
```

### 3.2 输出

输出类型为 RiskBundle 的 dict 形态：

1. schema_version
2. target
3. risk_items
4. summary（critical/high/medium/low）
5. errors

---

## 4. 技术实现方法

### 4.1 评分模型

当前评分公式：

RiskScore = Impact * Likelihood * Confidence * ExposureWeight

实现细节：

1. Impact/Likelihood 来源优先级：
- 优先按 category 使用 CATEGORY_BASELINE。
- 其次按 severity_hint 使用 SEVERITY_BASELINE。

2. Confidence：
- 从 finding.confidence 读取。
- 使用 _clamp_float 限制范围 [0.1, 1.0]。

3. ExposureWeight：
- 基于 location.url 和 location.param 推导。
- 规则示例：
- localhost/127.0.0.1 降权为 0.8。
- login/admin/api 等路径加权为 1.2。
- password/token/auth 等参数加权为 1.2。

4. 权重系统：
- 默认权重 DEFAULT_WEIGHTS = 1.0。
- 可通过 request.weights 覆盖 impact/likelihood/confidence/exposure。

### 4.2 风险分级

分级阈值：

1. score >= 16: Critical
2. score >= 10: High
3. score >= 5: Medium
4. 其余: Low

### 4.3 建议模板

由 RECOMMENDATION_TEMPLATES 按 category 注入：

1. recommendation（修复建议）
2. retest（复测建议）

若 category 未命中模板，使用 FALLBACK_RECOMMENDATION。

### 4.4 稳定性与错误处理

1. 输入校验在 _coerce_request 完成。
2. 单条 finding 处理失败时记录 risk_item_failed:*，不中断全量评估。
3. 输出 errors 包含上游 findings.errors + 本层新增错误。

---

## 5. 主流程接入方式

主流程 main.py 中调用顺序：

1. DetectionService.detect -> finding_bundle
2. AssessmentService.assess({"findings": finding_bundle}) -> risk_bundle
3. PresentationService.render 使用 risk_bundle 产出报告

这保证了分层解耦：评估层只依赖 findings 契约，不依赖探测执行细节。

---

## 6. 使用示例

### 6.1 代码示例

```python
from scanner.assessment import AssessmentService

service = AssessmentService()
risk_bundle = service.assess({
    "findings": finding_bundle,
    "weights": {
        "impact": 1.2,
        "likelihood": 1.0,
        "confidence": 1.0,
        "exposure": 1.0,
    },
})
```

### 6.2 CLI 端到端示例

```powershell
uv run main.py --target "http://127.0.0.1/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" --mode attack --max-depth 1 --allowed-domain 127.0.0.1 --auto-login --auth-login-url /dvwa/login.php --auth-username admin --auth-password password --auth-submit-field Login --auth-submit-value Login --auth-success-keyword logout.php --auth-extra security=low --report-json reports/dvwa-rich-risk.json --report-markdown reports/dvwa-rich-risk.md --report-html reports/dvwa-rich-risk.html --log-level INFO
```

---

## 7. 测试与验证

已覆盖测试：

1. tests/test_assessment_service.py
- 风险排序正确
- 权重覆盖生效
- 缺失 findings 时抛出错误

建议命令：

```powershell
uv run --with pytest pytest -q tests/test_assessment_service.py
```

---

## 8. 已知限制与后续方向

当前限制：

1. 暴露面权重规则仍是启发式规则，尚未接入资产分区/业务权重。
2. category 与模板映射是静态配置，未支持外部配置文件热更新。
3. 评分阈值目前固定在代码中。

后续建议：

1. 引入可配置评分策略（YAML/JSON）。
2. 增加资产标签（外网、内网、敏感系统）参与 ExposureWeight。
3. 为不同组织提供自定义建议模板覆盖机制。
