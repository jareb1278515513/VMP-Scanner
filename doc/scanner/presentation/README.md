# 表现层说明（Presentation Layer）

## 1. 目标与职责

表现层负责将上游三层输出（Collection、Detection、Assessment）组织为可消费报告，并输出多种格式。

当前已实现能力：

1. 输出统一结构化报告对象（report dict）。
2. 生成 JSON 报告。
3. 生成 Markdown 报告。
4. 生成可交互 HTML 报告（中文为主，保留关键术语英文）。

职责边界：

1. 负责报告聚合、渲染、导出。
2. 不负责漏洞探测与风险评分算法。
3. 不负责外部 Web 服务部署（当前为静态文件模式）。

---

## 2. 代码结构

1. 层导出入口: scanner/presentation/__init__.py
2. reporting 子模块入口: scanner/presentation/reporting/__init__.py
3. 核心服务: scanner/presentation/reporting/service.py

核心类：

1. PresentationService
- render(request): 统一入口
- _build_report(...): 构建标准报告对象
- _render_markdown(report): 渲染 Markdown
- _render_html(report): 渲染交互式 HTML

---

## 3. 输入输出契约

### 3.1 输入

PresentationService.render 接收 dict：

1. collection: CollectionBundle
2. findings: FindingBundle
3. risks: RiskBundle
4. output:
- json_path
- markdown_path
- html_path
5. metadata:
- mode
- tool_version
- args

示例：

```json
{
  "collection": {"schema_version": "1.0", "target": "http://127.0.0.1/dvwa/"},
  "findings": {"schema_version": "1.0", "findings": []},
  "risks": {"schema_version": "1.0", "risk_items": [], "summary": {}},
  "output": {
    "json_path": "reports/report.json",
    "markdown_path": "reports/report.md",
    "html_path": "reports/report.html"
  },
  "metadata": {
    "mode": "attack",
    "tool_version": "0.1.0",
    "args": {}
  }
}
```

### 3.2 输出

render 返回实际写入路径：

```json
{
  "json_path": "reports/report.json",
  "markdown_path": "reports/report.md",
  "html_path": "reports/report.html"
}
```

---

## 4. 技术实现方法

### 4.1 统一报告模型构建

_build_report 会将上游三层数据聚合为统一 report 对象，主要分区：

1. schema_version / generated_at / target / metadata
2. assets
- network_summary
- web_summary
- network_assets
- web_assets
3. vulnerabilities
- total
- by_category
- by_severity_hint
- findings
4. risks
- summary
- items
5. recommendations（按 category + recommendation + retest 聚合统计）
6. errors（分 collection / detection / assessment）

### 4.2 JSON 渲染

1. 直接输出 report dict。
2. 编码 UTF-8，缩进 2 空格。
3. 适合后续脚本处理与前端二次消费。

### 4.3 Markdown 渲染

生成结构化章节：

1. Basic Information
2. Asset Summary
3. Risk Summary
4. Top Risks
5. Recommendations
6. Errors

### 4.4 HTML 渲染（苹果风格）

当前 HTML 报告采用静态单文件方案，核心技术点：

1. 视觉风格
- 玻璃态卡片（半透明 + 模糊）
- 大留白与轻阴影
- 苹果风格字体栈（SF Pro Display/Text 优先）
- 渐变与径向背景气氛层

2. 响应式布局
- 桌面双栏布局（风险表 + 分布图）
- 平板与手机自动折叠单栏

3. 交互能力
- 全文搜索（标题/分类/插件/URL）
- 等级筛选
- 分类筛选
- 插件筛选
- 点击行弹出详情抽屉
- 风险分布环图动态更新
- 导出当前筛选结果 JSON

4. 安全与数据注入
- 通过 script[type=application/json] 内嵌报告数据
- 使用 _safe_json_for_html 避免 HTML 解析冲突

5. 文案策略
- 页面文案中文为主
- 关键术语保留英文（Risk、Score、Critical、High 等）

---

## 5. 与主流程的集成

main.py 已接入表现层输出参数：

1. --report-json
2. --report-markdown
3. --report-html

当任一报告参数存在时，主流程将调用 PresentationService.render 完成输出。

---

## 6. 使用示例

### 6.1 端到端生成三种报告

```powershell
uv run main.py --target "http://127.0.0.1/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" --mode attack --max-depth 1 --allowed-domain 127.0.0.1 --auto-login --auth-login-url /dvwa/login.php --auth-username admin --auth-password password --auth-submit-field Login --auth-submit-value Login --auth-success-keyword logout.php --auth-extra security=low --report-json reports/dvwa-rich-risk.json --report-markdown reports/dvwa-rich-risk.md --report-html reports/dvwa-rich-risk.html --log-level INFO
```

### 6.2 本地查看 HTML 报告

直接在浏览器打开生成文件：

1. reports/dvwa-rich-risk.html

---

## 7. 测试与验证

已覆盖测试：

1. tests/test_presentation_service.py
- JSON/Markdown/HTML 三类文件可生成
- 关键文案与关键节点存在

2. tests/test_main_detection_switches.py
- 运行配置支持 report_html 参数

建议命令：

```powershell
uv run --with pytest pytest -q tests/test_presentation_service.py tests/test_main_detection_switches.py
```

---

## 8. 已知限制与后续方向

当前限制：

1. 页面联动筛选仍有增强空间（例如点击概览卡片直接筛选）。
2. 未实现打印专用样式与离线打包方案。
3. 未实现敏感字段脱敏开关。
4. 风险趋势时间线图尚未实现。

后续建议：

1. 增加卡片联动和锚点导航。
2. 增加 print CSS 与 PDF 导出友好布局。
3. 增加脱敏规则层（对 Cookie、Token、账号字段做掩码）。
4. 将 HTML 模板拆分为组件化渲染，便于长期维护。
