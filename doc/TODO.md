# VMP-Scanner 开发任务清单（TODO）

## 使用方式

- 每完成一项就勾选，并在备注中记录 commit 或关键变更。
- 所有功能任务都要附带最小可运行示例和测试记录。

## 里程碑总览

- [x] M1 采集层可用（网络探测 + Web 爬虫）
- [ ] M2 漏洞探测层可用（插件框架 + 3~5 个插件）
- [ ] M3 风险评估与报告闭环（评分 + 输出）
- [ ] M4 表现层可用（Web 可视化报告）
- [ ] M5 稳定性与工程化完善（测试、日志、文档）

---

## M1：采集层（优先级 P0）

### 1.1 项目骨架与运行入口

- [x] 建立分层目录结构：scanner/collection、scanner/detection、scanner/assessment、scanner/presentation、tests
- [x] 在 main.py 实现参数入口（目标、模式、深度、并发、超时）
- [x] 统一配置加载（命令行参数 + 默认配置）
- [x] 输出最小运行日志（开始、结束、耗时、异常）

交付标准：
- [x] `uv run python main.py --help` 可正常显示参数
- [x] 运行后至少能输出任务初始化和结束日志

### 1.2 网络探测引擎（Network Discovery Engine）

- [x] 实现单主机 TCP connect 扫描
- [x] 支持端口范围与端口列表两种输入
- [x] 支持并发扫描与超时控制
- [x] 输出端口状态（open/closed/filtered）
- [x] 可选实现轻量 banner 抓取

交付标准：
- [x] 对 DVWA 宿主机可识别开放端口（如 80）
- [x] 扫描结果可保存为结构化对象（JSON 可序列化）

### 1.3 Web 状态感知爬虫引擎（Web Crawler Engine）

- [x] 基于 requests + BeautifulSoup 抓取页面
- [x] 提取链接、表单、输入字段
- [x] 实现 URL 去重和标准化
- [x] 支持最大深度限制与域名白名单
- [x] 支持会话 Cookie（用于 DVWA 登录态）

交付标准：
- [x] 能产出 URL 列表与表单列表
- [x] 输出字段包含来源页、方法、参数、深度

测试记录：
- `uv run --with pytest pytest -q` -> 3 passed
- `uv run main.py --target http://localhost/ --max-depth 1 --allowed-domain localhost --timeout 1` -> 爬虫流程可执行并输出统计日志
- `uv run --with pytest pytest -q`（新增 DVWA 自动登录测试）-> 4 passed
- `uv run main.py --target http://127.0.0.1/dvwa/ --max-depth 2 --allowed-domain 127.0.0.1 --auto-login --auth-login-url /dvwa/login.php --auth-username admin --auth-password password --auth-submit-field Login --auth-submit-value Login --auth-success-keyword logout.php --auth-extra security=low --crawler-output-json reports/dvwa-crawl.json` -> 在 DVWA 服务已启动时支持通用自动登录与 JSON 输出

---

## M2：漏洞探测层（优先级 P0）

### 2.1 插件框架

- [x] 设计插件基类（metadata/match/probe/verify/evidence）
- [x] 实现插件注册与加载机制（静态注册或自动发现）
- [x] 实现统一执行器（按目标分发插件）
- [x] 支持测试模式与攻击模式开关
- [x] 增加插件执行日志与异常隔离（单插件失败不影响全局）

交付标准：
- [x] 至少 1 个示例插件可独立执行并输出 Finding
- [x] 执行器可统计插件成功/失败数量

### 2.2 Payload 字典管理（参考 PayloadsAllTheThings）

- [x] 建立 scanner/payloads 目录和分类字典文件
- [x] 按漏洞分类维护字典（sqli/xss/csrf/path_traversal）
- [x] 为每个 payload 增加元数据（用途、风险等级、预期特征）
- [x] 区分测试模式与攻击模式 payload
- [x] 增加字典版本号和更新记录

交付标准：
- [x] 插件可按漏洞类型加载对应 payload 集合
- [x] 高风险 payload 默认禁用，需显式开启

测试记录：
- `uv run --with pytest pytest -q`（新增 payload 字典管理测试）-> 13 passed

### 2.3 首批漏洞插件

- [x] SQL 注入检测插件（错误回显/布尔差异基础验证）
- [x] XSS 检测插件（反射型回显检测）
- [x] 敏感路径探测插件（字典枚举 + 状态判定）
- [x] CSRF 基础检测插件（表单 token 缺失检查）
- [x] 弱口令策略评估插件（限速、低频、可配置）

交付标准：
- [x] 至少 3 个插件在 DVWA 场景可稳定输出结果
- [x] 每个插件都包含 evidence 字段用于复核

测试记录：
- `uv run --with pytest pytest -q`（新增 M2.3 插件与执行器联调测试）-> 通过

---

## M3：风险评估层（优先级 P1）

### 3.1 风险评估模型

- [ ] 定义 Finding -> RiskItem 映射规则
- [ ] 实现综合评分公式：RiskScore = Impact * Likelihood * Confidence * ExposureWeight
- [ ] 实现风险分级（Critical/High/Medium/Low）
- [ ] 为每类漏洞补充修复建议模板
- [ ] 增加复测建议字段（如何验证修复）

交付标准：
- [ ] 风险项可按分数排序输出
- [ ] 同一 Finding 重复执行分级结果稳定

### 3.2 报告输出

- [ ] CLI 输出实时进度与总结统计
- [ ] 生成 JSON 报告（便于后续可视化接入）
- [ ] 生成 Markdown 报告（便于归档和汇报）
- [ ] 增加执行元数据（时间、模式、工具版本、参数）

交付标准：
- [ ] 报告包含资产、漏洞、风险、建议四大部分
- [ ] 报告结构可被脚本再次读取处理

---

## M4：表现层（优先级 P1）

### 4.1 可视化报告数据契约

- [ ] 定义前端报告输入模型（Summary、Asset、Finding、RiskItem、Recommendation）
- [ ] 补充字段映射表（Detection/Assessment -> Presentation）
- [ ] 统一时间、风险等级、URL 与证据字段格式
- [ ] 设计版本字段与向后兼容策略（report_version）

交付标准：
- [ ] 前端可用单一 JSON 输入完成页面渲染
- [ ] 数据契约文档可独立指导第三方接入

### 4.2 Web 报告页面基础实现

- [ ] 实现独立 Web 报告页面（静态 HTML + CSS + JS）
- [ ] 完成首页概览卡片（资产数、漏洞数、高危数、扫描耗时）
- [ ] 完成漏洞列表表格（分页、排序、关键字段展示）
- [ ] 完成漏洞详情抽屉/弹窗（evidence、复现步骤、修复建议、复测建议）

交付标准：
- [ ] 报告页面在本地浏览器可直接打开，无需额外服务
- [ ] 主流程可通过参数输出 web 报告文件（如 reports/report.html）

### 4.3 交互与筛选能力

- [ ] 实现多维筛选（风险等级、插件类型、目标资产、状态码区间）
- [ ] 实现全文搜索（URL、参数名、漏洞标题、插件名）
- [ ] 实现视图联动（点击概览卡片可联动筛选结果）
- [ ] 增加批量展开/折叠与快速定位（回到顶部、锚点跳转）

交付标准：
- [ ] 1000 条 Finding 以内筛选与搜索响应可接受（目标 < 500ms）
- [ ] 常见分析路径可在 3 次点击内到达详情

### 4.4 可视化与美观性增强

- [ ] 增加风险分布图（等级分布、插件分布、资产分布）
- [ ] 增加时间维度图（扫描阶段耗时或任务时间线）
- [ ] 建立统一设计 token（颜色、字体、间距、圆角、阴影）
- [ ] 适配响应式布局（桌面/平板/移动）

交付标准：
- [ ] 页面在主流桌面分辨率与移动端可正常查看
- [ ] 视觉规范可复用到后续 CLI Web 面板或在线版

### 4.5 导出与分享

- [ ] 支持在页面内导出筛选后的 JSON 子集
- [ ] 支持打印友好样式（PDF 导出友好）
- [ ] 支持生成离线归档包（HTML + 资源 + 原始 JSON）
- [ ] 增加脱敏选项（隐藏账号、Cookie、敏感参数）

交付标准：
- [ ] 安全团队可直接用导出结果做汇报附件
- [ ] 离线环境可完整查看报告且不丢样式

测试记录：
- [ ] `uv run --with pytest pytest -q`（新增 presentation 层单元测试）-> 待补充
- [ ] `uv run main.py --target http://127.0.0.1/dvwa/ --mode detect --report-json reports/dvwa.json --report-html reports/dvwa.html` -> 待补充


## M5：稳定性与工程化（优先级 P1）

### 5.1 质量保障

- [ ] 为核心模块补齐单元测试（解析、评分、去重、加载）
- [ ] 增加基础集成测试（DVWA 端到端流程）
- [ ] 建立回归样本（固定输入和期望输出）
- [ ] 设置最小测试覆盖率目标（建议 60%+）

交付标准：
- [ ] `uv run pytest` 可稳定通过
- [ ] 核心路径变更可被测试覆盖

### 5.2 可维护性改进

- [ ] 使用统一的参数配置文件,可以不在cli中输入过多参数
- [ ] 统一日志格式与日志级别
- [ ] 完善错误处理（超时、连接失败、解析失败）
- [ ] 补充 README 运行说明与示例命令
- [ ] 在 doc 中补充样例报告与问题排查文档

交付标准：
- [ ] 新成员可按文档在 30 分钟内完成首次运行
- [ ] 常见错误有对应排查说明

---




