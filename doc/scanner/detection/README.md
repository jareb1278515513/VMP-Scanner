# Detection 层设计与实现说明

## 1. 模块定位

Detection 层负责把 Collection 层采集到的资产数据转换为漏洞发现结果。

输入：CollectionBundle（dict）

输出：FindingBundle（dict）

核心目标：

1. 插件化探测，支持快速扩展新漏洞类型。
2. 统一证据结构，便于人工复核与报告生成。
3. 支持 detect 与 attack 双模式运行。
4. 与 payload 字典解耦，支持开源同步和版本治理。

## 2. 目录结构

scanner/detection/

1. base.py: 插件抽象接口定义。
2. contracts.py: Finding/FindingBundle 数据契约。
3. registry.py: 插件注册与查询。
4. executor.py: 插件执行编排、异常隔离、统计汇总。
5. plugins/: 各漏洞插件实现。
6. payloads/: payload 字典、目录索引、同步与管理逻辑。

## 3. 关键数据契约

### 3.1 Finding

字段：

1. id
2. plugin
3. category
4. title
5. severity_hint
6. confidence
7. location
8. evidence
9. created_at

### 3.2 FindingBundle

字段：

1. schema_version
2. target
3. findings
4. plugin_stats: total/success/failed/skipped
5. errors

## 4. 执行流程

执行入口：scanner/detection/executor.py 的 DetectionExecutor.run。

流程：

1. 加载默认插件并按配置筛选启用列表。
2. 逐插件执行 match。
3. 对通过 match 的插件调用 probe 产出 candidates。
4. 对每个 candidate 执行 verify。
5. verify 通过后组装 Finding，写入 findings。
6. 记录每个插件执行状态与错误。

异常处理：

1. 单插件异常不会中断整体流程。
2. 异常以 plugin_failed:plugin_name:message 形式写入 errors。

## 5. 模式设计：detect 与 attack

### 5.1 detect/test

目的：发现漏洞存在性。

策略：

1. 优先低风险 payload。
2. 对结果做保守判定。
3. 证据聚焦可观测差异。

### 5.2 attack

目的：验证漏洞可利用性。

策略：

1. 可使用 attack 类 payload。
2. 可放开高风险/默认禁用项。
3. evidence 记录攻击动作与攻击特征。

主入口 main.py 支持：--mode detect/test/attack。

## 6. payload 字典协作机制

payload 管理模块在 scanner/detection/payloads。

### 6.1 字典加载

通过 PayloadDictionaryManager.load_payloads(category, mode, include_high_risk, include_disabled) 返回过滤后的记录。

### 6.2 字典治理能力

1. catalog.json 管理版本和分类映射。
2. 记录字段标准化：id/payload/mode/risk_level/enabled_by_default/purpose/expected_feature/source。
3. 支持开源仓库同步与增量合并。

### 6.3 目前插件使用情况

1. sqli_basic: 已接入 sqli 字典。
2. xss_reflected: 已接入 xss 字典。
3. sensitive_path: 已接入 path_traversal 字典。
4. csrf_missing_token: 已接入 csrf 字典（样本与 PoC）。
5. weak_password_policy: 未接入字典（策略型）。
6. suspicious_endpoint: 未接入字典（采集结果型）。

## 7. 与主入口的集成点

main.py 中的关键集成：

1. build_detection_metadata: 构建插件级 timeout/max_targets 等配置。
2. resolve_enabled_plugins: 按 enable/disable 参数筛选插件。
3. DetectionExecutor.run(collection_bundle, mode, enabled_plugins): 执行探测。

常用参数：

1. --enable-plugin
2. --disable-plugin
3. --detection-plugin-timeout
4. --detection-plugin-max-targets
5. --plugin-timeout plugin=seconds
6. --plugin-max-targets plugin=count

## 8. 典型运行命令

### 8.1 仅跑 SQLi（attack）

uv run main.py --target "http://127.0.0.1/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" --mode attack --max-depth 0 --allowed-domain 127.0.0.1 --auto-login --auth-login-url /dvwa/login.php --auth-username admin --auth-password password --auth-submit-field Login --auth-submit-value Login --auth-success-keyword logout.php --auth-extra security=low --enable-plugin sqli_basic --detection-plugin-timeout 2.0 --detection-plugin-max-targets 1 --log-level DEBUG

### 8.2 跑默认插件集合（detect）

uv run main.py --target "http://127.0.0.1/dvwa/" --mode detect --max-depth 2 --allowed-domain 127.0.0.1 --auto-login --auth-login-url /dvwa/login.php --auth-username admin --auth-password password --auth-submit-field Login --auth-submit-value Login --auth-success-keyword logout.php --auth-extra security=low --log-level INFO

## 9. 技术细节与设计取舍

1. 使用 dict 作为层间数据格式，降低跨层耦合成本。
2. 插件接口保持五段式（metadata/match/probe/verify/evidence），兼顾扩展与可测试性。
3. 执行器将“插件执行成功但无发现”记录为 plugin_no_findings，便于观察探测覆盖率。
4. evidence 强制结构化，避免只依赖日志文本。
5. 登录态 cookie 在采集层注入 metadata，插件复用 session 提升受保护页面探测成功率。

## 10. 下一步建议

1. 为 weak_password_policy 增加独立字典类别（如 weak_password）。
2. 为 suspicious_endpoint 增加特征字典（如 endpoint_markers）。
3. 增加 findings JSON 文件输出能力，便于回归对比与报告生成。
