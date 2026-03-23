# Detection Plugins 设计与实现说明

## 1. 模块目标

plugins 子模块负责将采集层输出的资产（URL、表单、可疑路径等）转化为结构化漏洞发现结果（Finding）。

每个插件遵循统一生命周期：

1. metadata: 声明插件名称、类别、默认标题和置信度。
2. match: 基于输入资产快速判断是否值得执行。
3. probe: 执行探测/攻击逻辑，产出候选结果。
4. verify: 二次确认候选结果是否可接受。
5. evidence: 归一化证据字段，供复核与报告使用。

接口定义见上层：scanner/detection/base.py。

## 2. 插件加载与执行

默认插件集合在 scanner/detection/plugins/__init__.py 的 load_default_plugins 中注册，当前包括：

1. suspicious_endpoint
2. sqli_basic
3. xss_reflected
4. sensitive_path
5. csrf_missing_token
6. weak_password_policy

执行器会按插件顺序调用插件，并统计每个插件 success/failed/skipped。

## 3. 运行模式语义

### 3.1 detect/test 模式

目标：判断是否存在漏洞线索。

特点：

1. 优先使用低风险 payload。
2. 不主动执行高风险攻击行为。
3. 证据侧重可观测差异与异常回显。

### 3.2 attack 模式

目标：在可控前提下进行攻击型验证。

特点：

1. 可启用高风险 payload 与默认禁用 payload。
2. 证据中包含攻击动作和攻击特征。
3. 标题与置信度更偏向“可利用性确认”。

## 4. payload 字典接入策略

当前插件中的字典使用覆盖：

1. sqli_basic: 使用 sqli 分类字典（test/attack 双模式）。
2. xss_reflected: 使用 xss 分类字典（test/attack 双模式）。
3. sensitive_path: 使用 path_traversal 分类字典（test/attack 双模式）。
4. csrf_missing_token: 使用 csrf 分类字典（PoC 与证据样本）。
5. weak_password_policy: 当前为策略驱动，不依赖 payload 字典。
6. suspicious_endpoint: 当前为路径特征驱动，不依赖 payload 字典。

字典加载统一通过 PayloadDictionaryManager（scanner/detection/payloads/manager.py）。

## 5. 插件技术细节

### 5.1 SQLi 插件（sqli_basic）

文件：scanner/detection/plugins/sqli_plugin.py

核心逻辑：

1. 从 URL 参数和 GET 表单字段构造探测目标。
2. 字典中选取布尔对照 payload（true/false）。
3. 对比 true/false 响应差异，并检测 SQL 错误关键字。
4. attack 模式下尝试攻击型 payload，提取攻击特征（如 mysql、information_schema 等）。

关键 evidence 字段：

1. true_probe_url / false_probe_url
2. true_status / false_status
3. error_marker / boolean_diff
4. attack_probe_url / attack_feature
5. used_payloads

### 5.2 XSS 插件（xss_reflected）

文件：scanner/detection/plugins/xss_plugin.py

核心逻辑：

1. 从 xss 字典选取 payload。
2. detect 模式使用可观察探针；attack 模式偏向可执行脚本载荷。
3. 基于 marker 检测原样回显、转义回显与可执行模式。

关键 evidence 字段：

1. payload / payload_id / payload_source
2. contains_raw / contains_escaped
3. executable_pattern

### 5.3 敏感路径插件（sensitive_path）

文件：scanner/detection/plugins/sensitive_path_plugin.py

核心逻辑：

1. 合并内置敏感路径与字典路径样本。
2. 探测目标路径并按状态码和页面内容判定。
3. attack 模式提取敏感数据特征（如 root:x:0:0、api_key 等）。

关键 evidence 字段：

1. path / status
2. attack_feature
3. content_preview

### 5.4 CSRF 插件（csrf_missing_token）

文件：scanner/detection/plugins/csrf_missing_token_plugin.py

核心逻辑：

1. 识别 POST 表单且缺失 CSRF token。
2. 从 csrf 字典提取 payload 样本，写入证据与 PoC。
3. attack 模式生成 forged_post 模板供人工复核。

关键 evidence 字段：

1. has_csrf_token
2. payload_ids / payload_samples
3. attack_poc.target / attack_poc.forged_post

### 5.5 弱口令策略插件（weak_password_policy）

文件：scanner/detection/plugins/weak_password_policy_plugin.py

核心逻辑：

1. detect 模式：被动评估登录表单是否缺少防自动化线索。
2. attack 模式：可配置低频凭据尝试，检测是否出现成功关键字。

关键 evidence 字段：

1. assessment
2. credential / success_keyword
3. attempt_budget / rate_limited_interval_seconds

### 5.6 可疑端点插件（suspicious_endpoint）

文件：scanner/detection/plugins/suspicious_endpoint_plugin.py

核心逻辑：

1. 消费爬虫输出的 suspicious_endpoints。
2. 转换为标准 Finding 记录。

## 6. 会话与认证上下文传递

为保证插件在受保护页面上的稳定性，采集层会在 metadata 中传递登录态 cookies。

插件通过 requests.Session 并注入 session_cookies 后执行 probe，避免因重定向到登录页导致误判。

## 7. 常见调参项

主入口可通过 detection 元数据覆盖插件参数：

1. --detection-plugin-timeout
2. --detection-plugin-max-targets
3. --plugin-timeout plugin=seconds
4. --plugin-max-targets plugin=count

示例：

uv run main.py --target "http://127.0.0.1/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" --mode attack --enable-plugin sqli_basic --detection-plugin-timeout 2.0 --detection-plugin-max-targets 1 --log-level DEBUG

## 8. 扩展新插件建议

1. 保持 metadata.name 全局唯一。
2. match 尽量轻量，避免无效网络请求。
3. evidence 必须可复核，避免只返回布尔值。
4. 区分 detect 与 attack 模式语义。
5. 优先使用 payload 字典，不在代码中硬编码大量载荷。
