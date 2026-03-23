# Network Discovery Layer 设计与实现说明

## 1. 文档目标

本文档详细介绍 scanner/collection/network 层当前已实现的能力、处理流程、数据结构与扩展方式。
该层是采集层中的网络探测引擎，负责主机端口状态发现与服务识别，为后续漏洞探测层提供基础攻击面信息。

## 2. 模块定位

### 2.1 在系统中的角色

网络探测层在整体链路中的位置：

1. 接收入口层传入的目标与扫描参数。
2. 执行 TCP 端口连通性探测。
3. 对开放端口进行服务识别、版本提取与置信度评估。
4. 产出结构化 JSON 结果，供日志输出和后续模块消费。

### 2.2 当前实现文件

1. scanner/collection/network/scanner.py
2. scanner/collection/network/service_fingerprints.json

## 3. 已实现功能清单

### 3.1 目标规范化

通过 normalize_target_host 支持以下输入形式：

1. 主机名，如 localhost
2. IPv4 地址，如 127.0.0.1
3. URL，如 http://localhost

若输入为 URL，会自动提取 hostname 作为扫描目标。

### 3.2 端口参数解析

通过 parse_ports 支持两种输入方式：

1. ports 列表模式，例如 80,443,3306
2. port-range 区间模式，例如 1-1024

约束与规则：

1. 两种模式互斥，不能同时指定。
2. 端口范围必须在 1 到 65535。
3. 默认端口集合为 80, 443, 8080, 3306。

### 3.3 TCP 连通性扫描

通过 scan_host_ports 与 _scan_single_port 实现：

1. 使用 connect_ex 做 TCP 连接判断。
2. 使用 ThreadPoolExecutor 并发扫描。
3. 支持 timeout 控制每个端口的连接时间。
4. 输出端口状态：open、closed、filtered。

状态判定逻辑：

1. connect_ex 返回 0，判定 open。
2. connect_ex 非 0，判定 closed。
3. 超时或系统错误，判定 filtered。

### 3.4 可选 banner 抓取

开启 grab_banner 后，会在开放端口连接后尝试读取少量响应数据：

1. 发送轻量换行请求。
2. 读取最多 256 字节。
3. 尝试解码为 UTF-8 文本。

说明：

1. 并非所有服务都会返回 banner。
2. banner 会作为服务识别与版本提取的重要辅助信息。

### 3.5 增强服务识别

当前服务识别不是单一端口映射，而是分层策略：

1. Banner 规则识别。
2. 轻量协议探测。
3. 端口映射兜底。

#### 3.5.1 Banner 规则识别

通过 service_fingerprints.json 中 service_hints 匹配 marker：

1. 命中后给出 service。
2. 如配置了 version_regex，则提取版本号。
3. 此路径置信度标记为 high。

#### 3.5.2 轻量协议探测

按照端口对应的 probe_order 执行探测函数，已实现：

1. HTTP 探测
2. HTTPS 探测
3. SSH 探测
4. MySQL 探测
5. Redis 探测
6. SMTP 探测
7. 数据库 banner 探测

探测成功时会返回：

1. service
2. service_version（若可提取）
3. confidence（通常为 high 或 medium）

#### 3.5.3 端口映射兜底

若探测未命中，则使用：

1. common_service_ports 映射
2. socket.getservbyport 系统映射

此路径置信度标记为 low。

## 4. 数据输出结构

单端口结果对象 PortScanResult 字段如下：

1. host: 目标主机
2. port: 端口号
3. status: 端口状态，open/closed/filtered
4. service_guess: 服务名推断结果
5. service_version: 服务版本，无法提取时为 null
6. confidence: high/medium/low
7. response_time_ms: 单端口探测耗时
8. banner: 读取到的原始 banner 文本（可为空）

该对象最终转为 dict，保证 JSON 可序列化。

## 5. 外置规则配置

配置文件位于 scanner/collection/network/service_fingerprints.json。

### 5.1 配置项说明

1. common_service_ports
作用：端口到服务名映射的低置信度兜底表。

2. service_hints
作用：banner 关键字与版本正则规则。
每项包含：marker、service、version_regex。

3. probe_order
作用：按端口定义协议探测顺序。
支持 default 回退顺序。

### 5.2 维护建议

1. 优先增补 service_hints 的高质量规则。
2. probe_order 中高概率协议放前面，减少无效探测。
3. 版本正则保持简单可维护，避免过拟合。

## 6. 与入口 main.py 的协作

入口层当前流程：

1. 解析参数。
2. 调用 normalize_target_host 和 parse_ports。
3. 调用 scan_host_ports。
4. 在日志中输出开放端口摘要。

开放端口摘要格式已包含：

1. 端口
2. 服务
3. 版本
4. 置信度

示例：80/http(v=1.24.0,conf=high)

## 7. 典型测试命令

### 7.1 最小端口检测

uv run python main.py --target localhost --ports 80 --timeout 1

### 7.2 区间扫描

uv run python main.py --target 127.0.0.1 --port-range 1-100 --timeout 1

### 7.3 查看详细结果

uv run python main.py --target localhost --ports 22,80,443,3306 --timeout 1 --log-level DEBUG

### 7.4 尝试 banner 抓取

uv run python main.py --target localhost --ports 22,80,443 --grab-banner --timeout 1 --log-level DEBUG

## 8. 已知限制

1. 当前使用轻量探测，覆盖面有限，不等同于专业指纹引擎。
2. 某些服务在非标准端口、代理后或加固环境下可能识别不准。
3. timeout 较小时可能导致更多 filtered 结果。
4. banner 依赖目标服务行为，很多场景无法获取。

## 9. 后续优化方向

1. 增加更多协议探测器，如 FTP、POP3、IMAP、RDP。
2. 引入服务识别证据字段，记录命中的规则与探测方法。
3. 增加规则热更新能力，避免重启进程才能生效。
4. 增加单元测试与回归样本，验证识别准确率。
