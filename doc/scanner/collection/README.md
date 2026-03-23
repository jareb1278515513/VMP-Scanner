# Collection Layer 总览

## 1. 目标与定位

Collection Layer 负责将目标系统转换为可消费的资产数据，并向下游层提供统一的服务接口。

核心目标：

1. 对网络资产进行发现（端口、服务、版本、状态）。
2. 对 Web 资产进行发现（URL、表单、输入字段、可疑端点）。
3. 统一产出 CollectionBundle，供 Detection Layer 直接消费。

本层不负责漏洞判断、风险评分、报告渲染。

## 2. 模块结构

1. network/
作用：网络探测引擎。

2. crawler/
作用：Web 状态感知爬虫引擎。

3. contracts.py
作用：跨层数据契约定义（请求、配置、输出 Bundle）。

4. service.py
作用：CollectionService 编排入口，聚合 network 与 crawler 结果。

## 3. 功能清单

### 3.1 网络探测能力

1. 目标规范化（支持主机名、IP、URL）。
2. 端口解析（列表和范围）。
3. TCP connect 扫描（open/closed/filtered）。
4. 可选 banner 抓取。
5. 轻量服务识别与版本提取。

### 3.2 Web 采集能力

1. 基于 requests + BeautifulSoup 抓取页面。
2. 链接、脚本资源、表单 action 提取。
3. URL 标准化与去重。
4. 深度限制与域名白名单。
5. Cookie 会话支持。
6. 通用表单自动登录支持。
7. 可疑路径与响应特征标记。

### 3.3 统一编排能力

1. 通过 CollectionService.collect 统一触发网络与爬虫采集。
2. 网络和爬虫异常隔离，不因单项失败导致整个链路崩溃。
3. 统一错误汇总到 CollectionBundle.errors。
4. 统一输出 schema_version、时间戳、metadata。

## 4. 对外服务接口

### 4.1 入口

接口：CollectionService.collect(request)

支持两种请求类型：

1. CollectionRequest（dataclass）
2. dict（运行时自动标准化）

### 4.2 最小请求示例

    {
      "target": "http://127.0.0.1/dvwa/",
      "mode": "test",
      "timeout": 3,
      "concurrency": 20,
      "network": {
        "ports": "80,443,3306",
        "port_range": null,
        "grab_banner": false
      },
      "crawler": {
        "enabled": true,
        "max_depth": 2,
        "allowed_domains": ["127.0.0.1"],
        "cookie_header": "PHPSESSID=xxx; security=low",
        "auth": {
          "enabled": true,
          "login_url": "/dvwa/login.php",
          "username": "admin",
          "password": "password",
          "username_field": "username",
          "password_field": "password",
          "csrf_field": "user_token",
          "submit_field": "Login",
          "submit_value": "Login",
          "success_keyword": "logout.php",
          "extra_fields": ["security=low"]
        }
      },
      "metadata": {
        "request_id": "abc-123",
        "source": "main"
      }
    }

### 4.3 输出契约

返回：CollectionBundle（可 JSON 序列化）

关键字段：

1. schema_version: 契约版本，当前为 1.0。
2. target: 扫描目标。
3. started_at / finished_at: UTC 时间戳。
4. network_assets: 网络资产数组。
5. web_assets: Web 资产对象；若目标不是 http/https，可为 null。
6. errors: 本层异常列表（可恢复错误）。
7. metadata: 透传元数据。

## 5. 交付物定义（向下游）

下游层应将 CollectionBundle 作为唯一输入，不直接耦合 network/crawler 内部实现。

### 5.1 Detection Layer 最小依赖字段

1. network_assets[].port
2. network_assets[].status
3. network_assets[].service_guess
4. web_assets.urls[]
5. web_assets.forms[]

### 5.2 异常消费建议

1. 若 errors 非空，不中断流程，按降级策略继续执行。
2. 若 network_assets 为空，跳过网络相关插件。
3. 若 web_assets 为空或 urls 为空，跳过 Web 相关插件。

## 6. Python 调用示例

    from scanner.collection import CollectionService

    service = CollectionService()
    bundle = service.collect(
        {
            "target": "http://127.0.0.1/dvwa/",
            "timeout": 3,
            "concurrency": 20,
            "network": {"ports": "80,443", "grab_banner": False},
            "crawler": {"enabled": True, "max_depth": 2},
            "metadata": {"request_id": "demo-001"},
        }
    )

    print(bundle["schema_version"])
    print(len(bundle["network_assets"]))

## 7. 与 main.py 的关系

当前 main.py 已改为通过 CollectionService.collect 获取统一采集结果，再进行日志与可选文件输出。

这意味着后续接入 Detection Layer 时，可以直接复用 main.py 中的 CollectionBundle，而无需再次拼接网络和爬虫调用细节。

## 8. 后续扩展建议

1. 在 contracts.py 增加 TypedDict 或 pydantic 校验，提升契约稳健性。
2. 在 service.py 增加 request_id 自动生成与 tracing 字段。
3. 提供 CollectionBundle JSON Schema，方便跨语言消费。
4. 增加批量目标采集接口（多 target 一次执行）。
