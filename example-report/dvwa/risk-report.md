# VMP-Scanner Risk Report

## 1. Basic Information

- Target: http://127.0.0.1/
- Generated At (UTC): 2026-03-24T08:59:50.686222Z
- Mode: attack
- Tool Version: 0.1.0

## 2. Asset Summary

- Network Ports: 4
- Open Ports: 1
- Visited Pages: 38
- URLs: 38
- Forms: 16

## 3. Risk Summary

| 严重 | 高危 | 中危 | 低危 |
| --- | --- | --- | --- |
| 0 | 4 | 14 | 4 |

## 4. Top Risks

| Finding ID | Category | Level | Score | Title |
| --- | --- | --- | --- | --- |
| finding-6692e72d3d01 | sqli | High | 14.4 | SQL injection confirmed |
| finding-37d03daee314 | sqli | High | 14.4 | SQL injection confirmed |
| finding-c82603008bdb | xss | High | 11.78 | Reflected XSS executable payload echoed |
| finding-40fd4f16cad9 | path_traversal | High | 11.78 | Sensitive path disclosure confirmed |
| finding-dbaf9f9a8074 | weak-credential | Medium | 8.83 | Potential weak credential accepted |
| finding-13acb767eb2e | weak-credential | Medium | 8.83 | Potential weak credential accepted |
| finding-1fec10512954 | weak-credential | Medium | 8.83 | Potential weak credential accepted |
| finding-97cfe2982b97 | path_traversal | Medium | 8.7 | Sensitive path disclosure confirmed |
| finding-15f005212383 | csrf | Medium | 6.12 | CSRF attack may be forgeable |
| finding-f0e44725922f | csrf | Medium | 6.12 | CSRF attack may be forgeable |
| finding-739959934d0b | csrf | Medium | 6.12 | CSRF attack may be forgeable |
| finding-e42a8e23880f | csrf | Medium | 6.12 | CSRF attack may be forgeable |
| finding-49ca0cda7909 | csrf | Medium | 6.12 | CSRF attack may be forgeable |
| finding-80ff5ed8bc8a | csrf | Medium | 6.12 | CSRF attack may be forgeable |
| finding-0b9f92bf33e3 | weak-credential | Medium | 5.76 | Weak password control may be insufficient |
| finding-331cf77312d9 | weak-credential | Medium | 5.76 | Weak password control may be insufficient |
| finding-05bf6971c753 | weak-credential | Medium | 5.76 | Weak password control may be insufficient |
| finding-e9245e39828a | weak-credential | Medium | 5.76 | Weak password control may be insufficient |
| finding-c9320cb2a927 | surface-anomaly | Low | 2.4 | Suspicious endpoint discovered |
| finding-bfa3bf67968e | surface-anomaly | Low | 2.4 | Suspicious endpoint discovered |

## 5. Recommendations

### 5.1 weak-credential
- Recommendation: 启用强密码策略、登录限速与失败锁定机制。
- Retest: 使用弱口令凭据重复登录尝试，应触发失败告警或锁定策略。
- Related Findings: 7

### 5.2 csrf
- Recommendation: 为关键操作加入一次性 CSRF Token，并校验来源与会话绑定。
- Retest: 在缺失或伪造 Token 情况下重复提交请求，应被服务端拒绝。
- Related Findings: 6

### 5.3 surface-anomaly
- Recommendation: 收敛对外暴露接口并为异常端点添加访问控制。
- Retest: 再次扫描异常端点时不应返回高价值信息或管理入口内容。
- Related Findings: 4

### 5.4 sqli
- Recommendation: 使用参数化查询并在服务端实施严格输入校验。
- Retest: 对相同参数重复提交 SQL 注入 payload，页面不应出现错误回显或差异响应。
- Related Findings: 2

### 5.5 path_traversal
- Recommendation: 限制可访问路径并在服务端做目录白名单校验。
- Retest: 访问同路径字典项时应返回 403 或 404，不应泄露敏感资源。
- Related Findings: 2

### 5.6 xss
- Recommendation: 对输出进行上下文感知编码，并配置 CSP 限制脚本执行。
- Retest: 提交相同 XSS payload，页面应只显示转义文本且脚本不执行。
- Related Findings: 1

## 6. Errors

- Collection: 0
- Detection: 0
- Assessment: 0
