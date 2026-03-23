# Web 状态感知爬虫引擎

## 目标能力

- 基于 requests + BeautifulSoup 抓取页面。
- 提取链接、表单和输入字段。
- 对 URL 做标准化与去重（主机小写、默认端口折叠、查询参数排序、去掉 fragment）。
- 支持最大深度与域名白名单。
- 支持通过 Cookie Header 复用登录态。
- 支持通用表单自动登录（可配置登录 URL、字段名和附加字段）。
- 支持将爬虫结果写入 JSON 文件。

## 主要入口

- `crawl_web_state(start_url, max_depth, timeout, allowed_domains=None, cookies=None, session=None)`
- `normalize_url(raw_url, base_url=None)`
- `parse_cookie_header(cookie_header)`

## 最小示例

```python
from scanner.collection.crawler import crawl_web_state, parse_cookie_header

result = crawl_web_state(
    start_url="http://localhost/",
    max_depth=2,
    timeout=3,
    allowed_domains=["localhost"],
    cookies=parse_cookie_header("PHPSESSID=abc; security=low"),
)

print("visited:", result["visited_count"])
print("urls:", len(result["urls"]))
print("forms:", len(result["forms"]))
```

## 输出结构

返回对象为可 JSON 序列化字典，关键字段：

- `start_url`: 起始 URL
- `max_depth`: 最大深度
- `visited_count`: 已访问页面数
- `status_code_stats`: HTTP 状态码统计
- `redirect_chains`: 重定向链列表
- `urls`: 发现的 URL 列表（包含 `url/method/params/source_url/depth/status_code`）
- `forms`: 表单列表（包含 `page_url/action/method/fields/has_csrf_token/depth`）
- `suspicious_endpoints`: 可疑接口列表（路径特征或响应错误特征）
- `errors`: 爬取异常记录

## CLI 示例

```bash
uv run main.py --target http://localhost/ --max-depth 2 --allowed-domain localhost --cookie "PHPSESSID=abc; security=low"
```

通用表单自动登录 + JSON 输出示例：

```bash
uv run main.py --target http://127.0.0.1/dvwa/ --max-depth 2 --allowed-domain 127.0.0.1 --auto-login --auth-login-url /dvwa/login.php --auth-username admin --auth-password password --auth-submit-field Login --auth-submit-value Login --auth-success-keyword logout.php --auth-extra security=low --crawler-output-json reports/dvwa-crawl.json
```
