# API 未授权访问方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的 API 未授权访问检测与利用流程。

## 1.2 适用范围

本文档适用于 RESTful API、GraphQL API 等各类 API 接口。

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

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-306 | 关键功能缺少认证 |
| CWE-284 | 不当访问控制 |
| CWE-639 | 参数化访问控制不当 |

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| REST API | 用户/数据 API | 缺少 Token 验证 |
| GraphQL | 查询/变更操作 | 查询权限未验证 |
| 内部 API | 管理 API | 未限制访问来源 |
| 版本 API | /api/v1/, /api/v2/ | 旧版本缺少安全控制 |
| 文档 API | Swagger/OpenAPI | 文档暴露敏感信息 |

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

## 2.5 漏洞利用绕过方法

### 2.5.1 认证头绕过

```bash
# 添加伪造认证头
Authorization: Bearer fake_token
X-Api-Key: fake_key
X-Access-Token: admin
```

### 2.5.2 内部 API 访问

```bash
# 如果 API 仅限制内部 IP
# 尝试：
# - SSRF 攻击
# - HTTP 请求走私
# - 反向代理绕过
```

### 2.5.3 API 版本绕过

```bash
# 新版本有认证，旧版本可能没有
/api/v1/users  → 无认证
/api/v2/users  → 需要认证
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
```

## 3.2 修复建议

1. **统一认证中间件** - 所有 API 端点经过认证检查
2. **基于角色的授权** - 实施细粒度的 API 授权
3. **API 网关** - 使用 API 网关统一管理
4. **速率限制** - 限制 API 访问频率

---

**参考资源**：
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [PortSwigger - API Testing](https://portswigger.net/web-security/api)
