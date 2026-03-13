# API 业务逻辑测试方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的 API 业务逻辑测试流程，帮助发现和利用 API 设计层面的安全缺陷。

## 1.2 适用范围

本文档适用于各类 API 系统，包括 RESTful API、GraphQL API、gRPC API、WebSocket 等。

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### API 业务逻辑漏洞原理

API 业务逻辑漏洞是指 API 在端点设计、参数验证、访问控制、速率限制等设计层面的缺陷。

**核心设计层面**：
- 端点设计与版本管理
- 参数验证与序列化
- 访问控制与认证
- 速率限制与配额

**本质问题**：
- API 设计未考虑滥用场景
- 参数验证不充分
- 访问控制设计缺陷
- 资源限制设计不足

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-840 | 业务逻辑缺陷 |
| CWE-284 | 访问控制不当 |
| CWE-770 | 资源分配无限制 |

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 数据查询 | GET 接口 | 越权查询、数据泄露 |
| 数据创建 | POST 接口 | 恶意数据注入 |
| 数据修改 | PUT/PATCH 接口 | 越权修改 |
| 数据删除 | DELETE 接口 | 越权删除 |
| 批量操作 | 批量接口 | 批量滥用 |
| 文件操作 | 上传下载接口 | 文件滥用 |
| 认证授权 | 登录/令牌接口 | 认证绕过 |
| Webhook | 回调接口 | 事件伪造 |

## 2.3 漏洞发现方法

### 2.3.1 API 枚举

**步骤 1：发现 API 端点**

```
发现方法：
- API 文档（Swagger/OpenAPI）
- JavaScript 文件分析
- 代理流量分析
- 常见端点猜测
- 错误信息泄露
```

**步骤 2：绘制 API 关系图**

```
API 端点分类：
- 公开端点（无需认证）
- 认证端点（需要令牌）
- 管理端点（需要管理员）
- 内部端点（不应暴露）
```

### 2.3.2 参数分析

```
参数类型分析：
- 路径参数：/api/users/{id}
- 查询参数：/api/users?role=admin
- 请求体参数：{"name": "test"}
- 请求头参数：X-User-ID: 123
```

### 2.3.3 信任边界识别

```
关键检查点：
- 参数验证位置（客户端/服务端）
- 访问控制检查位置
- 业务规则执行位置
- 数据过滤位置
```

## 2.4 漏洞测试方法

### 2.4.1 对象级别越权测试（BOLA/IDOR）

```bash
# 场景：资源访问

# 1. 正常请求
GET /api/users/me
Authorization: Bearer $TOKEN

# 2. 修改资源 ID
GET /api/users/123
Authorization: Bearer $TOKEN

# 3. 遍历 ID
GET /api/users/1
GET /api/users/2
GET /api/users/3
# 检查是否验证资源归属
```

### 2.4.2 功能级别越权测试（BFLA）

```bash
# 场景：功能访问

# 1. 访问管理端点
GET /api/admin/users
Authorization: Bearer $USER_TOKEN

# 2. 修改请求方法
POST /api/users  # 普通用户不可创建
Authorization: Bearer $USER_TOKEN

# 3. 访问内部端点
GET /api/internal/debug
GET /api/internal/metrics
```

### 2.4.3 参数篡改测试

```bash
# 场景：参数验证

# 1. 类型篡改
POST /api/users
{"age": "twenty"}  # 字符串而非数字

# 2. 范围篡改
POST /api/transfer
{"amount": -100}  # 负值

# 3. 额外参数注入
POST /api/users
{
    "name": "test",
    "is_admin": true,  # 额外参数
    "role": "admin"
}

# 4. 数组注入
POST /api/users
{"role": ["user", "admin"]}
```

### 2.4.4 批量操作测试

```bash
# 场景：批量接口

# 1. 超大数量
POST /api/users/batch
{"ids": [1, 2, 3, ..., 10000]}

# 2. 越权批量
POST /api/users/batch-delete
{"ids": [1, 2, 999]}  # 999 是他人资源

# 3. 并发批量
# 同时发起多个批量请求
```

### 2.4.5 速率限制测试

```bash
# 场景：速率限制

# 1. 基准测试
# 记录正常请求响应时间

# 2. 频率测试
for i in {1..1000}; do
    curl -X POST https://api.target.com/login \
         -d "user=test&pass=test"
done

# 3. 绕过测试
# 更换 IP、User-Agent、API Key
```

### 2.4.6 GraphQL 特定测试

```bash
# 场景：GraphQL API

# 1. 深度遍历查询
query {
  user {
    friends {
      friends {
        friends {
          # 深层嵌套
        }
      }
    }
  }
}

# 2. 大批量查询
query {
  users(first: 10000) {
    name email phone
  }
}

# 3. 字段遍历
query {
  __schema {
    types {
      fields {
        name
      }
    }
  }
}

# 4. 别名绕过
query {
  u1: user(id: 1) { name }
  u2: user(id: 2) { name }
  # 大量别名
}
```

### 2.4.7 Webhook 伪造测试

```bash
# 场景：Webhook 回调

# 1. 直接调用 Webhook
POST /api/webhook/payment
{
    "event": "payment.completed",
    "data": {"amount": 1000}
}

# 2. 伪造签名
# 修改 payload 但保持签名

# 3. 重放攻击
# 重放有效 Webhook 请求
```

### 2.4.8 API 版本测试

```bash
# 场景：API 版本

# 1. 访问旧版本
GET /api/v1/users  # 可能有已知漏洞
GET /api/v2/users

# 2. 访问未发布版本
GET /api/v3/users  # 测试中版本
GET /api/beta/users

# 3. 版本参数篡改
GET /api/users?version=admin
```

### 2.4.9 内容协商测试

```bash
# 场景：内容类型

# 1. 修改 Content-Type
POST /api/users
Content-Type: application/json
# 改为
Content-Type: application/xml
Content-Type: text/plain

# 2. 修改 Accept
Accept: application/json
# 改为
Accept: application/xml
Accept: text/html

# 3. 测试不同格式响应
# 可能泄露额外信息
```

## 2.5 漏洞利用方法

### 2.5.1 数据泄露攻击

```bash
# 利用越权查询

# 1. 遍历所有资源
# 2. 导出敏感数据
# 3. 造成数据泄露
```

### 2.5.2 业务滥用攻击

```bash
# 利用业务逻辑漏洞

# 1. 批量注册垃圾账户
# 2. 刷取奖励/积分
# 3. 破坏业务规则
```

### 2.5.3 资源耗尽攻击

```bash
# 利用资源限制不足

# 1. 发起大量复杂查询
# 2. 耗尽服务器资源
# 3. 造成服务中断
```

---

# 第三部分：附录

## 3.1 API 业务逻辑测试检查清单

```
□ 是否有对象级别越权
□ 是否有功能级别越权
□ 参数验证是否充分
□ 批量操作是否有限制
□ 速率限制是否有效
□ GraphQL 是否有深度限制
□ Webhook 是否验证签名
□ API 版本是否安全
□ 错误信息是否泄露
□ 是否有 API 文档泄露
```

## 3.2 常用工具

| 工具 | 用途 | 链接 |
|-----|------|------|
| Burp Suite | API 测试 | https://portswigger.net/burp |
| Postman | API 调试 | https://postman.com/ |
| OWASP Amass | API 枚举 | https://owasp.org/www-project-amass/ |
| GraphQL Playground | GraphQL 测试 | https://github.com/graphql/graphql-playground |
| Kiterunner | API 路由发现 | https://github.com/assetnote/kiterunner |

## 3.3 修复建议

1. **对象级授权** - 验证资源归属
2. **功能级授权** - 验证用户权限
3. **输入验证** - 严格验证所有参数
4. **速率限制** - 实施细粒度限流
5. **分页限制** - 限制单次查询数量
6. **错误处理** - 不泄露敏感信息
7. **文档保护** - 保护 API 文档
8. **监控告警** - 监控异常 API 行为

---

**参考资源**：
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [API Security Best Practices](https://www.apisecurity.io/)
