# 租户隔离设计测试方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的多租户系统租户隔离测试流程，帮助发现和利用租户隔离设计缺陷。

## 1.2 适用范围

本文档适用于各类多租户 SaaS 系统，包括企业软件、云平台、协作工具等。

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 租户隔离漏洞原理

租户隔离漏洞是指多租户系统在数据隔离、访问控制、资源配置等设计层面的缺陷，导致不同租户之间可能发生数据泄露或资源混用。

**核心隔离层面**：
- 数据隔离
- 访问控制隔离
- 网络隔离
- 计算资源隔离

**本质问题**：
- 租户标识传递设计缺陷
- 数据查询隔离设计不足
- 缓存隔离设计缺陷
- 配置隔离设计不足

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-284 | 访问控制不当 |
| CWE-200 | 信息泄露 |
| CWE-639 | 授权绕过 |

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 数据查询 | 列表/详情查询 | 越权访问他租户数据 |
| 数据创建 | 新建记录 | 数据归属错误租户 |
| 数据修改 | 更新记录 | 修改他租户数据 |
| 数据删除 | 删除记录 | 删除他租户数据 |
| 文件存储 | 文件上传下载 | 访问他租户文件 |
| 用户管理 | 成员管理 | 管理他租户成员 |
| 配置管理 | 租户配置 | 修改他租户配置 |
| API 调用 | 跨租户 API | 越权调用 API |

## 2.3 漏洞发现方法

### 2.3.1 业务流程分析

**步骤 1：绘制租户架构图**

```
典型多租户架构：
单实例多租户：
┌─────────────┐
│  应用实例   │
├─────┬─────┬─┤
│租户 A│租户 B│租户 C│
└─────┴─────┴─┘

数据隔离方式：
- 独立数据库
- 共享数据库独立 Schema
- 共享数据库共享 Schema（tenant_id 区分）
```

**步骤 2：识别租户标识传递**

```
租户标识传递方式：
- URL 路径：/api/tenant123/users
- 请求头：X-Tenant-ID: 123
- JWT Claim：{"tenant_id": "123"}
- 子域名：tenant123.app.com
- 参数：?tenant_id=123
```

**步骤 3：识别信任边界**

```
关键检查点：
- 数据查询是否过滤 tenant_id
- 文件访问是否验证租户权限
- 缓存是否按租户隔离
- 配置是否按租户隔离
```

### 2.3.2 关键参数识别

```
多租户请求中的关键参数：
- 租户 ID（各种形式）
- 资源 ID（可能跨租户）
- 用户 ID（可能跨租户）
- 组织 ID
```

## 2.4 漏洞测试方法

### 2.4.1 租户 ID 篡改测试

```bash
# 场景：API 请求

# 1. 正常请求
GET /api/users
X-Tenant-ID: tenant_A
Authorization: Bearer $TOKEN_A

# 2. 篡改租户 ID
GET /api/users
X-Tenant-ID: tenant_B  # 修改为他租户
Authorization: Bearer $TOKEN_A

# 3. 检查响应
# 是否返回 tenant_B 的数据
```

### 2.4.2 资源 ID 遍历测试

```bash
# 场景：资源访问

# 1. 获取本租户资源
GET /api/documents/1

# 2. 遍历资源 ID
GET /api/documents/2
GET /api/documents/3
GET /api/documents/4
# 检查是否验证租户归属

# 3. UUID 遍历
# 如果 ID 是 UUID，尝试预测或遍历
```

### 2.4.3 数据查询越权测试

```bash
# 场景：列表查询

# 1. 正常查询
GET /api/orders?tenant_id=tenant_A

# 2. 修改查询条件
GET /api/orders?tenant_id=tenant_B

# 3. 移除租户过滤
GET /api/orders  # 无 tenant_id

# 4. 注入租户 ID
GET /api/orders?tenant_id[$ne]=tenant_A
# 获取非本租户数据
```

### 2.4.4 文件访问越权测试

```bash
# 场景：文件存储

# 1. 获取本租户文件
GET /api/files/file_123

# 2. 遍历文件 ID
GET /api/files/file_001
GET /api/files/file_002
# 检查是否验证租户归属

# 3. 直接访问存储
GET https://storage.app.com/tenant_b/secret.pdf
# 检查是否有访问控制
```

### 2.4.5 缓存隔离测试

```bash
# 场景：缓存系统

# 1. 租户 A 设置缓存
POST /api/cache/set
{"key": "config", "value": "A_value"}

# 2. 租户 B 获取相同 key
POST /api/cache/get
{"key": "config"}
# 检查是否返回 A 的值

# 3. 缓存污染
# 设置恶意缓存影响他租户
```

### 2.4.6 配置隔离测试

```bash
# 场景：租户配置

# 1. 获取本租户配置
GET /api/tenant/config

# 2. 修改配置请求
PUT /api/tenant/config
{
    "tenant_id": "tenant_B",  # 修改他租户
    "setting": "value"
}

# 3. 检查是否生效
```

### 2.4.7 用户管理越权测试

```bash
# 场景：成员管理

# 1. 添加用户到他租户
POST /api/tenant/users
{
    "tenant_id": "tenant_B",
    "user_id": "user_123"
}

# 2. 删除他租户用户
DELETE /api/tenant/users
{
    "tenant_id": "tenant_B",
    "user_id": "admin"
}

# 3. 修改他租户用户角色
PUT /api/tenant/users/role
{
    "tenant_id": "tenant_B",
    "user_id": "user_123",
    "role": "admin"
}
```

### 2.4.8 子域名隔离测试

```bash
# 场景：子域名多租户

# 1. 正常访问
GET https://tenant_a.app.com/api/data

# 2. 修改 Host 头
GET https://tenant_b.app.com/api/data
Host: tenant_a.app.com

# 3. 检查响应
# 是否返回正确租户数据
```

### 2.4.9 GraphQL 越权测试

```bash
# 场景：GraphQL API

# 1. 正常查询
query {
  tenant(id: "tenant_A") {
    users { name }
  }
}

# 2. 查询他租户
query {
  tenant(id: "tenant_B") {
    users { name }
  }
}

# 3. 批量查询
query {
  tenantA: tenant(id: "tenant_A") { users { name } }
  tenantB: tenant(id: "tenant_B") { users { name } }
}
```

## 2.5 漏洞利用方法

### 2.5.1 数据泄露攻击

```bash
# 利用租户隔离漏洞

# 1. 遍历所有租户数据
# 2. 导出敏感信息
# 3. 造成数据泄露
```

### 2.5.2 数据污染攻击

```bash
# 利用写入漏洞

# 1. 向他租户写入恶意数据
# 2. 修改他租户配置
# 3. 破坏业务运行
```

### 2.5.3 资源耗尽攻击

```bash
# 利用资源隔离不足

# 1. 大量占用共享资源
# 2. 影响他租户使用
# 3. 造成服务中断
```

---

# 第三部分：附录

## 3.1 租户隔离测试检查清单

```
□ 租户 ID 是否可篡改
□ 数据查询是否过滤租户
□ 资源访问是否验证租户归属
□ 文件存储是否隔离
□ 缓存是否按租户隔离
□ 配置是否按租户隔离
□ 用户管理是否越权
□ 子域名是否正确解析
□ GraphQL 是否验证租户
□ 是否有跨租户监控
```

## 3.2 常用工具

| 工具 | 用途 | 链接 |
|-----|------|------|
| Burp Suite | 请求篡改 | https://portswigger.net/burp |
| Postman | API 测试 | https://postman.com/ |
| GraphQL Playground | GraphQL 测试 | https://github.com/graphql/graphql-playground |

## 3.3 修复建议

1. **租户标识不可篡改** - 从认证令牌提取租户 ID
2. **数据查询强制过滤** - 所有查询自动添加租户过滤
3. **资源归属验证** - 访问资源时验证租户归属
4. **缓存隔离** - 缓存 key 包含租户前缀
5. **配置隔离** - 配置按租户严格隔离
6. **文件访问控制** - 文件访问验证租户权限
7. **审计日志** - 记录跨租户访问尝试
8. **监控告警** - 监控异常跨租户行为

---

**参考资源**：
- [OWASP Multi-Tenancy Security](https://owasp.org/www-project-web-security-testing-guide/)
- [SaaS Security Best Practices](https://www.cloudsecurityalliance.org/)
