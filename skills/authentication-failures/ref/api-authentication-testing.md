# **渗透测试方法论：API 认证测试**

---

# **第一部分：文档概述**

## 1.1 编写目的
- 为渗透测试人员提供一套标准化的 REST/GraphQL API 认证安全测试流程
- 帮助测试人员系统性地发现 API 认证机制中的安全缺陷
- 提高 API 认证漏洞发现的准确率和效率

## 1.2 适用范围
- 适用于 RESTful API、GraphQL API、gRPC 等接口认证测试
- 适用于基于 Token、JWT、OAuth 的 API 认证机制
- 适用于微服务架构中的服务间认证

## 1.3 读者对象
- 本文件主要面向执行渗透测试任务的安全工程师、安全分析师
- 负责 API 开发的开发人员
- 负责代码审计和安全加固的技术人员

---

# **第二部分：核心渗透技术专题**

## 专题一：API 认证测试

### 2.1 技术介绍

API 认证测试是指对应用程序编程接口（API）的身份验证机制进行全面的安全评估。其本质是**验证 API 能否正确识别和验证调用者身份，防止未授权访问**。

API 认证常见机制：

| **认证机制** | **传输方式** | **特点** |
| :--- | :--- | :--- |
| API Key | Header/Query Parameter | 简单、长期有效 |
| Bearer Token | Authorization Header | 基于 OAuth2、JWT |
| Basic Auth | Authorization Header | Base64 编码用户名密码 |
| HMAC | 自定义 Header | 请求签名验证 |
| mTLS | TLS 证书 | 双向证书认证 |
| JWT | Authorization Header | 无状态、自包含 |

### 2.2 测试常见于哪些业务场景

| **业务场景** | **功能示例** | **风险点描述** |
| :--- | :--- | :--- |
| **用户认证 API** | `/api/auth/login` | 暴力破解、凭证泄露 |
| **资源访问 API** | `/api/users/{id}` | IDOR、越权访问 |
| **令牌刷新 API** | `/api/auth/refresh` | 令牌重放、无限刷新 |
| **密码重置 API** | `/api/auth/reset-password` | 令牌泄露、逻辑缺陷 |
| **第三方集成** | OAuth 回调端点 | 重定向劫持、令牌窃取 |
| **Webhook 端点** | 回调通知接口 | 签名验证缺失 |
| **GraphQL 端点** | `/graphql` | 查询复杂度攻击、内省泄露 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

- **认证端点测试**
  - 测试登录接口的速率限制
  - 测试账户枚举（不同错误响应）
  - 测试 JWT 算法篡改（none 算法）
  - 测试令牌有效期和刷新机制
  - 测试 API Key 的权限范围

- **授权头测试**
  - 测试缺失 Authorization 头的响应
  - 测试无效/过期令牌的响应
  - 测试不同认证方案的兼容性
  - 测试 Authorization 头注入

- **端点访问控制测试**
  - 尝试未认证访问受保护端点
  - 尝试低权限访问高权限端点
  - 尝试 HTTP 方法绕过（GET vs POST）
  - 测试内容类型绕过（Content-Type）

- **GraphQL 特定测试**
  - 测试内省查询是否启用
  - 测试查询复杂度限制
  - 测试批量查询攻击
  - 测试字段级权限控制

#### 2.3.2 白盒测试

- **代码审计**
  - 检查认证中间件实现
  - 审计令牌验证逻辑
  - 检查权限验证代码
  - 查找硬编码 API Key

- **配置检查**
  - 检查 CORS 配置
  - 检查速率限制配置
  - 检查 JWT 密钥管理
  - 检查日志记录配置

### 2.4 漏洞利用方法

#### 2.4.1 基础信息收集

```bash
# API 端点发现
curl -X OPTIONS https://api.target.com/users

# GraphQL 内省查询
curl -X POST https://api.target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { types { name } } }"}'

# 认证方式探测
curl -i https://api.target.com/protected/resource
```

#### 2.4.2 令牌攻击

| **操作** | **方法** | **目的** |
| :--- | :--- | :--- |
| JWT 篡改 | 修改 payload，使用 none 算法 | 绕过签名验证 |
| 令牌重放 | 重放捕获的有效令牌 | 未撤销令牌重用 |
| 令牌提升 | 修改 JWT 中的角色声明 | 权限提升 |
| 密钥爆破 | 对弱签名密钥进行爆破 | 伪造有效令牌 |

#### 2.4.3 API 滥用

```bash
# 速率限制测试
for i in {1..1000}; do
  curl -H "Authorization: Bearer $TOKEN" \
    https://api.target.com/resource
done

# 批量查询攻击（GraphQL）
curl -X POST https://api.target.com/graphql \
  -d '{"query": "{ user1: user(id:1) { email } user2: user(id:2) { email } ... }"}'
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过认证

- **路径遍历** - 尝试 `/api/../admin/users`
- **参数污染** - 使用多个相同参数
- **内容类型混淆** - 尝试不同 Content-Type
- **HTTP 方法绕过** - POST 改为 GET/PUT/PATCH

#### 2.5.2 绕过速率限制

- **IP 轮换** - 使用代理池
- **API Key 轮换** - 使用多个有效 API Key
- **参数变异** - 添加不同查询参数
- **时间分散** - 延长请求间隔

#### 2.5.3 绕过输入验证

- **编码绕过** - URL 编码、Base64、Unicode
- **嵌套 JSON** - 深层嵌套绕过验证
- **类型混淆** - 字符串 vs 数字 vs 数组
- **GraphQL 别名** - 使用别名绕过字段限制

---

# **第三部分：附录**

## 3.1 API 认证测试检查清单

| **检查项** | **测试方法** | **预期结果** |
| :--- | :--- | :--- |
| 认证强制 | 无 Authorization 头访问 | 返回 401 |
| 令牌验证 | 使用无效令牌访问 | 返回 401 |
| 令牌过期 | 使用过期令牌访问 | 返回 401 |
| 权限验证 | 低权限访问高权限资源 | 返回 403 |
| 速率限制 | 高频请求 | 返回 429 |
| CORS 配置 | 跨域请求测试 | 限制允许的源 |
| 错误处理 | 触发错误 | 不泄露敏感信息 |
| 输入验证 | 注入测试 Payload | 拒绝非法输入 |

## 3.2 API 认证测试工具

| **工具名称** | **用途** | **命令示例** |
| :--- | :--- | :--- |
| **Postman** | API 测试 | 手动发送请求 |
| **Burp Suite** | 拦截/修改请求 | 手动测试、Intruder |
| **jwt-tool** | JWT 攻击 | `python3 jwt_tool.py token` |
| **GraphQLmap** | GraphQL 测试 | `python3 graphqlmap.py` |
| **Kiterunner** | API 端点发现 | `kr scan target.com` |
| **Arjun** | 参数发现 | `python3 arjun.py -u url` |

## 3.3 修复建议

1. **强制认证** - 所有端点默认需要认证
2. **令牌安全** - 使用强签名密钥，设置合理有效期
3. **速率限制** - 基于 IP、用户、端点实施限制
4. **输入验证** - 对所有输入进行严格验证
5. **错误处理** - 统一错误响应，不泄露敏感信息
6. **CORS 配置** - 限制允许的源和方法
7. **审计日志** - 记录所有 API 访问
8. **密钥轮换** - 定期轮换 API Key 和 JWT 密钥
9. **最小权限** - API Key 限制最小必要权限
10. **HTTPS 强制** - 所有 API 流量使用 HTTPS
