# **渗透测试方法论：OAuth 认证测试**

---

# **第一部分：文档概述**

## 1.1 编写目的
- 为渗透测试人员提供一套标准化的 OAuth 2.0/OIDC 认证安全测试流程
- 帮助测试人员系统性地发现 OAuth 实现中的安全缺陷
- 提高 OAuth 认证漏洞发现的准确率和效率

## 1.2 适用范围
- 适用于使用 OAuth 2.0、OpenID Connect 的认证系统
- 适用于第三方应用授权场景
- 适用于社交登录（微信、QQ、Google、Facebook 等）集成

## 1.3 读者对象
- 本文件主要面向执行渗透测试任务的安全工程师、安全分析师
- 负责 OAuth 集成的开发人员
- 负责代码审计和安全加固的技术人员

---

# **第二部分：核心渗透技术专题**

## 专题一：OAuth 认证测试

### 2.1 技术介绍

OAuth 认证测试是指对 OAuth 2.0/OpenID Connect 授权流程进行全面的安全评估。其本质是**验证 OAuth 实现能否安全地处理授权流程，防止令牌泄露、未授权访问和权限提升**。

OAuth 2.0 核心概念：

| **概念** | **描述** | **安全风险** |
| :--- | :--- | :--- |
| 授权码 (Authorization Code) | 临时凭证，用于换取令牌 | 劫持、重放 |
| 访问令牌 (Access Token) | 访问资源的凭证 | 泄露、滥用 |
| 刷新令牌 (Refresh Token) | 用于获取新访问令牌 | 长期有效、泄露 |
| 重定向 URI | 回调地址 | 劫持、开放重定向 |
| 范围 (Scope) | 权限范围 | 过度授权、提升 |

### 2.2 测试常见于哪些业务场景

| **业务场景** | **功能示例** | **风险点描述** |
| :--- | :--- | :--- |
| **社交登录** | 微信/QQ/Google 登录 | 重定向劫持、令牌泄露 |
| **第三方授权** | 授权应用访问数据 | 过度授权、权限滥用 |
| **API 访问** | OAuth 保护的 API | 令牌验证不当 |
| **移动应用 OAuth** | App 内 OAuth 流程 | Scheme 劫持、PKCE 缺失 |
| **服务端 OAuth** | 服务器间授权 | 客户端凭证泄露 |
| **设备授权** | 智能设备授权 | 用户码泄露、劫持 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

- **授权流程测试**
  - 测试重定向 URI 篡改
  - 测试 state 参数 CSRF 保护
  - 测试授权码有效期和重用
  - 测试隐式流令牌泄露
  - 测试 PKCE 实施（移动应用）

- **令牌测试**
  - 测试访问令牌有效期
  - 测试刷新令牌轮换
  - 测试令牌撤销机制
  - 测试令牌范围限制
  - 测试令牌绑定（DPoP/MTLS）

- **客户端测试**
  - 测试客户端 ID 枚举
  - 测试客户端密钥保护
  - 测试注册客户端验证
  - 测试动态客户端注册

#### 2.3.2 白盒测试

- **代码审计**
  - 检查授权码验证逻辑
  - 审计重定向 URI 验证
  - 检查令牌生成和验证
  - 查找硬编码客户端凭证

- **配置检查**
  - 检查授权服务器配置
  - 审计客户端注册配置
  - 检查令牌有效期设置
  - 检查范围配置

### 2.4 漏洞利用方法

#### 2.4.1 基础信息收集

```bash
# 发现 OAuth 端点
curl https://example.com/.well-known/oauth-authorization-server
curl https://example.com/.well-known/openid-configuration

# 获取支持的授权类型
curl https://authorization-server.com/.well-known/oauth-authorization-server
# 查看 response_types_supported, grant_types_supported

# 客户端注册信息枚举
curl -X POST https://example.com/oauth/register \
  -d '{"client_name": "test"}'
```

#### 2.4.2 授权码劫持

```
# 正常授权请求
GET https://auth.example.com/authorize?
  client_id=app123&
  redirect_uri=https://app.example.com/callback&
  response_type=code&
  state=xyz123

# 攻击：篡改重定向 URI
GET https://auth.example.com/authorize?
  client_id=app123&
  redirect_uri=https://attacker.com/steal&
  response_type=code&
  state=xyz123
```

#### 2.4.3 CSRF 攻击（State 参数绕过）

```
# 攻击者构造的授权请求
GET https://auth.example.com/authorize?
  client_id=app123&
  redirect_uri=https://app.example.com/callback&
  response_type=code&
  # 缺少或固定 state 参数
```

#### 2.4.4 权限提升

| **操作** | **方法** | **目的** |
| :--- | :--- | :--- |
| 范围篡改 | 修改 scope 参数 | 获取额外权限 |
| 隐式授权 | 诱导用户授权 | 获取访问令牌 |
| 令牌替换 | 替换令牌中的 claims | 权限提升 |
| 客户端冒充 | 使用其他客户端 ID | 未授权访问 |

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过重定向 URI 验证

- **子域名绕过** - `https://attacker.example.com`
- **路径绕过** - `https://example.com/attacker/callback`
- **参数绕过** - `https://example.com/callback?next=attacker`
- **URL 解析差异** - 利用不同解析器的差异

#### 2.5.2 绕过 State 验证

- **State 预测** - 如果 state 可预测
- **State 固定** - 如果未验证 state
- **多 state 注入** - 发送多个 state 参数

#### 2.5.3 绕过 PKCE

- **PKCE 降级** - 如果未强制 PKCE
- **Code Verifier 预测** - 如果生成不当
- **重放攻击** - 如果未绑定授权码

---

# **第三部分：附录**

## 3.1 OAuth 测试检查清单

| **检查项** | **测试方法** | **预期结果** |
| :--- | :--- | :--- |
| 重定向 URI 验证 | 篡改 redirect_uri | 应拒绝非法 URI |
| State 参数 | 缺少/篡改 state | 应拒绝请求 |
| 授权码有效期 | 延迟使用授权码 | 应拒绝过期码 |
| 授权码重用 | 重复使用授权码 | 应拒绝重用 |
| PKCE 实施 | 移动应用测试 | 应强制 PKCE |
| 令牌有效期 | 使用过期令牌 | 应拒绝访问 |
| 令牌撤销 | 撤销后使用令牌 | 应拒绝访问 |
| 范围限制 | 访问范围外资源 | 应拒绝访问 |

## 3.2 OAuth 测试工具

| **工具名称** | **用途** | **命令示例** |
| :--- | :--- | :--- |
| **Burp Suite** | 拦截/修改请求 | 手动测试 OAuth 流程 |
| **OAuth Tester** | Burp 扩展 | 自动化 OAuth 测试 |
| **Postman** | API 测试 | 测试 OAuth 端点 |
| **jwt.io** | JWT 分析 | 分析 ID Token |
| **curl** | 手动请求 | 发送 OAuth 请求 |

## 3.3 修复建议

1. **重定向 URI 白名单** - 使用精确匹配的白名单
2. **State 参数** - 始终使用并验证 state 参数
3. **PKCE** - 移动应用强制使用 PKCE
4. **授权码短期有效** - 设置短的过期时间（如 10 分钟）
5. **授权码一次性** - 授权码使用后失效
6. **刷新令牌轮换** - 每次使用颁发新刷新令牌
7. **令牌撤销** - 实现令牌撤销机制
8. **最小范围** - 默认授予最小必要范围
9. **客户端认证** - 保护客户端密钥
10. **HTTPS 强制** - 所有 OAuth 流量使用 HTTPS
