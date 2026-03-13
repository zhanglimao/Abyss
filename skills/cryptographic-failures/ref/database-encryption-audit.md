# 数据库加密审计

---

## 第一部分：文档概述

### 1.1 编写目的
本文档旨在为渗透测试人员提供数据库加密配置审计的方法论。通过本指南，测试人员可以评估各类数据库的加密实现，发现静态数据加密、传输加密、密钥管理等方面的安全缺陷。

### 1.2 适用范围
本文档适用于以下场景：
- 关系型数据库（MySQL、PostgreSQL、Oracle、SQL Server）
- NoSQL 数据库（MongoDB、Redis、Cassandra）
- 云数据库（RDS、Cosmos DB、Cloud SQL）
- 数据仓库（Snowflake、Redshift）

### 1.3 读者对象
- 数据库安全审计人员
- 渗透测试工程师
- 数据安全合规人员
- DBA 安全管理人员

---

## 第二部分：核心渗透技术专题

### 专题一：数据库加密审计

#### 2.1 技术介绍

**数据库加密审计**是对数据库加密配置的全面评估，包括静态数据加密（TDE）、传输加密、列级加密、密钥管理等方面。

**数据库加密维度：**

| 维度 | 检测内容 | 风险等级 |
|------|---------|---------|
| 静态加密 | TDE、列加密、文件加密 | 高危 |
| 传输加密 | SSL/TLS 配置 | 高危 |
| 密钥管理 | 密钥存储、轮换 | 严重 |
| 备份加密 | 备份文件加密 | 高危 |
| 访问控制 | 加密密钥访问权限 | 严重 |
| 审计日志 | 加密操作日志 | 中危 |

#### 2.2 审计常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 金融系统 | 账户、交易数据 | 敏感金融数据需加密存储 |
| 医疗系统 | 患者记录、病历 | HIPAA 合规要求 |
| 电商系统 | 用户信息、订单 | 个人隐私保护 |
| 支付系统 | 卡号、CVV | PCI DSS 合规要求 |
| 政府系统 | 公民数据 | 数据保护法规要求 |

#### 2.3 漏洞检测方法

##### 2.3.1 MySQL 加密检测

```sql
-- 检查是否启用 SSL
SHOW VARIABLES LIKE '%ssl%';

-- 检查用户 SSL 要求
SELECT user, host, ssl_type, ssl_cipher FROM mysql.user;

-- 检查表空间加密（MySQL 8.0+）
SELECT TABLE_NAME, TABLESPACE_NAME, ENCRYPTION 
FROM information_schema.TABLES 
WHERE ENCRYPTION = 'Y';

-- 检查 InnoDB 表空间加密
SELECT * FROM information_schema.INNODB_TABLESPACES_ENCRYPTION;
```

```bash
# 检查配置文件中的加密设置
cat /etc/mysql/my.cnf | grep -i ssl

# 检查数据文件是否加密
file /var/lib/mysql/*.ibd
# 加密文件应显示为数据
```

##### 2.3.2 PostgreSQL 加密检测

```sql
-- 检查 SSL 配置
SHOW ssl;

-- 查看 SSL 连接统计
SELECT * FROM pg_stat_ssl;

-- 检查 pgcrypto 扩展（用于列加密）
SELECT * FROM pg_extension WHERE extname = 'pgcrypto';

-- 检查加密的列（需要手动识别）
-- 查找可能的加密函数使用
SELECT proname FROM pg_proc 
WHERE proname LIKE '%encrypt%' OR proname LIKE '%crypt%';
```

```bash
# 检查 postgresql.conf
cat $PGDATA/postgresql.conf | grep -i ssl

# 检查 pg_hba.conf 中的 SSL 要求
cat $PGDATA/pg_hba.conf | grep -i ssl
```

##### 2.3.3 SQL Server 加密检测

```sql
-- 检查 TDE 状态
SELECT 
    db_name(database_id) as DatabaseName,
    case encryption_state 
        when 0 then 'No encryption'
        when 1 then 'Unencrypted'
        when 2 then 'Encryption in progress'
        when 3 then 'Encrypted'
        when 4 then 'Key change in progress'
        when 5 then 'Decryption in progress'
        when 6 then 'Protection change in progress'
    end as EncryptionState
FROM sys.dm_database_encryption_keys;

-- 检查 SSL/TLS 配置
EXEC master.sys.sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC master.sys.sp_configure 'force encryption', 0;

-- 检查证书
SELECT name, expiry_date FROM sys.certificates;
```

##### 2.3.4 Oracle 加密检测

```sql
-- 检查 TDE 状态
SELECT * FROM V$ENCRYPTION_WALLET;

-- 检查加密的表空间
SELECT TABLESPACE_NAME, ENCRYPTED FROM DBA_TABLESPACES;

-- 检查加密列
SELECT OWNER, TABLE_NAME, COLUMN_NAME, ENCRYPTION_ALG 
FROM DBA_ENCRYPTED_COLUMNS;

-- 检查网络加密
SELECT * FROM V$SQL_NETWORK;
```

##### 2.3.5 MongoDB 加密检测

```javascript
// 检查 SSL 配置
db.adminCommand({getParameter: 1, featureFlagRequireSSL: 1})

// 检查审计日志（Enterprise 版）
db.adminCommand({getParameter: 1, auditAuthorizer: 1})

// 检查加密状态（需要管理员权限）
use admin
db.runCommand({serverStatus: 1}).security
```

```bash
# 检查 MongoDB 配置文件
cat /etc/mongod.conf | grep -i ssl

# 检查数据文件
ls -la /var/lib/mongodb/
# WiredTiger 支持加密，检查配置
```

##### 2.3.6 Redis 加密检测

```bash
# 检查 Redis 配置
redis-cli CONFIG GET requirepass
redis-cli CONFIG GET tls-port
redis-cli CONFIG GET tls-cert-file

# 检查是否启用 TLS
redis-cli -h target --tls PING

# 检查 Redis 6.0+ ACL
redis-cli ACL LIST
```

#### 2.4 漏洞利用方法

##### 2.4.1 未加密数据文件提取

```bash
# MySQL 数据文件提取（如果未加密）
cp /var/lib/mysql/target_db/*.ibd ./dump/

# 使用 ibd2sql 工具提取数据
ibd2sql dump/table.ibd > data.sql

# PostgreSQL 数据文件
cp $PGDATA/base/*/target_table ./dump/

# MongoDB 数据文件
cp /var/lib/mongodb/WiredTiger/* ./dump/
```

##### 2.4.2 传输层攻击

```bash
# 检测是否强制 SSL 连接
# MySQL
mysql -h target -u user -p --ssl-mode=DISABLED
# 如果连接成功，说明未强制 SSL

# PostgreSQL
psql -h target -U user -d database sslmode=disable
# 如果连接成功，说明未强制 SSL

# 中间人攻击（如果未启用 SSL）
# 使用 BetterCAP 或 mitmproxy 拦截数据库流量
```

##### 2.4.3 备份文件攻击

```bash
# 提取未加密的备份文件
# MySQL dump
mysqldump -h target -u user -p database > backup.sql

# 如果备份文件未加密，包含完整数据
# 搜索敏感数据
grep -iE "password|email|phone" backup.sql

# PostgreSQL dump
pg_dump -h target -U user database > backup.sql

# MongoDB dump
mongodump --host target --out ./dump/
```

##### 2.4.4 密钥提取攻击

```sql
-- SQL Server TDE 密钥提取（需要 sysadmin）
-- 导出证书
BACKUP CERTIFICATE TDE_Cert 
TO FILE = 'C:\cert.cer'
WITH PRIVATE KEY (
    FILE = 'C:\cert.key',
    ENCRYPTION BY PASSWORD = 'password',
    DECRYPTION BY PASSWORD = 'password'
);
```

```bash
# MySQL 密钥文件检查
cat /etc/mysql/keyring_file 2>/dev/null

# Oracle 钱包检查
ls -la $ORACLE_HOME/dbs/ewallet.p12
```

#### 2.5 安全配置建议

##### 2.5.1 MySQL 加密配置

```sql
-- 启用 SSL
ALTER USER 'user'@'%' REQUIRE SSL;

-- 启用表空间加密（MySQL 8.0+）
ALTER TABLE sensitive_table ENCRYPTION = 'Y';

-- 配置密钥环插件
-- my.cnf
[mysqld]
early-plugin-load=keyring_file.so
keyring_file_data=/var/lib/mysql-keyring/keyring
```

##### 2.5.2 PostgreSQL 加密配置

```conf
# postgresql.conf
ssl = on
ssl_cert_file = 'server.crt'
ssl_key_file = 'server.key'
ssl_min_protocol_version = 'TLSv1.2'

# pg_hba.conf
hostssl all all all cert
hostssl all all all scram-sha-256
```

```sql
-- 使用 pgcrypto 进行列加密
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- 加密存储
INSERT INTO users (email, encrypted_ssn) 
VALUES ('user@example.com', pgp_sym_encrypt('123-45-6789', 'encryption_key'));

-- 解密读取
SELECT pgp_sym_decrypt(encrypted_ssn, 'encryption_key') FROM users;
```

##### 2.5.3 SQL Server TDE 配置

```sql
-- 创建主密钥
USE master;
CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'StrongPassword123!';

-- 创建证书
CREATE CERTIFICATE TDE_Certificate WITH SUBJECT = 'TDE Certificate';

-- 创建数据库加密密钥
USE TargetDB;
CREATE DATABASE ENCRYPTION KEY
WITH ALGORITHM = AES_256
ENCRYPTION BY SERVER CERTIFICATE TDE_Certificate;

-- 启用加密
ALTER DATABASE TargetDB SET ENCRYPTION ON;

-- 强制 SSL 连接
EXEC master.sys.sp_configure 'force encryption', 1;
RECONFIGURE;
```

##### 2.5.4 数据库加密检查清单

**通用检查:**
- [ ] 静态数据加密（TDE 或列加密）
- [ ] 传输加密（SSL/TLS）
- [ ] 备份文件加密
- [ ] 密钥安全存储
- [ ] 密钥定期轮换
- [ ] 最小权限访问密钥
- [ ] 加密操作审计日志

**MySQL:**
- [ ] SSL 强制启用
- [ ] 敏感表空间加密
- [ ] 密钥环插件配置
- [ ] binlog 加密

**PostgreSQL:**
- [ ] ssl = on
- [ ] pg_hba.conf 配置 SSL
- [ ] pgcrypto 用于列加密
- [ ] 密码使用 scram-sha-256

**SQL Server:**
- [ ] TDE 启用
- [ ] 证书备份
- [ ] Always Encrypted 用于列
- [ ] 强制加密连接

**MongoDB:**
- [ ] TLS/SSL 启用
- [ ] WiredTiger 加密（Enterprise）
- [ ] 审计日志启用
- [ ] 客户端字段级加密

---

## 第三部分：附录

### 3.1 数据库加密工具

| 工具 | 用途 |
|-----|------|
| sqlmap | SQL 注入和数据库检测 |
| DbScan | 数据库安全扫描 |
| TDE 检测脚本 | 各数据库 TDE 状态检测 |
| IBD2SQL | MySQL InnoDB 文件解析 |

### 3.2 合规性要求

| 标准 | 数据库加密要求 |
|------|---------------|
| PCI DSS | 卡号数据加密存储 |
| HIPAA | PHI 数据加密 |
| GDPR | 个人数据保护 |
| 等保 2.0 | 重要数据加密 |

### 3.3 加密算法推荐

| 用途 | 推荐算法 |
|-----|---------|
| 对称加密 | AES-256-GCM |
| 非对称加密 | RSA-3072+, ECDSA P-256 |
| 哈希 | SHA-256, SHA-3 |
| 密钥派生 | PBKDF2, Argon2 |

---

## 参考资源

- [OWASP Database Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html)
- [CIS Database Benchmarks](https://www.cisecurity.org/benchmark/)
- [NIST SP 800-111 - Storage Encryption](https://csrc.nist.gov/publications/detail/sp/800-111/final)
