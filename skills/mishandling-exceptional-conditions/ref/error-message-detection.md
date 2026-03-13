# 错误信息检测方法论文档

---

# 第一部分：文档概述

## 1.1 编写目的

阐述错误信息检测的方法论，为测试人员提供一套标准化、可复现的错误信息泄露检测流程。帮助安全工程师发现应用程序返回的错误信息中可能泄露的敏感信息，为后续攻击提供情报。

## 1.2 适用范围

本文档适用于以下场景：
- 所有与用户交互的 Web 应用和 API 服务
- 存在数据库操作的应用系统
- 使用第三方组件和框架的应用
- 有详细错误日志记录的系统

## 1.3 读者对象

- 执行渗透测试任务的安全工程师
- 安全分析师
- 负责代码审计的开发人员

---

# 第二部分：核心渗透技术专题

## 专题一：错误信息检测

### 2.1 技术介绍

错误信息检测针对应用程序在异常情况下返回的错误信息进行安全分析，检测是否泄露：
- 技术栈信息（框架、语言、版本）
- 数据库结构（表名、字段名）
- 文件路径（绝对路径、目录结构）
- 业务逻辑（验证规则、流程）
- 敏感配置（连接字符串、API 密钥）

**漏洞本质：** 错误信息过于详细，将内部实现细节暴露给攻击者，降低攻击难度。

| 泄露类型 | 描述 | 风险等级 |
|---------|------|---------|
| 堆栈跟踪 | 完整的异常堆栈信息 | 高 |
| SQL 错误 | SQL 语法错误详情 | 高 |
| 路径泄露 | 服务器文件路径 | 中 |
| 版本信息 | 框架/库版本号 | 中 |
| 配置信息 | 连接字符串等 | 严重 |

### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 表单提交 | 登录、注册 | 验证错误泄露信息 |
| 数据查询 | 搜索、详情 | SQL 错误泄露结构 |
| 文件操作 | 上传、下载 | 路径信息泄露 |
| API 调用 | RESTful API | JSON 错误详情 |
| 后台管理 | 数据导入导出 | 详细错误报告 |
| 支付功能 | 支付回调 | 支付网关错误 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**错误信息探测技术：**

| 探测方法 | 操作说明 | 预期观察 |
|---------|---------|---------|
| SQL 注入探测 | 注入 SQL 特殊字符 | SQL 错误信息 |
| 路径遍历探测 | 注入路径字符 | 文件路径泄露 |
| 类型错误探测 | 传入错误数据类型 | 类型转换错误 |
| 空值探测 | 传入 null/空值 | 空指针错误 |
| 边界值探测 | 传入极值 | 溢出错误 |

**探测 Payload 示例：**

```http
# 1. SQL 错误探测
GET /api/user?id=1'
GET /api/user?id=1"
GET /api/user?id=1 OR 1=1--

# 预期响应：
# SQL Error: You have an error in your SQL syntax
# ORA-00933: SQL command not properly ended

# 2. 路径泄露探测
GET /api/file?path=../../../etc/passwd
GET /api/download?file=../web.config

# 预期响应：
# FileNotFoundError: /var/www/app/../../../etc/passwd
# Access to the path '/var/www/app/config' is denied

# 3. 类型错误探测
GET /api/user?id=abc
POST /api/transfer {"amount": "not_a_number"}

# 预期响应：
# TypeError: Cannot convert string to int
# NumberFormatException: For input string: "not_a_number"

# 4. 空值探测
GET /api/user?id=
POST /api/update {"name": null}

# 预期响应：
# NullPointerException at UserService.getUser(UserService.java:42)
# ArgumentNullException: Value cannot be null

# 5. 边界值探测
GET /api/items?limit=999999999999
POST /api/buy {"quantity": -1}

# 预期响应：
# OverflowException: Number overflow
# ValidationException: Quantity must be positive
```

#### 2.3.2 错误页面检测

**检测清单：**

```http
# 1. 访问不存在的页面
GET /nonexistent-page-12345

# 检测是否显示：
# - 服务器版本信息
# - 框架错误页面
# - 堆栈跟踪

# 2. 触发服务器错误
GET /api/error?action=throw_exception

# 检测是否显示：
# - 完整堆栈
# - 代码片段
# - 变量值

# 3. 检查自定义错误页面
# 即使有自定义错误页面，也可能泄露：
# - 错误类型
# - 错误代码
# - 部分堆栈信息
```

### 2.4 信息利用方法

#### 2.4.1 数据库结构侦察

**利用 SQL 错误信息：**
```
错误信息：
Unknown column 'username' in 'field list'

利用：
- 确认存在 username 字段
- 用于后续 SQL 注入攻击

错误信息：
Table 'users' doesn't exist

利用：
- 确认表名猜测
- 尝试其他表名
```

#### 2.4.2 路径信息利用

**利用路径泄露：**
```
错误信息：
FileNotFoundError: /var/www/html/app/uploads/../../../etc/passwd

利用：
- 确认 Web 根目录：/var/www/html/app
- 确认上传目录：uploads
- 用于后续文件包含攻击
```

#### 2.4.3 技术栈识别

**利用版本信息：**
```
错误信息：
Django Debug Page
Python 3.9.7
Django 3.2.5

利用：
- 查找对应版本的已知漏洞
- 使用针对性的攻击 payload
```

#### 2.4.4 业务逻辑推断

**利用验证错误：**
```
错误信息：
Validation failed:
- Password must be at least 8 characters
- Password must contain uppercase, lowercase, and number
- Email must be from company domain (@company.com)

利用：
- 了解密码策略
- 了解邮箱要求
- 构造更精确的暴力破解字典
```

### 2.5 绕过方法

#### 2.5.1 绕过错误过滤

**场景：** 系统过滤了部分错误信息

**绕过方法：**
```
1. 使用编码绕过
   URL 编码、HTML 实体编码、Unicode 编码

2. 使用特殊字符
   空字节、控制字符

3. 触发不同类型的错误
   如果 SQL 错误被过滤，尝试触发类型错误
```

#### 2.5.2 利用时间差

**场景：** 错误信息不直接显示在响应中

**绕过方法：**
```
1. 检查 HTTP 状态码
   500/502/503/504 都表示服务器错误

2. 检查响应时间
   错误处理可能更慢

3. 检查响应大小
   错误响应可能更大或更小
```

---

# 第三部分：附录

## 3.1 常见错误信息特征

| 技术栈 | 错误特征 | 泄露信息 |
|-------|---------|---------|
| MySQL | SQL syntax, MySQLSyntaxErrorException | SQL 结构 |
| Oracle | ORA-xxxxx | SQL 结构 |
| PostgreSQL | ERROR: syntax error at or near | SQL 结构 |
| SQL Server | SqlException, Unclosed quotation mark | SQL 结构 |
| Java | Exception at com.example.Class.method(Class.java:line) | 代码结构 |
| .NET | at System.Environment.GetStackTrace | 代码结构 |
| Python | Traceback (most recent call last) | 代码结构 |
| PHP | Fatal error in /path/to/file.php on line X | 路径、代码 |
| Django | Django Debug Page | 代码、配置 |
| Flask | Werkzeug Debugger | 代码、配置 |

## 3.2 错误信息检测清单

| 检查项 | 检测方法 | 风险等级 |
|-------|---------|---------|
| SQL 错误 | SQL 注入测试 | 高 |
| 堆栈跟踪 | 触发异常 | 高 |
| 路径泄露 | 路径遍历测试 | 中 |
| 版本信息 | 访问错误页面 | 中 |
| 配置信息 | 触发配置相关错误 | 严重 |
| 业务逻辑 | 输入验证测试 | 中 |

## 3.3 错误信息检测工具

| 工具 | 用途 | 命令示例 |
|-----|------|---------|
| Burp Suite | 请求拦截分析 | Repeater 模块 |
| SQLMap | SQL 注入检测 | `sqlmap -u "url" --batch` |
| OWASP ZAP | 漏洞扫描 | 主动扫描规则 |
| 自定义脚本 | 批量测试 | Python 编写 |

## 3.4 安全错误处理建议

```java
// 推荐做法

// 1. 使用全局异常处理器
@ControllerAdvice
public class GlobalExceptionHandler {
    
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleException(Exception e) {
        // 记录详细错误（服务器端）
        logger.error("Unexpected error", e);
        
        // 返回通用错误信息（客户端）
        ErrorResponse error = new ErrorResponse(
            "INTERNAL_ERROR",
            "An unexpected error occurred"
        );
        return ResponseEntity.status(500).body(error);
    }
}

// 2. 配置自定义错误页面
// Spring Boot: application.properties
server.error.whitelabel.enabled=false
server.error.path=/error

// 3. 生产环境关闭调试模式
# Django: settings.py
DEBUG = False

# Flask
app.run(debug=False)

# 4. 统一的错误响应格式
{
    "error": {
        "code": "INTERNAL_ERROR",
        "message": "An unexpected error occurred",
        "request_id": "abc123"  // 用于日志追踪
    }
}
```
