# 错误信息泄露利用方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的错误信息泄露检测和利用流程。

## 1.2 适用范围

本文档适用于所有可能返回详细错误信息的 Web 应用、API 接口和服务。

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

错误信息泄露是指应用程序在发生错误时，向用户返回过于详细的错误信息，包括堆栈跟踪、SQL 查询、文件路径等敏感信息。

**本质问题**：
- 生产环境开启调试模式
- 错误处理不当
- 缺少统一错误页面

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-209 | 错误消息泄露敏感信息 |
| CWE-215 | 通过调试信息的敏感信息泄露 |

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 触发方式 | 泄露信息 |
|---------|---------|---------|
| SQL 查询 | 注入特殊字符 | SQL 语句、表结构 |
| 文件操作 | 路径遍历 | 文件路径、存在性 |
| API 调用 | 无效参数 | API 结构、版本 |
| 认证失败 | 错误凭证 | 用户存在性 |
| 系统异常 | 触发异常 | 堆栈跟踪、代码路径 |

## 2.3 漏洞发现方法

### 2.3.1 错误触发测试

```bash
# SQL 错误触发
GET /api/user?id='
GET /api/user?id=1' OR '1'='1

# 文件操作错误
GET /api/file?path=../../../nonexistent

# API 参数错误
GET /api/data?invalid_param=test
POST /api/data {"wrong_type": 123}

# 认证错误
POST /login {"username": "nonexistent", "password": "wrong"}
```

### 2.3.2 错误信息分析

```
检查响应中是否包含：
□ SQL 查询语句
□ 数据库版本/类型
□ 表名/列名
□ 文件路径
□ 堆栈跟踪
□ 代码行号
□ 内部 IP 地址
□ 第三方组件版本
```

### 2.3.3 调试模式检测

```bash
# 常见调试信息特征
# Django
DoesNotExist: User matching query does not exist.

# Laravel
MethodNotAllowedHttpException

# Spring Boot
Whitelabel Error Page

# ASP.NET
Server Error in '/' Application

# 调试工具栏
# Django Debug Toolbar
# Laravel Debugbar
```

## 2.4 漏洞利用方法

### 2.4.1 SQL 侦察

```bash
# 利用错误信息进行 SQL 注入侦察

# MySQL 错误
You have an error in your SQL syntax... 
near ''1'' at line 1

# 分析：
# - 确认使用单引号
# - 确认查询结构
# - 构造进一步 Payload

# PostgreSQL 错误
ERROR: syntax error at or near "'"

# MSSQL 错误
Unclosed quotation mark after the character string
```

### 2.4.2 路径信息利用

```bash
# 从错误中获取文件路径
Error: Cannot open file: /var/www/html/config/database.php

# 利用：
# - 了解系统结构
# - 构造路径遍历 Payload
# - 定位敏感文件
```

### 2.4.3 堆栈跟踪分析

```
从堆栈跟踪中获取：
1. 应用框架和版本
2. 代码执行路径
3. 使用的库和版本
4. 潜在的攻击面

示例：
at com.example.UserController.getUser(UserController.java:45)
at org.springframework.web.servlet.FrameworkServlet...
```

### 2.4.4 组件版本指纹

```
从错误信息中识别：
- Web 服务器版本（Apache/Nginx）
- 应用服务器版本（Tomcat/JBoss）
- 框架版本（Django/Spring）
- 数据库版本（MySQL/PostgreSQL）

然后搜索对应版本的已知漏洞
```

## 2.5 漏洞利用绕过方法

### 2.5.1 自定义错误页面绕过

```bash
# 某些应用有自定义错误页面
# 但可能只在特定条件下触发

# 尝试：
# - 不同 HTTP 方法
# - 不同 Content-Type
# - 不同 Accept 头
# - 特殊字符组合
```

### 2.5.2 部分错误泄露

```bash
# 即使有错误处理
# 某些错误可能仍然泄露信息

# 尝试：
# - 深层嵌套请求
# - 并发请求
# - 超大 Payload
# - 超时请求
```

### 2.5.3 侧信道信息泄露

```bash
# 即使错误消息被隐藏
# 响应特征仍可能泄露信息

# 分析：
# - 响应长度差异
# - 响应时间差异
# - 状态码差异
```

---

# 第三部分：附录

## 3.1 错误信息泄露测试检查清单

```
□ 测试 SQL 错误
□ 测试文件操作错误
□ 测试认证错误
□ 测试 API 参数错误
□ 测试系统异常
□ 检查调试模式
□ 检查堆栈跟踪
□ 检查响应差异
```

## 3.2 常用触发 Payload

| 类型 | Payload | 说明 |
|-----|---------|------|
| SQL | `' " \` | 引号测试 |
| 路径 | `../../../` | 路径遍历 |
| 类型 | `{"a": null}` | 类型错误 |
| 大小 | 超大字符串 | 缓冲区测试 |

## 3.3 修复建议

1. **统一错误处理** - 使用统一的错误处理机制
2. **自定义错误页面** - 返回通用错误消息
3. **关闭调试模式** - 生产环境禁用调试
4. **日志记录** - 详细错误记录到日志而非返回给用户

## 3.4 相关 CWE 参考

| CWE 编号 | 名称 | 关联说明 |
|---------|------|---------|
| CWE-209 | Generation of Error Message Containing Sensitive Information | 生成包含敏感信息的错误消息 |
| CWE-215 | Insertion of Sensitive Information Into Debugging Code | 将敏感信息插入调试代码 |
| CWE-550 | Server-generated Error Message Containing Sensitive Information | 服务器生成的错误消息包含敏感信息 |
| CWE-756 | Missing Custom Error Page | 缺少自定义错误页面 |

---

**参考资源**：
- [OWASP Cheat Sheet: Error Handling](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html)
- [CWE-209](https://cwe.mitre.org/data/definitions/209.html)
- [OWASP Top 10:2025 A10](https://owasp.org/Top10/2025/A10_2025-Mishandling_of_Exceptional_Conditions/)
