# 日志信息泄露利用方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的日志信息泄露检测和利用流程。

## 1.2 适用范围

本文档适用于所有记录日志的 Web 应用和系统。

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

日志信息泄露是指应用程序在日志中记录了敏感信息，攻击者通过访问日志文件获取这些敏感数据。

**本质问题**：
- 日志记录过多敏感信息
- 日志文件访问控制不足
- 日志未脱敏处理

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-532 | 敏感信息写入日志 |
| CWE-200 | 敏感信息暴露 |
| CWE-538 | 文件和目录信息暴露 |

## 2.2 攻击常见于哪些业务场景

| 场景 | 泄露信息 | 潜在危害 |
|-----|---------|---------|
| 错误日志 | SQL 语句、堆栈跟踪 | 了解系统架构 |
| 访问日志 | URL（含 Token） | 会话劫持 |
| 调试日志 | 请求/响应全文 | 数据泄露 |
| 审计日志 | 用户操作详情 | 隐私泄露 |
| 数据库日志 | 查询内容 | 数据结构泄露 |

## 2.3 漏洞发现方法

### 2.3.1 日志文件位置探测

```bash
# 常见日志文件路径
/var/log/apache2/access.log
/var/log/nginx/access.log
/var/log/application/app.log
/logs/error.log
C:\inetpub\logs\LogFiles\

# 尝试访问
curl https://target.com/logs/access.log
curl https://target.com/app.log
```

### 2.3.2 触发错误记录

```bash
# 发送会导致错误的请求
curl https://target.com/api?id='
curl https://target.com/api?file=../../../etc/passwd

# 然后检查日志文件
# 查看是否记录了敏感信息
```

### 2.3.3 日志内容分析

```
检查日志中是否包含：
□ SQL 查询语句（含凭证）
□ 完整 URL（含 Token/Session）
□ 请求/响应正文
□ 用户密码
□ 信用卡号
□ 个人身份信息
□ API 密钥
□ 内部 IP 地址
```

## 2.4 漏洞利用方法

### 2.4.1 SQL 凭证窃取

```bash
# 如果日志记录了 SQL 查询
# 可能包含数据库凭证

# 示例日志内容：
# [ERROR] Connection failed: mysql://root:password123@db.internal:3306/app

# 使用窃取的凭证连接数据库
mysql -h db.internal -u root -p'password123'
```

### 2.4.2 会话 Token 窃取

```bash
# 如果日志记录了完整 URL
# 可能包含 Session Token

# 示例日志内容：
# GET /api/user?session=abc123xyz HTTP/1.1

# 使用窃取的 Token
curl -H "Authorization: Bearer abc123xyz" \
    https://target.com/api/user
```

### 2.4.3 用户数据收集

```bash
# 日志可能记录用户操作
# 包含用户输入的数据

# 示例日志内容：
# [INFO] User john@example.com updated password to: newpass123

# 收集的信息可用于：
# - 账户接管
# - 社会工程学攻击
# - 凭证填充
```

### 2.4.4 系统架构侦察

```bash
# 从日志中收集：
# - 内部 IP 地址
# - 服务器名称
# - 数据库类型和版本
# - 使用的框架和库
# - API 端点列表

# 用于规划进一步攻击
```

## 2.5 漏洞利用绕过方法

### 2.5.1 访问控制绕过

```bash
# 如果日志文件有访问限制
# 尝试：
# - 路径遍历
# - URL 编码绕过
# - HTTP 方法绕过
```

### 2.5.2 日志轮转利用

```bash
# 访问旧的日志文件
# 可能防护较弱

/logs/access.log.1
/logs/access.log.old
/logs/access-2024-01.log
```

### 2.5.3 部分信息利用

```bash
# 即使敏感信息被部分脱敏
# 仍可能有用

# 例如：
# credit_card: 4111-****-****-1234
# 可以推断发卡行和卡类型
```

---

# 第三部分：附录

## 3.1 日志信息泄露测试检查清单

```
□ 探测日志文件位置
□ 尝试直接访问日志
□ 触发错误记录
□ 分析日志内容
□ 查找敏感信息
□ 测试访问控制绕过
□ 检查日志轮转文件
```

## 3.2 常见敏感信息模式

| 信息类型 | 正则模式 |
|---------|---------|
| 邮箱 | `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}` |
| 信用卡 | `\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b` |
| SSN | `\b\d{3}-\d{2}-\d{4}\b` |
| API 密钥 | `[a-zA-Z0-9]{32,}` |
| JWT | `eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*` |

## 3.3 修复建议

1. **最小化记录** - 仅记录必要信息
2. **脱敏处理** - 敏感数据脱敏后记录
3. **访问控制** - 限制日志文件访问
4. **日志轮转** - 定期清理旧日志
5. **加密存储** - 加密日志文件

---

**参考资源**：
- [OWASP Cheat Sheet: Application Logging](https://cheatsheetseries.owasp.org/cheatsheets/Application_Logging_Cheat_Sheet.html)
- [CWE-532](https://cwe.mitre.org/data/definitions/532.html)
