# 日志敏感信息检测 (Log Sensitive Data Detection)

---

## 第一部分：文档概述

### 1.1 编写目的
本文档旨在为渗透测试人员提供日志中敏感信息检测的系统化方法论，帮助测试人员发现日志中的敏感数据泄露风险。

### 1.2 适用范围
本文档适用于以下场景：
- Web 应用日志敏感信息检测
- API 日志数据泄露评估
- 认证系统日志隐私测试
- 合规性日志审计（GDPR、PCI DSS）

### 1.3 读者对象
- 渗透测试工程师
- 隐私合规分析师
- 安全审计人员
- 数据保护官（DPO）

---

## 第二部分：核心渗透技术专题

### 2.1 技术介绍

日志敏感信息检测是指识别和评估日志系统中记录的不当敏感数据，包括个人身份信息（PII）、凭证、金融数据等。

**核心原理：**
- **过度日志记录**：应用程序记录了不必要的敏感信息
- **未脱敏记录**：敏感数据未经脱敏直接记录
- **错误信息泄露**：错误消息中包含敏感数据
- **调试日志泄露**：调试级别日志包含详细敏感信息

### 2.2 检测常见于哪些业务场景

| **业务场景** | **功能示例** | **敏感信息类型** |
| :--- | :--- | :--- |
| **认证系统** | 登录、注册 | 密码、令牌 |
| **支付系统** | 订单处理 | 卡号、CVV |
| **用户管理** | 个人信息更新 | PII、联系方式 |
| **API 系统** | RESTful API | API 密钥、令牌 |
| **数据库操作** | 查询日志 | SQL 语句、数据 |
| **错误处理** | 异常页面 | 堆栈跟踪、配置 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**认证日志敏感信息检测：**
```bash
# 测试登录日志
curl -X POST "http://target/login" \
     -d "username=admin&password=SecretPass123!"

# 检查日志是否记录：
# - 明文密码
# - 密码哈希
# - 完整认证请求

# 测试密码重置
curl -X POST "http://target/password-reset" \
     -d "email=user@example.com&token=reset_token_123"

# 检查日志是否记录重置令牌
```

**API 日志敏感信息检测：**
```bash
# 测试 API 请求日志
curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
     "http://target/api/users/me"

# 检查日志是否记录：
# - 完整 JWT 令牌
# - 刷新令牌
# - API 密钥

# 测试支付 API
curl -X POST "http://target/api/payment" \
     -d '{"card":"4111111111111111","cvv":"123","exp":"12/25"}'

# 检查日志是否记录卡号
```

**错误信息敏感信息检测：**
```bash
# 触发错误
curl "http://target/api/user?id=' OR '1'='1"
curl "http://target/api/file?name=../../../etc/passwd"
curl "http://target/api/debug?dump=true"

# 检查错误响应和日志是否包含：
# - 数据库连接字符串
# - 文件路径
# - 配置信息
# - 堆栈跟踪
```

#### 2.3.2 白盒测试

**代码审计要点：**
```java
// 危险模式：记录完整请求
logger.info("Request: {}", request.toString());
// 可能包含：密码、令牌、Cookie

// 危险模式：记录认证信息
logger.info("Login: user=" + username + ", pass=" + password);

// 危险模式：记录支付信息
logger.info("Payment: card=" + cardNumber + ", cvv=" + cvv);

// 危险模式：记录数据库操作
logger.debug("Executing SQL: " + sqlQuery);
// 可能包含查询的敏感数据

// 正确模式：脱敏记录
logger.info("Login attempt for user: {}", sanitize(username));
logger.info("Payment processed for user: {}", userId);
```

**日志配置审计：**
```xml
<!-- logback-spring.xml 检查 -->
<configuration>
    <appender name="FILE" class="ch.qos.logback.core.FileAppender">
        <encoder>
            <!-- 危险：记录所有参数 -->
            <pattern>%d %p %c - %m%n</pattern>
        </encoder>
    </appender>
    
    <!-- 危险：生产环境 DEBUG 级别 -->
    <root level="DEBUG">
        <appender-ref ref="FILE"/>
    </root>
</configuration>
```

### 2.4 漏洞利用方法

#### 2.4.1 凭证窃取

```bash
# 如果日志包含密码
grep -i "password" /var/log/application.log
grep -i "passwd" /var/log/application.log

# 提取凭证
grep -oP "password[\"']?\s*[:=]\s*[\"']?\K[^\s,\"']+" /var/log/app.log

# 提取令牌
grep -oP "Bearer \K[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+" /var/log/app.log
grep -oP "api[_-]?key[\"']?\s*[:=]\s*[\"']?\K[A-Za-z0-9]+" /var/log/app.log
```

#### 2.4.2 PII 提取

```bash
# 提取邮箱地址
grep -oP "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" /var/log/app.log

# 提取电话号码
grep -oP "\d{3}[-.]?\d{3}[-.]?\d{4}" /var/log/app.log

# 提取身份证号（中国）
grep -oP "\d{17}[\dXx]" /var/log/app.log

# 提取银行卡号
grep -oP "\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}" /var/log/app.log
```

#### 2.4.3 敏感数据关联

```bash
# 关联用户和敏感操作
grep "user_id" /var/log/app.log | grep "payment"

# 重建用户行为画像
grep "session_id=abc123" /var/log/app.log

# 提取完整会话
grep "session_id=abc123" /var/log/app.log | sort -k1,2
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过日志脱敏

```bash
# 如果系统脱敏特定字段
# 尝试变体字段名

# 原始（被脱敏）
{"password": "secret"}

# 绕过
{"pass_word": "secret"}
{"passwd": "secret"}
{"pwd": "secret"}
{"user_password": "secret"}
```

#### 2.5.2 利用调试端点

```bash
# 访问调试端点获取敏感日志
curl "http://target/actuator/loggers"
curl "http://target/debug/requests"
curl "http://target/api/dump"

# 提升日志级别获取更多信息
curl -X POST "http://target/actuator/loggers/com.app" \
     -d '{"configuredLevel":"DEBUG"}'
```

---

## 第三部分：附录

### 3.1 日志敏感信息检测清单

| **信息类型** | **检测模式** | **风险等级** | **状态** |
| :--- | :--- | :--- | :--- |
| 密码 | `password[\"']?\s*[:=]` | 高 | ☐ |
| API 密钥 | `api[_-]?key[\"']?\s*[:=]` | 高 | ☐ |
| JWT 令牌 | `eyJ[A-Za-z0-9_-]+\.eyJ` | 高 | ☐ |
| 银行卡号 | `\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}` | 高 | ☐ |
| 邮箱地址 | `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+` | 中 | ☐ |
| 电话号码 | `\d{3}[-.]?\d{3}[-.]?\d{4}` | 中 | ☐ |
| 身份证号 | `\d{17}[\dXx]` | 高 | ☐ |
| IP 地址 | `\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}` | 低 | ☐ |

### 3.2 日志脱敏建议

```java
// 实现日志脱敏工具类
public class LogSanitizer {
    
    // 脱敏邮箱
    public static String sanitizeEmail(String email) {
        if (email == null || !email.contains("@")) return email;
        String[] parts = email.split("@");
        return parts[0].charAt(0) + "***@" + parts[1];
    }
    
    // 脱敏手机号
    public static String sanitizePhone(String phone) {
        if (phone == null || phone.length() < 7) return phone;
        return phone.substring(0, 3) + "****" + phone.substring(phone.length() - 4);
    }
    
    // 脱敏卡号
    public static String sanitizeCardNumber(String card) {
        if (card == null || card.length() < 8) return card;
        return "****-****-****-" + card.substring(card.length() - 4);
    }
    
    // 脱敏密码
    public static String sanitizePassword(String password) {
        return password == null ? "null" : "***REDACTED***";
    }
}
```

### 3.3 参考资源

- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Application_Logging_Cheat_Sheet.html)
- [GDPR Logging Requirements](https://gdpr.eu/logging/)
- [PCI DSS Requirement 3 - Protect Stored Data](https://docs-prv.pcisecuritystandards.org/PCI%20DSS/Standard/PCI-DSS-v4_0.pdf)
- [NIST 800-92 Guide to Computer Security Log Management](https://csrc.nist.gov/publications/detail/sp/800-92/final)
