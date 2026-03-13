# 云加密配置审计

---

## 第一部分：文档概述

### 1.1 编写目的
本文档旨在为渗透测试人员提供云环境加密配置审计的方法论。通过本指南，测试人员可以评估 AWS、Azure、GCP 等云平台的加密配置，发现密钥管理、数据存储、传输加密等方面的安全缺陷。

### 1.2 适用范围
本文档适用于以下场景：
- AWS/Azure/GCP 云环境加密审计
- 云存储（S3、Blob、GCS）加密检测
- 云数据库加密配置评估
- 云 KMS（密钥管理服务）配置审计
- 多云环境加密策略评估

### 1.3 读者对象
- 云安全测试人员
- 渗透测试工程师
- 云合规性审计人员
- DevSecOps 工程师

---

## 第二部分：核心渗透技术专题

### 专题一：云加密配置审计

#### 2.1 技术介绍

**云加密配置审计**是对云环境中的加密实现进行全面评估的过程，包括静态数据加密、传输中数据加密、密钥管理和访问控制等方面。

**云加密核心领域：**

| 领域 | 检测内容 | 风险等级 |
|------|---------|---------|
| 存储加密 | S3/Blob/GCS 加密配置 | 高危 |
| 数据库加密 | RDS/Cosmos DB/Cloud SQL TDE | 高危 |
| 密钥管理 | KMS 密钥策略、轮换 | 严重 |
| 传输加密 | TLS 配置、证书管理 | 中 - 高危 |
| 访问控制 | IAM 密钥访问策略 | 严重 |
| 日志审计 | CloudTrail/Activity Log | 中危 |

#### 2.2 审计常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 数据湖/仓库 | S3 存储桶、Data Lake | 敏感数据未加密或密钥管理不当 |
| 云原生应用 | Lambda、Functions | 环境变量中的密钥明文 |
| 容器服务 | EKS、AKS、GKE | Secret 未加密存储 |
| 备份系统 | 云备份、快照 | 备份数据未加密 |
| 混合云 | Direct Connect、ExpressRoute | 传输加密配置不当 |

#### 2.3 漏洞检测方法

##### 2.3.1 AWS 加密检测

```bash
# 检测 S3 存储桶加密
aws s3api get-bucket-encryption --bucket target-bucket

# 检测未加密的 S3 存储桶
aws s3api list-buckets --query 'Buckets[].Name' | while read bucket; do
    aws s3api get-bucket-encryption --bucket "$bucket" 2>/dev/null || echo "未加密：$bucket"
done

# 检测 KMS 密钥策略
aws kms get-key-policy --key-id <key-id> --policy-name default

# 检测 KMS 密钥轮换
aws kms get-key-rotation-status --key-id <key-id>

# 检测 RDS 加密
aws rds describe-db-instances --query 'DBInstances[?StorageEncrypted==`false`].[DBInstanceIdentifier]'

# 检测 EBS 加密
aws ec2 describe-volumes --query 'Volumes[?Encrypted==`false`].[VolumeId]'
```

##### 2.3.2 Azure 加密检测

```bash
# 检测存储账户加密
az storage account show --name target-storage --query 'encryption'

# 检测未加密的存储账户
az storage account list --query "[?encryption.services.blob.enabled==`false`].name"

# 检测 Key Vault 密钥
az keyvault key list --vault-name target-vault

# 检测 Key Vault 访问策略
az keyvault show --name target-vault --query 'accessPolicies'

# 检测 SQL Database TDE
az sql db tde show --resource-group rg --server server --db dbname

# 检测磁盘加密
az vm show -d --resource-group rg --name vm --query 'storageProfile.osDisk.managedDisk.diskEncryptionSetId'
```

##### 2.3.3 GCP 加密检测

```bash
# 检测 GCS 存储桶加密
gsutil encryption get gs://target-bucket

# 检测 KMS 密钥
gcloud kms keys list --keyring target-ring --location global

# 检测 KMS 密钥策略
gcloud kms keys get-iam-policy key-id --keyring ring --location global

# 检测 Compute Engine 磁盘加密
gcloud compute disks describe disk-name --zone zone

# 检测 BigQuery 加密
bq show --format=prettyjson project:dataset.table
```

##### 2.3.4 使用 Prowler 进行云安全审计

```bash
# 安装 Prowler
git clone https://github.com/prowler-cloud/prowler.git
cd prowler

# AWS 审计
./prowler -c s3,cloudtrail,cloudwatch,config,ec2,iam,kms,rds

# 仅加密相关检查
./prowler -c s3_encryption,kms_key_rotation,rds_encryption,ec2_encryption

# 生成报告
./prowler -c s3,kms,rds -M csv,html,json
```

##### 2.3.5 使用 ScoutSuite 进行云审计

```bash
# 安装 ScoutSuite
pip install scoutsuite

# AWS 审计
scout run aws

# Azure 审计
scout run azure

# GCP 审计
scout run gcp

# 查看 Web 报告
# 报告生成在 scoutsuite-report.html
```

#### 2.4 漏洞利用方法

##### 2.4.1 S3 未加密数据访问

```bash
# 如果 S3 存储桶未加密且公开可访问
aws s3 cp s3://target-bucket/sensitive-data.csv ./ --no-sign-request

# 下载整个存储桶
aws s3 sync s3://target-bucket ./dump --no-sign-request

# 查找敏感文件
aws s3 ls s3://target-bucket --recursive | grep -E '\.(csv|json|sql|bak)$'
```

##### 2.4.2 KMS 密钥滥用

```bash
# 如果有 KMS 密钥使用权限但未正确限制
# 可以解密截获的密文

aws kms decrypt --ciphertext-blob fileb://encrypted-data \
    --key-id alias/target-key \
    --output text --query Plaintext | base64 -d

# 如果有 kms:GenerateDataKey 权限
# 可以生成新密钥解密历史数据
```

##### 2.4.3 环境变量密钥提取

```bash
# 如果有 Lambda/EC2 访问权限
# 提取环境变量中的密钥

# Lambda 环境变量
aws lambda get-function-configuration --function-name target-function \
    --query 'Environment.Variables'

# EC2 用户数据
aws ec2 describe-instance-attribute --instance-id i-xxx \
    --attribute userData

# 容器环境变量
kubectl get pod target-pod -o jsonpath='{.spec.containers[*].env}'
```

##### 2.4.4 云密钥泄露利用链

```
1. 发现未加密 S3 存储桶
   ↓
2. 读取配置文件（含 AK/SK 或连接字符串）
   ↓
3. 使用凭证访问其他云服务
   ↓
4. 提升权限（IAM 配置不当）
   ↓
5. 访问 KMS 密钥
   ↓
6. 解密所有静态数据
```

#### 2.5 安全配置建议

##### 2.5.1 AWS 加密最佳实践

```json
// S3 存储桶加密配置
{
    "Rules": [
        {
            "ApplyServerSideEncryptionByDefault": {
                "SSEAlgorithm": "aws:kms",
                "KMSMasterKeyID": "arn:aws:kms:region:account:key/key-id"
            },
            "BucketKeyEnabled": true
        }
    ]
}

// KMS 密钥策略（最小权限）
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "Enable IAM User Permissions",
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::account:root"},
            "Action": "kms:*",
            "Resource": "*"
        },
        {
            "Sid": "Allow use of the key",
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::account:user/target-user"},
            "Action": [
                "kms:Encrypt",
                "kms:Decrypt",
                "kms:ReEncrypt*",
                "kms:GenerateDataKey*",
                "kms:DescribeKey"
            ],
            "Resource": "*"
        }
    ]
}
```

##### 2.5.2 云加密配置检查清单

**AWS:**
- [ ] S3 存储桶启用默认加密
- [ ] S3 使用 KMS 而非 S3 托管密钥
- [ ] KMS 密钥启用自动轮换（每年）
- [ ] RDS 实例启用存储加密
- [ ] EBS 卷启用加密
- [ ] CloudTrail 日志文件加密
- [ ] S3 存储桶策略禁止非加密上传

**Azure:**
- [ ] 存储账户启用加密
- [ ] 使用 Customer-Managed Keys (CMK)
- [ ] SQL Database 启用 TDE
- [ ] 磁盘启用服务器端加密
- [ ] Key Vault 启用软删除和清除保护
- [ ] 启用存储威胁检测

**GCP:**
- [ ] GCS 使用 CMEK
- [ ] 默认 KMS 密钥轮换
- [ ] Compute Engine 磁盘加密
- [ ] Cloud SQL 启用加密
- [ ] BigQuery 使用 CMEK
- [ ] 审计日志启用

---

## 第三部分：附录

### 3.1 云加密工具清单

| 工具 | 用途 | 平台 |
|-----|------|------|
| Prowler | 云安全审计 | AWS/Azure/GCP |
| ScoutSuite | 云配置审计 | AWS/Azure/GCP |
| CloudSploit | 云安全监控 | AWS/Azure/GCP |
| Steampipe | 云资源配置查询 | AWS/Azure/GCP |
| Pacu | AWS 渗透测试 | AWS |

### 3.2 合规性映射

| 控制项 | AWS | Azure | GCP |
|-------|-----|-------|-----|
| 静态加密 | S3 SSE, EBS 加密 | Storage Encryption | GCS CMEK |
| 传输加密 | TLS 1.2+ | TLS 1.2+ | TLS 1.2+ |
| 密钥管理 | KMS | Key Vault | Cloud KMS |
| 访问审计 | CloudTrail | Activity Log | Cloud Audit Logs |

### 3.3 云加密风险评级

| 风险 | 影响 | 可能性 | 优先级 |
|-----|------|--------|--------|
| 未加密存储桶 | 数据泄露 | 高 | 紧急 |
| KMS 密钥公开 | 全面泄露 | 中 | 紧急 |
| 弱 IAM 策略 | 权限提升 | 高 | 高 |
| 未启用日志 | 无法检测 | 中 | 中 |
| 密钥未轮换 | 长期风险 | 低 | 中 |

---

## 参考资源

- [AWS Encryption Best Practices](https://docs.aws.amazon.com/security/latest/best-practices/encryption-best-practices.html)
- [Azure Encryption Overview](https://learn.microsoft.com/en-us/azure/security/fundamentals/encryption-overview)
- [GCP Encryption Overview](https://cloud.google.com/security/docs/encryption-overview)
- [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services)
- [Cloud Security Alliance](https://cloudsecurityalliance.org/)
