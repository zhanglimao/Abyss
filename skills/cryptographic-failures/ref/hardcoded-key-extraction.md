# 硬编码密钥提取方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的硬编码密钥检测和提取流程。

## 1.2 适用范围

本文档适用于所有可能存在硬编码密钥的 Web 应用、移动应用和客户端软件。

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

硬编码密钥是指将敏感密钥（API 密钥、加密密钥、密码等）直接写入源代码或配置文件中。

**本质问题**：
- 密钥与代码未分离
- 密钥提交到版本控制
- 客户端包含服务端密钥

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-798 | 使用硬编码凭证 |
| CWE-321 | 使用硬编码加密密钥 |
| CWE-259 | 使用硬编码密码 |

## 2.2 攻击常见于哪些业务场景

| 场景 | 风险点 | 潜在危害 |
|-----|-------|---------|
| 移动应用 | 客户端包含 API 密钥 | 密钥提取、API 滥用 |
| JavaScript 应用 | 前端包含密钥 | 密钥泄露 |
| 开源项目 | 代码公开 | 密钥被扫描 |
| 配置文件 | 配置含密钥 | 凭证泄露 |
| 备份文件 | 备份含源码 | 密钥泄露 |

## 2.3 漏洞发现方法

### 2.3.1 源码扫描

```bash
# 使用 TruffleHog
trufflehog git https://github.com/target/repo

# 使用 Gitleaks
gitleaks detect --source /path/to/repo

# 使用 GitLeaks 扫描 Git 历史
gitleaks git --verbose --repo-path /path/to/repo
```

### 2.3.2 常见密钥模式

```
# API 密钥模式
api_key = "sk-[a-zA-Z0-9]{32}"
API_KEY = "AKIA[0-9A-Z]{16}"
apikey: "[a-f0-9]{32}"

# AWS 密钥
aws_access_key_id = "AKIA..."
aws_secret_access_key = "[a-zA-Z0-9/+=]{40}"

# 加密密钥
secret_key = "[a-zA-Z0-9]{32}"
encryption_key = "..."

# 数据库凭证
DB_PASSWORD = "..."
DATABASE_URL = "mysql://user:pass@..."
```

### 2.3.3 文件类型扫描

```bash
# 扫描配置文件
find . -name "*.env" -o -name "*.config" -o -name "*.yml" -o -name "*.json"

# 扫描源代码
find . -name "*.py" -o -name "*.js" -o -name "*.java" -o -name "*.php"

# 扫描移动应用
# Android: .apk, .dex
# iOS: .ipa, .app
```

### 2.3.4 移动应用反编译

```bash
# Android APK 反编译
apktool d app.apk -o output_dir

# 查看源码和资源
cat output_dir/smali/**/*.smali | grep -i "key\|secret\|password"

# iOS IPA 分析
# 解压 IPA 文件
# 分析二进制文件中的字符串
strings app_binary | grep -i "key\|secret"
```

## 2.4 漏洞利用方法

### 2.4.1 API 密钥滥用

```bash
# 提取到 API 密钥后
API_KEY="sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# 测试密钥有效性
curl -H "Authorization: Bearer $API_KEY" \
    https://api.target.com/user

# 如果返回用户数据，密钥有效
```

### 2.4.2 云服务密钥利用

```bash
# AWS 密钥利用
aws configure set aws_access_key_id AKIA...
aws configure set aws_secret_access_key ...

# 列出 S3 桶
aws s3 ls

# 访问 EC2
aws ec2 describe-instances
```

### 2.4.3 数据库密钥利用

```bash
# 使用提取的数据库凭证
mysql -h target.com -u root -p'password'

# 访问数据库
SHOW DATABASES;
USE target_db;
SHOW TABLES;
```

### 2.4.4 加密密钥利用

```bash
# 如果获取到加密密钥
# 可以解密敏感数据
# 可以伪造加密数据
# 可以解密通信内容
```

## 2.5 漏洞利用绕过方法

### 2.5.1 混淆绕过

```bash
# 密钥可能被混淆
# Base64 编码
key = base64_decode("xxxxx")

# 字符串拼接
key = "part1" + "part2" + "part3"

# 异或加密
key = xor_decode(encoded_data, xor_key)
```

### 2.5.2 动态加载绕过

```bash
# 密钥可能动态加载
# 从远程服务器获取
# 从环境变量读取
# 从安全存储读取

# 使用动态分析工具
# Frida 插桩
# 调试器跟踪
```

### 2.5.3 Git 历史恢复

```bash
# 即使密钥已从当前代码删除
# 仍可能在 Git 历史中

# 使用 Git 历史扫描
gitleaks git --verbose

# 恢复已删除的文件
git log --diff-filter=D --summary
```

---

# 第三部分：附录

## 3.1 硬编码密钥测试检查清单

```
□ 扫描源代码
□ 扫描配置文件
□ 扫描 Git 历史
□ 反编译移动应用
□ 扫描 JavaScript 文件
□ 测试提取的密钥
□ 检查密钥权限范围
```

## 3.2 常用工具

| 工具 | 用途 | 链接 |
|-----|------|------|
| TruffleHog | 密钥扫描 | https://github.com/trufflesecurity/trufflehog |
| Gitleaks | Git 密钥扫描 | https://github.com/gitleaks/gitleaks |
| apktool | APK 反编译 | https://apktool.org/ |
| Frida | 动态插桩 | https://frida.re/ |
| Burp Suite | 密钥测试 | https://portswigger.net/burp |

## 3.3 修复建议

1. **密钥管理** - 使用密钥管理系统
2. **环境变量** - 从环境变量读取密钥
3. **Git 忽略** - 配置 .gitignore 排除密钥
4. **定期轮换** - 定期更换密钥
5. **最小权限** - 密钥使用最小权限

---

**参考资源**：
- [OWASP Secrets Management](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [CWE-798](https://cwe.mitre.org/data/definitions/798.html)
