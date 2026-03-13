# 存储加密攻击

---

## 第一部分：文档概述

### 1.1 编写目的
本文档旨在为渗透测试人员提供存储加密攻击的方法论。通过本指南，测试人员可以评估文件系统、磁盘、数据库等存储介质的加密实现，发现加密缺陷并提取敏感数据。

### 1.2 适用范围
本文档适用于以下场景：
- 全盘加密（FDE）安全评估
- 文件系统加密测试
- 数据库加密审计
- 云存储加密分析
- 移动设备存储加密
- 加密容器攻击

### 1.3 读者对象
- 渗透测试工程师
- 数据恢复专家
- 取证分析人员
- 存储安全审计人员

---

## 第二部分：核心渗透技术专题

### 专题一：存储加密攻击

#### 2.1 技术介绍

**存储加密攻击**是针对静态数据加密系统的攻击技术，包括绕过加密、提取密钥、暴力破解、利用实现缺陷等方法。

**存储加密类型：**

| 类型 | 技术 | 风险点 |
|------|------|--------|
| 全盘加密 | BitLocker、FileVault、LUKS | 密钥提取、冷启动攻击 |
| 文件系统加密 | EFS、APFS 加密、eCryptfs | 权限绕过、密钥泄露 |
| 容器加密 | VeraCrypt、DMG | 暴力破解、密钥文件泄露 |
| 数据库加密 | TDE、列加密 | 密钥管理不当 |
| 对象存储加密 | S3 SSE、客户托管密钥 | 权限配置错误 |
| 应用层加密 | 自定义加密 | 实现缺陷 |

**攻击复杂度对比：**

```
低复杂度                    中复杂度                     高复杂度
   │                           │                           │
   ▼                           ▼                           ▼
┌─────────┐              ┌─────────┐               ┌─────────┐
│配置错误 │              │暴力破解 │               │密码分析 │
│权限绕过 │              │密钥提取 │               │侧信道   │
│内存取证 │              │冷启动   │               │硬件攻击 │
└─────────┘              └─────────┘               └─────────┘
```

#### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 企业笔记本 | 员工电脑加密 | 设备丢失后数据泄露风险 |
| 云服务器 | 云盘加密 | 配置错误导致未加密 |
| 移动设备 | 手机加密存储 | 取证数据提取 |
| 备份系统 | 离线备份加密 | 弱口令保护 |
| 数据库 | 敏感数据加密 | 密钥与数据同存储 |
| 文件共享 | 加密压缩包 | 弱口令或已知漏洞 |

#### 2.3 漏洞检测方法

##### 2.3.1 全盘加密检测

```bash
# Windows BitLocker 检测
# 检查 BitLocker 状态
manage-bde -status

# 检查保护状态
manage-bde -protectors -get C:

# 检查是否启用 TPM
manage-bde -protectors -get C: | findstr TPM

# macOS FileVault 检测
# 检查 FileVault 状态
fdesetup status

# 检查恢复密钥位置
fdesetup recoverypersonal -list

# Linux LUKS 检测
# 检查加密分区
lsblk -o NAME,FSTYPE,TYPE,MOUNTPOINT

# 检查 LUKS 头
cryptsetup isLuks /dev/sdX

# 查看 LUKS 信息
cryptsetup luksDump /dev/sdX
```

##### 2.3.2 文件系统加密检测

```bash
# Windows EFS 检测
# 查找 EFS 加密文件
cipher /find:C:\Users\

# 检查 EFS 证书
certutil -user -store my

# Linux eCryptfs 检测
# 检查挂载的 eCryptfs
mount | grep ecryptfs

# 检查 eCryptfs 配置
cat ~/.ecryptfs/sig-cache.txt

# macOS APFS 加密检测
# 检查加密卷
diskutil apfs list

# 检查卷加密状态
diskutil info /Volumes/EncryptedVolume | grep Encrypted
```

##### 2.3.3 加密容器检测

```bash
# VeraCrypt 容器检测
# 识别 VeraCrypt 卷头
# 文件前 512 字节包含特定模式

# 使用 veracrypt 命令行
veracrypt -l  # 列出挂载的卷
veracrypt -t --list  # 文本模式列出

# TrueCrypt 遗留检测
# 类似 VeraCrypt，但使用不同头签名

# 加密 DMG 检测（macOS）
# 检查 DMG 文件
hdiutil imageinfo file.dmg

# 尝试挂载（需要密码）
hdiutil attach file.dmg
```

##### 2.3.4 加密实现缺陷检测

```python
#!/usr/bin/env python3
"""
检测加密实现缺陷
"""
import os
import re
from Crypto.Cipher import AES

def detect_crypto_weaknesses(file_path):
    """检测加密文件弱点"""
    
    print(f"[*] 分析文件：{file_path}")
    
    # 读取文件
    with open(file_path, 'rb') as f:
        data = f.read()
    
    # 检查文件头
    headers = {
        b'Salted__': 'OpenSSL 格式',
        b'Vera': 'VeraCrypt',
        b'True': 'TrueCrypt',
        b'LUKS': 'Linux LUKS',
        b'-FDE4-': 'BitLocker',
    }
    
    for header, desc in headers.items():
        if data.startswith(header):
            print(f"[+] 识别格式：{desc}")
            break
    else:
        print("[?] 未知格式")
    
    # 检查 ECB 模式特征
    if len(data) % 16 == 0:
        blocks = [data[i:i+16] for i in range(0, min(len(data), 1024*16), 16)]
        unique_blocks = len(set(blocks))
        
        if unique_blocks < len(blocks) * 0.9:
            print("[!] 可能使用 ECB 模式（重复块）")
    
    # 检查弱加密特征
    if len(data) < 1024:
        print("[!] 文件过小，可能加密不完整")
    
    # 熵值分析
    from collections import Counter
    entropy = -sum((c/len(data)) * (c/len(data)).bit_length() 
                   for c in Counter(data).values())
    print(f"[*] 文件熵值：{entropy:.2f} bits/byte")
    
    if entropy > 7.5:
        print("[+] 高熵值，可能是加密数据")
    elif entropy > 6.0:
        print("[⚠] 中等熵值，可能是压缩或弱加密")
    else:
        print("[-] 低熵值，可能未加密")

# 使用示例
# detect_crypto_weaknesses("encrypted_file.bin")
```

#### 2.4 漏洞利用方法

##### 2.4.1 BitLocker 攻击

```bash
# BitLocker 攻击方法

# 方法 1: 从内存提取密钥（需要物理访问）
# 使用 LiME 或 WinPmem 获取内存转储
# 使用 Elcomsoft 或 Passware 提取 BitLocker 密钥

# 方法 2: 冷启动攻击
# 快速冷却 RAM，重启到另一系统
# 从内存残留提取密钥
# 参考：https://citp.princeton.edu/research/memory/

# 方法 3: TPM 攻击
# 如果 TPM 未正确配置，可能提取密钥
# 需要专业设备

# 方法 4: 恢复密钥提取
# 从 Microsoft 账户、打印件、USB 驱动器获取
# 或使用 mimikatz 从域控制器提取

# 方法 5: 配置错误利用
# 如果 BitLocker 仅使用 TPM（无 PIN）
# 攻击者可以启动系统并访问数据

# 实际攻击命令（需要专业工具）
# elcomsoft_bitlocker_recovery.exe --memory-dump mem.dmp
```

##### 2.4.2 FileVault 攻击

```bash
# FileVault 攻击方法

# 方法 1: 恢复密钥攻击
# 从 iCloud 钥匙串获取
# 或暴力破解恢复密钥（3872 种组合）

# 方法 2: 内存取证
# 获取内存转储
# 提取 FileVault 2 密钥

# 使用 osxmem 工具
python3 osxmem.py --dump memory.dmp

# 方法 3: 目标磁盘模式
# 如果 FileVault 未启用或已解锁
# 通过 Thunderbolt 直接访问磁盘

# 方法 4: 休眠文件攻击
# 如果休眠时内存写入磁盘
# 可能从休眠文件提取密钥

# 检查休眠文件
ls -la /var/vm/sleepimage

# 分析休眠文件
strings /var/vm/sleepimage | grep -i password
```

##### 2.4.3 LUKS 攻击

```bash
# LUKS 攻击方法

# 方法 1: 暴力破解
# 使用 hashcat
cryptsetup luksDump /dev/sdX > luks_header.txt

# 提取哈希
luks2john /dev/sdX > luks_hash.txt

# hashcat 破解
hashcat -m 14600 luks_hash.txt wordlist.txt

# 方法 2: 密钥文件攻击
# 如果密钥文件存储在别处
# 提取并尝试解密

# 方法 3: 侧信道攻击
# 针对特定实现
# 需要专业设备

# 方法 4: 实现漏洞
# 检查 LUKS 版本和已知漏洞
cryptsetup --version

# 方法 5: 弱口令攻击
# 使用常见口令字典
hashcat -m 14600 luks_hash.txt rockyou.txt
```

##### 2.4.4 VeraCrypt 攻击

```bash
# VeraCrypt 攻击方法

# 方法 1: 暴力破解
# 使用 hashcat
# 提取 VeraCrypt 哈希（需要卷头）

# 方法 2: 密钥文件攻击
# 如果密钥文件弱或可预测
# 尝试常见密钥文件

# 方法 3: 隐藏卷检测
# 检测是否存在隐藏卷
# 但无法证明具体内容

# 方法 4: 实现漏洞
# 检查 VeraCrypt 版本
# 已知漏洞：CVE-2019-11931 等

# 方法 5: 内存取证
# 从内存提取密钥
# 卷挂载时密钥在内存中

# 使用 veracrypt_crack.sh（示例脚本）
```

```python
#!/usr/bin/env python3
"""
VeraCrypt 卷分析
"""
import struct

def analyze_veracrypt_header(file_path):
    """分析 VeraCrypt 卷头"""
    
    with open(file_path, 'rb') as f:
        header = f.read(512)  # 卷头 512 字节
    
    # 检查魔数
    # VeraCrypt 卷没有固定魔数（隐藏卷特征）
    
    # 检查加密算法标识
    algorithms = {
        b'AES': 'AES',
        b'SERP': 'Serpent',
        b'TWOF': 'Twofish',
        b'CAST': 'CAST-256',
    }
    
    print("[*] VeraCrypt 卷分析")
    
    # 尝试识别加密算法
    for sig, algo in algorithms.items():
        if sig in header:
            print(f"    可能的算法：{algo}")
    
    # 检查卷大小
    f.seek(0, 2)
    size = f.tell()
    print(f"    卷大小：{size / 1024 / 1024:.2f} MB")
    
    # 检查是否是系统加密
    if header[0:6] == b'EXT2\x00\x00':
        print("    [!] 可能是系统分区加密")
    
    # 熵值分析
    from collections import Counter
    entropy = -sum((c/len(header)) * (c/len(header)).bit_length()
                   for c in Counter(header).values())
    print(f"    头部熵值：{entropy:.2f}")

# 使用示例
# analyze_veracrypt_header("encrypted_volume.tc")
```

##### 2.4.5 数据库加密攻击

```sql
-- SQL Server TDE 攻击

-- 如果有足够权限，可以导出证书
USE master;
BACKUP CERTIFICATE TDE_Certificate
TO FILE = 'C:\\cert.cer'
WITH PRIVATE KEY (
    FILE = 'C:\\cert.key',
    ENCRYPTION BY PASSWORD = 'temp_password',
    DECRYPTION BY PASSWORD = 'original_password'
);

-- 然后分离并复制数据库文件
-- 在另一服务器还原

-- MySQL 表空间加密攻击

-- 如果密钥环文件可访问
-- 复制 .ibd 文件和 keyring 文件
-- 在另一实例挂载

-- Oracle TDE 攻击

-- 提取钱包文件
-- $ORACLE_HOME/dbs/ewallet.p12
-- 需要钱包密码或主密钥
```

##### 2.4.6 云存储加密攻击

```bash
# AWS S3 加密攻击

# 检测未加密的 S3 存储桶
aws s3api list-buckets --query 'Buckets[].Name' | while read bucket; do
    aws s3api get-bucket-encryption --bucket "$bucket" 2>/dev/null || \
    echo "[!] 未加密：$bucket"
done

# 如果有 S3 访问权限但加密配置错误
# 可以直接下载敏感数据

# Azure Blob 加密检测
az storage account list --query "[?encryption.services.blob.enabled==`false`].name"

# GCP GCS 加密检测
gsutil encryption get gs://bucket-name
```

#### 2.5 安全配置建议

##### 2.5.1 全盘加密最佳实践

```
BitLocker 配置:
- 启用 TPM + PIN 双因素
- 使用 AES-256 加密
- 启用启动前验证
- 安全存储恢复密钥
- 定期轮换恢复密钥

FileVault 配置:
- 启用 FileVault 2
- 使用强登录口令
- 安全存储恢复密钥
- 启用查找我的 Mac
- 禁用自动登录

LUKS 配置:
- 使用 LUKS2 格式
- 选择强 KDF（Argon2id）
- 设置强口令
- 备份 LUKS 头
- 使用密钥文件 + 口令
```

##### 2.5.2 存储加密检查清单

**全盘加密:**
- [ ] 启用加密
- [ ] 使用强认证（PIN/口令）
- [ ] 安全存储恢复密钥
- [ ] 启用启动前验证
- [ ] 定期更新加密软件

**文件系统加密:**
- [ ] 敏感目录加密
- [ ] 权限正确配置
- [ ] 密钥与数据分离
- [ ] 备份加密证书
- [ ] 定期轮换密钥

**容器加密:**
- [ ] 使用强口令（20+ 字符）
- [ ] 启用密钥文件
- [ ] 隐藏卷（可选）
- [ ] 定期更新软件
- [ ] 安全存储容器

**云存储:**
- [ ] 启用服务器端加密
- [ ] 使用客户托管密钥（CMK）
- [ ] 密钥轮换启用
- [ ] 访问策略限制
- [ ] 审计日志启用

---

## 第三部分：附录

### 3.1 存储加密攻击工具

| 工具 | 用途 |
|-----|------|
| hashcat | 加密口令爆破 |
| Elcomsoft | 商业解密工具 |
| Passware | 取证解密 |
| LiME | 内存转储 |
| Volatility | 内存分析 |
| veracrypt | 加密容器 |

### 3.2 加密强度对比

| 加密方式 | 暴力破解难度 | 已知漏洞 |
|---------|-------------|---------|
| BitLocker (TPM+PIN) | 极高 | 冷启动攻击 |
| FileVault 2 | 极高 | 内存取证 |
| LUKS2 (Argon2id) | 极高 | 弱口令 |
| VeraCrypt (AES) | 极高 | 实现漏洞 |
| 7-Zip (AES-256) | 高 | 弱口令 |
| ZIP (传统) | 低 | 已知漏洞 |

### 3.3 取证提取难度

| 场景 | 难度 | 备注 |
|-----|------|------|
| 关机状态 | 极高 | 需要口令/密钥 |
| 开机锁定 | 高 | 可能需要内存取证 |
| 开机解锁 | 低 | 直接访问数据 |
| 休眠状态 | 中 | 可能从休眠文件提取 |
| 睡眠状态 | 低 | 密钥在内存中 |

---

## 参考资源

- [NIST SP 800-111 - Storage Encryption](https://csrc.nist.gov/publications/detail/sp/800-111/final)
- [Cold Boot Attack](https://citp.princeton.edu/research/memory/)
- [VeraCrypt Documentation](https://veracrypt.fr/en/Documentation.html)
- [BitLocker Forensics](https://www.sans.org/blog/bitlocker-forensics/)
