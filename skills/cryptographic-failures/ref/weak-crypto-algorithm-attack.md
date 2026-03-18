# 弱加密算法攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的弱加密算法检测、验证和利用流程。通过本指南，测试人员可以识别目标系统中使用的不安全加密算法，评估其风险，并在授权范围内使用相应的攻击技术。

## 1.2 适用范围

本文档适用于以下场景：
- 使用已弃用加密算法的系统（MD5、SHA1、DES、RC4 等）
- 使用弱密钥长度的加密实现
- 使用自定义或不标准加密算法的应用
- 需要评估加密算法强度的安全审计

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师、密码学安全测试人员。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

弱加密算法攻击针对的是使用已过时、被破解或强度不足的加密算法的系统。随着密码学技术进步和算力提升，曾经"安全"的算法可能变得不安全。

**本质问题**：
- 使用已被密码分析攻破的算法（如 MD5、SHA1、DES）
- 使用密钥长度不足的算法
- 使用未经验证的自定义加密算法
- 使用简单混淆代替真正加密（如 XOR、ROT13、Base64）

### 常见 CWE 映射

| CWE 编号 | 描述 | 风险等级 |
|---------|------|---------|
| CWE-327 | 使用已损坏或有风险的加密算法 | 严重 |
| CWE-326 | 加密强度不足 | 高危 |
| CWE-328 | 使用弱哈希算法 | 高危 |
| CWE-759 | 使用无盐单向哈希 | 高危 |
| CWE-916 | 使用计算强度不足的密码哈希 | 高危 |

### 常见弱加密算法列表

| 算法类型 | 弱算法 | 推荐替代 | 主要风险 |
|---------|-------|---------|---------|
| **哈希函数** | MD5 | SHA-256/SHA-3 | 碰撞攻击、预图像攻击 |
| **哈希函数** | SHA1 | SHA-256/SHA-3 | 碰撞攻击（已实际演示） |
| **对称加密** | DES | AES-256 | 密钥空间过小（56 位） |
| **对称加密** | 3DES | AES-256 | Sweet32 攻击 |
| **对称加密** | RC4 | AES-GCM | 统计偏差、密钥恢复 |
| **对称加密** | Blowfish | AES-256 | 64 位块大小问题 |
| **非对称加密** | RSA-1024 | RSA-3072+/ECC | 因数分解攻击 |
| **流密码** | 自定义 XOR | AES-CTR | 密钥重用、统计分析 |

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 | 潜在危害 |
|---------|---------|-----------|---------|
| **密码存储** | 用户登录系统 | 使用 MD5/SHA1 存储密码 | 彩虹表破解、批量泄露 |
| **文件完整性** | 下载校验、签名验证 | 使用 MD5 校验文件 | 碰撞攻击、恶意文件替换 |
| **会话管理** | Session ID 生成 | 使用弱哈希生成会话 | 会话预测、劫持 |
| **数字签名** | 证书签名、代码签名 | 使用 SHA1 签名 | 签名伪造、证书欺骗 |
| **数据加密** | 敏感数据加密存储 | 使用 DES/RC4 加密 | 数据解密、信息泄露 |
| **API 认证** | API 签名验证 | 使用 MD5/HMAC-MD5 | 请求伪造、未授权访问 |
| **令牌生成** | CSRF Token、重置令牌 | 使用弱随机 + 弱哈希 | 令牌预测、绕过验证 |
| **遗留系统** | 旧版金融/医疗系统 | 使用过时加密标准 | 合规风险、数据泄露 |
| **移动应用** | 本地数据加密 | 使用硬编码弱密钥 | 逆向工程、数据提取 |
| **IoT 设备** | 固件签名、通信加密 | 使用资源受限的弱加密 | 设备劫持、固件篡改 |

## 2.3 漏洞发现方法

### 2.3.1 黑盒测试 - 算法识别

**步骤 1：识别哈希算法**

```bash
# 使用 hash-identifier 工具
hash-identifier
# 输入哈希值进行识别

# 使用 hashid 工具
hashid 5f4dcc3b5aa765d61d8327deb882cf99
# 输出：MD5

# 常见哈希长度识别
# 32 字符 (128 位): MD5, MD4, NTLM
# 40 字符 (160 位): SHA1, RIPEMD160
# 64 字符 (256 位): SHA256, SHA3-256
# 96 字符 (384 位): SHA384, SHA3-384
# 128 字符 (512 位): SHA512, SHA3-512
```

**步骤 2：识别加密算法**

```bash
# 使用 OpenSSL 识别加密数据特征
openssl enc -d -aes-256-cbc -in encrypted.bin -K <key> -iv <iv> 2>&1

# 使用 CyberChef 分析加密模式
# https://gchq.github.io/CyberChef/

# 检测 ECB 模式（相同明文块产生相同密文块）
python3 detect_ecb.py encrypted_file.bin
```

**步骤 3：TLS/SSL 算法检测**

```bash
# 检测 TLS 加密套件
nmap --script ssl-enum-ciphers -p 443 target.com

# 使用 OpenSSL 检测
openssl s_client -connect target.com:443 -cipher 'MD5:RC4:DES:3DES:NULL:EXPORT'

# 如果连接成功，说明支持弱加密套件
```

**步骤 4：HTTP 响应头分析**

```bash
# 检查安全头
curl -I https://target.com

# 查找加密相关头信息
# X-Encrypted-By: <algorithm>
# 某些应用会暴露使用的加密算法
```

### 2.3.2 白盒测试 - 代码审计

**检查哈希算法使用：**

```python
# ❌ 不安全 - MD5 哈希
import hashlib
hash = hashlib.md5(password.encode()).hexdigest()

# ❌ 不安全 - SHA1 哈希
hash = hashlib.sha1(password.encode()).hexdigest()

# ✅ 安全 - SHA256 加盐哈希
import secrets
salt = secrets.token_hex(16)
hash = hashlib.sha256((salt + password).encode()).hexdigest()

# ✅ 安全 - 使用 bcrypt
import bcrypt
hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
```

**检查加密算法使用：**

```python
# ❌ 不安全 - DES 加密
from Crypto.Cipher import DES
cipher = DES.new(key, DES.MODE_ECB)

# ❌ 不安全 - RC4 加密
from Crypto.Cipher import ARC4
cipher = ARC4.new(key)

# ❌ 不安全 - 自定义 XOR 加密
def xor_encrypt(data, key):
    return bytes([d ^ key[i % len(key)] for i, d in enumerate(data)])

# ✅ 安全 - AES-GCM 加密
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

nonce = get_random_bytes(12)
cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
ciphertext, tag = cipher.encrypt_and_digest(plaintext)
```

**检查 Java 加密实现：**

```java
// ❌ 不安全 - MD5
MessageDigest md = MessageDigest.getInstance("MD5");

// ❌ 不安全 - SHA1
MessageDigest md = MessageDigest.getInstance("SHA1");

// ❌ 不安全 - DES
Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");

// ❌ 不安全 - RC4
Cipher cipher = Cipher.getInstance("RC4");

// ✅ 安全 - SHA256
MessageDigest md = MessageDigest.getInstance("SHA-256");

// ✅ 安全 - AES-GCM
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
```

**检查 PHP 加密实现：**

```php
// ❌ 不安全 - MD5
$hash = md5($password);

// ❌ 不安全 - SHA1
$hash = sha1($password);

// ❌ 不安全 - 自定义加密
function encrypt($data, $key) {
    for($i = 0; $i < strlen($data); $i++) {
        $data[$i] = chr(ord($data[$i]) ^ ord($key[$i % strlen($key)]));
    }
    return base64_encode($data);
}

// ✅ 安全 - password_hash (使用 bcrypt)
$hash = password_hash($password, PASSWORD_BCRYPT);

// ✅ 安全 - OpenSSL AES
$ciphertext = openssl_encrypt($data, 'AES-256-GCM', $key, 0, $iv, $tag);
```

### 2.3.3 自动化扫描工具

```bash
# 使用 TruffleHog 扫描代码中的加密使用
trufflehog filesystem /path/to/code

# 使用 Gitleaks 扫描 Git 仓库
gitleaks detect --source /path/to/repo

# 使用 Semgrep 检测弱加密
semgrep --config p/cryptographic-primitives

# 使用 SonarQube 检测加密问题
# 配置加密相关规则

# 使用 Nmap NSE 脚本
nmap --script ssl-enum-ciphers,ssl-heartbleed,ssl-poodle -p 443 target.com
```

### 2.3.4 加密强度测试脚本

```python
#!/usr/bin/env python3
"""
加密算法强度检测脚本
"""
import hashlib
import time
from Crypto.Cipher import DES, AES, ARC4

def test_md5_collision_resistance():
    """测试 MD5 碰撞抵抗力（教育目的）"""
    print("[*] MD5 碰撞测试")
    
    # 已知 MD5 碰撞对（来自论文）
    msg1 = bytes.fromhex(
        "d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f89"
        "55ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5b"
        "d8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0"
        "e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70"
    )
    msg2 = bytes.fromhex(
        "d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f89"
        "55ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5b"
        "d8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0"
        "e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70"
    )
    
    hash1 = hashlib.md5(msg1).hexdigest()
    hash2 = hashlib.md5(msg2).hexdigest()
    
    print(f"    消息 1 哈希：{hash1}")
    print(f"    消息 2 哈希：{hash2}")
    
    if hash1 == hash2:
        print("    [!] MD5 碰撞成功 - 不应在任何安全场景使用 MD5")
    else:
        print("    [-] 未复现碰撞（可能需要特定消息对）")

def test_des_key_space():
    """测试 DES 密钥空间（教育目的）"""
    print("\n[*] DES 密钥空间测试")
    
    # DES 密钥空间 = 2^56 ≈ 7.2 x 10^16
    # 现代 GPU 可在数小时内穷举
    
    key_space = 2 ** 56
    gpu_speed = 10 ** 9  # 假设 GPU 每秒尝试 10 亿次
    
    time_hours = key_space / gpu_speed / 3600
    print(f"    DES 密钥空间：2^56 = {key_space:.2e}")
    print(f"    GPU 破解时间估计：{time_hours:.1f} 小时")
    print("    [!] DES 已不安全 - 应使用 AES-256")

def test_hash_speed():
    """测试哈希函数速度（用于评估暴力破解抵抗力）"""
    print("\n[*] 哈希函数速度测试")
    
    test_data = b"password123"
    iterations = 100000
    
    algorithms = {
        'MD5': hashlib.md5,
        'SHA1': hashlib.sha1,
        'SHA256': hashlib.sha256,
    }
    
    for name, func in algorithms.items():
        start = time.time()
        for _ in range(iterations):
            func(test_data).hexdigest()
        elapsed = time.time() - start
        print(f"    {name}: {iterations} 次耗时 {elapsed:.3f}秒 ({iterations/elapsed:.0f} 次/秒)")
    
    print("\n    [!] 快速哈希不利于抵抗暴力破解")
    print("    [✓] 推荐使用 bcrypt/scrypt/Argon2 等慢哈希")

def detect_weak_encryption(file_path):
    """检测文件中的弱加密特征"""
    print(f"\n[*] 检测文件弱加密特征：{file_path}")
    
    with open(file_path, 'rb') as f:
        data = f.read()
    
    # 检测 ECB 模式（重复块）
    block_size = 16  # AES 块大小
    blocks = [data[i:i+block_size] for i in range(0, len(data), block_size)]
    
    if len(blocks) != len(set(blocks)):
        duplicates = len(blocks) - len(set(blocks))
        print(f"    [!] 发现 {duplicates} 个重复块 - 可能使用 ECB 模式")
    
    # 检测 XOR 加密特征（低熵）
    # XOR 加密的数据通常熵值较低
    
    # 检测 Base64 编码（可能是简单混淆）
    import base64
    import re
    
    base64_pattern = rb'[A-Za-z0-9+/]{20,}={0,2}'
    matches = re.findall(base64_pattern, data)
    
    if matches:
        print(f"    [i] 发现 {len(matches)} 处 Base64 编码数据")
        print("    [!] Base64 不是加密，仅是编码")
    
    print("    [✓] 检测完成")

# 使用示例
if __name__ == "__main__":
    test_md5_collision_resistance()
    test_des_key_space()
    test_hash_speed()
    # detect_weak_encryption("encrypted_data.bin")
```

## 2.4 漏洞利用方法

### 2.4.1 MD5 碰撞攻击

```python
#!/usr/bin/env python3
"""
MD5 碰撞攻击利用
用于文件完整性校验绕过
"""
import hashlib

def md5_collision_attack():
    """
    利用 MD5 碰撞绕过文件完整性校验
    
    场景：
    - 系统使用 MD5 校验文件完整性
    - 攻击者构造碰撞文件绕过校验
    """
    
    print("[*] MD5 碰撞攻击演示")
    
    # 使用已知碰撞对（来自 Marc Stevens 的 MD5 碰撞项目）
    # 实际攻击需要使用专门工具如 fastcoll
    
    # 示例：构造两个不同但 MD5 相同的文件
    # 文件 1：良性文件
    # 文件 2：恶意文件
    
    print("""
    攻击步骤:
    1. 使用 fastcoll 工具生成碰撞对
       fastcoll -o file1.bin file2.bin
    
    2. 在碰撞对后附加相同后缀
       cat file1.bin suffix > benign.exe
       cat file2.bin suffix > malicious.exe
    
    3. benign.exe 和 malicious.exe 有相同 MD5
       但行为完全不同
    
    4. 提交 benign.exe 通过校验
       实际部署 malicious.exe
    
    工具:
    - fastcoll: https://github.com/cr-marcstevens/fastcoll
    - hashclash: https://github.com/cr-marcstevens/hashclash
    """)

def generate_md5_collision(prefix=b''):
    """
    生成 MD5 碰撞（需要外部工具）
    这里仅提供接口说明
    """
    import subprocess
    
    # 使用 fastcoll 生成碰撞
    # 需要预先安装 fastcoll
    try:
        result = subprocess.run(
            ['fastcoll', '-p', '-o', 'collision1.bin', 'collision2.bin'],
            input=prefix,
            capture_output=True
        )
        return True
    except FileNotFoundError:
        print("[-] fastcoll 未安装")
        print("    安装：https://github.com/cr-marcstevens/fastcoll")
        return False
```

### 2.4.2 SHA1 碰撞攻击（SHAttered）

```python
#!/usr/bin/env python3
"""
SHA1 碰撞攻击利用
基于 SHAttered 攻击（2017 年 Google 和 CWI 实现）
"""

def shattered_attack_info():
    """
    SHAttered 攻击信息
    
    2017 年，Google 和 CWI 实现了首个 SHA1 碰撞攻击
    生成两个不同 PDF 文件具有相同 SHA1 哈希
    """
    
    print("""
    SHAttered 攻击详情:
    
    复杂度:
    - 计算复杂度：2^63.1 次 SHA1 计算
    - 相当于 9,223,372,036,854,775,808 次 SHA1
    
    实际成本:
    - Google 使用 110 年 GPU 计算能力
    - 估计成本约$110,000（2017 年）
    - 现在成本更低
    
    影响:
    - Git 仓库完整性（Git 使用 SHA1）
    - PDF 签名验证
    - 证书签名（已弃用 SHA1 证书）
    
    防御:
    - 迁移到 SHA-256 或 SHA-3
    - Git 已支持 SHA256 仓库
    - 浏览器已不信任 SHA1 证书
    """)

# 实际碰撞生成需要大量计算资源
# 这里仅提供概念验证
```

### 2.4.3 DES 暴力破解

```python
#!/usr/bin/env python3
"""
DES 暴力破解攻击
"""
from Crypto.Cipher import DES
import itertools
import string

def des_bruteforce_attack(ciphertext, known_plaintext_prefix=b''):
    """
    DES 暴力破解
    
    由于 DES 密钥空间仅 2^56，现代硬件可在合理时间内穷举
    """
    
    print("[*] DES 暴力破解攻击")
    print("    [!] 警告：仅用于授权测试")
    
    # 实际攻击通常使用 Hashcat 或 John the Ripper
    # 这里提供概念验证
    
    print("""
    使用 Hashcat 破解 DES:
    
    # DES ECB 模式
    hashcat -m 14000 des_hash.txt wordlist.txt
    
    # DES CBC 模式（需要知道 IV）
    hashcat -m 14100 des_hash.txt wordlist.txt
    
    使用 John the Ripper:
    
    john --format=des-crypt hashes.txt
    john --format=descrypt hashes.txt
    
    预计时间:
    - 现代 GPU: 数小时
    - GPU 集群: 数分钟
    - 专用硬件：数秒
    """)
    
    # 简化版穷举（仅演示，实际密钥空间太大）
    # 实际攻击应使用专门工具
    
    return None

def des_known_plaintext_attack(ciphertext, plaintext):
    """
    DES 已知明文攻击
    
    如果知道部分明文 - 密文对，可尝试恢复密钥
    """
    
    print("[*] DES 已知明文攻击")
    
    # 实际攻击需要专门的密码分析工具
    # 这里提供概念说明
    
    print("""
    攻击原理:
    1. 获取明文 - 密文对
    2. 使用已知明文攻击技术
    3. 恢复加密密钥
    
    工具:
    - 自定义脚本（针对特定实现）
    - 密码分析框架
    """)
```

### 2.4.4 RC4 统计攻击

```python
#!/usr/bin/env python3
"""
RC4 统计偏差攻击
"""

def rc4_bias_attack_info():
    """
    RC4 统计偏差攻击信息
    
    RC4 存在多个统计偏差，可用于攻击：
    - 密钥流前缀偏差
    - 单字节偏差
    - 双字节偏差（NOMORE 攻击）
    """
    
    print("""
    RC4 攻击技术:
    
    1. RC4 NOMORE 攻击 (2015)
       - 利用双字节统计偏差
       - 可从 HTTPS Cookie 中解密数据
       - 需要收集大量加密流量（约 2^32 次请求）
    
    2. RC4 密钥恢复
       - 利用密钥流偏差
       - 部分密钥字节可被推断
    
    3. RC4 在 TLS 中的攻击
       - TLS 中使用 RC4 已被 RFC 7465 禁止
       - 但遗留系统可能仍支持
    
    防御:
    - 禁用 RC4 加密套件
    - 使用 AES-GCM 等现代加密
    - 更新 TLS 配置
    """)

def detect_rc4_usage(target_url):
    """检测目标是否支持 RC4"""
    import subprocess
    
    print(f"[*] 检测 RC4 支持：{target_url}")
    
    try:
        result = subprocess.run(
            ['openssl', 's_client', '-connect', f'{target_url}:443',
             '-cipher', 'RC4'],
            input=b'Q', capture_output=True, timeout=5
        )
        
        if 'Cipher' in result.stdout.decode():
            print("    [!] 目标支持 RC4 - 存在安全风险")
            return True
        else:
            print("    [-] 目标不支持 RC4")
            return False
    except Exception as e:
        print(f"    [-] 检测失败：{e}")
        return None
```

### 2.4.5 自定义加密算法逆向

```python
#!/usr/bin/python3
"""
自定义加密算法逆向分析
"""
import re

def analyze_custom_encryption(data_samples):
    """
    分析自定义加密算法特征
    
    data_samples: [(明文，密文), ...] 样本对
    """
    
    print("[*] 自定义加密算法分析")
    
    if not data_samples:
        print("[-] 需要提供明文 - 密文样本对")
        return
    
    # 分析 1: 检查是否为简单编码
    print("\n[1] 检查简单编码...")
    
    for plaintext, ciphertext in data_samples[:3]:
        # Base64 检测
        if re.match(rb'^[A-Za-z0-9+/]+=*$', ciphertext):
            print("    [!] 可能是 Base64 编码")
            import base64
            try:
                decoded = base64.b64decode(ciphertext)
                print(f"        解码：{decoded}")
            except:
                pass
        
        # Hex 编码检测
        if re.match(rb'^[0-9a-fA-F]+$', ciphertext):
            print("    [!] 可能是 Hex 编码")
            try:
                decoded = bytes.fromhex(ciphertext.decode())
                print(f"        解码：{decoded}")
            except:
                pass
    
    # 分析 2: 检查 XOR 特征
    print("\n[2] 检查 XOR 加密特征...")
    
    for plaintext, ciphertext in data_samples[:3]:
        if len(plaintext) == len(ciphertext):
            # 计算 XOR 密钥
            xor_result = bytes([p ^ c for p, c in zip(plaintext, ciphertext)])
            
            # 检查是否为重复密钥
            key_candidates = [1, 2, 4, 8, 16]
            for key_len in key_candidates:
                if len(xor_result) >= key_len * 2:
                    key1 = xor_result[:key_len]
                    key2 = xor_result[key_len:key_len*2]
                    if key1 == key2:
                        print(f"    [!] 发现 XOR 加密，密钥长度可能为 {key_len}")
                        print(f"        密钥：{key1.hex()}")
                        break
    
    # 分析 3: 检查块加密特征
    print("\n[3] 检查块加密特征...")
    
    for plaintext, ciphertext in data_samples[:3]:
        # 检查密文长度是否为块大小倍数
        block_sizes = [8, 16]  # DES/AES 块大小
        
        for block_size in block_sizes:
            if len(ciphertext) % block_size == 0:
                print(f"    [i] 密文长度是 {block_size} 的倍数 - 可能是块加密")
                
                # 检查 ECB 模式
                blocks = [ciphertext[i:i+block_size] 
                         for i in range(0, len(ciphertext), block_size)]
                if len(blocks) != len(set(blocks)):
                    print(f"    [!] 发现重复块 - 可能使用 ECB 模式")
    
    print("\n[✓] 分析完成")

def reverse_xor_encryption(plaintext, ciphertext):
    """
    逆向 XOR 加密，恢复密钥
    """
    if len(plaintext) != len(ciphertext):
        print("[-] 明文和密文长度不匹配")
        return None
    
    key = bytes([p ^ c for p, c in zip(plaintext, ciphertext)])
    
    # 尝试检测密钥模式
    print(f"[*] XOR 密钥：{key.hex()}")
    print(f"[*] XOR 密钥（ASCII）：{key}")
    
    # 检测重复模式
    for pattern_len in range(1, len(key) // 2 + 1):
        pattern = key[:pattern_len]
        is_repeated = True
        for i in range(pattern_len, len(key), pattern_len):
            if key[i:i+pattern_len] != pattern[:len(key)-i]:
                is_repeated = False
                break
        
        if is_repeated:
            print(f"[+] 检测到重复密钥模式：{pattern.hex()} (长度：{pattern_len})")
            return pattern
    
    return key

# 使用示例
if __name__ == "__main__":
    # 示例样本
    samples = [
        (b"Hello World", bytes.fromhex("2b3e4f1a0c5d6e7f8a9b0c1d")),
    ]
    analyze_custom_encryption(samples)
```

### 2.4.6 弱哈希密码破解

```python
#!/usr/bin/env python3
"""
弱哈希密码破解
"""

def crack_weak_hash(hash_value, hash_type='md5'):
    """
    破解弱哈希密码
    
    hash_type: md5, sha1, sha256, des, etc.
    """
    
    print(f"[*] 破解 {hash_type.upper()} 哈希")
    
    # Hashcat 模式对应
    hashcat_modes = {
        'md5': '0',
        'sha1': '100',
        'sha256': '1400',
        'sha512': '1700',
        'des': '1500',
        'md5(md5)': '2600',
        'md5(sha1)': '4400',
        'sha1(md5)': '4700',
    }
    
    mode = hashcat_modes.get(hash_type.lower(), '0')
    
    print(f"""
    使用 Hashcat 破解:
    
    # 字典攻击
    hashcat -m {mode} hashes.txt rockyou.txt
    
    # 规则攻击
    hashcat -m {mode} -r rules/best64.rule hashes.txt rockyou.txt
    
    # 掩码攻击（已知密码模式）
    hashcat -m {mode} -a 3 hashes.txt ?a?a?a?a?a?a?a?a
    
    # 组合攻击
    hashcat -m {mode} -a 6 hashes.txt dict1.txt dict2.txt
    
    使用 John the Ripper:
    
    john --format={hash_type} hashes.txt
    john --wordlist=rockyou.txt hashes.txt
    """)

def online_crack(hash_value):
    """
    使用在线服务破解哈希
    """
    
    print("[*] 在线破解服务")
    
    services = {
        'CrackStation': 'https://crackstation.net/',
        'HashKiller': 'https://hashkiller.co.uk/',
        'MD5Decrypt': 'https://md5decrypt.net/',
        'CMD5': 'https://www.cmd5.org/',
    }
    
    print("可用服务:")
    for name, url in services.items():
        print(f"    - {name}: {url}")
    
    print("\n[!] 注意：不要上传敏感哈希到在线服务")
```

## 2.5 漏洞利用绕过方法

### 2.5.1 绕过哈希校验

```python
#!/usr/bin/env python3
"""
绕过哈希校验的技术
"""

def bypass_hash_verification():
    """
    绕过哈希校验的方法
    """
    
    print("""
    方法 1: MD5/SHA1 碰撞
    
    适用场景:
    - 系统使用 MD5/SHA1 校验文件完整性
    - 攻击者可构造碰撞文件
    
    步骤:
    1. 使用 fastcoll 生成碰撞对
    2. 构造良性文件和恶意文件
    3. 两者哈希相同，绕过校验
    
    工具:
    - fastcoll
    - hashclash
    """)
    
    print("""
    方法 2: 长度扩展攻击
    
    适用场景:
    - 系统使用 MD5/SHA1/SHA256 进行消息认证
    - 格式：H(secret || message)
    
    原理:
    - Merkle-Damgård 构造的哈希函数存在长度扩展漏洞
    - 已知 H(x) 可计算 H(x || padding || extension)
    
    工具:
    - hashpump (https://github.com/bwall/HashPump)
    - 在线：https://www.kalitutorials.net/2017/09/length-extension-attacks.html
    
    示例:
    python hashpump.py -h <hash> -d <data> -s <suffix> -l <key_length>
    """)
    
    print("""
    方法 3: 哈希时间攻击
    
    适用场景:
    - 系统使用逐字节比较哈希
    - 比较时间与匹配长度成正比
    
    原理:
    - 测量哈希比较时间
    - 逐字节推断正确哈希值
    
    工具:
    - 自定义脚本
    - 需要精确计时
    """)

def length_extension_attack(hash_value, original_data, suffix, key_length=10):
    """
    长度扩展攻击示例
    
    使用 hashpump 库
    """
    
    try:
        import hashpump
        
        new_hash, new_data = hashpump.hashpump(
            hash_value,
            original_data,
            suffix,
            key_length
        )
        
        print(f"[+] 新哈希：{new_hash}")
        print(f"[+] 新数据：{new_data}")
        
        return new_hash, new_data
    except ImportError:
        print("[-] hashpump 未安装")
        print("    安装：pip install hashpumpy")
        return None, None
```

### 2.5.2 绕过加密检测

```python
#!/usr/bin/env python3
"""
绕过加密检测的技术
"""

def bypass_encryption_detection():
    """
    绕过加密检测的方法
    """
    
    print("""
    方法 1: 多层加密
    
    描述:
    - 外层使用强加密（AES-GCM）
    - 内层使用弱加密（用于绕过检测）
    - 检测工具只看到外层加密
    
    示例:
    plaintext -> 弱加密 -> 强加密 -> 传输
    
    防御:
    - 深度检测
    - 行为分析
    """)
    
    print("""
    方法 2: 动态密钥
    
    描述:
    - 每次会话使用不同密钥
    - 密钥通过安全通道协商
    - 静态分析无法获取密钥
    
    示例:
    - Diffie-Hellman 密钥交换
    - 基于时间的密钥派生
    
    防御:
    - 动态分析
    - 密钥提取
    """)
    
    print("""
    方法 3: 代码混淆
    
    描述:
    - 加密算法实现被混淆
    - 密钥被拆分存储
    - 增加逆向难度
    
    技术:
    - 控制流平坦化
    - 字符串加密
    - 反调试
    
    防御:
    - 动态插桩（Frida）
    - 符号执行
    - 耐心逆向
    """)
```

### 2.5.3 绕过速率限制

```python
#!/usr/bin/env python3
"""
绕过暴力破解速率限制
"""

def bypass_rate_limiting():
    """
    绕过速率限制的方法
    """
    
    print("""
    方法 1: 分布式攻击
    
    描述:
    - 使用多个 IP 地址
    - 使用代理池
    - 使用僵尸网络
    
    工具:
    - Proxychains
    - Tor 网络
    - 云函数（AWS Lambda 等）
    """)
    
    print("""
    方法 2: 凭证填充攻击
    
    描述:
    - 使用已泄露的凭证
    - 针对多个账户尝试
    - 绕过单账户速率限制
    
    防御:
    - 密码重用检测
    - 异常登录检测
    - MFA
    """)
    
    print("""
    方法 3: 离线破解
    
    描述:
    - 获取哈希数据库
    - 本地离线破解
    - 无速率限制
    
    获取方式:
    - SQL 注入
    - 备份泄露
    - 内部威胁
    """)
```

---

# 第三部分：附录

## 3.1 常用 Payload 速查表

| 类别 | 命令/代码 | 说明 |
|-----|----------|------|
| 检测 | `hashid <hash>` | 哈希类型识别 |
| 检测 | `nmap --script ssl-enum-ciphers` | TLS 加密套件检测 |
| 攻击 | `hashcat -m 0 hashes.txt` | MD5 破解 |
| 攻击 | `hashcat -m 100 hashes.txt` | SHA1 破解 |
| 攻击 | `john --format=raw-md5 hashes.txt` | John MD5 破解 |
| 碰撞 | `fastcoll -o file1.bin file2.bin` | MD5 碰撞生成 |
| 扩展 | `hashpump -h <hash> -d <data>` | 长度扩展攻击 |
| 工具 | `openssl enc -des -e` | DES 加密测试 |

## 3.2 哈希算法对比

| 算法 | 输出长度 | 安全性 | 推荐用途 |
|-----|---------|--------|---------|
| MD5 | 128 位 | ❌ 已破解 | 非安全校验 |
| SHA1 | 160 位 | ❌ 已破解 | 非安全校验 |
| SHA256 | 256 位 | ✅ 安全 | 通用哈希 |
| SHA384 | 384 位 | ✅ 安全 | 高安全需求 |
| SHA512 | 512 位 | ✅ 安全 | 高安全需求 |
| SHA3-256 | 256 位 | ✅ 安全 | 新一代标准 |
| bcrypt | 可变 | ✅ 安全 | 密码存储 |
| Argon2 | 可变 | ✅ 安全 | 密码存储（推荐） |
| scrypt | 可变 | ✅ 安全 | 密码存储 |

## 3.3 加密算法对比

| 算法 | 密钥长度 | 块大小 | 安全性 | 推荐用途 |
|-----|---------|--------|--------|---------|
| DES | 56 位 | 64 位 | ❌ 已破解 | 不应使用 |
| 3DES | 112/168 位 | 64 位 | ⚠️ 已弃用 | 遗留系统 |
| AES | 128/192/256 位 | 128 位 | ✅ 安全 | 通用加密 |
| RC4 | 可变 | 流密码 | ❌ 已破解 | 不应使用 |
| ChaCha20 | 256 位 | 流密码 | ✅ 安全 | 移动设备 |
| Blowfish | 可变 | 64 位 | ⚠️ 注意 | 一般用途 |
| Twofish | 可变 | 128 位 | ✅ 安全 | 通用加密 |

## 3.4 弱加密算法检测清单

- [ ] 检查是否使用 MD5/SHA1 进行安全相关操作
- [ ] 检查是否使用 DES/3DES/RC4 加密
- [ ] 检查 RSA 密钥长度是否≥2048 位
- [ ] 检查是否使用自定义加密算法
- [ ] 检查 TLS 配置是否禁用弱加密套件
- [ ] 检查密码存储是否使用 bcrypt/Argon2
- [ ] 检查是否使用 ECB 等不安全加密模式
- [ ] 检查哈希是否加盐

## 3.5 常用工具

| 工具 | 用途 | 链接 |
|-----|------|------|
| Hashcat | GPU 密码破解 | https://hashcat.net/ |
| John the Ripper | 密码破解 | https://www.openwall.com/john/ |
| hash-identifier | 哈希识别 | Kali 内置 |
| fastcoll | MD5 碰撞生成 | https://github.com/cr-marcstevens/fastcoll |
| hashpump | 长度扩展攻击 | https://github.com/bwall/HashPump |
| testssl.sh | TLS 配置检测 | https://testssl.sh/ |
| SSL Labs | 在线 TLS 测试 | https://ssllabs.com/ |

---

## 参考资源

- [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [NIST Cryptographic Standards](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines)
- [SHAttered: First SHA1 Collision](https://shattered.io/)
- [RFC 7465: Prohibiting RC4 Cipher Suites](https://tools.ietf.org/html/rfc7465)
