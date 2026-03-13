# 随机性检测

---

## 第一部分：文档概述

### 1.1 编写目的
本文档旨在为渗透测试人员提供随机性检测的方法论。通过本指南，测试人员可以评估系统生成的随机数的质量，发现伪随机数生成器（PRNG）的弱点，预测未来生成的随机值。

### 1.2 适用范围
本文档适用于以下场景：
- Session ID 生成质量评估
- CSRF Token 随机性检测
- 验证码随机性分析
- 加密密钥生成质量评估
- 抽奖系统公平性验证

### 1.3 读者对象
- 渗透测试工程师
- 密码学安全测试人员
- 安全研究员
- 代码审计人员

---

## 第二部分：核心渗透技术专题

### 专题一：随机性检测

#### 2.1 技术介绍

**随机性检测**是对系统生成的随机数或令牌进行统计分析，评估其不可预测性和熵值的过程。弱随机性可能导致会话劫持、CSRF 绕过、验证码预测等安全问题。

**随机性检测指标：**

| 指标 | 说明 | 理想值 |
|------|------|--------|
| 熵值 | 信息的不确定性 | 接近最大值 |
| 卡方检验 | 分布均匀性 | 接近自由度 |
| 算术平均值 | 字节平均值 | 127.5 |
| 蒙特卡洛 π | 随机性统计测试 | 接近 3.14159 |
| 序列相关性 | 相邻值相关性 | 接近 0 |

#### 2.2 检测常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 用户认证 | Session ID 生成 | 弱随机导致会话预测 |
| CSRF 保护 | CSRF Token | Token 可预测绕过保护 |
| 验证码 | 图形/短信验证码 | 验证码可预测 |
| 密码重置 | 重置令牌 | 令牌可预测导致账户接管 |
| 支付系统 | 交易 ID | 交易 ID 可预测 |
| 抽奖活动 | 随机抽奖 | 结果可操纵 |

#### 2.3 漏洞检测方法

##### 2.3.1 使用 ent 工具检测

```bash
# 收集随机数样本
# 例如收集 100 个 Session ID
for i in {1..100}; do
    curl -s -c - "https://target.com/login" | grep SESSIONID | awk '{print $NF}'
done > tokens.txt

# 转换为二进制
cat tokens.txt | xxd -r -p > tokens.bin

# 使用 ent 分析
ent tokens.bin

# 输出示例：
# Entropy = 7.921456 bits per byte (optimum = 8)
# Chi-square distribution = 256.34 (would be exceeded 50% of the time)
# Arithmetic mean value of data bytes = 127.3456 (127.5 = random)
# Monte Carlo value for Pi = 3.14159265 (error 0.00%)
# Serial correlation coefficient = 0.000012 (totally uncorrelated = 0.0)
```

##### 2.3.2 使用 Burp Sequencer 检测

```
1. 打开 Burp Suite → Sequencer 标签
2. 配置目标：
   - 选择包含随机 Token 的请求
   - 指定 Token 位置（Cookie、响应体、Header）
3. 捕获样本：
   - 至少捕获 1000 个样本
   - 建议捕获 5000+ 样本以获得准确结果
4. 分析结果：
   - 查看熵值随时间变化
   - 检查字符分布
   - 分析位级分布
   - 查看字符转换分析
5. 生成报告
```

##### 2.3.3 使用 Python 进行统计分析

```python
#!/usr/bin/env python3
"""
随机性统计分析脚本
"""
import math
from collections import Counter

def calculate_entropy(data):
    """计算香农熵"""
    counter = Counter(data)
    length = len(data)
    entropy = 0
    
    for count in counter.values():
        if count > 0:
            prob = count / length
            entropy -= prob * math.log2(prob)
    
    return entropy

def chi_square_test(data):
    """卡方检验"""
    counter = Counter(data)
    expected = len(data) / 256  # 假设字节数据
    
    chi_square = sum(
        (count - expected) ** 2 / expected 
        for count in counter.values()
    )
    
    return chi_square

def serial_correlation(data):
    """序列相关性"""
    if len(data) < 2:
        return 0
    
    mean = sum(data) / len(data)
    variance = sum((x - mean) ** 2 for x in data) / len(data)
    
    if variance == 0:
        return 0
    
    covariance = sum(
        (data[i] - mean) * (data[i+1] - mean) 
        for i in range(len(data) - 1)
    ) / (len(data) - 1)
    
    return covariance / variance

def analyze_randomness(hex_strings):
    """分析十六进制字符串的随机性"""
    # 转换为字节
    data = b''.join(bytes.fromhex(s) for s in hex_strings)
    
    print(f"[*] 样本大小：{len(data)} 字节")
    print(f"[*] 熵值：{calculate_entropy(data):.4f} bits/byte (最大 8.0)")
    print(f"[*] 卡方值：{chi_square_test(data):.2f}")
    print(f"[*] 序列相关性：{serial_correlation(data):.6f}")
    
    # 字符分布分析
    byte_counts = Counter(data)
    print(f"\n[*] 唯一字节数：{len(byte_counts)}/256")
    
    # 检测明显模式
    if len(set(hex_strings)) < len(hex_strings) * 0.9:
        print("[!] 警告：发现重复值")
    
    # 熵值评估
    entropy = calculate_entropy(data)
    if entropy < 7.0:
        print("[!] 警告：熵值过低，可能存在安全问题")
    elif entropy < 7.5:
        print("[⚠] 注意：熵值中等，建议进一步分析")
    else:
        print("[+] 熵值良好")

# 使用示例
tokens = [
    "5f4dcc3b5aa765d61d8327deb882cf99",
    "7c6a61c68ef8b9b6b061b28c348bc1a7",
    # ... 更多样本
]
analyze_randomness(tokens)
```

##### 2.3.4 NIST 统计测试套件

```bash
# 使用 NIST STS 测试套件
# 下载：https://csrc.nist.gov/projects/random-bit-generator-testing

# 编译
make

# 运行测试
./sts -ass 1000

# 测试结果解读
# p-value >= 0.01 表示通过测试
# 至少 96% 的测试应通过
```

##### 2.3.5 时间相关性检测

```python
#!/usr/bin/env python3
"""
检测随机数与时间的相关性
"""
import time
import hashlib
import requests

def timestamp_correlation_test(target_url, token_location='cookie'):
    """测试 Token 是否与时间戳相关"""
    
    tokens = []
    timestamps = []
    
    # 收集样本
    for i in range(100):
        if token_location == 'cookie':
            resp = requests.get(target_url)
            token = resp.cookies.get('session_id')
        else:
            resp = requests.get(target_url)
            token = resp.json().get('token')
        
        if token:
            tokens.append(token)
            timestamps.append(int(time.time() * 1000))  # 毫秒级
            time.sleep(0.1)
    
    # 分析 Token 中的时间成分
    print("[*] 分析 Token 中的时间相关性...")
    
    for i, token in enumerate(tokens):
        # 尝试用时间戳生成 Token
        ts = timestamps[i]
        
        # 测试常见模式
        patterns = [
            hashlib.md5(str(ts).encode()).hexdigest()[:16],
            hashlib.sha1(str(ts).encode()).hexdigest()[:16],
            hashlib.sha256(str(ts).encode()).hexdigest()[:16],
        ]
        
        for pattern in patterns:
            if pattern in token or token in pattern:
                print(f"[!] 发现时间相关性！")
                print(f"    Token: {token}")
                print(f"    时间戳：{ts}")
                return True
    
    print("[-] 未发现明显时间相关性")
    return False
```

#### 2.4 漏洞利用方法

##### 2.4.1 Session ID 预测攻击

```python
#!/usr/bin/env python3
"""
基于统计的 Session ID 预测
"""
from collections import Counter
import random

class SessionPredictor:
    def __init__(self, tokens):
        self.tokens = tokens
        self.token_length = len(tokens[0]) if tokens else 0
    
    def analyze_character_frequency(self):
        """分析字符频率"""
        print("[*] 字符频率分析:")
        
        for pos in range(min(10, self.token_length)):
            chars = [t[pos] for t in self.tokens if pos < len(t)]
            freq = Counter(chars)
            most_common = freq.most_common(5)
            print(f"    位置 {pos}: {most_common}")
    
    def detect_patterns(self):
        """检测模式"""
        print("\n[*] 模式检测:")
        
        # 检测递增/递减模式
        if all(t.isdigit() for t in self.tokens):
            int_tokens = [int(t) for t in self.tokens]
            diffs = [int_tokens[i+1] - int_tokens[i] 
                     for i in range(len(int_tokens)-1)]
            
            if len(set(diffs)) == 1:
                print(f"[!] 发现固定增量：{diffs[0]}")
                next_val = int_tokens[-1] + diffs[0]
                print(f"[+] 预测下一个值：{next_val}")
    
    def generate_candidates(self, num=10):
        """生成候选 Token"""
        # 基于字符频率生成
        char_freqs = []
        for pos in range(self.token_length):
            chars = [t[pos] for t in self.tokens if pos < len(t)]
            freq = Counter(chars)
            char_freqs.append(freq)
        
        candidates = []
        for _ in range(num):
            candidate = ''
            for freq in char_freqs:
                chars, weights = zip(*freq.most_common())
                candidate += random.choices(chars, weights=weights)[0]
            candidates.append(candidate)
        
        return candidates

# 使用示例
tokens = ["abc123", "abc124", "abc125", ...]  # 收集的 Token
predictor = SessionPredictor(tokens)
predictor.analyze_character_frequency()
predictor.detect_patterns()
candidates = predictor.generate_candidates(10)
print(f"\n候选 Token: {candidates}")
```

##### 2.4.2 验证码预测

```python
#!/usr/bin/env python3
"""
验证码预测攻击
"""
import requests
import re

def captcha_prediction_attack(target_url):
    """预测验证码"""
    
    # 收集验证码样本
    codes = []
    for i in range(100):
        resp = requests.get(f"{target_url}/captcha")
        code = resp.json().get('captcha_id')
        if code:
            codes.append(code)
    
    # 分析模式
    print("[*] 分析验证码模式...")
    
    # 检查长度
    lengths = set(len(c) for c in codes)
    print(f"    长度：{lengths}")
    
    # 检查字符集
    all_chars = set(''.join(codes))
    print(f"    字符集：{all_chars}")
    
    # 如果全是数字，尝试预测
    if all(c.isdigit() for c in codes):
        int_codes = [int(c) for c in codes]
        
        # 检查增量
        diffs = [int_codes[i+1] - int_codes[i] for i in range(len(int_codes)-1)]
        
        if len(set(diffs)) <= 3:  # 增量变化小
            print("[!] 验证码可能是递增的")
            
            # 预测下一个
            avg_diff = sum(diffs) / len(diffs)
            next_code = int(int_codes[-1] + avg_diff)
            print(f"[+] 预测下一个验证码：{next_code}")
    
    # 如果基于时间，尝试时间戳
    print("\n[*] 测试时间戳模式...")
    import time
    current_ts = int(time.time()) % 1000000  # 6 位时间戳
    print(f"    当前时间戳：{current_ts}")
```

##### 2.4.3 CSRF Token 预测

```python
#!/usr/bin/env python3
"""
CSRF Token 预测攻击
"""

def csrf_token_analysis(tokens):
    """分析 CSRF Token"""
    
    print("[*] CSRF Token 分析")
    print(f"    样本数：{len(tokens)}")
    print(f"    长度：{set(len(t) for t in tokens)}")
    
    # 熵值分析
    from collections import Counter
    import math
    
    all_chars = ''.join(tokens)
    counter = Counter(all_chars)
    entropy = -sum((c/len(all_chars)) * math.log2(c/len(all_chars)) 
                   for c in counter.values())
    
    print(f"    字符熵值：{entropy:.2f}")
    
    # 如果熵值低，Token 可能可预测
    if entropy < 4.0:
        print("[!] 警告：熵值过低，Token 可能可预测")
    
    # 检查是否包含时间成分
    import time
    current_ts = str(int(time.time()))
    for token in tokens[:10]:
        if current_ts[-6:] in token:
            print(f"[!] Token 可能包含时间戳成分")
            break

# 使用示例
# 从多个请求中收集 CSRF Token
tokens = ["abc123", "def456", ...]
csrf_token_analysis(tokens)
```

#### 2.5 安全随机数生成建议

##### 2.5.1 各语言安全 PRNG

```python
# Python
import secrets
token = secrets.token_hex(32)  # 64 字符十六进制

import os
token = os.urandom(32).hex()
```

```java
// Java
import java.security.SecureRandom;

SecureRandom random = new SecureRandom();
byte[] token = new byte[32];
random.nextBytes(token);
String tokenHex = bytesToHex(token);
```

```javascript
// Node.js
const crypto = require('crypto');
const token = crypto.randomBytes(32).toString('hex');

// 浏览器
const array = new Uint8Array(32);
crypto.getRandomValues(array);
```

```php
// PHP 7+
$token = bin2hex(random_bytes(32));

// 或使用 openssl
$token = bin2hex(openssl_random_pseudo_bytes(32));
```

##### 2.5.2 随机数安全检查清单

- [ ] 使用加密安全的 PRNG
- [ ] 种子来源有足够熵
- [ ] Token 长度至少 128 位（16 字节）
- [ ] 避免使用时间戳作为唯一种子
- [ ] 避免使用可预测信息（用户名、IP）
- [ ] 实施 Token 过期机制
- [ ] 每个会话/请求使用唯一 Token
- [ ] 定期重新播种 PRNG

---

## 第三部分：附录

### 3.1 随机性检测工具

| 工具 | 用途 |
|-----|------|
| ent | 熵值分析 |
| Burp Sequencer | 图形化随机性分析 |
| NIST STS | 统计测试套件 |
| Dieharder | 随机性测试 |
| Pratt's Randomness Test | 在线随机性测试 |

### 3.2 熵值评级

| 熵值 (bits/byte) | 评级 | 建议 |
|-----------------|------|------|
| 7.5 - 8.0 | 优秀 | 适合安全用途 |
| 7.0 - 7.5 | 良好 | 可用于一般用途 |
| 6.0 - 7.0 | 中等 | 不建议用于安全 |
| < 6.0 | 差 | 存在安全风险 |

### 3.3 最小 Token 长度建议

| 用途 | 最小长度 | 推荐长度 |
|-----|---------|---------|
| Session ID | 128 位 | 256 位 |
| CSRF Token | 128 位 | 256 位 |
| 密码重置令牌 | 128 位 | 256 位 |
| API Key | 256 位 | 512 位 |
| 加密密钥 | 256 位 | 256 位 |

---

## 参考资源

- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [NIST SP 800-90A - Random Number Generation](https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final)
- [Burp Suite Sequencer Documentation](https://portswigger.net/burp/documentation/desktop/tools/sequencer)
