# **渗透测试方法论：会话固定检测**

---

# **第一部分：文档概述**

## 1.1 编写目的
- 为渗透测试人员提供一套标准化的会话固定漏洞检测和利用流程
- 帮助测试人员系统性地发现会话固定攻击风险
- 提高会话固定漏洞发现的准确率和效率

## 1.2 适用范围
- 适用于所有使用会话机制的 Web 应用
- 适用于基于 Cookie、URL 重写的会话管理
- 适用于各种需要维持认证状态的业务场景

## 1.3 读者对象
- 本文件主要面向执行渗透测试任务的安全工程师、安全分析师
- 负责会话管理模块开发的开发人员
- 负责代码审计和安全加固的技术人员

---

# **第二部分：核心渗透技术专题**

## 专题一：会话固定检测

### 2.1 技术介绍

会话固定（Session Fixation）是指攻击者诱导受害者使用攻击者预设的会话标识（Session ID）进行认证，从而在受害者登录后能够劫持其会话的攻击方式。其本质是**系统未在认证后重新生成会话标识，导致攻击者能够预测或控制有效会话**。

会话固定攻击流程：

```
1. 攻击者获取一个有效 Session ID
   GET https://target.com/login → SessionID: ATTACKER_SID

2. 攻击者诱导受害者使用该 Session ID
   https://target.com/login?sessionid=ATTACKER_SID
   或通过 XSS 设置 Cookie: sessionid=ATTACKER_SID

3. 受害者使用该 Session ID 登录

4. 攻击者使用该 Session ID 访问受害者账户
   GET https://target.com/profile
   Cookie: sessionid=ATTACKER_SID
```

### 2.2 测试常见于哪些业务场景

| **业务场景** | **功能示例** | **风险点描述** |
| :--- | :--- | :--- |
| **登录流程** | 用户登录 | 登录后未重新生成 Session ID |
| **单点登录** | SSO 认证 | SSO 回调后未更新会话 |
| **权限提升** | 普通用户提升权限 | 权限变更后未更新会话 |
| **多因素认证** | MFA 验证 | MFA 前后使用同一会话 |
| **账户切换** | 切换账户功能 | 切换后未更新会话 |
| **访客转登录** | 访客登录后变正式用户 | 未重新生成会话 |
| **API 认证** | API Token 升级 | Token 升级后未失效旧 Token |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

- **会话固定测试**
  - 访问登录页面获取 Session ID
  - 记录 Session ID 值
  - 使用该 Session ID 登录
  - 检查登录后 Session ID 是否变化
  - 如果未变化，存在会话固定漏洞

- **Cookie 注入测试**
  - 尝试通过 URL 参数设置 Session ID
  - 尝试通过 POST 数据设置 Session ID
  - 尝试通过 JavaScript 设置 Cookie
  - 测试系统是否接受外部设置的 Session ID

- **会话跟踪测试**
  - 登录前记录 Session ID
  - 登录后检查 Session ID
  - 检查 Session ID 与用户的绑定关系
  - 测试会话是否可跨用户使用

- **多浏览器测试**
  - 在浏览器 A 获取 Session ID
  - 在浏览器 B 使用该 Session ID 登录
  - 在浏览器 A 检查是否可访问

#### 2.3.2 白盒测试

- **代码审计**
  - 检查登录成功后是否重新生成 Session ID
  - 审计会话创建逻辑
  - 检查权限变更时的会话处理
  - 查找会话固定相关代码

- **配置检查**
  - 检查会话配置
  - 审计 Cookie 配置
  - 检查会话存储机制
  - 检查会话绑定配置

### 2.4 漏洞利用方法

#### 2.4.1 基础信息收集

```bash
# 步骤 1：访问登录页面获取 Session ID
curl -c cookies.txt https://target.com/login
grep session cookies.txt

# 步骤 2：使用获取的 Session ID 登录
curl -b cookies.txt -X POST https://target.com/login \
  -d "username=attacker&password=password"

# 步骤 3：检查登录后的 Session ID
curl -c cookies.txt -b cookies.txt https://target.com/profile
# 检查 Session ID 是否变化
```

#### 2.4.2 会话固定攻击

| **攻击方法** | **描述** | **成功率** |
| :--- | :--- | :--- |
| URL 参数 | `?sessionid=ATTACKER_SID` | 中 |
| Cookie 注入 | 通过 XSS 设置 Cookie | 中 - 高 |
| Form 提交 | 通过表单提交 Session ID | 低 - 中 |
| HTTP Header | 通过 Header 设置 | 低 |
| Meta 标签 | 通过 Meta 标签设置 Cookie | 低 |

#### 2.4.3 攻击场景

```
场景 1：钓鱼攻击
1. 攻击者访问目标网站获取 Session ID
2. 构造钓鱼链接：https://target.com/login?sessionid=ATTACKER_SID
3. 诱导受害者点击链接并登录
4. 攻击者使用相同 Session ID 访问受害者账户

场景 2：XSS 辅助攻击
1. 攻击者在目标网站发现 XSS 漏洞
2. 通过 XSS 注入代码设置 Cookie：
   <script>document.cookie="sessionid=ATTACKER_SID"</script>
3. 诱导受害者访问并登录
4. 攻击者劫持会话

场景 3：中间人攻击
1. 攻击者在网络中拦截请求
2. 修改响应中的 Session ID
3. 受害者使用攻击者设置的 Session ID 登录
4. 攻击者劫持会话
```

#### 2.4.4 利用脚本

```python
# 会话固定检测脚本
import requests

# 步骤 1：获取 Session ID
session = requests.Session()
response = session.get("https://target.com/login")
original_sid = session.cookies.get("sessionid")
print(f"Original Session ID: {original_sid}")

# 步骤 2：登录
login_data = {"username": "testuser", "password": "password"}
response = session.post("https://target.com/login", data=login_data)

# 步骤 3：检查 Session ID 是否变化
new_sid = session.cookies.get("sessionid")
print(f"New Session ID: {new_sid}")

if original_sid == new_sid:
    print("[!] VULNERABLE: Session ID not regenerated after login!")
else:
    print("[+] Session ID regenerated after login.")
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过会话重新生成

- **会话恢复** - 如果系统支持会话恢复
- **多会话** - 如果系统允许多个有效会话
- **会话共享** - 如果会话可跨用户共享

#### 2.5.2 绕过检测机制

- **低频使用** - 降低使用频率
- **正常行为模拟** - 模拟正常用户行为
- **时间窗口** - 在会话过期前使用

#### 2.5.3 绕过会话绑定

- **IP 欺骗** - 如果绑定 IP
- **User-Agent 伪造** - 如果绑定 UA
- **指纹伪造** - 如果绑定设备指纹

---

# **第三部分：附录**

## 3.1 会话固定检测检查清单

| **检查项** | **测试方法** | **预期结果** |
| :--- | :--- | :--- |
| 登录重新生成 | 登录前后对比 Session ID | 应重新生成 |
| 权限变更重新生成 | 修改权限后检查 | 应重新生成 |
| MFA 重新生成 | MFA 前后检查 | 应重新生成 |
| Cookie 注入 | 尝试设置 Cookie | 应拒绝 |
| URL 参数注入 | 尝试 URL 参数 | 应拒绝 |
| 会话绑定 | 检查会话与用户绑定 | 应严格绑定 |
| 会话超时 | 检查会话超时 | 应合理超时 |
| 注销失效 | 注销后检查会话 | 应完全失效 |

## 3.2 会话固定测试工具

| **工具名称** | **用途** | **命令示例** |
| :--- | :--- | :--- |
| **Burp Suite** | 拦截/修改请求 | 手动测试 |
| **OWASP ZAP** | 自动化扫描 | Session 测试 |
| **浏览器 DevTools** | Cookie 检查 | 开发者工具 |
| **curl** | 命令行测试 | `curl -c/-b cookies.txt` |
| **自定义脚本** | 自动化检测 | Python 脚本 |

## 3.3 修复建议

1. **登录重新生成** - 登录成功后立即重新生成 Session ID
2. **权限变更重新生成** - 权限变更时重新生成会话
3. **拒绝外部 Session ID** - 不接受 URL/表单传递的 Session ID
4. **Cookie 安全属性** - 设置 HttpOnly、Secure、SameSite
5. **会话绑定** - 考虑绑定 IP、User-Agent 等
6. **会话超时** - 设置合理的超时时间
7. **注销销毁** - 注销时完全销毁会话
8. **审计日志** - 记录会话相关事件
9. **HTTPS 强制** - 所有会话流量使用 HTTPS
10. **输入验证** - 验证所有会话相关输入
