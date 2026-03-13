# 会话安全测试方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的会话管理安全测试流程。

## 1.2 适用范围

本文档适用于所有使用会话管理机制的 Web 应用和 API 接口。

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 测试范围

会话安全测试涵盖以下方面：
- 会话 ID 生成和熵值
- 会话生命周期管理
- 会话传输安全
- 会话存储安全

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-384 | 会话固定 |
| CWE-613 | 会话过期不足 |
| CWE-614 | Cookie 中的敏感信息 |

## 2.2 测试检查点

| 测试领域 | 检查项 | 风险等级 |
|---------|-------|---------|
| 会话 ID | 随机性/可预测性 | 高 |
| 会话生命周期 | 超时/失效机制 | 高 |
| 会话传输 | HTTPS/Secure 标志 | 高 |
| 会话存储 | HttpOnly/SameSite | 中 |

## 2.3 测试方法

### 2.3.1 会话 ID 熵值测试

```bash
# 收集多个会话 ID
for i in {1..50}; do
    curl -s -c - https://target.com | grep sessionid
done

# 分析：
# 1. 检查长度（至少 128 位）
# 2. 检查字符集（大小写字母 + 数字）
# 3. 检查随机性（无模式）
```

### 2.3.2 会话超时测试

```bash
# 1. 登录获取会话
# 2. 等待一段时间
# 3. 尝试使用会话

# 测试：
# - 空闲超时（无操作后过期）
# - 绝对超时（登录后固定时间过期）
```

### 2.3.3 会话失效测试

```bash
# 1. 登录获取会话
# 2. 执行注销
# 3. 尝试使用原会话

# 检查服务端是否正确销毁会话
```

### 2.3.4 Cookie 标志测试

```bash
# 检查 Set-Cookie 响应头
Set-Cookie: sessionid=xxx; HttpOnly; Secure; SameSite=Strict

# 检查标志：
# - HttpOnly: 防止 XSS 窃取
# - Secure: 仅 HTTPS 传输
# - SameSite: 防止 CSRF
```

## 2.4 漏洞利用方法

### 2.4.1 会话预测

```python
# 分析会话 ID 模式
import re
import requests

sessions = []
for i in range(100):
    r = requests.get('https://target.com')
    # 提取会话 ID 并分析模式
```

### 2.4.2 会话固定

```bash
# 1. 获取会话 ID
# 2. 诱使用户使用该会话 ID 登录
# 3. 使用原会话 ID 访问
```

### 2.4.3 会话劫持

```bash
# 通过网络嗅探、XSS 等方式窃取会话 ID
# 使用窃取的会话 ID 冒充用户
```

---

# 第三部分：附录

## 3.1 会话安全测试检查清单

```
□ 会话 ID 熵值测试
□ 会话超时测试
□ 会话失效测试
□ Cookie 标志检查
□ 会话固定测试
□ 并发会话测试
□ 会话绑定测试
```

## 3.2 修复建议

1. **强随机会话 ID** - 使用 CSPRNG 生成
2. **安全标志** - HttpOnly, Secure, SameSite
3. **合理超时** - 空闲和绝对超时
4. **登录后更新** - 认证后生成新会话 ID

---

**参考资源**：
- [OWASP Cheat Sheet: Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [PortSwigger - Session Security](https://portswigger.net/web-security/session-management)
