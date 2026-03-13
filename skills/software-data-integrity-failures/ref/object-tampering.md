# 对象篡改攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的对象篡改攻击检测和利用流程。

## 1.2 适用范围

本文档适用于使用序列化对象传输数据的 Web 应用和 API 服务。

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

对象篡改是指攻击者修改在网络传输中的序列化对象，由于缺少完整性验证，服务端接受并处理了被篡改的对象。

**本质问题**：
- 序列化对象未签名
- 客户端可控对象内容
- 缺少完整性验证

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-915 | 动态确定对象属性的修改控制不当 |
| CWE-345 | 数据真实性验证不足 |
| CWE-502 | 不可信数据的反序列化 |

## 2.2 攻击常见于哪些业务场景

| 场景 | 风险点 | 潜在危害 |
|-----|-------|---------|
| ViewState | ASP.NET ViewState | 权限提升 |
| 序列化 Cookie | 用户状态 Cookie | 会话劫持 |
| 隐藏字段 | 表单隐藏字段 | 参数篡改 |
| API 响应 | JSON/XML 对象 | 数据篡改 |
| 本地存储 | localStorage/SessionStorage | 状态篡改 |

## 2.3 漏洞发现方法

### 2.3.1 序列化对象识别

```bash
# ASP.NET ViewState
__VIEWSTATE=/wEPDwUK...

# Java 序列化
Cookie: session=rO0ABXNyABFqYXZhLnV0aWwu...

# PHP 序列化
Cookie: data=TzoyNDoiQ29va2llUG9wdGVk...

# Base64 JSON
Cookie: user=eyJ1c2VyX2lkIjogMTIzfQ==
```

### 2.3.2 对象内容分析

```bash
# 解码 Base64 内容
echo "eyJ1c2VyX2lkIjogMTIzfQ==" | base64 -d
# 输出：{"user_id": 123}

# 分析对象结构
# 识别可修改的字段
# 识别权限相关字段
```

### 2.3.3 完整性验证测试

```bash
# 1. 获取原始对象
# 2. 修改对象内容
# 3. 重新编码发送
# 4. 如果服务器接受，缺少完整性验证
```

## 2.4 漏洞利用方法

### 2.4.1 权限字段篡改

```javascript
// 原始对象
{
    "user_id": 123,
    "username": "user1",
    "role": "user",
    "permissions": ["read"]
}

// 篡改后
{
    "user_id": 1,
    "username": "admin",
    "role": "admin",
    "permissions": ["read", "write", "delete"]
}
```

### 2.4.2 价格字段篡改

```javascript
// 电商订单对象
{
    "order_id": "12345",
    "items": [{"id": 1, "price": 99.99}],
    "total": 99.99
}

// 篡改后
{
    "order_id": "12345",
    "items": [{"id": 1, "price": 0.01}],
    "total": 0.01
}
```

### 2.4.3 状态字段篡改

```javascript
// 订单状态对象
{
    "order_id": "12345",
    "status": "pending_payment",
    "paid": false
}

// 篡改后
{
    "order_id": "12345",
    "status": "completed",
    "paid": true
}
```

### 2.4.4 ASP.NET ViewState 篡改

```bash
# 如果 ViewState 未启用 MAC
# 可以修改 ViewState 内容

# 1. 解码 ViewState
# 2. 修改隐藏字段值
# 3. 重新编码
# 4. 提交表单
```

### 2.4.5 会话对象篡改

```javascript
// 会话 Cookie
{
    "session_id": "abc123",
    "user_id": 123,
    "logged_in": true,
    "is_admin": false
}

// 篡改后
{
    "session_id": "abc123",
    "user_id": 1,
    "logged_in": true,
    "is_admin": true
}
```

## 2.5 漏洞利用绕过方法

### 2.5.1 简单编码绕过

```bash
# 如果仅 Base64 编码
# 直接解码修改后重新编码

# 如果使用了压缩
# 先解压，修改，再压缩
```

### 2.5.2 签名验证绕过

```bash
# 如果签名验证存在缺陷：
# 1. 签名与对象分离
# 2. 签名算法弱
# 3. 签名密钥泄露
# 4. 签名验证逻辑缺陷
```

### 2.5.3 嵌套对象篡改

```bash
# 如果对象有嵌套结构
# 修改深层嵌套字段
# 可能绕过浅层验证
```

---

# 第三部分：附录

## 3.1 对象篡改测试检查清单

```
□ 识别序列化对象
□ 解码对象内容
□ 分析对象结构
□ 测试完整性验证
□ 测试签名验证
□ 篡改权限字段
□ 篡改状态字段
□ 篡改数据字段
```

## 3.2 常用工具

| 工具 | 用途 | 链接 |
|-----|------|------|
| Burp Suite | 请求拦截和修改 | https://portswigger.net/burp |
| ViewState Editor | ASP.NET ViewState 分析 | Burp 扩展 |
| CyberChef | 数据编码解码 | https://gchq.github.io/CyberChef/ |
| 序列化分析工具 | 各语言序列化分析 | 语言特定工具 |

## 3.3 修复建议

1. **数字签名** - 对所有序列化对象签名
2. **完整性验证** - 使用 HMAC 验证完整性
3. **服务端状态** - 敏感状态存储在服务端
4. **输入验证** - 验证反序列化对象内容

---

**参考资源**：
- [OWASP Cheat Sheet: Deserialization](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [CWE-915](https://cwe.mitre.org/data/definitions/915.html)
