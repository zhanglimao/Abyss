# 事务完整性测试方法论文档

---

# 第一部分：文档概述

## 1.1 编写目的

阐述事务完整性测试的方法论，为测试人员提供一套标准化、可复现的事务完整性测试流程。帮助安全工程师发现应用程序在事务处理过程中数据一致性、操作原子性方面的安全缺陷。

## 1.2 适用范围

本文档适用于以下场景：
- 涉及多步骤操作的 Web 应用和 API 服务
- 金融交易、电商订单等业务系统
- 需要保证数据一致性的关键业务
- 使用分布式事务的微服务架构

## 1.3 读者对象

- 执行渗透测试任务的安全工程师
- 安全分析师
- 负责代码审计的开发人员
- 数据库管理员

---

# 第二部分：核心渗透技术专题

## 专题一：事务完整性测试

### 2.1 技术介绍

事务完整性测试针对应用程序在事务处理过程中的数据一致性进行安全测试，包括：
- 操作的原子性保证
- 数据一致性验证
- 隔离级别正确性
- 持久性保证
- 分布式事务协调

**漏洞本质：** 事务管理不当导致部分操作成功、部分操作失败，造成数据不一致和业务逻辑错误。

| 完整性问题 | 描述 | 安全风险 |
|-----------|------|---------|
| 部分提交 | 多步操作部分成功 | 数据不一致 |
| 脏数据入库 | 无效数据被保存 | 业务逻辑错误 |
| 状态不一致 | 关联数据状态不同步 | 业务异常 |
| 计数不准 | 累计/统计值错误 | 财务损失 |
| 外键违反 | 关联关系破坏 | 数据孤立 |

### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 订单处理 | 下单、支付、发货 | 订单状态与支付状态不一致 |
| 账户转账 | 扣款、入账 | 金额不一致、资金丢失 |
| 库存管理 | 扣减库存、生成订单 | 超卖、库存负数 |
| 积分系统 | 消费积分、赠送积分 | 积分计算错误 |
| 多级审批 | 多级审核流程 | 审批状态混乱 |
| 数据同步 | 主从数据同步 | 数据不一致 |
| 批量操作 | 批量导入、更新 | 部分成功部分失败 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**事务完整性探测技术：**

| 探测方法 | 操作说明 | 预期观察 |
|---------|---------|---------|
| 中断测试 | 在事务执行中断开 | 检查数据最终状态 |
| 异常注入 | 注入触发异常的输入 | 检查回滚行为 |
| 并发测试 | 并发修改关联数据 | 检查一致性 |
| 边界测试 | 在事务边界操作 | 检查原子性 |
| 超时测试 | 触发事务超时 | 检查回滚 |

**探测步骤：**
1. 识别目标系统的事务操作链
2. 分析各步骤之间的依赖关系
3. 设计中断或异常触发方案
4. 执行测试并记录数据状态
5. 验证数据一致性和完整性

**探测 Payload 示例：**

```http
# 1. 订单处理中断测试
# 步骤 1: 创建订单
POST /api/order/create
{"items": [...], "total": 100}

# 步骤 2: 在支付前断开连接
# 步骤 3: 检查订单状态
GET /api/order/123

# 预期：订单状态应为"待支付"或已取消
# 实际可能：订单状态为"处理中"，库存已扣减

# 2. 转账异常注入
POST /api/transfer
{
  "from": "account_A",
  "to": "account_B",
  "amount": -100  # 负数触发异常
}

# 检查：
# - A 账户余额是否恢复
# - B 账户余额是否未变
# - 是否有悬挂事务

# 3. 库存并发测试
# 商品库存 = 1
# 并发发起 2 个订单
POST /api/order  # 请求 1
POST /api/order  # 请求 2

# 检查：
# - 库存是否为 -1（超卖）
# - 两个订单是否都成功
```

#### 2.3.2 白盒测试

**代码审计检查点：**

```java
// 高危代码示例 1：缺少事务边界
public void processOrder(Order order) {
    // 没有事务注解
    orderRepository.save(order);      // 成功
    inventoryService.deduct(order);   // 成功
    paymentService.charge(order);     // 抛出异常
    // 前两步已提交，无法回滚
}

// 高危代码示例 2：捕获异常后未处理
@Transactional
public void transfer(Account from, Account to, double amount) {
    try {
        from.withdraw(amount);
        to.deposit(amount);
    } catch (Exception e) {
        log.error(e);
        // 没有重新抛出，事务可能提交
    }
}

// 高危代码示例 3：非原子操作
public void updateBalance(String accountId, double amount) {
    // 读取和更新不是原子操作
    double balance = getBalance(accountId);
    // 这里可能被其他事务修改
    setBalance(accountId, balance + amount);
}

// 高危代码示例 4：分布式事务不一致
public void processDistributedTransaction() {
    // 本地事务
    localDatabase.update();
    
    // 远程调用（不在同一事务中）
    remoteService.process();  // 可能失败
    
    // 本地已提交，远程失败
}

// 高危代码示例 5：异步操作不一致
@Transactional
public void placeOrder(Order order) {
    orderRepository.save(order);
    inventoryService.deduct(order);
    // 异步发送通知，订单可能回滚但通知已发送
    eventPublisher.publish(new OrderCreatedEvent(order));
}
```

**审计关键词：**
- `@Transactional` - 事务边界
- `Propagation.REQUIRES_NEW` - 新事务
- `Propagation.NESTED` - 嵌套事务
- `isolation` - 隔离级别
- `rollbackFor` - 回滚条件
- `async` / `@Async` - 异步操作

### 2.4 漏洞利用方法

#### 2.4.1 部分提交攻击

**利用场景：** 多步骤业务流程

```
攻击步骤：
1. 识别业务流程的多个步骤
2. 在关键步骤后触发异常
3. 如果回滚不完整：
   - 部分操作已提交
   - 部分操作已回滚
   - 数据状态不一致

示例 - 电商订单：
T1: 创建订单 ✓
T2: 扣减库存 ✓
T3: 冻结资金 → 触发异常
T4: 回滚失败
结果：订单创建、库存扣减，但支付未完成
```

#### 2.4.2 状态不一致攻击

**利用场景：** 订单状态管理

```http
攻击步骤：
1. 创建订单，状态为"待支付"
2. 直接调用支付成功回调
3. 如果状态检查缺失：
   - 订单状态变为"已支付"
   - 但实际支付可能未完成

Payload:
POST /api/payment/callback
{
  "order_id": "123",
  "status": "success",
  "amount": 0.01  # 篡改金额
}
```

#### 2.4.3 计数不一致攻击

**利用场景：** 累计值更新

```
攻击步骤：
1. 分析计数器的更新逻辑
2. 在更新过程中触发异常
3. 如果计数器未正确回滚：
   - 主数据已更新
   - 计数器未更新（或反之）
   - 累计值与实际不符

示例：
- 订单金额总和 ≠ 实际订单金额之和
- 积分余额 ≠ 积分明细之和
- 统计报表与实际数据不符
```

#### 2.4.4 分布式事务攻击

**利用场景：** 微服务架构

```
攻击步骤：
1. 识别跨服务的事务流程
2. 在远程调用时触发异常
3. 如果分布式事务协调失败：
   - 服务 A 事务提交
   - 服务 B 事务回滚
   - 数据跨服务不一致

示例：
- 订单服务：订单已创建
- 库存服务：库存未扣减
- 支付服务：支付未完成
```

#### 2.4.5 外键违反攻击

**利用场景：** 关联数据删除

```
攻击步骤：
1. 找到有外键关联的数据
2. 尝试删除父记录
3. 如果外键检查缺失：
   - 父记录被删除
   - 子记录成为孤儿数据
   - 查询时可能出错

示例：
- 删除用户，但用户订单仍在
- 删除商品，但订单明细仍在
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过事务监控

**场景：** 系统有事务审计日志

**绕过方法：**
```
1. 在事务提交前取消
2. 利用异步日志时间差
3. 触发异常使日志记录失败
```

#### 2.5.2 利用最终一致性

**场景：** 分布式系统使用最终一致性

**绕过方法：**
```
1. 利用数据同步的时间窗口
2. 在同步前发起多次操作
3. 可能导致重复或不一致
```

---

# 第三部分：附录

## 3.1 事务完整性检测清单

| 检查项 | 检测方法 | 风险等级 |
|-------|---------|---------|
| 事务边界缺失 | 代码审计 | 高 |
| 异常吞没 | 代码审计 | 高 |
| 非原子操作 | 代码审计 + 测试 | 高 |
| 分布式事务 | 架构分析 | 高 |
| 异步操作 | 代码审计 | 中 |
| 外键约束 | 数据库检查 | 中 |

## 3.2 安全事务处理建议

```java
// 推荐做法

// 1. 明确事务边界
@Transactional(rollbackFor = Exception.class)
public void processOrder(Order order) {
    orderRepository.save(order);
    inventoryService.deduct(order);
    paymentService.charge(order);
    // 任何异常都会回滚
}

// 2. 使用合适的传播行为
@Transactional(propagation = Propagation.REQUIRED)
public void mainTransaction() {
    // 主事务
}

@Transactional(propagation = Propagation.REQUIRES_NEW)
public void independentTransaction() {
    // 独立事务，不受外部影响
}

// 3. 确保数据一致性
public void transfer(Account from, Account to, double amount) {
    // 使用数据库原子操作
    jdbcTemplate.update(
        "UPDATE accounts SET balance = balance - ? WHERE id = ?",
        amount, from.getId()
    );
    jdbcTemplate.update(
        "UPDATE accounts SET balance = balance + ? WHERE id = ?",
        amount, to.getId()
    );
}

// 4. 处理分布式事务
// 使用 Saga 模式或 TCC 模式
public void processDistributedTransaction() {
    try {
        // 尝试阶段
        orderService.tryCreateOrder();
        inventoryService.tryDeduct();
        paymentService.tryCharge();
        
        // 确认阶段
        orderService.confirmOrder();
        inventoryService.confirmDeduct();
        paymentService.confirmCharge();
    } catch (Exception e) {
        // 取消阶段
        orderService.cancelOrder();
        inventoryService.cancelDeduct();
        paymentService.cancelCharge();
    }
}

// 5. 异步操作的事务处理
@Transactional
public void placeOrder(Order order) {
    orderRepository.save(order);
    inventoryService.deduct(order);
    // 使用事务内事件，事务提交后才发布
    transactionSynchronizationManager.registerSynchronization(
        new TransactionSynchronization() {
            @Override
            public void afterCommit() {
                eventPublisher.publish(new OrderCreatedEvent(order));
            }
        }
    );
}
```

## 3.3 事务完整性测试工具

| 工具 | 用途 |
|-----|------|
| JMeter | 并发事务测试 |
| 自定义脚本 | 精确控制测试流程 |
| 数据库监控 | 观察事务状态 |
| 日志分析 | 追踪事务流程 |
