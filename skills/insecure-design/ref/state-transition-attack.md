# 状态转换攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的状态转换攻击检测和利用流程。

## 1.2 适用范围

本文档适用于所有具有状态机设计的 Web 应用，如订单系统、审批流程等。

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

状态转换攻击是指攻击者通过绕过预期的状态机流程，直接访问或修改系统状态，从而执行未授权的操作。

**本质问题**：
- 状态验证在服务端缺失
- 状态转换逻辑缺陷
- 缺少状态历史记录

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-840 | 业务逻辑缺陷 |
| CWE-284 | 不当访问控制 |

## 2.2 攻击常见于哪些业务场景

| 场景 | 风险点 | 潜在危害 |
|-----|-------|---------|
| 订单系统 | 订单状态流转 | 跳过支付直接完成 |
| 审批流程 | 审批状态变更 | 绕过审批直接通过 |
| 账户验证 | 验证状态流转 | 跳过验证直接使用 |
| 支付流程 | 支付状态变更 | 跳过支付步骤 |
| 物流系统 | 物流状态更新 | 伪造发货/签收 |

## 2.3 漏洞发现方法

### 2.3.1 状态机识别

```
识别系统的状态流转：

正常订单流程：
pending → paid → shipped → completed
   ↓        ↓
cancelled  refunded

攻击者尝试：
pending → shipped (跳过支付)
pending → completed (跳过多个步骤)
```

### 2.3.2 直接状态修改测试

```bash
# 尝试直接修改状态参数
POST /api/order/update
{
    "order_id": "12345",
    "status": "shipped"  # 从 pending 直接到 shipped
}

# 检查响应：
# - 如果成功，存在漏洞
# - 如果失败，检查错误消息
```

### 2.3.3 状态参数探测

```bash
# 识别状态参数名称
# status, state, order_status, payment_status

# 尝试不同值
curl -X POST https://target.com/api/order \
    -d "status=pending"
curl -X POST https://target.com/api/order \
    -d "status=paid"
curl -X POST https://target.com/api/order \
    -d "status=completed"
```

## 2.4 漏洞利用方法

### 2.4.1 跳过支付

```
场景：电商订单

正常流程：
1. 创建订单 (pending)
2. 支付 (paid)
3. 发货 (shipped)
4. 完成 (completed)

攻击流程：
1. 创建订单 (pending)
2. 直接修改状态为 paid 或 completed
3. 订单被视为已支付
4. 商家发货
```

### 2.4.2 绕过审批

```
场景：费用报销审批

正常流程：
submitted → manager_approved → finance_approved → paid

攻击流程：
1. 提交报销 (submitted)
2. 直接修改为 finance_approved
3. 绕过 manager 审批
4. 财务付款
```

### 2.4.3 账户验证绕过

```
场景：账户邮箱验证

正常流程：
registered → email_sent → email_verified → active

攻击流程：
1. 注册账户 (registered)
2. 直接修改为 email_verified
3. 绕过邮箱验证
4. 账户激活
```

### 2.4.4 物流状态伪造

```
场景：电商平台

攻击流程：
1. 创建订单
2. 修改物流状态为 shipped
3. 修改为 delivered
4. 确认收货
5. 资金打给卖家（但实际未发货）
```

## 2.5 漏洞利用绕过方法

### 2.5.1 服务端验证绕过

```bash
# 如果服务端验证状态转换
# 尝试：
# - 不同 HTTP 方法
# - 不同 API 版本
# - 不同端点
```

### 2.5.2 并发状态修改

```bash
# 并发发送多个状态修改请求
# 利用竞态条件
# 可能绕过状态检查
```

### 2.5.3 状态回退攻击

```bash
# 尝试将状态回退到之前的状态
# completed → pending
# 可能用于：
# - 重复使用优惠券
# - 重新触发支付
```

---

# 第三部分：附录

## 3.1 状态转换测试检查清单

```
□ 识别状态机设计
□ 绘制状态流转图
□ 测试直接状态修改
□ 测试状态跳过
□ 测试状态回退
□ 测试并发状态修改
□ 检查服务端验证
```

## 3.2 常用工具

| 工具 | 用途 | 链接 |
|-----|------|------|
| Burp Suite | 请求篡改 | https://portswigger.net/burp |
| OWASP ZAP | 自动化扫描 | https://www.zaproxy.org/ |
| 状态机可视化工具 | 绘制状态图 | 各种在线工具 |

## 3.3 修复建议

1. **服务端状态验证** - 所有状态转换在服务端验证
2. **状态机实现** - 使用状态机模式实现
3. **状态历史记录** - 记录所有状态变更
4. **审计日志** - 记录状态变更操作

---

**参考资源**：
- [OWASP Testing Guide - Business Logic](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger - Business Logic Vulnerabilities](https://portswigger.net/web-security/logic-flaws)
