# 垂直权限提升攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的垂直权限提升攻击检测与利用流程。

## 1.2 适用范围

本文档适用于所有具有角色/权限分级机制的 Web 应用和 API 接口。

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

垂直权限提升是指低权限用户（如普通用户）通过利用系统漏洞获取高权限（如管理员）的访问能力。

**本质问题**：
- 权限检查缺失或缺陷
- 角色信息客户端可控
- 管理功能未正确保护

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-269 | 不当权限管理 |
| CWE-284 | 不当访问控制 |
| CWE-639 | 参数化访问控制不当 |

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 用户管理 | 角色分配 | 用户可修改自己角色 |
| 管理后台 | 系统配置 | 管理 URL 未保护 |
| API 接口 | 管理 API | 缺少权限验证 |
| 功能菜单 | 管理功能 | 前端隐藏但未服务端验证 |

## 2.3 漏洞发现方法

### 2.3.1 角色参数检测

```bash
# 检查用户资料请求
GET /api/profile
{
    "id": 123,
    "username": "user1",
    "role": "user"  // 尝试改为 "admin"
}

# 修改后重新发送
POST /api/profile/update
{
    "role": "admin"
}
```

### 2.3.2 管理功能探测

```bash
# 常见管理路径
/admin
/administrator
/manage
/console
/admin/users
/admin/settings
```

### 2.3.3 API 权限测试

```bash
# 以普通用户身份测试管理 API
GET /api/admin/users  → 403
GET /api/users        → 200

# 尝试访问管理端点
POST /api/admin/create-user
```

## 2.4 漏洞利用方法

### 2.4.1 角色篡改

```bash
# 修改请求中的角色参数
POST /api/user/update
{
    "userId": 123,
    "role": "admin",      // 从 "user" 改为 "admin"
    "permissions": ["*"]  // 添加所有权限
}
```

### 2.4.2 权限 ID 遍历

```bash
# 遍历角色/权限 ID
GET /api/roles/1  # 普通用户
GET /api/roles/2  # VIP 用户
GET /api/roles/3  # 管理员
GET /api/roles/4  # 超级管理员
```

### 2.4.3 管理功能直接访问

```bash
# 直接访问管理功能
GET /admin/dashboard
POST /admin/users/create
POST /admin/settings/update
```

## 2.5 漏洞利用绕过方法

### 2.5.1 前端检查绕过

```bash
# 前端 JS 检查角色
# 直接使用 curl 或 Burp 绕过

curl -H "Cookie: session=xxx" https://target.com/admin
```

### 2.5.2 参数污染

```bash
# 发送多个角色参数
role=user&role=admin

# 服务端可能使用最后一个值
```

---

# 第三部分：附录

## 3.1 权限提升测试检查清单

```
□ 测试角色参数篡改
□ 测试权限 ID 遍历
□ 直接访问管理功能
□ 测试 API 权限检查
□ 检查前端隐藏的管理入口
□ 测试 HTTP 方法绕过
```

## 3.2 修复建议

1. **服务端权限验证** - 所有权限检查在服务端执行
2. **基于角色的访问控制** - 实施严格的 RBAC
3. **最小权限原则** - 用户仅拥有必要权限
4. **审计日志** - 记录所有权限变更

---

**参考资源**：
- [OWASP Cheat Sheet: Access Control](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html)
- [PortSwigger - Access Control](https://portswigger.net/web-security/access-control)
