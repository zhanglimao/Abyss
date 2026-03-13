# **认证绕过攻击方法论**

---

# **第一部分：文档概述**

## 1.1 编写目的
- 为测试人员提供一套标准化、可复现的认证绕过测试与利用流程
- 帮助识别和验证应用程序认证机制中的逻辑缺陷
- 提高认证绕过漏洞发现的准确率和效率

## 1.2 适用范围
- 适用于所有需要身份认证的 Web 应用、API 接口、移动应用
- 尤其适用于存在认证逻辑缺陷、会话管理不当、权限验证不完善的系统
- 常见于登录表单、API 端点、管理后台、单点登录系统

## 1.3 读者对象
- 本文件主要面向执行渗透测试任务的安全工程师、安全分析师
- 负责代码审计的开发人员和安全研究人员

---

# **第二部分：核心渗透技术专题**

## 专题：认证绕过攻击

## 2.1 技术介绍
- **漏洞原理：** 认证绕过是指攻击者能够在不提供有效凭证的情况下，通过操纵请求参数、利用逻辑缺陷或配置错误，绕过系统的身份验证机制，直接访问受保护资源或功能。
- **本质：** 应用程序的认证检查逻辑存在缺陷，未能对所有访问路径进行严格的身份验证，或验证逻辑可被攻击者操控。

| **绕过类型** | **描述** | **常见原因** |
| :--- | :--- | :--- |
| **直接访问绕过** | 直接访问登录后的页面 URL | 未在服务端验证会话状态 |
| **参数篡改绕过** | 修改请求参数绕过验证 | 信任客户端传来的认证状态参数 |
| **HTTP 方法绕过** | 使用不同 HTTP 方法访问同一资源 | 仅对特定方法实施认证检查 |
| **路径遍历绕过** | 通过特殊路径访问受保护资源 | URL 规范化处理不当 |
| **Header 注入绕过** | 伪造认证相关的 HTTP 头 | 信任 X-User、X-Auth 等头部 |

## 2.2 攻击常见于哪些业务场景

| **业务场景** | **功能示例** | **风险点描述** |
| :--- | :--- | :--- |
| **管理后台** | /admin、/manage 等路径 | 仅前端隐藏入口，后端未验证登录状态 |
| **API 接口** | /api/v1/user/info | 仅检查 Token 存在性，未验证有效性 |
| **单点登录** | SSO 回调接口 | 未验证 SSO 断言签名或状态 |
| **密码重置** | 重置密码确认页面 | 仅通过 URL 参数验证身份 |
| **多步流程** | 注册/绑卡/认证流程 | 可跳过中间步骤直接访问后续页面 |
| **移动应用** | App 内购/付费功能 | 客户端验证为主，服务端验证缺失 |

## 2.3 漏洞发现方法

### 2.3.1 黑盒测试

- **直接访问测试**
  - 未登录状态下直接访问登录后可见的 URL
  - 使用浏览器无痕模式或清除 Cookie 后访问
  - 尝试访问：`/admin`、`/dashboard`、`/profile`、`/settings`

- **参数篡改测试**
  - 修改认证状态参数：`is_logged_in=true`、`auth=1`、`verified=yes`
  - 修改用户 ID 参数：`user_id=1` 改为 `user_id=2`
  - 修改角色参数：`role=user` 改为 `role=admin`

- **HTTP 方法绕过测试**
  - 将 POST 请求改为 GET、PUT、DELETE、PATCH
  - 测试 HEAD、OPTIONS 方法是否返回敏感信息
  - 使用自定义 HTTP 方法测试

- **Header 注入测试**
  - 添加伪造的用户标识头：`X-User-ID: 1`、`X-Auth-User: admin`
  - 添加伪造的角色头：`X-User-Role: admin`、`X-Access-Level: 999`
  - 添加伪造的认证头：`X-Authenticated: true`

### 2.3.2 白盒测试

- **代码审计要点**
  - 搜索认证检查函数的调用位置
  - 检查是否有路径未纳入认证中间件
  - 查看认证逻辑是否存在条件分支可被绕过
  - 检查 URL 路由配置是否存在通配符绕过

- **关键代码模式**
  ```python
  # 危险模式：仅检查参数存在性
  if request.params.get('is_admin'):
      return admin_panel()
  
  # 危险模式：前端跳转未配合后端验证
  if user.is_authenticated:
      redirect('/admin')  # 但/admin 未验证
  ```

## 2.4 漏洞利用方法

### 2.4.1 基础信息收集

- **探测认证机制**
  - 识别会话 Cookie 名称和格式
  - 确定认证检查的 URL 路径模式
  - 识别认证相关的 HTTP 头

- **绘制访问路径图**
  - 列出所有可访问的 URL 路径
  - 标记需要认证和不需要认证的路径
  - 寻找认证检查的边界和例外情况

### 2.4.2 常见绕过技术

- **URL 参数绕过**
  ```
  # 原始请求
  GET /admin/dashboard
  
  # 绕过尝试
  GET /admin/dashboard?auth=true
  GET /admin/dashboard?login=success
  GET /admin/dashboard?user=admin&role=administrator
  ```

- **HTTP Header 绕过**
  ```
  GET /admin/dashboard
  X-User-ID: 1
  X-User-Name: admin
  X-Auth-Status: authenticated
  X-Forwarded-User: admin
  ```

- **Cookie 篡改绕过**
  ```
  # 修改 Cookie 值
  is_admin=true
  authenticated=yes
  role=admin
  session=deleted_session_id
  ```

- **路径遍历绕过**
  ```
  # 利用 URL 编码
  /admin/../../admin/dashboard
  /..;/admin/dashboard
  /admin;/dashboard
  
  # 利用大小写 (Windows)
  /Admin/Dashboard
  /ADMIN/DASHBOARD
  ```

### 2.4.3 高级绕过技术

- **JWT 令牌绕过**
  - 修改算法为 `none`：`{"alg":"none"}`
  - 使用弱密钥签名进行伪造
  - 修改 payload 中的权限声明

- **SAML 断言绕过**
  - 篡改 SAML Response 中的用户属性
  - 重放有效的 SAML 断言
  - 伪造签名（当验证配置不当时）

- **OAuth 流程绕过**
  - 直接访问回调 URL 并伪造授权码
  - 修改 state 参数绕过 CSRF 检查
  - 重放有效的 access token

## 2.5 漏洞利用绕过方法

### 2.5.1 绕过 WAF/防火墙规则

- **参数编码绕过**
  - URL 编码：`%74%72%75%65` 代替 `true`
  - 双重 URL 编码：`%2574%2572%2575%2565`
  - Base64 编码参数值

- **分块传输绕过**
  - 使用 HTTP 分块传输编码
  - 将敏感参数分散到多个数据块

### 2.5.2 绕过速率限制

- **IP 轮换**
  - 使用代理池轮换源 IP
  - 利用云函数动态出口 IP

- **参数变异**
  - 在参数中添加随机后缀
  - 使用不同的参数名传递相同数据

### 2.5.3 无回显场景利用

- **时间盲注**
  - 基于响应时间差异判断绕过成功
  - 使用 `sleep()` 等延迟函数探测

- **带外通信**
  - 利用 Webhook 回调验证权限
  - 通过邮件/SMS 发送功能触发探测

---

# **第三部分：附录**

## 3.1 常用 Payload 速查表

| **类别** | **Payload 示例** | **说明** |
| :--- | :--- | :--- |
| **参数绕过** | `?auth=true`、`?login=1`、`?verified=yes` | 伪造认证状态参数 |
| **参数绕过** | `?user_id=1`、`?admin=true`、`?role=999` | 伪造用户身份参数 |
| **Header 绕过** | `X-User-ID: 1`、`X-Auth-User: admin` | 伪造用户标识头 |
| **Header 绕过** | `X-User-Role: admin`、`X-Access-Level: 999` | 伪造权限头 |
| **Cookie 绕过** | `is_admin=true`、`authenticated=yes` | 伪造认证 Cookie |
| **路径绕过** | `/admin;/dashboard`、`/..;/admin` | 路径分隔符绕过 |
| **JWT 绕过** | `{"alg":"none"}` | 空算法绕过签名 |

## 3.2 常见认证绕过检查点

| **检查点** | **测试方法** | **预期结果** |
| :--- | :--- | :--- |
| **直接访问** | 未登录访问受保护页面 | 应重定向到登录页 |
| **参数篡改** | 修改认证相关参数 | 应忽略客户端参数 |
| **Header 注入** | 添加伪造认证头 | 应忽略不可信头部 |
| **HTTP 方法** | 变更请求方法 | 所有方法都应验证 |
| **Cookie 篡改** | 修改会话 Cookie | 应验证签名/有效性 |
| **URL 编码** | 使用编码绕过 | 应解码后统一验证 |

## 3.3 参考资源

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [PortSwigger Authentication Vulnerabilities](https://portswigger.net/web-security/authentication)
