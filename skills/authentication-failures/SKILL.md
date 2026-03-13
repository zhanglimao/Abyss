---
name: authentication-failures
description: 身份认证失效渗透测试技能，用于检测和利用认证机制、会话管理、凭证安全中的缺陷
---

# Authentication Failures（身份认证失效）渗透测试技能

## 简介

身份认证失效（Authentication Failures）是 OWASP Top 10:2025 排名第 7 的安全风险。当攻击者能够欺骗系统将无效或不正确的用户识别为合法用户时，就会发生认证失效漏洞。

本技能提供系统性的方法论，指导渗透测试人员发现和利用认证漏洞，包括凭证填充、会话劫持、认证绕过、MFA 绕过、JWT 攻击等攻击技术。

---

## 方法论映射表

### 1. 渗透过程中遇到什么情况该参考哪个方法论

| 遇到的情况 | 参考方法论 | 文件路径 |
|-----------|-----------|----------|
| 登录接口无速率限制 | 暴力破解攻击 | `ref/bruteforce-attack.md` |
| 使用泄露凭证尝试登录 | 凭证填充攻击 | `ref/credential-stuffing.md` |
| 会话 ID 可预测或固定 | 会话固定/劫持 | `ref/session-fixation-hijacking.md` |
| 认证流程可被绕过 | 认证绕过攻击 | `ref/authentication-bypass.md` |
| MFA 可被绕过或疲劳攻击 | MFA 绕过攻击 | `ref/mfa-bypass-attack.md` |
| JWT 令牌验证缺陷 | JWT 认证攻击 | `ref/jwt-authentication-attack.md` |
| 密码重置流程缺陷 | 密码重置攻击 | `ref/password-reset-attack.md` |
| 默认凭证未修改 | 默认凭证利用 | `ref/default-credential-exploitation.md` |
| 登录错误消息泄露信息 | 账户枚举攻击 | `ref/account-enumeration.md` |
| SSO/SAML 配置缺陷 | SSO 认证攻击 | `ref/sso-authentication-attack.md` |
| 发现硬编码会话密钥 | 会话伪造攻击 | `ref/session-forgery-attack.md` |
| HTTP 明文传输凭证 | 凭证拦截攻击 | `ref/credential-interception-attack.md` |
| Flask 应用使用客户端会话 | Flask 会话伪造攻击 | `ref/flask-session-forgery-attack.md` |
| 两阶段认证流程 | 两阶段认证账户枚举 | `ref/two-stage-auth-enumeration.md` |
| 登出后会话仍有效 | 会话固定/劫持 | `ref/session-fixation-hijacking.md` |
| 登出时仅清除部分会话数据 | 不完整登出攻击 | `ref/incomplete-logout-attack.md` |
| 应用接受 X-UserId 等自定义用户标识头部 | X-UserId 头部认证绕过 | `ref/x-userid-header-bypass-attack.md` |
| HTML/JS 中暴露用户 ID | 用户 ID 枚举攻击 | `ref/user-id-enumeration-attack.md` |
| 应用完全无认证机制 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` |
| Flask 应用无 SECRET_KEY 配置 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` `ref/flask-no-auth-architecture-exploitation-advanced.md` |
| 发现应用无登录页面 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` `ref/flask-no-auth-architecture-exploitation-advanced.md` |
| 所有端点无需认证即可访问 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` `ref/flask-no-auth-architecture-exploitation-advanced.md` |
| Flask 应用存在多重认证缺陷 | Flask 认证绕过高级攻击 | `ref/flask-authentication-bypass-advanced.md` |
| Flask 应用完全无认证架构 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` `ref/flask-no-auth-architecture-exploitation-advanced.md` |
| 无登录/登出端点 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` `ref/flask-no-auth-architecture-exploitation-advanced.md` |
| 无会话管理（无 Cookie/Token） | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` `ref/flask-no-auth-architecture-exploitation-advanced.md` |
| 无认证装饰器（@login_required） | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` `ref/flask-no-auth-architecture-exploitation-advanced.md` |
| 发现硬编码凭证（admin/!@ED#） | Flask 认证绕过高级攻击 | `ref/flask-authentication-bypass-advanced.md` |
| 登录前后会话 ID 不变 | Flask 认证绕过高级攻击 | `ref/flask-authentication-bypass-advanced.md` |
| 时序攻击枚举用户名 | Flask 认证绕过高级攻击 | `ref/flask-authentication-bypass-advanced.md` |
| 无账户锁定机制 | Flask 认证绕过高级攻击 | `ref/flask-authentication-bypass-advanced.md` |
| Flask 应用无 SECRET_KEY 配置 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` `ref/flask-no-auth-architecture-exploitation-advanced.md` |
| Werkzeug 响应头无认证端点 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` `ref/flask-no-auth-architecture-exploitation-advanced.md` |
| 无@login_required 装饰器 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` `ref/flask-no-auth-architecture-exploitation-advanced.md` |
| 所有路由公开访问 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` `ref/flask-no-auth-architecture-exploitation-advanced.md` |
| CTF 挑战应用无认证架构 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` `ref/flask-no-auth-architecture-exploitation-advanced.md` |
| Django 应用无速率限制 | 暴力破解攻击 | `ref/bruteforce-attack.md` |
| Django Admin 无 CAPTCHA | 暴力破解攻击 | `ref/bruteforce-attack.md` |
| HTTP 明文传输会话 Cookie | 凭证拦截攻击 | `ref/credential-interception-attack.md` |
| Django Session Cookie 无 Secure 标志 | 凭证拦截攻击 | `ref/credential-interception-attack.md` |
| 登录接口无速率限制可暴力攻击 | 无速率限制滥用 | `ref/no-rate-limit-abuse.md` |
| 无 CAPTCHA 可自动化攻击 | 无速率限制滥用 | `ref/no-rate-limit-abuse.md` |
| 无 IP 封禁机制 | 无速率限制滥用 | `ref/no-rate-limit-abuse.md` |
| 每请求触发高资源消耗操作（如 PhantomJS） | 无速率限制滥用 | `ref/no-rate-limit-abuse.md` |
| Flask 应用无速率限制 | 无速率限制滥用 | `ref/no-rate-limit-abuse.md` |
| 100 个快速连续请求全部成功 | 无速率限制滥用 | `ref/no-rate-limit-abuse.md` |
| 无 HTTP 429 响应 | 无速率限制滥用 | `ref/no-rate-limit-abuse.md` |
| CTF 挑战应用无认证 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` |
| XSS 挑战应用公开访问 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` |
| Flask 应用无 session 导入/使用 | Flask 无认证架构检测与利用 | `ref/flask-no-auth-architecture-exploitation.md` |
| Flask 应用完全无认证架构（无登录/登出/会话） | Flask 无认证架构检测与利用 | `ref/flask-no-auth-architecture-exploitation.md` |
| Werkzeug Server 头无认证端点 | Flask 无认证架构检测与利用 | `ref/flask-no-auth-architecture-exploitation.md` |
| 结合 XSS 利用无认证系统 | Flask 无认证架构检测与利用 | `ref/flask-no-auth-architecture-exploitation.md` |
| 临时文件 Race Condition 利用 | Flask 无认证架构检测与利用 | `ref/flask-no-auth-architecture-exploitation.md` |
| Flask 应用无 SECRET_KEY 配置 | 无认证系统检测与利用（Flask） | `ref/no-auth-system-flask-exploitation.md` |
| 无登录/登出端点 | 无认证系统检测与利用（Flask） | `ref/no-auth-system-flask-exploitation.md` |
| 无会话管理（无 Cookie/Token） | 无认证系统检测与利用（Flask） | `ref/no-auth-system-flask-exploitation.md` |
| 无认证装饰器（@login_required） | 无认证系统检测与利用（Flask） | `ref/no-auth-system-flask-exploitation.md` |
| 所有路由公开访问 | 无认证系统检测与利用（Flask） | `ref/no-auth-system-flask-exploitation.md` |
| CTF 挑战应用无认证架构 | 无认证系统检测与利用（Flask） | `ref/no-auth-system-flask-exploitation.md` |
| 登录接口无速率限制可暴力攻击 | 无速率限制滥用 | `ref/no-rate-limit-abuse.md` |
| 无 CAPTCHA 可自动化攻击 | 无速率限制滥用 | `ref/no-rate-limit-abuse.md` |
| 无 IP 封禁机制 | 无速率限制滥用 | `ref/no-rate-limit-abuse.md` |
| 每请求触发高资源消耗操作（如 PhantomJS） | 无速率限制滥用 | `ref/no-rate-limit-abuse.md` |
| 50+ 快速连续请求全部成功 | 无速率限制滥用 | `ref/no-rate-limit-abuse.md` |
| 自动化暴力测试无阻碍 | 无速率限制滥用 | `ref/no-rate-limit-abuse.md` |
| Cookie 仅 Base64 编码无签名 | Cookie 操纵认证绕过 | `ref/cookie-manipulation-attack.md` |
| PHP 序列化 Cookie 存储凭证 | Cookie 操纵认证绕过 | `ref/cookie-manipulation-attack.md` |
| Cookie 中存储明文密码 | Cookie 操纵认证绕过 | `ref/cookie-manipulation-attack.md` |
| 客户端 Cookie 控制认证状态 | Cookie 操纵认证绕过 | `ref/cookie-manipulation-attack.md` |
| Cookie 无 HttpOnly/Secure/SameSite | 会话劫持攻击 | `ref/session-fixation-hijacking.md` |
| 登录接口无速率限制 | 无速率限制滥用 | `ref/rate-limit-absence-exploitation.md` |
| 无 CAPTCHA 可自动化暴力攻击 | 无速率限制滥用 | `ref/rate-limit-absence-exploitation.md` |
| 无账户锁定机制 | 无速率限制滥用 | `ref/rate-limit-absence-exploitation.md` |
| 硬编码管理员密码在源码中 | 硬编码密钥利用 | `ref/hardcoded-secret-exploitation.md` |
| 凭证确定性生成无随机性 | 令牌重放攻击 | `ref/cookie-manipulation-attack.md` |
| 用户名在错误响应中反射 | 用户名枚举攻击 | `ref/account-enumeration-advanced.md` |
| HTTP 明文传输凭证 | 凭证拦截攻击 | `ref/credential-interception-attack.md` |
| 无登出端点/会话失效机制 | 不完整登出攻击 | `ref/incomplete-logout-attack.md` |

### 2. 遇到什么样的业务系统、软件环境、基础设施该参考哪个方法论

| 系统/环境特征 | 参考方法论 | 文件路径 |
|--------------|-----------|----------|
| 传统 Web 应用 | Web 认证测试 | `ref/web-authentication-testing.md` |
| REST API 服务 | API 认证测试 | `ref/api-authentication-testing.md` |
| 移动应用 | 移动认证测试 | `ref/mobile-authentication-testing.md` |
| OAuth2/OIDC 系统 | OAuth 认证测试 | `ref/oauth-authentication-testing.md` |
| SAML SSO 系统 | SAML 认证测试 | `ref/saml-authentication-testing.md` |
| JWT 认证系统 | JWT 认证测试 | `ref/jwt-authentication-testing.md` |
| 多因素认证系统 | MFA 安全测试 | `ref/mfa-security-testing.md` |
| 无密码认证系统 | 无密码认证测试 | `ref/passwordless-authentication-testing.md` |

### 3. 遇到什么样的问题该参考哪个方法论

| 问题类型 | 参考方法论 | 文件路径 |
|---------|-----------|----------|
| 如何系统化测试认证机制 | 认证测试框架 | `ref/authentication-testing-framework.md` |
| 如何检测弱密码策略 | 密码策略检测 | `ref/password-policy-detection.md` |
| 如何测试会话管理 | 会话管理测试 | `ref/session-management-testing.md` |
| 如何检测凭证泄露 | 凭证泄露检测 | `ref/credential-leak-detection.md` |
| 如何测试密码恢复流程 | 密码恢复测试 | `ref/password-recovery-testing.md` |
| 如何检测会话固定 | 会话固定检测 | `ref/session-fixation-detection.md` |
| 如何测试认证日志 | 认证日志测试 | `ref/authentication-logging-testing.md` |
| 如何进行认证 fuzzing | 认证 Fuzzing 指南 | `ref/authentication-fuzzing-guide.md` |

### 4. 渗透测试决策流程图

```
                                    ┌─────────────────┐
                                    │  认证安全测试    │
                                    └────────┬────────┘
                                             │
                                             ▼
                                    ┌─────────────────┐
                                    │   认证机制识别   │
                                    │  - 认证方式分析  │
                                    │  - 会话机制分析  │
                                    │  - MFA 机制分析  │
                                    └────────┬────────┘
                                             │
                    ┌────────────────────────┼────────────────────────┐
                    │                        │                        │
                    ▼                        ▼                        ▼
          ┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
          │  发现弱认证点    │      │  发现会话问题   │      │   发现 MFA 问题  │
          └────────┬────────┘      └────────┬────────┘      └────────┬────────┘
                   │                        │                        │
                   ▼                        ▼                        ▼
          ┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
          │  ref/brute-     │      │  ref/session-   │      │  ref/mfa-       │
          │  force-attack.md│      │  fixation-      │      │  bypass-attack.md│
          │                 │      │  hijacking.md   │      │                 │
          └─────────────────┘      └─────────────────┘      └─────────────────┘
```

### 5. 攻击技术思维导图

```
身份认证失效攻击技术
├── 凭证攻击
│   ├── 暴力破解
│   ├── 凭证填充
│   ├── 密码喷洒
│   └── 字典攻击
├── 会话攻击
│   ├── 会话固定
│   ├── 会话劫持
│   ├── 会话预测
│   └── 会话重放
├── 认证绕过
│   ├── 直接访问绕过
│   ├── 参数篡改绕过
│   ├── HTTP 方法绕过
│   └── 路径遍历绕过
├── MFA 攻击
│   ├── MFA 疲劳攻击
│   ├── SIM 交换攻击
│   ├── 验证码重放
│   └── 备用码利用
├── 令牌攻击
│   ├── JWT 算法混淆
│   ├── JWT 密钥爆破
│   ├── JWT 签名绕过
│   └── OAuth 令牌窃取
├── 恢复流程攻击
│   ├── 密码重置枚举
│   ├── 安全问题破解
│   ├── 邮箱接管
│   └── 短信拦截
└── SSO 攻击
    ├── SAML 断言篡改
    ├── OIDC 重定向操纵
    ├── 令牌范围提升
    └── 单点注销失效
```

### 6. 方法论引用清单

| 编号 | 方法论名称 | 引用文件 | 适用阶段 |
|-----|-----------|---------|---------|
| AF-001 | 暴力破解攻击 | `ref/bruteforce-attack.md` | 漏洞利用 |
| AF-002 | 凭证填充攻击 | `ref/credential-stuffing.md` | 漏洞利用 |
| AF-003 | 会话固定/劫持 | `ref/session-fixation-hijacking.md` | 漏洞利用 |
| AF-004 | 认证绕过攻击 | `ref/authentication-bypass.md` | 漏洞利用 |
| AF-005 | MFA 绕过攻击 | `ref/mfa-bypass-attack.md` | 漏洞利用 |
| AF-006 | JWT 认证攻击 | `ref/jwt-authentication-attack.md` | 漏洞利用 |
| AF-007 | 密码重置攻击 | `ref/password-reset-attack.md` | 漏洞利用 |
| AF-008 | 默认凭证利用 | `ref/default-credential-exploitation.md` | 漏洞利用 |
| AF-009 | 账户枚举攻击 | `ref/account-enumeration.md` | 漏洞发现 |
| AF-010 | SSO 认证攻击 | `ref/sso-authentication-attack.md` | 漏洞利用 |
| AF-011 | Web 认证测试 | `ref/web-authentication-testing.md` | 系统化测试 |
| AF-012 | API 认证测试 | `ref/api-authentication-testing.md` | 系统化测试 |
| AF-013 | 移动认证测试 | `ref/mobile-authentication-testing.md` | 系统化测试 |
| AF-014 | OAuth 认证测试 | `ref/oauth-authentication-testing.md` | 系统化测试 |
| AF-015 | SAML 认证测试 | `ref/saml-authentication-testing.md` | 系统化测试 |
| AF-016 | 认证测试框架 | `ref/authentication-testing-framework.md` | 测试规划 |
| AF-017 | 密码策略检测 | `ref/password-policy-detection.md` | 漏洞发现 |
| AF-018 | 会话管理测试 | `ref/session-management-testing.md` | 系统化测试 |
| AF-019 | 凭证泄露检测 | `ref/credential-leak-detection.md` | 信息收集 |
| AF-020 | 密码恢复测试 | `ref/password-recovery-testing.md` | 系统化测试 |
| AF-021 | 会话伪造攻击 | `ref/session-forgery-attack.md` | 漏洞利用 |
| AF-022 | 凭证拦截攻击 | `ref/credential-interception-attack.md` | 漏洞利用 |
| AF-023 | Flask 会话伪造攻击 | `ref/flask-session-forgery-attack.md` | 漏洞利用 |
| AF-024 | 两阶段认证账户枚举 | `ref/two-stage-auth-enumeration.md` | 漏洞发现 |
| AF-025 | X-UserId 头部认证绕过 | `ref/x-userid-header-bypass-attack.md` | 漏洞利用 |
| AF-026 | 不完整登出攻击 | `ref/incomplete-logout-attack.md` | 漏洞利用 |
| AF-027 | 用户 ID 枚举攻击 | `ref/user-id-enumeration-attack.md` | 漏洞发现 |
| AF-028 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` | 漏洞发现/利用 |
| AF-029 | JWT 令牌伪造攻击 | `ref/jwt-token-forgery-attack.md` | 漏洞利用 |
| AF-030 | 默认凭证利用攻击 | `ref/default-credential-exploitation-advanced.md` | 漏洞利用 |
| AF-031 | 暴力破解攻击 | `ref/bruteforce-attack-advanced.md` | 漏洞利用 |
| AF-032 | 用户名枚举攻击 | `ref/account-enumeration-advanced.md` | 漏洞发现 |
| AF-033 | 无速率限制滥用 | `ref/rate-limit-absence-exploitation.md` | 漏洞利用 |
| AF-034 | Flask 认证绕过高级攻击 | `ref/flask-authentication-bypass-advanced.md` | 漏洞利用 |
| AF-035 | Cookie 操纵认证绕过 | `ref/cookie-manipulation-attack.md` | 漏洞利用 |
| AF-036 | 硬编码密钥利用 | `ref/hardcoded-secret-exploitation.md` | 漏洞利用 |
| AF-037 | 凭证拦截攻击 | `ref/credential-interception-attack.md` | 漏洞利用 |
| AF-038 | 令牌重放攻击 | `ref/cookie-manipulation-attack.md` | 漏洞利用 |
| AF-039 | Flask 无认证架构检测与利用 | `ref/flask-no-auth-architecture-exploitation-advanced.md` | 漏洞发现/利用 |
| AF-040 | 无认证系统检测与利用（Flask） | `ref/no-auth-system-flask-exploitation.md` | 漏洞发现/利用 |
| AF-041 | 无速率限制滥用 | `ref/no-rate-limit-abuse.md` | 漏洞利用 |

---

## 使用指南

### 快速开始

1. **认证机制识别** - 确定目标系统使用的认证方式
2. **弱点扫描** - 使用自动化工具扫描常见认证漏洞
3. **手工测试** - 针对发现的弱点进行深入测试
4. **凭证验证** - 验证发现的凭证是否有效

### 技能关联

- 与 `pt-broken-access-control` 技能配合，在认证后测试访问控制
- 与 `pt-cryptographic-failures` 技能配合，破解密码哈希
- 与 `pt-security-logging-failures` 技能配合，利用日志缺失隐藏攻击痕迹

---

## 参考资源

- [OWASP Top 10:2025 A07](https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/)
- [OWASP Cheat Sheet: Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP ASVS V2 Authentication](https://owasp.org/www-project-application-security-verification-standard/)
- [Have I Been Pwned](https://haveibeenpwned.com/)
