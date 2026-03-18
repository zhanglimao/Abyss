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
| 对泄露凭证进行变体/递增尝试登录 | 混合凭证填充/密码喷洒攻击 | `ref/hybrid-credential-attack.md` |
| 密码呈现季节性/年份模式（Winter2025→Winter2026） | 混合凭证填充/密码喷洒攻击 | `ref/hybrid-credential-attack.md` |
| 仅使用密码认证无 MFA | 单因素认证风险检测 | `ref/single-factor-auth-risk.md` |
| 敏感操作无额外验证 | 单因素认证风险检测 | `ref/single-factor-auth-risk.md` |
| 高权限账户仅密码保护 | 单因素认证风险检测 | `ref/single-factor-auth-risk.md` |
| SSO 登录后多应用共享会话 | SSO/SLO 会话失效攻击 | `ref/sso-slo-session-expiration.md` |
| 单点注销后其他应用仍可访问 | SSO/SLO 会话失效攻击 | `ref/sso-slo-session-expiration.md` |
| 公共计算机会话残留 | SSO/SLO 会话失效攻击 | `ref/sso-slo-session-expiration.md` |
| 数据库泄露发现明文密码 | 弱密码存储检测 | `ref/weak-password-storage-detection.md` |
| 密码可逆加密（AES/DES） | 弱密码存储检测 | `ref/weak-password-storage-detection.md` |
| 使用 MD5/SHA1 存储密码 | 弱密码存储检测 | `ref/weak-password-storage-detection.md` |
| 管理员可查看用户明文密码 | 弱密码存储检测 | `ref/weak-password-storage-detection.md` |
| 数据库/服务允许空密码登录 | 空密码攻击 | `ref/empty-password-attack.md` |
| 默认账户空密码配置 | 空密码攻击 | `ref/empty-password-attack.md` |
| MySQL/Redis/SSH 空密码 | 空密码攻击 | `ref/empty-password-attack.md` |
| HTTPS 证书验证被禁用 | 证书验证攻击 | `ref/certificate-validation-attack.md` |
| 移动应用接受所有证书 | 证书验证攻击 | `ref/certificate-validation-attack.md` |
| 自签名证书无警告 | 证书验证攻击 | `ref/certificate-validation-attack.md` |
| 证书过期仍接受连接 | 证书验证攻击 | `ref/certificate-validation-attack.md` |
| 登出后会话令牌仍有效 | 捕获重放攻击 | `ref/capture-replay-attack.md` |
| API 令牌可重复使用 | 捕获重放攻击 | `ref/capture-replay-attack.md` |
| OTP 验证码可重用 | 捕获重放攻击 | `ref/capture-replay-attack.md` |
| 密码重置令牌可重用 | 捕获重放攻击 | `ref/capture-replay-attack.md` |
| 敏感操作请求可重放 | 捕获重放攻击 | `ref/capture-replay-attack.md` |
| 无 CSRF Token 防护 | 来源验证攻击 | `ref/origin-validation-attack.md` |
| CORS 配置允许任意域 | 来源验证攻击 | `ref/origin-validation-attack.md` |
| WebSocket 无 Origin 验证 | 来源验证攻击 | `ref/origin-validation-attack.md` |
| Webhook 无签名验证 | 来源验证攻击 | `ref/origin-validation-attack.md` |
| Referer 验证可绕过 | 来源验证攻击 | `ref/origin-validation-attack.md` |
| 证书吊销检查未启用 | 证书吊销检查绕过 | `ref/certificate-revocation-bypass.md` |
| OCSP 检查可被绕过 | 证书吊销检查绕过 | `ref/certificate-revocation-bypass.md` |
| CRL 检查软失败 | 证书吊销检查绕过 | `ref/certificate-revocation-bypass.md` |
| OCSP 响应可重放 | 证书吊销检查绕过 | `ref/certificate-revocation-bypass.md` |
| 会话 ID 可预测或固定 | 会话固定/劫持 | `ref/session-fixation-hijacking.md` `ref/flask-session-management-exploitation.md` |
| 登录成功后会话 ID 不变（无 session_regenerate_id） | PHP 会话管理缺陷利用 | `ref/php-session-management-exploitation.md` |
| Cookie 缺少 HttpOnly/Secure/SameSite 标志 | PHP 会话管理缺陷利用 | `ref/php-session-management-exploitation.md` |
| 无登出功能/登出不销毁会话 | 无登出机制会话持久化攻击 | `ref/no-logout-session-persistence.md` |
| 认证流程可被绕过 | 认证绕过攻击 | `ref/authentication-bypass.md` |
| MFA 可被绕过或疲劳攻击 | MFA 绕过攻击 | `ref/mfa-bypass-attack.md` |
| JWT 令牌验证缺陷 | JWT 认证攻击 | `ref/jwt-authentication-attack.md` |
| 密码重置流程缺陷 | 密码重置攻击 | `ref/password-reset-attack.md` |
| 默认凭证未修改 | 默认凭证利用 | `ref/default-credential-exploitation.md` |
| 登录错误消息泄露信息 | 账户枚举攻击 | `ref/account-enumeration.md` |
| SSO/SAML 配置缺陷 | SSO 认证攻击 | `ref/sso-authentication-attack.md` |
| 发现硬编码会话密钥 | 会话伪造攻击 | `ref/session-forgery-attack.md` `ref/flask-session-forgery-hardcoded-secret.md` |
| HTTP 明文传输凭证 | 凭证拦截攻击 | `ref/credential-interception-attack.md` |
| HTTP 明文传输会话 Cookie | HTTP 明文会话劫持攻击 | `ref/http-session-hijacking.md` |
| 网络嗅探截获会话 Cookie | HTTP 明文会话劫持攻击 | `ref/http-session-hijacking.md` |
| 同一 WiFi 网络会话窃取 | HTTP 明文会话劫持攻击 | `ref/http-session-hijacking.md` |
| ARP 欺骗会话劫持 | HTTP 明文会话劫持攻击 | `ref/http-session-hijacking.md` |
| 缺失 Secure 标志 Cookie | HTTP 明文会话劫持攻击 | `ref/http-session-hijacking.md` |
| JWT 签名验证被禁用 | JWT 令牌伪造攻击 | `ref/jwt-token-forgery-attack.md` |
| 硬编码 JWT 签名密钥 | JWT 令牌伪造攻击 | `ref/jwt-token-forgery-attack.md` |
| 两阶段登录流程（先用户名后密码） | 两阶段认证账户枚举 | `ref/two-stage-auth-enumeration.md` |
| 分步认证暴露用户信息 | 两阶段认证账户枚举 | `ref/two-stage-auth-enumeration.md` |
| 密码表单包含隐藏 user_id 字段 | 客户端控制会话固定攻击 | `ref/client-controlled-session-fixation.md` |
| 认证接受客户端提供的 user_id | 客户端控制会话固定攻击 | `ref/client-controlled-session-fixation.md` |
| 登录后可修改 user_id 访问他人账户 | 客户端控制会话固定攻击 | `ref/client-controlled-session-fixation.md` |
| 登出后 JWT 仍可重用 | 不完整登出攻击 | `ref/incomplete-logout-attack.md` |
| JWT 无过期时间（exp claim） | 不完整登出攻击 | `ref/incomplete-logout-attack.md` |
| PHP 博客应用会话固定漏洞 | PHP 会话管理缺陷利用 | `ref/php-session-management-exploitation.md` |
| PHP 应用 session_start() 无安全配置 | PHP 会话管理缺陷利用 | `ref/php-session-management-exploitation.md` |
| PHP 会话 Cookie 无 HttpOnly 标志 | PHP 会话管理缺陷利用 | `ref/php-session-management-exploitation.md` |
| PHP 会话 Cookie 无 Secure 标志 | HTTP 明文会话劫持攻击 | `ref/http-session-hijacking.md` |
| PHP 会话 Cookie 无 SameSite 标志 | PHP 会话管理缺陷利用 | `ref/php-session-management-exploitation.md` |
| 会话无超时配置 | 无登出机制会话持久化攻击 | `ref/no-logout-session-persistence.md` |
| 会话垃圾回收概率性触发 | 无登出机制会话持久化攻击 | `ref/no-logout-session-persistence.md` |
| Flask 应用使用客户端会话 | Flask 会话伪造攻击 | `ref/flask-session-forgery-attack.md` `ref/flask-session-management-exploitation.md` |
| Flask 应用硬编码弱 SECRET_KEY | Flask 弱密钥会话伪造攻击 | `ref/flask-weak-secret-session-forgery.md` `ref/flask-weak-secret-session-forgery-advanced.md` `ref/flask-session-forgery-hardcoded-secret.md` |
| Flask 会话 Cookie 可预测 | Flask 弱密钥会话伪造攻击 | `ref/flask-weak-secret-session-forgery.md` `ref/flask-weak-secret-session-forgery-advanced.md` `ref/flask-session-forgery-hardcoded-secret.md` |
| 发现 itsdangerous 签名密钥 | Flask 弱密钥会话伪造攻击 | `ref/flask-weak-secret-session-forgery.md` `ref/flask-weak-secret-session-forgery-advanced.md` `ref/flask-session-forgery-hardcoded-secret.md` |
| Flask 应用存在多重认证缺陷（弱密钥 + 无速率限制 + 明文密码） | Flask 认证缺陷综合攻击 | `ref/flask-auth-defenses-combo-attack.md` `ref/flask-auth-defenses-combo-advanced-attack.md` |
| Flask 应用默认凭证 + 无速率限制 | Flask 默认凭证利用攻击 | `ref/flask-default-credential-exploitation.md` `ref/flask-no-rate-limit-abuse.md` |
| Flask 应用登录接口无速率限制 | Flask 无速率限制滥用攻击 | `ref/flask-no-rate-limit-abuse.md` |
| Flask 应用无 CAPTCHA 可自动化攻击 | Flask 无速率限制滥用攻击 | `ref/flask-no-rate-limit-abuse.md` |
| Flask 应用 100 个快速连续请求全部成功 | Flask 无速率限制滥用攻击 | `ref/flask-no-rate-limit-abuse.md` |
| Flask SOAP Banking Service 会话伪造 | Flask 弱密钥会话伪造攻击 | `ref/flask-weak-secret-session-forgery.md` `ref/flask-session-forgery-hardcoded-secret.md` |
| Flask 硬编码密钥 'your_secret_key' | Flask 弱密钥会话伪造攻击 | `ref/flask-weak-secret-session-forgery.md` `ref/flask-session-forgery-hardcoded-secret.md` |
| Flask 明文密码存储 app.py:10 | Flask 认证缺陷综合攻击 | `ref/flask-auth-defenses-combo-attack.md` |
| Flask 无速率限制 ~300 请求/秒 | Flask 无速率限制滥用攻击 | `ref/flask-no-rate-limit-abuse.md` |
| 两阶段认证流程 | 两阶段认证账户枚举 | `ref/two-stage-auth-enumeration.md` |
| 登出后会话仍有效 | 会话固定/劫持 | `ref/session-fixation-hijacking.md` `ref/flask-session-management-exploitation.md` |
| 登出时仅清除部分会话数据 | 不完整登出攻击 | `ref/incomplete-logout-attack.md` `ref/flask-session-management-exploitation.md` |
| 无/logout 端点 | 无登出机制会话持久化攻击 | `ref/no-logout-session-persistence.md` |
| 无 session.clear() 调用 | 无登出机制会话持久化攻击 | `ref/no-logout-session-persistence.md` |
| 会话无过期时间配置 | 无登出机制会话持久化攻击 | `ref/no-logout-session-persistence.md` |
| 客户端会话无法服务器端撤销 | 无登出机制会话持久化攻击 | `ref/no-logout-session-persistence.md` |
| 应用接受 X-UserId 等自定义用户标识头部 | X-UserId 头部认证绕过 | `ref/x-userid-header-bypass-attack.md` |
| HTML/JS 中暴露用户 ID | 用户 ID 枚举攻击 | `ref/user-id-enumeration-attack.md` |
| 应用完全无认证机制 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` |
| PHP 应用无 session_start() 调用 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` |
| PHP 应用无 $_SESSION 使用 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` |
| Docker 环境内部服务无应用层认证 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` |
| CTF 挑战应用无认证架构 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` |
| GraphQL API 无认证要求 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` |
| GraphQL 端点公开访问无需凭证 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` |
| Flask 应用无 SECRET_KEY 配置 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` `ref/no-auth-system-exploitation.md` |
| 发现应用无登录页面 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` `ref/no-auth-system-exploitation.md` |
| 所有端点无需认证即可访问 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` `ref/no-auth-system-exploitation.md` |
| 无认证系统存在命令注入漏洞 | 无认证系统命令注入利用 | `../injection/ref/no-auth-command-injection-exploitation.md` |
| 完全无认证架构 + 命令执行端点 | 无认证系统命令注入利用 | `../injection/ref/no-auth-command-injection-exploitation.md` |
| PHP Twig 应用无认证机制 + SSTI 漏洞 | PHP Twig SSTI 利用 | `../injection/ref/php-twig-ssti-exploitation.md` |
| Twig 沙箱移除 + 无认证系统 | PHP Twig SSTI 利用 | `../injection/ref/php-twig-ssti-exploitation.md` |
| Flask 应用无 SECRET_KEY 配置 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` `ref/flask-no-auth-architecture-exploitation-advanced.md` |
| 发现应用无登录页面 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` `ref/flask-no-auth-architecture-exploitation-advanced.md` |
| 所有端点无需认证即可访问 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` `ref/flask-no-auth-architecture-exploitation-advanced.md` |
| Apache Struts 应用无 web.xml 安全约束配置 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` `ref/no-auth-system-detection-exploitation.md` |
| Struts 2 应用无登录端点 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` `ref/no-auth-system-detection-exploitation.md` |
| Struts 2 应用所有 Action 对匿名访问开放 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` `ref/no-auth-system-detection-exploitation.md` |
| Java Web 应用无<security-constraint>配置 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` `ref/no-auth-system-detection-exploitation.md` |
| IP 基础认证（request.remote_addr 检查） | IP 基础认证绕过攻击 | `ref/ip-based-auth-bypass-via-ssrf.md` |
| 认证端点使用 127.0.0.1 检查 | IP 基础认证绕过攻击 | `ref/ip-based-auth-bypass-via-ssrf.md` |
| SSRF 漏洞 + IP 认证组合 | IP 基础认证绕过攻击 | `ref/ip-based-auth-bypass-via-ssrf.md` |
| Flask 应用硬编码弱 SECRET_KEY | Flask 弱密钥会话伪造攻击 | `ref/flask-weak-secret-session-forgery.md` `ref/flask-session-forgery-advanced-exploitation.md` |
| Flask 会话 Cookie 可预测 | Flask 弱密钥会话伪造攻击 | `ref/flask-weak-secret-session-forgery.md` `ref/flask-session-forgery-advanced-exploitation.md` |
| 发现 itsdangerous 签名密钥 | Flask 弱密钥会话伪造攻击 | `ref/flask-weak-secret-session-forgery.md` `ref/flask-session-forgery-advanced-exploitation.md` |
| Flask 应用存在多重认证缺陷（弱密钥 + 无速率限制 + 明文密码） | Flask 认证缺陷综合攻击 | `ref/flask-auth-defenses-combo-attack.md` `ref/flask-auth-defenses-combo-advanced-attack.md` |
| Flask 应用会话伪造 + 水平权限提升 | Flask 会话伪造高级利用 | `ref/flask-session-forgery-advanced-exploitation.md` |
| Flask 应用会话伪造 + 垂直权限提升 | Flask 会话伪造高级利用 | `ref/flask-session-forgery-advanced-exploitation.md` |
| Flask 应用默认凭证 + 无速率限制 | Flask 认证缺陷综合攻击 | `ref/flask-auth-defenses-combo-attack.md` `ref/flask-auth-defenses-combo-advanced-attack.md` |
| Flask 应用会话重用 + 会话劫持 | Flask 认证缺陷综合攻击 | `ref/flask-auth-defenses-combo-attack.md` `ref/flask-auth-defenses-combo-advanced-attack.md` |
| Flask 应用 CSRF+ 会话劫持组合攻击 | Flask 认证缺陷综合攻击 | `ref/flask-auth-defenses-combo-attack.md` `ref/flask-auth-defenses-combo-advanced-attack.md` |
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
| Flask 应用无 session 导入/使用 | Flask 无认证架构检测 | `ref/flask-no-auth-architecture-detection.md` |
| Flask 应用无 SECRET_KEY 配置 | Flask 无认证架构检测 | `ref/flask-no-auth-architecture-detection.md` |
| Flask 应用无登录/登出端点 | Flask 无认证架构检测 | `ref/flask-no-auth-architecture-detection.md` |
| Flask 应用无认证装饰器 | Flask 无认证架构检测 | `ref/flask-no-auth-architecture-detection.md` |
| Flask 应用所有路由公开访问 | Flask 无认证架构检测 | `ref/flask-no-auth-architecture-detection.md` |
| Werkzeug 响应头无认证端点 | Flask 无认证架构检测 | `ref/flask-no-auth-architecture-detection.md` |
| CTF 挑战应用无认证架构 | Flask 无认证架构检测 | `ref/flask-no-auth-architecture-detection.md` |
| Flask 用户枚举时序攻击 | 用户名枚举攻击 | `ref/account-enumeration-advanced.md` |
| Flask 非恒定时间比较 | 用户名枚举攻击 | `ref/account-enumeration-advanced.md` |
| Flask 登出后会话 Cookie 仍有效 | 不完整登出攻击 | `ref/incomplete-logout-attack.md` `ref/flask-session-management-exploitation.md` |
| Flask 客户端会话无服务器失效 | 不完整登出攻击 | `ref/incomplete-logout-attack.md` `ref/flask-session-management-exploitation.md` |
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
| 50+ 并发请求全部成功（100% 成功率） | 无速率限制滥用 | `ref/no-rate-limit-abuse.md` |
| 每请求响应时间~2.7 秒（高资源消耗） | 无速率限制滥用 | `ref/no-rate-limit-abuse.md` |
| 无认证系统资源耗尽 DoS | 无速率限制滥用 | `ref/no-rate-limit-abuse.md` |
| 令牌仅 Base64 编码无签名 | Base64 令牌伪造攻击 | `ref/base64-token-forgery-attack.md` |
| 令牌结构可预测（仅含用户 ID） | Base64 令牌伪造攻击 | `ref/base64-token-forgery-attack.md` |
| 令牌无过期时间验证 | Base64 令牌伪造攻击 | `ref/base64-token-forgery-attack.md` |
| FastAPI 应用使用 Base64 令牌 | FastAPI Base64 令牌认证绕过 | `ref/fastapi-base64-token-bypass.md` |
| FastAPI 导入 jwt 但未使用 | FastAPI Base64 令牌认证绕过 | `ref/fastapi-base64-token-bypass.md` |
| FastAPI 定义了 SECRET_KEY 但未使用 | FastAPI Base64 令牌认证绕过 | `ref/fastapi-base64-token-bypass.md` |
| FastAPI 令牌验证仅检查格式 | FastAPI Base64 令牌认证绕过 | `ref/fastapi-base64-token-bypass.md` |
| CTF 挑战 FastAPI 认证绕过 | FastAPI Base64 令牌认证绕过 | `ref/fastapi-base64-token-bypass.md` |
| CTF 挑战应用无认证 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` |
| XSS 挑战应用公开访问 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` |
| Flask 应用无 session 导入/使用 | Flask 无认证架构检测与利用 | `ref/flask-no-auth-architecture-exploitation.md` |
| Flask 应用完全无认证架构（无登录/登出/会话） | Flask 无认证架构检测与利用 | `ref/flask-no-auth-architecture-exploitation.md` |
| Werkzeug Server 头无认证端点 | Flask 无认证架构检测与利用 | `ref/flask-no-auth-architecture-exploitation.md` |
| 结合 XSS 利用无认证系统 | Flask 无认证架构检测与利用 | `ref/flask-no-auth-architecture-exploitation.md` `../injection/ref/flask-no-auth-xss-combo-exploitation.md` |
| 临时文件 Race Condition 利用 | Flask 无认证架构检测与利用 | `ref/flask-no-auth-architecture-exploitation.md` |
| Flask 应用无认证架构 + XSS 组合攻击 | Flask 无认证架构 XSS 组合攻击 | `../injection/ref/flask-no-auth-xss-combo-exploitation.md` |
| 无认证系统 Flag 获取 | Flask 无认证架构 XSS 组合攻击 | `../injection/ref/flask-no-auth-xss-combo-exploitation.md` |
| 无认证架构数据外带攻击 | Flask 无认证架构 XSS 组合攻击 | `../injection/ref/flask-no-auth-xss-combo-exploitation.md` |
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
| 应用完全无认证机制 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` |
| PHP 应用无 session_start() 调用 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` |
| PHP 应用无 $_SESSION 使用 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` |
| Docker 环境内部服务无应用层认证 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` |
| CTF 挑战应用无认证架构 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` |
| 发现应用无登录页面 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` |
| 所有端点无需认证即可访问 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` |
| 无认证系统存在文件上传功能 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` |
| 无认证系统存在敏感数据读取 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` |
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
| Django 应用存在多重认证缺陷（硬编码 SECRET_KEY/无速率限制/明文密码存储） | Django 认证系统综合攻击 | `ref/django-auth-attack.md` |
| Django 应用 SECRET_KEY 硬编码 | Django 认证系统综合攻击 | `ref/django-auth-attack.md` |
| Django 应用无速率限制配置 | Django 认证系统综合攻击 | `ref/django-auth-attack.md` |
| Django 多步骤注册流程存储明文密码 | Django 认证系统综合攻击 | `ref/django-auth-attack.md` |
| Django 会话 Cookie 无 Secure 标志 | Django 认证系统综合攻击 | `ref/django-auth-attack.md` |
| Django 会话伪造攻击（SECRET_KEY 已知） | Django 认证系统综合攻击 | `ref/django-auth-attack.md` |
| Django 登录端点无速率限制暴力破解 | Django 认证系统综合攻击 | `ref/django-auth-attack.md` |
| Django 注册流程账户枚举 | Django 认证系统综合攻击 | `ref/django-auth-attack.md` |
| Django 会话明文密码存储漏洞 | Django 认证系统综合攻击 | `ref/django-auth-attack.md` |
| Flask 应用弱会话密钥（your_secret_key） | Flask 认证缺陷综合攻击 | `ref/flask-auth-defenses-combo-attack.md` |
| Flask 应用无速率限制 | Flask 认证缺陷综合攻击 | `ref/flask-auth-defenses-combo-attack.md` |
| Flask 应用明文密码存储 | Flask 认证缺陷综合攻击 | `ref/flask-auth-defenses-combo-attack.md` |
| Flask Cookie 缺少 Secure/SameSite 标志 | Flask 认证缺陷综合攻击 | `ref/flask-auth-defenses-combo-attack.md` |
| CTF 挑战 Flask 应用认证缺陷 | Flask 认证缺陷综合攻击 | `ref/flask-auth-defenses-combo-attack.md` |

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
| AF-028a | 无认证系统检测与利用（增强） | `ref/no-auth-system-exploitation.md` | 漏洞发现/利用 |
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
| AF-042 | Django 认证系统综合攻击 | `ref/django-auth-attack.md` | 漏洞发现/利用 |
| AF-043 | PHP 会话管理缺陷利用 | `ref/php-session-management-exploitation.md` | 漏洞发现/利用 |
| AF-044 | 可预测自动登录令牌绕过 | `ref/predictable-autologin-token-bypass.md` | 漏洞利用 |
| AF-045 | Base64 令牌伪造攻击 | `ref/base64-token-forgery-attack.md` | 漏洞发现/利用 |
| AF-046 | FastAPI Base64 令牌认证绕过 | `ref/fastapi-base64-token-bypass.md` | 漏洞发现/利用 |
| AF-047 | XML-RPC 暴力破解放大攻击 | `ref/xmlrpc-bruteforce-amplification.md` | 漏洞利用 |
| AF-048 | Flask 认证缺陷综合攻击 | `ref/flask-auth-defenses-combo-attack.md` | 漏洞发现/利用 |
| AF-049 | IP 基础认证绕过攻击 | `ref/ip-based-auth-bypass-via-ssrf.md` | 漏洞利用 |
| AF-050 | Flask 弱密钥会话伪造攻击 | `ref/flask-weak-secret-session-forgery.md` | 漏洞利用 |
| AF-051 | WordPress 认证系统攻击 | `ref/wordpress-authentication-attack.md` | 漏洞发现/利用 |
| AF-052 | Flask 会话伪造高级利用 | `ref/flask-session-forgery-advanced-exploitation.md` | 漏洞利用 |
| AF-053 | Flask 认证缺陷综合攻击（高级） | `ref/flask-auth-defenses-combo-advanced-attack.md` | 漏洞发现/利用 |
| AF-054 | Flask 弱密钥会话伪造攻击（高级） | `ref/flask-weak-secret-session-forgery-advanced.md` | 漏洞利用 |
| AF-055 | Flask 默认凭证利用攻击 | `ref/flask-default-credential-exploitation.md` | 漏洞发现/利用 |
| AF-056 | Flask 无速率限制滥用攻击 | `ref/flask-no-rate-limit-abuse.md` | 漏洞发现/利用 |
| AF-057 | Flask 会话伪造攻击（硬编码密钥） | `ref/flask-session-forgery-hardcoded-secret.md` | 漏洞发现/利用 |
| AF-058 | Flask 会话管理缺陷利用 | `ref/flask-session-management-exploitation.md` | 漏洞发现/利用 |
| AF-059 | 无速率限制滥用 | `ref/no-rate-limit-abuse.md` | 漏洞发现/利用 |
| AF-060 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` | 漏洞发现/利用 |
| AF-061 | WordPress 认证系统攻击 | `ref/wordpress-authentication-attack.md` | 漏洞发现/利用 |
| AF-062 | HTTP 明文会话劫持攻击 | `ref/http-session-hijacking.md` | 漏洞发现/利用 |
| AF-063 | 无登出机制会话持久化攻击 | `ref/no-logout-session-persistence.md` | 漏洞发现/利用 |
| AF-064 | 无认证系统检测与利用 | `ref/no-auth-system-detection-exploitation.md` | 漏洞发现/利用 |
| AF-065 | 无认证系统检测与利用（增强版） | `ref/no-authentication-system-detection-exploitation.md` | 漏洞发现/利用 |
| AF-066 | 无速率限制滥用（文件上传/下载） | `ref/no-rate-limit-abuse.md` | 漏洞发现/利用 |
| AF-067 | Flask 无认证架构渗透测试 | `ref/flask-no-auth-architecture-penetration-testing.md` | 漏洞发现/利用 |
| AF-068 | 无速率限制滥用攻击（高级） | `ref/no-rate-limit-abuse-advanced.md` | 漏洞发现/利用 |
| AF-069 | 客户端控制会话固定攻击 | `ref/client-controlled-session-fixation.md` | 漏洞发现/利用 |
| AF-070 | Flask 无速率限制 DoS 攻击 | `ref/flask-no-rate-limit-dos.md` | 漏洞发现/利用 |
| AF-071 | PhantomJS 进程耗尽攻击 | `ref/flask-no-rate-limit-dos.md` | 漏洞发现/利用 |
| AF-072 | 无速率限制暴力破解 | `ref/flask-no-rate-limit-dos.md` | 漏洞发现/利用 |
| AF-073 | 无速率限制数据枚举 | `ref/flask-no-rate-limit-dos.md` | 漏洞发现/利用 |
| AF-074 | 无速率限制存储耗尽攻击 | `ref/flask-no-rate-limit-dos.md` | 漏洞发现/利用 |
| AF-075 | 混合凭证填充/密码喷洒攻击 | `ref/hybrid-credential-attack.md` | 漏洞发现/利用 |
| AF-076 | 单因素认证风险检测 | `ref/single-factor-auth-risk.md` | 漏洞发现 |
| AF-077 | SSO/SLO 会话失效攻击 | `ref/sso-slo-session-expiration.md` | 漏洞发现/利用 |
| AF-078 | 弱密码存储检测 | `ref/weak-password-storage-detection.md` | 漏洞发现 |
| AF-079 | 空密码攻击 | `ref/empty-password-attack.md` | 漏洞发现/利用 |
| AF-080 | 证书验证攻击 | `ref/certificate-validation-attack.md` | 漏洞发现/利用 |
| AF-081 | 捕获重放攻击 | `ref/capture-replay-attack.md` | 漏洞发现/利用 |
| AF-082 | 来源验证攻击 | `ref/origin-validation-attack.md` | 漏洞发现/利用 |
| AF-083 | 证书吊销检查绕过 | `ref/certificate-revocation-bypass.md` | 漏洞发现/利用 |

### 7. WordPress 特定认证攻击场景

| 场景 | 参考方法论 | 文件路径 |
|------|-----------|----------|
| WordPress 备份插件自动登录令牌预测 | 可预测自动登录令牌绕过 | `ref/predictable-autologin-token-bypass.md` |
| WordPress XML-RPC 批量认证尝试 | XML-RPC 暴力破解放大攻击 | `ref/xmlrpc-bruteforce-amplification.md` |
| WordPress /wp-login.php 用户名枚举 | 用户名枚举攻击 | `ref/account-enumeration-advanced.md` `ref/wordpress-authentication-attack.md` |
| WordPress 无速率限制暴力破解 | 无速率限制滥用 | `ref/no-rate-limit-abuse.md` `ref/wordpress-authentication-attack.md` |
| WordPress HTTP 明文凭证传输 | 凭证拦截攻击 | `ref/credential-interception-attack.md` `ref/wordpress-authentication-attack.md` |
| WordPress 应用密码 GET 参数泄露 | 凭证拦截攻击 | `ref/credential-interception-attack.md` `ref/wordpress-authentication-attack.md` |
| WordPress 登录接口暴力破解 | WordPress 认证系统攻击 | `ref/wordpress-authentication-attack.md` |
| WordPress 密码重置 DoS | WordPress 认证系统攻击 | `ref/wordpress-authentication-attack.md` |
| WordPress 作者归档用户名枚举 | WordPress 认证系统攻击 | `ref/wordpress-authentication-attack.md` |
| WordPress 登录错误消息枚举 | WordPress 认证系统攻击 | `ref/wordpress-authentication-attack.md` |
| WordPress Canto OAuth CSRF | WordPress 认证系统攻击 | `ref/wordpress-authentication-attack.md` |
| WordPress 会话 Cookie 拦截 | WordPress 认证系统攻击 | `ref/wordpress-authentication-attack.md` |
| WordPress CSRF 攻击（缺少 SameSite） | WordPress 认证系统攻击 | `ref/wordpress-authentication-attack.md` |

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
