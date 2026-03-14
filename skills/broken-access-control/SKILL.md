---
name: broken-access-control
description: 访问控制失效渗透测试技能，用于检测和利用权限验证机制缺陷，实现未授权访问和权限提升
---

# Broken Access Control（访问控制失效）渗透测试技能

## 简介

访问控制失效（Broken Access Control）是 OWASP Top 10:2025 排名第 1 的安全风险。当应用程序的权限验证机制存在缺陷时，攻击者可以未经授权访问敏感信息、修改数据或执行特权操作。

本技能提供系统性的方法论，指导渗透测试人员发现和利用访问控制漏洞，包括 IDOR、强制浏览、权限提升、JWT 篡改等攻击技术。

---

## 方法论映射表

### 1. 渗透过程中遇到什么情况该参考哪个方法论

| 遇到的情况 | 参考方法论 | 文件路径 |
|-----------|-----------|----------|
| 修改 URL 参数 ID 可访问他人数据 | IDOR 漏洞检测与利用 | `ref/idor-detection-exploitation.md` |
| 直接访问需认证的 URL 成功 | 强制浏览攻击 | `ref/force-browsing-attack.md` |
| 未登录用户访问需认证页面 | 认证绕过检测 | `ref/authentication-bypass.md` |
| 普通用户可访问管理员功能 | 垂直权限提升 | `ref/vertical-privilege-escalation.md` |
| 用户 A 可访问用户 B 的数据 | 水平权限提升 | `ref/horizontal-privilege-escalation.md` |
| 修改 Cookie/JWT 后权限变化 | 令牌篡改攻击 | `ref/token-manipulation.md` |
| API 接口无权限验证 | API 未授权访问 | `ref/api-unauthorized-access.md` |
| CORS 配置过于宽松 | CORS 配置错误利用 | `ref/cors-misconfiguration.md` |
| 已确认 IDOR 漏洞需深度利用 | IDOR 漏洞利用技术 | `ref/idor-exploitation-techniques.md` |
| 多阶段流程可跳过前置步骤 | 工作流/上下文认证绕过 | `ref/workflow-auth-bypass.md` |
| 归档/修改操作缺少所有权检查 | IDOR 水平权限绕过 | `ref/idor-exploitation-techniques.md` |
| HTML/JS 中暴露用户 ID | 用户 ID 枚举攻击 | `ref/user-id-enumeration-attack.md` |
| 应用接受 X-UserId 等自定义头部 | X-UserId 头部认证绕过 | `ref/x-userid-header-bypass-attack.md` |
| 登出后仍可访问他人数据 | 不完整登出攻击 | `ref/incomplete-logout-attack.md` |
| 应用无授权机制 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` |
| Apache 2.4.49 静态文件服务无认证 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` `ref/apache-2.4.49-path-traversal-exploitation.md` |
| 应用完全无认证/授权机制 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` |
| 所有端点公开可访问 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` |
| 无认证架构所有功能公开 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` |
| 无访问控制装饰器 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` |
| 静态网站无认证机制 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` |
| Apache 配置 Require all granted | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` |
| CTF 挑战应用无认证架构 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` |
| 无速率限制可暴力攻击 | 速率限制绕过 | `ref/rate-limit-bypass.md` |
| 无 CAPTCHA 可自动化攻击 | 速率限制绕过 | `ref/rate-limit-bypass.md` |
| 并发请求无限制可 DoS | 速率限制绕过 | `ref/rate-limit-bypass.md` |
| 每个请求触发高资源消耗操作 | 速率限制绕过 | `ref/rate-limit-bypass.md` |
| 修改对象 ID 参数可访问他人数据 | IDOR 漏洞利用技术 | `ref/idor-exploitation-advanced.md` |
| 客户端权限控制（disabled 字段）可绕过 | 垂直权限提升 | `ref/vertical-privilege-escalation-advanced.md` |
| 无认证架构所有功能公开 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` |
| 无访问控制装饰器 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` |
| 表单参数可直接修改权限值 | 垂直权限提升 | `ref/vertical-privilege-escalation-advanced.md` |
| Django 注册流程 is_premium 字段可篡改 | 垂直权限提升 | `ref/vertical-privilege-escalation-advanced.md` |
| 多步骤注册流程无支付验证 | 垂直权限提升 | `ref/vertical-privilege-escalation-advanced.md` |
| 复选框控制权限可直接勾选 | 垂直权限提升 | `ref/vertical-privilege-escalation-advanced.md` |
| JWT 令牌权限字段可篡改 | 令牌篡改攻击 | `ref/token-manipulation.md` |
| 授权检查在输入转换前执行 | TOCTOU 授权绕过 | `ref/toctou-authorization-bypass.md` |
| 输入 sanitization 改变参数值 | TOCTOU 授权绕过 | `ref/toctou-authorization-bypass.md` |
| 检查与使用之间存在状态变化 | TOCTOU 授权绕过 | `ref/toctou-authorization-bypass.md` |
| GraphQL API 无认证要求 | GraphQL 未授权访问与 IDOR 攻击 | `ref/graphql-unauthorized-access-idor.md` |
| GraphQL 查询接受任意 userId | GraphQL 未授权访问与 IDOR 攻击 | `ref/graphql-unauthorized-access-idor.md` |
| GraphQL 突变接受任意 userId | GraphQL 未授权访问与 IDOR 攻击 | `ref/graphql-unauthorized-access-idor.md` |
| 可直接调用 API 绕过前端 | GraphQL 未授权访问与 IDOR 攻击 | `ref/graphql-unauthorized-access-idor.md` |
| GraphiQL 界面公开暴露 | GraphQL 未授权访问与 IDOR 攻击 | `ref/graphql-unauthorized-access-idor.md` |
| CTF 挑战应用无访问控制 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` |
| XSS 挑战应用所有端点公开 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` |
| Cookie 中权限字段可篡改 | Cookie 操纵认证绕过 | `ref/cookie-manipulation-attack.md` |
| 客户端存储授权状态无签名 | Cookie 操纵认证绕过 | `ref/cookie-manipulation-attack.md` |
| 普通用户可访问管理员功能 | 垂直权限提升 | `ref/vertical-privilege-escalation.md` |
| 修改对象 ID 可访问他人数据 | IDOR 漏洞利用技术 | `ref/idor-exploitation-advanced.md` |
| SOAP 服务接受任意 account_id 参数 | IDOR 通过 SOAP 参数篡改 | `ref/idor-via-soap-parameter-tampering.md` |
| 无账户所有权检查 | IDOR 通过 SOAP 参数篡改 | `ref/idor-via-soap-parameter-tampering.md` |
| SOAP XML 请求中对象 ID 可控 | IDOR 通过 SOAP 参数篡改 | `ref/idor-via-soap-parameter-tampering.md` |
| 批量枚举对象 ID | IDOR 通过 SOAP 参数篡改 | `ref/idor-via-soap-parameter-tampering.md` |
| CTF 挑战 SOAP 服务 IDOR | IDOR 通过 SOAP 参数篡改 | `ref/idor-via-soap-parameter-tampering.md` |
| SSRF 访问内部 admin 端点 | SSRF 垂直权限提升 | `ref/ssrf-vertical-privilege-escalation.md` |
| SSRF 绕过 IP 基础授权 | SSRF 垂直权限提升 | `ref/ssrf-vertical-privilege-escalation.md` |
| localhost 限制可被 SSRF 绕过 | SSRF 垂直权限提升 | `ref/ssrf-vertical-privilege-escalation.md` |

### 2. 遇到什么样的业务系统、软件环境、基础设施该参考哪个方法论

| 系统/环境特征 | 参考方法论 | 文件路径 |
|--------------|-----------|----------|
| RESTful API 架构 | API 权限测试 | `ref/api-permission-testing.md` |
| JWT 令牌认证系统 | JWT 安全测试 | `ref/jwt-security-testing.md` |
| 多租户 SaaS 系统 | 租户隔离测试 | `ref/tenant-isolation-testing.md` |
| 微服务架构 | 服务间权限测试 | `ref/microservice-permission-testing.md` |
| 单页应用 (SPA) | 前端控制绕过 | `ref/frontend-bypass.md` |
| 云原生应用 | 云 IAM 权限测试 | `ref/cloud-iam-testing.md` |
| GraphQL API | GraphQL 授权测试 | `ref/graphql-authorization-testing.md` |

### 3. 遇到什么样的问题该参考哪个方法论

| 问题类型 | 参考方法论 | 文件路径 |
|---------|-----------|----------|
| 如何系统化测试访问控制 | 访问控制测试框架 | `ref/access-control-testing-framework.md` |
| 如何绕过前端权限限制 | 前端控制绕过 | `ref/frontend-bypass.md` |
| 如何测试 IDOR 漏洞 | IDOR 系统化测试 | `ref/idor-systematic-testing.md` |
| 如何发现隐藏的管理接口 | 敏感目录枚举 | `ref/sensitive-directory-enumeration.md` |
| 如何测试会话管理缺陷 | 会话安全测试 | `ref/session-security-testing.md` |
| 如何绕过速率限制 | 速率限制绕过 | `ref/rate-limit-bypass.md` |
| 如何进行 CSRF 攻击 | CSRF 检测与利用 | `ref/csrf-detection-exploitation.md` |

### 4. 渗透测试决策流程图

```
                                    ┌─────────────────┐
                                    │   开始渗透测试   │
                                    └────────┬────────┘
                                             │
                                             ▼
                                    ┌─────────────────┐
                                    │   信息收集阶段   │
                                    │  - 识别认证机制  │
                                    │  - 绘制权限矩阵  │
                                    │  - 枚举 API 端点  │
                                    └────────┬────────┘
                                             │
                    ┌────────────────────────┼────────────────────────┐
                    │                        │                        │
                    ▼                        ▼                        ▼
          ┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
          │  发现 ID 参数     │      │  发现管理功能   │      │  发现 API 接口   │
          └────────┬────────┘      └────────┬────────┘      └────────┬────────┘
                   │                        │                        │
                   ▼                        ▼                        ▼
          ┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
          │  ref/idor-      │      │  ref/force-    │      │  ref/api-       │
          │  detection-     │      │  browsing-     │      │  unauthorized-  │
          │  exploitation.md│      │  attack.md     │      │  access.md     │
          └─────────────────┘      └─────────────────┘      └─────────────────┘
```

### 5. 攻击技术思维导图

```
访问控制失效攻击技术
├── 对象引用攻击
│   ├── IDOR（不安全直接对象引用）
│   ├── 可预测资源标识符
│   └── UUID 枚举攻击
├── 强制浏览攻击
│   ├── 目录/文件枚举
│   ├── 隐藏功能发现
│   └── 备份文件探测
├── 权限提升攻击
│   ├── 水平权限提升（同级别）
│   ├── 垂直权限提升（跨级别）
│   └── 上下文权限提升
├── 令牌攻击
│   ├── JWT 篡改
│   ├── Cookie 修改
│   ├── 会话固定
│   └── 令牌重放
├── API 攻击
│   ├── 未授权 API 访问
│   ├── HTTP 方法绕过
│   └── 参数污染
└── 配置攻击
    ├── CORS 配置错误
    ├── CSRF 防护缺失
    └── 缓存敏感数据
```

### 6. 方法论引用清单

| 编号 | 方法论名称 | 引用文件 | 适用阶段 |
|-----|-----------|---------|---------|
| AC-001 | IDOR 漏洞检测与利用 | `ref/idor-detection-exploitation.md` | 漏洞发现 |
| AC-002 | 强制浏览攻击 | `ref/force-browsing-attack.md` | 漏洞发现 |
| AC-003 | 认证绕过检测 | `ref/authentication-bypass.md` | 漏洞发现 |
| AC-004 | 垂直权限提升 | `ref/vertical-privilege-escalation.md` | 漏洞利用 |
| AC-005 | 水平权限提升 | `ref/horizontal-privilege-escalation.md` | 漏洞利用 |
| AC-006 | 令牌篡改攻击 | `ref/token-manipulation.md` | 漏洞利用 |
| AC-007 | API 未授权访问 | `ref/api-unauthorized-access.md` | 漏洞发现 |
| AC-008 | CORS 配置错误利用 | `ref/cors-misconfiguration.md` | 漏洞利用 |
| AC-009 | API 权限测试 | `ref/api-permission-testing.md` | 系统化测试 |
| AC-010 | JWT 安全测试 | `ref/jwt-security-testing.md` | 系统化测试 |
| AC-011 | 租户隔离测试 | `ref/tenant-isolation-testing.md` | 系统化测试 |
| AC-012 | 前端控制绕过 | `ref/frontend-bypass.md` | 漏洞利用 |
| AC-013 | 敏感目录枚举 | `ref/sensitive-directory-enumeration.md` | 信息收集 |
| AC-014 | 会话安全测试 | `ref/session-security-testing.md` | 系统化测试 |
| AC-015 | 速率限制绕过 | `ref/rate-limit-bypass.md` | 漏洞利用 |
| AC-016 | CSRF 检测与利用 | `ref/csrf-detection-exploitation.md` | 漏洞发现 |
| AC-017 | 访问控制测试框架 | `ref/access-control-testing-framework.md` | 测试规划 |
| AC-018 | 微服务权限测试 | `ref/microservice-permission-testing.md` | 系统化测试 |
| AC-019 | 云 IAM 权限测试 | `ref/cloud-iam-testing.md` | 系统化测试 |
| AC-020 | GraphQL 授权测试 | `ref/graphql-authorization-testing.md` | 系统化测试 |
| AC-021 | IDOR 漏洞利用技术 | `ref/idor-exploitation-techniques.md` | 漏洞利用 |
| AC-022 | 工作流/上下文认证绕过 | `ref/workflow-auth-bypass.md` | 漏洞发现 |
| AC-023 | 用户 ID 枚举攻击 | `ref/user-id-enumeration-attack.md` | 漏洞发现 |
| AC-024 | X-UserId 头部认证绕过 | `ref/x-userid-header-bypass-attack.md` | 漏洞利用 |
| AC-025 | 不完整登出攻击 | `ref/incomplete-logout-attack.md` | 漏洞利用 |
| AC-026 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` | 漏洞发现/利用 |
| AC-027 | IDOR 漏洞利用技术 | `ref/idor-exploitation-advanced.md` | 漏洞利用 |
| AC-028 | 垂直权限提升 | `ref/vertical-privilege-escalation-advanced.md` | 漏洞利用 |
| AC-029 | TOCTOU 授权绕过 | `ref/toctou-authorization-bypass.md` | 漏洞利用 |
| AC-030 | GraphQL 未授权访问与 IDOR 攻击 | `ref/graphql-unauthorized-access-idor.md` | 漏洞利用 |
| AC-031 | Cookie 操纵认证绕过 | `ref/cookie-manipulation-attack.md` | 漏洞利用 |
| AC-032 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` | 漏洞发现/利用 |
| AC-033 | 无认证 Web 系统检测与利用 | `ref/no-auth-system-web-exploitation.md` | 漏洞发现/利用 |
| AC-034 | IDOR 未授权文件访问 | `ref/idor-unauthorized-file-access.md` | 漏洞发现/利用 |
| AC-035 | 文件覆盖漏洞利用 | `ref/file-overwrite-attack.md` | 漏洞利用 |
| AF-036 | WordPress is_admin() 权限绕过 | `ref/wordpress-is-admin-bypass.md` | 漏洞利用 |
| AC-037 | IDOR 通过 SOAP 参数篡改 | `ref/idor-via-soap-parameter-tampering.md` | 漏洞利用 |
| AC-038 | SSRF 垂直权限提升 | `ref/ssrf-vertical-privilege-escalation.md` | 漏洞利用 |
| AC-039 | WordPress Canto 访问控制攻击 | `ref/wordpress-canto-access-control-attack.md` | 漏洞发现/利用 |

### 7. WordPress 特定访问控制攻击场景

| 场景 | 参考方法论 | 文件路径 |
|------|-----------|----------|
| WordPress 插件 is_admin() 垂直权限提升 | WordPress is_admin() 权限绕过 | `ref/wordpress-is-admin-bypass.md` |
| WordPress 备份文件 IDOR 下载 | IDOR 未授权文件访问 | `ref/idor-unauthorized-file-access.md` |
| WordPress 备份文件 IDOR 删除 | IDOR 漏洞利用技术 | `ref/idor-exploitation-advanced.md` |
| WordPress 配置认证绕过 | Cookie 操纵认证绕过 | `ref/cookie-manipulation-attack.md` |
| WordPress 自动登录令牌认证绕过 | 可预测自动登录令牌绕过 | `../authentication-failures/ref/predictable-autologin-token-bypass.md` |
| WordPress 备份存储路径 IDOR | IDOR 漏洞利用技术 | `ref/idor-exploitation-techniques.md` |
| WordPress Canto 插件 IDOR | WordPress Canto 访问控制攻击 | `ref/wordpress-canto-access-control-attack.md` |
| WordPress Canto get.php 未授权访问 | WordPress Canto 访问控制攻击 | `ref/wordpress-canto-access-control-attack.md` |
| WordPress Canto download.php 未授权访问 | WordPress Canto 访问控制攻击 | `ref/wordpress-canto-access-control-attack.md` |
| WordPress Canto detail.php 未授权访问 | WordPress Canto 访问控制攻击 | `ref/wordpress-canto-access-control-attack.md` |
| WordPress Canto tree.php 未授权访问 | WordPress Canto 访问控制攻击 | `ref/wordpress-canto-access-control-attack.md` |
| WordPress Canto copy-media.php IDOR | WordPress Canto 访问控制攻击 | `ref/wordpress-canto-access-control-attack.md` |
| WordPress Canto AJAX 垂直权限提升 | WordPress Canto 访问控制攻击 | `ref/wordpress-canto-access-control-attack.md` |
| WordPress Canto OAuth CSRF | WordPress Canto 访问控制攻击 | `ref/wordpress-canto-access-control-attack.md` |
| WordPress Canto 认证绕过 | WordPress Canto 访问控制攻击 | `ref/wordpress-canto-access-control-attack.md` |

---

## 使用指南

### 快速开始

1. **确定测试范围** - 识别目标应用的认证机制和权限模型
2. **选择方法论** - 根据上表选择对应的测试方法论
3. **执行测试** - 按照方法论文档中的步骤进行系统化测试
4. **记录结果** - 记录发现的漏洞和利用路径

### 技能关联

- 与 `pt-authentication-failures` 技能配合使用，全面测试认证授权体系
- 与 `pt-injection` 技能配合，在获取权限后深入利用
- 与 `pt-security-misconfiguration` 技能配合，发现配置相关的访问控制问题

---

## 参考资源

- [OWASP Top 10:2025 A01](https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/)
- [OWASP ASVS V8 Authorization](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP Testing Guide - Authorization Testing](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger - Access Control Vulnerabilities](https://portswigger.net/web-security/access-control)
