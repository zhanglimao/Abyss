---
name: security-misconfiguration
description: 安全配置错误渗透测试技能，用于检测和利用系统、应用、云服务的安全配置缺陷
---

# Security Misconfiguration（安全配置错误）渗透测试技能

## 简介

安全配置错误（Security Misconfiguration）是 OWASP Top 10:2025 排名第 2 的安全风险。当系统、应用程序或云服务的安全配置不当或缺失时，攻击者可以利用这些缺陷获取未授权访问、敏感信息或系统控制权。

本技能提供系统性的方法论，指导渗透测试人员发现和利用安全配置错误，包括默认凭证、目录列表、错误信息泄露、安全头缺失等攻击技术。

---

## 方法论映射表

### 1. 渗透过程中遇到什么情况该参考哪个方法论

| 遇到的情况 | 参考方法论 | 文件路径 |
|-----------|-----------|----------|
| 发现默认登录页面 | 默认凭证利用 | `ref/default-credentials-exploitation.md` |
| Apache 2.4.49 路径遍历配置错误（CVE-2021-41773） | Apache 2.4.49 路径遍历漏洞利用 | `ref/apache-2.4.49-path-traversal-exploitation.md` |
| Apache 2.4.50 路径遍历配置错误 | Apache 路径遍历与 CGI RCE 利用 | `ref/apache-path-traversal-rce-exploitation.md` |
| 根目录 Require all granted 配置 | Apache 路径遍历与 CGI RCE 利用 | `ref/apache-path-traversal-rce-exploitation.md` |
| CGI 未授权执行配置 | Apache 路径遍历与 CGI RCE 利用 | `ref/apache-path-traversal-rce-exploitation.md` |
| 目录列表功能开启 | 目录列表攻击 | `ref/directory-listing-attack.md` |
| 错误页面显示堆栈信息 | 错误信息泄露利用 | `ref/error-information-leakage.md` |
| 发现示例应用 | 示例应用漏洞利用 | `ref/sample-application-exploitation.md` |
| HTTP 安全头缺失 | 安全头缺失攻击 | `ref/security-headers-attack.md` |
| 云存储桶公开访问 | 云存储配置错误 | `ref/cloud-storage-misconfiguration.md` |
| 调试模式开启 | 调试功能滥用 | `ref/debug-mode-exploitation.md` |
| 发现备份文件 | 敏感文件泄露 | `ref/sensitive-file-exposure.md` |
| CORS 配置过于宽松 | CORS 配置错误 | `ref/cors-misconfiguration.md` |
| 不必要的服务开启 | 服务暴露攻击 | `ref/unnecessary-service-exposure.md` |
| 应用无 HTTPS/TLS 配置 | HTTP-only 部署攻击 | `ref/http-only-deployment-attack.md` |
| 仅 HTTP 端口（80）监听 | HTTP-only 部署攻击 | `ref/http-only-deployment-attack.md` |
| 缺少 HSTS 响应头 | HTTP-only 部署攻击 | `ref/http-only-deployment-attack.md` |
| Cookie 缺少 Secure 标志 | HTTP-only 部署攻击 | `ref/http-only-deployment-attack.md` |
| 网络嗅探凭证拦截 | HTTP-only 部署攻击 | `ref/http-only-deployment-attack.md` |
| 敏感信息明文存储 | 明文密钥存储利用 | `ref/plaintext-secret-storage-exploitation.md` |
| 发现 CTF Flag 文件 | 明文密钥存储利用 | `ref/plaintext-secret-storage-exploitation.md` |
| Flask 应用 debug=True 开启调试模式 | Flask 调试模式滥用 | `ref/flask-debug-mode-exploitation.md` `ref/flask-debug-mode-exploitation-advanced.md` |
| Werkzeug 调试器暴露 | Flask 调试模式滥用 | `ref/flask-debug-mode-exploitation.md` `ref/flask-debug-mode-exploitation-advanced.md` |
| 错误页面显示堆栈跟踪 | Flask 调试模式滥用 | `ref/flask-debug-mode-exploitation.md` `ref/flask-debug-mode-exploitation-advanced.md` |
| Django 应用 DEBUG=True 开启 | Django 安全配置错误 | `ref/debug-mode-exploitation.md` |
| Django SECRET_KEY 硬编码在 settings.py | 明文密钥存储利用 | `ref/plaintext-secret-storage-exploitation.md` `ref/plaintext-secret-storage-exploitation-advanced.md` |
| Django 数据库凭证硬编码 | 明文密钥存储利用 | `ref/plaintext-secret-storage-exploitation.md` `ref/plaintext-secret-storage-exploitation-advanced.md` |
| Docker 环境内部服务无认证 | 信任边界违规 | `ref/trust-boundary-violation-ssrf.md` |
| secret.txt/.env 明文存储 Flag | 明文密钥存储利用 | `ref/plaintext-secret-storage-exploitation.md` `ref/plaintext-secret-storage-exploitation-advanced.md` |
| Docker 镜像层嵌入敏感信息 | 明文密钥存储利用 | `ref/plaintext-secret-storage-exploitation.md` `ref/plaintext-secret-storage-exploitation-advanced.md` |
| Git 历史提交 Flag/凭证 | 明文密钥存储利用 | `ref/plaintext-secret-storage-exploitation.md` `ref/plaintext-secret-storage-exploitation-advanced.md` |
| 敏感文件 Web 可访问（644 权限） | 明文密钥存储利用 | `ref/plaintext-secret-storage-exploitation.md` `ref/plaintext-secret-storage-exploitation-advanced.md` |
| .env 文件提交到 Git 仓库 | 敏感信息明文存储利用 | `ref/sensitive-data-plaintext-exploitation.md` `ref/plaintext-secret-storage-exploitation-advanced.md` |
| Git 历史可追溯敏感信息 | 敏感信息明文存储利用 | `ref/sensitive-data-plaintext-exploitation.md` `ref/plaintext-secret-storage-exploitation-advanced.md` |
| Docker build ARG 包含密钥 | 敏感信息明文存储利用 | `ref/sensitive-data-plaintext-exploitation.md` `ref/plaintext-secret-storage-exploitation-advanced.md` |
| 日志文件包含敏感信息 | 敏感信息明文存储利用 | `ref/sensitive-data-plaintext-exploitation.md` `ref/plaintext-secret-storage-exploitation-advanced.md` |
| 备份文件（.bak/.old）Web 可访问 | 敏感信息明文存储利用 | `ref/sensitive-data-plaintext-exploitation.md` `ref/plaintext-secret-storage-exploitation-advanced.md` |

### 2. 遇到什么样的业务系统、软件环境、基础设施该参考哪个方法论

| 系统/环境特征 | 参考方法论 | 文件路径 |
|--------------|-----------|----------|
| Web 服务器 (Apache/Nginx/IIS) | Web 服务器配置审计 | `ref/web-server-audit.md` |
| 应用服务器 (Tomcat/JBoss/WebLogic) | 应用服务器配置审计 | `ref/app-server-audit.md` |
| 云环境 (AWS/Azure/GCP) | 云配置安全审计 | `ref/cloud-configuration-audit.md` |
| 容器环境 (Docker/K8s) | 容器配置审计 | `ref/container-configuration-audit.md` |
| 数据库系统 | 数据库配置审计 | `ref/database-configuration-audit.md` |
| CI/CD 管道 | CI/CD 配置审计 | `ref/cicd-configuration-audit.md` |
| 负载均衡器 | 负载均衡器配置审计 | `ref/load-balancer-audit.md` |
| WAF/防火墙 | WAF 配置绕过 | `ref/waf-misconfiguration-bypass.md` |

### 3. 遇到什么样的问题该参考哪个方法论

| 问题类型 | 参考方法论 | 文件路径 |
|---------|-----------|----------|
| 如何系统化检测配置错误 | 配置安全审计框架 | `ref/configuration-audit-framework.md` |
| 如何枚举敏感目录和文件 | 敏感资源枚举 | `ref/sensitive-resource-enumeration.md` |
| 如何检测默认凭证 | 默认凭证检测 | `ref/default-credential-detection.md` |
| 如何检测云存储权限 | 云权限检测 | `ref/cloud-permission-detection.md` |
| 如何检测安全头配置 | 安全头检测 | `ref/security-header-detection.md` |
| 如何绕过 WAF 防护 | WAF 绕过技术 | `ref/waf-bypass-techniques.md` |
| 如何利用错误信息 | 错误信息分析 | `ref/error-message-analysis.md` |
| 如何进行配置基线对比 | 配置基线检查 | `ref/configuration-baseline-check.md` |

### 4. 渗透测试决策流程图

```
                                    ┌─────────────────┐
                                    │   开始配置审计   │
                                    └────────┬────────┘
                                             │
                                             ▼
                                    ┌─────────────────┐
                                    │   资产发现阶段   │
                                    │  - 识别服务类型  │
                                    │  - 收集版本信息  │
                                    │  - 绘制架构图    │
                                    └────────┬────────┘
                                             │
                    ┌────────────────────────┼────────────────────────┐
                    │                        │                        │
                    ▼                        ▼                        ▼
          ┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
          │  Web 应用服务    │      │   云基础设施    │      │   容器环境      │
          └────────┬────────┘      └────────┬────────┘      └────────┬────────┘
                   │                        │                        │
                   ▼                        ▼                        ▼
          ┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
          │  ref/web-       │      │  ref/cloud-     │      │  ref/container- │
          │  server-audit.md│      │  configuration- │      │  configuration- │
          │                 │      │  audit.md       │      │  audit.md       │
          └─────────────────┘      └─────────────────┘      └─────────────────┘
```

### 5. 攻击技术思维导图

```
安全配置错误攻击技术
├── 默认配置攻击
│   ├── 默认凭证利用
│   ├── 默认页面/应用
│   └── 默认 API 密钥
├── 信息泄露攻击
│   ├── 目录列表
│   ├── 错误消息泄露
│   ├── 敏感文件暴露
│   └── 版本信息泄露
├── 安全头攻击
│   ├── X-Frame-Options 缺失（点击劫持）
│   ├── X-Content-Type-Options 缺失（MIME 嗅探）
│   ├── HSTS 缺失（协议降级）
│   └── CSP 缺失（XSS）
├── 云配置攻击
│   ├── S3 桶公开访问
│   ├── IAM 权限过宽
│   ├── 安全组配置错误
│   └── 元数据服务暴露
├── 服务暴露攻击
│   ├── 不必要的端口
│   ├── 调试接口暴露
│   ├── 管理界面暴露
│   └── 测试功能开启
└── 框架配置攻击
    ├── Spring Boot Actuator
    ├── Django Debug Toolbar
    ├── ASP.NET Trace
    └── PHP Info 页面
```

### 6. 方法论引用清单

| 编号 | 方法论名称 | 引用文件 | 适用阶段 |
|-----|-----------|---------|---------|
| SM-001 | 默认凭证利用 | `ref/default-credentials-exploitation.md` | 漏洞利用 |
| SM-002 | 目录列表攻击 | `ref/directory-listing-attack.md` | 漏洞发现 |
| SM-003 | 错误信息泄露利用 | `ref/error-information-leakage.md` | 漏洞利用 |
| SM-004 | 示例应用漏洞利用 | `ref/sample-application-exploitation.md` | 漏洞利用 |
| SM-005 | 安全头缺失攻击 | `ref/security-headers-attack.md` | 漏洞利用 |
| SM-006 | 云存储配置错误 | `ref/cloud-storage-misconfiguration.md` | 漏洞发现 |
| SM-007 | 调试功能滥用 | `ref/debug-mode-exploitation.md` | 漏洞利用 |
| SM-008 | 敏感文件泄露 | `ref/sensitive-file-exposure.md` | 漏洞发现 |
| SM-009 | CORS 配置错误 | `ref/cors-misconfiguration.md` | 漏洞利用 |
| SM-010 | 不必要服务暴露 | `ref/unnecessary-service-exposure.md` | 漏洞发现 |
| SM-011 | Web 服务器配置审计 | `ref/web-server-audit.md` | 系统化测试 |
| SM-012 | 应用服务器配置审计 | `ref/app-server-audit.md` | 系统化测试 |
| SM-013 | 云配置安全审计 | `ref/cloud-configuration-audit.md` | 系统化测试 |
| SM-014 | 容器配置审计 | `ref/container-configuration-audit.md` | 系统化测试 |
| SM-015 | 数据库配置审计 | `ref/database-configuration-audit.md` | 系统化测试 |
| SM-016 | CI/CD 配置审计 | `ref/cicd-configuration-audit.md` | 系统化测试 |
| SM-017 | WAF 配置绕过 | `ref/waf-misconfiguration-bypass.md` | 漏洞利用 |
| SM-018 | 配置安全审计框架 | `ref/configuration-audit-framework.md` | 测试规划 |
| SM-019 | 敏感资源枚举 | `ref/sensitive-resource-enumeration.md` | 信息收集 |
| SM-020 | WAF 绕过技术 | `ref/waf-bypass-techniques.md` | 漏洞利用 |
| SM-021 | HTTP-only 部署攻击 | `ref/http-only-deployment-attack.md` | 漏洞利用 |
| SM-022 | 缓存控制配置错误 | `ref/cache-control-misconfiguration.md` | 漏洞利用 |
| SM-023 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` | 漏洞发现/利用 |
| SM-024 | 敏感信息明文存储利用 | `ref/sensitive-data-plaintext-exploitation.md` | 漏洞利用 |
| SM-025 | Docker 环境敏感信息提取 | `ref/docker-secret-extraction.md` | 漏洞利用 |
| SM-026 | 缓存控制配置错误 | `ref/cache-control-misconfiguration.md` | 漏洞利用 |
| SM-027 | Flask 调试模式滥用 | `ref/flask-debug-mode-exploitation.md` | 漏洞利用 |
| SM-028 | 明文密钥存储利用 | `ref/plaintext-secret-storage-exploitation.md` | 漏洞利用 |
| SM-029 | Flask 调试模式滥用（高级） | `ref/flask-debug-mode-exploitation-advanced.md` | 漏洞利用 |
| SM-030 | 明文密钥存储利用（高级） | `ref/plaintext-secret-storage-exploitation-advanced.md` | 漏洞利用 |
| SM-031 | Apache 路径遍历与 CGI RCE 利用 | `ref/apache-path-traversal-rce-exploitation.md` | 漏洞发现/利用 |
| SM-032 | Apache 2.4.49 路径遍历漏洞利用 | `ref/apache-2.4.49-path-traversal-exploitation.md` | 漏洞发现/利用 |
| SM-033 | HTTP-only 部署攻击 | `ref/http-only-deployment-attack.md` | 漏洞发现/利用 |
| SM-034 | 明文密钥存储利用 | `ref/plaintext-secret-storage-exploitation.md` | 漏洞发现/利用 |
| SM-035 | WordPress 安全配置错误攻击 | `ref/wordpress-security-misconfiguration-attack.md` | 漏洞发现/利用 |

### 7. WordPress 特定安全配置错误场景

| 场景 | 参考方法论 | 文件路径 |
|------|-----------|----------|
| WordPress HTTP-only 部署无 HTTPS | HTTP-only 部署攻击 | `ref/http-only-deployment-attack.md` |
| WordPress 数据库凭证硬编码 | 明文密钥存储利用 | `ref/plaintext-secret-storage-exploitation.md` |
| WordPress 缺少安全响应头 | 安全头缺失攻击 | `ref/security-headers-attack.md` |
| WordPress 调试模式开启 | 调试功能滥用 | `ref/debug-mode-exploitation.md` |
| WordPress 备份文件 Web 可访问 | 敏感文件泄露 | `ref/sensitive-file-exposure.md` |
| Docker 容器环境变量 Flag | Docker 环境敏感信息提取 | `ref/docker-secret-extraction.md` |
| WordPress HTTP-only 部署凭证拦截 | WordPress 安全配置错误攻击 | `ref/wordpress-security-misconfiguration-attack.md` |
| WordPress 明文数据库凭证存储 | WordPress 安全配置错误攻击 | `ref/wordpress-security-misconfiguration-attack.md` |
| WordPress 明文 OAuth Token 存储 | WordPress 安全配置错误攻击 | `ref/wordpress-security-misconfiguration-attack.md` |
| WordPress 缺少 CSP 响应头 | WordPress 安全配置错误攻击 | `ref/wordpress-security-misconfiguration-attack.md` |
| WordPress 缺少 HSTS 响应头 | WordPress 安全配置错误攻击 | `ref/wordpress-security-misconfiguration-attack.md` |
| WordPress 缺少 X-Frame-Options | WordPress 安全配置错误攻击 | `ref/wordpress-security-misconfiguration-attack.md` |
| WordPress 目录列表启用 | WordPress 安全配置错误攻击 | `ref/wordpress-security-misconfiguration-attack.md` |
| WordPress Cookie 缺少 SameSite | WordPress 安全配置错误攻击 | `ref/wordpress-security-misconfiguration-attack.md` |

---

## 使用指南

### 快速开始

1. **资产发现** - 识别目标系统的所有组件和服务
2. **基线对比** - 对照安全配置基线进行检查
3. **自动化扫描** - 使用工具进行配置漏洞扫描
4. **手工验证** - 对发现的配置问题进行验证

### 技能关联

- 与 `pt-broken-access-control` 技能配合，利用配置错误绕过访问控制
- 与 `pt-cryptographic-failures` 技能配合，检测加密配置问题
- 与 `pt-security-logging-failures` 技能配合，检测日志配置问题

---

## 参考资源

- [OWASP Top 10:2025 A02](https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers-project/)
- [Cloud Security Alliance](https://cloudsecurityalliance.org/)
