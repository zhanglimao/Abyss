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
| PHP Twig 模板引擎沙箱被移除 | PHP Twig SSTI 利用 | `../injection/ref/php-twig-ssti-exploitation.md` |
| Twig_Loader_String 处理用户输入 | PHP Twig SSTI 利用 | `../injection/ref/php-twig-ssti-exploitation.md` |
| Twig 调试模式开启暴露内部错误 | PHP Twig SSTI 利用 | `../injection/ref/php-twig-ssti-exploitation.md` |
| Apache 2.4.49 路径遍历配置错误（CVE-2021-41773） | Apache 2.4.49 路径遍历漏洞利用 | `../injection/ref/apache-2.4.49-path-traversal-exploitation.md` |
| Apache 2.4.50 路径遍历配置错误 | Apache 路径遍历与 CGI RCE 利用 | `../injection/ref/apache-path-traversal-rce-exploitation.md` |
| 根目录 Require all granted 配置 | Apache 路径遍历与 CGI RCE 利用 | `../injection/ref/apache-path-traversal-rce-exploitation.md` `../injection/ref/apache-2.4.49-path-traversal-exploitation.md` |
| CGI 未授权执行配置 | Apache 路径遍历与 CGI RCE 利用 | `../injection/ref/apache-path-traversal-rce-exploitation.md` |
| Options Indexes 目录列表启用 | 目录列表攻击 | `ref/directory-listing-attack.md` |
| Options FollowSymLinks 符号链接遍历 | 路径遍历攻击 | `../injection/ref/path-traversal-attack.md` `../injection/ref/apache-2.4.49-path-traversal-exploitation.md` |
| 目录列表功能开启 | 目录列表攻击 | `ref/directory-listing-attack.md` |
| 错误页面显示堆栈信息 | 错误信息泄露利用 | `ref/error-information-leakage.md` |
| 发现示例应用 | 示例应用漏洞利用 | `ref/sample-application-exploitation.md` |
| HTTP 安全头缺失 | 安全头缺失攻击 | `ref/security-headers-attack.md` |
| 云存储桶公开访问 | 云存储配置错误 | `ref/cloud-storage-misconfiguration.md` |
| 调试模式开启 | 调试功能滥用 | `ref/debug-mode-exploitation.md` |
| 发现备份文件 | 敏感文件泄露 | `ref/sensitive-file-exposure.md` |
| CORS 配置过于宽松 | CORS 配置错误 | `ref/cors-misconfiguration.md` |
| 不必要的服务开启 | 服务暴露攻击 | `ref/unnecessary-service-exposure.md` |
| 应用无 HTTPS/TLS 配置 | HTTP-only 部署攻击 | `ref/http-only-deployment-attack.md` `ref/http-only-deployment-attack-advanced.md` `ref/plaintext-secret-storage-exploitation-advanced.md` |
| 仅 HTTP 端口（80）监听 | HTTP-only 部署攻击 | `ref/http-only-deployment-attack.md` `ref/http-only-deployment-attack-advanced.md` |
| 缺少 HSTS 响应头 | HTTP-only 部署攻击 | `ref/http-only-deployment-attack.md` `ref/http-only-deployment-attack-advanced.md` |
| Cookie 缺少 Secure 标志 | HTTP-only 部署攻击 | `ref/http-only-deployment-attack.md` `ref/http-only-deployment-attack-advanced.md` |
| 网络嗅探凭证拦截 | HTTP-only 部署凭证拦截攻击 | `ref/http-only-deployment-credential-interception.md` |
| 同一网络 HTTP 流量嗅探 | HTTP-only 部署凭证拦截攻击 | `ref/http-only-deployment-credential-interception.md` |
| ARP 欺骗中间人攻击 | HTTP-only 部署凭证拦截攻击 | `ref/http-only-deployment-credential-interception.md` |
| 会话 Cookie 明文传输劫持 | HTTP-only 部署凭证拦截攻击 | `ref/http-only-deployment-credential-interception.md` |
| PHP 应用仅 HTTP 部署 | HTTP-only 部署攻击 | `ref/http-only-deployment-attack.md` `ref/http-only-deployment-attack-advanced.md` |
| Docker 环境无 HTTPS 配置 | HTTP-only 部署攻击 | `ref/http-only-deployment-attack.md` `ref/http-only-deployment-attack-advanced.md` |
| HTTP-only+ 凭证拦截+SSTI 组合攻击 | HTTP-only 部署攻击 | `ref/http-only-deployment-attack-advanced.md` |
| 中间人攻击（MITM）会话劫持 | HTTP-only 部署攻击 | `ref/http-only-deployment-attack-advanced.md` |
| Django 应用无 HTTPS 配置 | HTTP-only 部署攻击 | `ref/http-only-deployment-attack.md` `ref/http-only-deployment-attack-advanced.md` |
| Flask 应用仅 HTTP 端口 38583 | HTTP-only 部署攻击 | `ref/http-only-deployment-attack.md` |
| Werkzeug 开发服务器无 SSL | HTTP-only 部署攻击 | `ref/http-only-deployment-attack.md` |
| 敏感信息明文存储 | 明文密钥存储利用 | `ref/plaintext-secret-storage-exploitation.md` `ref/plaintext-secret-storage-exploitation-advanced.md` |
| 发现 CTF Flag 文件 | 明文密钥存储利用 | `ref/plaintext-secret-storage-exploitation.md` `ref/plaintext-secret-storage-exploitation-advanced.md` |
| Docker 环境变量明文存储 Flag | 明文密钥存储利用 | `ref/plaintext-secret-storage-exploitation.md` `ref/plaintext-secret-storage-exploitation-advanced.md` |
| Docker 镜像层嵌入敏感信息 | 明文密钥存储利用 | `ref/plaintext-secret-storage-exploitation.md` `ref/plaintext-secret-storage-exploitation-advanced.md` |
| Git 历史提交 Flag/凭证 | 明文密钥存储利用 | `ref/plaintext-secret-storage-exploitation.md` `ref/plaintext-secret-storage-exploitation-advanced.md` |
| 敏感文件 Web 可访问（644 权限） | 明文密钥存储利用 | `ref/plaintext-secret-storage-exploitation.md` `ref/plaintext-secret-storage-exploitation-advanced.md` |
| Docker 环境敏感信息提取 | 明文密钥存储利用 | `ref/plaintext-secret-storage-exploitation.md` `ref/plaintext-secret-storage-exploitation-advanced.md` |
| Django SECRET_KEY 硬编码在源代码 | 明文密钥存储利用 | `ref/plaintext-secret-storage-exploitation.md` `ref/plaintext-secret-storage-exploitation-advanced.md` |
| Django 数据库凭证硬编码 | 明文密钥存储利用 | `ref/plaintext-secret-storage-exploitation.md` `ref/plaintext-secret-storage-exploitation-advanced.md` |
| SSRF 组合攻击提取明文存储 Flag | 明文密钥存储利用 | `ref/plaintext-secret-storage-exploitation.md` `ref/plaintext-secret-storage-exploitation-advanced.md` |
| 无认证系统命令注入提取明文 Flag | 明文密钥存储利用 | `ref/plaintext-secret-storage-exploitation.md` `../injection/ref/no-auth-command-injection-exploitation.md` |
| Flask 应用 debug=True 开启调试模式 | Flask 调试模式滥用 | `ref/flask-debug-mode-exploitation.md` `ref/flask-debug-mode-exploitation-advanced.md` |
| Werkzeug 调试器暴露 | Flask 调试模式滥用 | `ref/flask-debug-mode-exploitation.md` `ref/flask-debug-mode-exploitation-advanced.md` |
| 错误页面显示堆栈跟踪 | Flask 调试模式滥用 | `ref/flask-debug-mode-exploitation.md` `ref/flask-debug-mode-exploitation-advanced.md` |
| Flask 应用无认证架构 + 调试模式 | Flask 无认证架构 XSS 组合攻击 | `../injection/ref/flask-no-auth-xss-combo-exploitation.md` |
| Django 应用 DEBUG=True 开启 | Django 安全配置错误 | `ref/debug-mode-exploitation.md` |
| Django SECRET_KEY 硬编码在 settings.py | 明文密钥存储利用 | `ref/plaintext-secret-storage-exploitation.md` `ref/plaintext-secret-storage-exploitation-advanced.md` |
| Django 数据库凭证硬编码 | 明文密钥存储利用 | `ref/plaintext-secret-storage-exploitation.md` `ref/plaintext-secret-storage-exploitation-advanced.md` |
| Docker 环境内部服务无认证 | 信任边界违规 | `../insecure-design/ref/trust-boundary-violation-ssrf.md` |
| secret.txt/.env 明文存储 Flag | 明文密钥存储利用 | `ref/plaintext-secret-storage-exploitation.md` `ref/plaintext-secret-storage-exploitation-advanced.md` |
| Docker 镜像层嵌入敏感信息 | 明文密钥存储利用 | `ref/plaintext-secret-storage-exploitation.md` `ref/plaintext-secret-storage-exploitation-advanced.md` |
| Git 历史提交 Flag/凭证 | 明文密钥存储利用 | `ref/plaintext-secret-storage-exploitation.md` `ref/plaintext-secret-storage-exploitation-advanced.md` |
| 敏感文件 Web 可访问（644 权限） | 明文密钥存储利用 | `ref/plaintext-secret-storage-exploitation.md` `ref/plaintext-secret-storage-exploitation-advanced.md` |
| .env 文件提交到 Git 仓库 | 敏感信息明文存储利用 | `ref/sensitive-data-plaintext-exploitation.md` `ref/plaintext-secret-storage-exploitation-advanced.md` |
| Git 历史可追溯敏感信息 | 敏感信息明文存储利用 | `ref/sensitive-data-plaintext-exploitation.md` `ref/plaintext-secret-storage-exploitation-advanced.md` |
| Docker build ARG 包含密钥 | 敏感信息明文存储利用 | `ref/sensitive-data-plaintext-exploitation.md` `ref/plaintext-secret-storage-exploitation-advanced.md` |
| 日志文件包含敏感信息 | 敏感信息明文存储利用 | `ref/sensitive-data-plaintext-exploitation.md` `ref/plaintext-secret-storage-exploitation-advanced.md` |
| 备份文件（.bak/.old）Web 可访问 | 敏感信息明文存储利用 | `ref/sensitive-data-plaintext-exploitation.md` `ref/plaintext-secret-storage-exploitation-advanced.md` |
| 无认证系统存在路径遍历漏洞 | 无认证系统路径遍历利用 | `ref/no-auth-path-traversal-exploitation.md` |
| 静态文件服务无认证 + 路径遍历 | 无认证系统路径遍历利用 | `ref/no-auth-path-traversal-exploitation.md` |
| 登录接口无速率限制 | 无速率限制滥用 | `ref/no-rate-limit-abuse.md` |
| 无 CAPTCHA 可自动化攻击 | 无速率限制滥用 | `ref/no-rate-limit-abuse.md` |
| 无 IP 封禁机制 | 无速率限制滥用 | `ref/no-rate-limit-abuse.md` |
| 每请求触发高资源消耗操作（如 PhantomJS） | 无速率限制滥用 | `ref/no-rate-limit-abuse.md` |
| Flask 应用无速率限制 | 无速率限制滥用 | `ref/no-rate-limit-abuse.md` |
| 100 个快速连续请求全部成功 | 无速率限制滥用 | `ref/no-rate-limit-abuse.md` |
| 无 HTTP 429 响应 | 无速率限制滥用 | `ref/no-rate-limit-abuse.md` |
| Docker 容器内敏感文件读取 | Docker 环境敏感信息提取 | `ref/docker-secret-extraction-advanced.md` |
| Docker 环境变量包含 Flag/密钥 | Docker 环境敏感信息提取 | `ref/docker-secret-extraction-advanced.md` |
| CTF 挑战 Docker 环境信息提取 | Docker 环境敏感信息提取 | `ref/docker-secret-extraction-advanced.md` |
| Apache 静态文件服务 CTF 挑战 | Apache 2.4.49 路径遍历漏洞利用 | `ref/apache-2.4.49-path-traversal-exploitation.md` |
| 路径遍历读取/tmp/flag 文件 | Apache 2.4.49 路径遍历漏洞利用 | `ref/apache-2.4.49-path-traversal-exploitation.md` |
| 路径遍历读取/etc/passwd 用户枚举 | Apache 2.4.49 路径遍历漏洞利用 | `ref/apache-2.4.49-path-traversal-exploitation.md` |
| 路径遍历读取/proc/self/environ | Apache 2.4.49 路径遍历漏洞利用 | `ref/apache-2.4.49-path-traversal-exploitation.md` |
| 路径遍历读取 Apache 配置文件 | Apache 2.4.49 路径遍历漏洞利用 | `ref/apache-2.4.49-path-traversal-exploitation.md` |
| Cookie 缺少 Secure/HttpOnly 标志 | Cookie 安全配置错误利用 | `ref/cookie-security-misconfiguration.md` |
| Cookie 缺少 SameSite 标志 | Cookie 安全配置错误利用 | `ref/cookie-security-misconfiguration.md` |
| Cookie 明文存储敏感信息 | Cookie 安全配置错误利用 | `ref/cookie-security-misconfiguration.md` |
| Cookie Domain 作用域过宽 | Cookie 安全配置错误利用 | `ref/cookie-security-misconfiguration.md` |
| 环境变量泄露（DATABASE_URL、API_KEY 等） | 环境变量信息泄露利用 | `ref/environment-variable-leakage.md` |
| .env 文件 Web 可访问 | 环境变量信息泄露利用 | `ref/environment-variable-leakage.md` |
| 调试端点暴露环境变量 | 环境变量信息泄露利用 | `ref/environment-variable-leakage.md` |
| 容器环境变量明文存储 | 环境变量信息泄露利用 | `ref/environment-variable-leakage.md` |
| ASP.NET 调试模式开启（debug="true"） | ASP.NET 配置错误利用 | `ref/aspnet-misconfiguration-exploitation.md` |
| ASP.NET 自定义错误页面未配置 | ASP.NET 配置错误利用 | `ref/aspnet-misconfiguration-exploitation.md` |
| ASP.NET trace.axd 可访问 | ASP.NET 配置错误利用 | `ref/aspnet-misconfiguration-exploitation.md` |
| ASP.NET elmah.axd 未保护 | ASP.NET 配置错误利用 | `ref/aspnet-misconfiguration-exploitation.md` |
| ASP.NET web.config 可访问 | ASP.NET 配置错误利用 | `ref/aspnet-misconfiguration-exploitation.md` |
| ASP.NET ViewState 未加密 | ASP.NET 配置错误利用 | `ref/aspnet-misconfiguration-exploitation.md` |
| IIS 目录浏览启用 | ASP.NET 配置错误利用 | `ref/aspnet-misconfiguration-exploitation.md` |
| OPTIONS 方法暴露支持 HTTP 方法 | HTTP 方法测试攻击 | `ref/http-methods-attack.md` |
| PUT 方法允许文件上传 | HTTP 方法测试攻击 | `ref/http-methods-attack.md` |
| DELETE 方法允许删除文件 | HTTP 方法测试攻击 | `ref/http-methods-attack.md` |
| TRACE 方法启用（XST 攻击） | HTTP 方法测试攻击 | `ref/http-methods-attack.md` |
| CONNECT 方法允许代理隧道 | HTTP 方法测试攻击 | `ref/http-methods-attack.md` |
| HEAD 方法可能绕过访问控制 | HTTP 方法测试攻击 | `ref/http-methods-attack.md` |
| 错误页面显示详细 SQL 错误 | 错误处理测试攻击 | `ref/error-handling-testing.md` |
| 错误页面显示堆栈跟踪 | 错误处理测试攻击 | `ref/error-handling-testing.md` |
| 错误页面显示文件路径信息 | 错误处理测试攻击 | `ref/error-handling-testing.md` |
| 错误页面显示数据库版本 | 错误处理测试攻击 | `ref/error-handling-testing.md` |
| 触发异常返回详细调试信息 | 错误处理测试攻击 | `ref/error-handling-testing.md` |
| 需要系统化枚举敏感目录 | 敏感资源枚举 | `ref/sensitive-resource-enumeration.md` |
| 需要发现备份文件和配置 | 敏感资源枚举 | `ref/sensitive-resource-enumeration.md` |
| 需要发现管理接口路径 | 敏感资源枚举 | `ref/sensitive-resource-enumeration.md` |
| 需要发现 API 端点 | 敏感资源枚举 | `ref/sensitive-resource-enumeration.md` |
| 需要发现版本控制目录（.git） | 敏感资源枚举 | `ref/sensitive-resource-enumeration.md` |
| 发现 J2EE 应用使用 HTTP 传输 | J2EE 数据传输未加密攻击 | `ref/j2ee-unencrypted-transport-attack.md` |
| J2EE 应用未配置 HTTPS | J2EE 数据传输未加密攻击 | `ref/j2ee-unencrypted-transport-attack.md` |
| HTTP 流量可被嗅探 | J2EE 数据传输未加密攻击 | `ref/j2ee-unencrypted-transport-attack.md` |
| HTTPS 降级攻击（SSL 剥离） | J2EE 数据传输未加密攻击 | `ref/j2ee-unencrypted-transport-attack.md` |
| 发现硬编码密钥/密码 | 硬编码常量检测与利用 | `ref/hardcoded-constants-detection.md` |
| 发现硬编码 Flag/秘密值 | 硬编码常量检测与利用 | `ref/hardcoded-constants-detection.md` |
| 源代码审计发现魔术数字 | 硬编码常量检测与利用 | `ref/hardcoded-constants-detection.md` |
| 二进制文件逆向分析 | 硬编码常量检测与利用 | `ref/hardcoded-constants-detection.md` |
| Git 历史泄露硬编码凭证 | 硬编码常量检测与利用 | `ref/hardcoded-constants-detection.md` |
| 发现 XXE 漏洞（XML 解析） | XXE file:// 协议利用 | `../injection/ref/xxe-file-protocol-exploitation.md` |
| SOAP 服务存在 XXE 漏洞 | XXE file:// 协议利用 | `../injection/ref/xxe-file-protocol-exploitation.md` |
| XML-RPC 接口存在 XXE | XXE file:// 协议利用 | `../injection/ref/xxe-file-protocol-exploitation.md` |
| SVG 上传存在 XXE 漏洞 | XXE file:// 协议利用 | `../injection/ref/xxe-file-protocol-exploitation.md` |
| SAML 认证存在 XXE 漏洞 | XXE file:// 协议利用 | `../injection/ref/xxe-file-protocol-exploitation.md` |

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
| 如何测试 HTTP 方法配置 | HTTP 方法测试攻击 | `ref/http-methods-attack.md` |
| 如何检测默认凭证 | 默认凭证检测 | `ref/default-credential-detection.md` |
| 如何检测云存储权限 | 云权限检测 | `ref/cloud-permission-detection.md` |
| 如何检测安全头配置 | 安全头检测 | `ref/security-header-detection.md` |
| 如何绕过 WAF 防护 | WAF 绕过技术 | `ref/waf-bypass-techniques.md` |
| 如何利用错误信息 | 错误信息分析 | `ref/error-message-analysis.md` |
| 如何进行错误处理测试 | 错误处理测试攻击 | `ref/error-handling-testing.md` |
| 如何进行配置基线对比 | 配置基线检查 | `ref/configuration-baseline-check.md` |
| 如何检测硬编码常量 | 硬编码常量检测与利用 | `ref/hardcoded-constants-detection.md` |
| 如何检测传输加密配置 | J2EE 数据传输未加密攻击 | `ref/j2ee-unencrypted-transport-attack.md` |
| 如何进行 XXE 漏洞测试 | XXE file:// 协议利用 | `../injection/ref/xxe-file-protocol-exploitation.md` |

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
| SM-031 | Apache 路径遍历与 CGI RCE 利用 | `../injection/ref/apache-path-traversal-rce-exploitation.md` | 漏洞发现/利用 |
| SM-032 | Apache 2.4.49 路径遍历漏洞利用 | `../injection/ref/apache-2.4.49-path-traversal-exploitation.md` | 漏洞发现/利用 |
| SM-033 | HTTP-only 部署攻击 | `ref/http-only-deployment-attack.md` | 漏洞发现/利用 |
| SM-034 | 明文密钥存储利用 | `ref/plaintext-secret-storage-exploitation.md` | 漏洞发现/利用 |
| SM-035 | WordPress 安全配置错误攻击 | `ref/wordpress-security-misconfiguration-attack.md` | 漏洞发现/利用 |
| SM-036 | 无认证系统路径遍历利用 | `ref/no-auth-path-traversal-exploitation.md` | 漏洞发现/利用 |
| SM-037 | Docker 环境敏感信息提取（高级） | `ref/docker-secret-extraction-advanced.md` | 漏洞发现/利用 |
| SM-038 | HTTP-only 部署攻击（高级） | `ref/http-only-deployment-attack-advanced.md` | 漏洞发现/利用 |
| SM-039 | 明文密钥存储利用（高级） | `ref/plaintext-secret-storage-exploitation-advanced.md` | 漏洞发现/利用 |
| SM-040 | WordPress 安全配置错误攻击 | `ref/wordpress-security-misconfiguration-attack.md` | 漏洞发现/利用 |
| SM-041 | HTTP-only 部署攻击 | `ref/http-only-deployment-exploitation.md` | 漏洞发现/利用 |
| SM-042 | 明文密钥存储利用 | `ref/plaintext-secret-storage-exploitation.md` | 漏洞发现/利用 |
| SM-043 | Flask 应用 HTTP-only 部署 | `ref/http-only-deployment-exploitation.md` | 漏洞发现/利用 |
| SM-044 | Docker 环境明文 Flag 存储 | `ref/plaintext-secret-storage-exploitation.md` | 漏洞发现/利用 |
| SM-045 | 命令注入 + 明文存储组合攻击 | `ref/plaintext-secret-storage-exploitation.md` | 漏洞发现/利用 |
| SM-046 | 路径遍历 + 明文存储组合攻击 | `ref/plaintext-secret-storage-exploitation.md` | 漏洞发现/利用 |
| SM-047 | HTTP-only 部署凭证拦截攻击 | `ref/http-only-deployment-credential-interception.md` | 漏洞发现/利用 |
| SM-048 | HTTP-only 部署攻击（增强版） | `ref/http-only-deployment-attack.md` | 漏洞发现/利用 |
| SM-049 | 明文密钥存储利用（增强版） | `ref/plaintext-secret-storage-exploitation.md` | 漏洞发现/利用 |
| SM-050 | HTTP-only 部署攻击方法论 | `ref/http-only-deployment-attack-methodology.md` | 漏洞发现/利用 |
| SM-051 | 明文密钥存储利用方法论 | `ref/plaintext-secret-storage-exploitation-methodology.md` | 漏洞发现/利用 |
| SM-052 | 无速率限制滥用 | `ref/no-rate-limit-abuse.md` | 漏洞发现/利用 |
| SM-053 | Cookie 安全配置错误利用 | `ref/cookie-security-misconfiguration.md` | 漏洞发现/利用 |
| SM-054 | 环境变量信息泄露利用 | `ref/environment-variable-leakage.md` | 漏洞发现/利用 |
| SM-055 | ASP.NET 配置错误利用 | `ref/aspnet-misconfiguration-exploitation.md` | 漏洞发现/利用 |
| SM-056 | HTTP 方法测试攻击 | `ref/http-methods-attack.md` | 漏洞发现/利用 |
| SM-057 | 错误处理测试攻击 | `ref/error-handling-testing.md` | 漏洞发现/利用 |
| SM-058 | 敏感资源枚举 | `ref/sensitive-resource-enumeration.md` | 信息收集 |
| SM-059 | 硬编码常量检测与利用 | `ref/hardcoded-constants-detection.md` | 代码审计/漏洞利用 |
| SM-060 | J2EE 数据传输未加密攻击 | `ref/j2ee-unencrypted-transport-attack.md` | 漏洞发现/利用 |
| SM-061 | XXE file:// 协议利用 | `../injection/ref/xxe-file-protocol-exploitation.md` | 漏洞利用 |

### 7. WordPress 特定安全配置错误场景

| 场景 | 参考方法论 | 文件路径 |
|------|-----------|----------|
| WordPress HTTP-only 部署无 HTTPS | HTTP-only 部署攻击 | `ref/http-only-deployment-attack.md` `ref/wordpress-security-misconfiguration-attack.md` |
| WordPress 数据库凭证硬编码 | 明文密钥存储利用 | `ref/plaintext-secret-storage-exploitation.md` `ref/wordpress-security-misconfiguration-attack.md` |
| WordPress 缺少安全响应头 | 安全头缺失攻击 | `ref/security-headers-attack.md` `ref/wordpress-security-misconfiguration-attack.md` |
| WordPress 调试模式开启 | 调试功能滥用 | `ref/debug-mode-exploitation.md` `ref/wordpress-security-misconfiguration-attack.md` |
| WordPress 备份文件 Web 可访问 | 敏感文件泄露 | `ref/sensitive-file-exposure.md` `ref/wordpress-security-misconfiguration-attack.md` |
| Docker 容器环境变量 Flag | Docker 环境敏感信息提取 | `ref/docker-secret-extraction.md` `ref/wordpress-security-misconfiguration-attack.md` |
| WordPress HTTP-only 部署凭证拦截 | WordPress 安全配置错误攻击 | `ref/wordpress-security-misconfiguration-attack.md` |
| WordPress 明文数据库凭证存储 | WordPress 安全配置错误攻击 | `ref/wordpress-security-misconfiguration-attack.md` |
| WordPress 明文 OAuth Token 存储 | WordPress 安全配置错误攻击 | `ref/wordpress-security-misconfiguration-attack.md` |
| WordPress 缺少 CSP 响应头 | WordPress 安全配置错误攻击 | `ref/wordpress-security-misconfiguration-attack.md` |
| WordPress 缺少 HSTS 响应头 | WordPress 安全配置错误攻击 | `ref/wordpress-security-misconfiguration-attack.md` |
| WordPress 缺少 X-Frame-Options | WordPress 安全配置错误攻击 | `ref/wordpress-security-misconfiguration-attack.md` |
| WordPress 目录列表启用 | WordPress 安全配置错误攻击 | `ref/wordpress-security-misconfiguration-attack.md` |
| WordPress Cookie 缺少 SameSite | WordPress 安全配置错误攻击 | `ref/wordpress-security-misconfiguration-attack.md` |
| WordPress Cookie 缺少 Secure 标志 | WordPress 安全配置错误攻击 | `ref/wordpress-security-misconfiguration-attack.md` |
| WordPress Cookie 缺少 HttpOnly 标志 | Cookie 安全配置错误利用 | `ref/cookie-security-misconfiguration.md` `ref/wordpress-security-misconfiguration-attack.md` |
| WordPress 环境变量明文存储 | Docker 环境敏感信息提取 | `ref/docker-secret-extraction-advanced.md` `ref/wordpress-security-misconfiguration-attack.md` |
| WordPress 环境变量泄露 | 环境变量信息泄露利用 | `ref/environment-variable-leakage.md` `ref/wordpress-security-misconfiguration-attack.md` |

### 8. FastAPI/Python 应用特定安全配置错误场景

| 场景 | 参考方法论 | 文件路径 |
|------|-----------|----------|
| FastAPI 应用无 HTTPS 配置 | HTTP-only 部署攻击 | `ref/http-only-deployment-attack.md` `ref/http-only-deployment-attack-advanced.md` `ref/http-only-deployment-exploitation.md` |
| FastAPI 应用缺少安全响应头 | 安全头缺失攻击 | `ref/security-headers-attack.md` |
| FastAPI 应用调试模式开启 | Flask 调试模式滥用 | `ref/flask-debug-mode-exploitation.md` |
| FastAPI 应用无速率限制 | 无速率限制滥用 | `ref/no-rate-limit-abuse.md` `ref/flask-no-rate-limit-abuse.md` |
| FastAPI 应用 Cookie 缺少 Secure 标志 | Cookie 安全配置错误利用 | `ref/cookie-security-misconfiguration.md` |
| FastAPI 应用 Cookie 缺少 HttpOnly | Cookie 安全配置错误利用 | `ref/cookie-security-misconfiguration.md` |
| FastAPI 应用 Cookie 缺少 SameSite | Cookie 安全配置错误利用 | `ref/cookie-security-misconfiguration.md` |
| FastAPI 应用 CORS 配置过于宽松 | CORS 配置错误 | `ref/cors-misconfiguration.md` |
| FastAPI 应用环境变量明文存储 Flag | 环境变量信息泄露利用 | `ref/environment-variable-leakage.md` |
| FastAPI 应用环境变量泄露 | 环境变量信息泄露利用 | `ref/environment-variable-leakage.md` |
| FastAPI 应用 Docker 镜像层嵌入敏感信息 | 明文密钥存储利用 | `ref/plaintext-secret-storage-exploitation-advanced.md` `ref/plaintext-secret-storage-exploitation.md` |
| FastAPI 应用 Git 历史提交 Flag/凭证 | 明文密钥存储利用 | `ref/plaintext-secret-storage-exploitation-advanced.md` |
| FastAPI 应用敏感文件 Web 可访问 | 明文密钥存储利用 | `ref/plaintext-secret-storage-exploitation-advanced.md` `ref/plaintext-secret-storage-exploitation.md` |
| FastAPI 应用无认证架构 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` `../broken-access-control/ref/no-auth-system-detection-exploitation.md` |
| FastAPI 应用所有端点公开访问 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` |
| FastAPI 应用无安全中间件配置 | 无认证系统检测与利用 | `ref/no-authentication-system-exploitation.md` |
| FastAPI 应用自动生成的 API 文档暴露 | 敏感目录枚举 | `ref/sensitive-resource-enumeration.md` |
| FastAPI 应用 Uvicorn 默认配置暴露 | 服务暴露攻击 | `ref/unnecessary-service-exposure.md` |
| Docker 环境内部服务无应用层认证 | 信任边界违规 | `../insecure-design/ref/trust-boundary-violation-ssrf.md` |
| Docker 容器环境变量包含 Flag/密钥 | Docker 环境敏感信息提取 | `ref/docker-secret-extraction-advanced.md` `ref/plaintext-secret-storage-exploitation.md` |
| CTF 挑战 Docker 环境信息提取 | Docker 环境敏感信息提取 | `ref/docker-secret-extraction-advanced.md` `ref/plaintext-secret-storage-exploitation.md` |
| Python 应用使用 pickle 无安全警告 | 不安全设计检测 | `../insecure-design/ref/trust-boundary-violation-ssrf.md` |
| FastAPI 应用无 CSRF 保护 | CSRF 检测与利用 | `../broken-access-control/ref/csrf-detection-exploitation.md` |
| FastAPI 应用无日志记录安全事件 | 安全日志缺失 | `ref/security-logging-failures.md` |
| Flask 应用 HTTP-only 部署（仅端口 80） | HTTP-only 部署攻击 | `ref/http-only-deployment-exploitation.md` |
| Flask 应用明文 Flag 存储（/FLAG.txt） | 明文密钥存储利用 | `ref/plaintext-secret-storage-exploitation.md` |
| Flask 应用 Docker 镜像层嵌入 Flag | 明文密钥存储利用 | `ref/plaintext-secret-storage-exploitation.md` |
| Flask 应用命令注入 + 明文存储组合 | 明文密钥存储利用 | `ref/plaintext-secret-storage-exploitation.md` `../injection/ref/os-command-injection-exploitation.md` |
| Flask 应用无认证架构（所有端点公开） | Flask 无认证架构检测与利用 | `ref/flask-no-auth-architecture.md` |
| Flask 应用无 SECRET_KEY 配置 | Flask 无认证架构检测与利用 | `ref/flask-no-auth-architecture.md` |
| Flask 应用无登录/登出端点 | Flask 无认证架构检测与利用 | `ref/flask-no-auth-architecture.md` |
| Flask 应用无会话管理 | Flask 无认证架构检测与利用 | `ref/flask-no-auth-architecture.md` |
| CTF 挑战应用无认证架构 | Flask 无认证架构检测与利用 | `ref/flask-no-auth-architecture.md` |

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
