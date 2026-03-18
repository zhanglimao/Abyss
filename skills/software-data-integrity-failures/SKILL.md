---
name: software-data-integrity-failures
description: 软件或数据完整性失效渗透测试技能，用于检测和利用代码、数据、配置完整性验证缺失的漏洞
---

# Software or Data Integrity Failures（软件或数据完整性失效）渗透测试技能

## 简介

软件或数据完整性失效（Software or Data Integrity Failures）是 OWASP Top 10:2025 排名第 8 的安全风险。当代码和基础设施未能防止无效或不可信的数据/代码被当作可信和有效的来处理时，就会发生完整性失效漏洞。

本技能提供系统性的方法论，指导渗透测试人员发现和利用完整性漏洞，包括依赖投毒、反序列化攻击、更新劫持、签名验证绕过、CI/CD 管道入侵等攻击技术。

---

## 方法论映射表

### 1. 渗透过程中遇到什么情况该参考哪个方法论

| 遇到的情况 | 参考方法论 | 文件路径 |
|-----------|-----------|----------|
| 依赖包无签名验证 | 依赖投毒攻击 | `ref/dependency-poisoning.md` |
| 发现反序列化接口 | 反序列化攻击 | `ref/deserialization-attack.md` |
| 软件更新无签名 | 更新劫持攻击 | `ref/update-hijacking.md` |
| CI/CD 管道可篡改 | CI/CD 管道攻击 | `ref/cicd-pipeline-attack.md` |
| 发现从 CDN 加载脚本 | CDN 投毒攻击 | `ref/cdn-poisoning.md` |
| 固件更新无验证 | 固件投毒攻击 | `ref/firmware-poisoning.md` |
| 发现对象序列化传输 | 对象篡改攻击 | `ref/object-tampering.md` |
| 发现信任外部数据 | 数据完整性攻击 | `ref/data-integrity-attack.md` |
| 发现无哈希验证下载 | 下载篡改攻击 | `ref/download-tampering.md` |
| 发现不可信源包含 | 不可信源攻击 | `ref/untrusted-source-attack.md` |
| 发现 Cookie 域配置过宽 | Cookie 域与会话劫持攻击 | `ref/cookie-domain-attack.md` |
| 发现 DNS 映射到第三方 | Cookie 域与会话劫持攻击 | `ref/cookie-domain-attack.md` |
| 发现子域信任关系 | Cookie 域与会话劫持攻击 | `ref/cookie-domain-attack.md` |
| 发现下载代码无完整性检查 | 软件供应链完整性验证绕过 | `ref/supply-chain-integrity-bypass.md` |
| 发现依赖混淆风险 | 软件供应链完整性验证绕过 | `ref/supply-chain-integrity-bypass.md` |
| 发现仓库劫持风险 | 软件供应链完整性验证绕过 | `ref/supply-chain-integrity-bypass.md` |
| 发现签名验证缺陷 | 软件供应链完整性验证绕过 | `ref/supply-chain-integrity-bypass.md` |
| 发现哈希校验弱点 | 软件供应链完整性验证绕过 | `ref/supply-chain-integrity-bypass.md` |
| 发现批量赋值/对象注入风险 | 对象注入与批量赋值攻击 | `ref/object-injection-mass-assignment.md` |
| 发现原型污染风险 | 对象注入与批量赋值攻击 | `ref/object-injection-mass-assignment.md` |
| 发现动态属性修改风险 | 对象注入与批量赋值攻击 | `ref/object-injection-mass-assignment.md` |
| 发现 Android 组件导出风险 | Android 应用程序组件导出攻击 | `ref/android-component-export-attack.md` |
| 发现 Intent 过滤器滥用风险 | Android 应用程序组件导出攻击 | `ref/android-component-export-attack.md` |
| 发现 Content Provider 泄露风险 | Android 应用程序组件导出攻击 | `ref/android-component-export-attack.md` |

### 2. 遇到什么样的业务系统、软件环境、基础设施该参考哪个方法论

| 系统/环境特征 | 参考方法论 | 文件路径 |
|--------------|-----------|----------|
| Java 应用 | Java 反序列化测试 | `ref/java-deserialization-testing.md` |
| PHP 应用 | PHP 反序列化测试 | `ref/php-deserialization-testing.md` |
| .NET 应用 | .NET 反序列化测试 | `ref/dotnet-deserialization-testing.md` |
| Python 应用 | Python 反序列化测试 | `ref/python-deserialization-testing.md` |
| 使用 npm/PyPI/Maven | 包管理器安全测试 | `ref/package-manager-security.md` |
| 自动更新系统 | 更新机制安全测试 | `ref/update-mechanism-security.md` |
| 容器化部署 | 容器完整性测试 | `ref/container-integrity-testing.md` |
| IoT/嵌入式设备 | 固件完整性测试 | `ref/firmware-integrity-testing.md` |
| 使用 CDN 服务 | CDN 安全测试 | `ref/cdn-security-testing.md` |
| 使用代码签名 | 签名验证测试 | `ref/signature-verification-testing.md` |

### 3. 遇到什么样的问题该参考哪个方法论

| 问题类型 | 参考方法论 | 文件路径 |
|---------|-----------|----------|
| 如何检测反序列化点 | 反序列化点检测 | `ref/deserialization-point-detection.md` |
| 如何生成反序列化 Payload | Payload 生成指南 | `ref/payload-generation-guide.md` |
| 如何验证软件完整性 | 完整性验证方法 | `ref/integrity-verification-methods.md` |
| 如何检测依赖投毒 | 依赖投毒检测 | `ref/dependency-poisoning-detection.md` |
| 如何测试更新机制 | 更新机制测试 | `ref/update-mechanism-testing.md` |
| 如何审计 CI/CD 安全 | CI/CD 安全审计 | `ref/cicd-security-audit.md` |
| 如何检测信任边界 | 信任边界检测 | `ref/trust-boundary-detection.md` |
| 如何测试签名验证 | 签名验证测试 | `ref/signature-verification-testing.md` |

### 4. 渗透测试决策流程图

```
                                    ┌─────────────────┐
                                    │  完整性安全测试  │
                                    └────────┬────────┘
                                             │
                                             ▼
                                    ┌─────────────────┐
                                    │   信任点识别     │
                                    │  - 外部数据源   │
                                    │  - 更新机制     │
                                    │  - 反序列化点   │
                                    └────────┬────────┘
                                             │
                    ┌────────────────────────┼────────────────────────┐
                    │                        │                        │
                    ▼                        ▼                        ▼
          ┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
          │  发现反序列化点  │      │  发现更新机制   │      │   发现依赖问题  │
          └────────┬────────┘      └────────┬────────┘      └────────┬────────┘
                   │                        │                        │
                   ▼                        ▼                        ▼
          ┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
          │  ref/deserial-  │      │  ref/update-    │      │  ref/dependency-│
          │  ization-attack.│      │  hijacking.md   │      │  poisoning.md   │
          │  md             │      │                 │      │                 │
          └─────────────────┘      └─────────────────┘      └─────────────────┘
```

### 5. 攻击技术思维导图

```
软件或数据完整性失效攻击技术
├── 反序列化攻击
│   ├── Java 反序列化 RCE
│   ├── PHP 反序列化攻击
│   ├── .NET 反序列化攻击
│   ├── Python pickle 攻击
│   └── YAML 反序列化攻击
├── 依赖投毒攻击
│   ├── 依赖混淆 (Dependency Confusion)
│   ├── Typosquatting（包名混淆）
│   ├── 恶意包注入
│   └── 传递依赖投毒
├── 更新劫持攻击
│   ├── 更新服务器劫持
│   ├── 中间人攻击
│   ├── 签名伪造
│   └── 回滚攻击
├── CI/CD 管道攻击
│   ├── 构建脚本篡改
│   ├── 凭证窃取
│   ├── 构建缓存污染
│   └── 部署劫持
├── 数据篡改攻击
│   ├── 对象篡改
│   ├── 配置篡改
│   ├── 日志篡改
│   └── 数据库篡改
├── 信任边界攻击
│   ├── CDN 投毒
│   ├── 第三方脚本注入
│   ├── 不可信源包含
│   └── 跨域信任滥用
├── Cookie 域与会话劫持
│   ├── 子域 Cookie 泄露
│   ├── DNS 映射攻击
│   ├── Cookie 注入
│   ├── DNS 重绑定
│   └── 会话固定攻击
├── 软件供应链完整性绕过
│   ├── DNS 欺骗
│   ├── 中间人攻击
│   ├── 哈希校验绕过
│   ├── 签名验证绕过
│   ├── 仓库劫持
│   └── 依赖混淆
├── 对象注入与批量赋值
│   ├── 批量赋值攻击
│   ├── 对象注入攻击
│   ├── 原型污染
│   └── 属性篡改攻击
└── Android 组件攻击
    ├── Activity 劫持
    ├── Service 未授权访问
    ├── Content Provider 数据泄露
    └── Intent 过滤器滥用
```

### 6. 方法论引用清单

| 编号 | 方法论名称 | 引用文件 | 适用阶段 |
|-----|-----------|---------|---------|
| SDI-001 | 依赖投毒攻击 | `ref/dependency-poisoning.md` | 漏洞利用 |
| SDI-002 | 反序列化攻击 | `ref/deserialization-attack.md` | 漏洞利用 |
| SDI-003 | 更新劫持攻击 | `ref/update-hijacking.md` | 漏洞利用 |
| SDI-004 | CI/CD 管道攻击 | `ref/cicd-pipeline-attack.md` | 漏洞利用 |
| SDI-005 | CDN 投毒攻击 | `ref/cdn-poisoning.md` | 漏洞利用 |
| SDI-006 | 固件投毒攻击 | `ref/firmware-poisoning.md` | 漏洞利用 |
| SDI-007 | 对象篡改攻击 | `ref/object-tampering.md` | 漏洞利用 |
| SDI-008 | 数据完整性攻击 | `ref/data-integrity-attack.md` | 漏洞利用 |
| SDI-009 | 下载篡改攻击 | `ref/download-tampering.md` | 漏洞利用 |
| SDI-010 | 不可信源攻击 | `ref/untrusted-source-attack.md` | 漏洞利用 |
| SDI-011 | Java 反序列化测试 | `ref/java-deserialization-testing.md` | 系统化测试 |
| SDI-012 | PHP 反序列化测试 | `ref/php-deserialization-testing.md` | 系统化测试 |
| SDI-013 | .NET 反序列化测试 | `ref/dotnet-deserialization-testing.md` | 系统化测试 |
| SDI-014 | 包管理器安全测试 | `ref/package-manager-security.md` | 系统化测试 |
| SDI-015 | 更新机制安全测试 | `ref/update-mechanism-security.md` | 系统化测试 |
| SDI-016 | 反序列化点检测 | `ref/deserialization-point-detection.md` | 漏洞发现 |
| SDI-017 | Payload 生成指南 | `ref/payload-generation-guide.md` | 漏洞利用 |
| SDI-018 | 完整性验证方法 | `ref/integrity-verification-methods.md` | 漏洞发现 |
| SDI-019 | 依赖投毒检测 | `ref/dependency-poisoning-detection.md` | 漏洞发现 |
| SDI-020 | 信任边界检测 | `ref/trust-boundary-detection.md` | 漏洞发现 |
| SDI-021 | Cookie 域与会话劫持攻击 | `ref/cookie-domain-attack.md` | 漏洞利用 |
| SDI-022 | 软件供应链完整性验证绕过 | `ref/supply-chain-integrity-bypass.md` | 漏洞利用 |
| SDI-023 | 对象注入与批量赋值攻击 | `ref/object-injection-mass-assignment.md` | 漏洞利用 |
| SDI-024 | Android 应用程序组件导出攻击 | `ref/android-component-export-attack.md` | 漏洞利用 |

---

## 使用指南

### 快速开始

1. **信任点识别** - 识别所有接收外部数据或代码的点
2. **完整性检查** - 验证是否有签名、哈希等完整性保护
3. **反序列化检测** - 查找所有反序列化接口（识别 Java "rO0" 等特征）
4. **供应链审计** - 审计依赖来源和更新机制
5. **Cookie 域检查** - 检查 Cookie Domain 配置和子域映射
6. **DNS 映射分析** - 分析子域 DNS 记录，识别第三方映射

### OWASP A08 关键检测点

根据 OWASP Top 10:2025 A08，重点检测以下场景：

| 检测点 | 检测方法 | 参考方法论 |
|-------|---------|-----------|
| **Java 序列化接口** | 识别 "rO0" Base64 特征 | `ref/deserialization-point-detection.md` |
| **Cookie 域配置** | 检查 Domain 属性和子域映射 | `ref/cookie-domain-attack.md` |
| **固件签名验证** | 测试上传未签名固件 | `ref/firmware-poisoning.md` |
| **依赖包来源** | 审计 npm/PyPI/Maven 依赖源 | `ref/dependency-poisoning.md` |
| **CI/CD 凭证** | 检查 PR 触发时的凭证暴露 | `ref/cicd-pipeline-attack.md` |
| **更新机制** | 测试更新劫持和回滚 | `ref/update-hijacking.md` |
| **第三方脚本** | 检查 CDN 和外部资源加载 | `ref/cdn-poisoning.md` |
| **信任边界** | 识别跨域信任关系 | `ref/trust-boundary-detection.md` |
| **代码完整性检查** | 测试下载代码签名/哈希验证 | `ref/supply-chain-integrity-bypass.md` |
| **仓库劫持风险** | 检查依赖仓库名称占用 | `ref/supply-chain-integrity-bypass.md` |
| **DNS 映射安全** | 分析子域 CNAME 记录 | `ref/cookie-domain-attack.md` |
| **批量赋值/对象注入** | 测试额外参数绑定 | `ref/object-injection-mass-assignment.md` |
| **原型污染** | 测试 `__proto__` 参数 | `ref/object-injection-mass-assignment.md` |
| **PATH 环境变量** | 检查外部程序调用路径 | `ref/supply-chain-integrity-bypass.md` |
| **Android 组件导出** | 扫描 exported 组件和 intent-filter | `ref/android-component-export-attack.md` |
| **Content Provider** | 测试 URI 访问和数据泄露 | `ref/android-component-export-attack.md` |

### 技能关联

- 与 `pt-software-supply-chain-failures` 技能配合，全面测试供应链安全
- 与 `pt-injection` 技能配合，利用反序列化实现代码执行
- 与 `pt-security-misconfiguration` 技能配合，利用配置错误绕过完整性检查

---

## 参考资源

- [OWASP Top 10:2025 A08](https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/)
- [OWASP Cheat Sheet: Deserialization](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [OWASP Cheat Sheet: Software Supply Chain Security](https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html)
- [OWASP Cheat Sheet: Infrastructure as Code](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html)
- [ysoserial Project](https://github.com/frohoff/ysoserial)
- [Java Deserialization Scanner](https://github.com/federicodotta/Java-Deserialization-Scanner)
- [SLSA Framework](https://slsa.dev/)
- [SAFECode Software Integrity Controls](https://safecode.org/publications/)
- [PortSwigger - Deserialization](https://portswigger.net/web-security/deserialization)
