---
name: insecure-design
description: 不安全设计渗透测试技能，用于检测和利用架构设计、业务逻辑、信任边界等设计层面的安全缺陷
---

# Insecure Design（不安全设计）渗透测试技能

## 简介

不安全设计（Insecure Design）是 OWASP Top 10:2025 排名第 6 的安全风险。这类漏洞源于架构或设计层面的安全控制缺失或无效，无法通过完美的代码实现来修复。

本技能提供系统性的方法论，指导渗透测试人员发现和利用设计层面的漏洞，包括业务逻辑滥用、威胁建模缺失、信任边界违规、状态转换攻击等攻击技术。

---

## 方法论映射表

### 1. 渗透过程中遇到什么情况该参考哪个方法论

| 遇到的情况 | 参考方法论 | 文件路径 |
|-----------|-----------|----------|
| 业务流程可被绕过 | 业务逻辑滥用 | `ref/business-logic-abuse.md` |
| 状态机可被跳过 | 状态转换攻击 | `ref/state-transition-attack.md` |
| 参数可被篡改影响业务 | 参数篡改攻击 | `ref/parameter-tampering.md` |
| 并发操作导致异常 | 竞争条件攻击 | `ref/race-condition-attack.md` |
| 前端信任后端未验证 | 信任边界违规 | `ref/trust-boundary-violation.md` `ref/trust-boundary-violation-ssrf.md` |
| Django 多步骤注册流程可跳过 | 状态转换攻击 | `ref/state-transition-attack.md` |
| 注册流程会话状态验证仅检查键存在 | 状态转换攻击 | `ref/state-transition-attack.md` |
| 硬编码 SECRET_KEY 可伪造会话状态 | 信任边界违规 | `ref/trust-boundary-violation.md` |
| 微服务架构仅依赖网络隔离 | 信任边界违规 | `ref/trust-boundary-violation-ssrf.md` |
| Docker 环境内部服务无应用层认证 | 信任边界违规 | `ref/trust-boundary-violation-ssrf.md` |
| SSRF 可绕过网络隔离访问内部服务 | 信任边界违规 | `ref/trust-boundary-violation-ssrf.md` |
| 云环境元数据服务可通过 SSRF 访问 | 信任边界违规 | `ref/trust-boundary-violation-ssrf.md` |
| 仅依赖 Docker 网络作为安全边界 | 信任边界违规 | `ref/trust-boundary-violation-ssrf.md` |
| 容器内服务无认证装饰器 | 信任边界违规 | `ref/trust-boundary-violation-ssrf.md` |
| SSRF 访问 localhost 内部服务 | 信任边界违规 | `ref/trust-boundary-violation-ssrf.md` |
| SSRF 绕过 IP 基础认证 | 信任边界违规 | `ref/trust-boundary-violation-ssrf.md` |
| CTF 挑战信任边界违规设计 | 信任边界违规 | `ref/trust-boundary-violation-ssrf.md` |
| 凭证恢复流程薄弱 | 凭证恢复攻击 | `ref/credential-recovery-attack.md` |
| 批量操作无限制 | 批量操作滥用 | `ref/bulk-operation-abuse.md` |
| 机器人可自动化操作 | 自动化滥用攻击 | `ref/automation-abuse-attack.md` |
| 权限分配逻辑缺陷 | 权限设计攻击 | `ref/permission-design-attack.md` |
| 文件上传类型未限制 | 文件上传设计缺陷 | `ref/file-upload-design-flaw.md` |
| 凭证明文存储或弱保护 | 凭证存储攻击 | `ref/credential-storage-attack.md` |
| 文件路径未隔离设计 | 路径遍历设计缺陷 | `ref/path-traversal-design.md` |
| HTTP 多层架构解析不一致 | HTTP 请求走私攻击 | `ref/http-request-smuggling.md` |
| 依赖客户端输入进行安全决策 | 不可信输入安全决策 | `ref/untrusted-input-security-decision.md` |
| 安全逻辑在客户端实现 | 客户端强制服务器端安全 | `ref/client-side-enforcement.md` |

### 2. 遇到什么样的业务系统、软件环境、基础设施该参考哪个方法论

| 系统/环境特征 | 参考方法论 | 文件路径 |
|--------------|-----------|----------|
| 电商系统 | 电商业务逻辑测试 | `ref/ecommerce-logic-testing.md` |
| 金融/支付系统 | 金融业务逻辑测试 | `ref/finance-logic-testing.md` |
| 票务/预订系统 | 票务业务逻辑测试 | `ref/ticketing-logic-testing.md` |
| 社交网络平台 | 社交业务逻辑测试 | `ref/social-logic-testing.md` |
| 游戏系统 | 游戏逻辑测试 | `ref/gaming-logic-testing.md` |
| 多租户 SaaS | 租户隔离设计测试 | `ref/tenant-isolation-design.md` |
| API 经济系统 | API 业务逻辑测试 | `ref/api-business-logic.md` |
| 微服务架构 | 微服务设计安全测试 | `ref/microservice-design-security.md` |

### 3. 遇到什么样的问题该参考哪个方法论

| 问题类型 | 参考方法论 | 文件路径 |
|---------|-----------|----------|
| 如何进行威胁建模 | 威胁建模指南 | `ref/threat-modeling-guide.md` |
| 如何绘制数据流图 | 数据流图分析 | `ref/data-flow-analysis.md` |
| 如何识别信任边界 | 信任边界识别 | `ref/trust-boundary-identification.md` |
| 如何设计滥用案例 | 滥用案例设计 | `ref/misuse-case-design.md` |
| 如何测试业务逻辑 | 业务逻辑测试框架 | `ref/business-logic-testing-framework.md` |
| 如何检测竞争条件 | 竞争条件检测 | `ref/race-condition-detection.md` |
| 如何进行架构审查 | 安全架构审查 | `ref/security-architecture-review.md` |
| 如何测试状态机 | 状态机安全测试 | `ref/state-machine-testing.md` |

### 4. 渗透测试决策流程图

```
                                    ┌─────────────────┐
                                    │  不安全设计测试  │
                                    └────────┬────────┘
                                             │
                                             ▼
                                    ┌─────────────────┐
                                    │   业务理解阶段   │
                                    │  - 业务流程分析  │
                                    │  - 数据流图绘制  │
                                    │  - 信任边界识别  │
                                    └────────┬────────┘
                                             │
                    ┌────────────────────────┼────────────────────────┐
                    │                        │                        │
                    ▼                        ▼                        ▼
          ┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
          │  发现逻辑缺陷    │      │  发现状态问题   │      │   发现并发问题  │
          └────────┬────────┘      └────────┬────────┘      └────────┬────────┘
                   │                        │                        │
                   ▼                        ▼                        ▼
          ┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
          │  ref/business-  │      │  ref/state-     │      │  ref/race-      │
          │  logic-abuse.md │      │  transition-    │      │  condition-     │
          │                 │      │  attack.md      │      │  attack.md      │
          └─────────────────┘      └─────────────────┘      └─────────────────┘
```

### 5. 攻击技术思维导图

```
不安全设计攻击技术
├── 业务逻辑攻击
│   ├── 价格篡改
│   ├── 数量绕过
│   ├── 优惠券滥用
│   ├── 退款欺诈
│   └── 积分操纵
├── 状态攻击
│   ├── 状态跳过
│   ├── 状态回退
│   ├── 状态竞争
│   └── 状态污染
├── 并发攻击
│   ├── 双重支付
│   ├── 超卖攻击
│   ├── 竞态条件
│   └── TOCTOU 攻击
├── 信任边界攻击
│   ├── 客户端信任
│   ├── Cookie 信任
│   ├── HTTP 头信任
│   └── 隐藏字段信任
├── 权限设计攻击
│   ├── 角色分配缺陷
│   ├── 权限继承滥用
│   ├── 上下文权限绕过
│   └── 默认权限滥用
└── 资源设计攻击
│   ├── 配额绕过
│   ├── 速率限制绕过
│   ├── 存储配额绕过
│   └── 计算资源滥用
```

### 6. 方法论引用清单

| 编号 | 方法论名称 | 引用文件 | 适用阶段 |
|-----|-----------|---------|---------|
| ID-001 | 业务逻辑滥用 | `ref/business-logic-abuse.md` | 漏洞利用 |
| ID-002 | 状态转换攻击 | `ref/state-transition-attack.md` | 漏洞利用 |
| ID-003 | 参数篡改攻击 | `ref/parameter-tampering.md` | 漏洞利用 |
| ID-004 | 竞争条件攻击 | `ref/race-condition-attack.md` | 漏洞利用 |
| ID-005 | 信任边界违规 | `ref/trust-boundary-violation.md` | 漏洞发现 |
| ID-006 | 凭证恢复攻击 | `ref/credential-recovery-attack.md` | 漏洞利用 |
| ID-007 | 批量操作滥用 | `ref/bulk-operation-abuse.md` | 漏洞利用 |
| ID-008 | 自动化滥用攻击 | `ref/automation-abuse-attack.md` | 漏洞利用 |
| ID-009 | 权限设计攻击 | `ref/permission-design-attack.md` | 漏洞发现 |
| ID-010 | 文件上传设计缺陷 | `ref/file-upload-design-flaw.md` | 漏洞利用 |
| ID-011 | 电商业务逻辑测试 | `ref/ecommerce-logic-testing.md` | 系统化测试 |
| ID-012 | 金融业务逻辑测试 | `ref/finance-logic-testing.md` | 系统化测试 |
| ID-013 | 票务业务逻辑测试 | `ref/ticketing-logic-testing.md` | 系统化测试 |
| ID-014 | 威胁建模指南 | `ref/threat-modeling-guide.md` | 测试规划 |
| ID-015 | 数据流图分析 | `ref/data-flow-analysis.md` | 信息收集 |
| ID-016 | 信任边界识别 | `ref/trust-boundary-identification.md` | 信息收集 |
| ID-017 | 滥用案例设计 | `ref/misuse-case-design.md` | 测试规划 |
| ID-018 | 业务逻辑测试框架 | `ref/business-logic-testing-framework.md` | 测试规划 |
| ID-019 | 竞争条件检测 | `ref/race-condition-detection.md` | 漏洞发现 |
| ID-020 | 安全架构审查 | `ref/security-architecture-review.md` | 系统化测试 |
| ID-021 | 信任边界违规（SSRF） | `ref/trust-boundary-violation-ssrf.md` | 漏洞发现/利用 |
| ID-022 | Python Pickle 反序列化设计缺陷 | `ref/file-upload-design-flaw.md` | 漏洞发现/利用 |
| ID-023 | 无认证架构设计缺陷 | `ref/trust-boundary-violation-ssrf.md` | 漏洞发现/利用 |
| ID-024 | Docker 环境信任边界违规 | `ref/trust-boundary-violation-ssrf.md` | 漏洞发现/利用 |
| ID-025 | 文件上传无验证设计缺陷 | `ref/file-upload-design-flaw.md` | 漏洞发现/利用 |
| ID-026 | CTF 挑战不安全设计 | `ref/business-logic-abuse.md` | 漏洞利用 |
| ID-027 | 凭证存储设计缺陷 | `ref/credential-storage-attack.md` | 漏洞发现/利用 |
| ID-028 | 路径遍历设计缺陷 | `ref/path-traversal-design.md` | 漏洞发现/利用 |
| ID-029 | HTTP 请求走私攻击 | `ref/http-request-smuggling.md` | 漏洞发现/利用 |
| ID-030 | 不可信输入安全决策 | `ref/untrusted-input-security-decision.md` | 漏洞发现/利用 |
| ID-031 | 客户端强制服务器端安全 | `ref/client-side-enforcement.md` | 漏洞发现/利用 |
| ID-032 | 无速率限制设计 | `ref/automation-abuse-attack.md` | 漏洞发现/利用 |
| ID-033 | 安全日志记录缺陷 | `ref/security-architecture-review.md` | 漏洞发现 |

### 7. Python/FastAPI 应用特定不安全设计场景

| 场景 | 参考方法论 | 文件路径 |
|------|-----------|----------|
| Python 应用使用 pickle 处理不可信数据 | 文件上传设计缺陷（危险类型文件处理） | `ref/file-upload-design-flaw.md` |
| FastAPI 文件上传端点无验证逻辑 | 文件上传设计缺陷 | `ref/file-upload-design-flaw.md` |
| 应用完全无认证架构设计 | 信任边界违规 | `ref/trust-boundary-violation-ssrf.md` |
| Docker 环境内部服务无应用层认证 | Docker 环境信任边界违规 | `ref/trust-boundary-violation-ssrf.md` |
| 仅依赖网络隔离作为安全边界 | 信任边界违规 | `ref/trust-boundary-violation-ssrf.md` |
| CTF 挑战故意设计的不安全架构 | 业务逻辑滥用 | `ref/business-logic-abuse.md` |
| 应用无输入验证直接处理危险数据 | 文件上传设计缺陷 | `ref/file-upload-design-flaw.md` |
| 敏感数据存储在环境变量 | 凭证存储设计缺陷 | `ref/credential-storage-attack.md` |
| 应用无速率限制设计 | 自动化滥用攻击 | `ref/automation-abuse-attack.md` |
| 应用无日志记录设计 | 安全架构审查 | `ref/security-architecture-review.md` |
| 配置文件存储明文密码 | 凭证存储设计缺陷 | `ref/credential-storage-attack.md` |
| 文件路径拼接用户输入 | 路径遍历设计缺陷 | `ref/path-traversal-design.md` |
| 依赖 HTTP 头进行认证 | 不可信输入安全决策 | `ref/untrusted-input-security-decision.md` |
| 客户端验证后端未重复 | 客户端强制服务器端安全 | `ref/client-side-enforcement.md` |
| 多层 HTTP 架构（代理/网关） | HTTP 请求走私攻击 | `ref/http-request-smuggling.md` |

---

## 使用指南

### 快速开始

1. **业务理解** - 深入理解目标系统的业务流程和设计意图
2. **威胁建模** - 识别潜在的攻击面和信任边界
3. **滥用案例** - 设计正常用例之外的滥用场景
4. **逻辑测试** - 系统化测试业务逻辑的抗攻击性

### 技能关联

- 与 `pt-broken-access-control` 技能配合，利用设计缺陷提升权限
- 与 `pt-authentication-failures` 技能配合，利用设计缺陷绕过认证
- 与 `pt-injection` 技能配合，在设计层面寻找注入点

---

## 参考资源

- [OWASP Top 10:2025 A06](https://owasp.org/Top10/2025/A06_2025-Insecure_Design/)
- [OWASP Cheat Sheet: Secure Design Principles](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Design_Principles.html)
- [OWASP SAMM](https://owaspsamm.org/)
- [The Threat Modeling Manifesto](https://www.threatmodelingmanifesto.org/)
