---
name: software-supply-chain-failures
description: 软件供应链失效渗透测试技能，用于检测和利用第三方依赖、CI/CD 管道、制品管理中的安全漏洞
---

# Software Supply Chain Failures（软件供应链失效）渗透测试技能

## 简介

软件供应链失效（Software Supply Chain Failures）是 OWASP Top 10:2025 新增的安全风险类别。当第三方组件、库、工具链或开发流程存在安全漏洞时，攻击者可以通过污染供应链来影响下游应用，造成广泛的安全影响。

本技能提供系统性的方法论，指导渗透测试人员发现和利用软件供应链漏洞，包括依赖项投毒、CI/CD 管道入侵、制品篡改、签名验证绕过等攻击技术。

---

## 方法论映射表

### 1. 渗透过程中遇到什么情况该参考哪个方法论

| 遇到的情况 | 参考方法论 | 文件路径 |
|-----------|-----------|----------|
| 发现过时的依赖包 | 依赖项漏洞利用 | `ref/dependency-vulnerability-exploitation.md` |
| 依赖包签名验证缺失 | 依赖投毒攻击 | `ref/dependency-poisoning-attack.md` |
| CI/CD 配置可修改 | CI/CD 管道入侵 | `ref/cicd-pipeline-compromise.md` |
| 构建产物无签名 | 制品篡改攻击 | `ref/artifact-tampering.md` |
| 发现 typosquatting 包 | 包名混淆攻击 | `ref/package-typosquatting.md` |
| npm postinstall 脚本 | 恶意脚本执行 | `ref/malicious-script-execution.md` |
| Docker 镜像来源不明 | 镜像投毒攻击 | `ref/image-poisoning.md` |
| Git 仓库保护不足 | 代码仓库入侵 | `ref/repository-compromise.md` |
| 发现未锁定的依赖版本 | 依赖版本攻击 | `ref/dependency-version-attack.md` |
| 自动更新机制无验证 | 更新劫持攻击 | `ref/update-hijacking.md` |
| 发现内部包名与公共包冲突 | 依赖混淆攻击 | `ref/dependency-confusion-attack.md` |
| 发现编译时注入痕迹 | SolarWinds 类型攻击 | `ref/artifact-tampering.md` (专题二) |
| 发现条件触发恶意代码 | 条件触发攻击 | `ref/artifact-tampering.md` (专题二) |
| 发现自我传播 npm 蠕虫 | Shai-Hulud 蠕虫攻击 | `ref/malicious-script-execution.md` (专题二) |

### 2. 遇到什么样的业务系统、软件环境、基础设施该参考哪个方法论

| 系统/环境特征 | 参考方法论 | 文件路径 |
|--------------|-----------|----------|
| Node.js/npm项目 | npm 供应链安全测试 | `ref/npm-supply-chain-testing.md` |
| Python/pip 项目 | pip 供应链安全测试 | `ref/pip-supply-chain-testing.md` |
| Java/Maven项目 | Maven 供应链安全测试 | `ref/maven-supply-chain-testing.md` |
| 使用 GitHub Actions | GitHub Actions 安全测试 | `ref/github-actions-security.md` |
| 使用 Jenkins CI/CD | Jenkins 安全测试 | `ref/jenkins-security-testing.md` |
| Docker 容器化部署 | 容器供应链安全 | `ref/container-supply-chain.md` |
| 使用私有制品仓库 | 制品仓库安全测试 | `ref/artifact-repository-security.md` |
| 自动部署系统 | 部署管道安全测试 | `ref/deployment-pipeline-security.md` |

### 3. 遇到什么样的问题该参考哪个方法论

| 问题类型 | 参考方法论 | 文件路径 |
|---------|-----------|----------|
| 如何生成和分析 SBOM | SBOM 管理指南 | `ref/sbom-management.md` |
| 如何检测依赖漏洞 | 依赖漏洞扫描 | `ref/dependency-vulnerability-scanning.md` |
| 如何验证制品完整性 | 完整性验证方法 | `ref/integrity-verification.md` |
| 如何审计 CI/CD 配置 | CI/CD 安全审计 | `ref/cicd-security-audit.md` |
| 如何检测恶意依赖 | 恶意依赖检测 | `ref/malicious-dependency-detection.md` |
| 如何测试签名验证 | 签名验证测试 | `ref/signature-verification-testing.md` |
| 如何进行依赖树分析 | 依赖树分析 | `ref/dependency-tree-analysis.md` |
| 如何实施虚拟补丁 | 虚拟补丁部署 | `ref/virtual-patch-deployment.md` |
| 如何评估供应商安全 | 供应商安全评估 | `ref/vendor-security-assessment.md` |
| 如何选择开源组件 | 开源项目评估 | `ref/vendor-security-assessment.md` (专题一) |
| 如何评估商业供应商 | 商业供应商评估 | `ref/vendor-security-assessment.md` (专题二) |

### 4. 渗透测试决策流程图

```
                                    ┌─────────────────┐
                                    │  供应链安全测试  │
                                    └────────┬────────┘
                                             │
                                             ▼
                                    ┌─────────────────┐
                                    │   SBOM 生成分析   │
                                    │  - 依赖清单     │
                                    │  - 版本追踪     │
                                    │  - 传递依赖     │
                                    └────────┬────────┘
                                             │
                    ┌────────────────────────┼────────────────────────┐
                    │                        │                        │
                    ▼                        ▼                        ▼
          ┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
          │  发现漏洞依赖    │      │  发现配置弱点    │      │  发现签名缺失   │
          └────────┬────────┘      └────────┬────────┘      └────────┬────────┘
                   │                        │                        │
                   ▼                        ▼                        ▼
          ┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
          │  ref/dependency-│      │  ref/cicd-      │      │  ref/signature- │
          │  vulnerability- │      │  pipeline-      │      │  verification-  │
          │  exploitation.md│      │  compromise.md  │      │  testing.md     │
          └─────────────────┘      └─────────────────┘      └─────────────────┘
```

### 5. 攻击技术思维导图

```
软件供应链失效攻击技术
├── 依赖项攻击
│   ├── 依赖混淆 (Dependency Confusion)
│   ├── Typosquatting（包名混淆）
│   ├── 恶意包注入
│   └── 版本回滚攻击
├── CI/CD 管道攻击
│   ├── 构建脚本篡改
│   ├── 凭证窃取
│   ├── 构建缓存污染
│   └── 部署劫持
├── 制品攻击
│   ├── 未签名制品注入
│   ├── 签名伪造
│   ├── 镜像投毒
│   └── 固件篡改
├── 代码仓库攻击
│   ├── 分支保护绕过
│   ├── PR 审查绕过
│   ├── 提交历史篡改
│   └── 密钥泄露利用
├── 更新机制攻击
│   ├── 更新服务器劫持
│   ├── 中间人攻击
│   ├── 时间窗口攻击
│   └── 回滚攻击
└── 传递依赖攻击
    ├── 深层依赖投毒
    ├── 间接依赖利用
    └── 依赖树污染
```

### 6. 方法论引用清单

| 编号 | 方法论名称 | 引用文件 | 适用阶段 |
|-----|-----------|---------|---------|
| SSC-001 | 依赖项漏洞利用 | `ref/dependency-vulnerability-exploitation.md` | 漏洞利用 |
| SSC-001-A | Log4Shell 完整利用链 | `ref/dependency-vulnerability-exploitation.md` (专题二 2.6) | 漏洞利用 |
| SSC-001-B | Struts2 RCE 完整利用链 | `ref/dependency-vulnerability-exploitation.md` (专题二 2.7) | 漏洞利用 |
| SSC-002 | 依赖投毒攻击 | `ref/dependency-poisoning-attack.md` | 漏洞利用 |
| SSC-003 | CI/CD 管道入侵 | `ref/cicd-pipeline-compromise.md` | 漏洞利用 |
| SSC-003-A | OWASP Top 10 CI/CD 攻击向量 | `ref/cicd-pipeline-compromise.md` (专题二 2.6) | 漏洞利用 |
| SSC-003-B | GitHub Actions 特定攻击 | `ref/cicd-pipeline-compromise.md` (专题二 2.7) | 漏洞利用 |
| SSC-003-C | Jenkins 特定攻击 | `ref/cicd-pipeline-compromise.md` (专题二 2.8) | 漏洞利用 |
| SSC-004 | 制品篡改攻击 | `ref/artifact-tampering.md` | 漏洞利用 |
| SSC-004-A | SolarWinds 类型攻击 | `ref/artifact-tampering.md` (专题二 2.6) | 漏洞利用 |
| SSC-004-B | Bybit 条件触发攻击 | `ref/artifact-tampering.md` (专题二 2.8) | 漏洞利用 |
| SSC-005 | 包名混淆攻击 | `ref/package-typosquatting.md` | 漏洞发现 |
| SSC-006 | 恶意脚本执行 | `ref/malicious-script-execution.md` | 漏洞利用 |
| SSC-006-A | Shai-Hulud 蠕虫攻击 | `ref/malicious-script-execution.md` (专题二) | 漏洞利用 |
| SSC-007 | 镜像投毒攻击 | `ref/image-poisoning.md` | 漏洞利用 |
| SSC-008 | 代码仓库入侵 | `ref/repository-compromise.md` | 漏洞利用 |
| SSC-009 | 依赖版本攻击 | `ref/dependency-version-attack.md` | 漏洞利用 |
| SSC-010 | 更新劫持攻击 | `ref/update-hijacking.md` | 漏洞利用 |
| SSC-025 | 依赖混淆攻击 | `ref/dependency-confusion-attack.md` | 漏洞利用 |
| SSC-011 | npm 供应链安全测试 | `ref/npm-supply-chain-testing.md` | 系统化测试 |
| SSC-012 | pip 供应链安全测试 | `ref/pip-supply-chain-testing.md` | 系统化测试 |
| SSC-013 | Maven 供应链安全测试 | `ref/maven-supply-chain-testing.md` | 系统化测试 |
| SSC-014 | GitHub Actions 安全测试 | `ref/github-actions-security.md` | 系统化测试 |
| SSC-015 | Jenkins 安全测试 | `ref/jenkins-security-testing.md` | 系统化测试 |
| SSC-016 | 容器供应链安全 | `ref/container-supply-chain.md` | 系统化测试 |
| SSC-017 | SBOM 管理指南 | `ref/sbom-management.md` | 测试规划 |
| SSC-018 | 依赖漏洞扫描 | `ref/dependency-vulnerability-scanning.md` | 漏洞发现 |
| SSC-019 | 完整性验证方法 | `ref/integrity-verification.md` | 漏洞发现 |
| SSC-020 | CI/CD 安全审计 | `ref/cicd-security-audit.md` | 系统化测试 |
| SSC-021 | 恶意依赖检测 | `ref/malicious-dependency-detection.md` | 漏洞发现 |
| SSC-022 | 签名验证测试 | `ref/signature-verification-testing.md` | 系统化测试 |
| SSC-023 | 依赖树分析 | `ref/dependency-tree-analysis.md` | 信息收集 |
| SSC-024 | 虚拟补丁部署 | `ref/virtual-patch-deployment.md` | 漏洞利用 |
| SSC-026 | 供应商安全评估 | `ref/vendor-security-assessment.md` | 测试规划 |
| SSC-030 | 软件供应链攻击案例集 | `ref/software-supply-chain-attack-cases.md` | 测试规划/红队演练 |
| SSC-030-A | SolarWinds 攻击案例 | `ref/software-supply-chain-attack-cases.md` (专题一) | 红队演练 |
| SSC-030-B | Bybit 攻击案例 | `ref/software-supply-chain-attack-cases.md` (专题二) | 红队演练 |
| SSC-030-C | Shai-Hulud 蠕虫案例 | `ref/software-supply-chain-attack-cases.md` (专题三) | 红队演练 |
| SSC-030-D | Codecov 攻击案例 | `ref/software-supply-chain-attack-cases.md` (专题四) | 红队演练 |
| SSC-030-E | EventStream 攻击案例 | `ref/software-supply-chain-attack-cases.md` (专题五) | 红队演练 |
| SSC-030-F | 依赖混淆攻击案例 | `ref/software-supply-chain-attack-cases.md` (专题六) | 红队演练 |
| SSC-030-G | CCleaner 攻击案例 | `ref/software-supply-chain-attack-cases.md` (专题七) | 红队演练 |
| SSC-030-H | NotPetya 攻击案例 | `ref/software-supply-chain-attack-cases.md` (专题八) | 红队演练 |
| SSC-040 | CWE 映射与利用方法论 | `ref/cwe-mapping-exploitation.md` | 漏洞利用 |
| SSC-040-A | CWE-1395 依赖易受攻击组件 | `ref/cwe-mapping-exploitation.md` (专题一) | 漏洞利用 |
| SSC-040-B | CWE-1104 未维护组件利用 | `ref/cwe-mapping-exploitation.md` (专题二) | 漏洞利用 |
| SSC-040-C | CWE-1329 不可更新组件利用 | `ref/cwe-mapping-exploitation.md` (专题三) | 漏洞利用 |
| SSC-040-D | CWE-1357 不可信组件利用 | `ref/cwe-mapping-exploitation.md` (专题四) | 漏洞利用 |
| SSC-040-E | CWE-447 UI 功能未实现利用 | `ref/cwe-mapping-exploitation.md` (专题五) | 漏洞利用 |
| SSC-040-F | CWE-1035 已知漏洞组件利用 | `ref/cwe-mapping-exploitation.md` (专题六) | 漏洞利用 |

---

## 使用指南

### 快速开始

1. **生成 SBOM** - 创建完整的软件物料清单
2. **漏洞扫描** - 扫描所有依赖项的已知漏洞
3. **配置审计** - 审计 CI/CD 管道和制品仓库配置
4. **完整性验证** - 验证所有制品的签名和哈希

### 技能关联

- 与 `pt-security-misconfiguration` 技能配合，检测 CI/CD 配置错误
- 与 `pt-insecure-design` 技能配合，评估供应链安全设计
- 与 `pt-cryptographic-failures` 技能配合，检测签名验证问题

---

## 参考资源

- [OWASP Top 10:2025 A03](https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/)
- [OWASP Dependency-Track](https://dependencytrack.org/)
- [SLSA Framework](https://slsa.dev/)
- [Sigstore Project](https://www.sigstore.dev/)
