# Docker 环境敏感信息提取

## 1. 文档概述

### 1.1 编写目的
本文档为渗透测试人员提供 Docker 环境中敏感信息提取的方法论，针对 Docker 镜像层、容器环境变量、构建参数、Compose 配置等位置嵌入的敏感数据。通过本方法论，测试人员能够系统性地从 Docker 环境中提取明文存储的凭证、密钥和 Flag。

### 1.2 适用范围
- 适用于 Docker 镜像层嵌入敏感信息的场景
- 适用于 Docker Compose 配置包含敏感变量
- 适用于 Docker 构建参数（ARG）包含敏感信息
- 适用于容器环境变量明文存储凭证
- 适用于 CTF 挑战应用 Docker 部署
- 适用于 Flask/Django 应用 Docker 容器化部署

### 1.3 读者对象
- 执行渗透测试任务的安全工程师
- 进行容器安全审计的分析师
- 负责红队行动的渗透测试人员

---

## 2. 核心渗透技术专题

### 专题一：Docker 环境敏感信息提取

#### 2.1 技术介绍

Docker 环境敏感信息提取是指攻击者通过分析 Docker 镜像层、容器配置、环境变量、构建参数等，提取其中明文存储或嵌入的敏感数据（密码、密钥、Token、Flag 等）的攻击技术。

**漏洞本质：**
- Docker 镜像层包含敏感信息（即使后续删除仍可从历史层恢复）
- 构建参数（ARG）会保留在镜像元数据中
- 环境变量在容器运行时可见
- Docker Compose 文件明文存储配置
- 镜像推送到公共仓库时敏感信息暴露

**典型敏感位置：**
```
Dockerfile ARG/ENV → 镜像层 → 容器环境变量 → Compose 配置 → 镜像仓库
```

#### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
| :--- | :--- | :--- |
| **CTF 挑战 Docker** | Auth 挑战、XSS 挑战容器 | Flag 通过 ENV 注入到容器 |
| **Flask 应用容器化** | Dockerfile 嵌入 SECRET_KEY | 密钥在镜像层可见 |
| **Django 应用容器化** | settings.py 通过 ENV 注入 | 配置在容器中明文 |
| **CI/CD 管道** | 构建时注入凭证 | 构建参数保留在镜像中 |
| **微服务部署** | 多容器共享敏感配置 | Compose 文件明文存储 |
| **开发环境** | 本地 Docker 开发 | 临时凭证未清理 |

#### 2.3 漏洞探测方法

##### 2.3.1 黑盒测试

**步骤 1：Docker 服务识别**
```bash
# 识别 Docker 部署的应用
# 特征：Server 头包含 Docker 相关信息
curl -I http://target.com/

# 检查常见 Docker 暴露端口
nmap -p 2375,2376,80,443,8080 target.com
```

**步骤 2：敏感端点探测**
```bash
# 探测 Docker 相关敏感端点
curl http://target.com/.dockerenv
curl http://target.com/docker-compose.yml
curl http://target.com/Dockerfile
```

##### 2.3.2 白盒测试（有 Docker 访问权限）

**Dockerfile 审计：**
```dockerfile
# 危险模式 1：ENV 指令硬编码敏感信息
ENV ADMIN_PASSWORD=SuperSecret123
ENV FLAG=flag{docker-env-flag}
ENV SECRET_KEY=hardcoded-secret-key

# 危险模式 2：ARG 构建参数（保留在镜像层）
ARG SECRET_KEY=my-secret-key
RUN echo $SECRET_KEY > /app/config

# 危险模式 3：CMD 中包含凭证
CMD ["python", "app.py", "--password", "admin123"]

# 危险模式 4：COPY 敏感文件
COPY .env /app/.env
COPY credentials.txt /app/credentials.txt
```

**docker-compose.yml 审计：**
```yaml
version: '3'
services:
  web:
    # 危险模式 1：environment 明文
    environment:
      - DATABASE_PASSWORD=hardcoded-pass
      - SECRET_KEY=my-secret-key
      - FLAG=flag{compose-flag}
    
    # 危险模式 2：env_file 未加密
    env_file:
      - .env
    
    # 危险模式 3：command 包含凭证
    command: python app.py --password admin123
```

**镜像层分析：**
```bash
# 查看镜像历史（敏感信息可能暴露）
docker history --no-trunc target-image

# 查看镜像元数据
docker inspect target-image

# 查找敏感信息
docker history --no-trunc target-image | grep -i "password\|secret\|flag"
docker inspect target-image | grep -i "password\|secret\|flag"
```

#### 2.4 漏洞利用方法

##### 2.4.1 镜像历史分析提取

**方法 1：查看构建历史**
```bash
# 查看完整的镜像构建历史
docker history --no-trunc target-image

# 示例输出（敏感信息暴露）
# RUN |2 SECRET_KEY=hardcoded-secret-key bash -c ...
# ENV FLAG=flag{docker-history-flag}
```

**方法 2：提取特定层内容**
```bash
# 1. 获取镜像层 ID
docker history --format "{{.ID}}" target-image

# 2. 创建临时容器查看层内容
docker run --rm -it <layer-id> /bin/sh
cat /app/.env
cat /app/config.py
```

##### 2.4.2 容器环境变量提取

**方法 1：直接读取环境变量**
```bash
# 启动临时容器读取环境变量
docker run --rm target-image env

# 示例输出
# PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
# FLAG=flag{docker-env-flag}
# SECRET_KEY=docker-secret-key
# DATABASE_PASSWORD=super-secret-db-pass
```

**方法 2：过滤敏感变量**
```bash
# 只提取包含敏感关键词的环境变量
docker run --rm target-image env | grep -iE "flag|secret|password|key|token"

# 示例输出
# FLAG=flag{environment-variable-flag}
# SECRET_KEY=flask-hardcoded-key
# ADMIN_PASSWORD=kl!RtYuUUig664ds32AKA87
```

##### 2.4.3 镜像文件系统提取

**方法 1：直接读取容器文件**
```bash
# 启动临时容器读取敏感文件
docker run --rm target-image cat /app/.env
docker run --rm target-image cat /app/config.py
docker run --rm target-image cat /secret.txt
docker run --rm target-image cat /flag.txt

# 示例输出
# FLAG=flag{file-system-flag}
# SECRET_KEY="hardcoded-in-file"
```

**方法 2：导出整个镜像分析**
```bash
# 1. 保存镜像为 tar
docker save target-image -o image.tar

# 2. 解压分析
mkdir extracted && cd extracted
tar -xf ../image.tar

# 3. 查看层文件
for layer in */layer.tar; do
    echo "=== Layer: $layer ==="
    tar -tvf "$layer" | head -20
done

# 4. 查看层 JSON 配置
cat */json | jq '.config.Env'
```

**方法 3：使用 dive 工具分析**
```bash
# 安装 dive
wget https://github.com/wagoodman/dive/releases/download/v0.10.0/dive_0.10.0_linux_amd64.tar.gz
tar xvf dive_0.10.0_linux_amd64.tar.gz

# 分析镜像
dive target-image

# 交互式查看每层变化，发现敏感文件
```

##### 2.4.4 Docker Compose 配置提取

**场景 1：Compose 文件可访问**
```bash
# 如果 docker-compose.yml 可访问（如通过 Git/HTTP）
curl http://target.com/docker-compose.yml

# 提取环境变量
grep -A 10 "environment:" docker-compose.yml
```

**场景 2：.env 文件可访问**
```bash
# 提取.env 文件
curl http://target.com/.env
cat .env

# 示例内容
# FLAG=flag{env-file-flag}
# SECRET_KEY=compose-secret-key
# DATABASE_URL=mysql://root:password@db:3306/app
```

##### 2.4.5 CTF Flag 提取实战

**场景：CTF Auth 挑战 Docker 部署**
```bash
# 1. 获取 Docker 镜像
# 方法 A：从公共仓库拉取
docker pull target/ctf-auth-challenge

# 方法 B：从本地导出
docker save ctf-auth -o ctf.tar

# 2. 提取 Flag
# 方法 A：查看环境变量
docker run --rm ctf-auth env | grep FLAG
# 输出：FLAG=flag{f42b6ccb-617d-4aad-b3ea-f96f1d1c85a3}

# 方法 B：查看镜像历史
docker history --no-trunc ctf-auth | grep -i flag

# 方法 C：读取 Flag 文件
docker run --rm ctf-auth cat /flag.txt
docker run --rm ctf-auth cat /secret.txt

# 3. 验证 Flag
# 提交到 CTF 平台验证
```

#### 2.5 漏洞利用绕过方法

##### 2.5.1 绕过镜像层清理

**当敏感信息被后续层删除时：**
```bash
# Dockerfile 示例
# RUN echo "SECRET=abc123" > /app/secret
# RUN rm /app/secret  # 试图删除

# 绕过方法：从历史层恢复
docker history --no-trunc target-image

# 即使文件被删除，构建命令仍保留在历史中
# 输出：RUN |2 SECRET=abc123 bash -c ...
```

##### 2.5.2 绕过多阶段构建

**当使用多阶段构建隐藏敏感信息时：**
```bash
# Dockerfile 示例
# FROM node AS builder
# ENV SECRET=build-secret
# RUN npm build
# 
# FROM alpine
# COPY --from=builder /app/dist /app

# 绕过方法：检查构建阶段镜像
docker images -a  # 查看所有镜像（包括中间层）
docker inspect <builder-image-id>
```

##### 2.5.3 绕过私有仓库认证

**当镜像在私有仓库时：**
```bash
# 1. 尝试匿名拉取
docker pull private-registry/target-image

# 2. 使用默认凭证
docker login private-registry -u admin -p admin
docker pull private-registry/target-image

# 3. 从 CI/CD 管道提取
# 检查 Jenkins/GitLab CI 配置中的 Docker 凭证
```

---

## 3. 附录

### 3.1 Docker 敏感信息检测工具

| 工具 | 用途 | 命令示例 |
| :--- | :--- | :--- |
| **dive** | 镜像层分析 | `dive target-image` |
| **docker-scan** | 镜像漏洞扫描 | `docker scan target-image` |
| **trivy** | 镜像安全扫描 | `trivy image target-image` |
| **hadolint** | Dockerfile 检查 | `hadolint Dockerfile` |
| **gitleaks** | Git 仓库扫描 | `gitleaks detect --source .` |

### 3.2 常见敏感信息位置

| 位置 | 检测方法 |
| :--- | :--- |
| ENV 指令 | `docker history --no-trunc` |
| ARG 参数 | `docker inspect` |
| 环境变量 | `docker run --rm image env` |
| 配置文件 | `docker run --rm image cat /app/.env` |
| 镜像层 | `docker save` + 解压分析 |
| Compose 文件 | 检查 docker-compose.yml |

### 3.3 利用检查清单

- [ ] 获取目标 Docker 镜像
- [ ] 分析镜像构建历史
- [ ] 检查镜像元数据（inspect）
- [ ] 提取容器环境变量
- [ ] 读取容器内敏感文件
- [ ] 导出镜像进行深度分析
- [ ] 检查 Docker Compose 配置
- [ ] 搜索 Git 历史中的 Docker 配置
- [ ] 记录所有发现的敏感信息

### 3.4 修复建议

| 问题 | 修复方案 |
| :--- | :--- |
| ENV 硬编码 | 使用 Docker Secrets 或运行时注入 |
| ARG 敏感参数 | 使用--secret 标志（BuildKit） |
| 镜像层泄露 | 使用多阶段构建 + 单层写入 |
| Compose 明文 | 使用.env 文件 + 限制访问权限 |
| 公共镜像敏感 | 推送到私有仓库 + 扫描 |
