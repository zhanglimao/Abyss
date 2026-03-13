# 完整性验证方法论

---

# 第一部分：文档概述

## 1.1 编写目的
- 为安全团队提供软件制品完整性验证的系统化方法
- 指导组织建立制品哈希验证和防篡改机制
- 帮助理解完整性验证在软件供应链安全中的作用

## 1.2 适用范围
- 适用于软件制品（二进制、安装包、容器镜像）的分发场景
- 适用于需要验证下载文件完整性的场景
- 适用于 CI/CD 流程中的制品完整性保护

## 1.3 读者对象
- 安全工程师
- 发布工程师
- DevSecOps 工程师
- 软件供应商

---

# 第二部分：核心渗透技术专题

## 专题一：完整性验证

### 2.1 技术介绍

完整性验证是指通过密码学哈希函数（如 SHA256、SHA512）或数字签名技术，验证软件制品在存储、传输过程中未被篡改的过程。这是防止软件供应链攻击的基础防线。

**验证技术对比：**

```
┌─────────────────────────────────────────────────────────────┐
│                    完整性验证技术                            │
├─────────────────────────────────────────────────────────────┤
│  哈希校验（Hash Verification）                               │
│  ├── 原理：计算文件哈希值并与已知值对比                     │
│  ├── 算法：SHA256, SHA512, MD5（不推荐）                    │
│  ├── 优点：简单快速                                         │
│  └── 缺点：无法验证来源，哈希本身可能被篡改                │
├─────────────────────────────────────────────────────────────┤
│  数字签名（Digital Signature）                              │
│  ├── 原理：使用私钥签名，公钥验证                           │
│  ├── 算法：RSA, ECDSA, EdDSA                                │
│  ├── 优点：验证来源 + 完整性                                │
│  └── 缺点：需要密钥管理基础设施                             │
├─────────────────────────────────────────────────────────────┤
│  签名服务（Signing Service）                                │
│  ├── 原理：使用托管签名服务（如 Sigstore）                 │
│  ├── 优点：无需管理密钥，自动化程度高                       │
│  └── 缺点：依赖第三方服务                                   │
└─────────────────────────────────────────────────────────────┘
```

**常见验证场景：**

| 场景 | 验证方法 | 工具 |
|-----|---------|------|
| 文件下载 | SHA256 哈希校验 | sha256sum, shasum |
| npm 包 | integrity 哈希 | npm 内置 |
| Docker 镜像 | 内容信任签名 | Docker Content Trust |
| Maven 构件 | GPG 签名 | GPG, Maven 插件 |
| 二进制发布 | GPG/代码签名 | GPG, sigstore |

### 2.2 验证常见于哪些业务场景

| 业务场景 | 功能示例 | 验证要求 |
|---------|---------|---------|
| 软件官网下载 | 下载安装包 | 必须验证哈希 |
| 包管理器安装 | npm/pip/maven install | 自动验证 |
| 容器镜像拉取 | docker pull | 建议验证签名 |
| CI/CD 制品下载 | 下载构建产物 | 必须验证 |
| 第三方镜像源 | 使用非官方源 | 强烈建议验证 |
| 内部软件分发 | 企业内部分发 | 建议验证 |

### 2.3 完整性验证方法

#### 2.3.1 哈希校验

**Linux/macOS：**
```bash
# 计算文件哈希
sha256sum file.zip
sha512sum file.zip

# macOS
shasum -a 256 file.zip
shasum -a 512 file.zip

# 验证哈希
echo "abc123...  file.zip" | sha256sum -c
sha256sum -c file.zip.sha256
```

**Windows：**
```powershell
# PowerShell 计算哈希
Get-FileHash file.zip -Algorithm SHA256
Get-FileHash file.zip -Algorithm SHA512

# 验证哈希
$expected = "abc123..."
$actual = (Get-FileHash file.zip -Algorithm SHA256).Hash
if ($expected -eq $actual) { "验证通过" } else { "验证失败" }
```

**自动化脚本：**
```bash
#!/bin/bash
# 批量验证脚本

verify_hash() {
    local file=$1
    local expected_hash=$2
    
    actual_hash=$(sha256sum "$file" | awk '{print $1}')
    
    if [ "$expected_hash" = "$actual_hash" ]; then
        echo "[PASS] $file"
        return 0
    else
        echo "[FAIL] $file"
        echo "  Expected: $expected_hash"
        echo "  Actual:   $actual_hash"
        return 1
    fi
}

# 使用
verify_hash "app.zip" "abc123..."
```

#### 2.3.2 GPG 签名验证

**生成密钥：**
```bash
# 生成 GPG 密钥
gpg --full-generate-key

# 导出公钥
gpg --armor --export your@email.com > public.key

# 上传到密钥服务器
gpg --keyserver keyserver.ubuntu.com --send-keys KEY_ID
```

**签名文件：**
```bash
# 分离签名
gpg --armor --detach-sign file.zip
# 生成 file.zip.asc

# 嵌入式签名（清文签名）
gpg --armor --clearsign file.txt
# 生成 file.txt.asc（包含原文）
```

**验证签名：**
```bash
# 导入公钥
gpg --import public.key

# 验证签名
gpg --verify file.zip.asc file.zip

# 输出示例
# gpg: Signature made Mon 01 Jan 2024 00:00:00 UTC
# gpg:                using RSA key XXXXXXXXXXXXXXXX
# gpg: Good signature from "Name <email>" [unknown]
```

#### 2.3.3 npm 包完整性

```bash
# npm 自动验证 integrity
# package-lock.json 包含 integrity 字段
{
  "lockfileVersion": 2,
  "packages": {
    "node_modules/lodash": {
      "version": "4.17.21",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
      "integrity": "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg=="
    }
  }
}

# 验证 integrity
npm install --ignore-scripts  # 不执行脚本，仅验证

# 手动验证
echo "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg==" | \
  openssl base64 -d | sha512sum
```

#### 2.3.4 容器镜像验证

**Docker Content Trust：**
```bash
# 启用内容信任
export DOCKER_CONTENT_TRUST=1

# 拉取并验证镜像
docker pull ubuntu:20.04
# 如果镜像未签名，将拒绝拉取

# 查看信任信息
docker trust inspect --pretty ubuntu:20.04
```

**cosign 验证：**
```bash
# 安装 cosign
go install github.com/sigstore/cosign/cmd/cosign@latest

# 验证镜像签名
cosign verify \
  --key cosign.pub \
  ghcr.io/project/image:tag

# 无密钥验证（使用 Sigstore 免费签名）
cosign verify \
  --certificate-identity-regexp=.* \
  --certificate-oidc-issuer-regexp=.* \
  ghcr.io/project/image:tag
```

### 2.4 完整性破坏场景

#### 2.4.1 中间人攻击

```bash
# 场景：HTTP 下载被劫持
# 攻击者修改下载内容

# 防御：
# 1. 始终使用 HTTPS
# 2. 验证哈希或签名
# 3. 使用 HSTS

# 检测：
# 比较多个来源的哈希值
curl -s https://site1.com/file.zip | sha256sum
curl -s https://site2.com/file.zip | sha256sum
```

#### 2.4.2 哈希碰撞攻击

```bash
# 场景：MD5/SHA1 碰撞
# 攻击者生成相同哈希的恶意文件

# 防御：
# 1. 使用 SHA256 或更强算法
# 2. 结合数字签名

# 已废弃的算法：
# - MD5（已破解）
# - SHA1（已不建议使用）
```

#### 2.4.3 签名密钥泄露

```bash
# 场景：签名私钥被盗
# 攻击者可以签名恶意文件

# 防御：
# 1. 使用 HSM 保护私钥
# 2. 定期轮换密钥
# 3. 使用签名服务（如 Sigstore）

# 响应：
# 1. 吊销泄露密钥
# 2. 发布新密钥
# 3. 通知用户更新信任
```

### 2.5 CI/CD 集成

#### 2.5.1 GitHub Actions 集成

```yaml
name: Verify Integrity
on:
  push:
    branches: [main]

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Download Artifact
        uses: actions/download-artifact@v3
        with:
          name: build-artifact
      
      - name: Verify SHA256
        run: |
          echo "expected_hash  artifact.zip" | sha256sum -c
      
      - name: Verify GPG Signature
        run: |
          gpg --import public.key
          gpg --verify artifact.zip.sig artifact.zip
```

#### 2.5.2 Jenkins 集成

```groovy
pipeline {
    agent any
    stages {
        stage('Verify') {
            steps {
                sh '''
                    sha256sum -c checksums.txt
                    gpg --verify artifact.jar.sig artifact.jar
                '''
            }
        }
    }
}
```

---

# 第三部分：附录

## 3.1 哈希算法对比

| 算法 | 输出长度 | 安全性 | 推荐使用 |
|-----|---------|-------|---------|
| MD5 | 128 位 | 已破解 | ❌ 不推荐 |
| SHA1 | 160 位 | 已削弱 | ❌ 不推荐 |
| SHA256 | 256 位 | 安全 | ✅ 推荐 |
| SHA512 | 512 位 | 安全 | ✅ 推荐 |
| BLAKE3 | 可变 | 安全 | ✅ 新兴选择 |

## 3.2 完整性验证检查表

| 检查项 | 推荐做法 |
|-------|---------|
| 下载验证 | 始终验证哈希或签名 |
| 算法选择 | 使用 SHA256 或更强 |
| 密钥管理 | 使用 HSM 或签名服务 |
| 自动化 | CI/CD 中自动验证 |
| 密钥轮换 | 定期轮换签名密钥 |
| 公钥分发 | 通过安全渠道分发公钥 |

## 3.3 常见工具的完整性命令

| 工具 | 命令 | 说明 |
|-----|------|------|
| sha256sum | `sha256sum -c file.sha256` | Linux 哈希验证 |
| gpg | `gpg --verify file.sig file` | GPG 签名验证 |
| cosign | `cosign verify --key key.pub image` | 容器签名验证 |
| npm | `npm ci` | 自动验证 integrity |
| Maven | `mvn verify` | 验证构件完整性 |

## 3.4 安全工具

| 工具名称 | 用途 | 链接 |
|---------|------|------|
| GnuPG | GPG 签名 | https://gnupg.org/ |
| cosign | 容器签名 | https://github.com/sigstore/cosign |
| sigstore | 签名服务 | https://www.sigstore.dev/ |
| in-toto | 供应链完整性 | https://in-toto.io/ |

---

## 参考资源

- [Sigstore Project](https://www.sigstore.dev/)
- [Docker Content Trust](https://docs.docker.com/engine/security/trust/)
- [GnuPG Documentation](https://gnupg.org/documentation/)
- [in-toto Framework](https://in-toto.io/)
