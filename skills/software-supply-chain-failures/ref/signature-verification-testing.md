# 签名验证测试方法论

---

# 第一部分：文档概述

## 1.1 编写目的
- 为渗透测试人员提供签名验证测试的系统化方法
- 指导测试人员识别签名验证机制中的安全漏洞
- 帮助理解数字签名在软件供应链安全中的作用和测试方法

## 1.2 适用范围
- 适用于使用 GPG、代码签名、容器签名等签名机制的场景
- 适用于需要测试签名验证实现的环境
- 适用于软件发布和分发流程的安全评估

## 1.3 读者对象
- 渗透测试工程师
- 安全研究人员
- 发布工程师
- DevSecOps 工程师

---

# 第二部分：核心渗透技术专题

## 专题一：签名验证测试

### 2.1 技术介绍

签名验证测试是指对软件制品的数字签名验证机制进行系统性安全评估，识别签名验证绕过、密钥管理不当、验证逻辑缺陷等安全问题，确保签名机制能够有效保护软件供应链。

**签名类型：**

```
┌─────────────────────────────────────────────────────────────┐
│                    数字签名类型                              │
├─────────────────────────────────────────────────────────────┤
│  GPG/PGP 签名                                                │
│  ├── 用途：开源软件、Linux 包                                │
│  ├── 算法：RSA, DSA, ECDSA, EdDSA                           │
│  └── 工具：GnuPG, GPG                                       │
├─────────────────────────────────────────────────────────────┤
│  代码签名证书                                                │
│  ├── 用途：Windows/Mac 应用、驱动程序                        │
│  ├── 算法：RSA, ECDSA                                       │
│  └── 工具：SignTool, codesign                               │
├─────────────────────────────────────────────────────────────┤
│  容器镜像签名                                                │
│  ├── 用途：Docker/OCI 镜像                                   │
│  ├── 标准：Notary, cosign, Sigstore                         │
│  └── 工具：docker trust, cosign                             │
├─────────────────────────────────────────────────────────────┤
│  包管理器签名                                                │
│  ├── 用途：npm, Maven, PyPI 包                               │
│  ├── 机制：包内嵌签名或元数据签名                           │
│  └── 工具：npm, Maven GPG 插件                               │
└─────────────────────────────────────────────────────────────┘
```

**常见签名验证问题：**

| 问题类型 | 描述 | 危害等级 |
|---------|------|---------|
| 验证绕过 | 签名验证可被禁用或跳过 | 高 |
| 弱密钥 | 使用短密钥或弱算法 | 中 |
| 密钥泄露 | 私钥保护不当 | 严重 |
| 过期验证 | 不检查证书过期 | 中 |
| 吊销检查缺失 | 不检查证书吊销状态 | 中 |
| 信任链缺陷 | 信任链验证不完整 | 高 |

### 2.2 测试常见于哪些业务场景

| 业务场景 | 功能示例 | 测试重点 |
|---------|---------|---------|
| 软件安装包 | .deb/.rpm 包安装 | GPG 签名验证 |
| Windows 应用 | .exe/.msi 安装 | 代码签名验证 |
| 容器镜像 | docker pull | 镜像签名验证 |
| 移动应用 | iOS/Android 应用 | 应用签名验证 |
| 固件更新 | IoT 设备固件 | 固件签名验证 |
| 自动更新 | 应用内自动更新 | 更新包签名验证 |

### 2.3 签名验证测试方法

#### 2.3.1 GPG 签名验证测试

**检查验证配置：**
```bash
# 检查 GPG 配置
gpg --list-keys
gpg --list-config

# 检查密钥强度
gpg --list-keys --with-colons | grep pub
# 检查密钥长度（应 >= 2048）
# 检查算法（RSA/EdDSA 推荐）
```

**测试验证绕过：**
```bash
# 1. 测试无签名文件
# 如果系统接受无签名文件，验证未强制执行

# 2. 测试无效签名
# 修改签名文件
echo "invalid" > file.sig
# 尝试验证
gpg --verify file.sig file
# 如果系统仍接受，验证逻辑有缺陷

# 3. 测试过期密钥
# 使用过期的密钥签名
# 检查系统是否检查过期状态
```

**测试信任链：**
```bash
# 1. 测试自签名证书
# 创建自签名密钥并签名
# 检查系统是否接受

# 2. 测试信任链断裂
# 使用不受信任的 CA 签名的密钥
# 检查系统是否验证完整信任链

# 3. 测试密钥吊销
gpg --import revoked-key.asc
gpg --list-keys --with-crl-urls
# 检查是否检查 CRL/OCSP
```

#### 2.3.2 代码签名验证测试

**Windows 代码签名：**
```powershell
# 检查签名
sigcheck.exe file.exe

# 验证签名
sigcheck.exe -v file.exe

# 测试验证绕过
# 1. 修改已签名文件
# 2. 检查系统是否拒绝运行
```

**macOS 代码签名：**
```bash
# 检查签名
codesign -dv --verbose=4 app.app

# 验证签名
codesign --verify --verbose=4 app.app

# 检查公证状态
spctl --assess --type execute --verbose app.app
```

#### 2.3.3 容器签名验证测试

**Docker Content Trust：**
```bash
# 检查 DCT 状态
echo $DOCKER_CONTENT_TRUST

# 测试 DCT 绕过
# 1. 禁用 DCT
export DOCKER_CONTENT_TRUST=0

# 2. 拉取未签名镜像
docker pull untrusted/image:tag

# 3. 如果成功，DCT 未强制执行
```

**cosign 验证测试：**
```bash
# 验证签名
cosign verify \
  --key cosign.pub \
  registry/image:tag

# 测试绕过
# 1. 修改镜像
docker pull registry/image:tag
docker tag registry/image:tag malicious:tag

# 2. 尝试验证
cosign verify --key cosign.pub malicious:tag
# 应该失败
```

#### 2.3.4 包管理器签名验证测试

**Maven GPG 签名：**
```bash
# 验证签名
mvn gpg:verify

# 测试绕过
# 1. 修改 pom.xml 禁用 GPG 插件
# 2. 部署无签名构件
# 3. 检查仓库是否接受
```

**npm 签名验证：**
```bash
# 检查验证配置
npm config get signature-verification

# 测试绕过
npm config set signature-verification false
npm install package-name
```

### 2.4 常见验证漏洞

#### 2.4.1 验证逻辑绕过

```bash
# 场景 1: 验证可配置关闭
# 如果签名验证可通过配置禁用

# 利用：
npm config set signature-verification false
# 或
echo "verify-signatures=false" >> ~/.npmrc
```

#### 2.4.2 时间窗口攻击

```bash
# 场景：密钥轮换期间
# 旧密钥仍然有效

# 利用：
# 1. 在密钥轮换窗口期
# 2. 使用旧密钥签名恶意文件
# 3. 系统可能仍接受
```

#### 2.4.3 信任链缺陷

```bash
# 场景：不验证完整信任链
# 只验证签名，不验证证书链

# 利用：
# 1. 创建自签名证书
# 2. 签名恶意文件
# 3. 如果系统接受，信任链验证缺失
```

#### 2.4.4 算法降级攻击

```bash
# 场景：支持弱算法
# 系统接受弱算法签名

# 利用：
# 1. 使用弱算法（如 MD5、SHA1）签名
# 2. 如果系统接受，存在算法降级风险
```

### 2.5 签名验证加固

#### 2.5.1 强制验证配置

```bash
# npm 强制验证
npm config set signature-verification true
npm config set //registry.npmjs.org/:_authToken=$TOKEN

# Docker 强制 DCT
# /etc/docker/daemon.json
{
  "content-trust": true
}

# Maven 强制签名
# settings.xml
<settings>
  <profiles>
    <profile>
      <id>gpg-sign</id>
      <properties>
        <gpg.passphrase>${env.GPG_PASSPHRASE}</gpg.passphrase>
      </properties>
    </profile>
  </profiles>
</settings>
```

#### 2.5.2 密钥管理最佳实践

```bash
# 1. 使用强密钥
gpg --full-generate-key
# 选择 RSA 4096 或 EdDSA

# 2. 保护私钥
# 使用智能卡或 HSM
# 设置密钥密码

# 3. 定期轮换
# 设置密钥过期时间
# 定期生成新密钥

# 4. 吊销管理
# 生成吊销证书
gpg --gen-revoke KEY_ID
# 安全存储吊销证书
```

---

# 第三部分：附录

## 3.1 签名验证检查表

| 检查项 | 推荐配置 | 风险等级 |
|-------|---------|---------|
| 验证强制执行 | 签名验证不可禁用 | 高 |
| 密钥强度 | RSA >= 2048, EdDSA | 中 |
| 密钥过期 | 设置合理过期时间 | 中 |
| 吊销检查 | 检查 CRL/OCSP | 中 |
| 算法限制 | 禁用 MD5/SHA1 | 中 |
| 信任链验证 | 验证完整信任链 | 高 |
| 密钥存储 | 使用 HSM/智能卡 | 高 |

## 3.2 签名工具对比

| 工具 | 用途 | 算法 | 特点 |
|-----|------|------|------|
| GnuPG | 通用签名 | RSA, EdDSA | 开源标准 |
| cosign | 容器签名 | ECDSA, EdDSA | Sigstore 生态 |
| SignTool | Windows 签名 | RSA, ECDSA | Windows 原生 |
| codesign | macOS 签名 | RSA, ECDSA | macOS 原生 |

## 3.3 签名验证命令速查

```bash
# GPG 验证
gpg --verify file.sig file

# cosign 验证
cosign verify --key key.pub image:tag

# Docker 信任
docker trust inspect image:tag

# Windows 签名检查
sigcheck.exe -v file.exe

# macOS 签名检查
codesign --verify app.app
```

## 3.4 安全工具

| 工具名称 | 用途 | 链接 |
|---------|------|------|
| GnuPG | GPG 签名 | https://gnupg.org/ |
| cosign | 容器签名 | https://github.com/sigstore/cosign |
| sigstore-cli | Sigstore CLI | https://github.com/sigstore/sigstore-cli |
| sigcheck | Windows 签名检查 | https://learn.microsoft.com/sysinternals/ |

---

## 参考资源

- [Sigstore Documentation](https://docs.sigstore.dev/)
- [GnuPG Documentation](https://gnupg.org/documentation/)
- [Docker Content Trust](https://docs.docker.com/engine/security/trust/)
- [NIST Code Signing Guidelines](https://csrc.nist.gov/publications/detail/sp/800-193/final)
