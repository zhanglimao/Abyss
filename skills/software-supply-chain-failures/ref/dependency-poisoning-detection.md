# 依赖投毒检测方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的依赖投毒检测流程。

## 1.2 适用范围

本文档适用于使用包管理器的软件项目安全评估。

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 检测目标

依赖投毒检测旨在发现项目中是否存在恶意或被篡改的依赖包。

**检测范围**：
- 直接依赖
- 传递依赖
- 依赖脚本
- 包来源可信度

## 2.2 检测方法

### 2.2.1 依赖清单审计

```bash
# npm 项目
npm list --depth=0          # 直接依赖
npm list --all              # 所有依赖
cat package-lock.json       # 锁定文件审计

# Python 项目
pip list
pip freeze
cat requirements.txt

# Maven 项目
mvn dependency:tree
```

### 2.2.2 可疑包检测

```bash
# 检查以下可疑特征：
# 1. 包名与流行包相似
# 2. 包下载量异常低
# 3. 包发布时间异常
# 4. 发布者信息可疑
# 5. 包包含 postinstall 脚本

# 使用工具检测
npm audit
pip-audit
snyk test
```

### 2.2.3 脚本分析

```bash
# 检查 package.json 中的脚本
cat package.json | grep -A 10 "scripts"

# 可疑脚本特征：
# - postinstall 执行外部代码
# - preinstall 下载远程文件
# - 脚本包含编码内容
# - 脚本访问敏感路径
```

### 2.2.4 自动化扫描工具

```bash
# Socket.dev - 包行为分析
npx @socketsecurity/cli

# Snyk - 漏洞和恶意包检测
snyk test

# npm audit - 内置安全审计
npm audit --audit-level=high

# pip-audit - Python 包审计
pip-audit
```

## 2.3 检测指标

### 2.3.1 包可信度指标

| 指标 | 正常 | 可疑 | 危险 |
|-----|------|------|------|
| 下载量 | >100 万/月 | <1 万/月 | <100/月 |
| 发布时间 | >1 年 | <6 个月 | <1 个月 |
| 维护者 | 知名组织 | 个人 | 匿名 |
| 仓库链接 | GitHub 官方 | 个人仓库 | 无仓库 |
| postinstall | 无 | 简单脚本 | 复杂/编码 |

### 2.3.2 依赖树分析

```bash
# 分析深层依赖
# 恶意代码可能隐藏在传递依赖中

# 使用 npm ls 查看依赖树
npm ls <package-name>

# 检查不寻常的依赖路径
# 例如：正常包依赖了不相关的包
```

## 2.4 响应流程

### 2.4.1 发现可疑包

```
1. 记录包信息（名称、版本、发布者）
2. 分析包内容
3. 检查包行为
4. 评估风险等级
5. 制定响应计划
```

### 2.4.2 包内容分析

```bash
# 下载包内容
npm view <package> dist.tarball
curl -O <tarball-url>
tar -xzf package.tgz

# 分析内容：
# 1. 检查 package.json
# 2. 检查脚本文件
# 3. 检查是否有隐藏文件
# 4. 检查是否有编码内容
```

### 2.4.3 沙箱执行分析

```bash
# 在隔离环境中安装包
# 监控以下行为：
# - 网络连接
# - 文件访问
# - 环境变量读取
# - 子进程执行

# 使用工具：
# - Firejail (Linux 沙箱)
# - Docker 容器
```

---

# 第三部分：附录

## 3.1 依赖投毒检测检查清单

```
□ 审计直接依赖
□ 审计传递依赖
□ 检查包下载量
□ 检查包发布时间
□ 检查发布者信息
□ 检查 postinstall 脚本
□ 使用自动化工具扫描
□ 沙箱分析可疑包
```

## 3.2 常用工具

| 工具 | 用途 | 链接 |
|-----|------|------|
| npm audit | npm 安全审计 | 内置 |
| pip-audit | Python 包审计 | https://pypi.org/project/pip-audit/ |
| Snyk | 综合安全扫描 | https://snyk.io/ |
| Socket | 包行为分析 | https://socket.dev/ |
| OSV-Scanner | Google 漏洞扫描 | https://github.com/google/osv-scanner |

## 3.3 响应建议

1. **立即移除** - 移除确认恶意的包
2. **更新版本** - 更新到安全版本
3. **更换替代** - 使用可信替代包
4. **报告事件** - 向仓库维护者报告
5. **凭证轮换** - 如果凭证可能泄露

---

**参考资源**：
- [OWASP Software Supply Chain Security](https://owasp.org/www-project-software-supply-chain-security/)
- [npm Security Advisories](https://www.npmjs.com/advisories)
