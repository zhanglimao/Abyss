# 恶意依赖检测方法论

---

# 第一部分：文档概述

## 1.1 编写目的
- 为安全团队提供恶意依赖检测的系统化方法
- 指导组织识别和防范供应链中的恶意包攻击
- 帮助理解恶意依赖的特征、检测技术和响应流程

## 1.2 适用范围
- 适用于使用 npm、pip、Maven、RubyGems 等包管理器的场景
- 适用于需要防范依赖混淆、Typosquatting 等攻击的组织
- 适用于 CI/CD 流程中的恶意代码检测

## 1.3 读者对象
- 安全工程师
- 应用安全研究人员
- DevSecOps 工程师
- 威胁情报分析师

---

# 第二部分：核心渗透技术专题

## 专题一：恶意依赖检测

### 2.1 技术介绍

恶意依赖检测是指识别软件供应链中故意注入的恶意软件包的过程。与已知漏洞扫描不同，恶意依赖检测关注的是攻击者主动注入的恶意代码，包括 Typosquatting 包、依赖混淆攻击、被入侵维护者发布的恶意更新等。

**恶意包类型：**

```
┌─────────────────────────────────────────────────────────────┐
│                    恶意依赖类型                              │
├─────────────────────────────────────────────────────────────┤
│  Typosquatting（拼写相似）                                   │
│  ├── lodash -> lodahs                                      │
│  ├── requests -> requestss                                 │
│  └── 利用开发者拼写错误                                     │
├─────────────────────────────────────────────────────────────┤
│  依赖混淆（Dependency Confusion）                           │
│  ├── 内部包名在公共仓库注册                                │
│  ├── 版本号高于内部版本                                    │
│  └── 利用包管理器优先级                                     │
├─────────────────────────────────────────────────────────────┤
│  账户劫持（Account Takeover）                               │
│  ├── 维护者账户被盗                                         │
│  ├── 发布恶意更新                                           │
│  └── 影响所有下游项目                                       │
├─────────────────────────────────────────────────────────────┤
│  废弃包劫持（Unmaintained Package）                         │
│  ├── 长期未维护的包                                         │
│  ├── 攻击者获取发布权限                                     │
│  └── 发布恶意版本                                           │
├─────────────────────────────────────────────────────────────┤
│  恶意脚本（Malicious Scripts）                              │
│  ├── postinstall 脚本                                       │
│  ├── setup.py 执行                                          │
│  └── 安装时自动执行恶意代码                                 │
└─────────────────────────────────────────────────────────────┘
```

**常见恶意行为：**

| 行为类型 | 描述 | 检测难度 |
|---------|------|---------|
| 凭证窃取 | 读取 .npmrc、.aws/credentials 等 | 中 |
| 数据外带 | 发送环境变量、源码到外部服务器 | 中 |
| 后门植入 | 写入持久化脚本 | 高 |
| 加密货币挖矿 | 占用系统资源挖矿 | 低 |
| DDoS 参与 | 作为僵尸网络节点 | 中 |
| 传播感染 | 尝试感染其他项目 | 高 |

### 2.2 检测常见于哪些业务场景

| 业务场景 | 功能示例 | 检测策略 |
|---------|---------|---------|
| 新依赖引入 | 添加新包到项目 | 严格审查 |
| CI/CD 构建 | 自动安装依赖 | 自动化检测 |
| 依赖更新 | npm update | 变更分析 |
| 开源项目 | 接受外部 PR | PR 审查 |
| 供应商交付 | 第三方软件交付 | 全面扫描 |
| 应急响应 | 爆发恶意包事件 | 紧急排查 |

### 2.3 恶意依赖检测方法

#### 2.3.1 静态分析

**包元数据分析：**
```bash
# 检查包发布信息
npm view package-name --json
# 检查：
# - 发布时间（是否刚发布）
# - 维护者数量（是否单一）
# - 下载量（是否极低）
# - 仓库链接（是否存在）

# 检查版本历史
npm view package-name versions
# 检查：
# - 版本跳跃（是否异常）
# - 发布频率（是否突然活跃）
```

**代码特征检测：**
```bash
# 检测可疑代码模式
# package.json scripts
grep -E "postinstall|preinstall|install" package.json

# 检测敏感 API 调用
grep -rE "child_process\.exec|eval\(|Function\(" node_modules/

# 检测网络请求
grep -rE "https?\.get|axios\.post|fetch\(" node_modules/

# 检测文件系统访问
grep -rE "fs\.readFileSync|fs\.writeFileSync" node_modules/

# 检测环境变量访问
grep -rE "process\.env\.[A-Z_]*(KEY|SECRET|TOKEN|PASSWORD)" node_modules/
```

**自动化扫描工具：**
```bash
# 使用 Socket.dev
npx socket scan package-name

# 使用 Phylum
phylum analyze package-name

# 使用 Replit
npx @replit/package-analyzer package-name
```

#### 2.3.2 动态分析

**沙箱执行分析：**
```bash
# 在沙箱环境中安装包
# 使用 Docker 沙箱
docker run --rm -it node:alpine sh
npm install suspicious-package

# 监控系统调用
strace -f npm install suspicious-package 2>&1 | \
  grep -E "connect|open|exec"

# 监控网络活动
tcpdump -i any -n port 80 or port 443

# 监控文件变化
npm install suspicious-package
git status  # 查看修改的文件
```

**行为分析脚本：**
```python
#!/usr/bin/env python3
# 恶意行为检测脚本

import subprocess
import json
import os

def analyze_package(package_name):
    # 在沙箱中安装
    result = subprocess.run(
        ['npm', 'install', package_name],
        capture_output=True,
        text=True
    )
    
    # 检查网络请求
    # 检查文件修改
    # 检查进程创建
    
    return risk_score
```

#### 2.3.3 依赖树分析

```bash
# 检查完整依赖树
npm ls --all --depth=Infinity

# 检查新添加的依赖
# 比较 package-lock.json 变更
git diff main package-lock.json

# 检查深层依赖
npm ls --all | grep suspicious-package
```

### 2.4 已知恶意包案例

#### 2.4.1 colors.js 事件（2022）

```bash
# 事件概述
# 维护者故意破坏自己的包，导致数千项目受影响

# 检测指标
# - 单一维护者
# - 高下载量
# - 突然的破坏性更新

# 响应措施
# 1. 锁定版本： "colors": "1.4.0"
# 2. 使用镜像或 fork
# 3. 监控维护者动态
```

#### 2.4.2 node-ipc 事件（2022）

```bash
# 事件概述
# 维护者添加针对特定国家开发者的恶意代码

# 恶意代码特征
# - 条件触发（基于 IP）
# - 文件删除
# - 替换为特定内容

# 检测指标
# - 地缘政治相关代码
# - 文件系统破坏操作
# - 条件执行的恶意逻辑
```

#### 2.4.3 Typosquatting 案例

```bash
# 常见模式
# lodash -> lodash-utils, lodash-helper
# react -> reeact, r3act
# requests -> requests-python

# 检测命令
# 检查拼写相似的包
npm search lodash | grep -E "lodash[-_]?[a-z]+"
```

### 2.5 响应与缓解

#### 2.5.1 立即响应

```bash
# 1. 隔离受影响系统
# 断开网络连接
# 停止相关服务

# 2. 识别恶意包
npm ls  # 查看安装的包
cat package-lock.json  # 查看确切版本

# 3. 移除恶意包
rm -rf node_modules
rm package-lock.json
npm install  # 重新安装

# 4. 轮换凭证
# 更改所有可能泄露的凭证
```

#### 2.5.2 长期缓解

```bash
# 1. 锁定依赖版本
# 使用精确版本而非范围
"dependencies": {
  "lodash": "4.17.21"  # 而非 "^4.17.0"
}

# 2. 启用锁文件完整性检查
npm config set lockfile-version 2

# 3. 使用私有仓库代理
# Nexus/Artifactory 代理公共仓库
# 审核后才允许新包

# 4. 实施包白名单
# 只允许经过审核的包
```

---

# 第三部分：附录

## 3.1 恶意包检测指标

| 指标 | 检测方法 | 风险信号 |
|-----|---------|---------|
| 新发布 | 检查发布时间 | < 7 天 |
| 下载量低 | npm view downloads | < 100/周 |
| 单一维护者 | npm view maintainers | 仅 1 人 |
| 无仓库链接 | npm view repository | 空或无效 |
| postinstall 脚本 | 检查 scripts | 存在 |
| 代码混淆 | 检测混淆模式 | 高度混淆 |
| 网络请求 | 检测 https 调用 | 非常规域名 |
| 系统命令 | 检测 child_process | 存在 |

## 3.2 检测工具对比

| 工具 | 检测类型 | 准确率 | 特点 |
|-----|---------|-------|------|
| Socket.dev | 静态 + 行为 | 高 | 深度分析 |
| Phylum | 静态 + ML | 高 | 机器学习 |
| Snyk | 已知恶意包 | 中 | 数据库匹配 |
| npm audit | 已知漏洞 | 中 | 内置工具 |

## 3.3 安全配置示例

```json
// .npmrc 安全配置
registry=https://registry.npmjs.org/
// 禁用脚本
ignore-scripts=true
// 严格 SSL
strict-ssl=true
// 锁定版本
save-exact=true

// package.json 安全配置
{
  "resolutions": {
    // 强制使用安全版本
    "lodash": "4.17.21"
  },
  "overrides": {
    // npm 8+ 支持
    "vulnerable-pkg": "2.0.0"
  }
}
```

## 3.4 响应流程

```
发现可疑包
    │
    ▼
静态分析（代码审查）
    │
    ▼
动态分析（沙箱执行）
    │
    ├── 确认恶意 ──▶ 立即移除
    │                  │
    │                  ▼
    │               轮换凭证
    │                  │
    │                  ▼
    │               通知团队
    │                  │
    │                  ▼
    │               报告事件
    │
    └── 确认为安全 ──▶ 加入白名单
```

---

## 参考资源

- [Snyk Malicious Packages Report](https://snyk.io/blog/malicious-packages/)
- [Socket.dev Security Research](https://socket.dev/blog)
- [Phylum Supply Chain Security](https://www.phylum.io/)
- [npm Security Advisories](https://www.npmjs.com/advisories)
