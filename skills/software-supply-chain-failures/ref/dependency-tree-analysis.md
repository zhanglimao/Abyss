# 依赖树分析方法论

---

# 第一部分：文档概述

## 1.1 编写目的
- 为安全团队提供依赖树分析的系统化方法
- 指导组织理解和可视化软件依赖关系
- 帮助识别传递依赖风险和依赖健康问题

## 1.2 适用范围
- 适用于使用 npm、pip、Maven、Cargo 等包管理器的项目
- 适用于需要分析深层依赖关系的场景
- 适用于依赖优化和安全审计

## 1.3 读者对象
- 安全工程师
- 应用开发人员
- 架构师
- 技术负责人

---

# 第二部分：核心渗透技术专题

## 专题一：依赖树分析

### 2.1 技术介绍

依赖树分析是指对软件项目的依赖关系进行系统性解析和可视化的过程，包括直接依赖、传递依赖、循环依赖、版本冲突等分析，帮助理解软件供应链的完整结构和潜在风险。

**依赖树结构：**

```
┌─────────────────────────────────────────────────────────────┐
│                    依赖树示例 (npm)                          │
├─────────────────────────────────────────────────────────────┤
│  your-project@1.0.0                                         │
│  ├── express@4.18.2                                         │
│  │   ├── accepts@1.3.8                                      │
│  │   ├── body-parser@1.20.1                                 │
│  │   │   ├── bytes@3.1.2                                    │
│  │   │   └── depd@2.0.0                                     │
│  │   └── cookie@0.5.0                                       │
│  ├── lodash@4.17.21                                         │
│  └── axios@1.4.0                                            │
│      └── follow-redirects@1.15.2                            │
│          └── debug@4.3.4 (重复)                             │
├─────────────────────────────────────────────────────────────┤
│  直接依赖：express, lodash, axios (3 个)                     │
│  传递依赖：accepts, body-parser, cookie... (10+ 个)          │
│  重复依赖：debug (可能出现版本冲突)                          │
└─────────────────────────────────────────────────────────────┘
```

**依赖类型：**

| 类型 | 描述 | 风险等级 |
|-----|------|---------|
| 直接依赖 | 项目中直接声明的依赖 | 中 |
| 传递依赖 | 直接依赖的依赖 | 高（难以追踪） |
| 开发依赖 | 仅开发/构建时需要 | 低 |
| 对等依赖 | 需要宿主环境提供 | 中 |
| 可选依赖 | 可选的功能扩展 | 低 |
| 循环依赖 | A 依赖 B，B 依赖 A | 高 |

**常见依赖问题：**

- **依赖地狱**：版本冲突导致无法安装
- **重复依赖**：同一包的多个版本共存
- **深层依赖**：依赖树过深，难以追踪
- **幽灵依赖**：未声明但实际使用
- **僵尸依赖**：声明但未使用

### 2.2 分析常见于哪些业务场景

| 业务场景 | 功能示例 | 分析重点 |
|---------|---------|---------|
| 新项目初始化 | 添加首批依赖 | 依赖选择合理性 |
| 依赖添加 | npm install new-pkg | 传递依赖影响 |
| 版本升级 | npm update | 破坏性变更 |
| 漏洞响应 | Log4j 事件 | 定位受影响组件 |
| 构建优化 | 减少包体积 | 移除未使用依赖 |
| 安全审计 | 合规检查 | 许可证风险 |

### 2.3 依赖树分析方法

#### 2.3.1 npm 项目分析

```bash
# 查看依赖树
npm ls
npm ls --depth=0  # 只看直接依赖
npm ls --all  # 完整依赖树

# 查看特定包的依赖来源
npm ls lodash
npm ls --all --depth=Infinity | grep lodash

# 检查重复依赖
npm ls --all | sort | uniq -d

# 检查过时依赖
npm outdated

# 检查未使用依赖
npx depcheck

# 生成可视化依赖图
npx madge --image dependency-graph.png .
```

#### 2.3.2 Python 项目分析

```bash
# 安装依赖树工具
pip install pipdeptree

# 查看依赖树
pipdeptree
pipdeptree --tree  # 树形展示
pipdeptree --reverse  # 反向查看（谁依赖我）

# 检查冲突
pipdeptree --warn

# 生成依赖图
pipdeptree --graph-output png > dependencies.png

# 检查过时依赖
pip list --outdated

# 使用 pip-compile 锁定依赖
pip-compile requirements.in
```

#### 2.3.3 Maven 项目分析

```bash
# 查看依赖树
mvn dependency:tree
mvn dependency:tree -Dverbose  # 显示省略的依赖
mvn dependency:tree -Dincludes=com.example  # 过滤特定包

# 分析依赖
mvn dependency:analyze  # 分析依赖使用
mvn dependency:analyze-duplicate  # 分析重复依赖

# 检查过时依赖
mvn versions:display-dependency-updates

# 生成依赖图
mvn dependency:tree -Dverbose -DoutputFile=deps.txt
```

#### 2.3.4 通用分析工具

```bash
# 使用 Syft 生成 SBOM 和依赖树
syft dir:/path/to/project -o spdx-json=sbom.json

# 使用 Grype 分析依赖漏洞
grype dir:/path/to/project

# 使用 Snyk 分析
npx snyk wizard  # 交互式修复向导
```

### 2.4 依赖问题分析与修复

#### 2.4.1 版本冲突解决

**npm 分辨率 (resolutions)：**
```json
// package.json
{
  "resolutions": {
    "**/lodash": "4.17.21",
    "**/glob-parent": "5.1.2"
  }
}
```

**Maven 依赖管理：**
```xml
<dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>com.fasterxml.jackson.core</groupId>
            <artifactId>jackson-databind</artifactId>
            <version>2.15.0</version>
        </dependency>
    </dependencies>
</dependencyManagement>
```

#### 2.4.2 传递依赖漏洞修复

```bash
# 1. 识别漏洞传递依赖
npm ls vulnerable-package
mvn dependency:tree -Dincludes=vulnerable-package

# 2. 方案 A: 等待直接依赖更新
# 联系直接依赖维护者升级

# 3. 方案 B: 强制覆盖版本
# 使用 resolutions 或 dependencyManagement

# 4. 方案 C: 替换依赖
# 寻找替代包
```

#### 2.4.3 循环依赖检测

```bash
# npm 检测
npx madge --circular .

# Maven 检测
mvn dependency:analyze

# Python 检测
# 手动检查或使用 pyan
pyan *.py --uses --no-defines --colored --graph=svg
```

#### 2.4.4 未使用依赖清理

```bash
# npm
npx depcheck
# 编辑 package.json 移除未使用依赖

# Python
pipreqs /path/to/project --force
# 生成基于实际使用的 requirements.txt

# Maven
mvn dependency:analyze
# 查看 Unused dependencies 和 Used undeclared dependencies
```

### 2.5 依赖树可视化

#### 2.5.1 文本可视化

```bash
# npm 树形输出
npm ls --all --depth=Infinity

# Python 树形输出
pipdeptree --tree

# 输出示例
your-project@1.0.0
├── express@4.18.2
│   ├── accepts@1.3.8
│   └── body-parser@1.20.1
└── lodash@4.17.21
```

#### 2.5.2 图形可视化

```bash
# 生成 PNG/SVG 图
npx madge --image deps.png .
pipdeptree --graph-output svg > deps.svg

# 使用在线工具
# https://npm.anvaka.com/ - npm 依赖可视化
# https://deps.dev/ - Google 依赖探索器
```

#### 2.5.3 SBOM 格式输出

```bash
# 生成 CycloneDX SBOM
npx @cyclonedx/cyclonedx-npm > sbom.json

# 生成 SPDX SBOM
syft . -o spdx-json=sbom.spdx.json

# 导入 Dependency-Track 分析
curl -X POST "http://dtrack/api/v1/bom" \
  -H "X-API-Key: your-key" \
  -F "bom=@sbom.json"
```

---

# 第三部分：附录

## 3.1 依赖分析工具对比

| 工具 | 支持语言 | 特点 | 适用场景 |
|-----|---------|------|---------|
| npm ls | JavaScript | npm 内置 | 快速查看 |
| pipdeptree | Python | 轻量级 | Python 项目 |
| Maven Dependency | Java | 功能全面 | Maven 项目 |
| depcheck | 多语言 | 检测未使用 | 依赖清理 |
| madge | JavaScript | 可视化好 | 依赖图 |
| Syft | 多语言 | SBOM 生成 | 合规审计 |

## 3.2 依赖健康指标

| 指标 | 健康标准 | 风险信号 |
|-----|---------|---------|
| 直接依赖数 | < 50 | > 200 |
| 依赖树深度 | < 10 层 | > 20 层 |
| 重复依赖 | 0 | > 10 |
| 过时依赖 | < 10% | > 50% |
| 有漏洞依赖 | 0 | 任何数量 |
| 未使用依赖 | 0 | > 5 |

## 3.3 依赖管理最佳实践

| 实践 | 描述 |
|-----|------|
| 精确版本 | 使用精确版本号而非范围 |
| 锁定文件 | 提交 lock 文件到版本控制 |
| 定期更新 | 每周/每月更新依赖 |
| 最小依赖 | 只依赖必要的包 |
| 监控漏洞 | 启用自动漏洞通知 |
| 审计依赖 | 定期审查依赖树 |

## 3.4 相关资源

| 资源 | 链接 |
|-----|------|
| deps.dev | https://deps.dev/ |
| npm.anvaka.com | https://npm.anvaka.com/ |
| Snyk Vulnerability DB | https://snyk.io/vuln |
| Dependency-Track | https://dependencytrack.org/ |

---

## 参考资源

- [npm Dependencies Documentation](https://docs.npmjs.com/cli/v6/configuring-npm/package-json#dependencies)
- [Maven Dependency Plugin](https://maven.apache.org/plugins/maven-dependency-plugin/)
- [pipdeptree](https://github.com/tox-dev/pipdeptree)
- [madge](https://github.com/pahen/madge)
