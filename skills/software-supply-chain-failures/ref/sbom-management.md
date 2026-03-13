# SBOM 管理方法论

---

# 第一部分：文档概述

## 1.1 编写目的
- 为渗透测试人员和安全团队提供软件物料清单（SBOM）管理的系统化方法
- 指导组织生成、维护、分析和共享 SBOM
- 帮助理解 SBOM 在软件供应链安全中的核心作用

## 1.2 适用范围
- 适用于需要生成和维护 SBOM 的软件组织
- 适用于需要向客户或监管机构提供 SBOM 的场景
- 适用于软件供应链安全合规要求（如行政命令 14028）

## 1.3 读者对象
- 安全工程师
- 合规官员
- 软件供应商
- 采购和安全评估人员

---

# 第二部分：核心渗透技术专题

## 专题一：SBOM 管理

### 2.1 技术介绍

软件物料清单（Software Bill of Materials, SBOM）是软件组件及其关系的正式记录，类似于制造业的物料清单。SBOM 提供了软件组成的透明度，帮助组织识别、跟踪和管理软件供应链风险。

**SBOM 核心价值：**

```
┌─────────────────────────────────────────────────────────────┐
│                      SBOM 核心价值                           │
├─────────────────────────────────────────────────────────────┤
│  透明度                                                     │
│  ├── 清楚知道软件包含哪些组件                               │
│  ├── 了解组件的来源和版本                                   │
│  └── 追踪组件之间的依赖关系                                 │
├─────────────────────────────────────────────────────────────┤
│  风险管理                                                   │
│  ├── 快速识别受漏洞影响的组件                               │
│  ├── 评估许可证合规风险                                     │
│  └── 检测恶意或不受信任的组件                               │
├─────────────────────────────────────────────────────────────┤
│  合规性                                                     │
│  ├── 满足监管要求（如 FDA、行政命令）                       │
│  ├── 支持客户安全评估                                       │
│  └── 提供审计证据                                           │
└─────────────────────────────────────────────────────────────┘
```

**主流 SBOM 格式：**

| 格式 | 维护组织 | 特点 | 适用场景 |
|-----|---------|------|---------|
| SPDX | Linux Foundation | ISO 标准，广泛支持 | 通用软件供应链 |
| CycloneDX | OWASP | 轻量级，安全导向 | 应用安全、容器 |
| SWID | NIST | 软件标识标准 | 企业软件管理 |

**SBOM 关键元素：**

- 组件标识（名称、版本、供应商）
- 组件关系（依赖树）
- 许可证信息
- 安全参考（CVE、CPE）
- 构建信息（时间、工具）

### 2.2 应用常见于哪些业务场景

| 业务场景 | 功能示例 | SBOM 作用 |
|---------|---------|---------|
| 软件开发 | 持续集成流程 | 自动生成 SBOM |
| 采购评估 | 第三方软件评估 | 验证供应商 SBOM |
| 漏洞响应 | Log4j 等漏洞爆发 | 快速定位受影响组件 |
| 合规审计 | 监管检查 | 提供合规证据 |
| 软件交付 | 向客户交付软件 | 附带 SBOM 文档 |
| 资产管理 | 企业软件资产清单 | 维护软件库存 |

### 2.3 SBOM 生成方法

#### 2.3.1 源代码级别生成

**Node.js 项目：**
```bash
# 使用 CycloneDX
npm install -g @cyclonedx/cyclonedx-npm
cyclonedx-npm > sbom.json

# 使用 SPDX
npm install -g @spdx/spdx-sbom
spdx-sbom > sbom.spdx
```

**Python 项目：**
```bash
# 使用 CycloneDX
pip install cyclonedx-bom
cyclonedx-bom -f json -o sbom.json

# 使用 requirements.txt
cyclonedx-bom -r requirements.txt -o sbom.json
```

**Java/Maven 项目：**
```bash
# 使用 Maven 插件
mvn org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom

# 使用 SPDX
mvn org.spdx:spdx-maven-plugin:generate
```

**通用方法：**
```bash
# 使用 Syft（支持多种语言）
syft dir:/path/to/source -o spdx-json=sbom-spdx.json
syft dir:/path/to/source -o cyclonedx-json=sbom-cdx.json

# 使用 Tern（容器镜像）
tern report -i image:tag -f spdx > sbom.spdx
```

#### 2.3.2 容器镜像生成

```bash
# 使用 Syft
syft registry:ubuntu:latest -o spdx-json=sbom.json

# 使用 Docker 扫描
docker scan --file sbom.json image:tag

# 使用 Anchore
anchore-cli image content image:tag --format spdx > sbom.spdx
```

#### 2.3.3 CI/CD 集成

```yaml
# GitHub Actions 示例
name: Generate SBOM
on:
  push:
    branches: [main]

jobs:
  sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Generate SBOM
        uses: anchore/sbom-action@v0
        with:
          format: spdx-json
          output-file: sbom.json
      
      - name: Upload SBOM
        uses: actions/upload-artifact@v3
        with:
          name: sbom
          path: sbom.json
```

### 2.4 SBOM 分析方法

#### 2.4.1 组件清单分析

```bash
# 使用 Grype 分析 SBOM
grype sbom:sbom.json

# 使用 CycloneDX CLI
cyclonedx-cli validate --input-file sbom.json
cyclonedx-cli merge --input-files sbom1.json sbom2.json --output-file merged.json

# 使用 SPDX Tools
java -jar spdx-tools.jar Verify sbom.spdx
```

#### 2.4.2 漏洞关联分析

```bash
# 使用 Grype 扫描 SBOM 中的漏洞
grype sbom:sbom.json --only-fixed

# 使用 Dependency-Track 导入 SBOM
# Web UI 或 API 导入
curl -X POST "http://dependency-track/api/v1/bom" \
  -H "X-API-Key: your-api-key" \
  -F "bom=@sbom.json" \
  -F "project=your-project-uuid"
```

#### 2.4.3 许可证合规分析

```bash
# 使用 FOSSA
fossa analyze
fossa test

# 使用 Black Duck
# 上传 SBOM 到 Black Duck 平台

# 使用 Scancode
scancode -l --json-pp licenses.json /path/to/source
```

### 2.5 SBOM 共享方法

#### 2.5.1 内部共享

```bash
# 存储到版本控制
git add sbom.json
git commit -m "Add SBOM"
git push

# 存储到制品仓库
curl -u admin:password \
  -X PUT "http://nexus/repository/sbom/sbom.json" \
  --upload-file sbom.json
```

#### 2.5.2 外部共享

```bash
# 通过安全渠道共享
# 加密 SBOM 文件
gpg --encrypt --recipient customer@example.com sbom.json

# 通过客户门户上传
# 通过 API 共享
```

#### 2.5.3 SBOM 验证

```bash
# 验证 SBOM 完整性
sha256sum sbom.json > sbom.json.sha256
sha256sum -c sbom.json.sha256

# 验证 SBOM 签名
gpg --verify sbom.json.sig sbom.json

# 验证格式合规性
cyclonedx-cli validate --input-file sbom.json
```

---

# 第三部分：附录

## 3.1 SBOM 最小元素要求

根据 NTIA 要求，SBOM 应包含以下最小元素：

| 元素类别 | 具体内容 |
|---------|---------|
| 供应商 | 组件供应商名称 |
| 组件名称 | 组件的标识名称 |
| 版本 | 组件版本号 |
| 其他唯一标识符 | CPE、PURL、SWID 等 |
| 依赖关系 | 组件间依赖关系 |
| 作者 | 组件作者信息 |
| 时间戳 | SBOM 生成时间 |

## 3.2 SBOM 格式对比

| 特性 | SPDX | CycloneDX | SWID |
|-----|------|-----------|------|
| 标准组织 | ISO/IEC | OWASP | NIST |
| 主要用途 | 许可证合规 | 安全分析 | 软件标识 |
| 文件格式 | JSON, XML, RDF | JSON, XML | XML |
| 漏洞支持 | 有限 | 完整 | 有限 |
| 工具支持 | 广泛 | 增长中 | 有限 |

## 3.3 SBOM 工具生态

| 工具类型 | 工具名称 | 链接 |
|---------|---------|------|
| 生成工具 | Syft | https://github.com/anchore/syft |
| 生成工具 | CycloneDX CLI | https://github.com/CycloneDX/cyclonedx-cli |
| 分析工具 | Grype | https://github.com/anchore/grype |
| 分析工具 | Dependency-Track | https://dependencytrack.org/ |
| 管理平台 | Black Duck | https://www.synopsys.com/software-integrity/security-testing/black-duck.html |
| 管理平台 | FOSSA | https://fossa.com/ |

## 3.4 SBOM 最佳实践

| 实践 | 描述 |
|-----|------|
| 自动化生成 | 在 CI/CD 中自动生成 SBOM |
| 版本控制 | 将 SBOM 纳入版本管理 |
| 定期更新 | 每次发布或依赖变更时更新 |
| 多格式支持 | 同时生成 SPDX 和 CycloneDX |
| 签名验证 | 对 SBOM 进行签名和验证 |
| 漏洞关联 | 将 SBOM 与漏洞数据库关联 |
| 供应链传递 | 要求供应商提供 SBOM |

---

## 参考资源

- [NTIA SBOM Minimum Elements](https://www.ntia.doc.gov/files/ntia/publications/sbom_minimum_elements_report.pdf)
- [OWASP CycloneDX](https://cyclonedx.org/)
- [SPDX Specification](https://spdx.github.io/spdx-spec/)
- [Dependency-Track](https://dependencytrack.org/)
- [Executive Order 14028](https://www.whitehouse.gov/briefing-room/presidential-actions/2021/05/12/executive-order-on-improving-the-nations-cybersecurity/)
