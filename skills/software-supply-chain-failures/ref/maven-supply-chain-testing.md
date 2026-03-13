# Maven 供应链安全测试方法论

---

# 第一部分：文档概述

## 1.1 编写目的
- 为渗透测试人员提供 Maven 供应链安全测试的系统化方法
- 指导测试人员识别 Java 项目依赖中的安全风险
- 帮助理解 Maven 生态系统中的攻击面和防御措施

## 1.2 适用范围
- 适用于使用 Maven/Gradle 的 Java 项目
- 适用于使用 Maven Central 或私有仓库的场景
- 适用于企业级 Java 应用、Spring Boot 项目、Android 应用等

## 1.3 读者对象
- 渗透测试工程师
- Java 开发人员
- 构建工程师
- DevSecOps 工程师

---

# 第二部分：核心渗透技术专题

## 专题一：Maven 供应链安全测试

### 2.1 技术介绍

Maven 供应链安全测试是指对 Java 项目的 Maven 依赖进行系统性安全评估，识别依赖项中的已知漏洞、恶意构件、pom.xml 配置风险、凭证泄露等安全问题，确保项目依赖链的完整性和可信性。

**Maven 供应链架构：**

```
┌─────────────────────────────────────────────────────────────┐
│                    Maven 供应链架构                          │
├─────────────────────────────────────────────────────────────┤
│  开发者                                                     │
│    │ mvn install                                            │
│    ▼                                                        │
│  pom.xml (声明依赖)                                          │
│    │                                                        │
│    ▼                                                        │
│  Maven Repository (Central/私有)                             │
│    │ 下载构件                                               │
│    ▼                                                        │
│  ~/.m2/repository (本地缓存)                                 │
│    │                                                        │
│    ▼                                                        │
│  应用构建和运行                                             │
└─────────────────────────────────────────────────────────────┘
```

**常见安全问题：**

| 问题类型 | 描述 | 危害等级 |
|---------|------|---------|
| 已知漏洞 | 依赖构件存在 CVE 漏洞 | 高 |
| 恶意构件 | 包含恶意代码的 Maven 构件 | 严重 |
| 依赖混淆 | 公共构件名与内部构件冲突 | 高 |
| pom.xml 注入 | 构建配置被篡改 | 高 |
| 凭证泄露 | settings.xml 包含认证信息 | 高 |
| 传递依赖 | 深层依赖存在漏洞 | 中 |
| 插件风险 | 构建插件存在漏洞 | 高 |

### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 新项目构建 | mvn clean install | 直接下载未审查的依赖 |
| 依赖更新 | mvn versions:use-latest-versions | 更新到恶意版本 |
| CI/CD 构建 | mvn package | 自动构建可能使用恶意插件 |
| 企业项目 | 多模块项目 | 传递依赖复杂难追踪 |
| 私有构件发布 | mvn deploy | 可能发布恶意构件 |
| 插件执行 | mvn plugin:goal | 插件可能执行恶意代码 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**步骤一：识别项目依赖**
```bash
# 检查 pom.xml
curl https://target.com/pom.xml

# 检查依赖配置
<dependencies>
    <dependency>
        <groupId>org.springframework</groupId>
        <artifactId>spring-core</artifactId>
        <version>5.3.20</version>  <!-- 检查版本 -->
    </dependency>
</dependencies>
```

**步骤二：检查公开凭证**
```bash
# 检查 settings.xml 是否可访问
curl https://target.com/.m2/settings.xml

# 检查是否包含认证信息
<servers>
    <server>
        <id>nexus</id>
        <username>admin</username>
        <password>admin123</password>
    </server>
</servers>
```

**步骤三：漏洞扫描**
```bash
# 使用 OWASP Dependency-Check
mvn org.owasp:dependency-check-maven:check

# 使用 Snyk
npx snyk test

# 使用 Sonatype IQ
mvn -U org.sonatype.ossindex.maven:ossindex-maven-plugin:audit
```

#### 2.3.2 白盒测试

**步骤一：审计依赖树**
```bash
# 查看依赖树
mvn dependency:tree

# 查看依赖详情
mvn dependency:list

# 检查过时依赖
mvn versions:display-dependency-updates
```

**步骤二：检查 pom.xml 配置**
```xml
<!-- pom.xml -->
<project>
    <!-- 风险：使用 HTTP 而非 HTTPS -->
    <repositories>
        <repository>
            <id>central</id>
            <url>http://repo.maven.apache.org/maven2</url>
        </repository>
    </repositories>
    
    <!-- 风险：动态版本 -->
    <dependency>
        <groupId>com.example</groupId>
        <artifactId>lib</artifactId>
        <version>[1.0,2.0)</version>  <!-- 版本范围 -->
    </dependency>
</project>
```

**步骤三：检查 settings.xml**
```xml
<!-- ~/.m2/settings.xml -->
<settings>
    <!-- 风险：明文密码 -->
    <servers>
        <server>
            <id>nexus</id>
            <username>admin</username>
            <password>{plain}admin123</password>
        </server>
    </servers>
    
    <!-- 风险：不安全的镜像配置 -->
    <mirrors>
        <mirror>
            <id>unsafe-mirror</id>
            <url>http://mirror.example.com/maven2</url>
            <mirrorOf>*</mirrorOf>
        </mirror>
    </mirrors>
</settings>
```

### 2.4 漏洞利用方法

#### 2.4.1 依赖混淆攻击

```bash
# 1. 识别内部构件坐标
# groupId: com.company.internal
# artifactId: company-utils

# 2. 在 Maven Central 注册相同坐标
# 创建恶意构件

# 3. 发布到 Maven Central
# 如果目标配置不当，会从 Central 拉取
```

#### 2.4.2 恶意插件

```xml
<!-- pom.xml -->
<build>
    <plugins>
        <!-- 风险：使用未经验证的第三方插件 -->
        <plugin>
            <groupId>com.suspicious</groupId>
            <artifactId>malicious-plugin</artifactId>
            <version>1.0.0</version>
            <executions>
                <execution>
                    <phase>compile</phase>
                    <goals>
                        <goal>exploit</goal>
                    </goals>
                </execution>
            </executions>
        </plugin>
    </plugins>
</build>
```

#### 2.4.3 凭证窃取

```bash
# 1. 窃取 Maven 凭证
# ~/.m2/settings.xml 包含服务器密码

# 2. 窃取 GPG 密钥
# ~/.gnupg/ 包含签名密钥

# 3. 使用窃取的凭证
# 发布恶意构件
```

#### 2.4.4 传递依赖攻击

```xml
<!-- 直接依赖看似安全 -->
<dependency>
    <groupId>org.example</groupId>
    <artifactId>safe-lib</artifactId>
    <version>1.0.0</version>
</dependency>

<!-- 但传递依赖可能存在漏洞 -->
<!-- safe-lib -> vulnerable-lib:0.9.0 (存在 CVE) -->

# 检查传递依赖
mvn dependency:tree -Dincludes=vulnerable-lib
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过安全扫描

```bash
# 1. Dependency-Check 只扫描已知漏洞
# 恶意构件可能不在数据库中

# 2. 使用代码混淆
# 隐藏恶意代码

# 3. 利用传递依赖
# 深层依赖可能不被扫描
```

#### 2.5.2 绕过依赖管理

```xml
<!-- 1. 利用动态版本 -->
<version>[1.0,)</version>  <!-- 任何版本 -->
<version>LATEST</version>  <!-- 最新版本 -->
<version>RELEASE</version> <!-- 最新 release 版本 -->

<!-- 2. 利用版本范围 -->
<version>[1.0,2.0)</version>  <!-- 1.0 到 2.0 之间 -->
```

---

# 第三部分：附录

## 3.1 Maven 安全检测命令

```bash
# 安全审计
mvn org.owasp:dependency-check-maven:check
mvn -U org.sonatype.ossindex.maven:ossindex-maven-plugin:audit

# 检查依赖树
mvn dependency:tree
mvn dependency:list

# 检查过时依赖
mvn versions:display-dependency-updates

# 验证构件完整性
mvn verify
```

## 3.2 Maven 安全配置

```xml
<!-- settings.xml 安全配置 -->
<settings>
    <!-- 使用加密密码 -->
    <servers>
        <server>
            <id>nexus</id>
            <username>admin</username>
            <password>{AQ}encrypted-password</password>
        </server>
    </servers>
    
    <!-- 使用 HTTPS 仓库 -->
    <repositories>
        <repository>
            <id>central</id>
            <url>https://repo.maven.apache.org/maven2</url>
        </repository>
    </repositories>
    
    <!-- 锁定依赖版本 -->
    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>com.example</groupId>
                <artifactId>lib</artifactId>
                <version>1.2.3</version>  <!-- 精确版本 -->
            </dependency>
        </dependencies>
    </dependencyManagement>
</settings>
```

## 3.3 常见漏洞依赖

| 构件 | 漏洞版本 | 修复版本 | CVE 编号 |
|-----|---------|---------|---------|
| Log4j | 2.0-beta9 ~ 2.14.1 | 2.17.0+ | CVE-2021-44228 |
| Spring | 5.3.0 ~ 5.3.17 | 5.3.18+ | CVE-2022-22965 |
| Struts2 | 2.0.0 ~ 2.5.30 | 2.5.31+ | CVE-2021-31805 |
| Fastjson | < 1.2.83 | 1.2.83+ | CVE-2022-25845 |
| Jackson | < 2.13.2.1 | 2.13.2.1+ | CVE-2022-22963 |

## 3.4 安全工具

| 工具名称 | 用途 | 链接 |
|---------|------|------|
| OWASP Dependency-Check | 依赖漏洞扫描 | https://owasp.org/www-project-dependency-check/ |
| OSS Index | 构件漏洞扫描 | https://ossindex.sonatype.org/ |
| Snyk | 依赖安全扫描 | https://snyk.io/ |
| Maven Enforcer | 依赖规则执行 | https://maven.apache.org/enforcer/ |

---

## 参考资源

- [Maven Security Documentation](https://maven.apache.org/guides/introduction/introduction-to-security.html)
- [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/)
- [Sonatype OSS Index](https://ossindex.sonatype.org/)
- [Maven Central Repository](https://search.maven.org/)
