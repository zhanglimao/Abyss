# 敏感资源枚举方法论

---

## 第一部分：文档概述

### 1.1 编写目的
为渗透测试人员提供针对 Web 应用中敏感资源（文件、目录、API 端点等）进行系统性枚举的方法论。敏感资源枚举是信息收集阶段的关键环节，有助于发现未公开的接口、备份文件、配置文件等高风险目标。

### 1.2 适用范围
- Web 应用程序
- RESTful API 接口
- 移动应用后端
- 单页应用（SPA）
- 微服务架构

### 1.3 读者对象
- 渗透测试工程师
- Web 安全分析师
- 红队成员
- 安全研究人员

---

## 第二部分：核心渗透技术专题

### 专题：敏感资源枚举

#### 2.1 技术介绍

敏感资源枚举是指通过系统化方法发现目标系统中未公开或受保护的资源，包括文件、目录、API 端点、参数等。这些资源可能包含敏感信息或提供未授权访问途径。

**敏感资源类型：**

| 资源类型 | 示例 | 风险等级 |
|---------|------|---------|
| **备份文件** | `.bak`、`.old`、`~` | 高 |
| **配置文件** | `.env`、`config.php`、`web.config` | 严重 |
| **版本控制** | `.git/`、`.svn/`、`.hg/` | 严重 |
| **日志文件** | `.log`、`access.log` | 高 |
| **数据库文件** | `.sql`、`.db`、`.sqlite` | 严重 |
| **API 文档** | `/swagger/`、`/api-docs/` | 中 |
| **管理界面** | `/admin/`、`/manager/` | 高 |
| **测试文件** | `/test/`、`/debug/` | 中 |

**枚举方法分类：**

```
敏感资源枚举
├── 暴力枚举
│   ├── 字典攻击
│   ├── 模式猜测
│   └── 组合枚举
├── 被动枚举
│   ├── 搜索引擎
│   ├── 公开文档
│   └── 代码仓库
├── 主动枚举
│   ├── 爬虫分析
│   ├── JS 文件分析
│   └── API 探测
└── 侧信道枚举
    ├── 响应时间差异
    ├── 响应长度差异
    └── 状态码差异
```

#### 2.2 枚举常见于哪些场景

| 场景 | 风险点描述 |
|-----|-----------|
| **应用上线** | 开发文件未清理 |
| **版本更新** | 旧版本文件残留 |
| **错误配置** | 目录列表开启 |
| **第三方组件** | 默认路径未修改 |
| **CI/CD 部署** | 构建产物暴露 |

#### 2.3 漏洞探测方法

##### 2.3.1 暴力枚举

**1. 目录/文件扫描工具**

```bash
# Dirb
dirb http://target/
dirb http://target/ common.txt

# Dirbuster
dirbuster -u http://target/ -w wordlist.txt

# Gobuster (推荐)
gobuster dir -u http://target/ -w wordlist.txt
gobuster dir -u http://target/ -w wordlist.txt -x php,txt,bak

# Ffuf (快速)
ffuf -w wordlist.txt -u http://target/FUZZ
ffuf -w wordlist.txt -u http://target/FUZZ -e .bak,.old,.sql

# Nuclei
nuclei -t http/exposed-panels/ -u target
nuclei -t http/misconfiguration/ -u target
```

**2. 常用字典文件**

| 字典名称 | 内容 | 来源 |
|---------|------|------|
| **dirb/common.txt** | 常见目录和文件 | Dirb 自带 |
| **SecLists** | 综合字典集 | GitHub |
| **raft-large-words** | 大型目录字典 | Burp Suite |
| **fuzzdb** | Fuzz 测试字典 | GitHub |

**3. 自定义字典生成**

```bash
# 基于目标名称生成
crunch 4 8 -t targetXXX > custom_wordlist.txt

# 组合生成
echo -e "admin\nmanager\nconsole\ndashboard" > wordlist.txt

# 从 JS 文件提取路径
curl http://target/app.js | grep -oE '"/[a-zA-Z0-9/_-]+"' | tr -d '"'
```

##### 2.3.2 被动枚举

**1. 搜索引擎枚举（Google Hacking）**

```
# 查找目录列表
site:target.com intitle:"index of"

# 查找备份文件
site:target.com ext:bak OR ext:old OR ext:backup

# 查找配置文件
site:target.com ext:env OR ext:config OR ext:ini

# 查找日志文件
site:target.com ext:log

# 查找数据库文件
site:target.com ext:sql OR ext:db OR ext:sqlite

# 查找敏感文件
site:target.com intext:"password" OR intext:"secret"
```

**2. 公开资源枚举**

```bash
# Wayback Machine (历史 URL)
curl "http://web.archive.org/cdx/search/cdx?url=target.com/*"

# Common Crawl
curl "http://index.commoncrawl.org/CC-MAIN-2021-04-index?url=target.com/*"

# GitHub 代码搜索
# 搜索目标域名相关的硬编码 URL
```

**3. DNS 子域名枚举**

```bash
# Subfinder
subfinder -d target.com

# Sublist3r
python sublist3r.py -d target.com

# Amass
amass enum -d target.com

# OneForAll
python oneforall.py --target target.com run
```

##### 2.3.3 主动枚举

**1. 爬虫分析**

```bash
# Burp Suite Spider
# 自动爬取整个站点

# Gowitness (截图 + 爬虫)
gowitness chrome --url http://target/

# Katana (现代爬虫)
katana -u http://target/ -d 3

# Hakrawler
echo "http://target/" | hakrawler
```

**2. JavaScript 文件分析**

```bash
# 提取 JS 文件中的路径
curl http://target/app.js | grep -oE '"/[a-zA-Z0-9/_-]+"'

# 使用 JSParser
curl http://target/app.js | python jsparser.py

# 使用 LinkFinder
python linkfinder.py -i http://target/app.js -o cli
```

**3. API 端点枚举**

```bash
# 常见 API 路径
/api/
/api/v1/
/api/v2/
/api/v3/
/graphql
/swagger/
/api-docs/
/openapi.json

# 使用 API 扫描工具
nuclei -t http/exposed-apis/ -u target
```

##### 2.3.4 侧信道枚举

**1. 响应长度差异**

```bash
# 正常页面长度：1234 字节
# 404 页面长度：5678 字节
# 如果某个路径返回不同长度，可能存在

ffuf -w wordlist.txt -u http://target/FUZZ \
     -fs 5678  # 过滤特定长度
```

**2. 响应时间差异**

```bash
# 某些路径可能需要数据库查询，响应较慢
ffuf -w wordlist.txt -u http://target/FUZZ \
     -t 1  # 单线程提高时间精度
```

**3. 状态码分析**

```bash
# 200: 存在
# 301/302: 重定向（可能存在）
# 401/403: 受保护（存在但需要权限）
# 404: 不存在
# 500: 服务器错误（可能存在）

ffuf -w wordlist.txt -u http://target/FUZZ \
     -mc 200,301,302,401,403,500
```

#### 2.4 漏洞利用方法

##### 2.4.1 备份文件利用

```bash
# 1. 发现备份文件
gobuster dir -u http://target/ -x bak,old,backup

# 2. 下载备份文件
curl -O http://target/config.php.bak

# 3. 分析备份文件
# 查找数据库凭证、API 密钥、业务逻辑
```

##### 2.4.2 Git 目录泄露利用

```bash
# 1. 检测 Git 目录
curl http://target/.git/config

# 2. 下载 Git 数据
git-dumper.py http://target/.git ./dump

# 3. 恢复源码
cd dump
git checkout

# 4. 审计源码
# 查找硬编码凭证、API 密钥、内部逻辑
```

##### 2.4.3 配置文件利用

```bash
# 1. 发现配置文件
gobuster dir -u http://target/ -w config-wordlist.txt

# 2. 下载并分析
curl http://target/.env
curl http://target/config.php

# 3. 提取敏感信息
# 数据库连接字符串
# API 密钥
# 第三方服务凭证
```

##### 2.4.4 API 端点利用

```bash
# 1. 发现 API 端点
gobuster dir -u http://target/ -w api-wordlist.txt

# 2. 枚举 API 资源
curl http://target/api/v1/users
curl http://target/api/v1/admin

# 3. 测试未授权访问
curl http://target/api/v1/users --header "Authorization: Bearer "
```

#### 2.5 枚举绕过方法

##### 2.5.1 WAF 绕过

| 绕过技术 | 描述 | 示例 |
|---------|------|------|
| **速率限制绕过** | 降低请求频率 | `-t 1` 单线程 |
| **User-Agent 绕过** | 修改为浏览器 UA | `-H "User-Agent: Mozilla..."` |
| **IP 轮换** | 使用代理池 | `--proxy` |
| **路径编码** | URL 编码路径 | `/admin` → `/%61%64%6D%69%6E` |

##### 2.5.2 隐藏资源发现

```bash
# 使用模糊匹配
ffuf -w wordlist.txt -u http://target/FUZZ \
     -fw 0  # 过滤响应长度为 0

# 使用通配符
ffuf -w wordlist.txt -u http://target/FUZZ \
     -ac  # 自动校准

# 使用深度扫描
gobuster dir -u http://target/ -r  # 跟随重定向
```

##### 2.5.3 动态路径发现

```bash
# 基于已知路径推断
# 如果发现 /api/v1/users，尝试：
/api/v1/admin
/api/v1/config
/api/v2/users

# 基于参数名推断
# 如果发现 ?user_id=1，尝试：
?admin_id=1
?config_id=1
```

---

## 第三部分：附录

### 3.1 敏感路径字典

**高风险路径：**

```
/admin/
/manager/
/console/
/dashboard/
/wp-admin/
/phpmyadmin/
/.git/
/.env
/.svn/
/backup/
/config/
/debug/
/test/
/api/
/swagger/
```

**常见备份扩展名：**

```
.bak
.backup
.old
.orig
.save
.swp
~
.txt.bak
.zip
.tar.gz
.sql
.db
```

### 3.2 枚举工具

| 工具名称 | 用途 | 特点 |
|---------|------|------|
| **Gobuster** | 目录扫描 | 快速、多模式 |
| **Ffuf** | Fuzz 测试 | 极快、灵活 |
| **Dirsearch** | 目录扫描 | 丰富字典 |
| **Nuclei** | 漏洞扫描 | 模板化 |
| **Git-Dumper** | Git 泄露 | 专用工具 |

### 3.3 最佳实践

- [ ] 使用多个字典组合扫描
- [ ] 调整并发和延迟避免 WAF
- [ ] 关注 301/302/401/403 响应
- [ ] 手动验证自动化发现结果
- [ ] 记录所有发现的路径
- [ ] 对发现的路径进行深度枚举
- [ ] 结合被动和主动枚举方法
