# 敏感目录枚举方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的敏感目录和文件枚举检测流程。

## 1.2 适用范围

本文档适用于所有 Web 应用，用于发现隐藏的敏感目录和文件。

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

敏感目录枚举是指通过系统化地请求可能的路径，发现并访问那些本应隐藏但实际可访问的敏感目录和文件。

**本质问题**：
- 依赖隐蔽式安全
- 缺少访问控制
- 敏感资源未正确保护

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-538 | 文件和目录信息暴露 |
| CWE-200 | 敏感信息暴露 |
| CWE-425 | 直接请求 |

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 风险资源 | 潜在危害 |
|---------|---------|---------|
| 版本控制 | /.git, /.svn | 源码泄露 |
| 备份文件 | *.bak, *.old | 配置/源码泄露 |
| 配置文件 | /.env, /config | 敏感配置泄露 |
| 日志文件 | /logs, *.log | 访问记录泄露 |
| 管理后台 | /admin, /manage | 管理权限获取 |

## 2.3 漏洞发现方法

### 2.3.1 自动化工具扫描

```bash
# Gobuster
gobuster dir -u https://target.com \
    -w /usr/share/wordlists/dirb/common.txt \
    -x php,txt,html,bak

# FFUF
ffuf -w wordlist.txt -u https://target.com/FUZZ \
    -e .bak,.old,.sql,.txt

# Dirsearch
dirsearch -u https://target.com \
    -e php,html,js \
    --exclude-extensions gif,jpg,png
```

### 2.3.2 常见敏感路径

```
# 版本控制
/.git/
/.git/config
/.svn/
/.hg/

# 配置文件
/.env
/.env.local
/config.php
/web.config
/application.yml

# 备份文件
/backup.sql
/database.bak
/config.php.old
/site.tar.gz

# 日志文件
/logs/
/access.log
/error.log

# 管理路径
/admin/
/manager/
/phpmyadmin/
```

### 2.3.3 响应分析

| 状态码 | 含义 | 后续操作 |
|-------|------|---------|
| 200 | 资源存在 | 下载分析内容 |
| 301/302 | 重定向 | 跟踪重定向目标 |
| 401/403 | 需要认证 | 尝试绕过 |
| 404 | 不存在 | 继续扫描 |
| 500 | 服务器错误 | 可能存在漏洞 |

## 2.4 漏洞利用方法

### 2.4.1 Git 源码恢复

```bash
# 使用 GitHack 恢复源码
git clone https://github.com/lijiejie/GitHack
python GitHack.py https://target.com/.git/

# 恢复后审计：
# 1. 搜索硬编码凭证
# 2. 查找安全漏洞
# 3. 了解系统架构
```

### 2.4.2 配置文件分析

```bash
# 下载并分析配置文件
curl https://target.com/.env

# 可能包含：
# - 数据库凭证
# - API 密钥
# - 第三方服务密钥
# - 加密密钥
```

### 2.4.3 备份文件利用

```bash
# 下载备份文件
curl https://target.com/backup.sql -o backup.sql

# 分析 SQL 备份：
# 1. 查看表结构
# 2. 提取用户数据
# 3. 查找敏感信息
```

## 2.5 漏洞利用绕过方法

### 2.5.1 WAF 绕过

```bash
# URL 编码
/.git → /%2egit

# 使用特殊字符
/.git/
/.git/.
/.git/..;/
```

### 2.5.2 路径变形

```bash
# 使用双斜杠
//.git//config

# 使用点号
/.git/.
/.git/..

# 使用大小写（Windows）
/.GIT/
/.Git/
```

---

# 第三部分：附录

## 3.1 敏感目录测试检查清单

```
□ 扫描常见敏感路径
□ 测试版本控制目录
□ 测试备份文件
□ 测试配置文件
□ 测试日志文件
□ 测试管理后台
□ 分析发现的资源
```

## 3.2 常用工具

| 工具 | 用途 | 链接 |
|-----|------|------|
| Gobuster | 目录扫描 | https://github.com/OJ/gobuster |
| FFUF | 快速扫描 | https://github.com/ffuf/ffuf |
| Dirsearch | 目录扫描 | https://github.com/maurosoria/dirsearch |
| GitHack | Git 源码恢复 | https://github.com/lijiejie/GitHack |

## 3.3 修复建议

1. **删除敏感资源** - 移除备份文件、版本控制目录
2. **实施访问控制** - 限制敏感路径访问
3. **禁用目录列表** - 配置 Web 服务器
4. **使用 WAF** - 检测扫描行为

---

**参考资源**：
- [OWASP Testing Guide - Directory Enumeration](https://owasp.org/www-project-web-security-testing-guide/)
- [PayloadsAllTheThings - Directory Traversal](https://github.com/swisskyrepo/PayloadsAllTheThings)
