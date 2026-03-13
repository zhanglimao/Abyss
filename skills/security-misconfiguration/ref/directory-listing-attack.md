# 目录列表攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的目录列表漏洞检测与利用流程。

## 1.2 适用范围

本文档适用于所有配置了 Web 服务器且可能开启目录列表功能的应用。

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

目录列表漏洞是指 Web 服务器配置不当，允许用户浏览目录内容，导致敏感文件、备份文件、源代码等被暴露。

**本质问题**：
- Web 服务器开启目录浏览功能
- 缺少默认首页文件（index.html 等）
- 配置错误导致目录内容暴露

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-538 | 文件和目录信息暴露 |
| CWE-200 | 敏感信息暴露 |

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 风险点 | 潜在危害 |
|---------|-------|---------|
| 上传目录 | 用户上传文件目录 | 获取上传的敏感文件 |
| 备份目录 | 数据库/配置备份 | 获取备份数据 |
| 日志目录 | 访问/错误日志 | 获取访问记录和敏感信息 |
| 代码目录 | 源代码文件 | 源码泄露 |
| 管理目录 | 管理后台文件 | 获取管理工具 |

## 2.3 漏洞发现方法

### 2.3.1 目录列表检测

```bash
# 访问可能存在目录列表的路径
curl https://target.com/uploads/
curl https://target.com/backup/
curl https://target.com/logs/

# 检查响应是否包含目录列表
# 常见特征：
# - Index of /path
# - 文件列表链接
# - 文件大小/日期信息
```

### 2.3.2 常见目录列表路径

```
/uploads/
/files/
/backup/
/backups/
/logs/
/log/
/admin/
/config/
/database/
/sql/
/tmp/
/temp/
/archive/
/old/
```

### 2.3.3 自动化检测

```bash
# 使用 Gobuster 扫描
gobuster dir -u https://target.com -w common.txt

# 使用 Dirsearch
dirsearch -u https://target.com -e html,php,txt,sql,bak

# 使用 Nikto
nikto -h https://target.com
```

## 2.4 漏洞利用方法

### 2.4.1 敏感文件下载

```bash
# 下载发现的敏感文件
curl https://target.com/backup/database.sql -o db.sql
curl https://target.com/logs/access.log -o access.log
curl https://target.com/config/config.php -o config.php
```

### 2.4.2 备份文件分析

```bash
# 分析 SQL 备份
# 1. 查看表结构
# 2. 提取用户数据
# 3. 查找管理员凭证

# 分析日志文件
# 1. 了解系统架构
# 2. 发现用户行为模式
# 3. 寻找攻击线索
```

### 2.4.3 源码泄露利用

```bash
# 如果获取到源代码
# 1. 审计代码漏洞
# 2. 查找硬编码凭证
# 3. 了解业务逻辑
```

## 2.5 漏洞利用绕过方法

### 2.5.1 访问控制绕过

```bash
# 如果目录有基本认证
# 尝试默认凭证
# 尝试暴力破解

# 如果 IP 限制
# 尝试 IP 欺骗
# 尝试代理访问
```

### 2.5.2 隐藏文件发现

```bash
# 使用特殊工具扫描隐藏文件
# .htaccess
# .git/
# .svn/
# 配置文件
```

---

# 第三部分：附录

## 3.1 目录列表测试检查清单

```
□ 扫描常见目录路径
□ 检查目录列表响应
□ 下载并分析敏感文件
□ 检查隐藏文件
□ 测试访问控制绕过
□ 记录所有发现
```

## 3.2 修复建议

1. **禁用目录列表** - 配置 Web 服务器 Options -Indexes
2. **添加默认首页** - 创建 index.html 等文件
3. **访问控制** - 限制敏感目录访问
4. **定期审计** - 检查目录配置

---

**参考资源**：
- [OWASP Testing Guide - Directory Enumeration](https://owasp.org/www-project-web-security-testing-guide/)
- [Apache Directory Listing](https://httpd.apache.org/docs/2.4/mod/mod_autoindex.html)
