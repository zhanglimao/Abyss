# 安全头检测方法论

---

## 第一部分：文档概述

### 1.1 编写目的
为渗透测试人员提供针对 HTTP 安全响应头配置检测的方法论。安全响应头是增强 Web 应用安全的重要防线。

### 1.2 适用范围
- 所有 Web 应用
- API 服务
- CDN 配置
- 反向代理配置

### 1.3 读者对象
- 渗透测试工程师
- Web 安全分析师
- 应用安全审计人员

---

## 第二部分：核心检测技术专题

### 专题：安全头检测

#### 2.1 技术介绍

HTTP 安全响应头是服务器发送给浏览器的额外指令，用于增强安全性。缺失或配置不当的安全头可能导致点击劫持、XSS、MIME 嗅探等攻击。

**核心安全头：**

| 响应头 | 作用 | 风险等级 |
|-------|------|---------|
| **Strict-Transport-Security (HSTS)** | 强制 HTTPS | 高 |
| **Content-Security-Policy (CSP)** | 限制资源加载 | 高 |
| **X-Frame-Options** | 防止点击劫持 | 中 |
| **X-Content-Type-Options** | 防止 MIME 嗅探 | 中 |
| **X-XSS-Protection** | XSS 过滤器 | 低 |
| **Referrer-Policy** | 控制 Referrer 信息 | 低 |
| **Permissions-Policy** | 限制浏览器功能 | 中 |
| **Cache-Control** | 控制缓存行为 | 中 |

#### 2.2 检测方法

##### 2.2.1 手动检测

```bash
# 1. 获取响应头
curl -I https://target.com

# 2. 检查安全头
# 查找以下头：
# Strict-Transport-Security: max-age=31536000; includeSubDomains
# Content-Security-Policy: default-src 'self'
# X-Frame-Options: DENY 或 SAMEORIGIN
# X-Content-Type-Options: nosniff
# X-XSS-Protection: 1; mode=block
# Referrer-Policy: strict-origin-when-cross-origin
# Permissions-Policy: geolocation=(), microphone=()
```

##### 2.2.2 自动化检测

```bash
# 1. 使用 Nuclei
nuclei -t http/exposures/headers -u https://target.com
nuclei -t misconfiguration -u https://target.com

# 2. 使用 OWASP ZAP
# 内置安全头扫描规则

# 3. 使用 securityheaders.com
# 在线检测工具

# 4. 使用 Mozilla Observatory
# https://observatory.mozilla.org/
```

##### 2.2.3 检测脚本

```python
#!/usr/bin/env python3
import requests
import sys

def check_security_headers(url):
    try:
        response = requests.get(url, timeout=10)
        headers = response.headers

        security_headers = {
            'Strict-Transport-Security': False,
            'Content-Security-Policy': False,
            'X-Frame-Options': False,
            'X-Content-Type-Options': False,
            'X-XSS-Protection': False,
            'Referrer-Policy': False,
            'Permissions-Policy': False,
        }

        for header in security_headers:
            if header in headers:
                security_headers[header] = True
                print(f"[+] {header}: {headers[header]}")
            else:
                print(f"[-] Missing: {header}")

        # 风险评估
        missing = sum(1 for v in security_headers.values() if not v)
        if missing >= 5:
            print("\n[!] 高风险：缺少多个安全头")
        elif missing >= 3:
            print("\n[!] 中风险：缺少部分安全头")
        else:
            print("\n[+] 低风险：安全头配置良好")

    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        check_security_headers(sys.argv[1])
    else:
        print("Usage: python check_headers.py <url>")
```

#### 2.3 各安全头详解

##### 2.3.1 Strict-Transport-Security (HSTS)

**作用：** 强制浏览器使用 HTTPS 访问

**安全配置：**
```http
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

**检测要点：**
- `max-age` 应 ≥ 31536000（1 年）
- 应包含 `includeSubDomains`
- 可提交到 HSTS Preload List

**风险：**
- 缺失：可被 SSL 剥离攻击
- max-age 过短：保护时间不足

##### 2.3.2 Content-Security-Policy (CSP)

**作用：** 限制页面可加载的资源来源

**安全配置：**
```http
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'
```

**检测要点：**
- 避免 `unsafe-inline` 和 `unsafe-eval`
- 避免通配符 `*`
- 限制 `script-src`、`style-src`、`img-src` 等

**风险：**
- 缺失：XSS 攻击风险增加
- 配置宽松：CSP 绕过

##### 2.3.3 X-Frame-Options

**作用：** 防止页面被嵌入 iframe（点击劫持）

**安全配置：**
```http
X-Frame-Options: DENY
# 或
X-Frame-Options: SAMEORIGIN
```

**检测要点：**
- `DENY`：完全禁止嵌入
- `SAMEORIGIN`：仅允许同源嵌入
- `ALLOW-FROM uri`：已废弃

**风险：**
- 缺失：点击劫持攻击

##### 2.3.4 X-Content-Type-Options

**作用：** 防止浏览器 MIME 类型嗅探

**安全配置：**
```http
X-Content-Type-Options: nosniff
```

**检测要点：**
- 唯一有效值：`nosniff`

**风险：**
- 缺失：MIME 嗅探攻击

##### 2.3.5 X-XSS-Protection

**作用：** 启用浏览器内置 XSS 过滤器

**安全配置：**
```http
X-XSS-Protection: 1; mode=block
```

**检测要点：**
- `1`：启用过滤器
- `1; mode=block`：阻止页面渲染
- `0`：禁用过滤器

**注意：** 现代浏览器已弃用，建议依赖 CSP

##### 2.3.6 Referrer-Policy

**作用：** 控制 Referrer 头发送的信息

**安全配置：**
```http
Referrer-Policy: strict-origin-when-cross-origin
# 或更严格
Referrer-Policy: no-referrer
```

**可选值：**
- `no-referrer`：不发送 Referrer
- `no-referrer-when-downgrade`：默认行为
- `origin`：仅发送来源
- `origin-when-cross-origin`：跨域仅发送来源
- `strict-origin-when-cross-origin`：推荐
- `unsafe-url`：总是发送完整 URL

##### 2.3.7 Permissions-Policy

**作用：** 限制浏览器功能使用

**安全配置：**
```http
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

**可限制功能：**
- `geolocation`：地理位置
- `microphone`：麦克风
- `camera`：摄像头
- `payment`：支付 API
- `usb`：USB 访问

#### 2.4 漏洞利用方法

##### 2.4.1 点击劫持（X-Frame-Options 缺失）

```html
<!-- 攻击页面 -->
<!DOCTYPE html>
<html>
<head>
    <title>Click to Win!</title>
    <style>
        iframe {
            opacity: 0;
            position: absolute;
            top: 100px;
            left: 100px;
        }
        .clickbait {
            position: absolute;
            top: 100px;
            left: 100px;
        }
    </style>
</head>
<body>
    <div class="clickbait">
        <button>点击领取奖品!</button>
    </div>
    <iframe src="https://target.com/transfer"></iframe>
</body>
</html>
```

##### 2.4.2 MIME 嗅探攻击（X-Content-Type-Options 缺失）

```html
<!-- 上传包含 XSS 的 txt 文件 -->
<!-- 文件内容：<script>alert(1)</script> -->
<!-- Content-Type: text/plain -->

<!-- 如果浏览器嗅探为 HTML -->
<!-- XSS 将执行 -->
```

##### 2.4.3 协议降级（HSTS 缺失）

```bash
# 使用 sslstrip 降级
sslstrip -l 8080

# 用户访问 https://target.com
# 被降级为 http://target.com
# 攻击者可以窃听流量
```

##### 2.4.4 CSP 绕过导致 XSS

```html
<!-- 如果 CSP 缺失或配置宽松 -->
<script>alert(document.cookie)</script>

<!-- 如果 CSP 允许 unsafe-inline -->
<img src=x onerror=alert(1)>

<!-- 如果 CSP 配置 data: -->
<script src="data:text/javascript,alert(1)"></script>
```

---

## 第三部分：附录

### 3.1 检测工具

| 工具名称 | 用途 | 命令示例 |
|---------|------|---------|
| **curl** | 手动检查 | `curl -I target` |
| **Nuclei** | 自动化扫描 | `nuclei -t headers -u target` |
| **OWASP ZAP** | 综合扫描 | 内置安全头检查 |
| **securityheaders.com** | 在线检测 | Web 界面 |
| **Mozilla Observatory** | 综合评估 | Web 界面 |

### 3.2 安全配置示例

**Nginx 配置：**
```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header Content-Security-Policy "default-src 'self'" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
```

**Apache 配置：**
```apache
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
Header always set Content-Security-Policy "default-src 'self'"
Header always set X-Frame-Options "DENY"
Header always set X-Content-Type-Options "nosniff"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
```

### 3.3 修复建议

1. **配置所有安全头** - 根据应用需求配置
2. **使用合适值** - 如 X-Frame-Options 设为 DENY
3. **测试配置** - 确保安全头正常工作
4. **定期审查** - 跟进最新安全头标准

---

**参考资源：**
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers-project/)
- [MDN HTTP Headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers)
- [securityheaders.com](https://securityheaders.com/)
