---
name: injection
description: 注入攻击渗透测试技能，用于检测和利用各类解释器注入漏洞，包括 SQL、NoSQL、OS 命令、LDAP、XSS 等
---

# Injection（注入攻击）渗透测试技能

## 简介

注入攻击（Injection）是 OWASP Top 10:2025 排名第 5 的安全风险。当用户输入被发送到解释器（如数据库、命令行、浏览器）并被误认为是可信命令时，就会发生注入漏洞。

本技能提供系统性的方法论，指导渗透测试人员发现和利用各类注入漏洞，包括 SQL 注入、NoSQL 注入、OS 命令注入、LDAP 注入、XSS、模板注入等攻击技术。

---

## 方法论映射表

### 1. 渗透过程中遇到什么情况该参考哪个方法论

| 遇到的情况 | 参考方法论 | 文件路径 |
|-----------|-----------|----------|
| 输入点返回数据库错误 | SQL 注入检测与利用 | `ref/sql-injection-detection-exploitation.md` |
| 使用 MongoDB 等 NoSQL 数据库 | NoSQL 注入攻击 | `ref/nosql-injection-attack.md` |
| 参数值出现在系统命令中 | OS 命令注入 | `ref/os-command-injection.md` |
| LDAP 查询可被操纵 | LDAP 注入攻击 | `ref/ldap-injection-attack.md` |
| 输入在页面中原样输出 | XSS 跨站脚本攻击 | `ref/xss-attack.md` |
| HTTP 头部值在响应中反射 | XSS 跨站脚本攻击 | `ref/xss-attack.md` |
| 输入参数被反射到 HTML 属性上下文 | XSS 跨站脚本攻击（高级） | `ref/xss-attack-advanced.md` |
| 应用使用 PhantomJS 等渲染引擎 | XSS 跨站脚本攻击（高级） | `ref/xss-attack-advanced.md` `ref/xss-flask-phantomjs-ssrf.md` |
| 存在弱黑名单过滤（仅过滤 script/onerror/onclick/onmouseover/空格/单引号） | XSS 黑名单绕过技术 | `ref/xss-blacklist-bypass-techniques.md` |
| 黑名单过滤`<[a-yA-Y/]+`可使用`<z>`标签绕过 | XSS 黑名单绕过技术 | `ref/xss-blacklist-bypass-techniques.md` `ref/xss-flask-phantomjs-ssrf.md` |
| 黑名单过滤空格可使用 Tab/换行/斜杠绕过 | XSS 黑名单绕过技术 | `ref/xss-blacklist-bypass-techniques.md` |
| 黑名单过滤单引号可使用双引号/反引号绕过 | XSS 黑名单绕过技术 | `ref/xss-blacklist-bypass-techniques.md` |
| HTML 属性上下文未引号包裹（value=USER_INPUT） | XSS 黑名单绕过技术 | `ref/xss-blacklist-bypass-techniques.md` |
| 使用 autofocus+onfocus 自动触发 XSS | XSS 黑名单绕过技术 | `ref/xss-blacklist-bypass-techniques.md` |
| 使用 onmousemove/onanimationstart 绕过 onmouseover 过滤 | XSS 黑名单绕过技术 | `ref/xss-blacklist-bypass-techniques.md` |
| Flask 应用使用 PhantomJS 验证 XSS | Flask+PhantomJS XSS 攻击 | `ref/xss-flask-phantomjs-bypass.md` |
| 黑名单允许特定标签（如`<image>`） | Flask+PhantomJS XSS 攻击 | `ref/xss-flask-phantomjs-bypass.md` |
| 应用移除空格但允许`/`分隔 | Flask+PhantomJS XSS 攻击 | `ref/xss-flask-phantomjs-bypass.md` |
| 使用 autofocus 自动触发事件 | Flask+PhantomJS XSS 攻击 | `ref/xss-flask-phantomjs-bypass.md` |
| PhantomJS 拦截 alert/confirm/prompt | Flask+PhantomJS XSS 攻击 | `ref/xss-flask-phantomjs-bypass.md` |
| XSS 验证成功返回 Flag/敏感信息 | Flask+PhantomJS XSS 攻击 | `ref/xss-flask-phantomjs-bypass.md` |
| CTF 挑战应用存在 XSS 漏洞 | Flask+PhantomJS XSS 攻击 | `ref/xss-flask-phantomjs-bypass.md` |
| 无认证 Flask 应用 XSS 利用 | Flask+PhantomJS XSS 攻击 | `ref/xss-flask-phantomjs-bypass.md` |
| HTML 属性上下文 XSS 注入（value 属性逃逸） | XSS 跨站脚本攻击（高级） | `ref/xss-attack-advanced.md` |
| 双引号未过滤导致属性逃逸 | XSS 跨站脚本攻击（高级） | `ref/xss-attack-advanced.md` |
| 事件处理器注入绕过标签过滤（onfocus/onclick） | XSS 跨站脚本攻击（高级） | `ref/xss-attack-advanced.md` |
| 反引号绕过引号过滤（\`XSS\`） | XSS 跨站脚本攻击（高级） | `ref/xss-attack-advanced.md` |
| 弱正则过滤可绕过（仅过滤`<[a-z/]`和`"XSS"`） | XSS 跨站脚本攻击（高级） | `ref/xss-attack-advanced.md` |
| 输入被反射到 JavaScript 字符串上下文 | XSS 跨站脚本攻击 | `ref/xss-attack.md` |
| 黑名单过滤字母数字字符 | XSS 黑名单绕过 | `ref/sql-injection-blacklist-bypass.md` |
| 使用 autofocus 事件绕过标签过滤 | XSS 跨站脚本攻击 | `ref/xss-attack.md` |
| 无认证系统存在 XSS 漏洞 | XSS 跨站脚本攻击 | `ref/xss-attack.md` |
| 临时文件存在 Race Condition | XSS 跨站脚本攻击 | `ref/xss-attack.md` |
| 使用模板引擎 (Jinja2/Freemarker/Django) | 模板注入攻击 | `ref/template-injection.md` |
| Django 应用模板字符串拼接 | Django SSTI+XSS 组合攻击 | `ref/django-ssti-xss-combo.md` |
| 存在 SSTI 且可访问模板上下文 | Django SSTI+XSS 组合攻击 | `ref/django-ssti-xss-combo.md` |
| 用户可控 URL 发起请求 | SSRF 服务器端请求伪造 | `ref/ssrf-attack-advanced.md` `ref/ssrf-attack-unvalidated-url.md` |
| 应用加载外部资源 | SSRF 服务器端请求伪造 | `ref/ssrf-attack-advanced.md` `ref/ssrf-attack-unvalidated-url.md` |
| 云环境元数据服务可访问 | SSRF 服务器端请求伪造 | `ref/ssrf-attack-advanced.md` `ref/ssrf-attack-unvalidated-url.md` |
| PHP 应用使用 file_get_contents 处理用户 URL | SSRF 未验证 URL 攻击 | `ref/ssrf-attack-unvalidated-url.md` |
| Python 应用使用 requests.get 处理用户 URL | SSRF 未验证 URL 攻击 | `ref/ssrf-attack-unvalidated-url.md` |
| Docker 环境内部服务可通过 SSRF 访问 | SSRF 未验证 URL 攻击 | `ref/ssrf-attack-unvalidated-url.md` |
| 无认证系统存在 SSRF 端点 | SSRF 未验证 URL 攻击 | `ref/ssrf-attack-unvalidated-url.md` |
| 使用模板引擎 (Jinja2/Freemarker) | 模板注入攻击 | `ref/template-injection.md` |
| XML 解析存在漏洞 | XML/XPath 注入 | `ref/xml-xpath-injection.md` |
| ORM 查询可被操纵 | ORM 注入攻击 | `ref/orm-injection.md` |
| 表达式语言可被注入 | EL/OGNL 注入 | `ref/el-ognl-injection.md` |
| 文件路径参数可控 | 路径遍历/文件包含 | `ref/path-traversal-injection.md` |
| 静态文件服务存在路径遍历 | 路径遍历攻击 | `ref/path-traversal-attack.md` |
| Flask send_from_directory 无验证 | 路径遍历攻击 | `ref/path-traversal-attack.md` |
| Apache FilesMatch 可被 Flask 端点绕过 | 路径遍历攻击 | `ref/path-traversal-attack.md` |
| 目录列表启用泄露文件结构 | 路径遍历攻击 | `ref/path-traversal-attack.md` |
| 无认证系统路径遍历利用 | 路径遍历攻击 | `ref/path-traversal-attack.md` |
| SQL 关键词被过滤但仍可注入 | SQL 注入黑名单绕过 | `ref/sql-injection-blacklist-bypass.md` |
| 数据库内容在前端渲染 | 存储型 XSS 通过 SQL 注入链 | `ref/stored-xss-via-sql-injection.md` |
| 联合查询注入提取数据 | SQL 注入检测与利用 | `ref/sql-injection-detection-exploitation.md` |
| 布尔/时间盲注 | 盲注技术指南 | `ref/blind-injection-techniques.md` |
| CTF 挑战应用存在 XSS | Flask+PhantomJS XSS 攻击 | `ref/xss-flask-phantomjs-bypass.md` |
| XSS Payload 外带 Flag/敏感数据 | XSS 跨站脚本攻击 | `ref/xss-attack.md` |
| 无认证 Flask 应用 XSS 利用 | Flask+PhantomJS XSS 攻击 | `ref/xss-flask-phantomjs-bypass.md` |
| HTML 属性上下文 XSS 注入（value 属性逃逸） | XSS 跨站脚本攻击（高级） | `ref/xss-attack-advanced.md` |
| 双引号未过滤导致属性逃逸 | XSS 跨站脚本攻击（高级） | `ref/xss-attack-advanced.md` |
| 事件处理器注入绕过标签过滤（onfocus/onclick） | XSS 跨站脚本攻击（高级） | `ref/xss-attack-advanced.md` |
| 反引号绕过引号过滤（`XSS`） | XSS 跨站脚本攻击（高级） | `ref/xss-attack-advanced.md` |
| 弱正则过滤可绕过（仅过滤 `<[a-z/]` 和`"XSS"`） | XSS 跨站脚本攻击（高级） | `ref/xss-attack-advanced.md` |
| 黑名单允许 `<style>` 标签 | XSS 跨站脚本攻击（高级） | `ref/xss-attack-advanced.md` |
| 正则负向前瞻过滤 (`<(?!style\b)`) | XSS 跨站脚本攻击（高级） | `ref/xss-attack-advanced.md` |
| 自闭合标签语法绕过 (`<style/onload=...>`) | XSS 跨站脚本攻击（高级） | `ref/xss-attack-advanced.md` |
| CSS expression() 注入（旧 WebKit/PhantomJS） | XSS 跨站脚本攻击（高级） | `ref/xss-attack-advanced.md` |
| CSS url()+javascript: 协议注入 | XSS 跨站脚本攻击（高级） | `ref/xss-attack-advanced.md` |
| CSS @import javascript: 注入 | XSS 跨站脚本攻击（高级） | `ref/xss-attack-advanced.md` |
| 无 CSP 头可执行内联脚本 | XSS 跨站脚本攻击 | `ref/xss-attack.md` |
| autofocus 属性自动触发事件处理器 | XSS 跨站脚本攻击（高级） | `ref/xss-attack-advanced.md` |
| HTML 属性上下文未过滤（value/src/href） | XSS 跨站脚本攻击（高级） | `ref/xss-attack-advanced.md` |
| 双引号未转义导致属性逃逸 | XSS 跨站脚本攻击（高级） | `ref/xss-attack-advanced.md` |
| 事件处理器注入绕过标签过滤 | XSS 跨站脚本攻击（高级） | `ref/xss-attack-advanced.md` |
| 双引号未过滤导致属性逃逸 | HTML 属性上下文 XSS 注入 | `ref/xss-html-attribute-injection.md` |
| 输入反射到 HTML 属性 value/src/href | HTML 属性上下文 XSS 注入 | `ref/xss-html-attribute-injection.md` |
| 使用 autofocus+onfocus 自动触发 | HTML 属性上下文 XSS 注入 | `ref/xss-html-attribute-injection.md` `ref/xss-html-attribute-injection-advanced.md` |
| 事件处理器注入（onfocus/onclick/onerror） | HTML 属性上下文 XSS 注入 | `ref/xss-html-attribute-injection.md` `ref/xss-html-attribute-injection-advanced.md` |
| 标签注入（`<img>`/`<svg>`）绕过标签过滤 | HTML 属性上下文 XSS 注入 | `ref/xss-html-attribute-injection.md` `ref/xss-html-attribute-injection-advanced.md` |
| 弱正则过滤仅移除 `"XSS"`/`'XSS'` | HTML 属性上下文 XSS 注入 | `ref/xss-html-attribute-injection.md` `ref/xss-html-attribute-injection-advanced.md` |
| Python `.format()` 生成 HTML 无编码 | HTML 属性上下文 XSS 注入 | `ref/xss-html-attribute-injection.md` `ref/xss-html-attribute-injection-advanced.md` |
| Flask 应用 HTML 属性反射用户输入 | HTML 属性上下文 XSS 注入 | `ref/xss-html-attribute-injection.md` `ref/xss-html-attribute-injection-advanced.md` |
| CTF 挑战 HTML 属性 XSS | HTML 属性上下文 XSS 注入 | `ref/xss-html-attribute-injection.md` `ref/xss-html-attribute-injection-advanced.md` |
| 无引号属性上下文逃逸（value=USER_INPUT） | HTML 属性上下文 XSS 注入（高级） | `ref/xss-html-attribute-injection-advanced.md` |
| 双引号属性上下文逃逸（value="USER_INPUT"） | HTML 属性上下文 XSS 注入（高级） | `ref/xss-html-attribute-injection-advanced.md` |
| 单引号属性上下文逃逸（value='USER_INPUT'） | HTML 属性上下文 XSS 注入（高级） | `ref/xss-html-attribute-injection-advanced.md` |
| 应用使用 PhantomJS 渲染 HTML | SSRF via PhantomJS 攻击 | `ref/ssrf-phantomjs-attack.md` `ref/xss-flask-phantomjs-ssrf.md` |
| 头less 浏览器加载用户可控 HTML | SSRF via PhantomJS 攻击 | `ref/ssrf-phantomjs-attack.md` `ref/xss-flask-phantomjs-ssrf.md` |
| PhantomJS 执行用户注入的 JavaScript | SSRF via PhantomJS 攻击 | `ref/ssrf-phantomjs-attack.md` `ref/xss-flask-phantomjs-ssrf.md` |
| 访问 localhost/内网服务 | SSRF via PhantomJS 攻击 | `ref/ssrf-phantomjs-attack.md` `ref/xss-flask-phantomjs-ssrf.md` |
| 访问云元数据服务（169.254.169.254） | SSRF via PhantomJS 攻击 | `ref/ssrf-phantomjs-attack.md` `ref/xss-flask-phantomjs-ssrf.md` |
| 内网端口扫描 | SSRF via PhantomJS 攻击 | `ref/ssrf-phantomjs-attack.md` `ref/xss-flask-phantomjs-ssrf.md` |
| 使用 fetch/XMLHttpRequest 发起 SSRF 请求 | SSRF via PhantomJS 攻击 | `ref/ssrf-phantomjs-attack.md` `ref/xss-flask-phantomjs-ssrf.md` |
| 通过 alert() 回调 exfiltrate 数据 | SSRF via PhantomJS 攻击 | `ref/ssrf-phantomjs-attack.md` `ref/xss-flask-phantomjs-ssrf.md` |
| CTF 挑战 PhantomJS XSS 验证 | SSRF via PhantomJS 攻击 | `ref/ssrf-phantomjs-attack.md` `ref/xss-flask-phantomjs-ssrf.md` |

### 2. 遇到什么样的业务系统、软件环境、基础设施该参考哪个方法论

| 系统/环境特征 | 参考方法论 | 文件路径 |
|--------------|-----------|----------|
| 关系型数据库 (MySQL/PostgreSQL/Oracle) | SQL 注入测试 | `ref/sql-injection-testing.md` |
| NoSQL 数据库 (MongoDB/Redis/CouchDB) | NoSQL 注入测试 | `ref/nosql-injection-testing.md` |
| Java 应用 (Spring/Hibernate) | Java 注入测试 | `ref/java-injection-testing.md` |
| .NET 应用 | .NET 注入测试 | `ref/dotnet-injection-testing.md` |
| PHP 应用 | PHP 注入测试 | `ref/php-injection-testing.md` |
| Python 应用 (Django/Flask) | Python 注入测试 | `ref/python-injection-testing.md` |
| Node.js 应用 | Node.js 注入测试 | `ref/nodejs-injection-testing.md` |
| GraphQL API | GraphQL 注入测试 | `ref/graphql-injection-testing.md` |
| SOAP Web Service | SOAP 注入测试 | `ref/soap-injection-testing.md` |

### 3. 遇到什么样的问题该参考哪个方法论

| 问题类型 | 参考方法论 | 文件路径 |
|---------|-----------|----------|
| 如何系统化检测注入点 | 注入点检测框架 | `ref/injection-point-detection.md` |
| 如何绕过 WAF 过滤 | WAF 绕过技术 | `ref/waf-injection-bypass.md` |
| 如何进行盲注攻击 | 盲注技术指南 | `ref/blind-injection-techniques.md` |
| 如何提取数据库内容 | 数据提取技术 | `ref/data-extraction-techniques.md` |
| 如何建立反向 Shell | 命令注入后利用 | `ref/command-injection-post-exploitation.md` |
| 如何检测二阶注入 | 二阶注入检测 | `ref/second-order-injection.md` |
| 如何进行带外注入 | OOB 注入技术 | `ref/oob-injection-techniques.md` |
| 如何 fuzzing 测试注入 | 注入 Fuzzing 指南 | `ref/injection-fuzzing-guide.md` |

### 4. 渗透测试决策流程图

```
                                    ┌─────────────────┐
                                    │   注入漏洞测试   │
                                    └────────┬────────┘
                                             │
                                             ▼
                                    ┌─────────────────┐
                                    │   输入点识别     │
                                    │  - 参数收集      │
                                    │  - 请求头分析    │
                                    │  - Cookie 分析   │
                                    └────────┬────────┘
                                             │
                    ┌────────────────────────┼────────────────────────┐
                    │                        │                        │
                    ▼                        ▼                        ▼
          ┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
          │  数据库交互点    │      │  命令执行点     │      │   页面输出点    │
          └────────┬────────┘      └────────┬────────┘      └────────┬────────┘
                   │                        │                        │
                   ▼                        ▼                        ▼
          ┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
          │  ref/sql-       │      │  ref/os-        │      │  ref/xss-       │
          │  injection-     │      │  command-       │      │  attack.md      │
          │  detection.md   │      │  injection.md   │      │                 │
          └─────────────────┘      └─────────────────┘      └─────────────────┘
```

### 5. 攻击技术思维导图

```
注入攻击技术
├── SQL 注入
│   ├── 联合查询注入 (Union-based)
│   ├── 错误回显注入 (Error-based)
│   ├── 布尔盲注 (Boolean Blind)
│   ├── 时间盲注 (Time-based Blind)
│   ├── 堆叠查询 (Stacked Queries)
│   └── 二阶注入 (Second-order)
├── NoSQL 注入
│   ├── MongoDB 注入
│   ├── 运算符注入
│   └── JavaScript 注入
├── OS 命令注入
│   ├── 命令拼接
│   ├── 命令分隔符利用
│   ├── 反向 Shell
│   └── 无回显利用 (DNSLog)
├── XSS 跨站脚本
│   ├── 反射型 XSS
│   ├── 存储型 XSS
│   ├── DOM 型 XSS
│   └── 变异型 XSS
├── 模板注入
│   ├── SSTI (Jinja2)
│   ├── Freemarker 注入
│   └── EL 表达式注入
├── 其他注入
│   ├── LDAP 注入
│   ├── XML/XPath 注入
│   ├── ORM 注入
│   ├── CRLF 注入
│   └── 路径遍历
└── 高级技术
    ├── WAF 绕过
    ├── 编码绕过
    ├── 分块传输
    └── 多态 Payload
```

### 6. 方法论引用清单

| 编号 | 方法论名称 | 引用文件 | 适用阶段 |
|-----|-----------|---------|---------|
| INJ-001 | SQL 注入检测与利用 | `ref/sql-injection-detection-exploitation.md` | 漏洞发现/利用 |
| INJ-002 | NoSQL 注入攻击 | `ref/nosql-injection-attack.md` | 漏洞利用 |
| INJ-003 | OS 命令注入 | `ref/os-command-injection.md` | 漏洞利用 |
| INJ-004 | LDAP 注入攻击 | `ref/ldap-injection-attack.md` | 漏洞利用 |
| INJ-005 | XSS 跨站脚本攻击 | `ref/xss-attack.md` | 漏洞利用 |
| INJ-006 | XSS 跨站脚本攻击（高级） | `ref/xss-attack-advanced.md` | 漏洞利用 |
| INJ-007 | SSRF 服务器端请求伪造 | `ref/ssrf-attack-advanced.md` | 漏洞利用 |
| INJ-008 | 模板注入攻击 | `ref/template-injection.md` | 漏洞利用 |
| INJ-009 | XML/XPath 注入 | `ref/xml-xpath-injection.md` | 漏洞利用 |
| INJ-010 | ORM 注入攻击 | `ref/orm-injection.md` | 漏洞利用 |
| INJ-011 | EL/OGNL 注入 | `ref/el-ognl-injection.md` | 漏洞利用 |
| INJ-012 | 路径遍历/文件包含 | `ref/path-traversal-injection.md` | 漏洞利用 |
| INJ-013 | SQL 注入测试 | `ref/sql-injection-testing.md` | 系统化测试 |
| INJ-014 | NoSQL 注入测试 | `ref/nosql-injection-testing.md` | 系统化测试 |
| INJ-015 | Java 注入测试 | `ref/java-injection-testing.md` | 系统化测试 |
| INJ-016 | .NET 注入测试 | `ref/dotnet-injection-testing.md` | 系统化测试 |
| INJ-017 | PHP 注入测试 | `ref/php-injection-testing.md` | 系统化测试 |
| INJ-018 | Python 注入测试 | `ref/python-injection-testing.md` | 系统化测试 |
| INJ-019 | Node.js 注入测试 | `ref/nodejs-injection-testing.md` | 系统化测试 |
| INJ-020 | GraphQL 注入测试 | `ref/graphql-injection-testing.md` | 系统化测试 |
| INJ-021 | SOAP 注入测试 | `ref/soap-injection-testing.md` | 系统化测试 |
| INJ-022 | 注入点检测框架 | `ref/injection-point-detection.md` | 测试规划 |
| INJ-023 | WAF 绕过技术 | `ref/waf-injection-bypass.md` | 漏洞利用 |
| INJ-024 | 盲注技术指南 | `ref/blind-injection-techniques.md` | 漏洞利用 |
| INJ-025 | 数据提取技术 | `ref/data-extraction-techniques.md` | 漏洞利用 |
| INJ-026 | 命令注入后利用 | `ref/command-injection-post-exploitation.md` | 漏洞利用 |
| INJ-027 | 二阶注入检测 | `ref/second-order-injection.md` | 漏洞发现 |
| INJ-028 | OOB 注入技术 | `ref/oob-injection-techniques.md` | 漏洞利用 |
| INJ-029 | 注入 Fuzzing 指南 | `ref/injection-fuzzing-guide.md` | 漏洞发现 |
| INJ-030 | SQL 注入黑名单绕过 | `ref/sql-injection-blacklist-bypass.md` | 漏洞利用 |
| INJ-031 | 存储型 XSS 通过 SQL 注入链 | `ref/stored-xss-via-sql-injection.md` | 漏洞利用 |
| INJ-032 | Django SSTI+XSS 组合攻击 | `ref/django-ssti-xss-combo.md` | 漏洞利用 |
| INJ-033 | Flask+PhantomJS XSS 攻击 | `ref/xss-flask-phantomjs-bypass.md` | 漏洞利用 |
| INJ-034 | XSS 黑名单绕过技术 | `ref/xss-blacklist-bypass-techniques.md` | 漏洞利用 |
| INJ-035 | HTML 属性上下文 XSS 注入 | `ref/xss-html-attribute-injection.md` | 漏洞利用 |
| INJ-036 | SSRF via PhantomJS 攻击 | `ref/ssrf-phantomjs-attack.md` | 漏洞利用 |
| INJ-037 | Flask+PhantomJS XSS 与 SSRF 组合攻击 | `ref/xss-flask-phantomjs-ssrf.md` | 漏洞利用 |
| INJ-038 | HTML 属性上下文 XSS 注入（高级） | `ref/xss-html-attribute-injection-advanced.md` | 漏洞利用 |
| INJ-039 | 路径遍历攻击 | `ref/path-traversal-attack.md` | 漏洞利用 |
| INJ-040 | SSRF via PhantomJS 攻击（高级） | `ref/ssrf-phantomjs-attack.md` | 漏洞利用 |
| INJ-041 | SSRF 未验证 URL 攻击 | `ref/ssrf-attack-unvalidated-url.md` | 漏洞发现/利用 |

---

## 使用指南

### 快速开始

1. **输入点识别** - 收集所有用户可控的输入点
2. **初步探测** - 使用简单 Payload 测试注入可能性
3. **类型判断** - 确定注入类型（SQL/命令/XSS 等）
4. **深入利用** - 根据注入类型选择相应的利用方法

### 技能关联

- 与 `pt-broken-access-control` 技能配合，利用注入获取更高权限
- 与 `pt-cryptographic-failures` 技能配合，利用注入窃取敏感数据
- 与 `pt-security-misconfiguration` 技能配合，利用配置错误增强注入效果

---

## 参考资源

- [OWASP Top 10:2025 A05](https://owasp.org/Top10/2025/A05_2025-Injection/)
- [OWASP Cheat Sheet: Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)
- [PortSwigger - Web Security Academy](https://portswigger.net/web-security)
- [SQLMap Project](https://sqlmap.org/)
