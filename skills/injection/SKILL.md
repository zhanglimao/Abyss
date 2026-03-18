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
| 输入验证在 SQL 查询之后执行（TOCTOU 模式） | TOCTOU SQL 注入（错误基于） | `ref/toctou-sqli-error-based-exploitation.md` |
| 变量名暗示未转义（如$unescaped_xxx） | TOCTOU SQL 注入（错误基于） | `ref/toctou-sqli-error-based-exploitation.md` |
| mysqli_real_escape_string 在 query 之后调用 | TOCTOU SQL 注入（错误基于） | `ref/toctou-sqli-error-based-exploitation.md` |
| 错误回显包含 XPATH syntax error | TOCTOU SQL 注入（错误基于） | `ref/toctou-sqli-error-based-exploitation.md` |
| 使用 MongoDB 等 NoSQL 数据库 | NoSQL 注入攻击 | `ref/nosql-injection-attack.md` |
| GraphQL API 参数可控制数据库查询 | GraphQL SQL 注入攻击 | `ref/graphql-sqli-attack.md` |
| GraphQL 查询返回数据库内容 | GraphQL SQL 注入攻击 | `ref/graphql-sqli-attack.md` |
| GraphQL 参数绕过授权检查访问私有数据 | GraphQL SQL 注入攻击 | `ref/graphql-sqli-attack.md` |
| GraphQL 内省查询可获取 schema | GraphQL SQL 注入攻击 | `ref/graphql-sqli-attack.md` |
| 参数值出现在系统命令中 | OS 命令注入 | `ref/os-command-injection.md` |
| 命令参数未加引号/使用空格分隔 | 参数注入 (Argument Injection) | `ref/os-command-injection.md` |
| Git/SSH/rsync/curl 命令使用用户输入 | 参数注入 (Argument Injection) | `ref/os-command-injection.md` |
| 无认证系统存在命令注入漏洞 | 无认证系统命令注入利用 | `ref/no-auth-command-injection-exploitation.md` |
| 完全无认证架构 + 命令执行端点 | 无认证系统命令注入利用 | `ref/no-auth-command-injection-exploitation.md` |
| 命令注入端点无速率限制 | 无认证系统命令注入利用 | `ref/no-auth-command-injection-exploitation.md` |
| 文件上传功能无类型验证 | 文件上传 RCE 攻击 | `ref/file-upload-rce-exploitation.md` |
| 文件上传后存储在 Web 可访问目录 | 文件上传 RCE 攻击 | `ref/file-upload-rce-exploitation.md` |
| 上传目录具有 PHP 执行权限 | 文件上传 RCE 攻击 | `ref/file-upload-rce-exploitation.md` |
| 文件上传无认证要求 | 文件上传 RCE 攻击 | `ref/file-upload-rce-exploitation.md` |
| 文件上传仅检查扩展名 | 文件上传 RCE 攻击 | `ref/file-upload-rce-exploitation.md` |
| 文件上传 MIME 类型可伪造 | 文件上传 RCE 攻击 | `ref/file-upload-rce-exploitation.md` |
| LDAP 查询可被操纵 | LDAP 注入攻击 | `ref/ldap-injection-attack.md` |
| 输入在页面中原样输出 | XSS 跨站脚本攻击 | `ref/xss-attack.md` |
| HTTP 头部值在响应中反射 | XSS 跨站脚本攻击 | `ref/xss-attack.md` |
| 输入参数被反射到 HTML 属性上下文（img src、a href、input value 等） | HTML 属性上下文 XSS 攻击 | `ref/xss-html-attribute-context-attack.md` |
| 文件名反射到 img src 属性（文件上传场景） | HTML 属性上下文 XSS 攻击 | `ref/xss-html-attribute-context-attack.md` |
| 文件名反射到 a href 属性（上传确认消息） | HTML 属性上下文 XSS 攻击 | `ref/xss-html-attribute-context-attack.md` |
| 搜索关键词反射到 input value 属性 | HTML 属性上下文 XSS 攻击 | `ref/xss-html-attribute-context-attack.md` |
| 数据库内容反射到 option 标签双上下文 | HTML 属性上下文 XSS 攻击 | `ref/xss-html-attribute-context-attack.md` `ref/stored-xss-multi-context-exploitation.md` |
| 输入参数被反射到 HTML 属性上下文（通用） | XSS 跨站脚本攻击（高级） | `ref/xss-attack-advanced.md` |
| 数据库内容在多个 HTML 上下文中渲染（HTML_BODY、HTML_ATTRIBUTE、option 标签） | 多上下文存储型 XSS 利用 | `ref/stored-xss-multi-context-exploitation.md` |
| 博客/论坛/CMS 文章标题/分类/内容/图片多字段渲染 | 多上下文存储型 XSS 利用 | `ref/stored-xss-multi-context-exploitation.md` |
| 下拉菜单动态填充数据库值（option 标签双上下文） | 多上下文存储型 XSS 利用 | `ref/stored-xss-multi-context-exploitation.md` |
| 同一数据源在 h2/p/img alt/option 多处渲染 | 多上下文存储型 XSS 利用 | `ref/stored-xss-multi-context-exploitation.md` |
| substr() 截断但无 HTML 编码 | 多上下文存储型 XSS 利用 | `ref/stored-xss-multi-context-exploitation.md` |
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
| Flask 应用使用黑名单过滤 XSS | Flask XSS 黑名单绕过利用 | `ref/flask-xss-blacklist-bypass-exploitation.md` |
| Flask 应用使用 PhantomJS 验证 XSS | Flask XSS 黑名单绕过利用 | `ref/flask-xss-blacklist-bypass-exploitation.md` |
| 黑名单仅过滤 6 种 HTML 标签 | Flask XSS 黑名单绕过利用 | `ref/flask-xss-blacklist-bypass-exploitation.md` |
| Flask 应用黑名单过滤特定字符（<, >, (, ), throw, `, ´, javascript） | Flask XSS HTML 实体编码绕过利用 | `ref/flask-xss-html-entity-bypass-exploitation.md` |
| 黑名单过滤括号但允许 HTML 实体 | Flask XSS HTML 实体编码绕过利用 | `ref/flask-xss-html-entity-bypass-exploitation.md` |
| HTML 属性上下文反射 + 黑名单过滤 | Flask XSS HTML 实体编码绕过利用 | `ref/flask-xss-html-entity-bypass-exploitation.md` |
| 使用&#40;&#41;绕过括号过滤 | Flask XSS HTML 实体编码绕过利用 | `ref/flask-xss-html-entity-bypass-exploitation.md` |
| Flask 应用完全无认证架构 + XSS 漏洞 | Flask 无认证架构 XSS 组合攻击 | `ref/flask-no-auth-xss-combo-exploitation.md` |
| 无登录/登出/会话管理 + XSS | Flask 无认证架构 XSS 组合攻击 | `ref/flask-no-auth-xss-combo-exploitation.md` |
| 所有端点公开访问 + XSS 漏洞 | Flask 无认证架构 XSS 组合攻击 | `ref/flask-no-auth-xss-combo-exploitation.md` |
| 无认证系统 Flag 获取 | Flask 无认证架构 XSS 组合攻击 | `ref/flask-no-auth-xss-combo-exploitation.md` |
| 无认证架构数据外带攻击 | Flask 无认证架构 XSS 组合攻击 | `ref/flask-no-auth-xss-combo-exploitation.md` |
| Flask 应用使用 PhantomJS 服务端验证 XSS | Flask + PhantomJS HTML 属性上下文 XSS 利用 | `ref/flask-xss-html-attribute-phantomjs-exploitation.md` |
| 输入反射到 HTML value 属性 | Flask + PhantomJS HTML 属性上下文 XSS 利用 | `ref/flask-xss-html-attribute-phantomjs-exploitation.md` |
| 弱正则过滤仅移除<script>和"XSS"字符串 | Flask + PhantomJS HTML 属性上下文 XSS 利用 | `ref/flask-xss-html-attribute-phantomjs-exploitation.md` |
| 使用 autofocus+onfocus 自动触发 XSS | Flask + PhantomJS HTML 属性上下文 XSS 利用 | `ref/flask-xss-html-attribute-phantomjs-exploitation.md` |
| String.fromCharCode 绕过字符串过滤 | Flask + PhantomJS HTML 属性上下文 XSS 利用 | `ref/flask-xss-html-attribute-phantomjs-exploitation.md` |
| CTF XSS 挑战平台 | Flask + PhantomJS HTML 属性上下文 XSS 利用 | `ref/flask-xss-html-attribute-phantomjs-exploitation.md` |
| 使用模板引擎 (Jinja2/Freemarker/Django) | 模板注入攻击 | `ref/template-injection.md` `ref/jinja2-ssti-advanced-exploitation.md` |
| Flask 应用 f-string 嵌入用户输入到模板 | Flask Jinja2 模板注入攻击 | `ref/flask-jinja2-ssti-attack.md` `ref/jinja2-ssti-advanced-exploitation.md` |
| Flask 应用 render_template_string 处理用户输入 | Flask Jinja2 模板注入攻击 | `ref/flask-jinja2-ssti-attack.md` `ref/jinja2-ssti-advanced-exploitation.md` |
| SSTI 命令执行读取/flag | Flask Jinja2 模板注入攻击 | `ref/flask-jinja2-ssti-attack.md` `ref/jinja2-ssti-advanced-exploitation.md` |
| PHP 应用使用 Twig 模板引擎 (1.x/2.x 版本) | PHP Twig SSTI 利用 | `ref/php-twig-ssti-exploitation.md` |
| PHP 应用 Twig_Loader_String 处理用户输入 | PHP Twig SSTI 利用 | `ref/php-twig-ssti-exploitation.md` |
| Twig 沙箱扩展被移除/禁用 | PHP Twig SSTI 利用 | `ref/php-twig-ssti-exploitation.md` |
| Twig 调试模式开启暴露内部错误 | PHP Twig SSTI 利用 | `ref/php-twig-ssti-exploitation.md` |
| htmlspecialchars()  sanitization 但 Twig 语法未过滤 | PHP Twig SSTI 利用 | `ref/php-twig-ssti-exploitation.md` |
| CTF 挑战应用使用 Twig 模板引擎 | PHP Twig SSTI 利用 | `ref/php-twig-ssti-exploitation.md` |
| SSTI 通过 registerUndefinedFilterCallback 执行命令 | PHP Twig SSTI 利用 | `ref/php-twig-ssti-exploitation.md` |
| SSTI 读取容器内敏感文件 (/flag.txt) | PHP Twig SSTI 利用 | `ref/php-twig-ssti-exploitation.md` |
| Django 应用模板字符串拼接用户输入 | Django SSTI+XSS 组合攻击 | `ref/django-ssti-xss-combo.md` |
| Django 注册流程用户输入注入模板 | Django SSTI+XSS 组合攻击 | `ref/django-ssti-xss-combo.md` |
| SSTI 提取模板上下文敏感变量 (flag/config/SECRET_KEY) | Django SSTI+XSS 组合攻击 | `ref/django-ssti-xss-combo.md` |
| SSTI+XSS 组合攻击数据外带 | Django SSTI+XSS 组合攻击 | `ref/django-ssti-xss-combo.md` |
| Django 模板上下文暴露敏感数据 | Django SSTI+XSS 组合攻击 | `ref/django-ssti-xss-combo.md` |
| SSTI 通过 lipsum.__globals__访问 Python 全局命名空间 | Flask Jinja2 模板注入攻击 | `ref/flask-jinja2-ssti-attack.md` |
| SSTI 盲注数据外带（行数量化判断） | Flask Jinja2 模板注入攻击 | `ref/flask-jinja2-ssti-attack.md` |
| SSTI 黑名单绕过（{、}、% 过滤） | Flask Jinja2 模板注入攻击 | `ref/flask-jinja2-ssti-attack.md` |
| Django 应用模板字符串拼接 | Django SSTI+XSS 组合攻击 | `ref/django-ssti-xss-combo.md` |
| Django 注册流程用户输入注入模板 | Django SSTI+XSS 组合攻击 | `ref/django-ssti-xss-combo.md` |
| 存在 SSTI 且可访问模板上下文 | Django SSTI+XSS 组合攻击 | `ref/django-ssti-xss-combo.md` |
| Django 应用 DEBUG 模式开启 | Django SSTI+XSS 组合攻击 | `ref/django-ssti-xss-combo.md` |
| Django 模板上下文暴露敏感变量 (FLAG/SECRET_KEY) | Django SSTI+XSS 组合攻击 | `ref/django-ssti-xss-combo.md` |
| Flask 应用 f-string 嵌入用户输入到模板 | Jinja2 模板注入高级利用 | `ref/jinja2-ssti-advanced-exploitation.md` |
| Flask 应用 render_template_string 处理用户输入 | Jinja2 模板注入高级利用 | `ref/jinja2-ssti-advanced-exploitation.md` |
| SSTI 命令执行读取/flag | Jinja2 模板注入高级利用 | `ref/jinja2-ssti-advanced-exploitation.md` |
| SSTI 通过 config 全局命名空间执行命令 | Jinja2 模板注入高级利用 | `ref/jinja2-ssti-advanced-exploitation.md` |
| SSTI 绕过引号/空格/关键词过滤 | Jinja2 模板注入高级利用 | `ref/jinja2-ssti-advanced-exploitation.md` |
| 用户可控 URL 发起请求 | SSRF 服务器端请求伪造 | `ref/ssrf-attack-advanced.md` `ref/ssrf-attack-unvalidated-url.md` `ref/ssrf-unvalidated-url-exploitation.md` `ref/ssrf-unvalidated-url-attack.md` |
| 应用加载外部资源 | SSRF 服务器端请求伪造 | `ref/ssrf-attack-advanced.md` `ref/ssrf-attack-unvalidated-url.md` `ref/ssrf-unvalidated-url-exploitation.md` |
| 云环境元数据服务可访问 | SSRF 服务器端请求伪造 | `ref/ssrf-attack-advanced.md` `ref/ssrf-attack-unvalidated-url.md` `ref/ssrf-unvalidated-url-exploitation.md` |
| PHP 应用使用 file_get_contents 处理用户 URL | SSRF 未验证 URL 攻击 | `ref/ssrf-attack-unvalidated-url.md` `ref/ssrf-unvalidated-url-exploitation.md` |
| Python 应用使用 requests.get 处理用户 URL | SSRF 未验证 URL 攻击 | `ref/ssrf-attack-unvalidated-url.md` `ref/ssrf-unvalidated-url-exploitation.md` `ref/ssrf-unvalidated-url-attack.md` |
| Docker 环境内部服务可通过 SSRF 访问 | SSRF 未验证 URL 攻击 | `ref/ssrf-attack-unvalidated-url.md` `ref/ssrf-unvalidated-url-exploitation.md` `ref/ssrf-unvalidated-url-attack.md` |
| 无认证系统存在 SSRF 端点 | SSRF 未验证 URL 攻击 | `ref/ssrf-attack-unvalidated-url.md` `ref/ssrf-unvalidated-url-exploitation.md` `ref/ssrf-unvalidated-url-attack.md` |
| 使用模板引擎 (Jinja2/Freemarker) | 模板注入攻击 | `ref/template-injection.md` |
| XML 解析存在漏洞 | XML/XPath 注入 | `ref/xml-xpath-injection.md` |
| XML 解析器启用外部实体解析（resolve_entities=True） | XXE file:// 协议利用 | `ref/xxe-file-protocol-exploitation.md` |
| SOAP Web Service 存在 XXE 漏洞 | XXE file:// 协议利用 | `ref/xxe-file-protocol-exploitation.md` |
| XXE 非盲注响应（实体内容返回给用户） | XXE file:// 协议利用 | `ref/xxe-file-protocol-exploitation.md` |
| 读取服务器本地文件（/etc/passwd、flag.txt） | XXE file:// 协议利用 | `ref/xxe-file-protocol-exploitation.md` |
| Flask SOAP 服务 XXE 读取 Flag 文件 | XXE file:// 协议利用 | `ref/xxe-file-protocol-exploitation.md` |
| lxml XMLParser resolve_entities=True 配置 | XXE file:// 协议利用 | `ref/xxe-file-protocol-exploitation.md` |
| XML 响应被前端 innerHTML 渲染 | DOM-based XSS 通过 XML 注入 | `ref/dom-xss-via-xml-injection.md` |
| SOAP 响应包含用户可控 XML 内容 | DOM-based XSS 通过 XML 注入 | `ref/dom-xss-via-xml-injection.md` |
| 前端使用 innerHTML 渲染 XML 数据 | DOM-based XSS 通过 XML 注入 | `ref/dom-xss-via-xml-injection.md` |
| CDATA 注入绕过 XML 解析 | DOM-based XSS 通过 XML 注入 | `ref/dom-xss-via-xml-injection.md` |
| Flask SOAP Banking Service DOM-based XSS | DOM-based XSS 通过 XML 注入 | `ref/dom-xss-via-xml-injection.md` |
| GetAccountInfoRequest XSS 利用 | DOM-based XSS 通过 XML 注入 | `ref/dom-xss-via-xml-injection.md` |
| GetAccountHolderInfoRequest XSS 利用 | DOM-based XSS 通过 XML 注入 | `ref/dom-xss-via-xml-injection.md` |
| ORM 查询可被操纵 | ORM 注入攻击 | `ref/orm-injection.md` |
| 表达式语言可被注入 | EL/OGNL 注入 | `ref/el-ognl-injection.md` |
| Apache Struts 2 应用接受用户输入并求值 | OGNL 注入攻击 | `ref/ognl-injection-exploitation.md` |
| Struts 2 应用 message 参数可被 OGNL 表达式注入 | OGNL 注入攻击 | `ref/ognl-injection-exploitation.md` |
| OGNL 注入执行命令读取敏感文件（/tmp/flag） | OGNL 注入攻击 | `ref/ognl-injection-exploitation.md` |
| Struts 2 配置 allowStaticMethodAccess=true | OGNL 注入攻击 | `ref/ognl-injection-exploitation.md` |
| Struts 2 应用用户输入反射到 HTML 页面 | Struts2 XSS 攻击 | `ref/struts2-xss-attack.md` |
| Struts 2 success.jsp 中 escapeHtml="false" | Struts2 XSS 攻击 | `ref/struts2-xss-attack.md` |
| Struts 2 表单提交后消息回显未转义 | Struts2 XSS 攻击 | `ref/struts2-xss-attack.md` |
| 文件路径参数可控 | 路径遍历/文件包含 | `ref/path-traversal-injection.md` |
| 静态文件服务存在路径遍历 | 路径遍历攻击 | `ref/path-traversal-attack.md` |
| Flask send_from_directory 无验证 | 路径遍历攻击 | `ref/path-traversal-attack.md` |
| Apache FilesMatch 可被 Flask 端点绕过 | 路径遍历攻击 | `ref/path-traversal-attack.md` |
| 目录列表启用泄露文件结构 | 路径遍历攻击 | `ref/path-traversal-attack.md` |
| 无认证系统路径遍历利用 | 路径遍历攻击 | `ref/path-traversal-attack.md` |
| Apache 2.4.50 路径遍历导致 RCE | Apache 路径遍历与 CGI RCE 利用 | `ref/apache-path-traversal-rce-exploitation.md` |
| CVE-2021-41773/CVE-2021-42013 利用 | Apache 路径遍历与 CGI RCE 利用 | `ref/apache-path-traversal-rce-exploitation.md` |
| 双 URL 编码绕过路径遍历防护 | Apache 路径遍历与 CGI RCE 利用 | `ref/apache-path-traversal-rce-exploitation.md` |
| CGI 未授权执行导致命令注入 | Apache 路径遍历与 CGI RCE 利用 | `ref/apache-path-traversal-rce-exploitation.md` |
| 静态文件服务存在路径遍历 | 路径遍历攻击 | `ref/path-traversal-attack.md` `ref/apache-path-traversal-rce-exploitation.md` |
| Apache 2.4.49 路径遍历（CVE-2021-41773） | Apache 2.4.49 路径遍历漏洞利用 | `ref/apache-2.4.49-path-traversal-exploitation.md` |
| 静态文件服务无认证系统 | 无认证系统路径遍历利用 | `ref/apache-2.4.49-path-traversal-exploitation.md` `ref/no-auth-path-traversal-exploitation.md` |
| CTF 挑战应用存在路径遍历漏洞 | Apache 2.4.49 路径遍历漏洞利用 | `ref/apache-2.4.49-path-traversal-exploitation.md` |
| Apache 配置 Require all granted 导致任意文件读取 | Apache 2.4.49 路径遍历漏洞利用 | `ref/apache-2.4.49-path-traversal-exploitation.md` |
| 路径遍历读取/proc/self/environ 获取环境变量 | Apache 2.4.49 路径遍历漏洞利用 | `ref/apache-2.4.49-path-traversal-exploitation.md` |
| 路径遍历读取/etc/passwd 用户枚举 | Apache 2.4.49 路径遍历漏洞利用 | `ref/apache-2.4.49-path-traversal-exploitation.md` |
| 路径遍历读取容器内敏感文件 | Apache 2.4.49 路径遍历漏洞利用 | `ref/apache-2.4.49-path-traversal-exploitation.md` |
| 路径遍历读取 Flag 文件（/tmp/flag） | Apache 2.4.49 路径遍历漏洞利用 | `ref/apache-2.4.49-path-traversal-exploitation.md` |
| SQL 关键词被过滤但仍可注入 | SQL 注入黑名单绕过 | `ref/sql-injection-blacklist-bypass.md` |
| 数据库内容在前端渲染 | 存储型 XSS 通过 SQL 注入链 | `ref/stored-xss-via-sql-injection.md` |
| 应用允许上传 HTML 文件且存在 LFI | 存储型 XSS 通过文件上传与 LFI 链 | `ref/stored-xss-via-file-upload-lfi-chain.md` |
| 文件上传无类型验证 + 模板 include 用户文件 | 存储型 XSS 通过文件上传与 LFI 链 | `ref/stored-xss-via-file-upload-lfi-chain.md` |
| 上传恶意 HTML 通过 LFI 触发 XSS | 存储型 XSS 通过文件上传与 LFI 链 | `ref/stored-xss-via-file-upload-lfi-chain.md` |
| 存储型 XSS 凭证窃取/键盘记录/钓鱼 | 存储型 XSS 通过文件上传与 LFI 链 | `ref/stored-xss-via-file-upload-lfi-chain.md` |
| PHP 应用使用 include() 处理用户输入文件 | PHP 本地文件包含 (LFI) 文件读取利用 | `ref/php-lfi-file-read-exploitation.md` |
| 路径遍历保护仅过滤..字符串 | PHP 本地文件包含 (LFI) 文件读取利用 | `ref/php-lfi-file-read-exploitation.md` |
| 绝对路径绕过路径遍历保护 | PHP 本地文件包含 (LFI) 文件读取利用 | `ref/php-lfi-file-read-exploitation.md` |
| CTF 挑战应用存在 LFI 漏洞 | PHP 本地文件包含 (LFI) 文件读取利用 | `ref/php-lfi-file-read-exploitation.md` |
| Docker 环境内部服务 LFI 读取 Flag | PHP 本地文件包含 (LFI) 文件读取利用 | `ref/php-lfi-file-read-exploitation.md` |
| 输入反射到 HTML 属性 value/src/href | HTML 属性上下文 XSS 注入 | `ref/xss-html-attribute-injection.md` |
| HTML 属性值未使用引号包裹 | HTML 属性上下文 XSS 注入 | `ref/xss-html-attribute-injection.md` |
| 双引号未过滤导致属性逃逸 | HTML 属性上下文 XSS 注入 | `ref/xss-html-attribute-injection.md` |
| 事件处理器注入（onfocus/onclick/onerror） | HTML 属性上下文 XSS 注入 | `ref/xss-html-attribute-injection.md` |
| autofocus 属性自动触发事件处理器 | HTML 属性上下文 XSS 注入 | `ref/xss-html-attribute-injection.md` |
| 表单回显用户输入到 value 属性 | HTML 属性上下文 XSS 注入 | `ref/xss-html-attribute-injection.md` |
| 搜索关键词回显到 value 属性 | HTML 属性上下文 XSS 注入 | `ref/xss-html-attribute-injection.md` |
| 无引号属性上下文空格逃逸 | HTML 属性上下文 XSS 注入 | `ref/xss-html-attribute-injection.md` |
| 反引号绕过引号过滤 | HTML 属性上下文 XSS 注入 | `ref/xss-html-attribute-injection.md` |
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
| HTTP 响应中包含注入的头部 | CRLF 注入攻击 | `ref/crlf-injection-attack.md` |
| Location/Set-Cookie 头可被注入 | CRLF 注入攻击 | `ref/crlf-injection-attack.md` |
| 日志文件可被伪造 | CRLF 注入攻击 | `ref/crlf-injection-attack.md` |
| 重定向参数可控 | CRLF 注入攻击 | `ref/crlf-injection-attack.md` |
| 应用使用 eval()/exec() 执行用户输入 | 代码注入/Eval 注入攻击 | `ref/code-eval-injection-exploitation.md` |
| 数学表达式计算功能 | 代码注入/Eval 注入攻击 | `ref/code-eval-injection-exploitation.md` |
| 动态代码执行功能 | 代码注入/Eval 注入攻击 | `ref/code-eval-injection-exploitation.md` |
| Python eval/exec 函数处理用户输入 | 代码注入/Eval 注入攻击 | `ref/code-eval-injection-exploitation.md` |
| JavaScript eval/Function 处理用户输入 | 代码注入/Eval 注入攻击 | `ref/code-eval-injection-exploitation.md` |
| PHP eval/assert 函数处理用户输入 | 代码注入/Eval 注入攻击 | `ref/code-eval-injection-exploitation.md` |
| 应用启用 SSI 功能 | SSI 注入攻击 | `ref/ssi-injection-exploitation.md` |
| .shtml/.stm 文件处理用户输入 | SSI 注入攻击 | `ref/ssi-injection-exploitation.md` |
| SSI exec 指令启用 | SSI 注入攻击 | `ref/ssi-injection-exploitation.md` |
| 文件上传内容被 SSI 解析 | SSI 注入攻击 | `ref/ssi-injection-exploitation.md` |
| 用户输入控制文件路径 | 资源注入攻击 | `ref/resource-injection-exploitation.md` |
| 用户输入控制 URL | 资源注入攻击 | `ref/resource-injection-exploitation.md` |
| 用户输入控制类名/方法名 | 资源注入攻击/不安全反射 | `ref/resource-injection-exploitation.md` `ref/unsafe-reflection-exploitation.md` |
| 动态资源标识符使用 | 资源注入攻击 | `ref/resource-injection-exploitation.md` |
| 路径遍历读取敏感文件 | 资源注入攻击 | `ref/resource-injection-exploitation.md` |
| SSRF 访问内网资源 | 资源注入攻击 | `ref/resource-injection-exploitation.md` |
| 用户输入用于 Class.forName() | 不安全反射攻击 | `ref/unsafe-reflection-exploitation.md` |
| 用户输入用于 Method.invoke() | 不安全反射攻击 | `ref/unsafe-reflection-exploitation.md` |
| 用户输入用于 getattr()/setattr() | 不安全反射攻击 | `ref/unsafe-reflection-exploitation.md` |
| 表达式语言注入（EL/OGNL/SpEL） | 不安全反射攻击 | `ref/unsafe-reflection-exploitation.md` |
| Java/.NET/Python 反射 API 使用用户输入 | 不安全反射攻击 | `ref/unsafe-reflection-exploitation.md` |

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
| INJ-001a | TOCTOU SQL 注入（错误基于） | `ref/toctou-sqli-error-based-exploitation.md` | 漏洞发现/利用 |
| INJ-002 | NoSQL 注入攻击 | `ref/nosql-injection-attack.md` | 漏洞利用 |
| INJ-003 | OS 命令注入 | `ref/os-command-injection.md` | 漏洞利用 |
| INJ-003a | 无认证系统命令注入利用 | `ref/no-auth-command-injection-exploitation.md` | 漏洞发现/利用 |
| INJ-004 | LDAP 注入攻击 | `ref/ldap-injection-attack.md` | 漏洞利用 |
| INJ-005 | XSS 跨站脚本攻击 | `ref/xss-attack.md` | 漏洞利用 |
| INJ-005a | Flask XSS 黑名单绕过利用 | `ref/flask-xss-blacklist-bypass-exploitation.md` | 漏洞利用 |
| INJ-006 | XSS 跨站脚本攻击（高级） | `ref/xss-attack-advanced.md` | 漏洞利用 |
| INJ-007 | SSRF 服务器端请求伪造 | `ref/ssrf-attack-advanced.md` | 漏洞利用 |
| INJ-008 | 模板注入攻击 | `ref/template-injection.md` | 漏洞利用 |
| INJ-009 | XML/XPath 注入 | `ref/xml-xpath-injection.md` | 漏洞利用 |
| INJ-010 | ORM 注入攻击 | `ref/orm-injection.md` | 漏洞利用 |
| INJ-011 | EL/OGNL 注入 | `ref/el-ognl-injection.md` | 漏洞利用 |
| INJ-012 | 路径遍历/文件包含 | `ref/path-traversal-injection.md` | 漏洞利用 |
| INJ-049 | XXE file:// 协议利用 | `ref/xxe-file-protocol-exploitation.md` | 漏洞利用 |
| INJ-050 | DOM-based XSS 通过 XML 注入 | `ref/dom-xss-via-xml-injection.md` | 漏洞利用 |
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
| INJ-031a | 多上下文存储型 XSS 利用 | `ref/stored-xss-multi-context-exploitation.md` | 漏洞利用 |
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
| INJ-042 | Apache 路径遍历与 CGI RCE 利用 | `ref/apache-path-traversal-rce-exploitation.md` | 漏洞发现/利用 |
| INJ-043 | HTML 属性上下文 XSS 注入攻击 | `ref/xss-html-attribute-context-attack.md` | 漏洞利用 |
| INJ-044 | PHP 本地文件包含 (LFI) 文件读取利用 | `ref/php-lfi-file-read-exploitation.md` | 漏洞利用 |
| INJ-045 | WordPress 插件命令注入攻击 | `ref/command-injection-wordpress-plugin.md` | 漏洞利用 |
| INJ-046 | SQL 表名注入攻击 | `ref/sql-injection-table-name.md` | 漏洞利用 |
| INJ-047 | SSRF file:// 协议利用 | `ref/ssrf-file-protocol-exploitation.md` | 漏洞利用 |
| INJ-048 | Apache 2.4.49 路径遍历漏洞利用 | `ref/apache-2.4.49-path-traversal-exploitation.md` | 漏洞发现/利用 |
| INJ-049 | SSRF 未验证 URL 攻击 | `ref/ssrf-unvalidated-url-exploitation.md` | 漏洞发现/利用 |
| INJ-050 | Jinja2 Safe 过滤器 XSS 攻击 | `ref/jinja2-safe-filter-xss.md` | 漏洞利用 |
| INJ-051 | WordPress Canto 插件 SSRF 攻击 | `ref/wordpress-canto-ssrf-attack.md` | 漏洞发现/利用 |
| INJ-052 | WordPress Canto 插件 LFI 攻击 | `ref/wordpress-canto-lfi-attack.md` | 漏洞发现/利用 |
| INJ-053 | Jinja2 模板注入高级利用 | `ref/jinja2-ssti-advanced-exploitation.md` | 漏洞利用 |
| INJ-054 | 存储型 XSS 通过文件上传与 LFI 链 | `ref/stored-xss-via-file-upload-lfi-chain.md` | 漏洞利用 |
| INJ-055 | Flask Jinja2 模板注入（SSTI）攻击 | `ref/flask-jinja2-ssti-attack.md` | 漏洞发现/利用 |
| INJ-056 | SSRF 未验证 URL 攻击 | `ref/ssrf-unvalidated-url-attack.md` | 漏洞发现/利用 |
| INJ-057 | PHP 本地文件包含 (LFI) 文件读取利用 | `ref/php-lfi-file-read-exploitation.md` | 漏洞发现/利用 |
| INJ-058 | HTML 属性上下文 XSS 注入 | `ref/xss-html-attribute-injection.md` | 漏洞利用 |
| INJ-059 | PHP 认证系统 SQL 注入攻击 | `ref/php-auth-sqli-exploitation.md` | 漏洞发现/利用 |
| INJ-060 | WordPress 备份插件命令注入攻击 | `ref/wordpress-backup-plugin-command-injection.md` | 漏洞发现/利用 |
| INJ-061 | WordPress 备份插件 SSRF 攻击 | `ref/wordpress-backup-plugin-ssrf.md` | 漏洞发现/利用 |
| INJ-062 | SSRF 绕过 IP 基础认证攻击 | `ref/ssrf-ip-auth-bypass.md` | 漏洞发现/利用 |
| INJ-063 | XSS + SSRF 组合攻击 | `ref/xss-ssrf-combo-attack.md` | 漏洞发现/利用 |
| INJ-064 | Jinja2 Safe 过滤器 XSS 攻击 | `ref/jinja2-safe-filter-xss.md` | 漏洞发现/利用 |
| INJ-065 | OGNL 注入攻击 | `ref/ognl-injection-exploitation.md` | 漏洞发现/利用 |
| INJ-066 | Struts2 XSS 攻击 | `ref/struts2-xss-attack.md` | 漏洞发现/利用 |
| INJ-067 | OS 命令注入攻击 | `ref/os-command-injection-exploitation.md` | 漏洞发现/利用 |
| INJ-068 | SSRF 命令注入组合攻击 | `ref/ssrf-command-injection-exploitation.md` | 漏洞发现/利用 |
| INJ-069 | GraphQL SQL 注入攻击 | `ref/graphql-sqli-attack.md` | 漏洞发现/利用 |
| INJ-070 | PHP Twig SSTI 利用 | `ref/php-twig-ssti-exploitation.md` | 漏洞发现/利用 |
| INJ-071 | CRLF 注入攻击 | `ref/crlf-injection-attack.md` | 漏洞发现/利用 |
| INJ-072 | 代码注入/Eval 注入攻击 | `ref/code-eval-injection-exploitation.md` | 漏洞发现/利用 |
| INJ-073 | SSI 注入攻击 | `ref/ssi-injection-exploitation.md` | 漏洞发现/利用 |
| INJ-074 | 资源注入攻击 | `ref/resource-injection-exploitation.md` | 漏洞发现/利用 |
| INJ-075 | 不安全反射攻击 | `ref/unsafe-reflection-exploitation.md` | 漏洞发现/利用 |

### 7. WordPress 插件特定注入场景

| 场景 | 参考方法论 | 文件路径 |
|------|-----------|----------|
| WordPress 备份插件 URL 参数命令注入 | WordPress 插件命令注入攻击 | `ref/command-injection-wordpress-plugin.md` `ref/wordpress-backup-plugin-command-injection.md` |
| WordPress 备份插件文件名命令注入 | WordPress 插件命令注入攻击 | `ref/command-injection-wordpress-plugin.md` `ref/wordpress-backup-plugin-command-injection.md` |
| WordPress 备份插件配置持久化命令注入 | WordPress 插件命令注入攻击 | `ref/command-injection-wordpress-plugin.md` `ref/wordpress-backup-plugin-command-injection.md` |
| WordPress 备份恢复表名 SQL 注入 | SQL 表名注入攻击 | `ref/sql-injection-table-name.md` |
| WordPress 备份插件 SSRF 文件读取 | SSRF file:// 协议利用 | `ref/ssrf-file-protocol-exploitation.md` `ref/wordpress-backup-plugin-ssrf.md` |
| WordPress 备份插件 SSRF 内网探测 | WordPress 备份插件 SSRF 攻击 | `ref/wordpress-backup-plugin-ssrf.md` |
| WordPress 备份插件 file:// 协议利用 | WordPress 备份插件 SSRF 攻击 | `ref/wordpress-backup-plugin-ssrf.md` |
| WordPress 备份插件 gopher://协议攻击 | WordPress 备份插件 SSRF 攻击 | `ref/wordpress-backup-plugin-ssrf.md` |
| WordPress 插件 is_admin() 权限绕过 | WordPress is_admin() 权限绕过 | `../broken-access-control/ref/wordpress-is-admin-bypass.md` |
| SSRF 绕过 IP 基础认证（127.0.0.1 检查） | SSRF 绕过 IP 基础认证攻击 | `ref/ssrf-ip-auth-bypass.md` |
| Flask 应用 request.remote_addr 认证绕过 | SSRF 绕过 IP 基础认证攻击 | `ref/ssrf-ip-auth-bypass.md` |
| SSRF 访问 localhost/admin 端点 | SSRF 绕过 IP 基础认证攻击 | `ref/ssrf-ip-auth-bypass.md` |
| SSRF 提取 Flag（/admin/flag） | SSRF 绕过 IP 基础认证攻击 | `ref/ssrf-ip-auth-bypass.md` |
| XSS + SSRF 组合攻击提取 Flag | XSS + SSRF 组合攻击 | `ref/xss-ssrf-combo-attack.md` |
| Jinja2 |safe 过滤器 XSS 注入 | XSS + SSRF 组合攻击 | `ref/xss-ssrf-combo-attack.md` `ref/jinja2-safe-filter-xss.md` |
| markdown_text 参数 XSS 注入 | XSS + SSRF 组合攻击 | `ref/xss-ssrf-combo-attack.md` `ref/jinja2-safe-filter-xss.md` |
| XSS 窃取会话 Cookie | XSS + SSRF 组合攻击 | `ref/xss-ssrf-combo-attack.md` |
| XSS 键盘记录器注入 | XSS + SSRF 组合攻击 | `ref/xss-ssrf-combo-attack.md` |
| XSS 钓鱼表单注入 | XSS + SSRF 组合攻击 | `ref/xss-ssrf-combo-attack.md` |
| Jinja2 |safe 过滤器禁用 HTML 转义 | Jinja2 Safe 过滤器 XSS 攻击 | `ref/jinja2-safe-filter-xss.md` |
| markdown.markdown() 保留原始 HTML | Jinja2 Safe 过滤器 XSS 攻击 | `ref/jinja2-safe-filter-xss.md` |
| Flask 模板 XSS 注入 | Jinja2 Safe 过滤器 XSS 攻击 | `ref/jinja2-safe-filter-xss.md` |
| 存储型 XSS 持久化攻击 | Jinja2 Safe 过滤器 XSS 攻击 | `ref/jinja2-safe-filter-xss.md` |
| XSS 绕过内容过滤（svg/onload） | Jinja2 Safe 过滤器 XSS 攻击 | `ref/jinja2-safe-filter-xss.md` |
| WordPress Canto 插件 SSRF 攻击 | WordPress Canto 插件 SSRF 攻击 | `ref/wordpress-canto-ssrf-attack.md` |
| WordPress Canto 插件 LFI 攻击 | WordPress Canto 插件 LFI 攻击 | `ref/wordpress-canto-lfi-attack.md` |
| Canto 插件 get.php SSRF | WordPress Canto 插件 SSRF 攻击 | `ref/wordpress-canto-ssrf-attack.md` |
| Canto 插件 download.php SSRF | WordPress Canto 插件 SSRF 攻击 | `ref/wordpress-canto-ssrf-attack.md` |
| Canto 插件 detail.php SSRF | WordPress Canto 插件 SSRF 攻击 | `ref/wordpress-canto-ssrf-attack.md` |
| Canto 插件 tree.php SSRF | WordPress Canto 插件 SSRF 攻击 | `ref/wordpress-canto-ssrf-attack.md` |
| Canto 插件 copy-media.php SSRF 链 | WordPress Canto 插件 SSRF 攻击 | `ref/wordpress-canto-ssrf-attack.md` |
| Canto 插件 wp_abspath 参数 LFI | WordPress Canto 插件 LFI 攻击 | `ref/wordpress-canto-lfi-attack.md` |
| Canto 插件 abspath 参数 LFI | WordPress Canto 插件 LFI 攻击 | `ref/wordpress-canto-lfi-attack.md` |
| Canto 插件 LFI+RCE 组合攻击 | WordPress Canto 插件 LFI 攻击 | `ref/wordpress-canto-lfi-attack.md` |
| Canto 插件 LFI+ 认证绕过 | WordPress Canto 插件 LFI 攻击 | `ref/wordpress-canto-lfi-attack.md` |

### 8. Python 反序列化特定注入场景

| 场景 | 参考方法论 | 文件路径 |
|------|-----------|----------|
| Python 应用使用 `pickle.loads()` 处理用户上传文件 | Python Pickle 反序列化 RCE 攻击 | `ref/python-pickle-deserialization-rce.md` |
| Python 应用接受 pickle 序列化数据 | Python Pickle 反序列化 RCE 攻击 | `ref/python-pickle-deserialization-rce.md` |
| FastAPI 文件上传端点反序列化 pickle | Python Pickle 反序列化 RCE 攻击 | `ref/python-pickle-deserialization-rce.md` |
| Flask 应用使用 pickle 存储会话 | Python Pickle 反序列化 RCE 攻击 | `ref/python-pickle-deserialization-rce.md` |
| 使用 pickle 缓存数据到 Redis/Memcached | Python Pickle 反序列化 RCE 攻击 | `ref/python-pickle-deserialization-rce.md` |
| CTF 挑战涉及 Python 反序列化 | Python Pickle 反序列化 RCE 攻击 | `ref/python-pickle-deserialization-rce.md` |
| 文件上传功能接受 `.pkl`/`.pickle` 文件 | Python Pickle 反序列化 RCE 攻击 | `ref/python-pickle-deserialization-rce.md` |
| 通过 pickle RCE 执行系统命令 | Python Pickle 反序列化 RCE 攻击 | `ref/python-pickle-deserialization-rce.md` |
| 通过 pickle RCE 读取/写入敏感文件 | Python Pickle 反序列化 RCE 攻击 | `ref/python-pickle-deserialization-rce.md` |
| 通过 pickle RCE 建立反向 Shell | Python Pickle 反序列化 RCE 攻击 | `ref/python-pickle-deserialization-rce.md` |
| 使用 `__reduce__` 魔法方法执行任意代码 | Python Pickle 反序列化 RCE 攻击 | `ref/python-pickle-deserialization-rce.md` |
| 无回显 Pickle RCE 利用（DNSLog/时间延迟） | Python Pickle 反序列化 RCE 攻击 | `ref/python-pickle-deserialization-rce.md` |
| Pickle RCE 删除文件触发 Flag 暴露 | Python Pickle 反序列化 RCE 攻击 | `ref/python-pickle-deserialization-rce.md` |
| Pickle RCE 组合无认证系统利用 | Python Pickle 反序列化 RCE 攻击 | `ref/python-pickle-deserialization-rce.md` |

### 9. GraphQL 特定注入场景

| 场景 | 参考方法论 | 文件路径 |
|------|-----------|----------|
| GraphQL API 接受字符串参数查询数据库 | GraphQL SQL 注入攻击 | `ref/graphql-sqli-attack.md` |
| GraphQL 参数直接拼接到 SQL 查询 | GraphQL SQL 注入攻击 | `ref/graphql-sqli-attack.md` |
| GraphQL 查询返回数据库敏感数据 | GraphQL SQL 注入攻击 | `ref/graphql-sqli-attack.md` |
| GraphQL 内省查询暴露 schema 结构 | GraphQL SQL 注入攻击 | `ref/graphql-sqli-attack.md` |
| GraphQL 参数绕过弱授权检查 | GraphQL SQL 注入攻击 | `ref/graphql-sqli-attack.md` |
| GraphQL UNION 注入提取数据库内容 | GraphQL SQL 注入攻击 | `ref/graphql-sqli-attack.md` |
| GraphQL 布尔盲注提取数据 | GraphQL SQL 注入攻击 | `ref/graphql-sqli-attack.md` |
| GraphQL 时间盲注（无错误回显） | GraphQL SQL 注入攻击 | `ref/graphql-sqli-attack.md` |
| CTF 挑战应用使用 GraphQL+SQLite | GraphQL SQL 注入攻击 | `ref/graphql-sqli-attack.md` |
| 无认证系统 GraphQL 端点公开访问 | GraphQL SQL 注入攻击 | `ref/graphql-sqli-attack.md` |
| Flask 应用使用 pickle 存储会话 | Python Pickle 反序列化 RCE 攻击 | `ref/python-pickle-deserialization-rce.md` |
| 使用 pickle 缓存数据到 Redis/Memcached | Python Pickle 反序列化 RCE 攻击 | `ref/python-pickle-deserialization-rce.md` |
| CTF 挑战涉及 Python 反序列化 | Python Pickle 反序列化 RCE 攻击 | `ref/python-pickle-deserialization-rce.md` |
| 文件上传功能接受 `.pkl`/`.pickle` 文件 | Python Pickle 反序列化 RCE 攻击 | `ref/python-pickle-deserialization-rce.md` |
| 通过 pickle RCE 执行系统命令 | Python Pickle 反序列化 RCE 攻击 | `ref/python-pickle-deserialization-rce.md` |
| 通过 pickle RCE 读取/写入敏感文件 | Python Pickle 反序列化 RCE 攻击 | `ref/python-pickle-deserialization-rce.md` |
| 通过 pickle RCE 建立反向 Shell | Python Pickle 反序列化 RCE 攻击 | `ref/python-pickle-deserialization-rce.md` |
| 使用 `__reduce__` 魔法方法执行任意代码 | Python Pickle 反序列化 RCE 攻击 | `ref/python-pickle-deserialization-rce.md` |
| 无回显 Pickle RCE 利用（DNSLog/时间延迟） | Python Pickle 反序列化 RCE 攻击 | `ref/python-pickle-deserialization-rce.md` |
| Pickle RCE 删除文件触发 Flag 暴露 | Python Pickle 反序列化 RCE 攻击 | `ref/python-pickle-deserialization-rce.md` |
| Pickle RCE 组合无认证系统利用 | Python Pickle 反序列化 RCE 攻击 | `ref/python-pickle-deserialization-rce.md` |

### 9. Flask 命令注入特定场景

| 场景 | 参考方法论 | 文件路径 |
|------|-----------|----------|
| Flask 应用使用 subprocess 执行系统命令 | OS 命令注入攻击 | `ref/os-command-injection-exploitation.md` |
| Flask 应用 subprocess.Popen 使用 shell=True | OS 命令注入攻击 | `ref/os-command-injection-exploitation.md` |
| Flask 应用字符串拼接构建命令 | OS 命令注入攻击 | `ref/os-command-injection-exploitation.md` |
| Flask Ping 工具命令注入 | OS 命令注入攻击 | `ref/os-command-injection-exploitation.md` |
| 命令注入读取敏感文件（/FLAG.txt） | OS 命令注入攻击 | `ref/os-command-injection-exploitation.md` |
| 命令注入写入静态目录外带数据 | OS 命令注入攻击 | `ref/os-command-injection-exploitation.md` |
| 命令注入系统信息收集（whoami/id/uname） | OS 命令注入攻击 | `ref/os-command-injection-exploitation.md` |
| 命令注入建立反向 Shell | OS 命令注入攻击 | `ref/os-command-injection-exploitation.md` |
| 命令注入 + SSRF 组合攻击 | SSRF 命令注入组合攻击 | `ref/ssrf-command-injection-exploitation.md` |
| 命令注入内网端口扫描 | SSRF 命令注入组合攻击 | `ref/ssrf-command-injection-exploitation.md` |
| 命令注入云元数据访问 | SSRF 命令注入组合攻击 | `ref/ssrf-command-injection-exploitation.md` |
| 命令注入 DNS/HTTP 外带数据 | SSRF 命令注入组合攻击 | `ref/ssrf-command-injection-exploitation.md` |
| Flask 应用无输入验证（re 模块导入但未使用） | OS 命令注入攻击 | `ref/os-command-injection-exploitation.md` |
| 命令注入绕过空格过滤（${IFS}） | OS 命令注入攻击 | `ref/os-command-injection-exploitation.md` |
| 命令注入绕过关键词过滤（tac/more/less） | OS 命令注入攻击 | `ref/os-command-injection-exploitation.md` |
| 命令注入 Base64 编码绕过 | OS 命令注入攻击 | `ref/os-command-injection-exploitation.md` |

### 10. 文件上传特定注入场景

| 场景 | 参考方法论 | 文件路径 |
|------|-----------|----------|
| 文件上传功能无类型验证 | 文件上传 RCE 攻击 | `ref/file-upload-rce-exploitation.md` |
| 文件上传后存储在 Web 可访问目录 | 文件上传 RCE 攻击 | `ref/file-upload-rce-exploitation.md` |
| 上传目录具有 PHP 执行权限 | 文件上传 RCE 攻击 | `ref/file-upload-rce-exploitation.md` |
| 文件上传无认证要求 | 文件上传 RCE 攻击 | `ref/file-upload-rce-exploitation.md` |
| 文件上传仅检查扩展名 | 文件上传 RCE 攻击 | `ref/file-upload-rce-exploitation.md` |
| 文件上传 MIME 类型可伪造 | 文件上传 RCE 攻击 | `ref/file-upload-rce-exploitation.md` |
| 上传 PHP WebShell 执行命令 | 文件上传 RCE 攻击 | `ref/file-upload-rce-exploitation.md` |
| 文件上传 + XSS 组合攻击 | HTML 属性上下文 XSS 攻击 | `ref/xss-html-attribute-context-attack.md` |
| 文件名反射到 HTML 属性 | HTML 属性上下文 XSS 攻击 | `ref/xss-html-attribute-context-attack.md` |
| 存储型 XSS 持久化攻击 | HTML 属性上下文 XSS 攻击 | `ref/xss-html-attribute-context-attack.md` |
| 反射型 XSS 上传确认消息 | HTML 属性上下文 XSS 攻击 | `ref/xss-html-attribute-context-attack.md` |

### 11. Flask+PhantomJS 特定注入场景

| 场景 | 参考方法论 | 文件路径 |
|------|-----------|----------|
| CTF 挑战应用通过 XSS 验证获取 Flag | Flask+PhantomJS XSS Flag 获取利用 | `ref/flask-xss-phantomjs-flag-exploitation.md` |
| PhantomJS 验证 XSS 返回 Flag/敏感信息 | Flask+PhantomJS XSS Flag 获取利用 | `ref/flask-xss-phantomjs-flag-exploitation.md` |
| javascript: 协议注入绕过扩展名过滤 | Flask+PhantomJS XSS Flag 获取利用 | `ref/flask-xss-phantomjs-flag-exploitation.md` |
| 属性注入绕过角括号过滤 | Flask+PhantomJS XSS Flag 获取利用 | `ref/flask-xss-phantomjs-flag-exploitation.md` |
| PhantomJS 渲染用户控制 HTML | SSRF via PhantomJS 内网扫描 | `ref/ssrf-phantomjs-internal-scan.md` |
| PhantomJS 可访问 localhost/内网服务 | SSRF via PhantomJS 内网扫描 | `ref/ssrf-phantomjs-internal-scan.md` |
| PhantomJS 可访问云元数据服务 | SSRF via PhantomJS 内网扫描 | `ref/ssrf-phantomjs-internal-scan.md` |
| PhantomJS 支持 file:// 协议 | SSRF via PhantomJS 内网扫描 | `ref/ssrf-phantomjs-internal-scan.md` |
| 通过响应时间差异判断端口开放状态 | SSRF via PhantomJS 内网扫描 | `ref/ssrf-phantomjs-internal-scan.md` |
| 十进制 IP 绕过点分十进制过滤 | SSRF via PhantomJS 内网扫描 | `ref/ssrf-phantomjs-internal-scan.md` |
| SSRF 内网端口扫描（22/80/443/3306/6379 等） | SSRF via PhantomJS 内网扫描 | `ref/ssrf-phantomjs-internal-scan.md` |
| SSRF 读取本地文件（file:///etc/passwd） | SSRF via PhantomJS 内网扫描 | `ref/ssrf-phantomjs-internal-scan.md` |

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
- [Python Pickle Security](https://docs.python.org/3/library/pickle.html#module-pickle)
