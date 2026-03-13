# 证书检测指南

---

## 第一部分：文档概述

### 1.1 编写目的
本文档旨在为渗透测试人员提供 SSL/TLS 证书检测的方法论。通过本指南，测试人员可以发现证书配置缺陷、伪造证书、证书验证绕过等安全问题。

### 1.2 适用范围
本文档适用于以下场景：
- Web 应用证书审计
- 移动应用证书验证测试
- 内部 PKI 系统评估
- 证书固定有效性验证
- 自签名证书风险评估

### 1.3 读者对象
- 渗透测试工程师
- PKI 审计人员
- 网络安全测试人员
- 合规性检测人员

---

## 第二部分：核心渗透技术专题

### 专题一：证书检测

#### 2.1 技术介绍

**证书检测**是对 SSL/TLS 证书的配置、验证和信任链进行全面评估的过程，旨在发现可能导致中间人攻击的证书相关问题。

**证书检测维度：**

| 维度 | 检测内容 | 风险等级 |
|------|---------|---------|
| 证书有效性 | 过期、吊销、域名匹配 | 高危 |
| 证书链 | 链完整性、中间 CA | 中 - 高危 |
| 签名算法 | SHA-1、弱 RSA 密钥 | 中 - 高危 |
| 信任锚 | 自签名、私有 CA | 中危 |
| 证书固定 | 固定有效性、绕过 | 中危 |
| 扩展验证 | EV 证书、组织验证 | 低 - 中危 |

#### 2.2 检测常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 企业内网 | 内部系统 HTTPS | 大量自签名证书 |
| 开发环境 | 测试服务器 | 过期或无效证书 |
| 移动应用 | App 后端通信 | 证书验证不严格 |
| IoT 设备 | 设备管理界面 | 自签名证书 |
| 微服务 | 服务间 TLS | 内部 CA 证书 |
| API 网关 | API 端点 | 证书配置不当 |

#### 2.3 漏洞检测方法

##### 2.3.1 证书信息收集

```bash
# 使用 OpenSSL 获取证书信息
openssl s_client -connect target.com:443 -showcerts

# 提取证书详情
openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -text -noout

# 检查证书过期时间
openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -noout -dates

# 检查证书主题
openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -noout -subject

# 检查颁发者
openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -noout -issuer

# 检查 SAN（主题备用名称）
openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -noout -ext subjectAltName
```

##### 2.3.2 使用 Nmap 检测

```bash
# 证书信息枚举
nmap --script ssl-cert -p 443 target.com

# 证书过期检测
nmap --script ssl-cert --script-args ssl-cert.check-validity -p 443 target.com

# 完整证书链分析
nmap --script ssl-enum-ciphers,ssl-cert -p 443 target.com

# 检测自签名证书
nmap --script ssl-cert --script-args ssl-cert.info -p 443 target.com
```

##### 2.3.3 使用 testssl.sh 检测

```bash
# 完整证书检测
./testssl.sh target.com:443

# 仅证书相关检测
./testssl.sh --certinfo target.com:443

# 检测证书链问题
./testssl.sh --chain target.com:443

# 检测证书透明度
./testssl.sh --ct target.com:443
```

##### 2.3.4 证书链验证

```bash
# 验证证书链完整性
openssl s_client -connect target.com:443 -CAfile ca-bundle.crt

# 检测缺失中间证书
# 如果以下命令失败，说明中间证书缺失
openssl s_client -connect target.com:443 -partial_chain

# 使用在线工具检测
# https://www.ssllabs.com/ssltest/
# https://certificate.revocationcheck.com/
```

##### 2.3.5 证书吊销检测

```bash
# 获取 CRL 分发点
openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -noout -ext crlDistributionPoints

# 获取 OCSP URI
openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -noout -ext authorityInfoAccess

# 检查 OCSP 状态
openssl ocsp -issuer intermediate.crt -cert server.crt -url http://ocsp.example.com

# 使用 CRLCheck
nmap --script ssl-cert --script-args ssl-cert.check-crl -p 443 target.com
```

##### 2.3.6 证书透明度检测

```bash
# 使用 crt.sh 查询
curl "https://crt.sh/?q=target.com&output=json"

# 使用 certspotter
curl "https://api.certspotter.com/v1/issuances?domain=target.com&include_subdomains=true"

# 检测未授权证书颁发
# 检查是否有未知 CA 颁发了目标域名的证书
```

#### 2.4 漏洞利用方法

##### 2.4.1 自签名证书攻击

```bash
# 生成自签名证书
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=target.com"

# 在 MITM 攻击中使用
mitmproxy --certs *=cert.pem:key.pem

# 如果客户端接受自签名证书，攻击成功
```

##### 2.4.2 证书固定绕过

```javascript
// Android Frida 脚本绕过证书固定
Java.perform(function() {
    // 方法 1: 信任所有证书
    var TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    
    TrustManager.checkServerTrusted.implementation = function() {};
    TrustManager.checkClientTrusted.implementation = function() {};
    TrustManager.getAcceptedIssuers.implementation = function() { return []; };
    
    // 方法 2: OkHttp CertificatePinner
    var CertificatePinner = Java.use("okhttp3.CertificatePinner");
    CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function() {};
    
    // 方法 3: WebView
    var WebViewClient = Java.use("android.webkit.WebViewClient");
    WebViewClient.onReceivedSslError.implementation = function(webView, handler, error) {
        handler.proceed();  // 忽略 SSL 错误
    };
});

// 使用方式
frida -U -f com.target.app -l bypass_cert_pinning.js
```

```python
# iOS Frida 脚本绕过证书固定
# 使用 frida-ios-dump 和 objection
objection -g "App Name" explore

# 在 objection 中
android sslpinning disable
ios sslpinning disable
```

##### 2.4.3 弱签名算法利用

```bash
# 检测 SHA-1 签名证书
openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -noout -text | grep "Signature Algorithm"

# 如果输出包含 sha1RSA 或 sha1WithRSAEncryption，存在风险

# SHA-1 碰撞攻击（理论可行，实际成本高）
# 使用 SHAttered 攻击生成碰撞证书
# https://shattered.io/
```

##### 2.4.4 证书不匹配检测

```bash
# 检查证书 CN/SAN 是否匹配域名
openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -noout -subject -ext subjectAltName

# 检测通配符证书滥用
# 通配符证书 *.example.com 不应覆盖非子域名

# 检测多域名证书中的无关域名
openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -noout -ext subjectAltName
```

##### 2.4.5 过期证书利用

```bash
# 检测过期证书
openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -noout -enddate

# 如果证书已过期，客户端可能显示警告但仍允许继续
# 某些应用可能未正确验证证书有效期

# 批量检测脚本
#!/bin/bash
for domain in $(cat domains.txt); do
    echo -n "$domain: "
    openssl s_client -connect $domain:443 2>/dev/null | openssl x509 -noout -enddate 2>&1
done
```

#### 2.5 安全配置建议

##### 2.5.1 证书配置最佳实践

```
证书要求：
- RSA 密钥至少 2048 位，推荐 3072+ 位
- EC 密钥至少 256 位（P-256 曲线）
- 签名算法 SHA-256 或更强
- 有效期不超过 397 天（行业最佳实践）
- 启用证书透明度（CT）

证书链要求：
- 包含所有中间证书
- 使用可信 CA 颁发的证书
- 定期更新中间证书
- 配置 OCSP Stapling
```

##### 2.5.2 Nginx 证书配置

```nginx
server {
    listen 443 ssl http2;
    
    # 证书配置
    ssl_certificate /etc/ssl/certs/fullchain.pem;
    ssl_certificate_key /etc/ssl/private/privkey.pem;
    
    # 信任链（可选，用于发送中间证书）
    # ssl_trusted_certificate /etc/ssl/certs/chain.pem;
    
    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 8.8.8.8 8.8.4.4 valid=300s;
    resolver_timeout 5s;
    
    # HSTS（包含 preload）
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    
    # 期望的证书透明度
    add_header Expect-CT "max-age=86400, enforce" always;
}
```

##### 2.5.3 证书检查清单

- [ ] 证书未过期
- [ ] 证书链完整
- [ ] 域名匹配（CN 和 SAN）
- [ ] 签名算法安全（SHA-256+）
- [ ] 密钥长度足够（RSA 2048+）
- [ ] 由可信 CA 颁发
- [ ] 未被吊销（CRL/OCSP 检查）
- [ ] 证书透明度日志记录
- [ ] OCSP Stapling 启用
- [ ] HSTS 正确配置

---

## 第三部分：附录

### 3.1 证书检测工具

| 工具 | 用途 |
|-----|------|
| OpenSSL | 证书查看和分析 |
| testssl.sh | 完整 TLS/证书审计 |
| SSL Labs | 在线证书评级 |
| crt.sh | 证书透明度查询 |
| certspotter | 证书监控 |
| Nmap ssl-cert | 证书信息枚举 |

### 3.2 证书风险评级

| 问题 | 风险等级 | 建议 |
|-----|---------|------|
| 证书过期 | 高危 | 立即更新 |
| 自签名证书 | 中危 | 替换为 CA 证书 |
| SHA-1 签名 | 高危 | 更新为 SHA-256 |
| 密钥<2048 位 | 高危 | 更新密钥 |
| 证书链不完整 | 中危 | 补充中间证书 |
| 域名不匹配 | 高危 | 申请正确证书 |
| 已吊销证书 | 严重 | 立即更新 |

### 3.3 证书错误代码

| 错误 | 含义 | 风险 |
|-----|------|------|
| CERT_EXPIRED | 证书过期 | 高 |
| CERT_NOT_YET_VALID | 证书尚未生效 | 高 |
| CERT_COMMON_NAME_INVALID | 域名不匹配 | 高 |
| CERT_AUTHORITY_INVALID | 颁发者不受信任 | 中 |
| CERT_REVOKED | 证书已吊销 | 严重 |
| CERT_WEAK_SIGNATURE | 弱签名算法 | 高 |

---

## 参考资源

- [RFC 5280 - X.509 Certificate Profile](https://tools.ietf.org/html/rfc5280)
- [CA/Browser Forum Baseline Requirements](https://cabforum.org/baseline-requirements-documents/)
- [Certificate Transparency](https://certificate.transparency.dev/)
- [SSL Labs Best Practices](https://www.ssllabs.com/projects/best-practices/)
- [OWASP TLS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
