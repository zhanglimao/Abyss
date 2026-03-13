# TLS 安全检测

---

## 第一部分：文档概述

### 1.1 编写目的
本文档旨在为渗透测试人员提供 TLS/SSL 安全配置检测的系统性方法论。通过本指南，测试人员可以全面评估目标系统的 TLS 实现安全性，发现配置缺陷和协议漏洞。

### 1.2 适用范围
本文档适用于以下场景：
- Web 应用服务器 TLS 配置审计
- API 服务端点加密检测
- 邮件服务器 TLS 配置检测
- 数据库连接加密检测
- 任何使用 TLS/SSL 的网络服务

### 1.3 读者对象
- 渗透测试工程师
- 安全审计人员
- 基础设施安全测试人员
- 合规性检测人员

---

## 第二部分：核心渗透技术专题

### 专题一：TLS 安全检测

#### 2.1 技术介绍

**TLS 安全检测**是对传输层安全协议（TLS/SSL）的配置进行全面评估的过程，旨在发现可能导致中间人攻击、数据泄露的加密配置缺陷。

**检测维度：**

| 维度 | 检测内容 | 风险等级 |
|------|---------|---------|
| 协议版本 | SSL 2.0/3.0, TLS 1.0/1.1/1.2/1.3 | 高危（旧版本） |
| 加密套件 | 弱加密算法、导出级加密 | 高危 |
| 证书配置 | 过期、自签名、弱签名算法 | 中 - 高危 |
| 密钥交换 | DH 参数强度、椭圆曲线选择 | 中 - 高危 |
| 扩展支持 | HSTS、OCSP Stapling | 中危 |
| 压缩支持 | CRIME 攻击风险 | 中危 |

#### 2.2 检测常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 电商网站 | 支付页面、用户登录 | TLS 配置不当导致支付信息泄露 |
| 金融机构 | 网银系统、API 接口 | 合规性要求高，需严格检测 |
| 政府网站 | 政务服务平台 | 通常存在旧协议兼容问题 |
| 医疗健康 | 患者信息系统 | HIPAA 合规要求 |
| 企业内部 | OA 系统、邮件系统 | 常使用自签名证书 |

#### 2.3 漏洞检测方法

##### 2.3.1 使用 Nmap 检测

```bash
# 基础 TLS 检测
nmap --script ssl-enum-ciphers -p 443 target.com

# 检测 SSL/TLs 漏洞
nmap --script ssl-heartbleed,ssl-poodle,ssl-dh-params -p 443 target.com

# 检测证书信息
nmap --script ssl-cert -p 443 target.com

# 完整 TLS 审计
nmap --script ssl-enum-ciphers,ssl-cert,ssl-date,ssl-heartbleed -p 443 target.com
```

##### 2.3.2 使用 OpenSSL 检测

```bash
# 测试 TLS 1.3 支持
openssl s_client -connect target.com:443 -tls1_3

# 测试 TLS 1.2 支持
openssl s_client -connect target.com:443 -tls1_2

# 测试 TLS 1.1（应禁用）
openssl s_client -connect target.com:443 -tls1_1

# 测试 TLS 1.0（应禁用）
openssl s_client -connect target.com:443 -tls1

# 测试 SSL 3.0（应禁用）
openssl s_client -connect target.com:443 -ssl3

# 查看证书详情
openssl s_client -connect target.com:443 -showcerts
```

##### 2.3.3 使用 testssl.sh 检测

```bash
# 克隆工具
git clone https://github.com/drwetter/testssl.sh.git
cd testssl.sh

# 基础检测
./testssl.sh target.com:443

# 完整检测（包括所有漏洞）
./testssl.sh --full target.com:443

# 生成报告
./testssl.sh --html --logfile target_report target.com:443

# 检测特定漏洞
./testssl.sh --heartbleed target.com:443
./testssl.sh --poodle target.com:443
./testssl.sh --freak target.com:443
./testssl.sh --logjam target.com:443
```

##### 2.3.4 使用 SSLyze 检测

```bash
# 安装
pip install sslyze

# 基础检测
sslyze --regular target.com:443

# 完整检测
sslyze --all target.com:443

# 检测特定项目
sslyze --tls_1_2 --tls_1_3 --heartbleed target.com:443

# JSON 输出
sslyze --json_out report.json target.com:443
```

##### 2.3.5 使用 SSL Labs API

```bash
# 使用 SSL Labs API 检测
curl "https://api.ssllabs.com/api/v3/analyze?host=target.com&publish=off"

# 获取检测结果
curl "https://api.ssllabs.com/api/v3/getanalyzeData?all=done&host=target.com"
```

#### 2.4 检测结果评估

##### 2.4.1 协议版本评估

| 协议版本 | 评级 | 建议 |
|---------|------|------|
| TLS 1.3 | ✅ 优秀 | 推荐使用 |
| TLS 1.2 | ✅ 良好 | 可接受，需正确配置 |
| TLS 1.1 | ⚠️ 过时 | 应禁用 |
| TLS 1.0 | ❌ 不安全 | 必须禁用 |
| SSL 3.0 | ❌ 不安全 | 必须禁用 |
| SSL 2.0 | ❌ 严重漏洞 | 必须禁用 |

##### 2.4.2 加密套件评估

```bash
# 强加密套件（推荐）
TLS_AES_256_GCM_SHA384
TLS_AES_128_GCM_SHA256
TLS_CHACHA20_POLY1305_SHA256
ECDHE-RSA-AES256-GCM-SHA384
ECDHE-RSA-AES128-GCM-SHA256

# 中等强度（可接受）
ECDHE-RSA-AES256-SHA384
ECDHE-RSA-AES128-SHA256

# 弱加密套件（应禁用）
DES-CBC3-SHA
RC4-SHA
RC4-MD5
AES128-SHA
AES256-SHA

# 严重弱点（必须禁用）
EXPORT 级加密
NULL 加密
MD5 签名
```

##### 2.4.3 证书评估清单

```bash
# 证书检查清单
# [ ] 证书未过期
# [ ] 证书链完整
# [ ] 使用 SHA-256 或更强签名算法
# [ ] RSA 密钥至少 2048 位，EC 密钥至少 256 位
# [ ] 主题备用名称（SAN）包含所有域名
# [ ] 证书由可信 CA 签发
# [ ] 未使用已知弱 CA 签发的证书
```

#### 2.5 常见漏洞检测

##### 2.5.1 Heartbleed (CVE-2014-0160)

```bash
# 检测 Heartbleed
nmap --script ssl-heartbleed -p 443 target.com

# 使用 testssl.sh
./testssl.sh --heartbleed target.com:443

# 使用 Python 脚本检测
python3 heartbleed.py target.com 443
```

##### 2.5.2 POODLE (CVE-2014-3566)

```bash
# 检测 POODLE
nmap --script ssl-poodle -p 443 target.com

# 使用 testssl.sh
./testssl.sh --poodle target.com:443
```

##### 2.5.3 FREAK (CVE-2015-0204)

```bash
# 检测 FREAK
nmap --script ssl-freak -p 443 target.com

# 使用 OpenSSL 测试
openssl s_client -connect target.com:443 -cipher 'EXPORT'
```

##### 2.5.4 Logjam (CVE-2015-4000)

```bash
# 检测 Logjam
nmap --script ssl-dh-params -p 443 target.com

# 使用 testssl.sh
./testssl.sh --logjam target.com:443

# 检查 DH 参数强度
# 如果 DH 参数 < 1024 位，存在风险
```

##### 2.5.5 ROBOT Attack

```bash
# 检测 ROBOT
./testssl.sh --robot target.com:443

# 如果返回 "VULNERABLE"，存在风险
```

---

## 第三部分：附录

### 3.1 TLS 安全检测速查表

| 检测项目 | 命令 | 预期结果 |
|---------|------|---------|
| 协议版本 | `testssl.sh target:443` | 仅 TLS 1.2/1.3 |
| 加密套件 | `nmap --script ssl-enum-ciphers` | 无弱加密 |
| Heartbleed | `nmap --script ssl-heartbleed` | NOT VULNERABLE |
| POODLE | `testssl.sh --poodle` | NOT VULNERABLE |
| 证书有效期 | `openssl s_client -showcerts` | 未过期 |
| HSTS | `curl -I https://target` | Strict-Transport-Security |

### 3.2 安全 TLS 配置示例

**Nginx 安全配置：**
```nginx
server {
    listen 443 ssl http2;
    
    # 仅启用 TLS 1.2 和 1.3
    ssl_protocols TLSv1.2 TLSv1.3;
    
    # 强加密套件
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384';
    ssl_prefer_server_ciphers off;
    
    # 证书配置
    ssl_certificate /etc/ssl/certs/server.crt;
    ssl_certificate_key /etc/ssl/private/server.key;
    
    # 会话配置
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;
    
    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    
    # HSTS
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
}
```

**Apache 安全配置：**
```apache
<VirtualHost *:443>
    # 仅启用 TLS 1.2 和 1.3
    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
    
    # 强加密套件
    SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
    
    # 优先服务器套件
    SSLHonorCipherOrder on
    
    # 证书配置
    SSLCertificateFile /etc/ssl/certs/server.crt
    SSLCertificateKeyFile /etc/ssl/private/server.key
    SSLCertificateChainFile /etc/ssl/certs/chain.crt
    
    # HSTS
    Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
</VirtualHost>
```

### 3.3 TLS 检测工具清单

| 工具 | 类型 | 用途 |
|-----|------|------|
| testssl.sh | CLI | 完整 TLS 审计 |
| SSLyze | CLI/Python | 快速 TLS 检测 |
| Nmap ssl-enum-ciphers | CLI | 加密套件枚举 |
| SSL Labs | Web/API | 在线 TLS 评级 |
| OpenSSL | CLI | 手动 TLS 测试 |
| Wireshark | GUI | TLS 流量分析 |

---

## 参考资源

- [OWASP TLS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)
- [SSL Labs Server Test](https://www.ssllabs.com/ssltest/)
- [testssl.sh](https://github.com/drwetter/testssl.sh)
- [NIST SP 800-52 Rev. 2](https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final)
