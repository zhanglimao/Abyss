# 算法降级攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的算法降级攻击检测、验证和利用流程。通过本指南，测试人员可以识别目标系统中存在的协议降级和加密套件降级风险，评估其影响，并在授权范围内使用相应的攻击技术绕过安全保护。

## 1.2 适用范围

本文档适用于以下场景：
- TLS/SSL协议降级攻击
- 加密套件降级攻击
- SSH 协议版本降级
- 认证算法降级
- 签名算法降级
- 密钥交换算法降级
- 应用层协议降级

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师、协议安全测试人员。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

算法降级攻击（CWE-757）针对的是协议或实现支持多个参与者之间的交互，并允许这些参与者协商应使用哪种算法作为保护机制，但它不会在双方可用的算法中选择最强的算法。

**本质问题**：
- 协议协商过程未强制选择最强可用算法
- 客户端和服务器支持多种算法/协议版本
- 攻击者可篡改协商过程强制选择弱算法
- 受害者可能不知道正在使用安全性较低的算法

### 常见 CWE 映射

| CWE 编号 | 描述 | 风险等级 |
|---------|------|---------|
| CWE-757 | 协商期间选择安全性较低的算法（算法降级） | 严重 |
| CWE-759 | 使用无盐单向哈希 | 高危 |
| CWE-326 | 加密强度不足 | 高危 |
| CWE-327 | 使用已损坏或有风险的加密算法 | 高危 |
| CWE-1328 | 安全版本号可降级到旧版本 | 高危 |

### 常见降级攻击类型

| 攻击类型 | 目标 | 利用的弱点 | 潜在危害 |
|---------|------|-----------|---------|
| **TLS 版本降级** | TLS 1.2/1.3 → TLS 1.0/1.1/SSLv3 | 向后兼容性 | BEAST、POODLE 攻击 |
| **加密套件降级** | 强加密 → 弱加密（RC4、DES） | 弱套件支持 | 加密破解 |
| **签名算法降级** | RSA-PSS/ECDSA → RSA PKCS#1 v1.5 | 旧算法支持 | 签名伪造 |
| **密钥交换降级** | ECDHE → RSA/DH | 前向保密缺失 | 历史流量解密 |
| **SSH 版本降级** | SSH-2 → SSH-1 | 向后兼容 | 已知漏洞利用 |
| **认证降级** | MFA → 单因素认证 | 认证回退 | 认证绕过 |
| **出口级加密攻击** | 正常加密 → 出口级弱加密 | 历史遗留 | FREAK、Logjam |

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 | 潜在危害 |
|---------|---------|-----------|---------|
| **HTTPS 网站** | Web 浏览、登录 | TLS 配置支持旧协议 | 流量解密、会话劫持 |
| **邮件服务** | SMTP/IMAP/POP3 | STARTTLS 降级 | 邮件内容窃取 |
| **数据库连接** | MySQL/PostgreSQL | SSL 连接降级 | 查询/数据泄露 |
| **API 服务** | REST/SOAP API | API 加密降级 | 数据泄露、注入 |
| **远程管理** | SSH/RDP | 协议版本降级 | 凭证窃取、命令注入 |
| **VPN 服务** | OpenVPN/IPSec | 加密算法降级 | 隧道流量解密 |
| **即时通讯** | XMPP/Signal | 端到端加密降级 | 通信内容泄露 |
| **支付系统** | 支付网关 | 支付加密降级 | 支付数据窃取 |
| **云服务** | AWS/Azure/GCP | 服务间通信降级 | 云数据泄露 |
| **移动应用** | App 后端通信 | 自定义协议降级 | 用户数据泄露 |

## 2.3 漏洞发现方法

### 2.3.1 TLS 版本降级检测

**步骤 1：使用 OpenSSL 检测**

```bash
# 检测支持的 TLS 版本
# SSLv3
openssl s_client -connect target.com:443 -ssl3 2>&1 | grep -E "Protocol|Cipher"

# TLS 1.0
openssl s_client -connect target.com:443 -tls1 2>&1 | grep -E "Protocol|Cipher"

# TLS 1.1
openssl s_client -connect target.com:443 -tls1_1 2>&1 | grep -E "Protocol|Cipher"

# TLS 1.2
openssl s_client -connect target.com:443 -tls1_2 2>&1 | grep -E "Protocol|Cipher"

# TLS 1.3
openssl s_client -connect target.com:443 -tls1_3 2>&1 | grep -E "Protocol|Cipher"

# 如果旧版本连接成功，存在降级风险
```

**步骤 2：使用 Nmap 检测**

```bash
# 检测 TLS 支持的版本
nmap --script ssl-enum-ciphers -p 443 target.com

# 输出示例:
# | ssl-enum-ciphers:
# |   TLSv1.0:
# |     ciphers:
# |       TLS_RSA_WITH_AES_128_CBC_SHA
# |   TLSv1.2:
# |     ciphers:
# |       TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
# |   TLSv1.3:
# |     ciphers:
# |       TLS_AES_256_GCM_SHA384

# 如果显示 TLSv1.0/1.1，存在降级风险
```

**步骤 3：使用 testssl.sh 检测**

```bash
# 完整 TLS 检测
./testssl.sh target.com

# 仅检测协议
./testssl.sh --protocols target.com

# 检测降级攻击
./testssl.sh --poodle --beast --freak --logjam target.com
```

### 2.3.2 加密套件降级检测

**步骤 1：检测弱加密套件支持**

```bash
# 检测 RC4 支持
openssl s_client -connect target.com:443 -cipher 'RC4' 2>&1 | grep Cipher

# 检测 DES/3DES 支持
openssl s_client -connect target.com:443 -cipher 'DES:3DES' 2>&1 | grep Cipher

# 检测 MD5 MAC 支持
openssl s_client -connect target.com:443 -cipher 'MD5' 2>&1 | grep Cipher

# 检测 NULL 加密（无加密）
openssl s_client -connect target.com:443 -cipher 'NULL' 2>&1 | grep Cipher

# 检测 EXPORT 级加密（极弱）
openssl s_client -connect target.com:443 -cipher 'EXPORT' 2>&1 | grep Cipher

# 如果连接成功，存在加密套件降级风险
```

**步骤 2：使用 Nmap 检测弱套件**

```bash
# 检测弱加密套件
nmap --script ssl-enum-ciphers -p 443 target.com

# 查找以下弱套件:
# - RC4
# - DES
# - 3DES (Sweet32)
# - MD5 MAC
# - NULL
# - EXPORT
# - CBC 模式（BEAST/Lucky13）
```

**步骤 3：使用 SSL Labs 检测**

```
访问：https://www.ssllabs.com/ssltest/

输入目标域名进行检测

查看:
- 协议支持
- 加密套件列表
- 已知漏洞检测
- 总体评级
```

### 2.3.3 特定降级攻击检测

**POODLE 攻击检测（SSLv3）**

```bash
# 使用 OpenSSL 检测
openssl s_client -connect target.com:443 -ssl3 2>&1

# 如果连接成功，可能受 POODLE 攻击

# 使用 nmap 检测
nmap --script ssl-poodle -p 443 target.com

# 输出示例:
# | ssl-poodle:
# |   VULNERABLE:
# |   SSL/TLS POODLE
# |     状态：VULNERABLE
```

**BEAST 攻击检测（TLS 1.0 CBC）**

```bash
# 使用 nmap 检测
nmap --script ssl-beast -p 443 target.com

# 使用 testssl.sh
./testssl.sh --beast target.com

# 检测条件:
# - 支持 TLS 1.0
# - 使用 CBC 模式加密套件
```

**FREAK 攻击检测（出口级 RSA）**

```bash
# 使用 OpenSSL 检测
openssl s_client -connect target.com:443 -cipher 'EXPORT' 2>&1

# 使用 nmap 检测
nmap --script ssl-freak -p 443 target.com

# 使用专用工具
# https://github.com/adjoint-io/freak-check
```

**Logjam 攻击检测（弱 DH 参数）**

```bash
# 使用 nmap 检测
nmap --script ssl-dh-params -p 443 target.com

# 使用 testssl.sh
./testssl.sh --logjam target.com

# 检测条件:
# - DH 密钥交换
# - DH 参数 < 1024 位
```

**Sweet32 攻击检测（3DES/Blowfish）**

```bash
# 使用 nmap 检测
nmap --script ssl-enum-ciphers -p 443 target.com | grep -E "3DES|Blowfish"

# 使用专用工具
# https://github.com/0x09AL/sweet32

# 检测条件:
# - 支持 3DES 或 Blowfish
# - 64 位块大小
```

### 2.3.4 自动化扫描脚本

```python
#!/usr/bin/env python3
"""
TLS 降级攻击检测脚本
"""
import subprocess
import sys

class TLSDegradationScanner:
    def __init__(self, target, port=443):
        self.target = target
        self.port = port
        self.results = {
            'protocols': {},
            'ciphers': {},
            'vulnerabilities': []
        }
    
    def check_protocol(self, protocol, openssl_flag):
        """检查特定 TLS 协议版本支持"""
        try:
            result = subprocess.run(
                ['openssl', 's_client', '-connect', f'{self.target}:{self.port}', openssl_flag],
                input=b'Q',
                capture_output=True,
                timeout=10
            )
            
            output = result.stdout.decode() + result.stderr.decode()
            
            if 'Cipher' in output and 'NONE' not in output:
                self.results['protocols'][protocol] = True
                print(f"[!] {protocol} 支持 - 可能存在降级风险")
                return True
            else:
                self.results['protocols'][protocol] = False
                print(f"[-] {protocol} 不支持")
                return False
                
        except Exception as e:
            print(f"[-] {protocol} 检测失败：{e}")
            return None
    
    def check_cipher(self, cipher_name, cipher_string):
        """检查特定加密套件支持"""
        try:
            result = subprocess.run(
                ['openssl', 's_client', '-connect', f'{self.target}:{self.port}', '-cipher', cipher_string],
                input=b'Q',
                capture_output=True,
                timeout=10
            )
            
            output = result.stdout.decode() + result.stderr.decode()
            
            if 'Cipher' in output and 'NONE' not in output:
                self.results['ciphers'][cipher_name] = True
                print(f"[!] {cipher_name} 支持 - 弱加密套件")
                return True
            else:
                self.results['ciphers'][cipher_name] = False
                print(f"[-] {cipher_name} 不支持")
                return False
                
        except Exception as e:
            print(f"[-] {cipher_name} 检测失败：{e}")
            return None
    
    def check_vulnerabilities(self):
        """检查已知漏洞"""
        
        # POODLE
        if self.results['protocols'].get('SSLv3', False):
            self.results['vulnerabilities'].append('POODLE (SSLv3)')
            print("[!] 可能存在 POODLE 漏洞")
        
        # BEAST
        if self.results['protocols'].get('TLSv1.0', False):
            # 需要进一步检查 CBC 套件
            self.results['vulnerabilities'].append('Potential BEAST (TLS 1.0)')
            print("[!] 可能存在 BEAST 漏洞")
        
        # FREAK
        if self.results['ciphers'].get('EXPORT', False):
            self.results['vulnerabilities'].append('FREAK (Export cipher)')
            print("[!] 可能存在 FREAK 漏洞")
        
        # Logjam
        if self.results['ciphers'].get('DHE_EXPORT', False):
            self.results['vulnerabilities'].append('Logjam (Export DH)')
            print("[!] 可能存在 Logjam 漏洞")
        
        # Sweet32
        if self.results['ciphers'].get('3DES', False) or self.results['ciphers'].get('Blowfish', False):
            self.results['vulnerabilities'].append('Sweet32 (64-bit block cipher)')
            print("[!] 可能存在 Sweet32 漏洞")
    
    def scan(self):
        """执行完整扫描"""
        print(f"[*] 开始扫描 {self.target}:{self.port}")
        print("=" * 50)
        
        # 检测协议版本
        print("\n[1] 检测协议版本...")
        self.check_protocol('SSLv2', '-ssl2')
        self.check_protocol('SSLv3', '-ssl3')
        self.check_protocol('TLSv1.0', '-tls1')
        self.check_protocol('TLSv1.1', '-tls1_1')
        self.check_protocol('TLSv1.2', '-tls1_2')
        self.check_protocol('TLSv1.3', '-tls1_3')
        
        # 检测弱加密套件
        print("\n[2] 检测弱加密套件...")
        self.check_cipher('RC4', 'RC4')
        self.check_cipher('DES', 'DES')
        self.check_cipher('3DES', '3DES')
        self.check_cipher('MD5', 'MD5')
        self.check_cipher('NULL', 'NULL')
        self.check_cipher('EXPORT', 'EXPORT')
        self.check_cipher('DHE_EXPORT', 'EXP-DHE')
        
        # 检查已知漏洞
        print("\n[3] 检查已知漏洞...")
        self.check_vulnerabilities()
        
        # 输出报告
        print("\n" + "=" * 50)
        print("[*] 扫描完成")
        print(f"\n发现的漏洞: {len(self.results['vulnerabilities'])}")
        for vuln in self.results['vulnerabilities']:
            print(f"    - {vuln}")
        
        return self.results

# 使用示例
# scanner = TLSDegradationScanner('target.com')
# results = scanner.scan()
```

### 2.3.5 白盒测试 - 代码审计

**检查 TLS 配置：**

```python
# ❌ 不安全 - Python HTTPS 未验证证书
import ssl
import urllib.request

context = ssl._create_unverified_context()  # 禁用证书验证
response = urllib.request.urlopen('https://target.com', context=context)

# ❌ 不安全 - 允许旧协议
context = ssl.SSLContext(ssl.PROTOCOL_TLS)
context.minimum_version = ssl.TLSVersion.SSLv3  # 允许 SSLv3

# ✅ 安全 - 强制 TLS 1.2+
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.minimum_version = ssl.TLSVersion.TLSv1_2
context.verify_mode = ssl.CERT_REQUIRED
context.check_hostname = True
```

```java
// ❌ 不安全 - Java 允许旧协议
SSLContext context = SSLContext.getInstance("TLS");
context.init(null, null, null);  // 使用默认配置

// ❌ 不安全 - 禁用证书验证
TrustManager[] trustAll = new TrustManager[]{
    new X509TrustManager() {
        public void checkClientTrusted(...) {}
        public void checkServerTrusted(...) {}
        public X509Certificate[] getAcceptedIssuers() { return null; }
    }
};

// ✅ 安全 - 强制 TLS 1.2+
SSLContext context = SSLContext.getInstance("TLSv1.2");
context.init(keyManagers, trustManagers, null);
```

```python
# ❌ 不安全 - Requests 库未验证证书
import requests
response = requests.get('https://target.com', verify=False)

# ✅ 安全 - 验证证书
response = requests.get('https://target.com', verify=True)
```

**检查加密套件配置：**

```python
# ❌ 不安全 - 允许弱加密套件
import ssl
context = ssl.SSLContext(ssl.PROTOCOL_TLS)
context.set_ciphers('ALL:@SECLEVEL=0')  # 允许所有套件

# ✅ 安全 - 限制强加密套件
context.set_ciphers('ECDHE+AESGCM:DHE+AESGCM:ECDHE+CHACHA20:DHE+CHACHA20')
```

```nginx
# ❌ 不安全 - Nginx 允许弱套件
ssl_ciphers 'ALL:!aNULL:!eNULL';  # 太宽松

# ✅ 安全 - Nginx 强套件配置
ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
ssl_prefer_server_ciphers on;
```

## 2.4 漏洞利用方法

### 2.4.1 POODLE 攻击（SSLv3）

```python
#!/usr/bin/env python3
"""
POODLE 攻击实现
Padding Oracle On Downgraded Legacy Encryption
"""

def poodle_attack_info():
    """
    POODLE 攻击信息
    
    CVE: CVE-2014-3566
    发现时间：2014 年
    影响：SSLv3 协议
    """
    
    print("""
    POODLE 攻击原理:
    
    1. 攻击者强制客户端和服务器使用 SSLv3
    2. SSLv3 使用 CBC 模式加密，填充不验证
    3. 攻击者通过修改填充字节进行 Oracle 攻击
    4. 逐字节解密加密内容（如 Cookie）
    
    攻击复杂度:
    - 需要约 256 次请求解密 1 字节
    - 解密完整 Cookie 需要数千次请求
    - 需要中间人位置
    
    利用条件:
    - 服务器支持 SSLv3
    - 客户端支持 SSLv3
    - 攻击者可进行 MITM
    
    防御:
    - 禁用 SSLv3
    - 使用 TLS_FALLBACK_SCSV
    - 客户端禁用 SSLv3
    """)

def poodle_exploit_steps():
    """
    POODLE 攻击步骤
    """
    
    print("""
    攻击步骤:
    
    1. 设置中间人位置
       - ARP 欺骗
       - 恶意 WiFi
       - 路由器攻陷
    
    2. 强制 SSLv3 降级
       - 拦截 ClientHello
       - 修改支持的协议版本为 SSLv3
       - 或使用 sslstrip 类工具
    
    3. 注入恶意请求
       - 让受害者浏览器发送请求
       - 请求中包含目标 Cookie
    
    4. 执行 Padding Oracle 攻击
       - 修改密文最后一个字节
       - 观察服务器响应
       - 根据响应判断填充是否正确
    
    5. 逐字节解密
       - 对每个字节重复步骤 4
       - 平均 256 次尝试解密 1 字节
    
    工具:
    - https://github.com/mpgn/Poodle-MitM
    - https://github.com/tintinweb/ssl-poodle
    
    注意:
    - 现代系统已禁用 SSLv3
    - 此攻击主要用于历史系统测试
    """)

### 2.4.2 BEAST 攻击（TLS 1.0 CBC）

```python
#!/usr/bin/env python3
"""
BEAST 攻击实现
Browser Exploit Against SSL/TLS
"""

def beast_attack_info():
    """
    BEAST 攻击信息
    
    CVE: CVE-2011-3389
    发现时间：2011 年
    影响：TLS 1.0 及 SSL 3.0 的 CBC 模式
    """
    
    print("""
    BEAST 攻击原理:
    
    1. TLS 1.0 CBC 模式使用可预测的 IV
    2. IV 是前一个密文块
    3. 攻击者可预测下一个 IV
    4. 通过选择明文攻击解密 Cookie
    
    攻击条件:
    - 目标使用 TLS 1.0 或 SSL 3.0
    - 使用 CBC 模式加密套件
    - 攻击者可注入 JavaScript
    - 中间人位置
    
    攻击步骤:
    1. 注入恶意 JavaScript 到受害者浏览器
    2. JavaScript 发起多次 HTTPS 请求
    3. 每次请求泄露部分 Cookie
    4. 重复直到完整 Cookie 被解密
    
    防御:
    - 升级到 TLS 1.1+
    - 使用 1/n-1 记录分割
    - 使用非 CBC 套件（如 GCM）
    """)

def beast_exploit_steps():
    """
    BEAST 攻击步骤
    """
    
    print("""
    实际利用步骤:
    
    1. 设置中间人代理
       - 使用 Burp Suite 或 MITMProxy
       - 配置浏览器代理
    
    2. 注入 JavaScript
       - 修改 HTTP 响应
       - 注入恶意脚本
    
    3. JavaScript 执行选择明文攻击
       - 构造特定长度的请求
       - 使 Cookie 字节对齐到块边界
    
    4. 捕获和分析密文
       - 记录所有 HTTPS 请求
       - 分析 CBC 加密模式
    
    5. 逐字节恢复 Cookie
       - 使用预测的 IV
       - 尝试所有 256 种可能
    
    工具:
    - https://github.com/thcorg/thc-ssl-dos
    - 自定义 JavaScript
    
    注意:
    - 现代浏览器已实施缓解措施
    - 大多数服务器已升级到 TLS 1.2+
    """)

### 2.4.3 FREAK 攻击（出口级 RSA）

```python
#!/usr/bin/env python3
"""
FREAK 攻击实现
Factoring RSA Export Keys
"""

def freak_attack_info():
    """
    FREAK 攻击信息
    
    CVE: CVE-2015-0204
    发现时间：2015 年
    影响：支持 EXPORT RSA 的 TLS 实现
    """
    
    print("""
    FREAK 攻击原理:
    
    1. 历史原因，美国曾限制加密出口（≤512 位）
    2. 某些服务器仍支持 EXPORT 级 RSA
    3. 攻击者强制使用 EXPORT RSA
    4. 512 位 RSA 可被分解
    
    攻击步骤:
    1. 拦截 ClientHello
    2. 修改密码套件为 EXPORT RSA
    3. 服务器返回 512 位 RSA 密钥
    4. 分解 512 位 RSA 密钥（数小时内）
    5. 解密主密钥和会话数据
    
    攻击复杂度:
    - 分解 512 位 RSA 约需 7 小时（2015 年）
    - 使用云算力可更快
    - 分解后可解密所有会话
    
    防御:
    - 禁用 EXPORT 级加密套件
    - 使用 ≥2048 位 RSA 密钥
    - 更新 TLS 库
    """)

def freak_exploit_steps():
    """
    FREAK 攻击步骤
    """
    
    print("""
    实际利用步骤:
    
    1. 检测目标是否支持 EXPORT RSA
       openssl s_client -connect target:443 -cipher 'EXPORT'
    
    2. 设置中间人代理
       - 修改 ClientHello 中的密码套件列表
       - 仅保留 EXPORT RSA 套件
    
    3. 捕获服务器响应
       - 获取 512 位 RSA 公钥
    
    4. 分解 RSA 密钥
       - 使用 msieve 或 CADO-NFS
       - 或使用预计算的分解（如 factordb.com）
    
    5. 计算主密钥
       - 使用分解的私钥解密 Pre-Master Secret
       - 计算 Master Secret
    
    6. 解密会话数据
       - 使用 Master Secret 解密应用数据
    
    工具:
    - https://github.com/adjoint-io/freak-check
    - https://github.com/KrakenC2/freak
    
    注意:
    - 现代系统已禁用 EXPORT 套件
    - 主要用于历史系统测试
    """)

### 2.4.4 Logjam 攻击（弱 DH 参数）

```python
#!/usr/bin/env python3
"""
Logjam 攻击实现
"""

def logjam_attack_info():
    """
    Logjam 攻击信息
    
    CVE: CVE-2015-4000
    发现时间：2015 年
    影响：使用常见 DH 参数的 TLS 服务器
    """
    
    print("""
    Logjam 攻击原理:
    
    1. 许多服务器使用相同的 DH 参数（如 1024 位）
    2. 攻击者可预计算这些参数的离散对数
    3. 强制使用 EXPORT DHE
    4. 使用预计算结果快速恢复共享密钥
    
    攻击影响:
    - 1024 位 DH：国家级别可破解
    - 768 位 DH：学术团队可破解
    - 512 位 DH（EXPORT）：数小时可破解
    
    预计算成本:
    - 1024 位：约 1 亿美元（一次性）
    - 预计算后，单个连接破解仅需分钟
    
    防御:
    - 使用 ≥2048 位 DH 参数
    - 使用 ECDHE 密钥交换
    - 禁用 EXPORT DHE 套件
    """)

def logjam_detection():
    """
    Logjam 漏洞检测
    """
    
    print("""
    检测方法:
    
    1. 使用 nmap 检测
       nmap --script ssl-dh-params -p 443 target.com
    
    2. 使用 testssl.sh
       ./testssl.sh --logjam target.com
    
    3. 使用 OpenSSL 检查
       openssl s_client -connect target:443 -cipher 'DHE'
       # 查看 Server Key Exchange 中的 DH 参数大小
    
    4. 在线检测
       https://weakdh.org/
    
    修复:
    - 生成新的 2048 位 DH 参数
      openssl dhparam -out dhparam.pem 2048
    - 配置服务器使用新参数
    - 或切换到 ECDHE
    """)

### 2.4.5 Sweet32 攻击（64 位块加密）

```python
#!/usr/bin/env python3
"""
Sweet32 攻击实现
"""

def sweet32_attack_info():
    """
    Sweet32 攻击信息
    
    CVE: CVE-2016-2183
    发现时间：2016 年
    影响：使用 64 位块加密的 TLS（3DES、Blowfish）
    """
    
    print("""
    Sweet32 攻击原理:
    
    1. 64 位块加密（如 3DES）块空间为 2^64
    2. 生日悖论：2^32 次加密后碰撞概率 50%
    3. 长时间连接可收集足够密文块
    4. 碰撞导致信息泄露
    
    攻击条件:
    - 服务器支持 3DES 或 Blowfish
    - 长连接（大量数据）
    - 中间人位置
    
    攻击步骤:
    1. 建立长连接
    2. 注入已知数据（如 HTTP 头）
    3. 收集约 2^32 个密文块（约 32GB）
    4. 检测块碰撞
    5. 推断未知数据（如 Cookie）
    
    防御:
    - 禁用 3DES 和 Blowfish
    - 使用 AES（128 位块）
    - 限制连接时长/数据量
    """)

def sweet32_detection():
    """
    Sweet32 漏洞检测
    """
    
    print("""
    检测方法:
    
    1. 使用 nmap 检测
       nmap --script ssl-enum-ciphers -p 443 target.com | grep -E "3DES|Blowfish"
    
    2. 使用 testssl.sh
       ./testssl.sh target.com | grep -i sweet32
    
    3. 使用专用工具
       https://github.com/0x09AL/sweet32
    
    4. OpenSSL 检查
       openssl s_client -connect target:443 -cipher '3DES'
       openssl s_client -connect target:443 -cipher 'Blowfish'
    
    修复:
    - 从配置中移除 3DES 和 Blowfish
    - 优先使用 AES-GCM
    """)

### 2.4.6 自定义协议降级攻击

```python
#!/usr/bin/env python3
"""
自定义协议降级攻击
"""

def custom_protocol_downgrade():
    """
    自定义协议降级攻击场景
    """
    
    print("""
    场景 1: 版本协商降级
    
    描述:
    - 应用支持多版本协议
    - 客户端和服务器协商版本
    - 未强制选择最高版本
    
    利用:
    1. 拦截版本协商消息
    2. 修改支持的最高版本为旧版本
    3. 利用旧版本已知漏洞
    
    示例:
    - SSH-2 → SSH-1
    - SMB3 → SMB1 (EternalBlue)
    - HTTP/2 → HTTP/1.1
    
    防御:
    - 强制最高版本
    - 禁用旧版本
    - 版本签名验证
    """)
    
    print("""
    场景 2: 认证机制降级
    
    描述:
    - 支持多种认证方式
    - 协商选择认证方式
    - 可降级到弱认证
    
    利用:
    1. 拦截认证协商
    2. 强制使用弱认证（如明文密码）
    3. 窃取凭证
    
    示例:
    - NTLMv2 → LM
    - Kerberos → NTLM
    - MFA → 单因素
    
    防御:
    - 禁用弱认证机制
    - 强制强认证
    - 认证方式签名
    """)
    
    print("""
    场景 3: 加密算法协商降级
    
    描述:
    - 应用层支持多种加密算法
    - 客户端和服务器协商
    - 可选择弱算法
    
    利用:
    1. 拦截算法协商
    2. 强制使用弱算法
    3. 破解加密
    
    示例:
    - Signal 协议降级
    - OTR 降级
    - PGP 降级
    
    防御:
    - 强制最强算法
    - 算法选择签名
    - 降级检测机制
    """)

## 2.5 漏洞利用绕过方法

### 2.5.1 绕过 TLS 版本检查

```python
#!/usr/bin/env python3
"""
绕过 TLS 版本检查的技术
"""

def bypass_tls_version_check():
    """
    TLS 版本检查绕过方法
    """
    
    print("""
    方法 1: TLS_FALLBACK_SCSV 绕过
    
    描述:
    - TLS_FALLBACK_SCSV 用于检测降级
    - 某些实现检查不严格
    
    利用:
    1. 不使用 TLS_FALLBACK_SCSV
    2. 直接发送旧版本 ClientHello
    3. 某些服务器仍接受
    
    防御:
    - 严格实施 TLS_FALLBACK_SCSV
    - 拒绝无 SCSV 的旧版本连接
    """)
    
    print("""
    方法 2: 分片攻击
    
    描述:
    - ClientHello 分多个包发送
    - 某些实现仅检查第一个包
    
    利用:
    1. 第一个包包含新版本
    2. 后续包修改为旧版本
    3. 绕过版本检查
    
    防御:
    - 完整解析 ClientHello
    - 验证所有分片
    """)
    
    print("""
    方法 3: 会话恢复绕过
    
    描述:
    - 会话恢复可能跳过某些检查
    - 使用旧会话可能使用旧协议
    
    利用:
    1. 建立新连接获取会话
    2. 使用会话恢复连接
    3. 可能降级协议
    
    防御:
    - 会话绑定协议版本
    - 恢复时重新验证
    """)

### 2.5.2 绕过加密套件检查

```python
#!/usr/bin/env python3
"""
绕过加密套件检查的技术
"""

def bypass_cipher_suite_check():
    """
    加密套件检查绕过方法
    """
    
    print("""
    方法 1: 套件优先级操纵
    
    描述:
    - 服务器配置套件优先级
    - 客户端可影响选择
    
    利用:
    1. 仅发送弱套件在 ClientHello
    2. 服务器被迫选择弱套件
    3. 即使配置了强套件
    
    防御:
    - 服务器强制套件优先级
    - 拒绝弱套件连接
    """)
    
    print("""
    方法 2: 套件重排序
    
    描述:
    - ClientHello 中套件有顺序
    - 某些服务器选择第一个匹配
    
    利用:
    1. 将弱套件放在列表前面
    2. 服务器选择第一个匹配
    3. 忽略更强套件
    
    防御:
    - 服务器强制自己的优先级
    - 选择最强匹配套件
    """)
    
    print("""
    方法 3: 未知套件利用
    
    描述:
    - 发送未知/私有套件
    - 某些服务器回退到弱套件
    
    利用:
    1. 发送未知套件 ID
    2. 服务器无法识别
    3. 回退到默认/弱套件
    
    防御:
    - 严格套件白名单
    - 未知套件拒绝
    """)

### 2.5.3 绕过降级检测

```python
#!/usr/bin/env python3
"""
绕过降级检测的技术
"""

def bypass_downgrade_detection():
    """
    降级检测绕过方法
    """
    
    print("""
    方法 1: 选择性降级
    
    描述:
    - 仅对特定流量降级
    - 正常流量保持强加密
    
    利用:
    1. 检测敏感流量（登录、支付）
    2. 仅对这些流量降级
    3. 降低被检测概率
    
    防御:
    - 持续监控协议版本
    - 异常检测
    """)
    
    print("""
    方法 2: 时间窗口攻击
    
    描述:
    - 降级检测有延迟
    - 利用时间窗口
    
    利用:
    1. 快速完成降级攻击
    2. 在检测前完成
    3. 清理痕迹
    
    防御:
    - 实时检测
    - 自动阻断
    """)
    
    print("""
    方法 3: 日志规避
    
    描述:
    - 降级可能被记录
    - 规避日志记录
    
    利用:
    1. 利用不记录详细 TLS 信息的配置
    2. 清除或修改日志
    3. 使用加密通道隐藏
    
    防御:
    - 详细 TLS 日志
    - 日志完整性保护
    - 远程日志存储
    """)

---

# 第三部分：附录

## 3.1 常用 Payload 速查表

| 类别 | 命令/代码 | 说明 |
|-----|----------|------|
| 检测 | `openssl s_client -connect target:443 -tls1` | TLS 1.0 检测 |
| 检测 | `nmap --script ssl-enum-ciphers -p 443` | 加密套件枚举 |
| 检测 | `./testssl.sh target.com` | 完整 TLS 检测 |
| POODLE | `nmap --script ssl-poodle -p 443` | POODLE 检测 |
| BEAST | `nmap --script ssl-beast -p 443` | BEAST 检测 |
| FREAK | `openssl s_client -cipher 'EXPORT'` | FREAK 检测 |
| Logjam | `nmap --script ssl-dh-params` | Logjam 检测 |
| Sweet32 | `openssl s_client -cipher '3DES'` | Sweet32 检测 |

## 3.2 安全 TLS 配置建议

**推荐协议版本:**
- ✅ TLS 1.2（最低）
- ✅ TLS 1.3（推荐）
- ❌ TLS 1.0/1.1（禁用）
- ❌ SSL 2.0/3.0（禁用）

**推荐加密套件 (TLS 1.2):**
```
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
```

**推荐加密套件 (TLS 1.3):**
```
TLS_AES_256_GCM_SHA384
TLS_AES_128_GCM_SHA256
TLS_CHACHA20_POLY1305_SHA256
```

**禁用加密套件:**
- ❌ RC4
- ❌ DES/3DES
- ❌ MD5 MAC
- ❌ NULL
- ❌ EXPORT
- ❌ CBC 模式（优先）

## 3.3 降级攻击检测清单

- [ ] 检测 SSLv2/SSLv3 支持
- [ ] 检测 TLS 1.0/1.1 支持
- [ ] 检测弱加密套件支持
- [ ] 检测 EXPORT 级加密
- [ ] 检测 DH 参数强度
- [ ] 检测证书链完整性
- [ ] 检测 HSTS 配置
- [ ] 检测 TLS_FALLBACK_SCSV
- [ ] 检测已知漏洞（POODLE/BEAST/FREAK/Logjam/Sweet32）

## 3.4 常用工具

| 工具 | 用途 | 链接 |
|-----|------|------|
| OpenSSL | TLS 客户端测试 | https://openssl.org/ |
| Nmap | 端口和服务扫描 | https://nmap.org/ |
| testssl.sh | TLS 配置检测 | https://testssl.sh/ |
| SSL Labs | 在线 TLS 测试 | https://ssllabs.com/ |
| Wireshark | TLS 流量分析 | https://wireshark.org/ |
| ssl-poodle | POODLE 检测 | https://github.com/tintinweb/ssl-poodle |
| sweet32 | Sweet32 检测 | https://github.com/0x09AL/sweet32 |

## 3.5 合规要求

| 标准 | 加密要求 |
|-----|---------|
| PCI DSS 3.2.1 | TLS 1.2+，禁用 SSL/早期 TLS |
| NIST SP 800-52 | TLS 1.2+，特定套件 |
| HIPAA | 传输加密，推荐 TLS 1.2+ |
| GDPR | 适当加密，推荐 TLS 1.2+ |

---

## 参考资源

- [CWE-757: Selection of Less-Secure Algorithm During Negotiation](https://cwe.mitre.org/data/definitions/757.html)
- [OWASP TLS Configuration Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html)
- [RFC 7507: TLS Fallback Signaling Cipher Suite Value](https://tools.ietf.org/html/rfc7507)
- [RFC 8446: TLS 1.3](https://tools.ietf.org/html/rfc8446)
- [WeakDH.org](https://weakdh.org/) - Logjam 攻击信息
- [Sweet32.org](https://sweet32.info/) - Sweet32 攻击信息
