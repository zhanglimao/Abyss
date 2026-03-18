# 后量子加密迁移指南

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供后量子加密（PQC）迁移相关的安全评估方法论。随着 NIST 于 2024 年 8 月发布首批三项后量子加密标准，组织开始向 PQC 迁移。本指南帮助测试人员识别迁移过程中的安全风险、配置错误和潜在攻击面。

## 1.2 适用范围

本文档适用于以下场景：
- 评估组织的 PQC 迁移准备状态
- 检测混合加密方案实现缺陷
- 测试 PQC 算法配置安全性
- 审计密钥管理系统的 PQC 兼容性
- 识别"现在收集，以后解密"攻击风险

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、密码学安全评估人员、合规性审计人员。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 背景

**量子计算威胁**：
- 足够强大的量子计算机可使用 Shor 算法快速破解 RSA、ECC 等公钥加密
- 专家预测具有破解能力的量子计算机可能在 10-15 年内出现
- "现在收集，以后解密"攻击：攻击者现在截获加密流量，待量子计算机可用后解密

**NIST PQC 标准化进程**：
- 2016 年：公开征集后量子加密算法
- 2022 年：选出 4 个算法进行标准化
- **2024 年 8 月**：发布 3 项最终标准

### NIST  finalized 标准

| 标准编号 | 算法名称 | 原名 | 用途 | 数学基础 | 安全级别 |
|---------|---------|------|------|---------|---------|
| **FIPS 203** | ML-KEM | CRYSTALS-Kyber | 密钥封装 (KEM) | 模块格 (Module-Lattice) | 128/192/256 位 |
| **FIPS 204** | ML-DSA | CRYSTALS-Dilithium | 数字签名 | 模块格 (Module-Lattice) | 128/192/256 位 |
| **FIPS 205** | SLH-DSA | Sphincs+ | 数字签名 (备份) | 无状态哈希 | 128/192/256 位 |

### PQC 迁移策略

**混合加密方案**：
```
传统加密 + PQC = 混合方案
- 同时使用传统算法 (如 X25519) 和 PQC 算法 (如 Kyber)
- 即使一种算法被攻破，另一种仍提供保护
- 迁移期间的推荐方案
```

**迁移时间线（ENISA 建议）**：
| 时间 | 目标 |
|------|------|
| 2024-2025 | 加密资产清单、风险评估 |
| 2025-2027 | 高价值系统 PQC 试点 |
| 2027-2030 | 大规模 PQC 部署 |
| 2030+ | 完成迁移，淘汰传统算法 |

### 常见 CWE 映射

| CWE 编号 | 描述 | PQC 关联 |
|---------|------|---------|
| CWE-326 | 加密强度不足 | 传统算法不足以抵抗量子攻击 |
| CWE-327 | 使用已损坏或有风险的加密算法 | RSA/ECC 在量子计算时代不安全 |
| CWE-1240 | 使用具有风险实现的加密原语 | PQC 实现可能存在侧信道漏洞 |
| CWE-757 | 算法降级 | 混合方案可能被降级到传统加密 |

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 | 潜在危害 |
|---------|---------|-----------|---------|
| **TLS 1.3 PQC 扩展** | 支持 Kyber 的 HTTPS | 混合方案配置错误 | 降级攻击、密钥泄露 |
| **代码签名** | 使用 Dilithium 签名 | 签名验证逻辑缺陷 | 恶意代码注入 |
| **文档签名** | PDF/Office PQC 签名 | 验证绕过 | 文档伪造 |
| **密钥封装** | PQC KEM 密钥交换 | 封装/解封装缺陷 | 会话密钥泄露 |
| **区块链/加密货币** | PQC 钱包签名 | 签名方案迁移缺陷 | 资金盗窃 |
| **IoT 设备固件** | PQC 固件签名验证 | 验证逻辑缺陷 | 固件篡改 |
| **云 KMS** | PQC 密钥管理服务 | IAM 配置错误 | 密钥泄露 |
| **VPN 服务** | PQC 隧道建立 | 协议降级 | 流量解密 |
| **即时通讯** | PQC 端到端加密 | 降级到传统加密 | 通信窃听 |
| **证书颁发** | PQC 证书链 | 信任链验证缺陷 | 证书伪造 |

## 2.3 漏洞检测方法

### 2.3.1 PQC 支持检测

**TLS PQC 扩展检测**：

```bash
# 检测 TLS PQC 支持（使用支持 PQC 的 OpenSSL 分支）
# 注意：标准 OpenSSL 尚未支持 PQC，需使用 OQS-OpenSSL

# 使用 OQS-OpenSSL 检测 Kyber 支持
oqsopenssl s_client -connect target.com:443 \
    -groups X25519Kyber768 \
    2>&1 | grep -E "Protocol|Cipher|Group"

# 如果连接成功，说明支持混合 PQC 密钥交换
```

**Nmap PQC 检测脚本**：

```bash
# 自定义 Nmap NSE 脚本检测 PQC 支持
# pqc-detect.nse

local shortname = "pqc-detect"
local nmap = require "nmap"
local shortport = require "shortport"
local tls = require "tls"

description = [[
检测 TLS 服务是否支持后量子加密 (PQC) 扩展
]]

author = "Security Team"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.ssl

action = function(host, port)
    local pqc_groups = {
        "X25519Kyber512",
        "X25519Kyber768",
        "X25519Kyber1024",
        "secp256r1Kyber512",
        "secp384r1Kyber768",
    }
    
    local output = {}
    table.insert(output, "PQC 支持检测:")
    
    -- 检测 PQC 密钥交换组
    for _, group in ipairs(pqc_groups) do
        -- 尝试使用 PQC 组建立连接
        -- 实现细节省略
        table.insert(output, "  - " .. group .. ": 检测中...")
    end
    
    return table.concat(output, "\n")
end

-- 使用
nmap --script pqc-detect.nse -p 443 target.com
```

**浏览器 PQC 支持检测**：

```javascript
// 使用 JavaScript 检测浏览器 PQC 支持
// 注意：目前仅 Chrome/Edge 实验性支持

async function detectPQCSupport() {
    console.log("[*] 检测浏览器 PQC 支持...");
    
    // 检测 TLS 1.3 PQC 扩展支持
    // 通过尝试建立 PQC 连接检测
    
    const pqcIndicators = {
        chrome116Plus: navigator.userAgent.includes('Chrome/116') || 
                       navigator.userAgent.includes('Chrome/117') ||
                       navigator.userAgent.includes('Chrome/118+'),
        edgePQC: navigator.userAgent.includes('Edg/') && 
                 navigator.userAgent.match(/Edg\/(\d+)/)?.[1] >= 116,
    };
    
    console.log("浏览器 PQC 支持指标:", pqcIndicators);
    
    // 实际检测需要尝试 PQC 连接
    // 这通常需要原生代码或 WebAssembly
    
    return pqcIndicators;
}

// 使用
detectPQCSupport();
```

### 2.3.2 混合方案配置检测

**检测混合加密配置**：

```python
#!/usr/bin/env python3
"""
混合加密方案配置检测
"""
import ssl
import socket

def detect_hybrid_crypto_config(target, port=443):
    """检测混合加密配置"""
    
    print("[*] 混合加密方案检测")
    
    # PQC 混合密钥交换组
    pqc_hybrid_groups = [
        "X25519Kyber512",
        "X25519Kyber768",  # 最常用
        "X25519Kyber1024",
        "secp256r1Kyber512",
        "secp384r1Kyber768",
    ]
    
    issues = []
    
    # 检测 1: 是否仅使用传统加密
    print("\n[1] 检测传统加密依赖...")
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        # 仅允许传统密钥交换
        context.set_ecdh_curve('X25519')
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        
        with context.wrap_socket(sock, server_hostname=target) as ssock:
            print(f"    [i] 传统加密连接成功")
            print(f"        协议：{ssock.version()}")
            print(f"        加密套件：{ssock.cipher()}")
            
    except Exception as e:
        print(f"    [-] 传统加密连接失败：{e}")
    
    # 检测 2: 是否支持 PQC 降级
    print("\n[2] 检测 PQC 降级风险...")
    print("    [i] 如果同时支持传统和 PQC，需验证降级保护")
    
    # 检测 3: 检查证书链
    print("\n[3] 检测证书链 PQC 兼容性...")
    try:
        context = ssl.create_default_context()
        with socket.create_connection((target, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                print(f"    [i] 证书颁发者：{cert.get('issuer', {})}")
                print(f"    [i] 签名算法：{cert.get('signatureAlgorithm', 'Unknown')}")
                
    except Exception as e:
        print(f"    [-] 证书检测失败：{e}")
    
    return issues

# 使用示例
# detect_hybrid_crypto_config('target.com')
```

### 2.3.3 PQC 实现安全性检测

**侧信道漏洞检测**：

```python
#!/usr/bin/env python3
"""
PQC 实现侧信道漏洞检测
"""
import time
import statistics

def timing_attack_detection(target_func, inputs, iterations=100):
    """
    时序攻击检测
    
    检测 PQC 实现是否存在时序侧信道漏洞
    """
    
    print("[*] 时序侧信道检测")
    
    timing_results = {}
    
    for input_data in inputs:
        times = []
        
        for _ in range(iterations):
            start = time.perf_counter_ns()
            target_func(input_data)
            end = time.perf_counter_ns()
            
            times.append(end - start)
        
        # 移除异常值
        times.sort()
        trimmed_times = times[5:-5]  # 去掉前后 5%
        
        avg_time = statistics.mean(trimmed_times)
        std_dev = statistics.stdev(trimmed_times) if len(trimmed_times) > 1 else 0
        
        input_hash = hash(str(input_data)) % 1000
        timing_results[input_hash] = {
            'avg': avg_time,
            'std': std_dev,
            'count': len(trimmed_times)
        }
    
    # 分析时序差异
    avg_times = [r['avg'] for r in timing_results.values()]
    max_diff = max(avg_times) - min(avg_times)
    
    print(f"\n    最大时序差异：{max_diff} ns")
    
    if max_diff > 1000:  # 大于 1 微秒的差异可能可利用
        print("    [!] 发现显著时序差异 - 可能存在侧信道漏洞")
        return True
    else:
        print("    [-] 未发现显著时序差异")
        return False

def power_analysis_detection_info():
    """
    功耗分析攻击信息
    """
    
    print("""
    功耗分析攻击 (Power Analysis Attack):
    
    原理:
    - PQC 算法（尤其是格基算法）的功耗模式可能泄露密钥信息
    - 简单功耗分析 (SPA): 直接观察功耗轨迹
    - 差分功耗分析 (DPA): 统计分析多个轨迹
    
    PQC 算法风险:
    - Kyber: 多项式乘法可能泄露信息
    - Dilithium: 拒绝采样可能泄露信息
    
    检测条件:
    - 需要物理访问设备
    - 需要专业设备（示波器等）
    
    防御:
    - 恒定时间实现
    - 功耗均衡技术
    - 随机化操作顺序
    """)
```

### 2.3.4 自动化 PQC 审计脚本

```python
#!/usr/bin/env python3
"""
PQC 安全审计自动化脚本
"""
import subprocess
import json
from datetime import datetime

class PQCAuditor:
    def __init__(self, target):
        self.target = target
        self.report = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'findings': [],
            'recommendations': []
        }
    
    def check_crypto_inventory(self):
        """检查加密资产清单"""
        
        print("[*] 检查加密资产清单...")
        
        finding = {
            'id': 'PQC-001',
            'title': '加密资产清单',
            'severity': 'INFO',
            'details': []
        }
        
        # 检查证书
        try:
            result = subprocess.run(
                ['openssl', 's_client', '-connect', f'{self.target}:443'],
                input=b'Q', capture_output=True, timeout=10
            )
            
            output = result.stdout.decode()
            
            if 'Certificate chain' in output:
                finding['details'].append('发现 SSL/TLS 证书')
            
            # 提取证书信息
            if 'Server certificate' in output:
                finding['details'].append('证书可获取')
                
        except Exception as e:
            finding['details'].append(f'证书检测失败：{e}')
        
        self.report['findings'].append(finding)
    
    def check_quantum_readiness(self):
        """检查量子就绪状态"""
        
        print("[*] 检查量子就绪状态...")
        
        finding = {
            'id': 'PQC-002',
            'title': '量子就绪评估',
            'severity': 'MEDIUM',
            'details': []
        }
        
        # 检查是否仅使用传统加密
        traditional_algorithms = [
            'RSA', 'ECDSA', 'ECDH', 'X25519', 'X448',
            'secp256r1', 'secp384r1', 'secp521r1'
        ]
        
        finding['details'].append('检测到以下传统算法依赖风险:')
        for algo in traditional_algorithms[:3]:  # 示例
            finding['details'].append(f'  - {algo}: 易受量子攻击')
        
        finding['details'].append('')
        finding['details'].append('建议:')
        finding['details'].append('  - 开始 PQC 迁移规划')
        finding['details'].append('  - 评估混合加密方案')
        finding['details'].append('  - 参考 NIST FIPS 203/204/205')
        
        self.report['findings'].append(finding)
    
    def check_harvest_now_decrypt_later_risk(self):
        """检查'现在收集，以后解密'风险"""
        
        print("[*] 评估'现在收集，以后解密'攻击风险...")
        
        finding = {
            'id': 'PQC-003',
            'title': 'Harvest Now, Decrypt Later 风险',
            'severity': 'HIGH',
            'details': []
        }
        
        finding['details'].append('风险分析:')
        finding['details'].append('  - 攻击者现在可截获加密流量')
        finding['details'].append('  - 未来量子计算机可解密历史流量')
        finding['details'].append('  - 长期敏感数据面临风险')
        finding['details'].append('')
        finding['details'].append('受影响数据类型:')
        finding['details'].append('  - 国家机密')
        finding['details'].append('  - 商业机密')
        finding['details'].append('  - 个人健康信息')
        finding['details'].append('  - 金融交易数据')
        finding['details'].append('')
        finding['details'].append('缓解措施:')
        finding['details'].append('  - 优先迁移高价值数据的加密')
        finding['details'].append('  - 实施 PQC 混合方案')
        finding['details'].append('  - 缩短密钥有效期')
        
        self.report['findings'].append(finding)
    
    def generate_report(self):
        """生成审计报告"""
        
        print("\n" + "=" * 60)
        print("PQC 安全审计报告")
        print("=" * 60)
        
        for finding in self.report['findings']:
            print(f"\n[{finding['severity']}] {finding['id']}: {finding['title']}")
            for detail in finding['details']:
                print(f"    {detail}")
        
        print("\n" + "=" * 60)
        print("审计完成")
        
        return self.report

# 使用示例
# auditor = PQCAuditor('target.com')
# auditor.check_crypto_inventory()
# auditor.check_quantum_readiness()
# auditor.check_harvest_now_decrypt_later_risk()
# auditor.generate_report()
```

## 2.4 漏洞利用方法

### 2.4.1 混合方案降级攻击

```python
#!/usr/bin/env python3
"""
混合加密方案降级攻击
"""

def hybrid_downgrade_attack_info():
    """
    混合方案降级攻击信息
    """
    
    print("""
    攻击场景：混合 PQC 方案降级
    
    前提条件:
    - 目标支持混合加密 (传统 + PQC)
    - 降级保护实施不当
    - 客户端/服务器配置不一致
    
    攻击步骤:
    
    1. 拦截 ClientHello
       - 修改支持的密钥交换组
       - 移除 PQC 组，仅保留传统组
    
    2. 强制传统加密
       - 服务器回退到传统密钥交换
       - 无降级警告
    
    3. 利用传统加密弱点
       - 记录加密流量
       - 等待量子计算机可用后解密
    
    防御措施:
    - 实施 TLS_FALLBACK_SCSV 类似机制
    - 客户端记住服务器的 PQC 能力
    - 拒绝无解释的协议降级
    """)

def hybrid_downgrade_exploit():
    """
    混合降级攻击概念验证
    """
    
    print("""
    概念验证步骤:
    
    1. 设置中间人代理
       mitmproxy --mode transparent
    
    2. 修改 TLS 握手
       - 拦截 ClientHello
       - 移除 supported_groups 中的 PQC 组
       - 转发修改后的 ClientHello
    
    3. 观察服务器响应
       - 如果服务器接受降级，记录
       - 检查是否有降级警告
    
    4. 建立连接
       - 完成握手
       - 记录加密流量
    
    5. 分析
       - 确认使用的是传统加密
       - 评估"现在收集，以后解密"价值
    
    工具:
    - mitmproxy
    - 自定义 TLS 栈
    - OQS-OpenSSL
    """)
```

### 2.4.2 PQC 实现侧信道攻击

```python
#!/usr/bin/env python3
"""
PQC 实现侧信道攻击
"""

def side_channel_attack_info():
    """
    PQC 侧信道攻击信息
    """
    
    print("""
    针对 Kyber 的侧信道攻击:
    
    1. 时序攻击 (Timing Attack)
       
       原理:
       - Kyber 解密操作时间可能依赖于密钥
       - 特别是去封装 (decapsulation) 操作
       
       攻击步骤:
       a. 发送大量密文
       b. 精确测量解密时间
       c. 统计分析时间差异
       d. 推断密钥信息
       
       已知攻击:
       - 2022 年：针对 Kyber 参考实现的时序攻击
       - 需要约 10^6 次测量
    
    2. 功耗分析 (Power Analysis)
       
       原理:
       - 格基操作功耗模式泄露信息
       - 多项式乘法、拒绝采样等
       
       攻击步骤:
       a. 物理访问设备
       b. 连接示波器测量功耗
       c. 统计分析功耗轨迹
       d. 恢复密钥
       
       防御:
       - 恒定时间实现
       - 功耗均衡
       - 随机化
    
    3. 电磁分析 (EM Analysis)
       
       原理:
       - 电磁辐射泄露操作信息
       - 类似功耗分析
       
       防御:
       - 电磁屏蔽
       - 随机化操作
    """)

def cache_timing_attack():
    """
    缓存时序攻击
    """
    
    print("""
    针对 PQC 的缓存时序攻击:
    
    原理:
    - PQC 算法访问模式可能泄露信息
    - 缓存命中/未命中产生时序差异
    
    攻击 Kyber:
    1. 监控缓存访问模式
    2. 推断多项式系数
    3. 恢复密钥
    
    防御:
    - 恒定内存访问模式
    - 缓存预填充
    - 避免密钥依赖分支
    """)
```

### 2.4.3 证书链攻击

```python
#!/usr/bin/env python3
"""
PQC 证书链攻击
"""

def pqc_certificate_chain_attack():
    """
    PQC 证书链攻击场景
    """
    
    print("""
    攻击场景 1: 混合证书链降级
    
    描述:
    - 证书链包含传统和 PQC 签名
    - 验证逻辑可能仅检查部分链
    
    攻击:
    1. 拦截证书链
    2. 移除 PQC 证书
    3. 仅呈现传统证书
    4. 如果验证通过，降级成功
    
    防御:
    - 强制验证完整证书链
    - 拒绝不完整的混合链
    """)
    
    print("""
    攻击场景 2: PQC 签名验证绕过
    
    描述:
    - PQC 签名验证实现缺陷
    - 某些边界条件未正确处理
    
    攻击:
    1. 构造特殊签名
    2. 利用验证逻辑缺陷
    3. 绕过签名验证
    
    已知问题:
    - Dilithium 实现中的边界检查问题
    - 签名长度验证缺陷
    
    防御:
    - 严格验证签名格式
    - 使用经过审计的库
    """)
```

### 2.4.4 密钥封装攻击

```python
#!/usr/bin/env python3
"""
PQC 密钥封装攻击
"""

def kem_attack_info():
    """
    密钥封装机制 (KEM) 攻击信息
    """
    
    print("""
    针对 Kyber KEM 的攻击:
    
    1. 解密失败攻击 (Decryption Failure Attack)
       
       原理:
       - Kyber 解密有极小概率失败
       - 失败模式可能泄露密钥信息
       
       攻击:
       a. 发送大量精心构造的密文
       b. 观察解密是否失败
       c. 从失败模式推断密钥
       
       复杂度:
       - 需要约 2^139 次尝试 (不可行)
       - 但实现缺陷可能降低复杂度
    
    2. 密钥恢复攻击
       
       原理:
       - 某些 KEM 实现缺陷
       - 重放攻击、密钥重用等
       
       攻击:
       a. 捕获封装的密钥
       b. 利用实现缺陷
       c. 恢复共享密钥
    
    3. 混合 KEM 攻击
       
       原理:
       - 混合 KEM 结合传统和 PQC
       - 如果传统部分被攻破，整体安全性降低
       
       防御:
       - 确保两种 KEM 独立
       - 使用 XOR 组合共享密钥
    """)
```

## 2.5 安全配置建议

### 2.5.1 PQC 迁移最佳实践

```
迁移策略:

1. 加密资产清单
   - 识别所有使用公钥加密的系统
   - 评估量子脆弱性
   - 确定迁移优先级

2. 混合方案部署
   - 同时使用传统和 PQC 算法
   - 确保独立安全性
   - 正确组合共享密钥

3. 渐进式迁移
   - 先试点高价值系统
   - 逐步扩大范围
   - 监控兼容性问题

4. 传统算法淘汰
   - 设定淘汰时间表
   - 更新依赖库
   - 测试回退机制
```

### 2.5.2 PQC 配置检查清单

**TLS PQC 配置:**
- [ ] 支持 X25519Kyber768 混合组
- [ ] 实施降级保护
- [ ] 配置适当的 KEM 参数
- [ ] 测试与传统客户端兼容性

**证书配置:**
- [ ] 使用 PQC 签名算法 (ML-DSA)
- [ ] 维护混合证书链
- [ ] 正确配置证书扩展
- [ ] 测试证书验证

**密钥管理:**
- [ ] 安全生成 PQC 密钥
- [ ] 正确存储 PQC 私钥
- [ ] 实施密钥轮换
- [ ] 审计密钥使用

**实现安全:**
- [ ] 使用经过审计的 PQC 库
- [ ] 恒定时间实现
- [ ] 侧信道防护
- [ ] 错误处理安全

---

## 第三部分：附录

### 3.1 PQC 工具列表

| 工具 | 用途 | 链接 |
|-----|------|------|
| OQS-OpenSSL | PQC 扩展 OpenSSL | https://github.com/open-quantum-safe/oqs-openssl |
| liboqs | 开源 PQC 库 | https://github.com/open-quantum-safe/liboqs |
| PQClean | 清洁 PQC 实现 | https://github.com/PQClean/PQClean |
| NIST PQC | NIST 标准参考 | https://csrc.nist.gov/projects/post-quantum-cryptography |

### 3.2 PQC 算法参数

**ML-KEM (Kyber) 参数:**

| 变体 | 安全级别 | 公钥大小 | 私钥大小 | 密文大小 |
|------|---------|---------|---------|---------|
| ML-KEM-512 | 128 位 | 800 字节 | 1632 字节 | 768 字节 |
| ML-KEM-768 | 192 位 | 1184 字节 | 2400 字节 | 1088 字节 |
| ML-KEM-1024 | 256 位 | 1568 字节 | 3168 字节 | 1568 字节 |

**ML-DSA (Dilithium) 参数:**

| 变体 | 安全级别 | 公钥大小 | 私钥大小 | 签名大小 |
|------|---------|---------|---------|---------|
| ML-DSA-44 | 128 位 | 1312 字节 | 2400 字节 | 2420 字节 |
| ML-DSA-65 | 192 位 | 1952 字节 | 4000 字节 | 3309 字节 |
| ML-DSA-87 | 256 位 | 2592 字节 | 4864 字节 | 4595 字节 |

### 3.3 迁移时间线参考

**ENISA 建议时间线:**
- 2024-2025: 准备阶段（清单、风险评估）
- 2025-2027: 试点阶段（高价值系统）
- 2027-2030: 部署阶段（大规模迁移）
- 2030+: 完成阶段（淘汰传统算法）

**NIST 建议:**
- 立即开始规划
- 2030 年前完成高风险系统迁移
- 2033 年前完成所有系统迁移

---

## 参考资源

- [NIST PQC 项目](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [FIPS 203 ML-KEM 标准](https://csrc.nist.gov/publications/detail/fips/203/final)
- [FIPS 204 ML-DSA 标准](https://csrc.nist.gov/publications/detail/fips/204/final)
- [FIPS 205 SLH-DSA 标准](https://csrc.nist.gov/publications/detail/fips/205/final)
- [ENISA PQC 迁移路线图](https://www.enisa.europa.eu/topics/cybersecurity-strategy/post-quantum-cryptography)
- [Cloudflare PQC 实验](https://blog.cloudflare.com/post-quantum-for-all/)
