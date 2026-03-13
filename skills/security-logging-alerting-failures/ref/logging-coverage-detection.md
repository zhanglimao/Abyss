# 日志覆盖检测 (Logging Coverage Detection)

---

## 第一部分：文档概述

### 1.1 编写目的
本文档旨在为渗透测试人员提供日志覆盖范围检测的系统化方法论，帮助测试人员评估目标系统的日志记录完整性和覆盖范围。

### 1.2 适用范围
本文档适用于以下场景：
- Web 应用日志覆盖评估
- API 接口日志记录测试
- 认证授权日志检测
- 关键业务操作日志验证

### 1.3 读者对象
- 渗透测试工程师
- 安全审计人员
- 安全运营分析师
- 合规性评估人员

---

## 第二部分：核心渗透技术专题

### 2.1 技术介绍

日志覆盖检测是指系统性地测试和评估目标系统对各种操作和事件的日志记录能力，识别日志记录盲区和不足。

**核心原理：**
- **输入点映射**：识别所有可能的用户输入点
- **操作分类**：将操作分为认证、授权、数据访问等类别
- **日志验证**：验证每类操作是否被适当记录
- **上下文完整性**：检查日志是否包含足够的调查上下文

### 2.2 检测常见于哪些业务场景

| **业务场景** | **功能示例** | **应记录内容** |
| :--- | :--- | :--- |
| **认证系统** | 登录、登出、密码重置 | 用户、IP、时间、结果 |
| **授权操作** | 权限变更、角色分配 | 操作者、目标、变更内容 |
| **数据访问** | 查询、导出、删除 | 用户、查询条件、记录数 |
| **配置变更** | 系统设置修改 | 操作者、原值、新值 |
| **异常处理** | 错误、异常、验证失败 | 错误类型、输入、堆栈 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**认证日志覆盖检测：**
```bash
# 测试各种认证场景
# 1. 成功登录
curl -X POST "http://target/login" -d "user=admin&pass=correct"

# 2. 失败登录（错误密码）
curl -X POST "http://target/login" -d "user=admin&pass=wrong"

# 3. 失败登录（不存在的用户）
curl -X POST "http://target/login" -d "user=nonexistent&pass=test"

# 4. 账户锁定
for i in {1..10}; do
    curl -X POST "http://target/login" -d "user=admin&pass=wrong$i"
done

# 5. 密码重置
curl -X POST "http://target/password-reset" -d "email=user@example.com"

# 检查日志系统是否记录了以上所有场景
```

**数据操作日志覆盖检测：**
```bash
# CRUD 操作测试
# Create
curl -X POST "http://target/api/users" -d '{"name":"test"}'

# Read
curl "http://target/api/users/1"
curl "http://target/api/users?search=admin"

# Update
curl -X PUT "http://target/api/users/1" -d '{"name":"updated"}'

# Delete
curl -X DELETE "http://target/api/users/1"

# 批量操作
curl -X POST "http://target/api/users/batch-delete" -d '{"ids":[1,2,3]}'

# 导出操作
curl "http://target/api/users/export?format=csv"
```

**边界场景日志检测：**
```bash
# 异常输入测试
# 1. 超长输入
curl -d "name=$(python3 -c 'print("A"*10000)')" "http://target/api/users"

# 2. 特殊字符
curl -d "name=<script>alert(1)</script>" "http://target/api/users"

# 3. SQL 注入尝试
curl "http://target/api/users?id=1' OR '1'='1"

# 4. 路径遍历
curl "http://target/api/files?name=../../../etc/passwd"

# 检查这些异常输入是否被日志记录
```

#### 2.3.2 白盒测试

**代码审计要点：**
```java
// 检查关键操作是否有日志记录
// 1. 认证相关
public boolean login(String username, String password) {
    // 应该有日志
    logger.info("Login attempt for user: {}", username);
    // ...
}

// 2. 权限变更
public void grantRole(String userId, String role) {
    // 应该有审计日志
    auditLogger.info("Role granted: {} -> {}", userId, role);
    // ...
}

// 3. 数据删除
public void deleteUser(String userId) {
    // 应该有删除日志
    logger.info("User deleted: {}", userId);
    // ...
}
```

**日志配置审计：**
```xml
<!-- 检查日志配置是否覆盖关键组件 -->
<Configuration>
    <Loggers>
        <!-- 认证组件日志 -->
        <Logger name="com.app.auth" level="INFO"/>
        
        <!-- 数据访问日志 -->
        <Logger name="com.app.repository" level="INFO"/>
        
        <!-- 审计日志 -->
        <Logger name="com.app.audit" level="INFO"/>
        
        <!-- 危险：排除关键组件 -->
        <!-- <Logger name="com.app.sensitive" level="OFF"/> -->
    </Loggers>
</Configuration>
```

### 2.4 漏洞利用方法

#### 2.4.1 识别日志盲区

```bash
# 系统性地探测日志覆盖
# 创建测试矩阵

ENDPOINTS=(
    "/api/users"
    "/api/admin"
    "/api/reports"
    "/api/settings"
)

METHODS=("GET" "POST" "PUT" "DELETE")

for endpoint in "${ENDPOINTS[@]}"; do
    for method in "${METHODS[@]}"; do
        echo "Testing: $method $endpoint"
        curl -X "$method" "http://target$endpoint"
        # 记录请求，稍后与日志对比
    done
done
```

#### 2.4.2 评估日志质量

```bash
# 检查日志是否包含足够的调查信息
# 发送带唯一标识的请求
UNIQUE_ID="TEST_$(date +%s)_$RANDOM"
curl -H "X-Request-ID: $UNIQUE_ID" "http://target/api/test"

# 在日志中搜索该标识
# 检查是否能关联到：
# - 用户身份
# - 源 IP 地址
# - 时间戳
# - 请求内容
# - 响应状态
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 利用日志盲区

```bash
# 如果检测到某些操作未被日志记录
# 在这些盲区执行敏感操作

# 例如：如果 OPTIONS 请求不被记录
curl -X OPTIONS "http://target/api/sensitive"

# 或：如果某些 HTTP 方法不被记录
curl -X PATCH "http://target/api/users/1"
```

---

## 第三部分：附录

### 3.1 日志覆盖检测清单

| **操作类型** | **检测项** | **应记录** | **状态** |
| :--- | :--- | :--- | :--- |
| 认证 | 成功登录 | 用户、IP、时间 | ☐ |
| 认证 | 失败登录 | 用户、IP、原因 | ☐ |
| 认证 | 账户锁定 | 用户、尝试次数 | ☐ |
| 授权 | 权限变更 | 操作者、目标、变更 | ☐ |
| 数据 | 敏感数据访问 | 用户、查询内容 | ☐ |
| 数据 | 数据导出 | 用户、导出范围 | ☐ |
| 配置 | 系统配置修改 | 操作者、变更内容 | ☐ |

### 3.2 日志上下文完整性检查

日志条目应包含以下信息以支持安全调查：

- **时间戳**：精确到毫秒，包含时区信息
- **事件类型**：清晰标识事件性质
- **主体身份**：执行操作的用户/系统
- **客体信息**：被操作的对象/资源
- **操作结果**：成功/失败及原因
- **来源信息**：IP 地址、User-Agent 等
- **关联标识**：Session ID、Request ID 等

### 3.3 参考资源

- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Application_Logging_Cheat_Sheet.html)
- [NIST 800-92 Guide to Computer Security Log Management](https://csrc.nist.gov/publications/detail/sp/800-92/final)
- [CIS Controls - Log Management](https://www.cisecurity.org/)
