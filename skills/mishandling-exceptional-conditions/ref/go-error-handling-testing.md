# Go 错误处理测试方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的 Go 应用错误处理检测和利用流程。针对 Go 语言特有的错误处理机制（error 返回值、panic/recover），提供系统性的测试方法。

## 1.2 适用范围

本文档适用于：
- 使用 Go 开发的 Web 应用和 API 服务
- 使用 Gin、Echo、net/http 等框架的应用
- 使用标准 error 返回值模式的 Go 代码
- 使用 panic/recover 机制的 Go 应用
- 微服务架构中的 Go 服务

## 1.3 读者对象

- 执行渗透测试任务的安全工程师
- 安全分析师
- 负责代码审计的开发人员
- Go 应用安全架构师

---

# 第二部分：核心渗透技术专题

## 专题一：Go 错误处理测试

### 2.1 技术介绍

Go 语言的错误处理有其独特性：

**Go 错误处理特点：**
- 使用 error 返回值而非异常
- 错误需要显式检查：`if err != nil`
- panic 用于严重错误，可被 recover 捕获
- 没有 try-catch 机制
- 错误可以包装和链式传递

**常见 CWE 映射：**

| CWE 编号 | 描述 | Go 场景 |
|---------|------|--------|
| CWE-252 | 未检查的返回值 | 忽略 error 返回值 |
| CWE-754 | 异常条件检查不当 | 未检查 error 就使用结果 |
| CWE-636 | 未安全失败 | 错误时返回成功状态 |
| CWE-209 | 错误消息泄露敏感信息 | 返回详细错误信息 |
| CWE-460 | 异常时清理不当 | panic 后资源未释放 |
| CWE-248 | 未捕获的异常 | panic 未被 recover |

### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| HTTP 处理 | Web 处理器、API 端点 | 未检查 error 返回 |
| 数据库操作 | SQL 查询、事务处理 | 查询错误未处理 |
| 文件操作 | 文件读写、配置加载 | 文件操作错误忽略 |
| JSON 解析 | 请求体解析、配置解析 | Unmarshal 错误未检查 |
| 网络调用 | HTTP 客户端、RPC 调用 | 网络错误未处理 |
| 并发处理 | goroutine、channel | goroutine 中 panic |
| 中间件 | 认证、日志、恢复中间件 | recover 处理不当 |

### 2.3 漏洞探测方法

#### 2.3.1 未检查返回值检测

**Go 高危代码模式：**

```go
// Go 高危代码模式 1：忽略 error 返回值
func getUser(id string) string {
    data, _ := db.Query(id)  // 忽略 error！
    return data.Name         // 如果查询失败，data 可能是零值
}

// Go 高危代码模式 2：检查但不处理
func readFile(path string) {
    content, err := os.ReadFile(path)
    if err != nil {
        // 只记录日志，继续执行
        log.Println(err)
    }
    // 继续使用 content - 可能是空！
    process(content)
}

// Go 高危代码模式 3：panic 未 recover
func handler(w http.ResponseWriter, r *http.Request) {
    panic("something went wrong")  // 如果没有 recover，连接会关闭
}

// Go 高危代码模式 4：错误信息直接返回给用户
func handler(w http.ResponseWriter, r *http.Request) {
    err := process(r)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        // 直接返回原始错误，可能泄露敏感信息
    }
}
```

**探测 Payload：**

```bash
# 1. 触发数据库错误
curl -X GET "https://target.com/api/user?id='; DROP TABLE users;--"

# 2. 触发文件操作错误
curl -X GET "https://target.com/api/file?path=/nonexistent"

# 3. 触发 JSON 解析错误
curl -X POST https://target.com/api/data \
  -H "Content-Type: application/json" \
  -d '{invalid json}'

# 4. 触发除零错误
curl -X GET "https://target.com/api/calculate?a=1&b=0"

# 5. 触发空指针（nil dereference）
curl -X GET "https://target.com/api/user?id=nonexistent"

# 6. 触发 panic
curl -X GET "https://target.com/api/crash"
```

#### 2.3.2 全局 recover 检测

**检测 panic 恢复机制：**

```bash
# 发送会触发 panic 的请求
# 观察：
# 1. 连接是否被关闭
# 2. 是否返回详细错误堆栈
# 3. 服务是否继续运行

# 检测是否有 recover 中间件
curl -X GET https://target.com/api/panic

# 检查响应
# 有 recover：返回 500 错误，服务继续
# 无 recover：连接重置，可能需要重启
```

**Gin 框架检测：**

```go
// 检查是否有 Recovery 中间件
// 应该存在：
r.Use(gin.Recovery())

// 或者自定义 recover 中间件
r.Use(func(c *gin.Context) {
    defer func() {
        if err := recover(); err != nil {
            c.JSON(500, gin.H{"error": "Internal server error"})
        }
    }()
    c.Next()
})
```

#### 2.3.3 错误包装和传递检测

**测试错误链传递：**

```bash
# 深层调用链中触发错误
# 观察错误是否被正确包装和传递

# 测试错误包装是否泄露信息
curl -X POST https://target.com/api/complex-operation \
  -H "Content-Type: application/json" \
  -d '{"trigger_error": true}'

# 检查响应中是否包含：
# - 原始错误类型
# - 调用栈信息
# - 内部服务细节
```

### 2.4 漏洞利用方法

#### 2.4.1 利用未检查的 error 返回值

**攻击场景：**

```go
// 目标代码
func handler(w http.ResponseWriter, r *http.Request) {
    id := r.URL.Query().Get("id")
    
    // 忽略错误
    user, _ := getUserFromDB(id)
    
    // 如果 getUserFromDB 失败，user 是零值
    // 访问 user.Name 可能导致 panic
    w.Write([]byte(user.Name))
}

// 利用方法
GET /api/user?id=invalid_id

// 结果：
// - user 是零值 User{}
// - user.Name 是空字符串
// - 可能绕过某些检查
```

#### 2.4.2 利用错误时继续使用零值

**攻击场景：**

```go
// 目标代码
func transfer(w http.ResponseWriter, r *http.Request) {
    var req TransferRequest
    err := json.NewDecoder(r.Body).Decode(&req)
    // 如果未检查 err
    // req 是零值，Amount 是 0
    
    // 继续处理
    db.Exec("UPDATE accounts SET balance = balance - ? WHERE id = ?", 
        req.Amount, req.FromID)  // Amount 是 0！
}

// 利用方法
POST /api/transfer
{"from_id": "123", "to_id": "456"}  // 缺少 amount 字段

// 结果：可能转账 0 元，但状态更新为成功
```

#### 2.4.3 利用 panic 导致拒绝服务

**攻击场景：**

```go
// 目标代码 - 没有 recover
func handler(w http.ResponseWriter, r *http.Request) {
    user := getUser(r.URL.Query().Get("id"))
    // 如果用户不存在，getUser 可能 panic
    panic("user not found")
}

// 利用方法
GET /api/user?id=nonexistent

// 结果：
// - panic 导致 goroutine 崩溃
// - 连接被关闭
// - 大量请求可导致服务不可用
```

#### 2.4.4 利用错误信息泄露

**从错误响应中提取信息：**

```
典型 Go 错误信息泄露：

1. 堆栈跟踪泄露
http: panic serving 127.0.0.1:12345: user not found
goroutine 12 [running]:
main.getUser(...)
    /app/main.go:45
main.handler(...)
    /app/handler.go:23

泄露信息：
- 文件路径：/app/main.go
- 代码行号：45
- 函数名：getUser, handler

2. SQL 错误泄露
Error 1064: You have an error in your SQL syntax...
泄露信息：
- 数据库类型：MySQL
- 查询结构信息

3. 文件路径泄露
open /etc/secrets/config.json: permission denied
泄露信息：
- 文件路径：/etc/secrets/config.json
- 权限问题
```

#### 2.4.5 利用资源清理不当

**攻击场景：**

```go
// 目标代码
func handler(w http.ResponseWriter, r *http.Request) {
    file, err := os.Open("data.txt")
    if err != nil {
        return  // 忘记关闭文件！
    }
    defer file.Close()
    
    // 如果这里 panic
    panic("error")
    // defer 仍然会执行，但某些资源可能未清理
}

// 利用方法
// 反复触发 panic
// 导致文件描述符耗尽
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过错误检查

```bash
# 某些应用只检查特定类型的错误
# 尝试：

# 1. 触发不同类型的错误
# 网络错误 vs 数据库错误 vs 验证错误

# 2. 利用错误包装
# 某些错误包装可能丢失类型信息
# 导致类型断言失败

# 3. 利用并发竞态
# 在错误检查和资源使用之间制造竞态
```

#### 2.5.2 利用错误包装链

```go
// 如果应用使用 errors.Wrap
// 错误链可能丢失原始错误类型

// 攻击者可以：
// 1. 触发深层错误
// 2. 利用错误包装中的信息丢失
// 3. 绕过基于错误类型的处理逻辑
```

#### 2.5.3 利用 goroutine 泄漏

```bash
# 发送会启动 goroutine 但提前关闭连接的请求
# 可能导致 goroutine 泄漏

# 反复执行导致 goroutine 耗尽
```

---

# 第三部分：附录

## 3.1 Go 错误处理测试清单

```
□ 测试未检查的 error 返回值
□ 测试错误检查后继续使用结果
□ 测试 panic 和 recover 机制
□ 测试错误信息泄露
□ 测试资源清理（defer）
□ 测试错误包装和传递
□ 测试全局错误处理器
□ 测试并发错误处理
□ 测试 goroutine 错误传播
□ 测试中间件错误处理
```

## 3.2 常见 Go 错误模式

| 错误类型 | 特征 | 风险等级 |
|---------|------|---------|
| Ignored error | `_, _ = func()` | 高 |
| Error checked but ignored | `if err != nil { log(err) }` | 高 |
| Panic without recover | panic 未被捕获 | 高 |
| Error message leakage | 返回 err.Error() | 中 |
| Resource leak on error | 错误路径未关闭资源 | 高 |
| Wrong error comparison | `err == io.EOF` | 中 |
| Missing error context | 错误无上下文信息 | 低 |

## 3.3 安全错误处理最佳实践

```go
// 1. 始终检查 error 返回值
func getUser(id string) (*User, error) {
    user, err := db.Query(id)
    if err != nil {
        return nil, fmt.Errorf("query user %s: %w", id, err)
    }
    return user, nil
}

// 2. 使用 defer 确保资源清理
func readFile(path string) ([]byte, error) {
    file, err := os.Open(path)
    if err != nil {
        return nil, err
    }
    defer file.Close()  // 确保关闭
    
    return io.ReadAll(file)
}

// 3. 使用 recover 中间件
func RecoveryMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        defer func() {
            if err := recover(); err != nil {
                // 记录详细日志
                log.Printf("Panic: %v", err)
                // 返回通用错误
                c.JSON(500, gin.H{"error": "Internal server error"})
                c.Abort()
            }
        }()
        c.Next()
    }
}

// 4. 不返回详细错误给用户
func handler(w http.ResponseWriter, r *http.Request) {
    err := process(r)
    if err != nil {
        // 记录详细错误
        log.Printf("Process failed: %v", err)
        // 返回通用错误
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }
}

// 5. 使用 errors.Is 和 errors.As 进行错误判断
if errors.Is(err, io.EOF) {
    // 处理 EOF
}

var target *MyError
if errors.As(err, &target) {
    // 处理特定错误类型
}
```

## 3.4 自动化检测工具

| 工具 | 用途 | 命令示例 |
|-----|------|---------|
| go vet | 静态检查 | `go vet ./...` |
| errcheck | 检查未处理的 error | `errcheck ./...` |
| staticcheck | 静态分析 | `staticcheck ./...` |
| golangci-lint | 综合 lint | `golangci-lint run` |
| Burp Suite | 动态测试 | 手动/自动扫描 |

---

**参考资源：**
- [Go Error Handling](https://go.dev/blog/error-handling-and-go)
- [Effective Go - Errors](https://go.dev/doc/effective_go#errors)
- [Go Panic and Recover](https://go.dev/blog/defer-panic-and-recover)
- [CWE-252](https://cwe.mitre.org/data/definitions/252.html)
