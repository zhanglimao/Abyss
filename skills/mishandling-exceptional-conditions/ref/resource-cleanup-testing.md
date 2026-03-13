# 资源清理测试方法论文档

---

# 第一部分：文档概述

## 1.1 编写目的

阐述资源清理测试的方法论，为测试人员提供一套标准化、可复现的资源清理漏洞测试流程。帮助安全工程师发现应用程序在异常情况下未能正确释放资源的安全缺陷，包括文件句柄、数据库连接、内存、网络连接等。

## 1.2 适用范围

本文档适用于以下场景：
- 处理文件上传下载的 Web 应用
- 有数据库连接池的应用系统
- 处理大文件或大量数据的应用
- 长时间运行的服务和后台任务

## 1.3 读者对象

- 执行渗透测试任务的安全工程师
- 安全分析师
- 负责代码审计的开发人员
- 系统运维人员

---

# 第二部分：核心渗透技术专题

## 专题一：资源清理测试

### 2.1 技术介绍

资源清理测试针对应用程序在正常和异常流程中的资源管理能力进行安全测试，包括：
- 文件句柄的打开和关闭
- 数据库连接的获取和释放
- 内存分配和释放
- 网络连接的建立和断开
- 临时文件的创建和删除

**漏洞本质：** 异常处理程序中资源清理逻辑缺失或不正确，导致资源泄漏，最终可能引发拒绝服务或信息泄露。

| 资源类型 | 泄漏后果 | 风险等级 |
|---------|---------|---------|
| 文件句柄 | 无法打开新文件 | 高 |
| 数据库连接 | 连接池耗尽 | 高 |
| 内存 | 内存溢出 | 高 |
| 线程 | 线程池耗尽 | 高 |
| 临时文件 | 磁盘空间耗尽、信息泄露 | 中 |
| Socket 连接 | 端口耗尽 | 高 |

### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 文件上传 | 头像、附件上传 | 临时文件未删除 |
| 文件下载 | 报表导出 | 文件流未关闭 |
| 数据库操作 | 查询、批量处理 | 连接未释放 |
| 图片处理 | 缩略图生成 | 图片句柄未释放 |
| 压缩解压 | 文件打包 | 流未关闭 |
| 网络请求 | 外部 API 调用 | HTTP 连接未关闭 |
| 报表生成 | PDF/Excel 生成 | 临时文件残留 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**资源泄漏探测技术：**

| 探测方法 | 操作说明 | 预期观察 |
|---------|---------|---------|
| 重复操作 | 重复执行相同操作 | 响应时间变长 |
| 异常触发 | 操作中触发异常 | 资源未释放 |
| 并发测试 | 并发执行操作 | 资源快速耗尽 |
| 疲劳测试 | 长时间持续操作 | 资源逐渐耗尽 |
| 边界测试 | 大文件/大数据量 | 资源消耗激增 |

**探测步骤：**
1. 识别目标系统的资源密集型操作
2. 建立性能基线（响应时间、资源使用）
3. 执行重复操作或触发异常
4. 监控资源使用情况
5. 观察系统性能变化

**探测 Payload 示例：**

```bash
# 1. 文件上传泄漏测试
# 重复上传大文件，触发异常
for i in {1..100}; do
  curl -X POST https://target.com/api/upload \
    -F "file=@large_file.zip" &
done
wait

# 观察：
# - 磁盘空间是否减少
# - /tmp 目录是否有残留文件
# - 文件句柄数是否增加

# 2. 数据库连接泄漏测试
# 快速发起大量数据库操作
for i in {1..1000}; do
  curl -X GET https://target.com/api/user?id=$i &
done
wait

# 观察：
# - 数据库连接池使用率
# - 响应时间是否变长
# - 是否出现"连接池耗尽"错误

# 3. 内存泄漏测试
# 重复执行内存密集型操作
for i in {1..100}; do
  curl -X POST https://target.com/api/process \
    -d "data=$(head -c 1000000 /dev/urandom | base64)" &
done
wait

# 观察：
# - 服务器内存使用率
# - 是否出现 OOM 错误
```

#### 2.3.2 白盒测试

**代码审计检查点：**

```java
// 高危代码示例 1：文件流未关闭
public void readFile(String path) {
    FileInputStream fis = null;
    try {
        fis = new FileInputStream(path);
        // 处理文件
        byte[] data = new byte[fis.available()];
        fis.read(data);
    } catch (IOException e) {
        log.error(e);
        // 漏洞：fis 未关闭
    }
}

// 高危代码示例 2：数据库连接未释放
public List<User> getUsers() {
    Connection conn = dataSource.getConnection();
    Statement stmt = conn.createStatement();
    ResultSet rs = stmt.executeQuery("SELECT * FROM users");
    // 处理结果集
    // 漏洞：rs, stmt, conn 都未关闭
}

// 高危代码示例 3：临时文件未删除
public void processFile(File upload) {
    File temp = File.createTempFile("upload", ".tmp");
    // 处理临时文件
    // 漏洞：temp 未删除
}

// 高危代码示例 4：HTTP 连接未关闭
public String callExternalApi(String url) {
    HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
    conn.setRequestMethod("GET");
    // 读取响应
    BufferedReader in = new BufferedReader(
        new InputStreamReader(conn.getInputStream()));
    // 漏洞：in 和 conn 未关闭
}

// 高危代码示例 5：finally 块中未清理资源
public void processData() {
    FileInputStream fis = null;
    try {
        fis = new FileInputStream("data.txt");
        // 可能抛出异常
        process(fis);
    } catch (IOException e) {
        log.error(e);
    } finally {
        // 漏洞：finally 块为空，fis 未关闭
    }
}

// 推荐做法：使用 try-with-resources
public void readFile(String path) {
    try (FileInputStream fis = new FileInputStream(path)) {
        byte[] data = fis.readAllBytes();
        // 自动关闭
    } catch (IOException e) {
        log.error(e);
    }
}
```

**审计关键词：**
- `new FileInputStream` / `FileOutputStream` - 文件流
- `getConnection()` - 数据库连接
- `createTempFile` - 临时文件
- `openConnection()` - 网络连接
- `close()` / `dispose()` - 资源释放方法
- `try-with-resources` - 自动资源管理

### 2.4 漏洞利用方法

#### 2.4.1 文件句柄耗尽攻击

**利用场景：** 文件操作频繁的应用

```
攻击步骤：
1. 分析系统的文件操作流程
2. 触发文件打开但不关闭的异常
3. 重复执行直到文件句柄耗尽
4. 系统无法打开新文件

效果：
- 无法上传/下载文件
- 无法读取配置
- 服务不可用
```

#### 2.4.2 数据库连接池耗尽

**利用场景：** 数据库操作频繁的应用

```
攻击步骤：
1. 确定连接池大小（如 50）
2. 并发发起超过连接池大小的请求
3. 每个请求获取连接但不释放
4. 连接池耗尽，新请求阻塞

Payload:
# 并发 100 个请求，连接池大小 50
for i in {1..100}; do
  curl -X POST https://target.com/api/query \
    -d "id=$i&delay=10" &  # 故意延迟
done
```

#### 2.4.3 磁盘空间耗尽

**利用场景：** 文件上传、临时文件处理

```
攻击步骤：
1. 找到创建临时文件的功能
2. 触发异常使临时文件不被清理
3. 重复执行直到磁盘空间耗尽

效果：
- 无法写入新数据
- 日志无法记录
- 服务崩溃
```

#### 2.4.4 内存泄漏利用

**利用场景：** 大数据处理

```
攻击步骤：
1. 找到内存分配操作
2. 触发异常使内存不被释放
3. 重复执行直到内存耗尽

效果：
- OutOfMemoryError
- 服务崩溃
- 可能触发 GC 导致性能下降
```

#### 2.4.5 临时文件信息泄露

**利用场景：** 文件处理

```
攻击步骤：
1. 上传包含敏感信息的文件
2. 触发异常使临时文件残留
3. 通过其他漏洞读取临时文件

效果：
- 敏感信息泄露
- 文件内容被窃取
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过连接池监控

**场景：** 系统有连接池监控

**绕过方法：**
```
1. 慢速攻击：每次只占用少量连接，延长攻击时间
2. 间歇攻击：攻击一段时间后停止，等待监控重置
3. 伪装正常：在正常请求中穿插泄漏请求
```

#### 2.5.2 绕过自动清理

**场景：** 系统有定时清理任务

**绕过方法：**
```
1. 在清理间隔内快速攻击
2. 创建清理任务无法识别的临时文件
3. 利用清理逻辑的盲区
```

---

# 第三部分：附录

## 3.1 资源清理检测清单

| 检查项 | 检测方法 | 风险等级 |
|-------|---------|---------|
| 文件流未关闭 | 代码审计 | 高 |
| 数据库连接泄漏 | 代码审计 + 监控 | 高 |
| 临时文件残留 | 文件系统检查 | 中 |
| HTTP 连接未关闭 | 代码审计 | 中 |
| 内存泄漏 | 压力测试 | 高 |
| 线程泄漏 | 监控分析 | 高 |

## 3.2 安全资源管理建议

```java
// 推荐做法

// 1. 使用 try-with-resources
public void readFile(String path) {
    try (FileInputStream fis = new FileInputStream(path);
         BufferedInputStream bis = new BufferedInputStream(fis)) {
        // 自动关闭所有资源
    } catch (IOException e) {
        log.error(e);
    }
}

// 2. 数据库连接管理
public List<User> getUsers() {
    String sql = "SELECT * FROM users";
    try (Connection conn = dataSource.getConnection();
         PreparedStatement stmt = conn.prepareStatement(sql);
         ResultSet rs = stmt.executeQuery()) {
        
        List<User> users = new ArrayList<>();
        while (rs.next()) {
            users.add(mapRow(rs));
        }
        return users;
    } catch (SQLException e) {
        log.error(e);
        throw new DataAccessException(e);
    }
}

// 3. 临时文件管理
public void processFile(File upload) {
    File temp = null;
    try {
        temp = File.createTempFile("upload", ".tmp");
        // 处理
    } finally {
        if (temp != null && temp.exists()) {
            temp.delete();  // 确保删除
        }
    }
}

// 4. HTTP 连接管理
public String callApi(String url) {
    HttpURLConnection conn = null;
    BufferedReader in = null;
    try {
        conn = (HttpURLConnection) new URL(url).openConnection();
        in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        // 读取
    } finally {
        if (in != null) in.close();
        if (conn != null) conn.disconnect();
    }
}

// 5. 使用连接池
// 配置合理的连接池大小和超时
HikariConfig config = new HikariConfig();
config.setMaximumPoolSize(10);
config.setIdleTimeout(300000);
config.setMaxLifetime(1800000);
config.setConnectionTimeout(30000);
```

## 3.3 资源清理测试工具

| 工具 | 用途 |
|-----|------|
| JMeter | 压力测试 |
| ab | 并发测试 |
| VisualVM | Java 内存分析 |
| jmap/jstat | JVM 监控 |
| lsof | 文件句柄检查 |
| 自定义脚本 | 自动化测试 |
