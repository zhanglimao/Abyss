# .NET 异常处理测试方法论文档

---

# 第一部分：文档概述

## 1.1 编写目的

阐述 .NET 应用程序异常处理测试的方法论，为测试人员提供一套标准化、可复现的 .NET 异常处理安全测试流程。帮助安全工程师发现并利用 .NET 应用在异常捕获、处理、传播中的安全缺陷。

## 1.2 适用范围

本文档适用于以下场景：
- 使用 C#、VB.NET 开发的 Web 应用（ASP.NET、ASP.NET Core）
- .NET Framework 和 .NET Core/.NET 5+ 应用
- WCF 服务
- Windows Forms/WPF 桌面应用

## 1.3 读者对象

- 执行渗透测试任务的安全工程师
- 安全分析师
- 负责代码审计的开发人员

---

# 第二部分：核心渗透技术专题

## 专题一：.NET 异常处理测试

### 2.1 技术介绍

.NET 异常处理测试针对 .NET 框架特有的异常机制进行安全测试，包括：
- try-catch-finally 块的正确使用
- using 语句和资源管理
- 异常过滤器（Exception Filters）
- 自定义异常和异常层次结构
- ASP.NET 全局异常处理

**漏洞本质：** .NET 异常处理机制使用不当，导致安全控制被绕过、敏感信息泄露或资源未正确释放。

| 异常类型 | 描述 | 安全风险 |
|---------|------|---------|
| SystemException | 系统级异常基类 | 未处理导致服务中断 |
| ApplicationException | 应用级异常基类 | 业务异常处理不当 |
| NullReferenceException | 空引用异常 | 信息泄露 |
| SqlException | SQL Server 异常 | 数据库信息泄露 |
| SecurityException | 安全异常 | 权限信息泄露 |

### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| ASP.NET MVC | Controller 异常处理 | HandleError 配置不当 |
| ASP.NET Web API | ApiController 异常 | ExceptionHandler 泄露信息 |
| WCF 服务 | ServiceBehavior 异常 | FaultException 配置 |
| Entity Framework | LINQ 查询异常 | 数据库错误泄露 |
| 文件操作 | FileStream 异常 | 路径信息泄露 |
| 序列化 | JSON/XML 序列化异常 | 对象结构泄露 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**.NET 异常探测技术：**

| 探测方法 | 操作说明 | 预期观察 |
|---------|---------|---------|
| 类型不匹配 | 传入错误数据类型 | InvalidCastException |
| 空值注入 | 传入 null 值 | NullReferenceException |
| 数字溢出 | 传入溢出值 | OverflowException |
| 索引越界 | 传入越界索引 | IndexOutOfRangeException |
| 格式错误 | 传入错误格式 | FormatException |

**探测 Payload 示例：**

```http
# 1. 触发 NullReferenceException
POST /api/user
{"name": null}

# 2. 触发 FormatException
GET /api/parse?value=not_a_number

# 3. 触发 OverflowException
GET /api/calculate?a=999999999999999999999

# 4. 触发 SqlException（SQL Server）
GET /api/user?id=1'--
```

#### 2.3.2 白盒测试

**代码审计检查点：**

```csharp
// 高危代码示例 1：空 catch 块
try {
    PerformOperation();
} catch {
    // 空的 catch 块 - 异常被吞没
}

// 高危代码示例 2：捕获 Exception 但不处理
try {
    RiskyOperation();
} catch (Exception ex) {
    // 没有日志，没有重新抛出
}

// 高危代码示例 3：异常信息泄露
try {
    db.ExecuteQuery(sql);
} catch (SqlException ex) {
    Response.Write("SQL Error: " + ex.Message);
    // 泄露数据库信息
}

// 高危代码示例 4：using 语句外的异常
SqlConnection conn = null;
try {
    conn = new SqlConnection(connectionString);
    // 业务逻辑
} catch (Exception ex) {
    // conn 可能未关闭
}

// 高危代码示例 5：不正确的异常重新抛出
try {
    ProcessData();
} catch (Exception ex) {
    throw ex; // 错误：丢失原始堆栈
}

// 正确做法
try {
    ProcessData();
} catch (Exception ex) {
    throw; // 正确：保留原始堆栈
}

// 高危代码示例 6：ASP.NET 自定义错误配置
// web.config 中
<customErrors mode="Off"/>
// 或
<customErrors mode="On" redirectMode="ResponseRewrite"/>
// 可能泄露信息
```

**审计关键词：**
- `catch { }` - 空 catch 块
- `catch (Exception)` - 宽泛捕获
- `throw ex` - 错误的重新抛出
- `ex.Message` / `ex.StackTrace` - 异常信息输出
- `customErrors mode="Off"` - 详细错误开启

### 2.4 漏洞利用方法

#### 2.4.1 ASP.NET 异常信息泄露

**利用场景：** customErrors 配置不当

```xml
<!-- web.config 漏洞配置 -->
<configuration>
  <system.web>
    <!-- 显示详细错误 -->
    <customErrors mode="Off"/>
    <!-- 或 -->
    <customErrors mode="RemoteOnly"/>
  </system.web>
</configuration>
```

**利用 Payload：**
```http
GET /admin.aspx?id=' OR '1'='1
Response:
[SqlException (0x80131904): Unclosed quotation mark after the character string '' OR '1'='1'.]
   at System.Data.SqlClient.SqlConnection.OnError(SqlException exception)
   at System.Web.UI.Page.ProcessRequestMain()
```

#### 2.4.2 Web API 异常处理利用

```csharp
// 漏洞代码
public class GlobalExceptionFilter : ExceptionFilterAttribute {
    public override void OnException(HttpActionExecutedContext context) {
        // 漏洞：返回详细异常信息
        var response = new HttpResponseMessage {
            StatusCode = HttpStatusCode.InternalServerError,
            Content = new StringContent(context.Exception.ToString())
        };
        context.Response = response;
    }
}
```

#### 2.4.3 Entity Framework 异常利用

```csharp
// 漏洞代码
try {
    var user = context.Users.Find(id);
} catch (DbUpdateException ex) {
    // 泄露 EF 内部信息
    return Json(new { error = ex.InnerException?.Message });
}
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过 ASP.NET 验证

```csharp
// 利用 ValidateInput 配置
[ValidateInput(false)]  // 禁用输入验证
public ActionResult Submit(string input) {
    // 可能接收恶意输入
    return View();
}
```

#### 2.5.2 利用序列化异常

```
攻击步骤：
1. 找到 .NET 序列化端点
2. 发送畸形序列化对象（如 ViewState）
3. 触发反序列化异常
4. 利用异常处理缺陷
```

---

# 第三部分：附录

## 3.1 .NET 异常检测清单

| 检查项 | 检测方法 | 风险等级 |
|-------|---------|---------|
| 空 catch 块 | 代码审计 | 高 |
| throw ex | 代码审计 | 中 |
| 异常信息泄露 | 黑盒测试 | 高 |
| customErrors 配置 | 配置检查 | 高 |
| using 语句缺失 | 代码审计 | 中 |
| 全局异常处理 | 代码审计 | 高 |

## 3.2 安全 .NET 异常处理建议

```csharp
// 推荐做法

// 1. 使用 using 语句管理资源
using (var conn = new SqlConnection(connectionString)) {
    // 自动释放资源
}

// 2. 正确的异常重新抛出
try {
    ProcessData();
} catch (SqlException ex) {
    _logger.LogError(ex, "Database error");
    throw; // 保留堆栈
}

// 3. 不泄露敏感信息
[HandleError]
public class HomeController : Controller {
    protected override void OnException(ExceptionContext filterContext) {
        filterContext.ExceptionHandled = true;
        // 返回通用错误视图
        filterContext.Result = View("Error");
    }
}

// 4. ASP.NET Core 全局异常处理
app.UseExceptionHandler("/Home/Error");
// Error 控制器返回通用错误信息
```

## 3.3 .NET 异常测试工具

| 工具 | 用途 |
|-----|------|
| FxCop / Roslyn Analyzers | 静态代码分析 |
| SonarQube | 代码质量检查 |
| Burp Suite | Web 异常响应分析 |
| dnSpy | .NET 反编译审计 |
