# Python 异常处理测试方法论文档

---

# 第一部分：文档概述

## 1.1 编写目的

阐述 Python 应用程序异常处理测试的方法论，为测试人员提供一套标准化、可复现的 Python 异常处理安全测试流程。帮助安全工程师发现并利用 Python 应用在异常捕获、处理、传播中的安全缺陷。

## 1.2 适用范围

本文档适用于以下场景：
- 使用 Python 开发的 Web 应用（Django、Flask、FastAPI 等框架）
- Python 脚本和自动化工具
- Python 微服务和 API
- 数据处理和科学计算应用

## 1.3 读者对象

- 执行渗透测试任务的安全工程师
- 安全分析师
- 负责代码审计的开发人员

---

# 第二部分：核心渗透技术专题

## 专题一：Python 异常处理测试

### 2.1 技术介绍

Python 异常处理测试针对 Python 语言特有的异常机制进行安全测试，包括：
- try-except-else-finally 块的正确使用
- 异常层次结构和自定义异常
- 上下文管理器（with 语句）
- 异常链（exception chaining）
- 断言（assert）的使用

**漏洞本质：** Python 异常处理机制使用不当，导致安全控制被绕过、敏感信息泄露或资源未正确释放。

| 异常类型 | 描述 | 安全风险 |
|---------|------|---------|
| Exception | 所有内置异常的基类 | 过度捕获隐藏问题 |
| BaseException | 所有异常的基类 | 不应直接捕获 |
| AttributeError | 属性访问异常 | 信息泄露 |
| KeyError | 字典键不存在 | 信息泄露 |
| TypeError | 类型错误 | 信息泄露 |
| ValueError | 值错误 | 信息泄露 |
| AssertionError | 断言失败 | 调试信息泄露 |

### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| Flask 路由 | @app.errorhandler | 全局异常处理泄露信息 |
| Django 视图 | 自定义中间件异常 | 调试模式泄露信息 |
| API 接口 | REST framework 异常 | 序列化异常泄露 |
| 数据库操作 | SQLAlchemy 异常 | 数据库错误泄露 |
| 文件操作 | open/读写异常 | 路径信息泄露 |
| 反序列化 | pickle.loads 异常 | 对象结构泄露 |
| 命令执行 | subprocess 异常 | 命令信息泄露 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**Python 异常探测技术：**

| 探测方法 | 操作说明 | 预期观察 |
|---------|---------|---------|
| 类型不匹配 | 传入错误数据类型 | TypeError |
| 空值注入 | 传入 None 值 | AttributeError/TypeError |
| 键不存在 | 访问不存在的键 | KeyError |
| 属性不存在 | 访问不存在的属性 | AttributeError |
| 格式错误 | 传入错误格式 | ValueError |
| 索引越界 | 传入越界索引 | IndexError |

**探测 Payload 示例：**

```http
# 1. 触发 KeyError
GET /api/user?field=nonexistent

# 2. 触发 AttributeError
POST /api/action
{"object": null}

# 3. 触发 TypeError
GET /api/calculate?a=1&b=string

# 4. 触发 ValueError
GET /api/parse?value=not_an_int

# 5. 触发 IndexError
GET /api/items?index=999999
```

#### 2.3.2 白盒测试

**代码审计检查点：**

```python
# 高危代码示例 1：裸 except 子句
try:
    perform_operation()
except:
    # 捕获所有异常，包括 SystemExit、KeyboardInterrupt
    pass

# 高危代码示例 2：捕获 Exception 但不处理
try:
    risky_operation()
except Exception as e:
    # 没有日志，没有重新抛出
    pass

# 高危代码示例 3：异常信息泄露
try:
    cursor.execute(sql)
except sqlite3.Error as e:
    return f"Database error: {e}"
    # 泄露 SQL 信息

# 高危代码示例 4：finally 块中的异常
file = None
try:
    file = open('data.txt')
    process(file)
except Exception as e:
    log.error(e)
finally:
    file.close()  # file 可能为 None

# 高危代码示例 5：不正确的异常链
try:
    process_data()
except Exception as e:
    raise CustomException("Error")  # 丢失原始异常

# 正确做法
try:
    process_data()
except Exception as e:
    raise CustomException("Error") from e  # 保留异常链

# 高危代码示例 6：调试模式泄露
# Flask 开发服务器
if __name__ == '__main__':
    app.run(debug=True)  # 生产环境不应开启 debug

# 高危代码示例 7：assert 用于安全验证
def transfer_money(user, amount):
    assert user.balance >= amount  # assert 可被 -O 优化禁用
    user.balance -= amount
```

**审计关键词：**
- `except:` - 裸 except
- `except Exception:` - 宽泛捕获
- `pass` 在 except 块中
- `str(e)` / `repr(e)` - 异常字符串
- `traceback.print_exc()` - 堆栈输出
- `debug=True` - 调试模式
- `assert` - 断言语句

### 2.4 漏洞利用方法

#### 2.4.1 Flask 异常信息泄露

**利用场景：** 调试模式或错误处理不当

```python
# 漏洞代码
@app.errorhandler(Exception)
def handle_exception(e):
    # 返回详细异常信息
    return f"Error: {e}\n\n{traceback.format_exc()}", 500

# 或开启调试模式
app.run(debug=True)  # Werkzeug 调试器泄露信息
```

**利用 Payload：**
```http
GET /admin?id=' OR '1'='1
Response:
Error: near "OR": syntax error

Traceback (most recent call last):
  File "app.py", line 42, in admin
    cursor.execute(f"SELECT * FROM users WHERE id='{id}'")
sqlite3.OperationalError: near "OR": syntax error
```

#### 2.4.2 Django 调试模式泄露

```python
# settings.py 漏洞配置
DEBUG = True  # 显示详细调试页面

# 利用
GET /nonexistent-page/
# 显示完整的堆栈跟踪和代码片段
```

#### 2.4.3 反序列化异常利用

```python
# 漏洞代码
import pickle

def load_data(data):
    try:
        return pickle.loads(data)
    except Exception as e:
        return f"Deserialization error: {e}"
        # 可能泄露对象结构信息
```

#### 2.4.4 上下文管理器异常

```python
# 漏洞代码
class DatabaseConnection:
    def __enter__(self):
        self.conn = create_connection()
        return self.conn
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        # 如果这里抛出异常，可能掩盖原始问题
        self.conn.close()

# 使用
with DatabaseConnection() as conn:
    conn.execute(query)  # 异常可能被掩盖
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过异常监控

```python
# 利用 logging 配置不当
import logging
logging.basicConfig(level=logging.ERROR)  # 只记录 ERROR 及以上

# 触发 WARNING 级别的异常不会被记录
```

#### 2.5.2 利用异常抑制

```python
# 利用 warnings 模块
import warnings
warnings.filterwarnings('ignore')  # 忽略所有警告

# 某些安全警告可能被忽略
```

---

# 第三部分：附录

## 3.1 Python 异常检测清单

| 检查项 | 检测方法 | 风险等级 |
|-------|---------|---------|
| 裸 except | 代码审计 | 高 |
| 空 except 块 | 代码审计 | 高 |
| 异常信息泄露 | 黑盒测试 | 高 |
| debug 模式 | 配置检查 | 高 |
| assert 用于安全 | 代码审计 | 高 |
| 资源未释放 | 代码审计 | 中 |

## 3.2 安全 Python 异常处理建议

```python
# 推荐做法

# 1. 使用具体的异常类型
try:
    value = int(user_input)
except ValueError:
    logger.warning(f"Invalid integer: {user_input}")
    raise BadRequest("Invalid integer format")

# 2. 使用上下文管理器
with open('file.txt', 'r') as f:
    data = f.read()
# 自动关闭文件

# 3. 正确的异常链
try:
    process_data()
except DatabaseError as e:
    raise ServiceError("Database operation failed") from e

# 4. 不泄露敏感信息
@app.errorhandler(Exception)
def handle_exception(e):
    logger.error(f"Unexpected error: {e}", exc_info=True)
    return jsonify({"error": "Internal server error"}), 500

# 5. 不使用 assert 进行安全验证
def transfer_money(user, amount):
    if user.balance < amount:
        raise InsufficientFundsError()
    user.balance -= amount

# 6. 生产环境关闭调试模式
if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)
```

## 3.3 Python 异常测试工具

| 工具 | 用途 |
|-----|------|
| pylint | 代码静态分析 |
| flake8 | 代码风格和安全检查 |
| bandit | Python 安全漏洞扫描 |
| pytest | 异常测试用例编写 |
| Burp Suite | Web 异常响应分析 |
