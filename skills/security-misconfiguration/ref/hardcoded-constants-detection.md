# 硬编码常量检测与利用方法论

---

## 第一部分：文档概述

### 1.1 编写目的
为渗透测试人员提供针对代码中硬编码安全相关常量的检测与利用方法论。硬编码常量本身是代码质量问题，但可能间接导致安全漏洞，如缓冲区溢出、认证绕过、信息泄露等。

### 1.2 适用范围
- 源代码审计
- 二进制文件逆向分析
- 配置安全审计
- 代码质量评估

### 1.3 读者对象
- 渗透测试工程师
- 代码审计人员
- 安全研究人员
- 逆向工程师

---

## 第二部分：核心渗透技术专题

### 专题：硬编码常量检测与利用

#### 2.1 技术介绍

硬编码常量（Hardcoded Constants）是指在代码中直接使用字面值（数字、字符串等）代替符号常量来定义安全关键参数。这本身是**间接性弱点**（CWE-547），但可能引入多种安全风险。

**硬编码常量的风险分类：**

| 风险类型 | 描述 | 危害等级 |
|---------|------|---------|
| **维护疏漏** | 安全策略变更时未同步更新所有实例 | 中 |
| **信息泄露** | 硬编码的密钥、路径、配置被提取 | 高 |
| **边界条件利用** | 利用未同步更新的缓冲区大小 | 高 |
| **逆向工程** | 从二进制文件提取硬编码值 | 中 |

**常见 CWE 映射：**

| CWE 编号 | 描述 |
|---------|------|
| CWE-547 | 使用硬编码的安全相关常量 |
| CWE-798 | 使用硬编码凭证 |
| CWE-1078 | 不当的代码风格/实践 |
| CWE-119 | 缓冲区溢出（可能由硬编码导致） |

#### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| **认证系统** | 硬编码密码哈希、盐值 | 凭证可被逆向提取 |
| **加密模块** | 硬编码密钥、IV、算法参数 | 加密可被破解 |
| **文件处理** | 硬编码缓冲区大小、路径 | 缓冲区溢出、路径遍历 |
| **网络服务** | 硬编码端口、超时、重试次数 | DoS、连接劫持 |
| **权限控制** | 硬编码角色 ID、权限阈值 | 权限绕过、提权 |
| **CTF 挑战** | 硬编码 Flag、密钥 | 直接提取获胜 |

#### 2.3 漏洞探测方法

##### 2.3.1 静态分析检测

**1. 源代码扫描**

```bash
# 查找重复出现的数字常量（3 位以上）
grep -rn '[0-9]\{3,\}' source_code/ | sort | uniq -d

# 查找可能的硬编码密钥
grep -rniE '(key|secret|password|token)\s*=\s*["\047][^"\047]+["\047]' source_code/

# 查找硬编码路径
grep -rn '["\047]/[a-zA-Z/]+["\047]' source_code/ | grep -v "http"

# 查找硬编码端口
grep -rn ':\s*[0-9]\{2,5\}' source_code/

# 查找魔术数字
grep -rn '\b[0-9]{2,}\b' source_code/ | grep -v "return\|if\|for\|while"
```

**2. 二进制文件分析**

```bash
# 提取可打印字符串
strings binary_file | grep -iE '(key|secret|password|flag|token)'

# 使用 rabin2 提取字符串
rabin2 -z binary_file

# 使用 IDA Pro 分析
# 打开二进制文件 → Shift+F12 查看字符串窗口

# 使用 Ghidra 分析
# 打开二进制文件 → Search → For Strings
```

**3. 自动化工具**

```bash
# SonarQube 扫描
# 配置规则：Hard-coded IP addresses, Hard-coded passwords

# Checkmarx 扫描
# 查询：Hardcoded_Password, Hardcoded_Secret_Key

# Fortify 扫描
# 规则：Hard Coded Password, Hard Coded Encryption Key

# 使用 truffleHog 查找密钥
git clone https://github.com/dxa4481/truffleHog
truffleHog --regex --entropy=False https://github.com/target/repo.git
```

##### 2.3.2 白盒测试

**1. 代码审计检查清单**

```
□ 缓冲区大小定义（如 char buffer[1024]）
□ 加密相关参数（密钥长度、迭代次数、IV）
□ 认证阈值（最大尝试次数、超时时间）
□ 权限标识符（角色 ID、权限级别）
□ 文件路径、端口号、协议标识
□ 魔术数字（未解释的数值常量）
□ 硬编码的 API 密钥、密码、令牌
□ 硬编码的 Flag、秘密值
```

**2. 代码模式识别**

```c
// ❌ 不良代码：硬编码缓冲区大小
char buffer[1024];
fgets(buffer, 1024, stdin);
process(buffer, 1024);

// ✅ 安全代码：使用符号常量
#define MAX_BUFFER_SIZE 1024
char buffer[MAX_BUFFER_SIZE];
fgets(buffer, MAX_BUFFER_SIZE, stdin);
process(buffer, MAX_BUFFER_SIZE);
```

```python
# ❌ 不良代码：硬编码密钥
SECRET_KEY = "super_secret_key_12345"
API_KEY = "sk-1234567890abcdef"

# ✅ 安全代码：从环境变量读取
import os
SECRET_KEY = os.environ.get('SECRET_KEY')
API_KEY = os.environ.get('API_KEY')
```

```java
// ❌ 不良代码：硬编码密码
String dbPassword = "admin123";

// ✅ 安全代码：从配置读取
String dbPassword = config.getProperty("db.password");
```

#### 2.4 漏洞利用方法

##### 2.4.1 信息泄露利用

**1. 提取硬编码凭证**

```bash
# 从源代码提取
grep -rn "password\s*=" src/
grep -rn "api_key\s*=" src/
grep -rn "secret\s*=" src/

# 从二进制文件提取
strings binary | grep -i "password"
strings binary | grep -i "flag"

# 从 Git 历史提取
git log -p --all -- "**/*.py" | grep -i "password"
```

**2. 利用提取的凭证**

```bash
# 使用提取的数据库密码
mysql -u root -p"extracted_password" -h target

# 使用提取的 API 密钥
curl -H "Authorization: Bearer extracted_api_key" \
     https://target.com/api/admin

# 使用提取的 Flag
# CTF 场景：直接提交 Flag
```

##### 2.4.2 缓冲区溢出利用

**利用场景：硬编码缓冲区大小不一致**

```c
// 漏洞代码分析
#define BUFFER_SIZE 256  // 定义在 header.h

// file1.c
char buffer[256];  // 直接使用 256
read(input, buffer, 256);

// file2.c（安全策略更新后）
char buffer[512];  // 更新为 512
read(input, buffer, 512);  // 读取 512 字节
process(buffer, 256);  // 但处理函数仍用 256 → 溢出
```

**利用步骤：**

```bash
# 1. 识别不一致的缓冲区大小
grep -rn "buffer\[" src/
grep -rn "fgets\|read\|memcpy" src/

# 2. 构造溢出 Payload
# 如果读取 512 但处理 256
# 发送 512 字节输入，其中包含覆盖数据

# 3. 发送 Payload
python3 -c "print('A'*512)" | ./vulnerable_program
```

##### 2.4.3 认证绕过利用

**利用场景：硬编码权限阈值**

```python
# 漏洞代码
MAX_LOGIN_ATTEMPTS = 3  # 散落在代码多处

def check_login(username, password):
    # 位置 1：正确使用了 3
    if attempts >= 3:
        lock_account(username)

    # 位置 2：忘记更新（仍用旧值 5）
    if attempts >= 5:  # 应该是 3
        lock_account(username)

# 利用方法：
# 在第 2 个位置，使用 4 次尝试即可绕过锁定
```

**利用步骤：**

```bash
# 1. 识别所有认证检查点
grep -rn "attempt" src/
grep -rn "lock" src/

# 2. 找到不一致的阈值
# 位置 1: if attempts >= 3
# 位置 2: if attempts >= 5

# 3. 利用不一致
# 使用 4 次尝试登录，绕过位置 2 的检查
```

##### 2.4.4 逆向工程利用

**1. 二进制文件常量提取**

```bash
# 使用 strings 提取
strings target_binary | grep -i "flag"
strings target_binary | grep -i "key"

# 使用 rabin2
rabin2 -z target_binary | grep "flag"

# 使用 IDA Pro
# 1. 打开二进制文件
# 2. Shift+F12 查看字符串
# 3. 搜索敏感关键词
```

**2. 内存转储分析**

```bash
# 使用 GDB 附加进程
gdb -p $(pidof target)

# 转储内存
gcore $(pidof target)

# 分析转储文件
strings core.dump | grep -i "flag"
```

##### 2.4.5 CTF 挑战利用

**典型场景：硬编码 Flag**

```python
# 漏洞代码示例
@app.route('/check')
def check():
    flag = "flag{hardcoded_flag_12345}"
    user_input = request.args.get('input')
    if user_input == flag:
        return "Correct!"
    return "Wrong!"

# 利用方法：
# 1. 反编译 Python 字节码
uncompyle6 app.pyc > app.py

# 2. 查看源码获取 Flag
grep "flag" app.py
```

#### 2.5 漏洞利用绕过方法

##### 2.5.1 代码混淆绕过

| 绕过技术 | 描述 | 检测方法 |
|---------|------|---------|
| **Base64 编码** | 密钥使用 Base64 编码 | 查找 `base64.b64decode()` |
| **XOR 加密** | 密钥与固定值 XOR | 查找 XOR 操作循环 |
| **字符串拼接** | 密钥分多段存储 | 查找多处字符串拼接 |
| **动态生成** | 运行时生成密钥 | 查找密钥生成函数 |

**检测示例：**

```python
# Base64 编码检测
grep -rn "base64" src/
# 解码可疑字符串
python3 -c "import base64; print(base64.b64decode('c3VwZXJfc2VjcmV0X2tleQ=='))"

# XOR 加密检测
grep -rn "xor\|^\|&" src/
# 分析 XOR 模式
```

##### 2.5.2 条件编译绕过

```c
// 检测条件编译
#ifdef DEBUG
#define PASSWORD "debug_password"
#else
#define PASSWORD "production_password"
#endif

// 利用方法：
// 1. 修改编译条件
// 2. 重新编译获取调试凭证
```

##### 2.5.3 动态加载绕过

```java
// 检测动态加载
String className = System.getProperty("config.class");
Class<?> clazz = Class.forName(className);

// 利用方法：
// 1. 控制配置类名
// 2. 提供恶意实现类
```

---

## 第三部分：附录

### 3.1 硬编码常量检测检查清单

```
□ 扫描源代码中的数字常量（3 位以上）
□ 扫描源代码中的字符串常量
□ 扫描硬编码路径、端口、URL
□ 扫描硬编码密钥、密码、令牌
□ 扫描硬编码 Flag、秘密值
□ 检查二进制文件中的字符串
□ 检查 Git 历史中的敏感提交
□ 检查配置文件中的明文凭证
□ 检查环境变量默认值
□ 检查魔术数字使用情况
```

### 3.2 自动化工具

| 工具名称 | 用途 | 命令示例 |
|---------|------|---------|
| **truffleHog** | Git 历史密钥扫描 | `truffleHog https://github.com/target/repo` |
| **GitLeaks** | Git 仓库扫描 | `gitleaks detect --source .` |
| **SonarQube** | 代码质量扫描 | Web 界面配置规则 |
| **Checkmarx** | 静态代码分析 | Web 界面扫描 |
| **strings** | 二进制字符串提取 | `strings binary \| grep flag` |
| **rabin2** | 二进制分析 | `rabin2 -z binary` |
| **Ghidra** | 逆向工程 | GUI 界面分析 |
| **IDA Pro** | 逆向工程 | GUI 界面分析 |

### 3.3 修复建议

- [ ] **使用符号常量** - 定义 `#define`、`const`、`enum` 代替字面值
- [ ] **从配置读取** - 使用配置文件、环境变量、密钥管理服务
- [ ] **实施密钥轮换** - 定期更换密钥、密码
- [ ] **代码审查** - 检查新代码中的硬编码
- [ ] **使用静态分析** - 自动化检测硬编码
- [ ] **分离敏感数据** - 敏感数据与代码分离存储
- [ ] **实施最小权限** - 硬编码凭证使用最小权限

---

**参考资源：**
- [CWE-547: Use of Hard-coded, Security-relevant Constants](https://cwe.mitre.org/data/definitions/547.html)
- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [OWASP Secrets Management](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [truffleHog - Git 历史扫描](https://github.com/dxa4481/truffleHog)
- [GitLeaks - Git 仓库扫描](https://github.com/zricethezav/gitleaks)
