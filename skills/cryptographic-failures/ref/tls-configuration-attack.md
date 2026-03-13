# TLS 配置攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的 TLS/SSL 配置检测和攻击流程。

## 1.2 适用范围

本文档适用于所有使用 HTTPS 的 Web 应用和服务。

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

TLS 配置攻击针对的是 TLS/SSL 协议实现或配置中的缺陷，包括弱加密套件、过时协议版本、证书验证问题等。

**本质问题**：
- 使用过时/弱加密协议
- 配置不当的加密套件
- 证书验证缺陷

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-326 | 加密强度不足 |
| CWE-327 | 使用已损坏或有风险的加密算法 |
| CWE-295 | 证书验证不当 |

## 2.2 攻击常见于哪些业务场景

| 场景 | 风险点 | 潜在危害 |
|-----|-------|---------|
| 旧版 TLS 支持 | TLS 1.0/1.1 | 协议降级攻击 |
| 弱加密套件 | RC4、3DES、MD5 | 加密破解 |
| 证书问题 | 自签名、过期 | 中间人攻击 |
| HSTS 缺失 | 无强制 HTTPS | 协议降级 |
| 证书链不完整 | 缺少中间证书 | 信任链断裂 |

## 2.3 漏洞发现方法

### 2.3.1 TLS 版本检测

```bash
# 使用 OpenSSL 检测
openssl s_client -connect target.com:443 -tls1
openssl s_client -connect target.com:443 -tls1_1
openssl s_client -connect target.com:443 -tls1_2
openssl s_client -connect target.com:443 -tls1_3

# 支持的版本表示可能存在风险
# TLS 1.0/1.1 应禁用
```

### 2.3.2 加密套件检测

```bash
# 测试弱加密套件
openssl s_client -connect target.com:443 \
    -cipher 'RC4:DES:MD5:NULL:EXPORT'

# 如果连接成功，存在配置问题
```

### 2.3.3 在线工具检测

```
使用以下在线工具：
- SSL Labs (ssllabs.com/ssltest/)
- testssl.sh
- SSL Scanner
```

### 2.3.4 证书验证

```bash
# 检查证书信息
openssl s_client -connect target.com:443 \
    -showcerts

# 检查：
# - 证书有效期
# - 证书链完整性
# - 域名匹配
# - 颁发机构可信度
```

## 2.4 漏洞利用方法

### 2.4.1 协议降级攻击

```bash
# POODLE 攻击 (SSLv3)
# 强制使用 SSLv3 协议
# 解密加密内容

# BEAST 攻击 (TLS 1.0)
# 利用 CBC 模式缺陷
# 解密 Cookie 等敏感数据
```

### 2.4.2 中间人攻击

```bash
# 使用 sslstrip 降级 HTTPS 到 HTTP
sslstrip -l 8080

# 使用自签名证书进行 MITM
# 如果客户端不验证证书，可成功
```

### 2.4.3 加密破解

```bash
# FREAK 攻击
# 强制使用出口级加密（弱）
# 爆破加密密钥

# Logjam 攻击
# 针对 Diffie-Hellman 密钥交换
# 预计算攻击
```

### 2.4.4 CRIME/BREACH 攻击

```
利用 TLS 压缩缺陷：
1. 注入已知文本
2. 观察压缩后长度
3. 推断敏感内容
```

## 2.5 漏洞利用绕过方法

### 2.5.1 证书警告绕过

```
用户通常会：
- 点击"继续访问"
- 忽略证书警告
- 不验证证书详情

攻击者利用这一点进行 MITM
```

### 2.5.2 HSTS 绕过

```bash
# 首次请求前 HSTS 未生效
# 使用 sslstrip 拦截首次请求

# 使用相似域名
target.com → target0.com
```

---

# 第三部分：附录

## 3.1 TLS 配置测试检查清单

```
□ 检测支持的 TLS 版本
□ 检测弱加密套件
□ 检查证书有效性
□ 检查证书链
□ 检查 HSTS 配置
□ 检查 OCSP Stapling
□ 检查 DHE 参数强度
□ 测试协议降级
```

## 3.2 常用工具

| 工具 | 用途 | 链接 |
|-----|------|------|
| testssl.sh | TLS 配置扫描 | https://testssl.sh/ |
| SSL Labs | 在线 TLS 测试 | https://ssllabs.com/ |
| OpenSSL | 命令行 TLS 测试 | https://openssl.org/ |
| sslstrip | HTTPS 降级 | https://github.com/moxie0/sslstrip |

## 3.3 修复建议

1. **禁用旧协议** - 仅支持 TLS 1.2+
2. **强加密套件** - 使用 AEAD 加密
3. **有效证书** - 使用可信 CA 颁发的证书
4. **HSTS** - 启用 HTTP Strict Transport Security
5. **完美前向保密** - 使用 ECDHE 密钥交换

---

**参考资源**：
- [OWASP Cheat Sheet: Transport Layer Protection](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
- [SSL Labs Best Practices](https://www.ssllabs.com/projects/best-practices/)
