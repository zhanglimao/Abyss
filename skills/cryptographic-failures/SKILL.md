---
name: cryptographic-failures
description: 加密失效渗透测试技能，用于检测和利用加密算法、密钥管理、传输/存储加密中的安全缺陷
---

# Cryptographic Failures（加密失效）渗透测试技能

## 简介

加密失效（Cryptographic Failures）是 OWASP Top 10:2025 排名第 4 的安全风险。当敏感数据缺乏加密保护、使用弱加密算法或密钥管理不当时，攻击者可以窃取、篡改或解密敏感信息。

本技能提供系统性的方法论，指导渗透测试人员发现和利用加密漏洞，包括弱加密算法、密钥泄露、传输层攻击、密码哈希破解等攻击技术。

---

## 方法论映射表

### 1. 渗透过程中遇到什么情况该参考哪个方法论

| 遇到的情况 | 参考方法论 | 文件路径 |
|-----------|-----------|----------|
| 网站未强制 HTTPS | TLS 配置攻击 | `ref/tls-configuration-attack.md` |
| 发现弱加密套件 | 加密套件降级攻击 | `ref/cipher-suite-downgrade.md` |
| 密码使用 MD5/SHA1 存储 | 密码哈希破解 | `ref/password-hash-cracking.md` |
| 发现硬编码密钥 | 密钥提取攻击 | `ref/hardcoded-key-extraction.md` |
| JWT 使用 HS256 弱密钥 | JWT 密钥爆破 | `ref/jwt-key-bruteforce.md` |
| 发现自签名证书 | 证书验证绕过 | `ref/certificate-validation-bypass.md` |
| 敏感数据明文传输 | 中间人攻击 | `ref/man-in-the-middle-attack.md` |
| 发现 ECB 模式加密 | 加密模式攻击 | `ref/encryption-mode-attack.md` |
| 随机数可预测 | 随机数预测攻击 | `ref/random-number-prediction.md` |
| 发现 Padding Oracle | Padding Oracle 攻击 | `ref/padding-oracle-attack.md` |
| 密码明文存储数据库 | 明文凭证存储攻击 | `ref/plaintext-credential-storage.md` |
| 发现硬编码会话/加密密钥 | 硬编码密钥利用 | `ref/hardcoded-secret-exploitation.md` |
| Flask 应用硬编码 SECRET_KEY | 硬编码密钥利用 | `ref/hardcoded-secret-exploitation.md` |
| 数据库明文存储用户密码 | 明文凭证存储攻击 | `ref/plaintext-credential-storage.md` |
| 敏感数据未加密存储 | 敏感信息明文存储利用 | `ref/sensitive-data-plaintext-exploitation.md` |
| .env 文件明文存储敏感凭证 | 敏感信息明文存储利用 | `ref/sensitive-data-plaintext-exploitation.md` |
| Git 仓库提交敏感配置文件 | 敏感信息明文存储利用 | `ref/sensitive-data-plaintext-exploitation.md` |
| Docker 镜像层嵌入敏感信息 | Docker 环境敏感信息提取 | `ref/docker-secret-extraction.md` |
| Flag/密钥通过 HTTP 明文传输 | HTTP-only 部署攻击 | `ref/http-only-deployment-attack.md` |
| 无 HTTPS 导致凭证可被窃听 | HTTP-only 部署攻击 | `ref/http-only-deployment-attack.md` |
| 同一网络段可监听 HTTP 流量 | HTTP-only 部署攻击 | `ref/http-only-deployment-attack.md` |
| 使用 MD5/SHA1/DES/RC4 等弱算法 | 弱加密算法攻击 | `ref/weak-crypto-algorithm-attack.md` |
| HTTP 页面传输登录凭证 | 敏感信息明文传输攻击 | `ref/sensitive-data-plaintext-transmission.md` |
| API 接口未使用 HTTPS | 敏感信息明文传输攻击 | `ref/sensitive-data-plaintext-transmission.md` |
| TLS 握手支持旧版本协议 | 算法降级攻击 | `ref/algorithm-downgrade-attack.md` |
| 服务器支持弱加密套件 | 算法降级攻击 | `ref/algorithm-downgrade-attack.md` |
| 证书链验证不当 | 证书链信任攻击 | `ref/certificate-chain-attack.md` |
| 客户端接受自签名证书 | 证书链信任攻击 | `ref/certificate-chain-attack.md` |
| 证书吊销检查缺失 | 证书链信任攻击 | `ref/certificate-chain-attack.md` |
| 需要评估 PQC 迁移状态 | 后量子加密迁移指南 | `ref/post-quantum-crypto-migration.md` |
| 检测混合加密方案配置 | 后量子加密迁移指南 | `ref/post-quantum-crypto-migration.md` |
| "现在收集，以后解密"风险评估 | 后量子加密迁移指南 | `ref/post-quantum-crypto-migration.md` |

### 2. 遇到什么样的业务系统、软件环境、基础设施该参考哪个方法论

| 系统/环境特征 | 参考方法论 | 文件路径 |
|--------------|-----------|----------|
| 传统金融系统 | 传统加密审计 | `ref/legacy-crypto-audit.md` |
| 云环境 (AWS/Azure/GCP) | 云加密配置审计 | `ref/cloud-encryption-audit.md` |
| 移动应用 | 移动加密安全测试 | `ref/mobile-encryption-testing.md` |
| API 服务 | API 传输加密测试 | `ref/api-transport-encryption.md` |
| 数据库系统 | 数据库加密审计 | `ref/database-encryption-audit.md` |
| 区块链应用 | 区块链加密审计 | `ref/blockchain-crypto-audit.md` |
| IoT 设备 | IoT 加密安全测试 | `ref/iot-encryption-testing.md` |
| 即时通讯系统 | 端到端加密测试 | `ref/e2e-encryption-testing.md` |

### 3. 遇到什么样的问题该参考哪个方法论

| 问题类型 | 参考方法论 | 文件路径 |
|---------|-----------|----------|
| 如何检测 TLS 配置问题 | TLS 安全检测 | `ref/tls-security-detection.md` |
| 如何破解密码哈希 | 哈希破解指南 | `ref/hash-cracking-guide.md` |
| 如何提取硬编码密钥 | 密钥提取技术 | `ref/key-extraction-techniques.md` |
| 如何检测弱随机数 | 随机性检测 | `ref/randomness-detection.md` |
| 如何实施中间人攻击 | MITM 实施指南 | `ref/mitm-implementation.md` |
| 如何检测证书问题 | 证书检测指南 | `ref/certificate-detection.md` |
| 如何破解对称加密 | 对称加密攻击 | `ref/symmetric-encryption-attack.md` |
| 如何检测侧信道漏洞 | 侧信道检测 | `ref/side-channel-detection.md` |
| 如何检测弱加密算法 | 弱加密算法攻击 | `ref/weak-crypto-algorithm-attack.md` |
| 如何实施 MD5/SHA1 碰撞攻击 | 弱加密算法攻击 | `ref/weak-crypto-algorithm-attack.md` |
| 如何嗅探网络流量 | 敏感信息明文传输攻击 | `ref/sensitive-data-plaintext-transmission.md` |
| 如何劫持 HTTP 会话 | 敏感信息明文传输攻击 | `ref/sensitive-data-plaintext-transmission.md` |
| 如何实施 TLS 降级攻击 | 算法降级攻击 | `ref/algorithm-downgrade-attack.md` |
| 如何检测 POODLE/BEAST 漏洞 | 算法降级攻击 | `ref/algorithm-downgrade-attack.md` |
| 如何绕过证书绑定 | 证书链信任攻击 | `ref/certificate-chain-attack.md` |
| 如何实施证书链 MITM 攻击 | 证书链信任攻击 | `ref/certificate-chain-attack.md` |
| 如何检测证书验证缺陷 | 证书链信任攻击 | `ref/certificate-chain-attack.md` |
| 如何评估 PQC 迁移准备 | 后量子加密迁移指南 | `ref/post-quantum-crypto-migration.md` |
| 如何检测混合加密降级风险 | 后量子加密迁移指南 | `ref/post-quantum-crypto-migration.md` |
| 如何评估"现在收集，以后解密"风险 | 后量子加密迁移指南 | `ref/post-quantum-crypto-migration.md` |
| 如何预测会话 ID/令牌 | 随机数预测攻击 | `ref/random-number-prediction.md` |
| 如何爆破弱 PRNG 种子 | 随机数预测攻击 | `ref/random-number-prediction.md` |
| 如何利用 CWE-338 弱 PRNG | 随机数预测攻击 | `ref/random-number-prediction.md` |

### 4. 渗透测试决策流程图

```
                                    ┌─────────────────┐
                                    │   加密安全测试   │
                                    └────────┬────────┘
                                             │
                                             ▼
                                    ┌─────────────────┐
                                    │   数据分类识别   │
                                    │  - 敏感数据发现  │
                                    │  - 加密状态评估  │
                                    │  - 加密算法识别  │
                                    └────────┬────────┘
                                             │
                    ┌────────────────────────┼────────────────────────┐
                    │                        │                        │
                    ▼                        ▼                        ▼
          ┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
          │  传输层加密问题  │      │  存储加密问题   │      │   密钥管理问题  │
          └────────┬────────┘      └────────┬────────┘      └────────┬────────┘
                   │                        │                        │
                   ▼                        ▼                        ▼
          ┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
          │  ref/tls-       │      │  ref/storage-   │      │  ref/key-       │
          │  configuration- │      │  encryption-    │      │  management-    │
          │  attack.md      │      │  attack.md      │      │  attack.md      │
          └─────────────────┘      └─────────────────┘      └─────────────────┘
```

### 5. 攻击技术思维导图

```
加密失效攻击技术
├── 传输层攻击
│   ├── TLS/SSL 降级攻击
│   ├── 中间人攻击 (MITM)
│   ├── 证书验证绕过
│   └── 会话劫持
├── 存储加密攻击
│   ├── 未加密数据窃取
│   ├── 弱加密算法破解
│   ├── 加密模式攻击 (ECB)
│   └── IV 重用攻击
├── 密钥管理攻击
│   ├── 硬编码密钥提取
│   ├── 默认密钥利用
│   ├── 密钥爆破攻击
│   └── 密钥轮换缺失利用
├── 密码哈希攻击
│   ├── 彩虹表攻击
│   ├── 暴力破解
│   ├── 字典攻击
│   └── GPU 加速破解
├── 算法攻击
│   ├── 弱算法利用 (MD5/SHA1/DES)
│   ├── Padding Oracle
│   ├── 侧信道攻击
│   └── 算法降级
└── 随机数攻击
    ├── 弱 PRNG 利用
    ├── 种子预测
    ├── 会话 ID 预测
    └── 令牌预测
```

### 6. 方法论引用清单

| 编号 | 方法论名称 | 引用文件 | 适用阶段 |
|-----|-----------|---------|---------|
| CF-001 | TLS 配置攻击 | `ref/tls-configuration-attack.md` | 漏洞利用 |
| CF-002 | 加密套件降级攻击 | `ref/cipher-suite-downgrade.md` | 漏洞利用 |
| CF-003 | 密码哈希破解 | `ref/password-hash-cracking.md` | 漏洞利用 |
| CF-004 | 硬编码密钥提取 | `ref/hardcoded-key-extraction.md` | 漏洞发现 |
| CF-005 | JWT 密钥爆破 | `ref/jwt-key-bruteforce.md` | 漏洞利用 |
| CF-006 | 证书验证绕过 | `ref/certificate-validation-bypass.md` | 漏洞利用 |
| CF-007 | 中间人攻击 | `ref/man-in-the-middle-attack.md` | 漏洞利用 |
| CF-008 | 加密模式攻击 | `ref/encryption-mode-attack.md` | 漏洞利用 |
| CF-009 | 随机数预测攻击 | `ref/random-number-prediction.md` | 漏洞利用 |
| CF-010 | Padding Oracle 攻击 | `ref/padding-oracle-attack.md` | 漏洞利用 |
| CF-011 | 传统加密审计 | `ref/legacy-crypto-audit.md` | 系统化测试 |
| CF-012 | 云加密配置审计 | `ref/cloud-encryption-audit.md` | 系统化测试 |
| CF-013 | 移动加密安全测试 | `ref/mobile-encryption-testing.md` | 系统化测试 |
| CF-014 | API 传输加密测试 | `ref/api-transport-encryption.md` | 系统化测试 |
| CF-015 | 数据库加密审计 | `ref/database-encryption-audit.md` | 系统化测试 |
| CF-016 | TLS 安全检测 | `ref/tls-security-detection.md` | 漏洞发现 |
| CF-017 | 哈希破解指南 | `ref/hash-cracking-guide.md` | 漏洞利用 |
| CF-018 | 密钥提取技术 | `ref/key-extraction-techniques.md` | 漏洞发现 |
| CF-019 | 随机性检测 | `ref/randomness-detection.md` | 漏洞发现 |
| CF-020 | MITM 实施指南 | `ref/mitm-implementation.md` | 漏洞利用 |
| CF-021 | 明文凭证存储攻击 | `ref/plaintext-credential-storage.md` | 漏洞利用 |
| CF-022 | 硬编码密钥利用 | `ref/hardcoded-secret-exploitation.md` | 漏洞利用 |
| CF-023 | HTTP-only 部署攻击 | `ref/http-only-deployment-attack.md` | 漏洞利用 |
| CF-024 | 敏感信息明文存储利用 | `ref/sensitive-data-plaintext-exploitation.md` | 漏洞利用 |
| CF-025 | Docker 环境敏感信息提取 | `ref/docker-secret-extraction.md` | 漏洞利用 |
| CF-026 | 弱加密算法攻击 | `ref/weak-crypto-algorithm-attack.md` | 漏洞发现/利用 |
| CF-027 | 敏感信息明文传输攻击 | `ref/sensitive-data-plaintext-transmission.md` | 漏洞发现/利用 |
| CF-028 | 算法降级攻击 | `ref/algorithm-downgrade-attack.md` | 漏洞发现/利用 |
| CF-029 | 证书链信任攻击 | `ref/certificate-chain-attack.md` | 漏洞发现/利用 |
| CF-030 | 后量子加密迁移指南 | `ref/post-quantum-crypto-migration.md` | 系统化测试/评估 |

---

## 使用指南

### 快速开始

1. **数据分类** - 识别所有敏感数据及其加密状态
2. **算法检测** - 检测使用的加密算法和协议版本
3. **密钥审计** - 审计密钥生成、存储和轮换机制
4. **漏洞利用** - 根据发现的问题选择相应的攻击方法

### 技能关联

- 与 `pt-security-misconfiguration` 技能配合，检测加密配置问题
- 与 `pt-authentication-failures` 技能配合，破解密码哈希
- 与 `pt-broken-access-control` 技能配合，利用加密缺陷绕过访问控制

---

## 参考资源

- [OWASP Top 10:2025 A04](https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/)
- [OWASP Cheat Sheet: Transport Layer Protection](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
- [OWASP Cheat Sheet: Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [SSL Labs](https://www.ssllabs.com/ssltest/)
