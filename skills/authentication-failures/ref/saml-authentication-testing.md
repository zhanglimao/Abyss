# **渗透测试方法论：SAML 认证测试**

---

# **第一部分：文档概述**

## 1.1 编写目的
- 为渗透测试人员提供一套标准化的 SAML 2.0 认证安全测试流程
- 帮助测试人员系统性地发现 SAML 实现中的安全缺陷
- 提高 SAML 认证漏洞发现的准确率和效率

## 1.2 适用范围
- 适用于使用 SAML 2.0 的企业 SSO 系统
- 适用于 SAML IdP（身份提供商）和 SP（服务提供商）集成
- 适用于 B2B  federated identity 场景

## 1.3 读者对象
- 本文件主要面向执行渗透测试任务的安全工程师、安全分析师
- 负责 SAML 集成的开发人员
- 负责身份管理系统运维的技术人员

---

# **第二部分：核心渗透技术专题**

## 专题一：SAML 认证测试

### 2.1 技术介绍

SAML 认证测试是指对 Security Assertion Markup Language (SAML) 2.0 联邦认证实现进行全面的安全评估。其本质是**验证 SAML 断言的生成、传输和验证过程是否安全，防止认证绕过和身份冒充**。

SAML 核心组件：

| **组件** | **描述** | **安全风险** |
| :--- | :--- | :--- |
| IdP (身份提供商) | 认证用户并颁发断言 | 配置错误、证书泄露 |
| SP (服务提供商) | 消费断言并授予访问 | 验证不当、信任错误 |
| SAML 断言 | 包含用户身份和属性 | 篡改、伪造 |
| XML 签名 | 保护断言完整性 | 签名绕过、算法降级 |
| SAML Metadata | 配置信任关系 | 配置泄露、篡改 |

### 2.2 测试常见于哪些业务场景

| **业务场景** | **功能示例** | **风险点描述** |
| :--- | :--- | :--- |
| **企业 SSO** | 员工登录企业应用 | 签名验证不当导致绕过 |
| **云服务集成** | Office365、Salesforce 登录 | 配置错误导致未授权访问 |
| **B2B 门户** | 合作伙伴访问门户 | 信任关系配置错误 |
| **教育联邦** | 高校间资源共享 | 跨域信任配置不当 |
| **政府系统** | 跨部门身份互认 | 属性映射配置错误 |
| **医疗系统** | 医疗机构间数据共享 | 患者隐私泄露 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

- **SAML 流量分析**
  - 拦截 SAML Request 和 Response
  - 分析断言结构和签名
  - 检查加密使用情况
  - 分析 NameID 格式

- **签名测试**
  - 尝试移除签名
  - 尝试修改签名算法
  - 尝试 XML 签名包装攻击
  - 尝试证书混淆

- **断言篡改测试**
  - 修改用户身份属性
  - 修改权限/角色属性
  - 修改有效期条件
  - 重放旧断言

- **元数据分析**
  - 获取 IdP/SP 元数据
  - 分析支持的绑定和协议
  - 检查证书信息
  - 分析端点配置

#### 2.3.2 白盒测试

- **配置审计**
  - 检查 IdP 和 SP 配置
  - 审计证书管理
  - 检查属性映射配置
  - 检查信任关系配置

- **代码审计**
  - 检查 SAML Response 验证逻辑
  - 审计签名验证代码
  - 检查属性处理逻辑
  - 查找硬编码证书

### 2.4 漏洞利用方法

#### 2.4.1 基础信息收集

```bash
# 获取 SAML 元数据
curl https://idp.example.com/saml/metadata
curl https://sp.example.com/saml/metadata

# 分析元数据
# 查看 EntityID、端点、证书、支持的绑定
```

#### 2.4.2 签名绕过攻击

```xml
<!-- 原始签名 SAML Response -->
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <!-- 有效签名 -->
  </ds:Signature>
  <saml:Assertion>
    <saml:Subject>
      <saml:NameID>user@example.com</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>

<!-- 攻击：移除签名 -->
<samlp:Response>
  <saml:Assertion>
    <saml:Subject>
      <saml:NameID>admin@example.com</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>
```

#### 2.4.3 XML 签名包装攻击

```xml
<!-- 攻击：签名包装 -->
<samlp:Response>
  <ds:Signature>
    <!-- 签名指向伪造的 Assertion -->
    <ds:Reference URI="#fake">
  </ds:Signature>
  <!-- 伪造的 Assertion（被签名） -->
  <saml:Assertion Id="fake">
    <saml:Subject>
      <saml:NameID>attacker@example.com</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
  <!-- 真实的 Assertion（实际使用） -->
  <saml:Assertion>
    <saml:Subject>
      <saml:NameID>admin@example.com</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>
```

#### 2.4.4 属性篡改

| **操作** | **方法** | **目的** |
| :--- | :--- | :--- |
| 用户身份篡改 | 修改 NameID 或 email 属性 | 冒充其他用户 |
| 角色提升 | 修改 role 或 group 属性 | 获取管理员权限 |
| 有效期延长 | 修改 Conditions 有效期 | 延长断言有效时间 |
| 审计绕过 | 修改审计相关属性 | 绕过日志记录 |

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过签名验证

- **算法降级** - 使用弱算法或 none 算法
- **证书混淆** - 利用多个证书的验证混乱
- **签名位置** - 将签名放在非标准位置
- **XML 规范化** - 利用规范化差异

#### 2.5.2 绕过有效期检查

- **时间同步** - 修改系统时间
- **时区绕过** - 利用时区处理差异
- **边界测试** - 在有效期边界测试

#### 2.5.3 绕过重放保护

- **快速重放** - 在有效期内快速重放
- **多 SP 重放** - 在不同 SP 间重放
- **索引绕过** - 如果仅检查最近的重放

---

# **第三部分：附录**

## 3.1 SAML 测试检查清单

| **检查项** | **测试方法** | **预期结果** |
| :--- | :--- | :--- |
| 签名验证 | 移除签名 | 应拒绝响应 |
| 签名算法 | 使用弱算法 | 应拒绝响应 |
| 证书验证 | 使用无效证书 | 应拒绝响应 |
| 有效期检查 | 使用过期断言 | 应拒绝响应 |
| 重放保护 | 重放断言 | 应拒绝重放 |
| 属性验证 | 修改属性 | 应检测篡改 |
| 加密使用 | 检查敏感属性 | 应加密传输 |
| 绑定验证 | 修改绑定方式 | 应拒绝请求 |

## 3.2 SAML 测试工具

| **工具名称** | **用途** | **命令示例** |
| :--- | :--- | :--- |
| **SAML Raider** | Burp 扩展 | SAML 测试专用 |
| **SAMLtrator** | Firefox 扩展 | 拦截 SAML 流量 |
| **Modlishka** | 反向代理 | 钓鱼测试 |
| **xmlsec** | XML 签名工具 | 验证/创建签名 |
| **Burp Suite** | 拦截/修改 | 手动测试 |

## 3.3 修复建议

1. **强制签名验证** - 始终验证 SAML Response 签名
2. **签名位置验证** - 验证签名在正确位置
3. **算法白名单** - 仅允许安全算法（RSA-SHA256+）
4. **证书链验证** - 完整验证证书链
5. **有效期检查** - 严格检查 NotBefore 和 NotOnOrAfter
6. **重放保护** - 实现断言 ID 缓存
7. **属性加密** - 加密敏感属性
8. **绑定验证** - 验证请求绑定方式
9. **审计日志** - 记录所有 SSO 事件
10. **定期轮换** - 定期轮换证书和密钥
