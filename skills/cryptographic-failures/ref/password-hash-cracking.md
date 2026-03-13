# 密码哈希破解方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的密码哈希破解流程和方法。

## 1.2 适用范围

本文档适用于获取到密码哈希后需要破解的场景。

## 1.3 读者对象

本文件主要面向执行渗透测试任务的安全工程师、安全分析师。

---

# 第二部分：核心渗透技术专题

## 2.1 技术介绍

### 哈希破解原理

密码哈希破解是通过各种技术手段从哈希值恢复原始密码的过程。

**常见方法**：
- 字典攻击 - 使用密码列表尝试
- 暴力破解 - 尝试所有可能组合
- 彩虹表 - 使用预计算哈希表
- 规则攻击 - 基于字典的变形

### 常见 CWE 映射

| CWE 编号 | 描述 |
|---------|------|
| CWE-916 | 使用计算强度不足的密码哈希 |
| CWE-759 | 使用无盐单向哈希 |
| CWE-328 | 使用弱哈希算法 |

## 2.2 常见哈希算法识别

| 哈希类型 | 长度 | 示例 |
|---------|------|------|
| MD5 | 32 字符 | 5f4dcc3b5aa765d61d8327deb882cf99 |
| SHA1 | 40 字符 | a94a8fe5ccb19ba61c4c0873d391e987982fbbd3 |
| SHA256 | 64 字符 | 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8 |
| bcrypt | 60 字符 | $2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy |
| NTLM | 32 字符 | 8846f7eaee8fb117ad06bdd830b7586c |
| WordPress | 34 字符 | $P$B5ZD5mWkS6V08jDzEc7g5J8B0XqkZ0 |

## 2.3 哈希破解方法

### 2.3.1 字典攻击

```bash
# 使用 Hashcat
hashcat -m 0 hashes.txt rockyou.txt

# 使用 John the Ripper
john --wordlist=rockyou.txt hashes.txt

# 常用字典：
# - rockyou.txt (1400 万密码)
# - SecLists 字典集
# - 常用密码字典
```

### 2.3.2 暴力破解

```bash
# Hashcat 暴力破解
# ?a = 字母数字特殊字符
# ?l = 小写字母
# ?u = 大写字母
# ?d = 数字

hashcat -m 0 -a 3 hashes.txt ?a?a?a?a?a?a?a?a

# 8 位纯数字
hashcat -m 0 -a 3 hashes.txt ?d?d?d?d?d?d?d?d
```

### 2.3.3 规则攻击

```bash
# 使用 Hashcat 规则引擎
hashcat -m 0 -r rules/best64.rule hashes.txt rockyou.txt

# 常见规则：
# - 大小写变换
# - 添加数字后缀
# - 添加特殊字符
# - 替换字符 (e→3, a→@)
```

### 2.3.4 彩虹表攻击

```bash
# 使用在线彩虹表
# - CrackStation.net
# - HashKiller.co.uk
# - md5decrypt.net

# 本地彩虹表
# 使用 rainbowcrack 工具
```

## 2.4 漏洞利用方法

### 2.4.1 数据库密码哈希破解

```bash
# 1. 从数据库获取哈希
SELECT username, password FROM users;

# 2. 识别哈希类型
hashid '$2a$10$...'

# 3. 选择对应模式破解
hashcat -m 3200 hashes.txt rockyou.txt  # bcrypt
```

### 2.4.2 系统密码文件破解

```bash
# Linux /etc/shadow
unshadow passwd shadow > crackable.txt
john crackable.txt

# Windows SAM 文件
pwdump.py system sam > hashes.txt
hashcat -m 1000 hashes.txt rockyou.txt  # NTLM
```

### 2.4.3 在线服务哈希破解

```bash
# 从网络抓包获取哈希
# 从 API 响应获取哈希
# 从日志文件获取哈希
```

## 2.5 优化破解效率

### 2.5.1 GPU 加速

```bash
# 使用 GPU 加速（比 CPU 快 10-100 倍）
hashcat -D 2 -m 0 hashes.txt rockyou.txt

# -D 2 = 使用 GPU
# -D 1 = 使用 CPU
# -D 3 = 使用 CPU+GPU
```

### 2.5.2 掩码攻击

```bash
# 如果知道密码模式
# 例如：大写字母 +6 位数字
hashcat -m 0 -a 3 hashes.txt ?u?d?d?d?d?d?d

# 例如：单词 +4 位数字
hashcat -m 0 -a 3 hashes.txt password?d?d?d?d
```

### 2.5.3 组合攻击

```bash
# 组合两个字典
hashcat -m 0 -a 6 hashes.txt rockyou.txt rockyou.txt
```

---

# 第三部分：附录

## 3.1 哈希类型速查

| Hashcat 模式 | 算法 | 描述 |
|------------|------|------|
| 0 | MD5 | 常见 Web 应用 |
| 100 | SHA1 | 常见 Web 应用 |
| 1400 | SHA256 | 现代应用 |
| 3200 | bcrypt | WordPress, OpenBSD |
| 1000 | NTLM | Windows |
| 2611 | vBulletin | vBulletin < 4.2.5 |
| 8400 | WPA2 | WiFi 密码 |

## 3.2 常用工具

| 工具 | 用途 | 链接 |
|-----|------|------|
| Hashcat | GPU 密码破解 | https://hashcat.net/hashcat/ |
| John the Ripper | 密码破解 | https://www.openwall.com/john/ |
| hash-identifier | 哈希识别 | Kali 内置 |
| CrackStation | 在线破解 | https://crackstation.net/ |

## 3.3 修复建议

1. **使用强哈希算法** - bcrypt, Argon2, scrypt
2. **加盐** - 每个密码唯一盐值
3. **工作因子** - 增加计算成本
4. **密码策略** - 最小长度、复杂度要求

---

**参考资源**：
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [Hashcat Wiki](https://hashcat.net/wiki/)
