# 配置基线检查方法论

---

## 第一部分：文档概述

### 1.1 编写目的
为渗透测试人员提供针对系统配置基线检查的方法论，用于对比安全配置标准发现配置偏差。

### 1.2 适用范围
- 操作系统配置
- 应用服务器配置
- 数据库配置
- 网络设备配置
- 云基础设施配置

### 1.3 读者对象
- 渗透测试工程师
- 安全审计人员
- 合规审计人员

---

## 第二部分：核心检测技术专题

### 专题：配置基线检查

#### 2.1 技术介绍

配置基线检查是指将目标系统的配置与安全标准基线进行对比，发现配置偏差和安全隐患的过程。

**常见基线标准：**
- CIS Benchmarks
- NIST SP 800-53
- ISO 27001
- PCI DSS
- STIG

#### 2.2 检查方法

##### 2.2.1 自动化基线检查

```bash
# CIS-CAT (CIS 基准检查)
./cis-cat.sh -b <benchmark> -t <target>

# Lynis (Linux 安全审计)
lynis audit system

# Docker Bench (Docker 安全检查)
docker run --rm \
  --net host --pid host --userns host \
  --cap-add audit_control \
  -v /etc:/etc:ro \
  -v /var/lib/docker:/var/lib/docker:ro \
  docker/docker-bench-security

# Kube-bench (Kubernetes CIS 检查)
kube-bench
```

##### 2.2.2 手动基线检查

**Linux 系统检查：**
```bash
# 1. 密码策略
cat /etc/login.defs | grep -E "PASS_MAX_DAYS|PASS_MIN_LEN"
cat /etc/pam.d/common-password

# 2. SSH 配置
cat /etc/ssh/sshd_config | grep -E "PermitRootLogin|PasswordAuthentication"

# 3. 防火墙配置
iptables -L -n
firewall-cmd --list-all

# 4. 文件权限
ls -la /etc/passwd /etc/shadow
find / -perm -4000 -type f 2>/dev/null  # SUID 文件
```

**Windows 系统检查：**
```powershell
# 1. 密码策略
net accounts

# 2. 本地用户
net user

# 3. 服务配置
Get-Service | Where-Object {$_.Status -eq "Running"}

# 4. 防火墙配置
Get-NetFirewallRule | Where-Object {$_.Enabled -eq True}
```

#### 2.3 常见基线检查项

| 类别 | 检查项 | 安全要求 |
|-----|-------|---------|
| **账户策略** | 密码最大年龄 | ≤90 天 |
| **账户策略** | 密码最小长度 | ≥12 位 |
| **账户策略** | 账户锁定阈值 | ≤5 次失败 |
| **日志审计** | 审计策略启用 | 所有安全事件 |
| **日志审计** | 日志留存时间 | ≥6 个月 |
| **网络安全** | 不必要端口关闭 | 仅开放必要端口 |
| **网络安全** | 防火墙启用 | 所有网络接口 |
| **服务安全** | 不必要服务禁用 | 仅运行必要服务 |

#### 2.4 偏差分析

```
1. 收集当前配置
2. 对比基线标准
3. 识别偏差项
4. 评估风险等级
5. 生成修复建议
```

---

## 第三部分：附录

### 3.1 检测工具

| 工具名称 | 用途 |
|---------|------|
| **CIS-CAT** | CIS 基准评估 |
| **Lynis** | Linux 安全审计 |
| **Docker Bench** | Docker 安全检查 |
| **Kube-bench** | K8s CIS 检查 |
| **ScoutSuite** | 云安全审计 |

### 3.2 参考资源

- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)
- [NIST SP 800-53](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
