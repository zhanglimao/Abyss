import paramiko
import os
from typing import Tuple, Optional

def execute_remote_command(
    hostname: str,
    username: str,
    command: str,
    password: Optional[str] = None,
    port: int = 22,
    key_filename: Optional[str] = None,
    timeout: int = 30
) -> Tuple[bool, str, str]:
    """
    在远程服务器上执行命令
    
    Args:
        hostname: 远程主机地址
        username: 用户名
        command: 要执行的命令
        password: 密码（如果使用密码认证）
        port: SSH端口，默认22
        key_filename: 私钥文件路径（如果使用密钥认证）
        timeout: 连接超时时间（秒）
    
    Returns:
        Tuple[bool, str, str]: (是否成功, 标准输出, 错误输出)
    """
    ssh_client = None
    try:
        # 创建SSH客户端
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # 连接远程主机
        ssh_client.connect(
            hostname=hostname,
            port=port,
            username=username,
            password=password,
            key_filename=key_filename,
            timeout=timeout
        )
        
        # 执行命令
        stdin, stdout, stderr = ssh_client.exec_command(command)
        
        # 读取输出
        stdout_output = stdout.read().decode('utf-8', errors='ignore')
        stderr_output = stderr.read().decode('utf-8', errors='ignore')
        
        # 获取命令执行状态
        exit_status = stdout.channel.recv_exit_status()
        
        success = exit_status == 0
        
        return success, stdout_output, stderr_output
        
    except Exception as e:
        return False, "", f"执行命令失败: {str(e)}"
        
    finally:
        if ssh_client:
            ssh_client.close()

def execute_remote_code(
    hostname: str,
    username: str,
    code: str,
    language: str = "python",
    password: Optional[str] = None,
    port: int = 22,
    key_filename: Optional[str] = None,
    timeout: int = 30,
    working_dir: Optional[str] = None
) -> Tuple[bool, str, str]:
    """
    在远程服务器上执行代码
    
    Args:
        hostname: 远程主机地址
        username: 用户名
        code: 要执行的代码
        language: 代码语言，支持 python, bash, ruby, perl 等
        password: 密码（如果使用密码认证）
        port: SSH端口，默认22
        key_filename: 私钥文件路径（如果使用密钥认证）
        timeout: 连接超时时间（秒）
        working_dir: 工作目录
    
    Returns:
        Tuple[bool, str, str]: (是否成功, 标准输出, 错误输出)
    """
    ssh_client = None
    temp_file_path = None
    
    try:
        # 创建SSH客户端
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # 连接远程主机
        ssh_client.connect(
            hostname=hostname,
            port=port,
            username=username,
            password=password,
            key_filename=key_filename,
            timeout=timeout
        )
        
        # 确定文件扩展名和执行命令
        file_ext = {
            "python": "py",
            "bash": "sh",
            "ruby": "rb",
            "perl": "pl",
            "node": "js",
            "php": "php"
        }.get(language.lower(), "txt")
        
        exec_commands = {
            "python": "python3",
            "bash": "bash",
            "ruby": "ruby",
            "perl": "perl",
            "node": "node",
            "php": "php"
        }
        
        exec_command = exec_commands.get(language.lower(), language)
        
        # 创建临时文件
        temp_file_name = f"temp_code_{os.getpid()}.{file_ext}"
        
        # 如果需要指定工作目录
        if working_dir:
            # 创建工作目录（如果不存在）
            mkdir_command = f"mkdir -p {working_dir}"
            ssh_client.exec_command(mkdir_command)
            temp_file_path = f"{working_dir}/{temp_file_name}"
        else:
            temp_file_path = f"/tmp/{temp_file_name}"
        
        # 使用SFTP上传代码文件
        sftp = ssh_client.open_sftp()
        
        # 将代码写入远程文件
        with sftp.open(temp_file_path, 'w') as remote_file:
            remote_file.write(code)
        
        sftp.close()
        
        # 设置文件执行权限
        chmod_command = f"chmod +x {temp_file_path}"
        ssh_client.exec_command(chmod_command)
        
        # 执行代码文件
        exec_full_command = f"cd {working_dir} && {exec_command} {temp_file_path}" if working_dir else f"{exec_command} {temp_file_path}"
        stdin, stdout, stderr = ssh_client.exec_command(exec_full_command)
        
        # 读取输出
        stdout_output = stdout.read().decode('utf-8', errors='ignore')
        stderr_output = stderr.read().decode('utf-8', errors='ignore')
        
        # 获取执行状态
        exit_status = stdout.channel.recv_exit_status()
        
        success = exit_status == 0
        
        return success, stdout_output, stderr_output
        
    except Exception as e:
        return False, "", f"执行代码失败: {str(e)}"
        
    finally:
        # 清理临时文件
        if ssh_client and temp_file_path:
            try:
                ssh_client.exec_command(f"rm -f {temp_file_path}")
            except:
                pass
            
        if ssh_client:
            ssh_client.close()

# 使用示例
def example_usage():
    # 配置信息
    host = "0.0.0.0"
    user = "root"
    port = 23
    pwd = "root"
    
    # 示例1：执行远程命令
    print("="*50)
    print("执行远程命令示例")
    print("="*50)
    
    success, stdout, stderr = execute_remote_command(
        hostname=host,
        username=user,
        port=port,
        password=pwd,
        command="ls /key_information"
    )
    
    if success:
        print("命令执行成功")
        print("标准输出:")
        print(stdout)
    else:
        print("命令执行失败")
        print("错误信息:")
        print(stderr)
    
    # 示例2：执行远程Python代码
    print("\n" + "="*50)
    print("执行远程Python代码示例")
    print("="*50)
    
    python_code = """
import sys
print("Hello from remote server!")
print(f"Python version: {sys.version}")
for i in range(3):
    print(f"Count: {i}")
"""
    
    success, stdout, stderr = execute_remote_code(
        hostname=host,
        username=user,
        port=port,
        password=pwd,
        code=python_code,
        language="python"
    )
    
    if success:
        print("代码执行成功")
        print("标准输出:")
        print(stdout)
    else:
        print("代码执行失败")
        print("错误信息:")
        print(stderr)
    
    # 示例3：执行远程Bash脚本
    print("\n" + "="*50)
    print("执行远程Bash脚本示例")
    print("="*50)
    
    bash_code = """
#!/bin/bash
echo "Current directory: $(pwd)"
echo "Current user: $(whoami)"
echo "System info: $(uname -a)"
"""
    
    success, stdout, stderr = execute_remote_code(
        hostname=host,
        username=user,
        port=port,
        password=pwd,
        code=bash_code,
        language="bash"
    )
    
    if success:
        print("脚本执行成功")
        print("标准输出:")
        print(stdout)
    else:
        print("脚本执行失败")
        print("错误信息:")
        print(stderr)

if __name__ == "__main__":
    example_usage()