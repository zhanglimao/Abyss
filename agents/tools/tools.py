from pydantic import BaseModel, Field
import os
import json
from langchain.tools import tool
import datetime
from agents.tools.sandbox_interface import execute_remote_command,execute_remote_code

config_path = os.path.join(os.path.dirname(__file__), "sandbox.json")
with open(config_path, "r") as f:
    data = json.load(f)
    sb_host = data["host"]
    sb_user = data["user"]
    sb_pwd = data["pwd"]
    sb_port = data["port"]

@tool()
def GetCurrentSystemTime()->int:
    "查询当前系统时间"
    now = datetime.datetime.now()
    return now.strftime("%Y-%m-%d %H:%M:%S")

class ExecCmdInput(BaseModel):
    script_cmd: str = Field("需要执行的命令", examples=["ls -l","curl xxx","/bin/wget xxx"])
@tool(args_schema=ExecCmdInput)
def ExecCmd(script_cmd:str) -> str:
    """执行命令并返回输出结果"""
    success, stdout, stderr = execute_remote_command(
        hostname=sb_host,
        username=sb_user,
        port=sb_port,
        password=sb_pwd,
        command=script_cmd
    )
    
    if success:
        return stdout[:100000]  # 只返回前100k字符，避免输出过长
    else:
        return stderr

class ExecCodeInput(BaseModel):
    code: str = Field("需要执行的代码，默认使用python")
    ctype: str = Field("代码类型", examples=["python","bash"])
@tool(args_schema=ExecCodeInput)
def ExecCode(code:str, ctype:str):
    """执行代码或者脚本并返回输出结果"""
    success, stdout, stderr = execute_remote_code(
        hostname=sb_host,
        username=sb_user,
        port=sb_port,
        password=sb_pwd,
        code=code,
        language=ctype
    )
    
    if success:
        return stdout[:100000]  # 只返回前100k字符，避免输出过长
    else:
        return stderr