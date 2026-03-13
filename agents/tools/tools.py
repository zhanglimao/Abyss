from pydantic import BaseModel, Field
from typing import List
import sys
from langchain.tools import tool
import subprocess
import datetime


@tool()
def GetCurrentSystemTime()->int:
    "查询当前系统时间"
    now = datetime.datetime.now()
    return now.strftime("%Y-%m-%d %H:%M:%S")

class ExecScriptInput(BaseModel):
    script_cmd: str = Field("需要执行的命令或者脚本", examples=["ls -l","python xxx.py","/bin/du -sh"])
@tool(args_schema=ExecScriptInput)
def ExecScript(script_cmd:str) -> str:
    """执行脚本或者命令并返回输出结果"""
    try:
        result = subprocess.run(script_cmd, shell=True, capture_output=True, text=True, timeout=5*60)
        if result.returncode == 0:
            return result.stdout[:100000]  # 只返回前2000个字符，避免输出过长
        else:
            return result.stderr
    except Exception as e:
        print(f"执行脚本{script_cmd}失败，错误原因:" + str(e))
        return f"执行脚本{script_cmd}失败，错误原因:" + str(e)

class ExecCode(BaseModel):
    code: str = Field("需要执行的代码，默认使用python")
    ctype: str = Field("代码类型", examples=["python"])
@tool(args_schema=ExecCode)
def ExecPythonCode(code:str, ctype:str):
    """执行python代码并返回输出结果"""
    with open("temp_exec_code.py", "w", encoding='utf-8') as f:
        f.write(code)
    try:
        result = subprocess.run("python temp_exec_code.py", shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout[:100000]
        else:
            return result.stderr
    except Exception as e:
        print(f"执行代码{code[:100]}...失败，错误原因:" + str(e))
        return f"执行代码{code[:100]}...失败，错误原因:" + str(e)