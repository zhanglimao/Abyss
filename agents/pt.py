import os
import sys
import shutil
sys.path.append("..")
from deepagents import create_deep_agent
from deepagents.backends import FilesystemBackend
from langgraph.checkpoint.memory import MemorySaver
from langchain.messages import HumanMessage
from langchain_core.messages.base import BaseMessage
from langgraph.store.memory import InMemoryStore
from agents.exploiter import exploiter_agents
from agents.analyzer import analyzer_agents
from agents.report import report_agents
from agents.tools.tools import GetCurrentSystemTime
from llm.openai import model

sys_prompt = '''
### 角色定义

你是一名资深的**渗透测试调度专家**，代号“调度官”。你的核心职责不是直接进行技术攻击，而是作为团队的大脑和中枢，负责指挥、协调并整合一个由多个专业子智能体（Subagent）组成的渗透测试团队，以高效、系统化地完成指定的渗透测试任务。

**你的团队（子智能体）**

你拥有一个由三位专家组成的精英团队，每位专家都有其独特的职责。你需要根据任务进展，精准地向他们下达指令并处理他们的反馈。

1.  **分析专家 (analyzer)**
    *   **职责**：团队的“军师”。负责分析当前渗透测试的全局情况，结合历史记录、已知漏洞、系统架构等信息，规划后续的渗透测试方向与具体计划。
    *   **输入**：你（调度官）需要向它提供 **`当前渗透测试情况`**（包括已尝试的方法、已获得的信息、遇到的困难等）。
    *   **输出**：它会返回一份 **`后续渗透测试建议`**，通常是一个或多个具体的、可执行的任务点子项。
    *   **能力**: 分析当前渗透情况；对后续渗透计划进行指导；根据业务需求，制定适当的渗透测试计划。

2.  **执行专家 (exploiter)**
    *   **职责**：团队的“手脚”。负责将分析专家的建议或你的指令转化为实际的技术操作。它是唯一一个真正“动手”的专家。
    *   **输入**：你（调度官）需要向它下达 **`明确的渗透测试任务`**，并提供必要的 **`参考文档或工具路径`**（如POC代码地址、漏洞利用手册、命令脚本等）。
    *   **输出**：它会返回 **`任务执行结果`**（成功/失败、返回数据、错误信息等）。
    *   **能力**: 执行具体的渗透测试任务，包括执行命令、编写代码、执行代码、调用工具等。

3.  **报告专家 (reporter)**
    *   **职责**：团队的“笔杆子”。负责在渗透测试任务结束时，将所有过程、发现、成果整理成一份结构清晰、内容详实的最终报告。
    *   **输入**：你（调度官）需要向它提供最终的 **`渗透测试结论与所有相关过程记录`**。
    *   **输出**：它会生成一份完整的 **`渗透测试报告`**。

---

### **你的核心工作流程（调度策略）**

请严格按照以下流程图逻辑进行思考和调度。这是一个基于任务状态的循环决策过程。

```mermaid
graph TD
    Start([开始新任务/收到用户请求]) --> Step1{调用分析专家<br>拆解任务形成计划};
    Step1 -- 分析建议 --> Step2[调度官: 解析建议,<br>形成具体子任务];
    Step2 --> Step3{子任务是否需要执行?};

    Step3 -- 需要执行 --> Step4[调用执行专家<br>执行具体任务];
    Step4 -- 返回执行结果与方法 --> Step5{是否完成<br>原始渗透任务?};

    Step5 -- 是, 已完成 --> Step6[调用报告专家<br>生成最终报告];
    Step6 --> End([任务结束, 输出报告]);

    Step5 -- 否, 未完成 --> Step7[调用分析专家<br>规划后续渗透任务];
    Step7 -- 返回后续任务 --> Step1;

    Step3 -- 不需要执行 --> Step8{检查是否还有<br>未执行的子任务?};
    Step8 -- 有 --> Step2;
    Step8 -- 无 --> Step7;
```

---

### **启动指令与注意事项**

*   **初始状态**：当用户提出一个渗透测试目标（如“请对目标IP 192.168.1.100 进行完整的渗透测试”）时，你的第一个动作就是**调用分析专家**，进入工作流程的第一步。
*   **信息传递**：在与各专家交互时，务必清晰、完整地传递信息。例如，给执行专家的指令必须包含具体命令或工具用法，给监督专家的信息必须包含“用什么方法”和“得到什么结果”。
*   **循环决策**：你的核心是“调度”和“决策”。在每次执行专家返回失败后，你都必须先通过监督专家记录，再回到分析专家重新规划，直到任务完成或你认为所有路径都已尝试完毕（此时也应通过报告专家生成一份包含所有尝试过程的报告）。

**现在，请你以渗透测试调度专家的身份，开始接收用户的渗透测试请求。**
'''

checkpointer = MemorySaver()

# Get the base directory relative to this file
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

skill_path = "/skills/"

_stop_pt = False

def start_pt(query:str):
    global _stop_pt
    _stop_pt = False  # 重置停止标志
    
    pt_test = create_deep_agent(
        name = "PenetrationTestingAgent",
        model = model,
        tools=[GetCurrentSystemTime],
        backend=FilesystemBackend(root_dir=BASE_DIR, virtual_mode=True),
        # store = InMemoryStore(),
        skills=[skill_path],
        system_prompt=sys_prompt,
        subagents=[exploiter_agents,analyzer_agents,report_agents],
    )
    query_msg = {"messages": [HumanMessage(query)]}

    for namespace, chunk in pt_test.stream(query_msg,stream_mode="updates",subgraphs=True):
        if _stop_pt:
            break
        # Main agent updates (empty namespace)
        subagent=None
        if namespace:
            subagent = namespace[0]
            
        for node_name, data in chunk.items():
            if data and "messages" in data:
                msgs = data['messages']
                if hasattr(msgs, "value"):
                    msgs = msgs.value
                
                for msg in msgs:
                    if isinstance(msg, BaseMessage) is False:
                        print("Not BaseMessage:", msg)
                        continue
                    conversation = {
                        "subagent": subagent,
                        "type": msg.type,
                        "content": msg.content,
                        "id": msg.id
                    }

                    if hasattr(msg, "tool_calls"):
                        conversation["tool_calls"] = msg.tool_calls
                    
                    if hasattr(msg, "tool_call_id"):
                        conversation["tool_call_id"] = msg.tool_call_id

                    yield conversation

def stop_pt():
    """停止当前运行的渗透测试任务"""
    global _stop_pt
    _stop_pt = True
    key_information_path = os.path.join(BASE_DIR, "key_information")
    print("key_information_path:",key_information_path)
    shutil.rmtree(key_information_path, ignore_errors=True)
    os.makedirs(key_information_path, exist_ok=True)
    
    
                            
if __name__ == "__main__":
    for item in start_pt("获取指定地址的FLAG，FLAG格式固定为：CTF{{xxxxxx}}、FLAG{{xxxxx}} 或者ctfhub{{xxxxxx}}，\
        必须拿到FLAG后且验证无误后才算完成任务，\
        禁止地址解析成IP后进行渗透，\
        渗透地址： 0.0.0.0:50960"):
        
        print(item)