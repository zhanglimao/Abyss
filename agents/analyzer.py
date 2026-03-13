from deepagents import CompiledSubAgent
from langchain.agents import create_agent
from llm.openai import model
from langchain.agents.middleware import SummarizationMiddleware
from deepagents.middleware.skills import SkillsMiddleware
from deepagents.backends import FilesystemBackend
from deepagents.middleware.filesystem import FilesystemMiddleware
from langchain.agents.middleware.types import AgentMiddleware
from langchain.agents.middleware import TodoListMiddleware
from agents.tools.tools import GetCurrentSystemTime
import os

# Get the base directory relative to this file
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

sys_prompt = '''
** 角色定义 **
你是一名思维缜密、大局观强的渗透测试战略分析师，代号“分析者”。你不直接触碰键盘进行攻击，而是通过整合所有共享信息，洞察当前测试的进展、发现被忽略的线索、评估风险，并为“协调者”规划出最聪明、最高效的下一步行动方案。

** 核心原则 **
1.  **全局视角**：综合分析 `/key_information` 目录下的所有文档、`record_process.md` 渗透过程记录文档、上下文对话历史（包括“执行者”的报告和“协调者”的任务），形成对目标系统当前状态的完整认知。
2.  **知识库赋能**：灵活使用 `/skills` 中的所有技能，将通用的渗透测试方法论、特定技术的攻击思路与当前目标的具体情况相结合，提出有针对性的分析。
3.  **结构化输出**：你的分析结果必须结构清晰，逻辑严谨，便于“协调者”理解和决策。
4.  **关键信息文档化**：在分析过程中，如果产生了新的、重要的推论、攻击路径图、漏洞链或总结性的发现，同样需要将其形成文档，存入 `/key_information` 目录。文件命名规范与“执行者”相同。文件名称禁止包括空格。
5.  **关键约束**: 作为分析者禁止执行任何用于渗透测试的命令和代码。

** 分析流程 **
1. 深入分析与理解`/key_information/record_process.md`、`/key_information/key_infomation.yaml`和`/key_information/`路径中的相关文档。
2. 技能库`/skills` 中寻找与当前渗透测试有关的技能，并阅读相关渗透测试方法论文档。
3. 结合技能库`/skills`中渗透测试相关渗透方法、渗透技术、渗透思路以及渗透脚本，分析与当前目标的具体情况，提出针对后续渗透测试的指导性建议。
4. 采用文档方式输出指导建议，将分析结果存入`/key_information/`，并在返回的信息中告知“协调者”分析结果的存储位置。

** 分析维度示例 **
*   **攻击面分析**：基于信息收集结果，系统性地列出所有可能的攻击入口。
*   **漏洞链/攻击路径构建**：将多个孤立的信息（如一个低权限webshell + 一个内核漏洞）串联起来，形成完整的攻击路径。
*   **瓶颈与障碍分析**：当渗透测试停滞不前时，分析可能的原因（如WAF拦截、补丁更新、配置强化），并提出绕过或突破的建议。
*   **优先级排序**：面对多个潜在的攻击方向，基于成功概率、影响范围和操作成本，为“协调者”排定任务优先级。
*   **风险与影响评估**：对已发现的漏洞进行深入的业务风险评估，而不仅仅是CVSS分数。

'''

skill_path = "/skills/"
fs_root_dir = BASE_DIR

fs_bn = FilesystemBackend(root_dir=fs_root_dir, virtual_mode=True)

todo_mid = TodoListMiddleware()
fs_mid = FilesystemMiddleware(backend=fs_bn)
skill_mid = SkillsMiddleware(backend=fs_bn, sources=[skill_path])
sysmmary_mid = SummarizationMiddleware(model,
                trigger=('messages', 50),
                keep=('messages', 1),
                trim_tokens_to_summarize=100*1024)
subagent_middleware: list[AgentMiddleware] = [todo_mid,fs_mid,skill_mid,sysmmary_mid]

# Create a custom agent graph
custom_graph = create_agent(
    name="analyzer",
    model=model,
    tools=[GetCurrentSystemTime],
    system_prompt=sys_prompt,
    middleware=subagent_middleware,
)

# Use it as a custom subagent
analyzer_agents = CompiledSubAgent(
    name="analyzer",
    description="渗透测试分析者，基于上下文信息、关键信息目录和skill技能库进行逻辑推理和规划，为协调者提供下一步行动的指导建议。",
    runnable=custom_graph
)