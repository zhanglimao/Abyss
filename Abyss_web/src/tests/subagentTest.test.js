/**
 * Subagent 消息配对和分组测试
 * 测试基于示例数据的消息解析、工具配对和 subagent 分组逻辑
 */

import { describe, test, expect } from 'vitest';
import {
  parseMessageStream,
  convertToFrontendMessage,
  convertMessagesToFrontend,
  pairToolCalls,
  groupBySubAgent,
} from '../utils/messageParser.js';

// 示例测试数据
const SAMPLE_DATA = `----消息说明----
{"subagent": null, "type": "human", "content": "渗透 0.0.0.0:1234", "id": "38f41652-fcba-4cf5-b7cf-152b6438045a"}
----end----
----消息说明----
{"subagent": null, "type": "ai", "content": "我将启动渗透测试流程。首先，让我调用分析专家来制定渗透测试计划。\\n\\n", "id": "lc_run--019cd878-c37f-72c1-a321-6668134b37d6-0", "tool_calls": [{"name": "task", "args": {"description": "作为分析专家，请分析以下渗透测试目标并制定详细的渗透测试计划：\\n\\n**目标信息：**\\n- 目标地址：0.0.0.0:1234\\n\\n**任务要求：**\\n1. 分析该目标的潜在攻击面\\n2. 制定系统化的渗透测试步骤和优先级\\n3. 考虑常见的 Web 服务漏洞、网络服务漏洞等\\n4. 提供具体可执行的子任务列表\\n\\n请返回一份结构化的后续渗透测试建议，包括具体的测试方向和优先级排序。", "subagent_type": "analyzer"}, "id": "call_75f850d12daf4fb5b2e715b5", "type": "tool_call"}]}
----end----
----消息说明----
{"subagent": "tools:89e482bf-7707-3e10-1852-16859683c50a", "type": "ai", "content": "# 渗透测试战略分析报告\\n\\n**目标地址**: 0.0.0.0:1234  \\n**分析者代号**: 分析者  \\n**分析时间**: 2026-01-03\\n\\n---\\n\\n## 一、初始情报评估\\n", "id": "lc_run--019cd878-d66e-7b21-8e09-1bd0d5ad0aea-0", "tool_calls": [{"name": "write_todos", "args": {"todos": [{"content": "阶段一：信息收集与侦察", "status": "in_progress"}]}, "id": "call_567682a3174e4ee798303d3d", "type": "tool_call"}]}
----end----
----消息说明----
{"subagent": "tools:89e482bf-7707-3e10-1852-16859683c50a", "type": "tool", "content": "Updated todo list to [{'content': '阶段一：信息收集与侦察', 'status': 'in_progress'}]", "id": "b9bcab51-28fe-4a83-a19e-2fa9306f50e7", "tool_call_id": "call_567682a3174e4ee798303d3d"}
----end----
----消息说明----
{"subagent": "tools:89e482bf-7707-3e10-1852-16859683c50a", "type": "ai", "content": "现在让我创建详细的信息收集文档和攻击路径分析文档：\\n\\n", "id": "lc_run--019cd878-fe57-7ea3-9353-fa80efa14c42-0", "tool_calls": [{"name": "write_file", "args": {"file_path": "/key_information/reconnaissance_plan.md", "content": "# 信息收集计划"}, "id": "call_85be82a82dbb4e169d241819", "type": "tool_call"}]}
----end----
----消息说明----
{"subagent": "tools:89e482bf-7707-3e10-1852-16859683c50a", "type": "tool", "content": "Updated file /key_information/reconnaissance_plan.md", "id": "959b218b-b0a9-4d18-8474-b43f58fff5b8", "tool_call_id": "call_85be82a82dbb4e169d241819"}
----end----
----消息说明----
{"subagent": null, "type": "tool", "content": "---\\n\\n# 📊 渗透测试战略分析总结\\n\\n", "id": "a838fd57-9f15-4595-abc0-1f96812a065e", "tool_call_id": "call_75f850d12daf4fb5b2e715b5"}
----end----
----消息说明----
{"subagent": null, "type": "ai", "content": "好的，分析专家已经完成了初步分析并制定了详细的渗透测试计划。现在我需要调度执行专家开始执行第一阶段的任务。\\n\\n让我先创建一个任务列表来跟踪整个渗透测试过程：\\n\\n", "id": "lc_run--019cd87b-f8fa-71e0-93dc-c724796ade20-0", "tool_calls": [{"name": "write_todos", "args": {"todos": [{"content": "阶段一：信息收集 - 端口扫描和服务识别", "status": "in_progress"}]}, "id": "call_eca92c7098714ba5a91bc501", "type": "tool_call"}]}
----end----
----消息说明----
{"subagent": null, "type": "tool", "content": "Updated todo list to [{'content': '阶段一：信息收集 - 端口扫描和服务识别', 'status': 'in_progress'}]", "id": "804e2662-a4ca-4055-9556-cf9f1553fbeb", "tool_call_id": "call_eca92c7098714ba5a91bc501"}
----end----`;

describe('Subagent 消息配对和分组', () => {
  test('应该正确解析消息流', () => {
    const parsedMessages = parseMessageStream(SAMPLE_DATA);
    
    expect(parsedMessages.length).toBe(9);
    
    // 验证第一条消息（用户消息）
    expect(parsedMessages[0].msgType).toBe('human');
    expect(parsedMessages[0].subagent).toBeNull();
    expect(parsedMessages[0].msg.content).toBe('渗透 0.0.0.0:1234');
    
    // 验证第二条消息（AI 消息，包含工具调用）
    expect(parsedMessages[1].msgType).toBe('ai');
    expect(parsedMessages[1].subagent).toBeNull();
    expect(parsedMessages[1].msg.tool_calls).toHaveLength(1);
    expect(parsedMessages[1].msg.tool_calls[0].id).toBe('call_75f850d12daf4fb5b2e715b5');
    
    // 验证第三条消息（子 Agent AI 消息）
    expect(parsedMessages[2].msgType).toBe('ai');
    expect(parsedMessages[2].subagent).toBe('tools:89e482bf-7707-3e10-1852-16859683c50a');
    
    // 验证第四条消息（子 Agent 工具结果）
    expect(parsedMessages[3].msgType).toBe('tool');
    expect(parsedMessages[3].subagent).toBe('tools:89e482bf-7707-3e10-1852-16859683c50a');
    expect(parsedMessages[3].msg.tool_call_id).toBe('call_567682a3174e4ee798303d3d');
  });

  test('应该正确转换为前端消息格式', () => {
    const parsedMessages = parseMessageStream(SAMPLE_DATA);
    const frontendMessages = parsedMessages
      .map(msg => convertToFrontendMessage(msg, 'test-task-id'))
      .filter(msg => msg !== null);

    expect(frontendMessages.length).toBe(9);

    // 验证第一条消息（用户消息）
    const userMsg = frontendMessages[0];
    expect(userMsg.type).toBe('user_message');
    expect(userMsg.isSubAgent).toBe(false);
    expect(userMsg.subAgentId).toBeNull();

    // 验证第二条消息（AI 消息，包含工具调用）
    const aiMsg = frontendMessages[1];
    expect(aiMsg.type).toBe('assistant_message');
    expect(aiMsg.isSubAgent).toBe(false);
    expect(aiMsg.toolCalls).toHaveLength(1);
    expect(aiMsg.toolCalls[0].id).toBe('call_75f850d12daf4fb5b2e715b5');

    // 验证第三条消息（子 Agent AI 消息）
    const subAgentMsg = frontendMessages[2];
    expect(subAgentMsg.type).toBe('assistant_message');
    expect(subAgentMsg.isSubAgent).toBe(true);
    expect(subAgentMsg.subAgentId).toBe('tools:89e482bf-7707-3e10-1852-16859683c50a');

    // 验证工具结果消息
    const toolResultMsg = frontendMessages[3];
    expect(toolResultMsg.type).toBe('tool_result');
    expect(toolResultMsg.toolCallId).toBe('call_567682a3174e4ee798303d3d');
  });

  test('应该正确配对工具调用和工具结果', () => {
    const parsedMessages = parseMessageStream(SAMPLE_DATA);
    const frontendMessages = parsedMessages
      .map(msg => convertToFrontendMessage(msg, 'test-task-id'))
      .filter(msg => msg !== null);

    const { messages: pairedMessages, pairedToolResultIds, toolCallMap } = pairToolCalls(frontendMessages);

    // 验证配对结果
    // 应该有 4 个工具调用被配对：
    // 1. call_75f850d12daf4fb5b2e715b5 (主 Agent -> 主 Agent tool)
    // 2. call_567682a3174e4ee798303d3d (子 Agent -> 子 Agent tool)
    // 3. call_85be82a82dbb4e169d241819 (子 Agent -> 子 Agent tool)
    // 4. call_eca92c7098714ba5a91bc501 (主 Agent -> 主 Agent tool)
    expect(pairedToolResultIds.size).toBe(4);

    // 验证工具调用状态
    expect(toolCallMap.get('call_75f850d12daf4fb5b2e715b5').toolCall.status).toBe('completed');
    expect(toolCallMap.get('call_567682a3174e4ee798303d3d').toolCall.status).toBe('completed');
    expect(toolCallMap.get('call_85be82a82dbb4e169d241819').toolCall.status).toBe('completed');
    expect(toolCallMap.get('call_eca92c7098714ba5a91bc501').toolCall.status).toBe('completed');

    // 验证配对的消息数量（过滤掉已配对的工具结果）
    const displayMessages = pairedMessages.filter(msg => !pairedToolResultIds.has(msg.id));
    expect(displayMessages.length).toBe(5); // 9 - 4 = 5
  });

  test('应该正确按 subagent 分组消息', () => {
    const parsedMessages = parseMessageStream(SAMPLE_DATA);
    const frontendMessages = parsedMessages
      .map(msg => convertToFrontendMessage(msg, 'test-task-id'))
      .filter(msg => msg !== null);

    const { messages: pairedMessages, pairedToolResultIds } = pairToolCalls(frontendMessages);
    const groups = groupBySubAgent(pairedMessages);

    // 验证分组数量
    // 消息流程：
    // 0: user_message (null)
    // 1: assistant_message (null) <- call_75f850d 的 AI 消息
    // 2: assistant_message (subagent)
    // 3: tool_result (subagent) <- 配对到 2
    // 4: assistant_message (subagent)
    // 5: tool_result (subagent) <- 配对到 4
    // 6: tool_result (null) <- 配对到 1，但在消息 7 之前到达
    // 7: assistant_message (null)
    // 8: tool_result (null) <- 配对到 7
    //
    // 分组逻辑：按连续 subagent 分组，工具结果跟随配对的 AI 消息的 subagent
    // 分组 0: 消息 0, 1 (主 Agent - human + ai)
    // 分组 1: 消息 2, 3, 4, 5 (子 Agent)
    // 分组 2: 消息 6, 7, 8 (主 Agent - tool + ai + tool)
    expect(groups.length).toBe(3);

    // 验证第一个分组（主 Agent - human + ai）
    expect(groups[0].isSubAgent).toBe(false);
    expect(groups[0].messages.length).toBe(2);
    expect(groups[0].messages[0].type).toBe('user_message');
    expect(groups[0].messages[1].type).toBe('assistant_message');

    // 验证第二个分组（子 Agent）
    expect(groups[1].isSubAgent).toBe(true);
    expect(groups[1].subAgentId).toBe('tools:89e482bf-7707-3e10-1852-16859683c50a');
    expect(groups[1].messages.length).toBe(4); // 2 AI + 2 tool

    // 验证第三个分组（主 Agent - tool + ai + tool）
    expect(groups[2].isSubAgent).toBe(false);
    expect(groups[2].messages.length).toBe(3); // 1 tool (call_75f850d) + 1 AI + 1 tool (call_eca92c7)
    expect(groups[2].messages[0].type).toBe('tool_result');
    expect(groups[2].messages[0].toolCallId).toBe('call_75f850d12daf4fb5b2e715b5');
    expect(groups[2].messages[1].type).toBe('assistant_message');
    expect(groups[2].messages[2].type).toBe('tool_result');
  });

  test('应该正确处理工具结果的 subagent 跟随逻辑', () => {
    const parsedMessages = parseMessageStream(SAMPLE_DATA);
    const frontendMessages = parsedMessages
      .map(msg => convertToFrontendMessage(msg, 'test-task-id'))
      .filter(msg => msg !== null);

    const { messages: pairedMessages, pairedToolResultIds, toolCallMap } = pairToolCalls(frontendMessages);
    const groups = groupBySubAgent(pairedMessages);

    // 验证子 Agent 组的工具结果是否正确跟随 AI 消息的 subagent
    const subAgentGroup = groups[1];
    expect(subAgentGroup.isSubAgent).toBe(true);
    
    // 子 Agent 组中的工具结果应该与 AI 消息的 subagent 一致
    const toolResults = subAgentGroup.messages.filter(msg => msg.type === 'tool_result');
    toolResults.forEach(toolResult => {
      // 验证工具结果已配对
      expect(pairedToolResultIds.has(toolResult.id)).toBe(true);
      
      // 验证配对的 AI 消息的 subagent 与工具结果一致
      const pairedAiMsg = toolResult.pairedToolCall.message;
      expect(pairedAiMsg.subAgentId).toBe('tools:89e482bf-7707-3e10-1852-16859683c50a');
    });
  });

  test('应该正确验证完整的消息流程', () => {
    const parsedMessages = parseMessageStream(SAMPLE_DATA);
    const frontendMessages = parsedMessages
      .map(msg => convertToFrontendMessage(msg, 'test-task-id'))
      .filter(msg => msg !== null);

    const { messages: pairedMessages, pairedToolResultIds } = pairToolCalls(frontendMessages);
    const groups = groupBySubAgent(pairedMessages);

    // 计算应该显示的消息数量
    let totalDisplayMessages = 0;
    groups.forEach(group => {
      const displayMessages = group.messages.filter(msg => !pairedToolResultIds.has(msg.id));
      totalDisplayMessages += displayMessages.length;
    });

    // 总消息数应该是 5（9 条消息 - 4 条已配对的工具结果）
    expect(totalDisplayMessages).toBe(5);

    // 验证主 Agent 消息
    const mainAgentGroups = groups.filter(g => !g.isSubAgent);
    expect(mainAgentGroups.length).toBe(2); // 2 个主 Agent 分组

    // 验证子 Agent 消息
    const subAgentGroups = groups.filter(g => g.isSubAgent);
    expect(subAgentGroups.length).toBe(1); // 1 个子 Agent 分组
  });
});
