/**
 * WebSocket 消息处理综合测试
 * 测试 WebSocket 消息的接收、解析、配对和显示
 */

import { describe, test, expect } from 'vitest';
import {
  parseMessageStream,
  convertToFrontendMessage,
  pairToolCalls,
  groupBySubAgent,
} from '../utils/messageParser.js';

describe('WebSocket 消息处理综合测试', () => {
  // 完整的渗透测试对话数据
  const COMPLETE_CONVERSATION = `----消息说明----
{"subagent": null, "type": "human", "content": "渗透 0.0.0.0:5013", "id": "msg-human-001"}
----end----
----消息说明----
{"subagent": null, "type": "ai", "content": "我将开始渗透测试", "id": "msg-ai-001", "tool_calls": [{"name": "write_todos", "args": {"todos": [{"content": "信息收集", "status": "in_progress"}, {"content": "漏洞扫描", "status": "pending"}]}, "id": "call-001"}]}
----end----
----消息说明----
{"subagent": null, "type": "tool", "content": "Updated todo list to [{'content': '信息收集', 'status': 'in_progress'}, {'content': '漏洞扫描', 'status': 'pending'}]", "id": "msg-tool-001", "tool_call_id": "call-001"}
----end----
----消息说明----
{"subagent": "tools:agent-001", "type": "ai", "content": "# 渗透测试报告\\n\\n## 目标分析", "id": "msg-ai-002", "tool_calls": [{"name": "write_file", "args": {"file_path": "/report.md", "content": "# Report"}, "id": "call-002"}]}
----end----
----消息说明----
{"subagent": "tools:agent-001", "type": "tool", "content": "Updated file /report.md", "id": "msg-tool-002", "tool_call_id": "call-002"}
----end----
----消息说明----
{"subagent": null, "type": "ai", "content": "渗透测试完成", "id": "msg-ai-003", "tool_calls": []}
----end----`;

  test('应该正确解析完整的对话消息流', () => {
    const parsedMessages = parseMessageStream(COMPLETE_CONVERSATION);
    
    expect(parsedMessages.length).toBe(6);
    
    // 验证消息类型
    expect(parsedMessages[0].msgType).toBe('human');
    expect(parsedMessages[1].msgType).toBe('ai');
    expect(parsedMessages[2].msgType).toBe('tool');
    expect(parsedMessages[3].msgType).toBe('ai');
    expect(parsedMessages[4].msgType).toBe('tool');
    expect(parsedMessages[5].msgType).toBe('ai');
  });

  test('应该正确转换所有消息为前端格式', () => {
    const parsedMessages = parseMessageStream(COMPLETE_CONVERSATION);
    const frontendMessages = parsedMessages
      .map(msg => convertToFrontendMessage(msg, 'test-task'))
      .filter(msg => msg !== null);

    expect(frontendMessages.length).toBe(6);

    // 验证用户消息
    const userMsg = frontendMessages[0];
    expect(userMsg.type).toBe('user_message');
    expect(userMsg.content).toBe('渗透 0.0.0.0:5013');
    expect(userMsg.isSubAgent).toBe(false);

    // 验证 AI 消息（有工具调用）
    const aiMsg1 = frontendMessages[1];
    expect(aiMsg1.type).toBe('assistant_message');
    expect(aiMsg1.toolCalls).toHaveLength(1);
    expect(aiMsg1.toolCalls[0].name).toBe('write_todos');
    expect(aiMsg1.toolCalls[0].id).toBe('call-001');

    // 验证工具结果
    const toolMsg1 = frontendMessages[2];
    expect(toolMsg1.type).toBe('tool_result');
    expect(toolMsg1.toolCallId).toBe('call-001');

    // 验证子 Agent 消息
    const subAgentMsg = frontendMessages[3];
    expect(subAgentMsg.type).toBe('assistant_message');
    expect(subAgentMsg.isSubAgent).toBe(true);
    expect(subAgentMsg.subAgentId).toBe('tools:agent-001');
  });

  test('应该正确配对所有工具调用和工具结果', () => {
    const parsedMessages = parseMessageStream(COMPLETE_CONVERSATION);
    const frontendMessages = parsedMessages
      .map(msg => convertToFrontendMessage(msg, 'test-task'))
      .filter(msg => msg !== null);

    const { messages: pairedMessages, pairedToolResultIds, toolCallMap } = pairToolCalls(frontendMessages);

    // 验证配对数量
    expect(pairedToolResultIds.size).toBe(2); // 2 个工具结果已配对
    
    // 验证工具调用状态
    expect(toolCallMap.get('call-001').toolCall.status).toBe('completed');
    expect(toolCallMap.get('call-001').toolCall.result).toBeDefined();
    expect(toolCallMap.get('call-002').toolCall.status).toBe('completed');
    expect(toolCallMap.get('call-002').toolCall.result).toBeDefined();
  });

  test('应该正确按 subagent 分组消息', () => {
    const parsedMessages = parseMessageStream(COMPLETE_CONVERSATION);
    const frontendMessages = parsedMessages
      .map(msg => convertToFrontendMessage(msg, 'test-task'))
      .filter(msg => msg !== null);

    const { messages: pairedMessages } = pairToolCalls(frontendMessages);
    const groups = groupBySubAgent(pairedMessages);

    // 验证分组数量（主 Agent -> 主 Agent -> 子 Agent -> 主 Agent）
    expect(groups.length).toBeGreaterThanOrEqual(2);
    
    // 验证第一个分组（主 Agent - human）
    expect(groups[0].isSubAgent).toBe(false);
    
    // 验证存在子 Agent 分组
    const subAgentGroup = groups.find(g => g.isSubAgent);
    expect(subAgentGroup).toBeDefined();
    expect(subAgentGroup.subAgentId).toBe('tools:agent-001');
  });

  test('应该正确处理 write_todos 工具调用', () => {
    const parsedMessages = parseMessageStream(COMPLETE_CONVERSATION);
    const frontendMessages = parsedMessages
      .map(msg => convertToFrontendMessage(msg, 'test-task'))
      .filter(msg => msg !== null);

    const { messages: pairedMessages } = pairToolCalls(frontendMessages);
    
    // 找到 write_todos 的 AI 消息
    const writeTodosMsg = pairedMessages.find(m => 
      m.toolCalls && m.toolCalls.some(tc => tc.name === 'write_todos')
    );
    
    expect(writeTodosMsg).toBeDefined();
    expect(writeTodosMsg.toolCalls[0].name).toBe('write_todos');
    expect(writeTodosMsg.toolCalls[0].args.todos).toHaveLength(2);
    expect(writeTodosMsg.toolCalls[0].status).toBe('completed');
  });

  test('应该正确处理空 tool_calls 的 AI 消息', () => {
    const parsedMessages = parseMessageStream(COMPLETE_CONVERSATION);
    const frontendMessages = parsedMessages
      .map(msg => convertToFrontendMessage(msg, 'test-task'))
      .filter(msg => msg !== null);

    // 找到最后一条 AI 消息（tool_calls 为空）
    const lastAiMsg = frontendMessages[frontendMessages.length - 1];
    
    expect(lastAiMsg.type).toBe('assistant_message');
    expect(lastAiMsg.content).toBe('渗透测试完成');
    expect(lastAiMsg.toolCalls).toEqual([]);
  });

  test('应该正确过滤已配对的工具结果', () => {
    const parsedMessages = parseMessageStream(COMPLETE_CONVERSATION);
    const frontendMessages = parsedMessages
      .map(msg => convertToFrontendMessage(msg, 'test-task'))
      .filter(msg => msg !== null);

    const { messages: pairedMessages, pairedToolResultIds } = pairToolCalls(frontendMessages);
    const groups = groupBySubAgent(pairedMessages);

    // 计算显示的消息数量（过滤已配对的工具结果）
    let displayCount = 0;
    groups.forEach(group => {
      const displayMessages = group.messages.filter(msg => !pairedToolResultIds.has(msg.id));
      displayCount += displayMessages.length;
    });

    // 6 条消息 - 2 条已配对的工具结果 = 4 条显示消息
    expect(displayCount).toBe(4);
  });

  test('应该正确处理消息中的 task_id', () => {
    const parsedMessages = parseMessageStream(COMPLETE_CONVERSATION);
    const frontendMessages = parsedMessages
      .map(msg => convertToFrontendMessage(msg, 'test-task'))
      .filter(msg => msg !== null);

    // 验证所有消息都有 task_id
    frontendMessages.forEach(msg => {
      expect(msg.task_id).toBeDefined();
      expect(msg.task_id).toBe('test-task');
    });
  });

  test('应该正确处理消息 ID 生成', () => {
    const invalidMessage = `----消息说明----
{"subagent": null, "type": "ai", "content": "测试消息"}
----end----`;

    const parsedMessages = parseMessageStream(invalidMessage);
    const frontendMessages = parsedMessages
      .map(msg => convertToFrontendMessage(msg, 'test-task'))
      .filter(msg => msg !== null);

    expect(frontendMessages.length).toBe(1);
    expect(frontendMessages[0].id).toBeDefined();
    expect(frontendMessages[0].id).toMatch(/^msg-\d{13}-[a-z0-9]{9}$/);
  });
});
