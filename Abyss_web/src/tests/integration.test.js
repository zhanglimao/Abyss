/**
 * 集成测试：验证完整的消息渲染流程
 */

import { describe, test, expect } from 'vitest';
import {
  parseMessageStream,
  convertToFrontendMessage,
  pairToolCalls,
  groupBySubAgent,
} from '../utils/messageParser.js';

const PROBLEM_DATA = `----消息说明----
{"subagent": null, "type": "human", "content": "渗透 0.0.0.0:5013", "id": "8453d474-9560-428b-a160-c39b09fe9caa"}
----end----
----消息说明----
{"subagent": null, "type": "ai", "content": "", "id": "lc_run--019cd8f7-ebc8-7190-8ac8-c69a4e93cbee-0", "tool_calls": [{"name": "write_todos", "args": {"todos": [{"content": "调用分析专家", "status": "in_progress"}]}, "id": "call_72bde2487e1d45af94033702", "type": "tool_call"}]}
----end----
----消息说明----
{"subagent": null, "type": "tool", "content": "Updated todo list to [...]", "id": "d603c07f-5a9d-4900-bd6f-f7f1570d45a7", "tool_call_id": "call_72bde2487e1d45af94033702"}
----end----`;

describe('工具调用配对集成测试', () => {
  test('应该正确处理空 content 的 AI 消息和工具配对', () => {
    // 1. 解析消息
    const parsedMessages = parseMessageStream(PROBLEM_DATA);
    expect(parsedMessages.length).toBe(3);

    // 2. 转换为前端消息
    const frontendMessages = parsedMessages
      .map(msg => convertToFrontendMessage(msg, 'test-task'))
      .filter(msg => msg !== null);

    expect(frontendMessages.length).toBe(3);
    
    // 验证 AI 消息
    const aiMsg = frontendMessages[1];
    expect(aiMsg.type).toBe('assistant_message');
    expect(aiMsg.content).toBe(''); // content 为空
    expect(aiMsg.toolCalls).toHaveLength(1);
    expect(aiMsg.toolCalls[0].id).toBe('call_72bde2487e1d45af94033702');

    // 验证工具消息
    const toolMsg = frontendMessages[2];
    expect(toolMsg.type).toBe('tool_result');
    expect(toolMsg.toolCallId).toBe('call_72bde2487e1d45af94033702');

    // 3. 配对工具调用
    const { messages: pairedMessages, pairedToolResultIds, toolCallMap } = pairToolCalls(frontendMessages);

    // 验证配对结果
    expect(pairedToolResultIds.size).toBe(1);
    expect(pairedToolResultIds.has('d603c07f-5a9d-4900-bd6f-f7f1570d45a7')).toBe(true);

    // 验证工具调用状态
    const toolCall = toolCallMap.get('call_72bde2487e1d45af94033702').toolCall;
    expect(toolCall.status).toBe('completed');
    expect(toolCall.result).toBeDefined();
    expect(toolCall.result.id).toBe('d603c07f-5a9d-4900-bd6f-f7f1570d45a7');

    // 4. 分组消息
    const groups = groupBySubAgent(pairedMessages);
    expect(groups.length).toBe(1); // 所有消息都是主 Agent

    // 5. 验证渲染逻辑
    const group = groups[0];
    const displayMessages = group.messages.filter(msg => !pairedToolResultIds.has(msg.id));
    
    // 过滤后应该只剩 2 条消息（用户消息 + AI 消息）
    expect(displayMessages.length).toBe(2);
    expect(displayMessages[0].type).toBe('user_message');
    expect(displayMessages[1].type).toBe('assistant_message');
    
    // AI 消息的 toolCalls 应该包含配对结果
    expect(displayMessages[1].toolCalls[0].status).toBe('completed');
    expect(displayMessages[1].toolCalls[0].result).toBeDefined();
  });

  test('应该正确渲染空 content 的 AI 消息的工具调用', () => {
    const parsedMessages = parseMessageStream(PROBLEM_DATA);
    const frontendMessages = parsedMessages
      .map(msg => convertToFrontendMessage(msg, 'test-task'))
      .filter(msg => msg !== null);

    const { messages: pairedMessages, pairedToolResultIds } = pairToolCalls(frontendMessages);
    const groups = groupBySubAgent(pairedMessages);

    // 模拟 ChatPanel.jsx 的渲染逻辑
    const renderedMessages = [];
    groups.forEach(group => {
      const displayMessages = group.messages.filter(msg => !pairedToolResultIds.has(msg.id));
      renderedMessages.push(...displayMessages);
    });

    // 验证渲染的消息
    expect(renderedMessages.length).toBe(2);
    
    // 第一条是用户消息
    expect(renderedMessages[0].type).toBe('user_message');
    expect(renderedMessages[0].content).toBe('渗透 0.0.0.0:5013');
    
    // 第二条是 AI 消息，content 为空但有 toolCalls
    const aiMsg = renderedMessages[1];
    expect(aiMsg.type).toBe('assistant_message');
    expect(aiMsg.content).toBe('');
    expect(aiMsg.toolCalls).toHaveLength(1);
    expect(aiMsg.toolCalls[0].name).toBe('write_todos');
    expect(aiMsg.toolCalls[0].status).toBe('completed');
    expect(aiMsg.toolCalls[0].result).toBeDefined();
  });

  test('应该正确判断所有工具调用是否完成', () => {
    const parsedMessages = parseMessageStream(PROBLEM_DATA);
    const frontendMessages = parsedMessages
      .map(msg => convertToFrontendMessage(msg, 'test-task'))
      .filter(msg => msg !== null);

    const { messages: pairedMessages } = pairToolCalls(frontendMessages);
    
    // 获取 AI 消息
    const aiMsg = pairedMessages.find(m => m.type === 'assistant_message');
    
    // 验证所有工具调用都已完成
    const allToolsCompleted = aiMsg.toolCalls.every(tc => tc.status === 'completed' && tc.result !== null);
    expect(allToolsCompleted).toBe(true);
  });

  test('应该正确处理多个工具调用的配对', () => {
    const multiToolData = `----消息说明----
{"subagent": null, "type": "ai", "content": "", "id": "msg-1", "tool_calls": [
  {"name": "tool1", "args": {}, "id": "call-1"},
  {"name": "tool2", "args": {}, "id": "call-2"}
]}
----end----
----消息说明----
{"subagent": null, "type": "tool", "content": "result-1", "id": "tool-1", "tool_call_id": "call-1"}
----end----
----消息说明----
{"subagent": null, "type": "tool", "content": "result-2", "id": "tool-2", "tool_call_id": "call-2"}
----end----`;

    const parsedMessages = parseMessageStream(multiToolData);
    const frontendMessages = parsedMessages
      .map(msg => convertToFrontendMessage(msg, 'test-task'))
      .filter(msg => msg !== null);

    const { messages: pairedMessages } = pairToolCalls(frontendMessages);
    
    // 获取 AI 消息
    const aiMsg = pairedMessages.find(m => m.type === 'assistant_message');
    
    // 验证所有工具调用都已完成
    expect(aiMsg).toBeDefined();
    expect(aiMsg.toolCalls).toHaveLength(2);
    expect(aiMsg.toolCalls[0].status).toBe('completed');
    expect(aiMsg.toolCalls[0].result).toBeDefined();
    expect(aiMsg.toolCalls[1].status).toBe('completed');
    expect(aiMsg.toolCalls[1].result).toBeDefined();
    
    // 验证所有工具调用都完成的判断
    const allToolsCompleted = aiMsg.toolCalls.every(tc => tc.status === 'completed' && tc.result !== null);
    expect(allToolsCompleted).toBe(true);
  });

  test('应该正确处理部分工具调用未完成的情况', () => {
    const partialToolData = `----消息说明----
{"subagent": null, "type": "ai", "content": "", "id": "msg-1", "tool_calls": [
  {"name": "tool1", "args": {}, "id": "call-1"},
  {"name": "tool2", "args": {}, "id": "call-2"}
]}
----end----
----消息说明----
{"subagent": null, "type": "tool", "content": "result-1", "id": "tool-1", "tool_call_id": "call-1"}
----end----`;

    const parsedMessages = parseMessageStream(partialToolData);
    const frontendMessages = parsedMessages
      .map(msg => convertToFrontendMessage(msg, 'test-task'))
      .filter(msg => msg !== null);

    const { messages: pairedMessages } = pairToolCalls(frontendMessages);
    
    // 获取 AI 消息
    const aiMsg = pairedMessages.find(m => m.type === 'assistant_message');
    
    // 验证工具调用状态
    expect(aiMsg).toBeDefined();
    expect(aiMsg.toolCalls).toHaveLength(2);
    expect(aiMsg.toolCalls[0].status).toBe('completed'); // call-1 已配对
    expect(aiMsg.toolCalls[0].result).toBeDefined();
    expect(aiMsg.toolCalls[1].status).toBe('pending'); // call-2 未配对
    expect(aiMsg.toolCalls[1].result).toBeNull();
    
    // 验证所有工具调用都完成的判断（应该为 false）
    const allToolsCompleted = aiMsg.toolCalls.every(tc => tc.status === 'completed' && tc.result !== null);
    expect(allToolsCompleted).toBe(false);
  });

  test('应该正确处理 write_todos 工具调用', () => {
    const writeTodosData = `----消息说明----
{"subagent": null, "type": "ai", "content": "创建任务列表", "id": "msg-1", "tool_calls": [
  {"name": "write_todos", "args": {"todos": [
    {"content": "任务 1", "status": "pending"},
    {"content": "任务 2", "status": "in_progress"}
  ]}, "id": "call-todos"}
]}
----end----
----消息说明----
{"subagent": null, "type": "tool", "content": "Updated todo list to [{'content': '任务 1', 'status': 'completed'}, {'content': '任务 2', 'status': 'in_progress'}]", "id": "tool-1", "tool_call_id": "call-todos"}
----end----`;

    const parsedMessages = parseMessageStream(writeTodosData);
    const frontendMessages = parsedMessages
      .map(msg => convertToFrontendMessage(msg, 'test-task'))
      .filter(msg => msg !== null);

    const { messages: pairedMessages } = pairToolCalls(frontendMessages);
    
    // 获取 AI 消息
    const aiMsg = pairedMessages.find(m => m.type === 'assistant_message');
    
    // 验证 write_todos 工具调用
    expect(aiMsg).toBeDefined();
    expect(aiMsg.toolCalls).toHaveLength(1);
    expect(aiMsg.toolCalls[0].name).toBe('write_todos');
    expect(aiMsg.toolCalls[0].status).toBe('completed');
    expect(aiMsg.toolCalls[0].result).toBeDefined();
    
    // 验证任务列表参数
    expect(aiMsg.toolCalls[0].args.todos).toHaveLength(2);
    expect(aiMsg.toolCalls[0].args.todos[0].content).toBe('任务 1');
    expect(aiMsg.toolCalls[0].args.todos[1].status).toBe('in_progress');
    
    // 验证工具结果解析
    const resultContent = aiMsg.toolCalls[0].result.content;
    expect(resultContent).toContain('Updated todo list');
  });
});
