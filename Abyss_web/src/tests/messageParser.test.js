/**
 * 消息解析器测试
 * 验证 WebSocket 消息解析逻辑是否正确
 */

import { describe, it, expect } from 'vitest';
import { parseMessage, convertToFrontendMessage, pairToolCalls, groupBySubAgent } from '../utils/messageParser.js';
import { getFrontendMessages } from '../utils/mockWebSocketData.js';

describe('MessageParser', () => {
  describe('parseMessage', () => {
    it('应该正确解析人类消息（JSON 格式）', () => {
      const rawMessage = '{"subagent": null, "type": "human", "content": "测试消息", "id": "test-id-123"}';

      const result = parseMessage(rawMessage);

      expect(result).not.toBeNull();
      expect(result.subagent).toBeNull();
      expect(result.msgType).toBe('human');
      expect(result.msg.content).toBe('测试消息');
      expect(result.msg.id).toBe('test-id-123');
    });

    it('应该正确解析 AI 消息（带工具调用，JSON 格式）', () => {
      const rawMessage = '{"subagent": null, "type": "ai", "content": "我来处理", "id": "ai-id-123", "tool_calls": [{"name": "write_todos", "args": {"todos": []}, "id": "call-123", "type": "tool_call"}]}';

      const result = parseMessage(rawMessage);

      expect(result).not.toBeNull();
      expect(result.subagent).toBeNull();
      expect(result.msgType).toBe('ai');
      expect(result.msg.content).toBe('我来处理');
      expect(result.msg.tool_calls).toHaveLength(1);
      expect(result.msg.tool_calls[0].name).toBe('write_todos');
    });

    it('应该正确解析子 Agent 消息（JSON 格式）', () => {
      const rawMessage = '{"subagent": "tools:agent-uuid", "type": "ai", "content": "子 Agent 回复", "id": "sub-id-123"}';

      const result = parseMessage(rawMessage);

      expect(result).not.toBeNull();
      expect(result.subagent).toBe('tools:agent-uuid');
      expect(result.msgType).toBe('ai');
      expect(result.msg.content).toBe('子 Agent 回复');
    });

    it('应该正确解析工具结果消息（JSON 格式）', () => {
      const rawMessage = '{"subagent": null, "type": "tool", "content": "工具执行结果", "id": "tool-result-id", "tool_call_id": "call-123"}';

      const result = parseMessage(rawMessage);

      expect(result).not.toBeNull();
      expect(result.subagent).toBeNull();
      expect(result.msgType).toBe('tool');
      expect(result.msg.content).toBe('工具执行结果');
      expect(result.msg.tool_call_id).toBe('call-123');
    });
  });

  describe('convertToFrontendMessage', () => {
    it('应该将人类消息转换为前端格式', () => {
      const parsed = {
        subagent: null,
        msgType: 'human',
        msg: { content: '用户消息', id: 'msg-1' },
        taskId: 'task1'
      };

      const result = convertToFrontendMessage(parsed, 'task1');

      expect(result).not.toBeNull();
      expect(result.type).toBe('user_message');
      expect(result.content).toBe('用户消息');
      expect(result.isSubAgent).toBe(false);
      expect(result.subAgentId).toBeNull();
    });

    it('应该将 AI 消息转换为前端格式（带工具调用）', () => {
      const parsed = {
        subagent: null,
        msgType: 'ai',
        msg: {
          content: 'AI 回复',
          id: 'msg-2',
          tool_calls: [{ name: 'test_tool', args: {}, id: 'call-1', type: 'tool_call' }]
        },
        taskId: 'task1'
      };

      const result = convertToFrontendMessage(parsed, 'task1');

      expect(result).not.toBeNull();
      expect(result.type).toBe('assistant_message');
      expect(result.content).toBe('AI 回复');
      expect(result.toolCalls).toHaveLength(1);
      expect(result.toolCalls[0].name).toBe('test_tool');
    });

    it('应该将子 Agent 消息转换为前端格式', () => {
      const parsed = {
        subagent: 'tools:agent-uuid',
        msgType: 'ai',
        msg: { content: '子 Agent 回复', id: 'msg-3' },
        taskId: 'task1'
      };

      const result = convertToFrontendMessage(parsed, 'task1');

      expect(result).not.toBeNull();
      expect(result.isSubAgent).toBe(true);
      expect(result.subAgentId).toBe('tools:agent-uuid');
      expect(result.agentName).toContain('tools');
    });

    it('应该将工具结果转换为前端格式', () => {
      const parsed = {
        subagent: null,
        msgType: 'tool',
        msg: { content: '工具结果', id: 'msg-4', tool_call_id: 'call-123' },
        taskId: 'task1'
      };

      const result = convertToFrontendMessage(parsed, 'task1');

      expect(result).not.toBeNull();
      expect(result.type).toBe('tool_result');
      expect(result.content).toBe('工具结果');
      expect(result.toolCallId).toBe('call-123');
    });
  });

  describe('pairToolCalls', () => {
    it('应该正确配对工具调用和工具结果', () => {
      const messages = [
        {
          id: 'msg-1',
          type: 'assistant_message',
          content: '调用工具',
          toolCalls: [
            { id: 'call-1', name: 'test_tool', args: {}, status: 'pending', result: null }
          ]
        },
        {
          id: 'msg-2',
          type: 'tool_result',
          content: '工具结果',
          toolCallId: 'call-1'
        }
      ];

      const { messages: paired, toolCallMap, toolResultMap, pairedToolResultIds } = pairToolCalls(messages);

      // 配对后，所有消息都保留（包括已配对的工具结果）
      expect(paired).toHaveLength(2); // AI 消息 + 工具结果
      expect(toolCallMap.size).toBe(1);
      expect(toolResultMap.size).toBe(1);
      expect(toolCallMap.get('call-1')).toBeDefined();
      expect(toolCallMap.get('call-1').toolCall.status).toBe('completed');
      expect(toolCallMap.get('call-1').toolCall.result).toBeDefined();
      expect(pairedToolResultIds.has('msg-2')).toBe(true); // 工具结果已被标记为已配对
    });
  });

  describe('groupBySubAgent', () => {
    it('应该按 subagent 正确分组消息', () => {
      const messages = [
        { id: 'msg-1', subAgentId: null, isSubAgent: false, agentName: '主 Agent' },
        { id: 'msg-2', subAgentId: 'agent-1', isSubAgent: true, agentName: '子 Agent 1' },
        { id: 'msg-3', subAgentId: 'agent-1', isSubAgent: true, agentName: '子 Agent 1' },
        { id: 'msg-4', subAgentId: null, isSubAgent: false, agentName: '主 Agent' }
      ];

      const groups = groupBySubAgent(messages);

      // groupBySubAgent 会合并连续相同 subAgent 的消息
      // msg-1 (主) -> msg-2,3 (子 agent-1) -> msg-4 (主)
      expect(groups).toHaveLength(3);
      expect(groups[0].subAgentId).toBeNull();
      expect(groups[0].messages).toHaveLength(1);
      expect(groups[1].subAgentId).toBe('agent-1');
      expect(groups[1].messages).toHaveLength(2);
      expect(groups[2].subAgentId).toBeNull();
      expect(groups[2].messages).toHaveLength(1);
    });
  });

  describe('getFrontendMessages', () => {
    it('应该从 mock 数据中获取解析后的消息', async () => {
      const messages = await getFrontendMessages('task1');

      expect(messages).toBeDefined();
      expect(Array.isArray(messages)).toBe(true);
      expect(messages.length).toBeGreaterThan(0);

      // 验证第一条消息是人类消息
      expect(messages[0].type).toBe('user_message');
      expect(messages[0].content).toContain('渗透 0.0.0.0:1234');

      // 验证存在子 Agent 消息
      const subAgentMessages = messages.filter(m => m.isSubAgent);
      expect(subAgentMessages.length).toBeGreaterThan(0);

      // 验证存在工具调用
      const messagesWithTools = messages.filter(m => m.toolCalls && m.toolCalls.length > 0);
      expect(messagesWithTools.length).toBeGreaterThan(0);

      // 验证存在工具结果
      const toolResultMessages = messages.filter(m => m.type === 'tool_result');
      expect(toolResultMessages.length).toBeGreaterThan(0);
    });
  });
});
