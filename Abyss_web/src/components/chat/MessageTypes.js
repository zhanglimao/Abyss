/**
 * 消息类型定义
 */
export const MessageType = {
  USER: 'user_message',         // 用户消息
  ASSISTANT: 'assistant_message', // AI 助手回复
  SYSTEM: 'system_message',      // 系统消息
  SUBAGENT: 'subagent_message',  // 子代理消息
  TOOL_CALL: 'tool_call',        // 工具调用
  TOOL_RESULT: 'tool_result',    // 工具执行结果
  ERROR: 'error',                // 错误消息
};

/**
 * 消息状态
 */
export const MessageStatus = {
  PENDING: 'pending',
  SENDING: 'sending',
  SENT: 'sent',
  FAILED: 'failed',
};
