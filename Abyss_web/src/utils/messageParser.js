/**
 * WebSocket 消息解析器
 * 解析后端返回的消息格式，转换为前端可用的消息对象
 *
 * 数据格式说明：
 * - "----消息说明----" 与 "----end----" 之间的数据是一个消息
 * - subagent 字段：None 表示主 Agent，否则为子 Agent（需要包裹显示）
 * - content：对话框主要内容，需要 HTML 转义
 * - id: 消息 ID
 * - tool_calls: 工具调用列表（AI 消息）
 * - tool_call_id: 工具结果对应的调用 ID
 */

import { parsePythonDict } from './pythonDictParser.js';

/**
 * 解析单条消息
 * @param {string} rawMessage - 原始消息文本（----消息说明---- 和 ----end---- 之间的内容）
 * @returns {object|null} 解析后的消息对象
 */
export function parseMessage(rawMessage) {
  if (!rawMessage || typeof rawMessage !== 'string') {
    return null;
  }

  // 移除所有换行符和多余空白，将多行 JSON 转换为单行
  const normalizedMessage = rawMessage.trim().replace(/\s+/g, ' ');

  // 尝试查找字典字符串（可能跨越多行）
  // 匹配从 { 开始到最后一个 } 结束的内容
  const match = normalizedMessage.match(/\{.*\}/s);
  if (!match) {
    return null;
  }

  const dictString = match[0];

  // 解析 Python 字典
  const parsedDict = parsePythonDict(dictString);
  if (!parsedDict) {
    return null;
  }

  return {
    subagent: parsedDict.subagent === null ? null : parsedDict.subagent,
    msgType: parsedDict.type || 'unknown',
    msg: parsedDict,
    rawText: rawMessage,
    taskId: parsedDict.task_id,
  };
}

/**
 * 解析完整的 WebSocket 消息流
 * @param {string} rawText - 完整的原始文本（包含多个 ----消息说明---- 块）
 * @returns {array} 解析后的消息数组
 */
export function parseMessageStream(rawText) {
  if (!rawText || typeof rawText !== 'string') {
    return [];
  }

  const messages = [];
  // 使用正则表达式匹配所有消息块
  const messageBlocks = rawText.match(/----消息说明----\s*([\s\S]*?)\s*----end----/g);
  
  if (!messageBlocks) {
    return [];
  }

  for (const block of messageBlocks) {
    // 提取 ----消息说明---- 和 ----end---- 之间的内容
    const content = block.replace(/----消息说明----\s*/, '').replace(/\s*----end----/, '').trim();
    if (content) {
      const parsed = parseMessage(content);
      if (parsed) {
        messages.push(parsed);
      }
    }
  }

  return messages;
}

/**
 * 从消息数组直接转换为前端消息格式（支持数组格式）
 * @param {array} messages - 消息数组（已经是对象格式）
 * @param {string} taskId - 任务 ID
 * @returns {array} 前端消息数组
 */
export function convertMessagesToFrontend(messages, taskId) {
  if (!Array.isArray(messages)) {
    return [];
  }

  return messages
    .map(msg => convertToFrontendMessage({
      subagent: msg.subagent,
      msgType: msg.type,
      msg: msg,
      taskId
    }, taskId))
    .filter(msg => msg !== null);
}

/**
 * 将解析后的消息转换为前端消息格式
 * @param {object} parsedMessage - parseMessage 返回的对象
 * @param {string} taskId - 任务 ID
 * @returns {object} 前端消息对象
 */
export function convertToFrontendMessage(parsedMessage, taskId) {
  if (!parsedMessage || !parsedMessage.msg) {
    return null;
  }

  const { subagent, msgType, msg, taskId: msgTaskId } = parsedMessage;

  // 新格式：msg 本身就是消息对象，直接从中提取字段
  const content = msg?.content || '';
  const msgId = msg?.id || `msg-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  const toolCallId = msg?.tool_call_id;
  const toolCalls = msg?.tool_calls || [];

  // subagent 为 null 表示主 Agent，否则为子 Agent
  const isSubAgent = !!subagent;

  // 从 subagent 中提取 agent 名称（格式：tools:uuid 或 其他：uuid）
  let agentName = '主 Agent';
  if (isSubAgent) {
    const parts = subagent.split(':');
    if (parts.length > 1) {
      agentName = `${parts[0]} ${parts[1]?.substring(0, 8)}...`;
    } else {
      agentName = `子 Agent ${subagent.substring(0, 12)}...`;
    }
  }

  // 从工具调用参数中提取 subagent_type（仅当 msgType 为 ai 且有 tool_calls 时）
  let subagentType = null;
  if (msgType === 'ai' && toolCalls && toolCalls.length > 0) {
    // 查找第一个包含 subagent_type 参数的工具调用
    const toolCallWithSubagentType = toolCalls.find(tc => tc.args?.subagent_type);
    if (toolCallWithSubagentType) {
      subagentType = toolCallWithSubagentType.args.subagent_type;
    }
  }

  const frontendMsg = {
    id: msgId,
    task_id: msgTaskId || taskId,
    timestamp: new Date().toISOString(),
    isSubAgent,
    subAgentId: subagent,
    agentName,
    subagentType, // 子 Agent 类型（从工具调用参数中提取）
    type: msgType, // 保留原始类型用于调试
  };

  // 根据消息类型转换
  // msgType: 'human' | 'ai' | 'tool'
  if (msgType === 'human') {
    // 用户消息
    frontendMsg.type = 'user_message';
    frontendMsg.content = content;
  } else if (msgType === 'ai') {
    // AI 消息（可能包含工具调用）
    frontendMsg.type = 'assistant_message';
    frontendMsg.content = content;

    // 如果有工具调用，存储工具调用信息
    if (toolCalls && toolCalls.length > 0) {
      frontendMsg.toolCalls = toolCalls.map(tc => ({
        name: tc.name,
        args: tc.args,
        id: tc.id,
        type: tc.type,
        status: 'pending',
        result: null,
      }));
    } else {
      // 空 tool_calls 也要设置为空数组
      frontendMsg.toolCalls = [];
    }
  } else if (msgType === 'tool') {
    // 工具返回结果
    frontendMsg.type = 'tool_result';
    frontendMsg.content = content;
    frontendMsg.toolCallId = toolCallId;
  }

  return frontendMsg;
}

/**
 * HTML 转义工具函数
 * 将特殊字符转换为 HTML 实体，防止 XSS 攻击
 * @param {string} text - 需要转义的文本
 * @returns {string} 转义后的文本
 */
export function escapeHtml(text) {
  if (!text) return '';

  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

/**
 * 从消息内容中提取并高亮 FLAG
 * @param {string} content - 消息内容
 * @returns {string} HTML 格式的内容（FLAG 被高亮）
 */
export function highlightFlag(content) {
  if (!content) return '';

  const escaped = escapeHtml(content);
  // 匹配 FLAG 格式：CTF{{...}}, FLAG{{...}}, ctfhub{{...}}
  const flagPattern = /(CTF\{\{[^}]+\}\}|FLAG\{\{[^}]+\}\}|ctfhub\{\{[^}]+\}\})/gi;
  return escaped.replace(flagPattern, '<span class="flag-highlight">$1</span>');
}

/**
 * 配对工具调用和工具结果
 * 通过 tool_call_id 匹配工具调用和工具返回结果
 *
 * 数据流程：
 * 1. AI 消息包含 tool_calls 数组，每个工具调用有唯一的 id
 * 2. tool 类型消息包含 tool_call_id，用于关联对应的工具调用
 * 3. 配对后，工具结果显示在 AI 消息的工具调用框中
 *
 * 配对逻辑：
 * - 工具调用和工具结果的配对仅基于 tool_call_id，不考虑 subagent
 * - subagent 只影响消息的分组显示，不影响工具配对逻辑
 * - 即使 tool 消息的 subagent 与 AI 消息不同，只要 tool_call_id 匹配就配对
 * - **所有消息（包括已配对的工具结果）都会保留在返回的消息数组中**
 *
 * @param {array} messages - 消息数组
 * @returns {object} 包含配对后消息数组和工具调用状态的对象
 */
export function pairToolCalls(messages) {
  const toolCallMap = new Map(); // 存储工具调用：id -> { toolCall, message }
  const toolResultMap = new Map(); // 存储工具结果：tool_call_id -> toolResult
  const result = [];
  const pairedToolResultIds = new Set(); // 记录已配对的工具结果 ID

  // 第一遍：收集所有工具调用（包括 AI 消息中的 tool_calls）
  for (const msg of messages) {
    if (msg.toolCalls && msg.toolCalls.length > 0) {
      for (const tc of msg.toolCalls) {
        tc.status = 'pending';
        tc.result = null;
        // 存储工具调用及其所属消息的引用
        toolCallMap.set(tc.id, { toolCall: tc, message: msg });
      }
      result.push(msg);
    } else if (msg.type === 'tool_result' || msg.type === 'tool') {
      // 所有工具结果都暂存到 toolResultMap，等待配对
      if (msg.toolCallId) {
        toolResultMap.set(msg.toolCallId, msg);
      }
      // 所有工具结果先添加到 result 数组
      result.push(msg);
    } else {
      result.push(msg);
    }
  }

  // 第二遍：配对工具结果到工具调用
  // 遍历所有工具结果，查找匹配的工具调用
  for (const [toolCallId, toolResult] of toolResultMap.entries()) {
    const toolCallEntry = toolCallMap.get(toolCallId);
    if (toolCallEntry) {
      const { toolCall, message: aiMessage } = toolCallEntry;
      // 配对成功
      toolCall.status = 'completed';
      toolCall.result = toolResult;
      // 存储工具调用和 AI 消息的引用，以便 groupBySubAgent 使用
      toolResult.pairedToolCall = {
        toolCall,
        message: aiMessage,
      };
      pairedToolResultIds.add(toolResult.id); // 标记为已配对
    } else {
      // 未找到匹配的工具调用，单独显示
      console.warn(`⚠️ 未找到匹配的工具调用：${toolCallId.substring(0, 12)}...`);
    }
  }

  return {
    messages: result,
    toolCallMap,
    toolResultMap,
    pairedToolResultIds,
  };
}

/**
 * 按 subagent 分组消息
 * 将同一 subagent 的消息组织在一起，便于 UI 渲染
 *
 * 分组逻辑：
 * - subagent 为 null 的消息属于主 Agent
 * - subagent 不为 null 的消息属于对应的子 Agent
 * - 同一个 subagent 的连续消息会被分组在一起
 * - 工具结果消息（type='tool'）的分组应该跟随其配对的 AI 消息的 subagent
 * - subagent_type 从主 Agent 调用工具时的参数中提取，传递给子 Agent 消息组
 *
 * @param {array} messages - 消息数组
 * @returns {array} 分组后的消息数组
 */
export function groupBySubAgent(messages) {
  const groups = [];
  let currentGroup = null;

  // 首先，收集所有主 Agent 消息中的 subagent_type 映射
  // key: subagent ID, value: subagent_type
  const subagentTypeMap = new Map();
  for (const msg of messages) {
    // 主 Agent 的 AI 消息（isSubAgent 为 false），从 toolCalls 的 args 中提取 subagent_type 和 subagent
    if (!msg.isSubAgent && msg.type === 'assistant_message' && msg.toolCalls && msg.toolCalls.length > 0) {
      for (const tc of msg.toolCalls) {
        // 直接从 toolCall 的 args 中提取 subagent_type 和 subagent
        if (tc.args?.subagent_type && tc.args?.subagent) {
          const subagentId = tc.args.subagent;
          const subagentType = tc.args.subagent_type;
          console.log('🔑 建立 subagent 映射:', subagentId, '→', subagentType);
          subagentTypeMap.set(subagentId, subagentType);
        }
      }
    }
  }

  for (const msg of messages) {
    // 确定消息的 subagent ID
    // 对于工具结果消息，如果它已配对到某个 AI 消息，使用该 AI 消息的 subagent
    let msgSubAgentId = msg.subAgentId;
    let msgIsSubAgent = msg.isSubAgent;
    let msgAgentName = msg.agentName;
    let msgSubagentType = null; // 不直接使用 msg.subagentType，而是从映射表中获取

    // 如果工具结果已配对，使用配对的 AI 消息的 subagent 信息
    if ((msg.type === 'tool_result' || msg.type === 'tool') && msg.pairedToolCall) {
      const pairedAiMsg = msg.pairedToolCall.message;
      if (pairedAiMsg) {
        msgSubAgentId = pairedAiMsg.subAgentId;
        msgIsSubAgent = pairedAiMsg.isSubAgent;
        msgAgentName = pairedAiMsg.agentName;
        // 从映射表中获取 subagent_type
        if (pairedAiMsg.subAgentId && subagentTypeMap.has(pairedAiMsg.subAgentId)) {
          msgSubagentType = subagentTypeMap.get(pairedAiMsg.subAgentId);
        }
      }
    }

    // 如果是子 Agent 消息，从映射表中获取 subagent_type
    if (msg.isSubAgent && msgSubAgentId && subagentTypeMap.has(msgSubAgentId)) {
      msgSubagentType = subagentTypeMap.get(msgSubAgentId);
      console.log('📋 子 Agent 消息获取 subagentType:', msgSubAgentId, '→', msgSubagentType);
    }

    // 如果消息的 subagent 与当前组相同，加入当前组
    if (currentGroup && currentGroup.subAgentId === msgSubAgentId) {
      currentGroup.messages.push(msg);
      // 更新组的 subagent_type
      if (msgSubagentType && !currentGroup.subagentType) {
        currentGroup.subagentType = msgSubagentType;
      }
    } else {
      // 否则创建新组
      currentGroup = {
        subAgentId: msgSubAgentId,
        isSubAgent: msgIsSubAgent,
        agentName: msgAgentName,
        subagentType: msgSubagentType,
        messages: [msg],
      };
      groups.push(currentGroup);
    }
  }

  return groups;
}

/**
 * 获取工具调用的显示状态
 * @param {string} toolCallId - 工具调用 ID
 * @param {Map} toolCallMap - 工具调用映射表
 * @returns {object} 工具调用状态
 */
export function getToolCallStatus(toolCallId, toolCallMap) {
  const toolCall = toolCallMap.get(toolCallId);
  if (!toolCall) {
    return { status: 'unknown', result: null };
  }
  return {
    status: toolCall.status,
    result: toolCall.result,
    name: toolCall.name,
    args: toolCall.args,
  };
}
