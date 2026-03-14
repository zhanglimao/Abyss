import React, { useEffect, useRef, useState, useCallback } from 'react';
import { MessageSquare, Globe, Globe2, ArrowDown } from 'lucide-react';
import clsx from 'clsx';
import { useChatStore, useTaskStore, useInfoStore } from '../../store/store.js';
import webSocketService from '../../services/websocket.js';
import { parseMessageStream, convertToFrontendMessage, pairToolCalls, groupBySubAgent } from '../../utils/messageParser.js';
import { MessageBubble, SubAgentGroup } from './MessageBubble.jsx';
import ChatInput from './ChatInput.jsx';
import LoadingIndicator from './LoadingIndicator.jsx';
import { MessageType } from './MessageTypes.js';

/**
 * 聊天面板组件 - 支持全局 WebSocket 连接
 * 每条 WebSocket 消息触发 RESTful API 查询关键信息
 */
const ChatPanel = () => {
  const messagesEndRef = useRef(null);
  const messagesContainerRef = useRef(null);
  const globalTaskRef = useRef(null);

  // 滚动状态
  const [isAtBottom, setIsAtBottom] = useState(true);
  const [hasNewMessage, setHasNewMessage] = useState(false);

  // WebSocket 连接状态
  const [wsConnectionStatus, setWsConnectionStatus] = useState('disconnected');

  // 加载状态：'idle' | 'loading' | 'cancelled'
  const [loadingStatus, setLoadingStatus] = useState('idle');

  const { messages, addMessage, addMessages, clearMessages, setTyping, setConnectionStatus, currentTaskId, setCurrentTaskId, taskMessages } =
    useChatStore();
  const { globalTask } = useTaskStore();
  const { refreshAll } = useInfoStore();

  // 更新 ref
  useEffect(() => {
    globalTaskRef.current = globalTask;
    console.log('🔄 [ChatPanel] globalTaskRef 更新:', globalTask?.id);
  }, [globalTask]);

  // 获取当前会话 ID（使用全局任务 ID 或 WebSocket 的 currentTaskId）
  const currentSessionId = globalTask?.id || webSocketService.currentTaskId || currentTaskId;

  // 获取当前会话的消息（使用普通变量，不使用 Hook）
  // 注意：taskMessages 是一个对象，key 是 taskId，value 是消息数组
  const currentTaskMessages = currentSessionId ? (taskMessages[currentSessionId] || []) : [];

  // 调试：监听消息数量变化
  useEffect(() => {
    console.log('📊 [ChatPanel] 当前会话 ID:', currentSessionId);
    console.log('📊 [ChatPanel] 当前消息数量:', currentTaskMessages.length);
    if (currentTaskMessages.length > 0) {
      console.log('   第一条消息:', currentTaskMessages[0]);
    }
  }, [currentSessionId, currentTaskMessages.length]);

  // 使用 ref 存储 currentTaskId 和 store 方法，避免依赖变化
  const currentTaskIdRef = useRef(currentTaskId);
  const addMessageRef = useRef(addMessage);
  const refreshAllRef = useRef(refreshAll);
  
  useEffect(() => {
    currentTaskIdRef.current = currentTaskId;
  }, [currentTaskId]);
  
  useEffect(() => {
    addMessageRef.current = addMessage;
  }, [addMessage]);
  
  useEffect(() => {
    refreshAllRef.current = refreshAll;
  }, [refreshAll]);

  // 防抖刷新关键信息（避免频繁请求）
  const refreshTimerRef = useRef(null);
  const debouncedRefresh = useCallback((taskId) => {
    if (refreshTimerRef.current) {
      clearTimeout(refreshTimerRef.current);
    }
    refreshTimerRef.current = setTimeout(() => {
      console.log('🔄 WebSocket 消息触发关键信息刷新:', taskId);
      refreshAllRef.current(taskId);
    }, 1000); // 1 秒防抖
  }, []); // 空依赖，使用 ref

  // 处理 WebSocket 消息接收（使用 ref 避免依赖变化）
  const handleMessageReceived = useCallback((message) => {
    console.log('📡 [ChatPanel] 收到 WebSocket 消息:', message);
    
    // 过滤心跳消息（ping/pong）
    if (message.type === 'ping' || message.type === 'pong') {
      return;
    }

    // 特殊处理：检查是否是任务完成消息（status: "complate"）
    // 这种消息可能没有 type 字段，需要优先处理
    if (message.status === 'complate') {
      console.log('✅ 任务完成，清除 loading 状态');
      setLoadingStatus('idle');
      return;  // 完成消息不显示在聊天窗口中
    }

    // 过滤未知类型的消息（只处理已知类型）
    const knownTypes = ['human', 'ai', 'tool', 'system'];
    if (!knownTypes.includes(message.type)) {
      console.log('⚠️ 未知消息类型，已忽略:', message.type);
      return;
    }

    // 从消息中提取 task_id（支持 task_id 和 taskId 两种格式）
    const messageTaskId = message.task_id || message.taskId;

    // 始终使用全局任务 ID 作为目标 ID（如果没有全局任务，则使用消息中的 task_id）
    const currentGlobalTask = globalTaskRef.current;
    const targetTaskId = currentGlobalTask?.id || messageTaskId || currentTaskIdRef.current;

    if (!targetTaskId) {
      console.log('⚠️ 消息缺少 task_id，已忽略');
      return;
    }

    console.log('📥 收到消息，任务 ID:', targetTaskId, '类型:', message.type, '消息 task_id:', messageTaskId || '无');

    // 将 WebSocket 原始消息转换为前端消息格式
    // WebSocket 原始格式包含：subagent, type (human/ai/tool), content, id, tool_calls, tool_call_id
    const frontendMessage = convertToFrontendMessage({
      subagent: message.subagent,
      msgType: message.type,
      msg: message,
      taskId: targetTaskId,
    }, targetTaskId);

    if (!frontendMessage) {
      console.log('⚠️ 消息转换失败，已忽略');
      return;
    }

    console.log('✅ 消息转换成功:', frontendMessage);

    // 添加消息到全局任务（使用 ref）
    addMessageRef.current({
      ...frontendMessage,
      task_id: targetTaskId,
      timestamp: frontendMessage.timestamp || new Date().toISOString(),
    }, targetTaskId);

    // 状态流转逻辑：
    // 1. 收到系统停止确认 → 任务已停止，清除 loading
    // 2. 其他情况 → 保持 loading 状态，显示"处理中"
    if (message.type === 'system' && (message.content?.includes('已停止') || message.content?.includes('已取消'))) {
      console.log('✅ 任务已停止，清除 loading 状态');
      setLoadingStatus('idle');
    }

    // 触发关键信息查询（使用防抖）
    debouncedRefresh(targetTaskId);
  }, []); // 空依赖，完全使用 ref

  // 监听全局 WebSocket 连接状态
  useEffect(() => {
    const unsubscribe = webSocketService.onStatusChange((status) => {
      console.log('📡 ChatPanel 收到连接状态变化:', status);
      setWsConnectionStatus(status);
      // 同步到 store
      setConnectionStatus(status === 'connected' ? 'connected' : 'disconnected');
    });

    // 初始化状态
    const initialStatus = webSocketService.getConnectionStatus();
    console.log('📡 ChatPanel 初始化连接状态:', initialStatus);
    setWsConnectionStatus(initialStatus);
    setConnectionStatus(initialStatus === 'connected' ? 'connected' : 'disconnected');

    return unsubscribe;
  }, [setConnectionStatus]);

  // 注册 WebSocket 消息监听器（只注册一次）
  // 注意：handleMessageReceived 使用空依赖，内部通过 ref 访问最新值
  useEffect(() => {
    console.log('📡 [ChatPanel] 注册 WebSocket 消息监听器');
    const unsubscribe = webSocketService.onMessage((message) => {
      console.log('📬 [ChatPanel] 监听器收到消息:', message.type);
      handleMessageReceived(message);
    });

    return () => {
      console.log('📡 [ChatPanel] 注销 WebSocket 消息监听器');
      unsubscribe();
    };
  }, []); // 空依赖，只注册一次

  // 确保 currentSessionId 变化时更新 currentTaskId
  useEffect(() => {
    if (currentSessionId) {
      setCurrentTaskId(currentSessionId);
    }
  }, [currentSessionId, setCurrentTaskId]);

  // 滚动到底部
  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    setHasNewMessage(false);
  };

  // 检查是否在底部
  const checkIsAtBottom = () => {
    const container = messagesContainerRef.current;
    if (!container) return true;

    // 容忍 50px 的误差
    const threshold = 50;
    const scrollTop = container.scrollTop;
    const scrollHeight = container.scrollHeight;
    const clientHeight = container.clientHeight;

    return scrollHeight - scrollTop - clientHeight <= threshold;
  };

  // 处理滚动事件
  const handleScroll = () => {
    const atBottom = checkIsAtBottom();
    setIsAtBottom(atBottom);

    // 如果滚动到底部，清除新消息提示
    if (atBottom) {
      setHasNewMessage(false);
    }
  };

  // 监听消息数量变化
  const prevMessageCountRef = useRef(currentTaskMessages.length);
  useEffect(() => {
    const prevCount = prevMessageCountRef.current;
    const currentCount = currentTaskMessages.length;
    
    if (currentCount > prevCount) {
      // 有新消息
      if (isAtBottom) {
        // 在底部，自动滚动
        scrollToBottom();
      } else {
        // 不在底部，显示新消息提示
        setHasNewMessage(true);
      }
    }
    
    prevMessageCountRef.current = currentCount;
  }, [currentTaskMessages.length, isAtBottom]);

  useEffect(() => {
    scrollToBottom();
  }, []); // 只在初始挂载时滚动

  // 初始化：设置当前任务 ID，使用全局 WebSocket 连接，并自动设置 loading 状态
  useEffect(() => {
    if (globalTask?.id) {
      console.log('📋 任务切换，使用全局 WebSocket 连接');
      console.log('   当前任务 ID:', globalTask.id);

      // 更新当前任务 ID（Store 中已按 task_id 隔离）
      setCurrentTaskId(globalTask.id);

      // 只切换任务 ID，不重新连接 WebSocket
      webSocketService.switchTask(globalTask.id);

      // 进入任务后自动设置 loading 状态（任务执行中）
      setLoadingStatus('loading');
    }

    return () => {
      // 不断开连接，保持全局连接
    };
  }, [globalTask?.id]);

  const handleSendMessage = (content) => {
    // 使用当前会话 ID
    const targetTaskId = currentSessionId || 'global-session';

    console.log('📤 发送消息，任务 ID:', targetTaskId);

    // 设置加载状态
    setLoadingStatus('loading');

    // 通过 WebSocket 发送（后端会返回 human 消息，由 handleMessageReceived 处理）
    webSocketService.sendUserMessage(content, targetTaskId);
  };

  // 处理任务停止
  const handleTaskStop = () => {
    const targetTaskId = currentSessionId || globalTask?.id || 'global-session';

    console.log('⏹️ 停止任务，任务 ID:', targetTaskId);

    // 设置取消状态
    setLoadingStatus('cancelled');

    // 通过 WebSocket 发送任务停止消息
    webSocketService.send({
      type: 'task_stop',
      task_id: targetTaskId,
    });

    // 可选：显示确认提示
    console.log('✅ 已发送任务停止请求');
  };

  // 处理加载提示的取消
  const handleLoadingCancel = () => {
    setLoadingStatus('cancelled');
    handleTaskStop();
  };

  const getMessageTypeLabel = (type) => {
    const labels = {
      [MessageType.USER]: '用户',
      [MessageType.ASSISTANT]: '助手',
      [MessageType.SUBAGENT]: '子代理',
      [MessageType.TOOL_CALL]: '工具调用',
      [MessageType.TOOL_RESULT]: '工具结果',
      [MessageType.SYSTEM]: '系统',
      [MessageType.ERROR]: '错误',
    };
    return labels[type] || '未知';
  };

  /**
   * 渲染消息列表（支持子 Agent 分组和工具调用配对）
   */
  const renderMessages = () => {
    if (currentTaskMessages.length === 0) return null;

    // 1. 配对工具调用和工具结果
    const { messages: pairedMessages, toolCallMap, pairedToolResultIds } = pairToolCalls(currentTaskMessages);

    // 2. 按 subagent 分组消息
    const groups = groupBySubAgent(pairedMessages);

    // 3. 渲染消息（过滤掉已配对的工具结果，避免重复显示）
    return (
      <>
        {groups.map((group, groupIndex) => {
          // 过滤掉已配对的工具结果（它们已显示在 AI 消息的工具调用框中）
          const displayMessages = group.messages.filter(msg => !pairedToolResultIds.has(msg.id));

          // 使用消息组中的 subagentType
          const subagentType = group.subagentType || null;

          // 如果是子 Agent 消息组，使用包裹组件
          if (group.isSubAgent) {
            return (
              <SubAgentGroup
                key={`group-${groupIndex}-${group.subAgentId}`}
                subAgentId={group.subAgentId}
                agentName={group.agentName}
                subagentType={subagentType}
                messages={group.messages}
              >
                {displayMessages.map((message, msgIndex) => (
                  <MessageBubble
                    key={`msg-${groupIndex}-${msgIndex}-${message.id}`}
                    message={message}
                    isGrouped={true}
                  />
                ))}
              </SubAgentGroup>
            );
          } else {
            // 主 Agent 消息，直接渲染
            return (
              <React.Fragment key={`group-${groupIndex}`}>
                {displayMessages.map((message, msgIndex) => (
                  <MessageBubble
                    key={`msg-${groupIndex}-${msgIndex}-${message.id}`}
                    message={message}
                  />
                ))}
              </React.Fragment>
            );
          }
        })}
        <div ref={messagesEndRef} />
      </>
    );
  };

  const isConnected = wsConnectionStatus === 'connected';

  return (
    <div className="flex flex-col h-full bg-light-bg relative">
      {/* 消息列表 */}
      <div
        ref={messagesContainerRef}
        onScroll={handleScroll}
        className="flex-1 overflow-y-auto p-5"
      >
        {currentTaskMessages.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-light-textMuted">
            <div className="w-20 h-20 rounded-2xl bg-gradient-to-br from-primary-100 to-accent-100 flex items-center justify-center mb-4 animate-float">
              <MessageSquare size={40} className="text-primary-400" />
            </div>
            <p className="text-sm font-medium text-light-text">暂无消息</p>
            <p className="text-xs mt-1 text-light-textMuted">开始与 AI 助手对话，执行渗透测试任务</p>
            {!isConnected && (
              <div className="mt-4 text-xs text-amber-600 bg-amber-50 px-4 py-2 rounded-lg flex items-center gap-2">
                <Globe size={14} className="text-amber-500" />
                <span>WebSocket 未连接，请在系统设置中配置并建立连接</span>
              </div>
            )}
            {isConnected && (
              <div className="mt-4 text-xs text-emerald-600 bg-emerald-50 px-4 py-2 rounded-lg flex items-center gap-2">
                <Globe2 size={14} className="text-emerald-500" />
                <span>已连接，可以开始对话</span>
              </div>
            )}
          </div>
        ) : (
          renderMessages()
        )}
      </div>

      {/* 转到最新消息按钮 */}
      {!isAtBottom && (
        <div className="absolute bottom-24 left-1/2 -translate-x-1/2 z-10">
          <button
            onClick={scrollToBottom}
            className={clsx(
              'flex items-center gap-2 px-4 py-2.5 rounded-full shadow-lg border transition-all duration-300',
              hasNewMessage
                ? 'bg-primary-500 text-white border-primary-600 animate-bounce'
                : 'bg-white text-light-text border-light-border hover:bg-primary-50'
            )}
          >
            <ArrowDown size={16} />
            <span className="text-sm font-medium">
              {hasNewMessage ? '新消息' : '转到最新消息'}
            </span>
            {hasNewMessage && (
              <span className="w-2 h-2 bg-red-500 rounded-full animate-ping" />
            )}
          </button>
        </div>
      )}

      {/* 加载提示 */}
      <LoadingIndicator
        status={loadingStatus}
        onCancel={handleLoadingCancel}
      />

      {/* 输入框 */}
      <ChatInput
        onSend={handleSendMessage}
        onTaskStop={handleTaskStop}
        disabled={!isConnected}
        placeholder={isConnected ? '输入消息... (Shift+Enter 换行)' : 'WebSocket 未连接，请在系统设置中配置'}
      />
    </div>
  );
};

export default ChatPanel;
