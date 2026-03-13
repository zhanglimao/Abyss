import React, { useState } from 'react';
import { ChevronDown, ChevronRight, Terminal, Bot, User, AlertCircle, CheckCircle, Clock, Wrench, Box, Minimize2, Maximize2, ListTodo, Circle, CircleDot, CheckCircle2 } from 'lucide-react';
import clsx from 'clsx';
import { MessageType } from './MessageTypes.js';
import { format } from 'date-fns';
import { escapeHtml, highlightFlag } from '../../utils/messageParser.js';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

/**
 * 可折叠的内容组件（支持 Markdown）
 */
const ContentWithCollapse = ({ content, isExpanded, onToggle, isUserMessage = false }) => {
  if (!content) return null;

  const isLong = content.length > 500 || content.split('\n').length > 20;

  const displayContent = isLong && !isExpanded
    ? content.split('\n').slice(0, 20).join('\n') + '\n...(内容过长，点击展开)'
    : content;

  // Markdown 渲染组件
  const MarkdownContent = () => (
    <div className="markdown-content prose prose-sm max-w-none">
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        components={{
          // 自定义代码块渲染
          code({ node, inline, className, children, ...props }) {
            return inline ? (
              <code className="bg-gray-100 rounded px-1 py-0.5 text-sm" {...props}>
                {children}
              </code>
            ) : (
              <pre className="bg-gray-50 rounded-lg p-3 overflow-x-auto">
                <code className="text-sm" {...props}>{children}</code>
              </pre>
            );
          },
          // 自定义表格渲染
          table({ children }) {
            return (
              <div className="overflow-x-auto my-3">
                <table className="min-w-full border-collapse border border-gray-300 text-sm">
                  {children}
                </table>
              </div>
            );
          },
          th({ children }) {
            return (
              <th className="border border-gray-300 bg-gray-50 px-3 py-2 text-left font-semibold">
                {children}
              </th>
            );
          },
          td({ children }) {
            return (
              <td className="border border-gray-300 px-3 py-2">
                {children}
              </td>
            );
          },
          // 链接渲染
          a({ href, children }) {
            return (
              <a href={href} className="text-primary-600 hover:underline" target="_blank" rel="noopener noreferrer">
                {children}
              </a>
            );
          },
          // 列表渲染
          ul({ children }) {
            return <ul className="list-disc list-inside my-2 space-y-1">{children}</ul>;
          },
          ol({ children }) {
            return <ol className="list-decimal list-inside my-2 space-y-1">{children}</ol>;
          },
          // 引用渲染
          blockquote({ children }) {
            return (
              <blockquote className="border-l-4 border-primary-300 pl-4 my-2 italic text-gray-600">
                {children}
              </blockquote>
            );
          },
          // 标题渲染
          h1({ children }) {
            return <h1 className="text-xl font-bold my-3 text-gray-800">{children}</h1>;
          },
          h2({ children }) {
            return <h2 className="text-lg font-semibold my-2 text-gray-800">{children}</h2>;
          },
          h3({ children }) {
            return <h3 className="text-base font-semibold my-2 text-gray-800">{children}</h3>;
          },
        }}
      >
        {displayContent}
      </ReactMarkdown>
    </div>
  );

  return (
    <div className="relative">
      <div
        className={clsx(
          'text-sm leading-relaxed',
          !isLong || isExpanded ? '' : 'max-h-80 overflow-hidden'
        )}
      >
        {isUserMessage ? (
          // 用户消息：简单文本显示
          <div className="whitespace-pre-wrap">{escapeHtml(displayContent)}</div>
        ) : (
          // AI 消息：Markdown 渲染
          <MarkdownContent />
        )}
      </div>
      {isLong && (
        <button
          onClick={onToggle}
          className="mt-2 flex items-center gap-1 text-xs text-primary-600 hover:text-primary-700 bg-primary-50 hover:bg-primary-100 px-3 py-1.5 rounded-lg transition-colors"
        >
          {isExpanded ? (
            <>
              <Minimize2 size={12} />
              <span>收起</span>
            </>
          ) : (
            <>
              <Maximize2 size={12} />
              <span>展开更多内容</span>
            </>
          )}
        </button>
      )}
    </div>
  );
};

/**
 * 任务列表展示组件（用于 write_todos 工具）
 * 解析工具返回的任务列表并以美观的方式展示
 */
const TaskListDisplay = ({ toolCall, toolResult }) => {
  // 从工具调用参数中获取任务列表
  const todos = toolCall?.args?.todos || [];
  
  // 从工具结果中解析更新后的任务状态
  const getUpdatedTodos = () => {
    if (!toolResult?.content) return todos;
    
    // 尝试从工具结果中解析更新后的任务列表
    // 格式：Updated todo list to [{...}, {...}]
    const match = toolResult.content.match(/Updated todo list to (\[.*\])/s);
    if (match) {
      try {
        // 尝试解析 Python 格式的列表
        const updatedTodos = JSON.parse(match[1].replace(/'/g, '"'));
        return updatedTodos;
      } catch (e) {
        return todos;
      }
    }
    return todos;
  };
  
  const updatedTodos = getUpdatedTodos();
  
  // 获取任务状态图标和样式
  const getStatusIcon = (status) => {
    switch (status) {
      case 'completed':
        return <CheckCircle2 size={16} className="text-emerald-500" />;
      case 'in_progress':
        return <CircleDot size={16} className="text-blue-500" />;
      case 'pending':
      default:
        return <Circle size={16} className="text-gray-400" />;
    }
  };
  
  const getStatusStyle = (status) => {
    switch (status) {
      case 'completed':
        return 'bg-emerald-50 text-emerald-700 border-emerald-200';
      case 'in_progress':
        return 'bg-blue-50 text-blue-700 border-blue-200';
      case 'pending':
      default:
        return 'bg-gray-50 text-gray-600 border-gray-200';
    }
  };
  
  const getStatusLabel = (status) => {
    switch (status) {
      case 'completed':
        return '已完成';
      case 'in_progress':
        return '进行中';
      case 'pending':
      default:
        return '等待中';
    }
  };
  
  return (
    <div className="space-y-2">
      {/* 任务列表头 */}
      <div className="flex items-center gap-2 px-3 py-2 bg-gradient-to-r from-blue-50 to-blue-100/50 rounded-lg border border-blue-200">
        <ListTodo size={16} className="text-blue-600" />
        <span className="font-semibold text-blue-700 text-sm">任务计划列表</span>
        <span className="text-xs text-blue-600 bg-blue-100 px-2 py-0.5 rounded-full ml-auto">
          {updatedTodos.length} 个任务
        </span>
      </div>
      
      {/* 任务列表 */}
      <div className="space-y-1.5">
        {updatedTodos.map((todo, index) => (
          <div
            key={index}
            className={clsx(
              'flex items-start gap-2 p-2.5 rounded-lg border transition-colors',
              getStatusStyle(todo.status)
            )}
          >
            {/* 状态图标 */}
            <div className="mt-0.5 flex-shrink-0">
              {getStatusIcon(todo.status)}
            </div>
            
            {/* 任务内容 */}
            <div className="flex-1 min-w-0">
              <div className={clsx(
                'text-sm',
                todo.status === 'completed' ? 'line-through text-gray-500' : 'text-gray-700'
              )}>
                {todo.content}
              </div>
            </div>
            
            {/* 状态标签 */}
            <div className="flex-shrink-0">
              <span className="text-xs px-2 py-1 rounded-md font-medium border">
                {getStatusLabel(todo.status)}
              </span>
            </div>
          </div>
        ))}
      </div>
      
      {/* 任务统计 */}
      <div className="flex items-center gap-4 pt-2 border-t border-gray-200">
        <div className="flex items-center gap-1.5 text-xs">
          <CheckCircle2 size={12} className="text-emerald-500" />
          <span className="text-gray-600">已完成：{updatedTodos.filter(t => t.status === 'completed').length}</span>
        </div>
        <div className="flex items-center gap-1.5 text-xs">
          <CircleDot size={12} className="text-blue-500" />
          <span className="text-gray-600">进行中：{updatedTodos.filter(t => t.status === 'in_progress').length}</span>
        </div>
        <div className="flex items-center gap-1.5 text-xs">
          <Circle size={12} className="text-gray-400" />
          <span className="text-gray-600">等待中：{updatedTodos.filter(t => t.status === 'pending').length}</span>
        </div>
      </div>
    </div>
  );
};

/**
 * 工具调用配对显示组件
 * 展示工具调用信息和对应的返回结果（在同一个框中）
 */
const ToolCallPair = ({ toolCall, toolResult }) => {
  const [expanded, setExpanded] = useState(false);

  // 渲染工具名称（格式化显示）
  const renderToolName = (name) => {
    // 将 snake_case 转换为可读格式
    return name
      .split('_')
      .map(word => word.charAt(0).toUpperCase() + word.slice(1))
      .join(' ');
  };

  // 渲染参数可视化
  const renderArgs = (args) => {
    if (!args || Object.keys(args).length === 0) {
      return <div className="text-xs text-gray-400 italic">无参数</div>;
    }

    return (
      <div className="space-y-2">
        {Object.entries(args).map(([key, value]) => (
          <div key={key} className="text-xs">
            <span className="font-medium text-emerald-700">{key}:</span>
            {typeof value === 'object' ? (
              <pre className="mt-1 ml-2 text-xs text-gray-600 whitespace-pre-wrap break-all bg-gray-50 rounded p-2">
                {JSON.stringify(value, null, 2)}
              </pre>
            ) : (
              <span className="ml-2 text-gray-600">{String(value)}</span>
            )}
          </div>
        ))}
      </div>
    );
  };

  // 特殊处理 write_todos 工具调用
  if (toolCall.name === 'write_todos') {
    return (
      <div className="my-2 border border-blue-200 rounded-xl overflow-hidden shadow-sm">
        {/* 工具调用头部 */}
        <div className="bg-gradient-to-r from-blue-50 to-blue-100/50 px-4 py-3 border-b border-blue-100">
          <div className="flex items-center gap-2 flex-wrap">
            <ListTodo size={16} className="text-blue-600" />
            <span className="font-semibold text-blue-700 text-sm">
              {renderToolName(toolCall.name)}
            </span>
            <span className="text-xs text-blue-600 bg-blue-100 px-2 py-0.5 rounded font-mono">
              ID: {toolCall.id?.substring(0, 8)}...
            </span>
            {toolResult ? (
              <span className="text-xs text-blue-600 flex items-center gap-1 bg-blue-50 px-2 py-0.5 rounded">
                <CheckCircle size={12} /> 已更新
              </span>
            ) : (
              <span className="text-xs text-amber-600 animate-pulse flex items-center gap-1 bg-amber-50 px-2 py-0.5 rounded">
                <Clock size={12} /> 更新中...
              </span>
            )}
          </div>
        </div>

        {/* 任务列表展示 */}
        <div className="bg-white p-4">
          <TaskListDisplay toolCall={toolCall} toolResult={toolResult} />
        </div>
      </div>
    );
  }

  // 特殊处理 task 工具调用（需要显示 subagent_type）
  if (toolCall.name === 'task') {
    const subagentType = toolCall.args?.subagent_type;
    return (
      <div className="my-2 border border-emerald-200 rounded-xl overflow-hidden shadow-sm">
        {/* 工具调用头部 */}
        <div className="bg-gradient-to-r from-emerald-50 to-emerald-100/50 px-4 py-3 border-b border-emerald-100">
          <div className="flex items-center gap-2 flex-wrap">
            <Wrench size={16} className="text-emerald-600" />
            <span className="font-semibold text-emerald-700 text-sm">
              {renderToolName(toolCall.name)}
            </span>
            <span className="text-xs text-emerald-600 bg-emerald-100 px-2 py-0.5 rounded font-mono">
              ID: {toolCall.id?.substring(0, 8)}...
            </span>
            {toolResult ? (
              <span className="text-xs text-emerald-600 flex items-center gap-1 bg-emerald-50 px-2 py-0.5 rounded">
                <CheckCircle size={12} /> 已完成
              </span>
            ) : (
              <span className="text-xs text-amber-600 animate-pulse flex items-center gap-1 bg-amber-50 px-2 py-0.5 rounded">
                <Clock size={12} /> 执行中...
              </span>
            )}
            {/* 显示 Sub Agent Type */}
            {subagentType && (
              <span className="text-xs text-emerald-700 font-medium bg-emerald-100 px-2 py-0.5 rounded ml-2">
                Sub Agent Type: {subagentType}
              </span>
            )}
          </div>
        </div>

        {/* 参数展示区域 */}
        <div className="bg-white/80 backdrop-blur px-4 py-3 border-b border-emerald-100">
          <div className="text-xs font-medium text-emerald-700 mb-2 flex items-center gap-2">
            <span>调用参数：</span>
            {toolCall.args && Object.keys(toolCall.args).length > 0 && (
              <button
                onClick={() => setExpanded(!expanded)}
                className="flex items-center text-xs text-emerald-600 hover:text-emerald-700 transition-colors"
              >
                {expanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
                <span>{expanded ? '收起' : '展开'}</span>
              </button>
            )}
          </div>
          {expanded && renderArgs(toolCall.args)}
        </div>

        {/* 工具返回结果 */}
        {toolResult && (
          <div className="bg-white px-4 py-3">
            <div className="text-xs text-gray-500 mb-2 flex items-center gap-2 pb-2 border-b border-gray-100">
              <CheckCircle size={12} className="text-emerald-500" />
              <span>返回结果:</span>
            </div>
            <div className="bg-gray-50 rounded-lg p-3 max-h-64 overflow-y-auto">
              <pre className="text-xs text-gray-700 whitespace-pre-wrap break-all font-mono">
                {escapeHtml(toolResult.content)}
              </pre>
            </div>
          </div>
        )}
      </div>
    );
  }

  // 其他工具调用的默认显示
  return (
    <div className="my-2 border border-emerald-200 rounded-xl overflow-hidden shadow-sm">
      {/* 工具调用部分 */}
      <div className="bg-gradient-to-r from-emerald-50 to-emerald-100/50 px-4 py-3 border-b border-emerald-100">
        <div className="flex items-center gap-2 flex-wrap">
          <Wrench size={16} className="text-emerald-600" />
          <span className="font-semibold text-emerald-700 text-sm">
            {renderToolName(toolCall.name)}
          </span>
          <span className="text-xs text-emerald-600 bg-emerald-100 px-2 py-0.5 rounded font-mono">
            ID: {toolCall.id?.substring(0, 8)}...
          </span>
          {toolResult ? (
            <span className="text-xs text-emerald-600 flex items-center gap-1 bg-emerald-50 px-2 py-0.5 rounded">
              <CheckCircle size={12} /> 已完成
            </span>
          ) : (
            <span className="text-xs text-amber-600 animate-pulse flex items-center gap-1 bg-amber-50 px-2 py-0.5 rounded">
              <Clock size={12} /> 执行中...
            </span>
          )}
        </div>

        {/* 参数展示区域 */}
        <div className="mt-2 bg-white/80 backdrop-blur rounded-lg p-3 border border-emerald-100">
          <div className="text-xs font-medium text-emerald-700 mb-2 flex items-center gap-2">
            <span>调用参数：</span>
            {toolCall.args && Object.keys(toolCall.args).length > 0 && (
              <button
                onClick={() => setExpanded(!expanded)}
                className="flex items-center text-xs text-emerald-600 hover:text-emerald-700 transition-colors"
              >
                {expanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
                <span>{expanded ? '收起' : '展开'}</span>
              </button>
            )}
          </div>
          {expanded && renderArgs(toolCall.args)}
        </div>
      </div>

      {/* 工具返回结果 */}
      {toolResult && (
        <div className="bg-white px-4 py-3">
          <div className="text-xs text-gray-500 mb-2 flex items-center gap-2 pb-2 border-b border-gray-100">
            <CheckCircle size={12} className="text-emerald-500" />
            <span>返回结果:</span>
          </div>
          <div className="bg-gray-50 rounded-lg p-3 max-h-64 overflow-y-auto">
            <pre className="text-xs text-gray-700 whitespace-pre-wrap break-all font-mono">
              {escapeHtml(toolResult.content)}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
};

/**
 * 子 Agent 消息组包裹组件
 */
const SubAgentGroup = ({ subAgentId, agentName, subagentType, messages, children }) => {
  const [collapsed, setCollapsed] = useState(false);

  return (
    <div className="my-3 mr-4 ml-8 border-2 border-accent-200 rounded-2xl overflow-hidden bg-gradient-to-br from-accent-50/30 to-primary-50/30">
      {/* 子 Agent 头部 */}
      <div
        className="bg-gradient-to-r from-accent-100 to-accent-50 px-4 py-2 flex items-center gap-2 cursor-pointer hover:from-accent-200 hover:to-accent-100 transition-colors"
        onClick={() => setCollapsed(!collapsed)}
      >
        <Box size={16} className="text-accent-600" />
        <span className="font-semibold text-accent-700 text-sm">{agentName}</span>
        <span className="text-xs text-accent-600 bg-accent-100 px-2 py-0.5 rounded font-mono">
          {subAgentId?.substring(0, 12)}...
        </span>
        {/* 显示 subagent_type */}
        {subagentType && (
          <span className="text-xs text-accent-600 bg-accent-100 px-2 py-0.5 rounded font-medium">
            {subagentType}
          </span>
        )}
        <span className="text-xs text-accent-600 ml-auto flex items-center gap-1">
          {collapsed ? <ChevronRight size={12} /> : <ChevronDown size={12} />}
          {collapsed ? '展开' : '收起'} ({messages.length} 条消息)
        </span>
      </div>

      {/* 子 Agent 消息内容 */}
      {!collapsed && (
        <div className="p-4 space-y-3">
          {children}
        </div>
      )}
    </div>
  );
};

/**
 * 单个消息组件
 */
const MessageBubble = ({ message, isGrouped = false }) => {
  const [expanded, setExpanded] = useState(false);
  const [contentExpanded, setContentExpanded] = useState(false);

  // 标准化消息类型判断
  const getNormalizedType = () => {
    const type = message.type;
    // WebSocket 原始类型：human, ai, tool
    // 前端类型：user_message, assistant_message, tool_result, system_message, error
    if (type === 'human' || type === 'user' || type === MessageType.USER) return 'user';
    if (type === 'ai' || type === 'assistant' || type === MessageType.ASSISTANT) return 'assistant';
    if (type === 'tool' || type === 'tool_call' || type === 'tool_result' || type === MessageType.TOOL_CALL || type === MessageType.TOOL_RESULT) return 'tool';
    if (type === 'system' || type === MessageType.SYSTEM) return 'system';
    if (type === 'error' || type === MessageType.ERROR) return 'error';
    return 'unknown';
  };

  const normalizedType = getNormalizedType();

  const renderIcon = () => {
    switch (normalizedType) {
      case 'user':
        return <User size={16} className="text-white" />;
      case 'assistant':
        return message.isSubAgent ? <Bot size={16} className="text-accent-500" /> : <Bot size={16} className="text-primary-500" />;
      case 'tool':
        return <Terminal size={16} className="text-emerald-500" />;
      case 'error':
        return <AlertCircle size={16} className="text-red-500" />;
      default:
        return <Clock size={16} className="text-light-textMuted" />;
    }
  };

  const renderHeader = () => {
    let typeLabel = '未知';
    let iconBgClass = 'bg-gradient-to-br from-gray-400 to-gray-500';

    switch (normalizedType) {
      case 'user':
        typeLabel = '你';
        iconBgClass = 'bg-gradient-to-br from-primary-500 to-primary-600';
        break;
      case 'assistant':
        typeLabel = message.isSubAgent ? 'Sub Agent' : 'AI 助手';
        iconBgClass = message.isSubAgent
          ? 'bg-gradient-to-br from-accent-500 to-accent-600'
          : 'bg-gradient-to-br from-primary-500 to-primary-600';
        break;
      case 'tool':
        typeLabel = '工具';
        iconBgClass = 'bg-gradient-to-br from-emerald-500 to-emerald-600';
        break;
      case 'error':
        typeLabel = '错误';
        iconBgClass = 'bg-gradient-to-br from-red-500 to-red-600';
        break;
      case 'system':
        typeLabel = '系统';
        iconBgClass = 'bg-gradient-to-br from-gray-400 to-gray-500';
        break;
    }

    return (
      <div className="flex items-center gap-2 mb-2">
        <div
          className={clsx(
            'w-6 h-6 rounded-full flex items-center justify-center',
            iconBgClass
          )}
        >
          {renderIcon()}
        </div>
        <span className="font-medium text-sm text-light-text">
          {typeLabel}
        </span>
        {message.agentName && (
          <span className={clsx(
            'text-xs px-2 py-0.5 rounded-lg font-medium',
            message.isSubAgent
              ? 'text-accent-600 bg-accent-50'
              : 'text-primary-600 bg-primary-50'
          )}>
            {message.agentName}
          </span>
        )}
        {/* subagent_type 只在 Sub Agent 消息中显示 */}
        {message.isSubAgent && message.subagentType && (
          <span className={clsx(
            'text-xs px-2 py-0.5 rounded-lg font-medium border',
            'text-accent-600 bg-accent-50 border-accent-200'
          )}>
            {message.subagentType}
          </span>
        )}
        <span className="text-xs text-light-textMuted ml-auto">
          {format(new Date(message.timestamp || Date.now()), 'HH:mm:ss')}
        </span>
      </div>
    );
  };

  const renderContent = () => {
    // 检查是否是 AI 消息（支持多种类型格式）
    const isAssistantMessage = normalizedType === 'assistant';

    // 工具调用和工具结果配对显示
    if (isAssistantMessage && message.toolCalls && message.toolCalls.length > 0) {
      // 检查是否所有工具调用都已完成配对
      const allToolsCompleted = message.toolCalls.every(tc => tc.status === 'completed' && tc.result !== null);

      return (
        <div className="space-y-3">
          {/* AI 消息内容 - 即使 content 为空也要显示工具调用 */}
          {message.content && message.content.trim() !== '' ? (
            <ContentWithCollapse
              content={message.content}
              isExpanded={contentExpanded}
              onToggle={() => setContentExpanded(!contentExpanded)}
              isUserMessage={false}
            />
          ) : (
            // content 为空时，根据工具调用状态显示提示文本
            <div className={clsx(
              'text-sm italic mb-2 flex items-center gap-2',
              allToolsCompleted ? 'text-emerald-600' : 'text-gray-500'
            )}>
              {allToolsCompleted ? (
                <>
                  <CheckCircle size={14} className="text-emerald-500" />
                  <span>完成工具调用</span>
                </>
              ) : (
                <>
                  <Clock size={14} className="text-gray-400" />
                  <span>正在调用工具...</span>
                </>
              )}
            </div>
          )}

          {/* 工具调用列表 */}
          <div className="space-y-2 mt-3">
            {message.toolCalls.map((toolCall) => (
              <ToolCallPair
                key={toolCall.id}
                toolCall={toolCall}
                toolResult={toolCall.result}
              />
            ))}
          </div>
        </div>
      );
    }

    // 工具结果（单独显示，未被配对的情况）
    const isToolResult = normalizedType === 'tool';
    if (isToolResult) {
      // 如果已配对到 AI 消息的工具调用中，不单独显示
      if (message.pairedToolCall) {
        return null;
      }

      return (
        <div className="bg-white rounded-xl p-4 font-mono text-sm border border-emerald-200">
          <div className="flex items-center gap-2 mb-2">
            <CheckCircle size={14} className="text-emerald-500" />
            <span className="text-emerald-600 font-semibold">{message.toolName || '工具'}</span>
            {message.toolCallId && (
              <span className="text-xs text-emerald-600 bg-emerald-50 px-2 py-0.5 rounded">
                ID: {message.toolCallId.substring(0, 8)}...
              </span>
            )}
          </div>

          {/* 工具返回内容，进行 HTML 转义 */}
          <div className="bg-light-bgSecondary rounded-lg p-3 overflow-x-auto max-h-64 overflow-y-auto">
            <pre className="text-light-text text-xs whitespace-pre-wrap">
              {escapeHtml(message.content)}
            </pre>
          </div>
        </div>
      );
    }

    // 错误消息特殊渲染
    if (normalizedType === 'error') {
      return (
        <div className="bg-red-50 rounded-xl p-4 border border-red-200">
          <div className="flex items-center gap-2 mb-2">
            <AlertCircle size={16} className="text-red-500" />
            <span className="text-red-600 font-semibold">发生错误</span>
          </div>
          <div className="text-red-700 text-sm">{escapeHtml(message.content)}</div>
        </div>
      );
    }

    // 普通文本消息（用户消息或 AI 回复）
    return (
      <ContentWithCollapse
        content={message.content}
        isExpanded={contentExpanded}
        onToggle={() => setContentExpanded(!contentExpanded)}
        isUserMessage={normalizedType === 'user'}
      />
    );
  };

  // 如果是子 Agent 消息且被分组，使用简化的样式
  if (isGrouped) {
    return (
      <div className="p-3 rounded-xl bg-white border border-accent-100 shadow-sm">
        {renderHeader()}
        {renderContent()}
      </div>
    );
  }

  // 根据消息类型选择不同的样式
  const getBubbleStyle = () => {
    switch (normalizedType) {
      case 'user':
        // 用户消息显示在右侧
        return 'message-user ml-auto mr-8 bg-primary-50 border border-primary-100';
      case 'assistant':
        // AI 消息显示在左侧
        return message.isSubAgent
          ? 'message-subagent mr-8 bg-accent-50 border border-accent-100'
          : 'message-assistant mr-8 bg-white border border-light-border';
      case 'tool':
        // 工具消息显示在左侧
        return 'message-tool mr-8 bg-emerald-50 border border-emerald-100';
      case 'error':
        // 错误消息显示在左侧
        return 'bg-red-50 border border-red-200 mr-8';
      case 'system':
        // 系统消息显示在左侧
        return 'message-system mr-8 bg-white border border-light-border';
      default:
        // 默认显示在左侧
        return 'mr-8 bg-white border border-light-border';
    }
  };

  return (
    <div
      className={clsx(
        'p-4 rounded-2xl mb-3 animate-fade-in shadow-sm',
        getBubbleStyle()
      )}
    >
      {renderHeader()}
      {renderContent()}
    </div>
  );
};

export { MessageBubble, SubAgentGroup, ToolCallPair, ContentWithCollapse };
export default MessageBubble;
