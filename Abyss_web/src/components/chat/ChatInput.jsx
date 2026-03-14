import React, { useState, useRef, useEffect } from 'react';
import { Send, Square } from 'lucide-react';
import clsx from 'clsx';

/**
 * 聊天输入框组件
 */
const ChatInput = ({ onSend, onTaskStop, disabled, isRunning, placeholder = '输入消息... (Shift+Enter 换行)' }) => {
  const [input, setInput] = useState('');
  const [isFocused, setIsFocused] = useState(false);
  const textareaRef = useRef(null);

  // 自动调整高度
  useEffect(() => {
    if (textareaRef.current) {
      textareaRef.current.style.height = 'auto';
      textareaRef.current.style.height = `${Math.min(textareaRef.current.scrollHeight, 200)}px`;
    }
  }, [input]);

  const handleSubmit = (e) => {
    e.preventDefault();
    if (input.trim() && !disabled) {
      // 先清空输入框，再发送消息
      setInput('');
      // 重置高度
      if (textareaRef.current) {
        textareaRef.current.style.height = 'auto';
      }
      // 发送消息
      onSend(input.trim());
    }
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSubmit(e);
    }
  };

  return (
    <div className="border-t border-light-border bg-white p-5">
      {/* 输入框 */}
      <form onSubmit={handleSubmit} className="relative">
        <div
          className={clsx(
            'flex items-end gap-2 p-3 rounded-2xl border transition-all',
            isFocused
              ? 'border-primary-400 bg-white shadow-lg shadow-primary-100'
              : 'border-light-border bg-light-bgSecondary'
          )}
        >
          {/* 文本输入 */}
          <textarea
            ref={textareaRef}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onFocus={() => setIsFocused(true)}
            onBlur={() => setIsFocused(false)}
            onKeyDown={handleKeyDown}
            placeholder={disabled ? placeholder : placeholder}
            disabled={disabled}
            rows={1}
            className="flex-1 bg-transparent text-light-text placeholder-light-textMuted resize-none focus:outline-none py-2 max-h-48 disabled:opacity-50"
          />

          {/* 任务取消按钮 */}
          <button
            type="button"
            onClick={onTaskStop}
            disabled={disabled}
            className={clsx(
              'p-2.5 rounded-xl transition-all',
              !disabled
                ? 'bg-red-500 hover:bg-red-600 text-white shadow-md hover:shadow-lg'
                : 'bg-light-border text-light-textMuted cursor-not-allowed'
            )}
            title="停止任务"
          >
            <Square size={18} />
          </button>

          {/* 发送按钮 */}
          <button
            type="submit"
            disabled={!input.trim() || disabled}
            className={clsx(
              'p-2.5 rounded-xl transition-all',
              input.trim() && !disabled
                ? 'bg-gradient-to-r from-primary-500 to-accent-500 hover:shadow-glow text-white'
                : 'bg-light-border text-light-textMuted cursor-not-allowed'
            )}
          >
            <Send size={18} />
          </button>
        </div>
      </form>
    </div>
  );
};

export default ChatInput;
