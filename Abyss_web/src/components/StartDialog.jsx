import React, { useState } from 'react';
import { ArrowRight, Settings, WifiOff, Shield, Target, Radar } from 'lucide-react';
import clsx from 'clsx';
import { useTaskStore, useChatStore } from '../store/store.js';
import webSocketService from '../services/websocket.js';
import { MessageType } from './chat/MessageTypes.js';

/**
 * 起始页对话框组件 - 扁平简洁风格（参考 deepseek/豆包）
 */
const StartDialog = ({ onConfirm, connectionStatus, onOpenSettings }) => {
  const [inputValue, setInputValue] = useState('');
  const [isStarting, setIsStarting] = useState(false);
  const { initGlobalTask } = useTaskStore();
  const { addMessage, setCurrentTaskId } = useChatStore();

  const handleConfirm = async () => {
    if (!inputValue.trim()) return;

    const targetAddress = inputValue.trim();
    setIsStarting(true);

    try {
      // 1. 创建全局任务
      const task = await initGlobalTask({
        name: '渗透测试任务 - ' + new Date().toLocaleString('zh-CN'),
        target: targetAddress,
        description: '',
      });

      // 2. 设置当前任务 ID
      setCurrentTaskId(task.id);

      // 3. 连接 WebSocket（使用任务 ID）
      // 优先使用 localStorage 中配置的地址，否则使用相对路径（通过 Vite 代理）
      const wsUrl = localStorage.getItem('wsUrl');
      await webSocketService.connect(task.id, wsUrl);

      // 4. 通过 WebSocket 发送启动消息，触发后端响应
      webSocketService.sendUserMessage(`${targetAddress}`, task.id);

      // 5. 等待一小段时间，确保 WebSocket 消息能被 ChatPanel 接收
      await new Promise(resolve => setTimeout(resolve, 100));

      // 6. 通知父组件关闭对话框
      onConfirm();
    } catch (error) {
      console.error('❌ 启动任务失败:', error);
      alert('启动任务失败：' + error.message);
    } finally {
      setIsStarting(false);
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      if (inputValue.trim() && connectionStatus === 'connected' && !isStarting) {
        handleConfirm();
      }
    }
  };

  const isConnected = connectionStatus === 'connected';

  // 自动调整 textarea 高度
  const handleTextareaChange = (e) => {
    setInputValue(e.target.value);
    e.target.style.height = 'auto';
    e.target.style.height = Math.min(e.target.scrollHeight, 200) + 'px';
  };

  return (
    <div className="fixed inset-0 bg-gradient-to-br from-indigo-50 via-white to-blue-50 flex flex-col z-50">
      {/* 顶部导航栏 */}
      <div className="h-16 flex items-center justify-between px-6 flex-shrink-0">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-indigo-600 to-blue-600 flex items-center justify-center shadow-lg">
            <Shield size={22} className="text-white" />
          </div>
          <div>
            <h1 className="text-lg font-bold text-slate-800">渗透测试管理平台</h1>
            <p className="text-xs text-slate-500">AI 驱动的智能安全测试系统</p>
          </div>
        </div>

        <button
          onClick={onOpenSettings}
          className="p-2.5 rounded-xl text-slate-400 hover:text-slate-600 hover:bg-slate-100 transition-all"
          title="系统设置"
        >
          <Settings size={20} />
        </button>
      </div>

      {/* 居中对话框区域 */}
      <div className="flex-1 flex items-center justify-center p-8">
        <div className="w-full max-w-2xl">
          {/* 对话框主体 - 扁平化设计 */}
          <div className="bg-white/70 backdrop-blur-xl rounded-3xl shadow-xl border border-white/50 overflow-hidden">
            {/* 头部 */}
            <div className="p-8 pb-4 text-center">
              <div className="w-16 h-16 mx-auto mb-4 rounded-2xl bg-gradient-to-br from-indigo-500 via-purple-500 to-blue-500 flex items-center justify-center shadow-lg shadow-indigo-500/30">
                <Radar size={32} className="text-white" />
              </div>
              <h2 className="text-xl font-semibold text-slate-800 mb-2">开始新的渗透测试</h2>
              <p className="text-sm text-slate-500">输入目标地址，AI 助手将协助您完成渗透测试</p>
            </div>

            {/* 连接状态提示 */}
            {!isConnected && (
              <div className="px-8 pb-4">
                <div className="p-3 rounded-xl bg-amber-50/80 border border-amber-200/50 flex items-start gap-3">
                  <WifiOff size={16} className="text-amber-500 mt-0.5 flex-shrink-0" />
                  <div className="flex-1">
                    <p className="text-sm font-medium text-amber-800">WebSocket 未连接</p>
                    <p className="text-xs text-amber-600 mt-0.5">请在右上角设置中配置 WebSocket 地址并建立连接</p>
                  </div>
                </div>
              </div>
            )}

            {/* 输入区域 */}
            <div className="p-8 pt-4">
              {/* 输入框和按钮容器 - 整体居中 */}
              <div className="flex justify-center">
                <div className="flex items-start gap-3 w-full max-w-3xl">
                  {/* 输入框 */}
                  <div className="flex-1 relative">
                    <textarea
                      value={inputValue}
                      onChange={handleTextareaChange}
                      onKeyPress={handleKeyPress}
                      placeholder={isConnected ? "输入目标地址，例如：192.168.1.0/24 或 https://example.com" : "请先连接 WebSocket"}
                      disabled={!isConnected || isStarting}
                      rows={1}
                      className={clsx(
                        'w-full px-4 py-3.5 rounded-2xl resize-none transition-all outline-none text-sm overflow-hidden',
                        isConnected
                          ? 'bg-white border border-slate-200 focus:border-indigo-400 focus:ring-4 focus:ring-indigo-100'
                          : 'bg-slate-100 border border-slate-200 text-slate-400 cursor-not-allowed'
                      )}
                    />
                  </div>

                  {/* 开始按钮 - 与输入框平行 */}
                  <button
                    onClick={handleConfirm}
                    disabled={!isConnected || !inputValue.trim() || isStarting}
                    className={clsx(
                      'px-6 py-3.5 rounded-2xl transition-all flex items-center gap-2 text-sm font-medium shadow-md flex-shrink-0 h-fit',
                      isConnected && inputValue.trim() && !isStarting
                        ? 'bg-gradient-to-r from-indigo-600 via-purple-600 to-blue-600 text-white hover:shadow-lg hover:shadow-indigo-500/30 hover:scale-105'
                        : 'bg-slate-200 text-slate-400 cursor-not-allowed shadow-none'
                    )}
                  >
                    {isStarting ? (
                      <>
                        <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>
                        <span>启动中...</span>
                      </>
                    ) : (
                      <>
                        <span>开始</span>
                        <ArrowRight size={16} />
                      </>
                    )}
                  </button>
                </div>
              </div>

              {/* 提示信息 */}
              <div className="mt-4 flex items-center justify-center gap-3 text-xs text-slate-400">
                <span>按 Enter 发送</span>
                <span className="w-px h-3 bg-slate-300"></span>
                <span>Shift + Enter 换行</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default StartDialog;
