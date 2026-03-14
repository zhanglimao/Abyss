import React, { useState, useEffect } from 'react';
import { Menu, X, Settings, HelpCircle, Bell, Globe, Globe2, Server, RefreshCw, WifiOff, MessageSquare, Shield } from 'lucide-react';
import clsx from 'clsx';
import StartDialog from './StartDialog.jsx';
import ChatPanel from './chat/ChatPanel.jsx';
import InfoPanel from './InfoPanel.jsx';
import webSocketService from '../services/websocket.js';
import { useTaskStore } from '../store/store.js';

/**
 * 主布局组件 - 新架构：全局单一任务
 * 布局：左侧对话区域 70%，右侧关键信息区域 30%
 */
const Layout = () => {
  const [rightPanelCollapsed, setRightPanelCollapsed] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [showStartDialog, setShowStartDialog] = useState(true);
  const [taskStarted, setTaskStarted] = useState(false);
  const [wsConnectionStatus, setWsConnectionStatus] = useState('disconnected');

  const { globalTask, fetchGlobalTask, initGlobalTask } = useTaskStore();

  // 监听 WebSocket 连接状态
  useEffect(() => {
    const unsubscribe = webSocketService.onStatusChange((status) => {
      console.log('📡 Layout 收到 WebSocket 状态变化:', status);
      setWsConnectionStatus(status);
    });

    // 初始化状态
    const initialStatus = webSocketService.getConnectionStatus();
    console.log('📡 Layout 初始化 WebSocket 状态:', initialStatus);
    setWsConnectionStatus(initialStatus);

    // 页面加载时自动尝试连接（只要有配置就连接）
    const currentWsUrl = localStorage.getItem('wsUrl');
    const currentApiUrl = localStorage.getItem('apiUrl');
    // 检测是否是页面刷新（二级页面刷新场景）
    const isPageRefresh = sessionStorage.getItem('taskStarted') === 'true';
    const savedTaskId = sessionStorage.getItem('currentTaskId');

    console.log('🔍 Layout 页面加载，检查配置...');
    console.log('   wsUrl:', currentWsUrl);
    console.log('   apiUrl:', currentApiUrl);
    console.log('   isPageRefresh:', isPageRefresh);
    console.log('   savedTaskId:', savedTaskId);

    if (currentWsUrl && currentApiUrl) {
      console.log('🔌 Layout 检测到已保存的配置，尝试自动连接...');
      console.log('   WebSocket 地址:', currentWsUrl);
      console.log('   API 地址:', currentApiUrl || '未设置');
      console.log('   是否页面刷新:', isPageRefresh);
      console.log('   保存的任务 ID:', savedTaskId || '无');

      // 确定使用的任务 ID
      // 页面刷新时使用 sessionStorage 中的任务 ID，否则使用新的全局会话 ID
      const targetTaskId = (isPageRefresh && savedTaskId) ? savedTaskId : 'global-session-' + Date.now();
      console.log('🚀 Layout 使用任务 ID 连接 WebSocket:', targetTaskId);

      // 测试 API 连接
      testApiConnection(currentApiUrl).then(apiConnected => {
        if (apiConnected) {
          console.log('✅ RESTful API 连接成功');
        } else {
          console.warn('⚠️ RESTful API 连接失败');
        }
      }).catch(err => {
        console.error('❌ RESTful API 测试失败:', err);
      });

      // 连接 WebSocket
      webSocketService.connect(targetTaskId, currentWsUrl)
        .then(() => {
          console.log('✅ Layout WebSocket 自动连接成功');
          setWsConnectionStatus('connected');

          // 如果是页面刷新场景，先发送 task_stop 停止之前的任务，再发送 task_continue 恢复任务
          if (isPageRefresh && savedTaskId) {
            console.log('🔄 Layout 页面刷新检测到，先发送 task_stop 停止之前的任务');
            webSocketService.send({
              type: 'task_stop',
              task_id: savedTaskId,
              timestamp: new Date().toISOString(),
            });
            
            // 等待一小段时间后再发送 task_continue
            setTimeout(() => {
              console.log('📤 发送 task_continue 恢复任务');
              webSocketService.sendTaskContinue(savedTaskId);
            }, 100);
          }
        })
        .catch((error) => {
          console.error('❌ Layout WebSocket 自动连接失败:', error);
          setWsConnectionStatus('error');
        });
    } else {
      console.log('ℹ️ Layout 未检测到已保存的配置，请在系统设置中配置');
    }

    // 清理函数
    return () => {
      unsubscribe();
    };
  }, []);

  // 测试 RESTful API 连接
  const testApiConnection = async (url) => {
    console.log('🌐 测试 RESTful API 连接:', url);
    try {
      const endpoints = ['/api', '/config', '/tools', '/'];
      for (const endpoint of endpoints) {
        try {
          const fullUrl = `${url}${endpoint}`;
          console.log('  尝试端点:', fullUrl);
          const response = await fetch(fullUrl, {
            method: 'GET',
            headers: { 'Content-Type': 'application/json' },
          });
          console.log('  响应状态码:', response.status);
          if (response.ok || response.status === 404) {
            console.log('✅ RESTful API 连接成功 (端点：' + endpoint + ')');
            return true;
          }
        } catch (endpointError) {
          console.log('  端点', endpoint, '请求失败:', endpointError.message);
          continue;
        }
      }
      console.warn('⚠️ RESTful API 所有端点都失败');
      return false;
    } catch (error) {
      console.error('❌ RESTful API 连接失败:', error.message);
      return false;
    }
  };

  // 处理起始对话框确认
  const handleStartConfirm = async () => {
    console.log('🚀 任务已启动');

    // 获取或创建全局任务
    const task = await fetchGlobalTask();

    // 连接 WebSocket（如果尚未连接）
    // 优先使用 localStorage 中配置的地址，否则使用相对路径（通过 Vite 代理）
    const wsUrl = localStorage.getItem('wsUrl');
    if (webSocketService.getConnectionStatus() !== 'connected') {
      await webSocketService.connect(task.id, wsUrl);
    }

    // 保存任务状态到 sessionStorage，用于刷新检测
    sessionStorage.setItem('taskStarted', 'true');
    sessionStorage.setItem('currentTaskId', task.id);
    console.log('💾 已保存任务状态到 sessionStorage，任务 ID:', task.id);

    // 关闭对话框，显示主界面
    setShowStartDialog(false);
    setTaskStarted(true);
  };

  // 清理任务状态（用户主动退出时调用）
  const clearTaskState = () => {
    sessionStorage.removeItem('taskStarted');
    sessionStorage.removeItem('currentTaskId');
    console.log('🗑️ 已清理任务状态');
  };

  // 注意：不在 beforeunload 时清理 sessionStorage
  // 这样页面刷新时可以自动恢复任务
  // 只在用户主动退出任务时调用 clearTaskState() 清理

  return (
    <div className="flex h-screen bg-light-bg overflow-hidden relative">
      {/* 起始对话框 */}
      {showStartDialog && (
        <StartDialog 
          onConfirm={handleStartConfirm}
          connectionStatus={wsConnectionStatus}
          onOpenSettings={() => setShowSettings(true)}
        />
      )}

      {/* 主界面 */}
      {taskStarted && (
        <>
          {/* 左侧对话区域 - 70% */}
          <div className="flex-[7] flex flex-col min-w-0 border-r border-light-border bg-white">
            {/* 顶部导航栏 */}
            <header className="h-16 border-b border-light-border bg-white/80 backdrop-blur-md flex items-center justify-between px-6 shadow-sm">
              <div className="flex items-center gap-4">
                <div className="flex items-center gap-3">
                  <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-primary-500 via-primary-600 to-accent-600 flex items-center justify-center shadow-glow">
                    <MessageSquare size={18} className="text-white" />
                  </div>
                  <div>
                    <h1 className="text-lg font-bold gradient-text">渗透测试管理平台</h1>
                    <p className="text-xs text-light-textMuted">AI 驱动的智能安全测试</p>
                  </div>
                </div>
                
                {/* 任务信息 */}
                {globalTask && (
                  <div className="ml-4 px-4 py-2 rounded-xl bg-light-bgSecondary border border-light-border">
                    <div className="text-xs font-medium text-light-text">{globalTask.name}</div>
                    <div className="text-xs text-light-textMuted truncate max-w-[200px]">{globalTask.target}</div>
                  </div>
                )}
              </div>

              <div className="flex items-center gap-2">
                {/* WebSocket 状态 */}
                <div className={clsx(
                  'flex items-center gap-2 px-3 py-2 rounded-xl text-xs font-medium',
                  wsConnectionStatus === 'connected'
                    ? 'bg-emerald-50 text-emerald-600 border border-emerald-200'
                    : wsConnectionStatus === 'error'
                    ? 'bg-red-50 text-red-600 border border-red-200'
                    : 'bg-gray-100 text-gray-500 border border-gray-200'
                )}>
                  {wsConnectionStatus === 'connected' ? (
                    <Globe2 size={14} className="text-emerald-500" />
                  ) : (
                    <WifiOff size={14} className="text-gray-400" />
                  )}
                  <span>
                    {wsConnectionStatus === 'connected' ? '已连接' : 
                     wsConnectionStatus === 'error' ? '连接失败' : '未连接'}
                  </span>
                </div>

                <button
                  className="p-2.5 rounded-xl text-light-textMuted hover:text-primary-600 hover:bg-primary-50 transition-all"
                  title="通知"
                >
                  <Bell size={18} />
                </button>
                <button
                  onClick={() => setShowSettings(true)}
                  className="p-2.5 rounded-xl text-light-textMuted hover:text-primary-600 hover:bg-primary-50 transition-all"
                  title="系统设置"
                >
                  <Settings size={18} />
                </button>
                <button
                  className="p-2.5 rounded-xl text-light-textMuted hover:text-primary-600 hover:bg-primary-50 transition-all"
                  title="帮助"
                >
                  <HelpCircle size={18} />
                </button>
              </div>
            </header>

            {/* 聊天区域 */}
            <main className="flex-1 overflow-hidden">
              <ChatPanel />
            </main>
          </div>

          {/* 右侧关键信息区域 - 30% */}
          <div
            className={clsx(
              'flex-[3] transition-all duration-300 border-l border-light-border bg-white min-w-[350px]',
              rightPanelCollapsed ? 'w-16 min-w-0' : ''
            )}
          >
            <div className="h-full relative">
              {!rightPanelCollapsed ? (
                <InfoPanel />
              ) : (
                <div className="flex flex-col items-center py-4 gap-4 bg-white h-full">
                  <button
                    onClick={() => setRightPanelCollapsed(false)}
                    className="p-3 rounded-xl bg-light-bgSecondary hover:bg-light-border transition-all"
                    title="展开信息面板"
                  >
                    <Menu size={20} className="text-light-text" />
                  </button>
                </div>
              )}

              {/* 折叠按钮 */}
              <button
                onClick={() => setRightPanelCollapsed(!rightPanelCollapsed)}
                className="absolute top-4 -left-3 w-6 h-6 rounded-full bg-white border border-light-border hover:border-primary-300 flex items-center justify-center transition-all shadow-sm z-10"
                title={rightPanelCollapsed ? '展开' : '收起'}
              >
                {rightPanelCollapsed ? (
                  <Menu size={12} className="text-light-text" />
                ) : (
                  <X size={12} className="text-light-text" />
                )}
              </button>
            </div>
          </div>
        </>
      )}

      {/* 设置模态框 */}
      {showSettings && (
        <SettingsModal onClose={() => setShowSettings(false)} />
      )}
    </div>
  );
};

/**
 * 设置模态框 - 支持自动连接和定时检测
 */
const SettingsModal = ({ onClose }) => {
  const [apiUrl, setApiUrl] = useState(() => {
    return localStorage.getItem('apiUrl') || '/api';
  });
  const [wsUrl, setWsUrl] = useState(() => {
    // 使用相对路径作为默认值，支持容器环境
    return localStorage.getItem('wsUrl') || `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}/ws`;
  });
  const [notificationsEnabled, setNotificationsEnabled] = useState(true);
  const [autoRefreshEnabled, setAutoRefreshEnabled] = useState(true);
  const [isConnecting, setIsConnecting] = useState(false);

  // 分别管理 RESTful API 和 WebSocket 的连接状态
  const [apiConnectionStatus, setApiConnectionStatus] = useState('disconnected');
  const [wsConnectionStatus, setWsConnectionStatus] = useState('disconnected');
  const [lastPingTime, setLastPingTime] = useState(null);

  // 监听 WebSocket 连接状态变化（SettingsModal 内部）
  useEffect(() => {
    const unsubscribe = webSocketService.onStatusChange((status) => {
      console.log('📡 SettingsModal 收到 WebSocket 状态变化:', status);
      setWsConnectionStatus(status);

      // 如果连接异常断开，自动重连
      if (status === 'disconnected' || status === 'error') {
        const currentWsUrl = localStorage.getItem('wsUrl');
        if (currentWsUrl && status === 'disconnected') {
          console.log('🔄 WebSocket 异常断开，准备自动重连...');
          setTimeout(() => {
            // 优先使用 sessionStorage 中的任务 ID（页面刷新场景）
            const savedTaskId = sessionStorage.getItem('currentTaskId');
            const globalTaskId = savedTaskId || 'global-session-' + Date.now();
            console.log('🔌 自动重连 WebSocket，任务 ID:', globalTaskId);
            webSocketService.connect(globalTaskId, currentWsUrl)
              .then(() => {
                console.log('✅ WebSocket 自动重连成功');
                // 如果是页面刷新场景，发送任务恢复消息
                if (savedTaskId) {
                  console.log('📤 发送任务恢复消息');
                  webSocketService.sendTaskContinue(savedTaskId);
                }
              })
              .catch((error) => {
                console.error('❌ WebSocket 自动重连失败:', error);
              });
          }, 2000);
        }
      }
    });

    // 初始化 WebSocket 状态（从全局服务获取）
    const initialWsStatus = webSocketService.getConnectionStatus();
    console.log('📡 SettingsModal 初始化 WebSocket 状态:', initialWsStatus);
    setWsConnectionStatus(initialWsStatus);

    // 从 localStorage 加载配置（用于显示）
    const currentWsUrl = localStorage.getItem('wsUrl');
    const currentApiUrl = localStorage.getItem('apiUrl');

    if (currentWsUrl) setWsUrl(currentWsUrl);
    if (currentApiUrl) setApiUrl(currentApiUrl);

    // 监听页面可见性变化
    const handleVisibilityChange = () => {
      if (document.visibilityState === 'visible') {
        const currentStatus = webSocketService.getConnectionStatus();
        console.log('👁️ 页面可见，当前 WebSocket 状态:', currentStatus);

        // 如果连接已断开或关闭，尝试重连
        if ((currentStatus === 'disconnected' || currentStatus === 'closed' || currentStatus === 'error') && currentWsUrl) {
          console.log('🔄 WebSocket 连接已断开，尝试重连...');
          const currentTaskId = sessionStorage.getItem('currentTaskId');
          const globalTaskId = currentTaskId || 'global-session-' + Date.now();
          webSocketService.connect(globalTaskId, currentWsUrl)
            .then(() => {
              console.log('✅ WebSocket 重连成功');
              // 如果是页面刷新场景，发送任务恢复消息
              if (currentTaskId) {
                console.log('📤 发送任务恢复消息');
                webSocketService.sendTaskContinue(currentTaskId);
              }
            })
            .catch((error) => {
              console.error('❌ WebSocket 重连失败:', error);
            });
        }
      }
    };

    document.addEventListener('visibilitychange', handleVisibilityChange);

    return () => {
      unsubscribe();
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    };
  }, []);

  // 注意：页面刷新时浏览器会关闭 WebSocket 连接，这是正常行为
  // 我们通过自动重连逻辑在页面加载后重新建立连接

  // 测试 RESTful API 连接
  const testApiConnection = async (url) => {
    console.log('🌐 测试 RESTful API 连接:', url);
    try {
      // 尝试多个可能的端点
      const endpoints = ['/api', '/config', '/tools', '/'];

      for (const endpoint of endpoints) {
        try {
          const fullUrl = `${url}${endpoint}`;
          console.log('  尝试端点:', fullUrl);

          const response = await fetch(fullUrl, {
            method: 'GET',
            headers: { 'Content-Type': 'application/json' },
          });

          console.log('  响应状态码:', response.status);

          // 200-299 或 404 都表示服务器可达
          if (response.ok || response.status === 404) {
            console.log('✅ RESTful API 连接成功 (端点：' + endpoint + ')');
            setApiConnectionStatus('connected');
            return true;
          }
        } catch (endpointError) {
          console.log('  端点', endpoint, '请求失败:', endpointError.message);
          continue;
        }
      }

      // 所有端点都失败
      console.warn('⚠️ RESTful API 所有端点都失败');
      setApiConnectionStatus('error');
      return false;
    } catch (error) {
      console.error('❌ RESTful API 连接失败:', error.message);
      setApiConnectionStatus('error');
      return false;
    }
  };

  const handleSaveSettings = async () => {
    console.log('💾 开始保存配置并连接服务器...');
    console.log('   API 地址:', apiUrl);
    console.log('   WebSocket 地址:', wsUrl);

    // 保存到 localStorage
    localStorage.setItem('apiUrl', apiUrl);
    localStorage.setItem('wsUrl', wsUrl);

    // 更新 WebSocket 服务地址
    webSocketService.setBaseUrl(wsUrl);

    setIsConnecting(true);
    setApiConnectionStatus('connecting');
    setWsConnectionStatus('connecting');

    try {
      // 1. 先测试 RESTful API 连接
      console.log('🌐 正在测试 RESTful API 连接...');
      const apiConnected = await testApiConnection(apiUrl);

      if (!apiConnected) {
        console.error('❌ RESTful API 连接失败');
        setApiConnectionStatus('error');
        throw new Error('RESTful API 连接失败');
      }
      console.log('✅ RESTful API 连接成功');
      setApiConnectionStatus('connected');

      // 2. 建立 WebSocket 连接
      console.log('🔌 正在连接 WebSocket...');
      const globalTaskId = 'global-session-' + Date.now();

      await webSocketService.connect(globalTaskId, wsUrl);
      console.log('✅ WebSocket 连接成功');
      setWsConnectionStatus('connected');

      // 连接成功，延迟关闭模态框
      setTimeout(() => {
        onClose();
        setIsConnecting(false);
      }, 500);
    } catch (error) {
      console.error('❌ 连接失败:', error);
      setApiConnectionStatus('error');
      setWsConnectionStatus('error');
      alert('服务器连接失败，请检查地址是否正确或服务器是否运行');
      setIsConnecting(false);
    }
  };

  // 根据连接状态返回图标和信息
  const getConnectionStatusInfo = (status) => {
    if (status === 'connected') {
      return {
        icon: <Globe2 size={16} className="text-emerald-500" />,
        text: '已连接',
        color: 'text-emerald-600',
        bg: 'bg-emerald-50'
      };
    }
    if (status === 'connecting') {
      return {
        icon: <Server size={16} className="text-blue-500 animate-pulse" />,
        text: '连接中...',
        color: 'text-blue-600',
        bg: 'bg-blue-50'
      };
    }
    if (status === 'error') {
      return {
        icon: <WifiOff size={16} className="text-red-500" />,
        text: '连接失败',
        color: 'text-red-600',
        bg: 'bg-red-50'
      };
    }
    return {
      icon: <Globe size={16} className="text-light-textMuted" />,
      text: '未连接',
      color: 'text-light-textMuted',
      bg: 'bg-light-bgSecondary'
    };
  };

  return (
    <div className="fixed inset-0 bg-black/40 backdrop-blur-sm flex items-center justify-center z-50">
      <div className="bg-white rounded-2xl w-full max-w-md mx-4 border border-light-border shadow-2xl overflow-hidden animate-fade-in-up">
        <div className="p-6 border-b border-light-border bg-gradient-to-r from-primary-50 to-accent-50">
          <h3 className="text-xl font-semibold gradient-text">系统设置</h3>
          <p className="text-sm text-light-textMuted mt-1">配置系统参数和偏好设置</p>
        </div>

        <div className="p-6 space-y-5">
          {/* API 服务器地址 */}
          <div>
            <label className="block text-sm font-medium text-light-text mb-2">
              API 服务器地址
            </label>
            <input
              type="text"
              value={apiUrl}
              onChange={(e) => setApiUrl(e.target.value)}
              placeholder="http://0.0.0.0:80"
              className="w-full px-4 py-3 input-field font-mono text-sm"
            />
          </div>

          {/* WebSocket 地址 */}
          <div>
            <label className="block text-sm font-medium text-light-text mb-2">
              WebSocket 地址
            </label>
            <div className="relative">
              <input
                type="text"
                value={wsUrl}
                onChange={(e) => setWsUrl(e.target.value)}
                placeholder="ws://0.0.0.0:80"
                className="w-full px-4 py-3 input-field font-mono text-sm pr-10"
              />
              <div className="absolute right-3 top-1/2 -translate-y-1/2">
                {getConnectionStatusInfo(wsConnectionStatus).icon}
              </div>
            </div>
          </div>

          {/* 连接状态显示 */}
          <div className="space-y-2">
            {/* RESTful API 状态 */}
            <div className={clsx(
              'p-3 rounded-xl border flex items-center gap-3',
              apiConnectionStatus === 'connected' ? 'bg-emerald-50 text-emerald-600 border-emerald-200' :
              apiConnectionStatus === 'connecting' ? 'bg-blue-50 text-blue-600 border-blue-200' :
              apiConnectionStatus === 'error' ? 'bg-red-50 text-red-600 border-red-200' :
              'bg-light-bgSecondary text-light-textMuted border-light-border'
            )}>
              {apiConnectionStatus === 'connected' ? <Globe2 size={16} /> : 
               apiConnectionStatus === 'connecting' ? <Server size={16} className="animate-pulse" /> :
               apiConnectionStatus === 'error' ? <WifiOff size={16} /> : <Globe size={16} />}
              <div className="flex-1">
                <p className="font-medium text-sm">
                  RESTful API: {apiConnectionStatus === 'connected' ? '已连接' : 
                               apiConnectionStatus === 'connecting' ? '连接中...' : 
                               apiConnectionStatus === 'error' ? '连接失败' : '未连接'}
                </p>
              </div>
            </div>

            {/* WebSocket 状态 */}
            <div className={clsx(
              'p-3 rounded-xl border flex items-center gap-3',
              wsConnectionStatus === 'connected' ? 'bg-emerald-50 text-emerald-600 border-emerald-200' :
              wsConnectionStatus === 'connecting' ? 'bg-blue-50 text-blue-600 border-blue-200' :
              wsConnectionStatus === 'error' ? 'bg-red-50 text-red-600 border-red-200' :
              'bg-light-bgSecondary text-light-textMuted border-light-border'
            )}>
              {wsConnectionStatus === 'connected' ? <Globe2 size={16} /> : 
               wsConnectionStatus === 'connecting' ? <Server size={16} className="animate-pulse" /> :
               wsConnectionStatus === 'error' ? <WifiOff size={16} /> : <Globe size={16} />}
              <div className="flex-1">
                <p className="font-medium text-sm">
                  WebSocket: {wsConnectionStatus === 'connected' ? '已连接' : 
                             wsConnectionStatus === 'connecting' ? '连接中...' : 
                             wsConnectionStatus === 'error' ? '连接失败' : '未连接'}
                </p>
                {lastPingTime && (
                  <p className="text-xs opacity-75 mt-0.5">
                    最后心跳：{new Date(lastPingTime).toLocaleTimeString()}
                  </p>
                )}
              </div>
              {wsConnectionStatus === 'connected' && (
                <div className="flex items-center gap-1 text-xs">
                  <span className="w-2 h-2 bg-emerald-500 rounded-full animate-pulse"></span>
                  <span>正常</span>
                </div>
              )}
            </div>
          </div>

          {/* 连接状态提示 */}
          <div className="p-3 rounded-xl bg-light-bgSecondary border border-light-border">
            <div className="flex items-start gap-2">
              <Server size={16} className="text-primary-500 mt-0.5" />
              <div className="text-xs text-light-textMuted">
                <p className="font-medium text-light-text mb-1">连接说明：</p>
                <ul className="space-y-1">
                  <li>• 配置 API 和 WebSocket 地址后点击"建立连接"</li>
                  <li>• 全局网络会话使用这里建立的连接</li>
                  <li>• 任务列表切换时只进行任务 ID 切换，不再重新连接</li>
                  <li>• 系统自动每 10 秒发送心跳检测连接状态</li>
                </ul>
              </div>
            </div>
          </div>

          {/* 通知开关 */}
          <div className="flex items-center justify-between p-3 rounded-xl bg-light-bgSecondary">
            <div>
              <label className="text-sm font-medium text-light-text">启用通知</label>
              <p className="text-xs text-light-textMuted mt-0.5">接收系统通知和提醒</p>
            </div>
            <label className="relative inline-flex items-center cursor-pointer">
              <input 
                type="checkbox" 
                checked={notificationsEnabled}
                onChange={(e) => setNotificationsEnabled(e.target.checked)}
                className="sr-only peer" 
              />
              <div className="w-11 h-6 bg-light-border peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-primary-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-gradient-to-r peer-checked:from-primary-500 peer-checked:to-accent-500"></div>
            </label>
          </div>

          {/* 自动刷新开关 */}
          <div className="flex items-center justify-between p-3 rounded-xl bg-light-bgSecondary">
            <div>
              <label className="text-sm font-medium text-light-text">自动刷新数据</label>
              <p className="text-xs text-light-textMuted mt-0.5">实时更新任务状态</p>
            </div>
            <label className="relative inline-flex items-center cursor-pointer">
              <input 
                type="checkbox" 
                checked={autoRefreshEnabled}
                onChange={(e) => setAutoRefreshEnabled(e.target.checked)}
                className="sr-only peer" 
              />
              <div className="w-11 h-6 bg-light-border peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-primary-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-gradient-to-r peer-checked:from-primary-500 peer-checked:to-accent-500"></div>
            </label>
          </div>
        </div>

        <div className="p-6 border-t border-light-border bg-light-bg space-y-3">
          {/* 连接状态显示 */}
          {(apiConnectionStatus !== 'connected' || wsConnectionStatus !== 'connected') && (
            <button
              onClick={handleSaveSettings}
              disabled={isConnecting || apiConnectionStatus === 'connecting' || wsConnectionStatus === 'connecting'}
              className={clsx(
                'w-full px-4 py-3 rounded-xl font-medium transition-all flex items-center justify-center gap-2',
                (isConnecting || apiConnectionStatus === 'connecting' || wsConnectionStatus === 'connecting')
                  ? 'bg-light-bgSecondary text-light-textMuted cursor-not-allowed'
                  : 'btn-primary'
              )}
            >
              {(isConnecting || apiConnectionStatus === 'connecting' || wsConnectionStatus === 'connecting') ? (
                <>
                  <Server size={18} className="animate-spin" />
                  <span>连接中...</span>
                </>
              ) : (
                <>
                  <Globe size={18} />
                  <span>保存并连接</span>
                </>
              )}
            </button>
          )}

          {apiConnectionStatus === 'connected' && wsConnectionStatus === 'connected' && (
            <div className="p-4 rounded-xl bg-emerald-50 border border-emerald-200">
              <div className="flex items-center gap-2 text-emerald-700">
                <Globe2 size={18} />
                <span className="font-medium">已连接到服务器</span>
              </div>
              <p className="text-xs text-emerald-600 mt-1">
                RESTful API 和 WebSocket 均已连接，异常中断后会自动重连
              </p>
            </div>
          )}

          <button
            onClick={onClose}
            className="w-full px-4 py-3 bg-light-bgSecondary border border-light-border rounded-xl text-light-textSecondary hover:bg-light-border transition-colors font-medium"
          >
            取消
          </button>
        </div>
      </div>
    </div>
  );
};

export default Layout;
