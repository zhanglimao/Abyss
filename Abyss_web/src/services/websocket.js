/**
 * WebSocket 服务 - 用于实时对话管理
 * 后端启动 WebSocket 服务器，前端主动连接，后端主动推送数据
 */

// 是否使用 Mock 模式（连接真实 WebSocket 时设置为 false）
const USE_MOCK = false;

// WebSocket 服务器配置
const WS_CONFIG = {
  // WebSocket 服务器地址
  // 优先使用 localStorage 中配置的地址
  // 如果未配置，使用相对路径（通过 Vite 代理）以支持容器环境
  get baseUrl() {
    const stored = localStorage.getItem('wsUrl');
    if (stored) return stored;
    // 使用相对路径，通过 Vite 代理连接到后端
    // 自动适配：开发环境用代理，生产环境用绝对路径
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    return `${protocol}//${window.location.host}/ws`;
  },
  // 重连配置
  maxReconnectAttempts: 10,
  reconnectDelay: 1000,
  // 心跳配置
  heartbeatInterval: 30000,  // 30 秒发送一次心跳
  heartbeatTimeout: 10000,   // 10 秒超时
};

/**
 * WebSocket 服务 - 用于实时对话管理
 */
class WebSocketService {
  constructor() {
    this.ws = null;
    this.reconnectAttempts = 0;
    this.maxReconnectAttempts = WS_CONFIG.maxReconnectAttempts;
    this.reconnectDelay = WS_CONFIG.reconnectDelay;
    this.messageHandlers = new Set();
    this.statusHandlers = new Set();
    this.isConnected = false;
    this.connectionStatus = 'disconnected'; // 'disconnected' | 'connecting' | 'connected' | 'error'
    this.mockInterval = null;
    this.heartbeatTimer = null;
    this.reconnectTimer = null; // 重连定时器
    this.currentTaskId = null;
    this.currentBaseUrl = WS_CONFIG.baseUrl;
  }

  /**
   * 获取连接状态
   */
  getConnectionStatus() {
    return this.connectionStatus;
  }

  /**
   * 发送 ping 心跳消息
   */
  sendPing() {
    if (this.isConnected && this.ws?.readyState === WebSocket.OPEN) {
      this.send({ type: 'ping', timestamp: new Date().toISOString() });
      console.log('💓 发送心跳 ping');
    }
  }

  /**
   * 连接 WebSocket 服务器
   * @param {string} taskId - 任务 ID
   * @param {string} baseUrl - WebSocket 服务器地址（可选，默认使用配置的地址）
   */
  connect(taskId, baseUrl) {
    if (USE_MOCK) {
      return this.connectMock(taskId);
    }

    // 保存当前配置
    this.currentBaseUrl = baseUrl || WS_CONFIG.baseUrl;

    // 如果已经连接，只切换 task_id，不重新连接
    if (this.isConnected && this.ws?.readyState === WebSocket.OPEN) {
      console.log('✅ WebSocket 已连接，仅切换任务 ID');
      console.log('   原任务 ID:', this.currentTaskId);
      console.log('   新任务 ID:', taskId);

      // 只切换任务 ID，不发送 switch_task 消息
      this.currentTaskId = taskId;
      return Promise.resolve();
    }

    this.currentTaskId = taskId;

    // 构建 WebSocket URL（无需 Token）
    // baseUrl 已经包含 /ws 路径，直接拼接 /chat
    const wsUrl = `${this.currentBaseUrl}/chat?task_id=${taskId}`;

    console.log('🔌 正在连接 WebSocket:', wsUrl);
    console.log('   任务 ID:', taskId);
    console.log('   服务器地址:', this.currentBaseUrl);
    console.log('   Mock 模式:', USE_MOCK);

    // 立即通知 connecting 状态
    this.connectionStatus = 'connecting';
    this.notifyStatusChange('connecting');

    return new Promise((resolve, reject) => {
      try {
        // 如果已有连接，先关闭
        if (this.ws) {
          console.log('🔌 关闭旧连接...');
          this.ws.close();
        }

        this.ws = new WebSocket(wsUrl);

        this.ws.onopen = () => {
          this.isConnected = true;
          this.connectionStatus = 'connected';
          this.reconnectAttempts = 0;
          this.notifyStatusChange('connected');
          console.log('✅ WebSocket 已连接');
          console.log('   URL:', wsUrl);

          // 启动心跳
          this.startHeartbeat();

          resolve();
        };

        this.ws.onmessage = (event) => {
          try {
            const message = JSON.parse(event.data);

            // 处理 pong 响应
            if (message.type === 'pong') {
              console.log('💓 收到 pong 响应，连接正常');
              this.connectionStatus = 'connected';
              this.notifyStatusChange('connected');
              return;
            }

            console.log('📥 收到消息:', message.type, message);
            this.notifyMessageHandlers(message);
          } catch (error) {
            console.error('❌ 解析 WebSocket 消息失败:', error, '原始数据:', event.data);
          }
        };

        this.ws.onclose = (event) => {
          this.isConnected = false;
          this.connectionStatus = 'disconnected';
          this.notifyStatusChange('disconnected');
          console.log('🔌 WebSocket 已关闭');
          console.log('   代码:', event.code);
          console.log('   原因:', event.reason || '无');

          // 停止心跳
          this.stopHeartbeat();

          // 异常中断后自动重连（非正常关闭才重连）
          if (event.code !== 1000) { // 1000 是正常关闭
            this.startReconnect();
          }
        };

        this.ws.onerror = (error) => {
          console.error('❌ WebSocket 错误:', error);
          console.error('   状态:', this.ws?.readyState);
          this.connectionStatus = 'error';
          this.notifyStatusChange('error');

          // 不 reject，让 onclose 处理重连
        };
      } catch (error) {
        console.error('❌ 创建 WebSocket 连接失败:', error);
        reject(error);
      }
    });
  }

  /**
   * 切换任务（不重新连接）
   * @param {string} taskId - 新任务 ID
   */
  switchTask(taskId) {
    console.log('🔄 切换任务');
    console.log('   原任务 ID:', this.currentTaskId);
    console.log('   新任务 ID:', taskId);

    // 只更新 currentTaskId，不发送 switch_task 消息
    this.currentTaskId = taskId;

    return true;
  }

  /**
   * 连接 Mock WebSocket（模拟后端推送）
   */
  connectMock(taskId) {
    return new Promise(async (resolve) => {
      this.isConnected = true;
      this.notifyStatusChange('connected');
      console.log('✅ Mock WebSocket 已连接 ( taskId:', taskId + ')');

      // 使用新的 mock 数据格式进行模拟
      const { getFrontendMessages } = require('../utils/mockWebSocketData.js');

      // 获取解析后的前端消息（等待 Promise 解析）
      const frontendMessages = await getFrontendMessages(taskId);

      console.log('📋 Mock 消息数量:', frontendMessages.length);

      // 模拟后端主动推送消息（都携带 task_id）
      resetMockMessages();
      let messageIndex = 0;

      this.mockInterval = setInterval(() => {
        if (messageIndex < frontendMessages.length) {
          const message = frontendMessages[messageIndex];
          // 确保消息携带 task_id
          const messageWithTaskId = {
            ...message,
            task_id: message.task_id || taskId,
            timestamp: message.timestamp || new Date().toISOString(),
          };
          console.log('📤 推送 Mock 消息:', messageIndex + 1, messageWithTaskId.type, messageWithTaskId.subAgentId ? '(子 Agent)' : '(主 Agent)');
          this.notifyMessageHandlers(messageWithTaskId);
          messageIndex++;
        }
      }, 500); // 每 500ms 推送一条消息

      resolve();
    });
  }

  /**
   * 发送消息
   */
  send(message) {
    if (USE_MOCK) {
      return this.sendMock(message, message.taskId || this.currentTaskId);
    }

    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(message));
      return true;
    }
    console.warn('WebSocket not connected, message not sent');
    return false;
  }

  /**
   * 发送 Mock 消息（模拟）
   */
  sendMock(message, taskId) {
    console.log('Mock send:', message, 'taskId:', taskId);
    // 模拟 AI 回复（携带 task_id）
    setTimeout(() => {
      if (message.type === 'user_message') {
        this.notifyMessageHandlers({
          type: 'assistant_message',
          content: `收到您的消息："${message.content}"。我正在处理这个请求...`,
          task_id: taskId || this.currentTaskId,  // 携带 task_id
          timestamp: new Date().toISOString(),
        });
      }
    }, 1000);
    return true;
  }

  /**
   * 发送用户消息
   * @param {string} content - 消息内容
   * @param {string} taskId - 任务 ID
   */
  sendUserMessage(content, taskId) {
    return this.send({
      type: 'user_message',
      content,
      task_id: taskId,  // 带上任务 ID（下划线命名）
      timestamp: new Date().toISOString(),
    });
  }

  /**
   * 发送控制命令
   * @param {string} command - 命令类型
   * @param {object} params - 命令参数
   * @param {string} taskId - 任务 ID
   */
  sendCommand(command, params = {}, taskId) {
    return this.send({
      type: 'command',
      command,
      params,
      task_id: taskId,  // 带上任务 ID（下划线命名）
      timestamp: new Date().toISOString(),
    });
  }

  /**
   * 发送任务继续/恢复消息（用于页面刷新后恢复任务）
   * @param {string} taskId - 任务 ID
   */
  sendTaskContinue(taskId) {
    return this.send({
      type: 'task_continue',
      task_id: taskId,  // 带上任务 ID（下划线命名）
      timestamp: new Date().toISOString(),
    });
  }

  /**
   * 设置 WebSocket 服务器地址
   * @param {string} baseUrl - WebSocket 服务器地址，例如 'ws://0.0.0.0:8765'
   */
  setBaseUrl(baseUrl) {
    this.currentBaseUrl = baseUrl;
    console.log('📍 WebSocket 服务器地址已设置为:', baseUrl);
  }

  /**
   * 获取当前 WebSocket 服务器地址
   */
  getBaseUrl() {
    return this.currentBaseUrl;
  }

  /**
   * 启动心跳
   */
  startHeartbeat() {
    this.stopHeartbeat(); // 先停止已有的心跳
    
    this.heartbeatTimer = setInterval(() => {
      if (this.isConnected && this.ws?.readyState === WebSocket.OPEN) {
        this.send({ type: 'ping', timestamp: new Date().toISOString() });
        console.log('💓 发送心跳');
      }
    }, WS_CONFIG.heartbeatInterval);
  }

  /**
   * 停止心跳
   */
  stopHeartbeat() {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
  }

  /**
   * 添加消息处理器
   */
  onMessage(handler) {
    this.messageHandlers.add(handler);
    return () => this.messageHandlers.delete(handler);
  }

  /**
   * 添加状态变化处理器
   */
  onStatusChange(handler) {
    this.statusHandlers.add(handler);
    return () => this.statusHandlers.delete(handler);
  }

  /**
   * 通知消息处理器
   */
  notifyMessageHandlers(message) {
    this.messageHandlers.forEach((handler) => {
      try {
        handler(message);
      } catch (error) {
        console.error('Message handler error:', error);
      }
    });
  }

  /**
   * 通知状态变化处理器
   */
  notifyStatusChange(status) {
    console.log('📢 WebSocket 通知状态变化:', status, '处理器数量:', this.statusHandlers.size);
    this.statusHandlers.forEach((handler) => {
      try {
        handler(status, this.isConnected);
      } catch (error) {
        console.error('Status handler error:', error);
      }
    });
  }

  /**
   * 断开连接
   */
  disconnect() {
    // 停止重连
    this.stopReconnect();

    // 停止心跳
    this.stopHeartbeat();

    // 停止 Mock 定时器
    if (this.mockInterval) {
      clearInterval(this.mockInterval);
      this.mockInterval = null;
    }

    if (this.ws) {
      const ws = this.ws;
      this.ws = null;
      ws.close(1000, 'Client disconnect'); // 正常关闭
    }
    this.isConnected = false;
    this.connectionStatus = 'disconnected';
    this.notifyStatusChange('disconnected');
    console.log('🔌 已断开 WebSocket 连接');
  }

  /**
   * 开始重连（指数退避）
   */
  startReconnect() {
    if (this.reconnectTimer) {
      return; // 已经在重连中
    }

    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.error('❌ 重连失败，已达最大尝试次数');
      this.connectionStatus = 'error';
      this.notifyStatusChange('error');
      return;
    }

    // 指数退避：1s, 2s, 4s, 8s, 16s... 最大 30s
    const delay = Math.min(this.reconnectDelay * Math.pow(2, this.reconnectAttempts), 30000);
    this.reconnectAttempts++;

    console.log(`🔄 准备重连... (${this.reconnectAttempts}/${this.maxReconnectAttempts}) ${delay}ms 后`);
    this.connectionStatus = 'reconnecting';
    this.notifyStatusChange('reconnecting');

    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      console.log('🔄 开始重连 WebSocket');
      this.connect(this.currentTaskId, this.currentBaseUrl);
    }, delay);
  }

  /**
   * 停止重连
   */
  stopReconnect() {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    this.reconnectAttempts = 0;
  }

  /**
   * 获取连接状态
   */
  getConnectionStatus() {
    if (!this.ws && !this.mockInterval) return 'closed';
    if (!this.ws) return 'connecting';
    return this.isConnected ? 'connected' : 'disconnected';
  }

  /**
   * 获取详细连接信息
   */
  getConnectionInfo() {
    return {
      isConnected: this.isConnected,
      taskId: this.currentTaskId,
      baseUrl: this.currentBaseUrl,
      readyState: this.ws?.readyState,
      reconnectAttempts: this.reconnectAttempts,
      isMock: USE_MOCK
    };
  }
}

// 单例模式
const webSocketService = new WebSocketService();
export default webSocketService;
