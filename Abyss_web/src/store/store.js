import { create } from 'zustand';
import { infoService } from '../services/services.js';
import { mockInfoService } from '../services/mockData.js';

// 是否使用 Mock 数据模式
// true = 使用 Mock 数据（前端开发/测试）
// false = 使用真实 API（生产环境）
const USE_MOCK = false;

// 选择服务（只使用 infoService，taskService 已废弃）
const infoSvc = USE_MOCK ? mockInfoService : infoService;

/**
 * 安全调用 RESTful API - 统一异常捕获
 * @param {Function} apiCall - API 调用函数
 * @param {any} defaultValue - 失败时的默认返回值
 * @param {string} errorMessage - 错误日志前缀
 */
const safeApiCall = async (apiCall, defaultValue = null, errorMessage = 'API 调用失败') => {
  try {
    return await apiCall();
  } catch (error) {
    console.warn(`⚠️ ${errorMessage}:`, error.message);
    return defaultValue;
  }
};

/**
 * 全局任务管理 Store - 全局只有一个任务
 */
export const useTaskStore = create((set, get) => ({
  // 状态 - 全局单一任务
  globalTask: null,
  loading: false,
  error: null,

  // 动作
  // 初始化或创建全局任务
  initGlobalTask: async (taskData) => {
    set({ loading: true, error: null });
    try {
      // 创建本地任务对象
      const localTask = {
        id: 'global-task-' + Date.now(),
        name: taskData.name || '渗透测试任务',
        target: taskData.target || '未设置',
        description: taskData.description || '',
        status: 'pending',
        progress: 0,
        createdAt: new Date().toISOString(),
      };

      set({ globalTask: localTask, loading: false });
      return localTask;
    } catch (error) {
      set({ error: error.message, loading: false });
      throw error;
    }
  },

  // 获取全局任务（简化版：不再调用后端 API，直接使用本地/已保存的任务）
  fetchGlobalTask: async () => {
    set({ loading: true, error: null });
    try {
      // 如果已有任务，直接返回
      const existingTask = get().globalTask;
      if (existingTask) {
        console.log('✅ 使用已保存的全局任务:', existingTask.id);
        set({ loading: false });
        return existingTask;
      }

      // 否则创建新的本地任务
      const localTask = {
        id: 'global-task-' + Date.now(),
        name: '渗透测试任务',
        target: '未设置',
        description: '',
        status: 'pending',
        progress: 0,
        createdAt: new Date().toISOString(),
      };

      console.log('🆕 创建新的全局任务:', localTask.id);
      set({ globalTask: localTask, loading: false });
      return localTask;
    } catch (error) {
      set({ error: error.message, loading: false });
      throw error;
    }
  },

  // 启动全局任务
  startGlobalTask: async () => {
    const task = get().globalTask;
    if (task) {
      set((state) => ({
        globalTask: { ...state.globalTask, status: 'running' },
      }));
    }
  },

  // 停止全局任务
  stopGlobalTask: async () => {
    const task = get().globalTask;
    if (task) {
      set((state) => ({
        globalTask: { ...state.globalTask, status: 'completed' },
      }));
    }
  },
}));

/**
 * 聊天消息 Store - 按任务 ID 隔离
 */
export const useChatStore = create((set, get) => ({
  // 按任务 ID 存储消息：{ [taskId]: [messages] }
  taskMessages: {},
  currentTaskId: null,
  isTyping: false,
  connectionStatus: 'disconnected',

  // 设置当前任务 ID
  setCurrentTaskId: (taskId) => set({ currentTaskId: taskId }),

  // 获取当前任务的消息
  getCurrentTaskMessages: () => {
    const { taskMessages, currentTaskId } = get();
    return currentTaskId ? (taskMessages[currentTaskId] || []) : [];
  },

  // 添加消息到指定任务
  addMessage: (message, taskId) => {
    if (!taskId) {
      taskId = get().currentTaskId;
    }
    if (!taskId) return;

    set((state) => {
      const taskMessages = state.taskMessages[taskId] || [];
      const messageWithId = message.id ? message : { ...message, id: Date.now().toString() };
      return {
        taskMessages: {
          ...state.taskMessages,
          [taskId]: [...taskMessages, messageWithId],
        },
      };
    });
  },

  // 批量添加消息到指定任务
  addMessages: (messages, taskId) => {
    if (!taskId) {
      taskId = get().currentTaskId;
    }
    if (!taskId) return;

    set((state) => {
      const taskMessages = state.taskMessages[taskId] || [];
      const messagesWithId = messages.map((m, i) =>
        m.id ? m : { ...m, id: `${Date.now()}-${i}` }
      );
      return {
        taskMessages: {
          ...state.taskMessages,
          [taskId]: [...taskMessages, ...messagesWithId],
        },
      };
    });
  },

  // 清空指定任务的消息
  clearMessages: (taskId) => {
    if (!taskId) {
      taskId = get().currentTaskId;
    }
    if (!taskId) return;

    set((state) => ({
      taskMessages: {
        ...state.taskMessages,
        [taskId]: [],
      },
    }));
  },

  // 清空所有任务的消息
  clearAllMessages: () => set({ taskMessages: {} }),

  setTyping: (isTyping) => set({ isTyping }),

  setConnectionStatus: (status) => set({ connectionStatus: status }),

  getMessagesByType: (type) => {
    const { taskMessages, currentTaskId } = get();
    const messages = currentTaskId ? (taskMessages[currentTaskId] || []) : [];
    return messages.filter((m) => m.type === type);
  },
}));

/**
 * 关键信息 Store - 按任务 ID 隔离，支持 13 个核心信息模块
 */
export const useInfoStore = create((set, get) => ({
  // 按任务 ID 存储信息：{ [taskId]: { stats, moduleDetails } }
  taskInfo: {},
  loading: false,

  // 设置任务信息
  setTaskInfo: (taskId, key, value) => {
    set((state) => ({
      taskInfo: {
        ...state.taskInfo,
        [taskId]: {
          ...state.taskInfo[taskId],
          [key]: value,
        },
      },
    }));
  },

  // 获取任务信息
  getTaskInfo: (taskId, key) => {
    const { taskInfo } = get();
    return taskInfo[taskId]?.[key] || null;
  },

  // 获取任务所有信息
  getAllTaskInfo: (taskId) => {
    const { taskInfo } = get();
    return taskInfo[taskId] || null;
  },

  setLoading: (loading) => set({ loading }),

  /**
   * 获取任务统计摘要
   */
  fetchTaskStats: async (taskId) => {
    set({ loading: true });
    const stats = await safeApiCall(
      () => infoSvc.getTaskStats(taskId),
      null,
      '获取任务统计失败'
    );
    console.log('📥 [Store] fetchTaskStats 存储数据，taskId:', taskId, 'stats:', stats);
    set((state) => ({
      taskInfo: {
        ...state.taskInfo,
        [taskId]: {
          ...state.taskInfo[taskId],
          stats,
        },
      },
      loading: false,
    }));
    return stats;
  },

  /**
   * 获取模块详细数据（统一接口）
   * @param {string} taskId - 任务 ID
   * @param {string} type - 模块类型
   */
  fetchModuleDetail: async (taskId, type) => {
    set({ loading: true });
    const detail = await safeApiCall(
      () => infoSvc.getModuleDetail(taskId, type),
      null,
      `获取模块详情失败：${type}`
    );
    console.log(`📥 [Store] fetchModuleDetail 存储数据，taskId: ${taskId}, type: ${type}`, detail);
    set((state) => ({
      taskInfo: {
        ...state.taskInfo,
        [taskId]: {
          ...state.taskInfo[taskId],
          moduleDetails: {
            ...state.taskInfo[taskId]?.moduleDetails,
            [type]: detail,
          },
        },
      },
      loading: false,
    }));
    return detail;
  },

  /**
   * 清空指定任务的信息
   */
  clearTaskInfo: (taskId) => {
    set((state) => {
      const newTaskInfo = { ...state.taskInfo };
      delete newTaskInfo[taskId];
      return { taskInfo: newTaskInfo };
    });
  },

  /**
   * 清空所有任务的信息
   */
  clearAll: () => set({ taskInfo: {} }),

  /**
   * 刷新所有信息
   * 目前只刷新 stats 统计信息
   */
  refreshAll: async (taskId) => {
    console.log('🔄 [Store] refreshAll 开始，taskId:', taskId);
    const { fetchTaskStats } = get();

    try {
      await fetchTaskStats(taskId);
      console.log('✅ [Store] refreshAll 完成，taskId:', taskId);
      console.log('   存储的数据:', get().taskInfo[taskId]);
    } catch (error) {
      console.error('❌ [Store] refreshAll 失败:', error);
    }
  },

  /**
   * 获取任务的统计摘要
   */
  getTaskStats: (taskId) => {
    const { taskInfo } = get();
    const info = taskInfo[taskId];
    if (!info) return null;

    return info.stats || null;
  },
}));
