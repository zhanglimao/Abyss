import apiClient from './api.js';

/**
 * 关键信息服务 - 13 个核心信息模块
 */
export const infoService = {
  /**
   * 获取任务统计摘要
   */
  async getTaskStats(taskId) {
    return apiClient.get(`/tasks/${taskId}/stats`);
  },

  /**
   * 获取模块详细数据（统一接口）
   * @param {string} taskId - 任务 ID
   * @param {string} type - 模块类型：reconnaissance, services, webApplications, etc.
   */
  async getModuleDetail(taskId, type) {
    return apiClient.get(`/tasks/${taskId}/detail?type=${type}`);
  },
};

/**
 * 系统配置服务
 */
export const configService = {
  /**
   * 获取系统配置
   */
  async getSystemConfig() {
    return apiClient.get('/config');
  },

  /**
   * 获取可用工具列表
   */
  async getAvailableTools() {
    return apiClient.get('/tools');
  },
};
