/**
 * 任务 ID 生成工具
 * 生成唯一且固定的任务 ID
 */

/**
 * 生成 UUID v4
 * @returns {string} UUID 字符串
 */
export const generateUUID = () => {
  // 浏览器环境
  if (typeof crypto !== 'undefined' && crypto.randomUUID) {
    return crypto.randomUUID();
  }
  
  // 备用方案
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = Math.random() * 16 | 0;
    const v = c === 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
};

/**
 * 生成基于时间戳的唯一 ID
 * @returns {string} 唯一 ID
 */
export const generateTimestampId = () => {
  const timestamp = Date.now();
  const random = Math.random().toString(36).substring(2, 7); // 5 位随机字符
  return `task-${timestamp}-${random}`;
};

/**
 * 生成简短的任务 ID（适合展示）
 * @returns {string} 简短 ID
 */
export const generateShortId = () => {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let result = '';
  for (let i = 0; i < 8; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return `TASK-${result}`;
};

/**
 * 验证任务 ID 格式
 * @param {string} id - 待验证的 ID
 * @returns {boolean} 是否有效
 */
export const isValidTaskId = (id) => {
  if (!id || typeof id !== 'string') return false;
  
  // 支持多种格式
  const patterns = [
    /^task-\d+$/,  // task-001, task-123456
    /^task-\d+-[a-z0-9]+$/,  // task-1709876543210-abc12
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,  // UUID
    /^TASK-[A-Z0-9]{8}$/,  // TASK-ABCD1234
  ];
  
  return patterns.some(pattern => pattern.test(id));
};

/**
 * 格式化任务 ID 用于显示
 * @param {string} id - 任务 ID
 * @returns {string} 格式化后的 ID
 */
export const formatTaskId = (id) => {
  if (!id) return '未知任务';
  
  // UUID 格式，截取前 8 位
  if (id.includes('-') && id.length > 20) {
    return id.substring(0, 8);
  }
  
  // 其他格式直接返回
  return id;
};
