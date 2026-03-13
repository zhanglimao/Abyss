import axios from 'axios';

const apiClient = axios.create({
  baseURL: '/api',
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 30000,
});

// 请求拦截器
apiClient.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    console.log('📤 [API] 请求:', config.method?.toUpperCase(), config.url);
    return config;
  },
  (error) => Promise.reject(error)
);

// 响应拦截器
apiClient.interceptors.response.use(
  (response) => {
    const responseData = response.data;
    const requestUrl = response.config.url;
    
    console.log('📥 [API] 响应 URL:', requestUrl);
    console.log('📥 [API] 原始响应数据:', responseData);
    console.log('📥 [API] responseData 类型:', typeof responseData, Array.isArray(responseData) ? '(Array)' : '(Object)');
    console.log('📥 [API] responseData 是否有 data 字段:', responseData?.data !== undefined);
    console.log('📥 [API] responseData 是否有 success 字段:', responseData?.success !== undefined);
    
    // 如果响应包含 { success: true, data: {...} } 格式，提取 data 字段
    if (responseData && typeof responseData === 'object') {
      // 情况 1: { success: true, data: {...} } - 标准格式
      if (responseData.success !== undefined && responseData.data !== undefined) {
        console.log('📡 [API] ✅ 情况 1: 提取 data 字段，结果:', responseData.data);
        return responseData.data;
      }
      // 情况 2: { data: {...} } - 没有 success 字段
      if (responseData.data !== undefined && typeof responseData.data === 'object') {
        console.log('📡 [API] ✅ 情况 2: 直接返回 data，结果:', responseData.data);
        return responseData.data;
      }
      // 情况 3: 直接是数组或对象（没有 data 字段）
      console.log('📡 [API] ✅ 情况 3: 返回原始数据，结果:', responseData);
      return responseData;
    }
    console.log('📡 [API] ⚠️ 返回原始数据:', responseData);
    return responseData;
  },
  (error) => {
    console.error('❌ [API] 错误:', error.response?.data || error.message);
    return Promise.reject(error);
  }
);

export default apiClient;
