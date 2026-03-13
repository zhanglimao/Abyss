import React, { useEffect } from 'react';
import Layout from './components/Layout.jsx';
import { useTaskStore } from './store/store.js';

/**
 * 应用入口组件 - 全局单一任务架构
 */
const App = () => {
  const { fetchGlobalTask } = useTaskStore();

  // 初始化加载全局任务
  useEffect(() => {
    fetchGlobalTask();
  }, []);

  return (
    <div className="app">
      <Layout />
    </div>
  );
};

export default App;
