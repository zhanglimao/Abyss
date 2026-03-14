import React from 'react';
import { Clock, XCircle, Loader } from 'lucide-react';
import clsx from 'clsx';

/**
 * 加载提示组件
 * 显示在输入框上方，展示当前任务状态
 */
const LoadingIndicator = ({ status, onCancel }) => {
  // status: 'loading' | 'cancelled' | 'idle'
  
  if (status === 'idle') {
    return null;
  }

  if (status === 'cancelled') {
    return (
      <div className="mx-5 mb-3">
        <div className="bg-red-50 border border-red-200 rounded-xl px-4 py-3 flex items-center gap-3">
          <XCircle size={18} className="text-red-500 flex-shrink-0" />
          <span className="text-sm text-red-700 font-medium">任务取消</span>
        </div>
      </div>
    );
  }

  return (
    <div className="mx-5 mb-3">
      <div className="bg-gradient-to-r from-blue-50 to-blue-100/50 border border-blue-200 rounded-xl px-4 py-3 flex items-center gap-3">
        <Loader size={18} className="text-blue-500 animate-spin flex-shrink-0" />
        <span className="text-sm text-blue-700 font-medium">正在处理中...</span>
        <div className="ml-auto flex items-center gap-2">
          <span className="text-xs text-blue-600 bg-blue-100 px-2 py-1 rounded">AI 助手中</span>
          <button
            onClick={onCancel}
            className="text-xs text-red-600 hover:text-red-700 bg-red-50 hover:bg-red-100 px-2 py-1 rounded transition-colors font-medium"
          >
            取消
          </button>
        </div>
      </div>
    </div>
  );
};

export default LoadingIndicator;
