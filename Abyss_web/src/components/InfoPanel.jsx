import React, { useState, useEffect } from 'react';
import {
  Globe,
  Shield,
  Key,
  Network,
  Hammer,
  Bot,
  ChevronDown,
  ChevronRight,
  RefreshCw,
  AlertTriangle,
  CheckCircle,
  ExternalLink,
  Database,
  Lock,
  Unlock,
  ArrowRight,
  FileText,
  Terminal,
  BookOpen,
  Search,
  Layers,
  Wifi,
} from 'lucide-react';
import clsx from 'clsx';
import { useInfoStore, useTaskStore } from '../store/store.js';
import { infoService } from '../services/services.js';
import JsonViewer from './JsonViewer.jsx';

/**
 * 信息面板组件 - 支持 13 个核心信息模块
 */
const InfoPanel = () => {
  const [activeTab, setActiveTab] = useState('overview');
  const [expandedSections, setExpandedSections] = useState({});
  const [selectedItem, setSelectedItem] = useState(null);
  const [selectedModule, setSelectedModule] = useState(null);
  const [moduleDetail, setModuleDetail] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');

  const { globalTask } = useTaskStore();
  const getAllTaskInfo = useInfoStore((state) => state.getAllTaskInfo);
  const setTaskInfo = useInfoStore((state) => state.setTaskInfo);
  const setLoading = useInfoStore((state) => state.setLoading);
  const loading = useInfoStore((state) => state.loading);
  const refreshAll = useInfoStore((state) => state.refreshAll);

  // 从 Store 获取当前任务的所有信息
  const taskInfo = getAllTaskInfo(globalTask?.id) || {};

  // 13 个核心模块数据（从原始数据获取）
  const reconnaissance = taskInfo.reconnaissance || null;
  const services = taskInfo.services || [];
  const webApplications = taskInfo.webApplications || [];
  const vulnerabilities = taskInfo.vulnerabilities || [];
  const credentials = taskInfo.credentials || [];
  const exploitation = taskInfo.exploitation || null;
  const privilegeEscalation = taskInfo.privilegeEscalation || [];
  const lateralMovement = taskInfo.lateralMovement || null;
  const sensitiveData = taskInfo.sensitiveData || [];
  const passwordCracking = taskInfo.passwordCracking || [];
  const wordlists = taskInfo.wordlists || null;
  const toolCommands = taskInfo.toolCommands || [];
  const subAgents = taskInfo.subAgents || [];
  
  // 从 stats 获取统计数据（优先使用）
  const stats = taskInfo.stats || null;

  // 当全局任务变化时，刷新所有信息
  useEffect(() => {
    if (globalTask?.id) {
      console.log('📡 [InfoPanel] 任务切换，使用 RESTful API 查询关键信息，taskId:', globalTask.id);
      refreshAll(globalTask.id);
    }
  }, [globalTask?.id]);

  // 点击模块卡片 - 调用统一的 detail API 查询详细数据
  const handleModuleClick = async (module) => {
    setSelectedModule(module);
    setModuleDetail(null); // 清空之前的详情

    if (!globalTask?.id) {
      console.warn('⚠️ 没有任务 ID，无法查询详情');
      return;
    }

    // 构建统一的 API URL - 使用 /detail 接口，type 参数指定类别
    const apiUrl = localStorage.getItem('apiUrl') || 'http://0.0.0.0:80';
    const type = module.id;
    const fullUrl = `${apiUrl}/api/tasks/${globalTask.id}/detail?type=${type}`;

    console.log('🔍 查询模块详情:', module.label, fullUrl);

    try {
      const response = await fetch(fullUrl, {
        method: 'GET',
        headers: { 'Content-Type': 'application/json' },
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const result = await response.json();
      // 提取 data 字段（如果存在）
      const detailData = result.data !== undefined ? result.data : result;
      setModuleDetail(detailData);
      console.log('✅ 获取详情成功:', detailData);
    } catch (error) {
      console.error('❌ 获取详情失败:', error.message);
      setModuleDetail({ error: error.message, module: module.label });
    }
  };

  // 手动刷新
  const handleRefresh = async () => {
    if (globalTask?.id) {
      console.log('🔄 手动刷新关键信息');
      await refreshAll(globalTask.id);
    }
  };

  // 点击查阅详细信息
  const handleItemClick = (item, type) => {
    setSelectedItem({ ...item, itemType: type });
  };

  // 关闭详细信息
  const handleCloseDetail = () => {
    setSelectedItem(null);
  };

  // 切换展开/收起
  const toggleSection = (section) => {
    setExpandedSections((prev) => ({
      ...prev,
      [section]: !prev[section],
    }));
  };

  // 全部展开
  const expandAll = () => {
    const allExpanded = {};
    modules.forEach(mod => {
      allExpanded[mod.id] = true;
    });
    setExpandedSections(allExpanded);
  };

  // 全部收起
  const collapseAll = () => {
    setExpandedSections({});
  };

  // 严重程度颜色
  const getSeverityColor = (severity) => {
    const colors = {
      critical: 'text-red-600 bg-red-50 border-red-200',
      high: 'text-orange-600 bg-orange-50 border-orange-200',
      medium: 'text-amber-600 bg-amber-50 border-amber-200',
      low: 'text-blue-600 bg-blue-50 border-blue-200',
      info: 'text-gray-500 bg-gray-100 border-gray-200',
    };
    return colors[severity?.toLowerCase()] || colors.info;
  };

  // 状态颜色
  const getStatusColor = (status) => {
    const colors = {
      running: 'text-emerald-600 bg-emerald-50',
      completed: 'text-blue-600 bg-blue-50',
      failed: 'text-red-600 bg-red-50',
      pending: 'text-amber-600 bg-amber-50',
      confirmed: 'text-purple-600 bg-purple-50',
      exploited: 'text-red-600 bg-red-50',
      fixed: 'text-green-600 bg-green-50',
      valid: 'text-emerald-600 bg-emerald-50',
      invalid: 'text-red-600 bg-red-50',
    };
    return colors[status?.toLowerCase()] || 'text-gray-400 bg-gray-100';
  };

  // 模块定义 - 按严重等级排序：红色（最严重）→ 橙色 → 琥珀色
  const modules = [
    { id: 'vulnerabilities', label: '漏洞', icon: Shield, count: getModuleCount('vulnerabilities'), color: 'red', bg: 'bg-red-100', text: 'text-red-700', border: 'border-red-400', alert: true },
    { id: 'exploitation', label: '漏洞利用', icon: Unlock, count: getModuleCount('exploitation'), color: 'red', bg: 'bg-red-100', text: 'text-red-700', border: 'border-red-400', alert: true },
    { id: 'lateralMovement', label: '横向移动', icon: Network, count: getModuleCount('lateralMovement'), color: 'red', bg: 'bg-red-50', text: 'text-red-600', border: 'border-red-300', alert: true },
    { id: 'passwordCracking', label: '密码破解', icon: Hammer, count: getModuleCount('passwordCracking'), color: 'red', bg: 'bg-red-50', text: 'text-red-600', border: 'border-red-300', alert: true },
    { id: 'reconnaissance', label: '信息收集', icon: Search, count: getModuleCount('reconnaissance'), color: 'red', bg: 'bg-red-50', text: 'text-red-600', border: 'border-red-300', alert: true },
    { id: 'privilegeEscalation', label: '权限提升', icon: ArrowRight, count: getModuleCount('privilegeEscalation'), color: 'orange', bg: 'bg-orange-50', text: 'text-orange-600', border: 'border-orange-300', alert: true },
    { id: 'services', label: '端口服务', icon: Wifi, count: getModuleCount('services'), color: 'orange', bg: 'bg-orange-50', text: 'text-orange-600', border: 'border-orange-300', alert: true },
    { id: 'wordlists', label: '密码字典', icon: BookOpen, count: getModuleCount('wordlists'), color: 'orange', bg: 'bg-orange-50', text: 'text-orange-600', border: 'border-orange-300', alert: true },
    { id: 'sensitiveData', label: '敏感数据', icon: Lock, count: getModuleCount('sensitiveData'), color: 'amber', bg: 'bg-amber-50', text: 'text-amber-600', border: 'border-amber-300', alert: true },
    { id: 'webApplications', label: 'Web 应用', icon: Globe, count: getModuleCount('webApplications'), color: 'amber', bg: 'bg-amber-50', text: 'text-amber-600', border: 'border-amber-300', alert: true },
    { id: 'credentials', label: '凭证', icon: Key, count: getModuleCount('credentials'), color: 'amber', bg: 'bg-amber-50', text: 'text-amber-600', border: 'border-amber-300', alert: true },
    { id: 'toolCommands', label: '工具命令', icon: Terminal, count: getModuleCount('toolCommands'), color: 'amber', bg: 'bg-amber-50', text: 'text-amber-600', border: 'border-amber-300', alert: true },
  ];

  // 获取模块统计数量 - 优先使用 stats
  function getModuleCount(type) {
    if (!stats) {
      // 没有 stats 时使用原始数据
      switch (type) {
        case 'reconnaissance':
          return reconnaissance ? ((reconnaissance.domains?.length || 0) + (reconnaissance.ipAddresses?.length || 0) + (reconnaissance.whoisInfo?.length || 0)) : 0;
        case 'services':
          return Array.isArray(services) ? services.length : 0;
        case 'webApplications':
          return Array.isArray(webApplications) ? webApplications.length : 0;
        case 'vulnerabilities':
          return Array.isArray(vulnerabilities) ? vulnerabilities.length : 0;
        case 'credentials':
          return typeof credentials === 'object' ? (credentials.total || 0) : (Array.isArray(credentials) ? credentials.length : 0);
        case 'exploitation':
          return exploitation?.sessions?.length || 0;
        case 'privilegeEscalation':
          return Array.isArray(privilegeEscalation) ? privilegeEscalation.length : 0;
        case 'lateralMovement':
          return (lateralMovement?.pivoting?.length || 0) + (lateralMovement?.movement?.length || 0);
        case 'sensitiveData':
          return Array.isArray(sensitiveData) ? sensitiveData.length : 0;
        case 'passwordCracking':
          return Array.isArray(passwordCracking) ? passwordCracking.length : 0;
        case 'wordlists':
          return wordlists ? ((wordlists.usernames?.length || 0) + (wordlists.passwords?.length || 0)) : 0;
        case 'toolCommands':
          return Array.isArray(toolCommands) ? toolCommands.length : 0;
        default:
          return 0;
      }
    }

    // 使用 stats 统计数据
    switch (type) {
      case 'reconnaissance':
        return (stats.reconnaissance?.domains || 0) + (stats.reconnaissance?.ipAddresses || 0) + (stats.reconnaissance?.whoisInfo || 0);
      case 'services':
        return typeof stats.services === 'number' ? stats.services : 0;
      case 'webApplications':
        return typeof stats.webApplications === 'number' ? stats.webApplications : 0;
      case 'vulnerabilities':
        return stats.vulnerabilities?.total || 0;
      case 'credentials':
        return stats.credentials?.total || 0;
      case 'exploitation':
        return stats.exploitation?.sessions || 0;
      case 'privilegeEscalation':
        return stats.privilegeEscalation?.total || 0;
      case 'lateralMovement':
        return (stats.lateralMovement?.pivoting || 0) + (stats.lateralMovement?.movement || 0);
      case 'sensitiveData':
        return stats.sensitiveData || 0;
      case 'passwordCracking':
        return stats.passwordCracking?.total || 0;
      case 'wordlists':
        return (stats.wordlists?.usernames?.length || 0) + (stats.wordlists?.passwords?.length || 0);
      case 'toolCommands':
        return typeof stats.toolCommands === 'number' ? stats.toolCommands : 0;
      default:
        return 0;
    }
  }

  if (!globalTask) {
    return (
      <div className="flex flex-col h-full bg-white border-l border-light-border">
        <div className="flex items-center justify-center h-full text-light-textMuted">
          <div className="text-center">
            <div className="w-20 h-20 mx-auto mb-4 rounded-2xl bg-gradient-to-br from-primary-100 to-accent-100 flex items-center justify-center animate-float">
              <Globe size={40} className="text-primary-400" />
            </div>
            <p className="text-sm font-medium text-light-text">等待任务启动...</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full bg-white border-l border-light-border">
      {/* 头部 */}
      <div className="p-3 border-b border-light-border bg-gradient-to-r from-primary-50/50 to-accent-50/50">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-base font-semibold gradient-text">关键信息</h2>
            <div className="flex items-center gap-2 mt-1">
              <span className="inline-flex items-center px-2.5 py-1 rounded-lg bg-primary-100 border border-primary-200">
                <span className="text-base font-bold text-primary-700">{modules.filter(m => m.count > 0).length}</span>
                <span className="text-xs font-medium text-primary-600 ml-1">个类别有关键信息</span>
              </span>
              <span className="text-gray-400">·</span>
              <span className="inline-flex items-center px-2.5 py-1 rounded-lg bg-accent-100 border border-accent-200">
                <span className="text-xs font-medium text-accent-600 mr-1">总关键信息</span>
                <span className="text-base font-bold text-accent-700">{modules.reduce((sum, m) => sum + m.count, 0)}</span>
                <span className="text-xs font-medium text-accent-600 ml-1">条</span>
              </span>
            </div>
          </div>
          <button
            onClick={handleRefresh}
            disabled={loading}
            className="p-2 rounded-xl text-light-textMuted hover:text-primary-600 hover:bg-primary-50 transition-all disabled:opacity-50"
            title="刷新"
          >
            <RefreshCw size={14} className={clsx(loading && 'animate-spin')} />
          </button>
        </div>
      </div>

      {/* 内容区域 - 分为上下两部分 */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* 上部：模块网格 - 每行 4 个（警示风格） */}
        <div className="p-2 border-b border-light-border overflow-y-auto bg-gradient-to-b from-red-50/30 to-orange-50/30">
          <div className="grid grid-cols-4 gap-1.5">
            {modules.map((mod) => {
              const Icon = mod.icon;
              const isActive = selectedModule?.id === mod.id;
              const hasData = mod.count > 0;
              return (
                <button
                  key={mod.id}
                  onClick={() => handleModuleClick(mod)}
                  className={clsx(
                    'relative rounded-md p-1.5 border-2 transition-all group',
                    'hover:-translate-y-1',
                    isActive
                      ? `${mod.bg} ${mod.border} ring-2 ring-offset-2 ring-${mod.color}-500 shadow-xl`
                      : hasData
                        ? 'bg-white border-red-300 shadow-md hover:shadow-xl hover:border-red-400'
                        : 'bg-white border-gray-200 shadow-sm hover:shadow-md hover:border-gray-300'
                  )}
                >
                  {/* 警示角标 - 仅当有数据时显示 */}
                  {hasData && (
                    <div className={clsx(
                      'absolute top-1 right-1 w-1.5 h-1.5 rounded-full',
                      mod.color === 'red' ? 'bg-red-500' :
                      mod.color === 'orange' ? 'bg-orange-500' :
                      'bg-amber-500'
                    )} />
                  )}

                  {/* 顶部警示条 - 仅当有数据时显示 */}
                  {hasData && (
                    <div className={clsx(
                      'absolute top-0 left-0 right-0 h-0.5 rounded-t-md',
                      mod.color === 'red' ? 'bg-gradient-to-r from-red-600 via-red-500 to-red-600' :
                      mod.color === 'orange' ? 'bg-gradient-to-r from-orange-600 via-orange-500 to-orange-600' :
                      'bg-gradient-to-r from-amber-600 via-amber-500 to-amber-600'
                    )} />
                  )}

                  {/* 内容区域 - 上下布局，居中对齐 */}
                  <div className="flex flex-col items-center gap-0.5">
                    {/* 图标 */}
                    <div className={clsx(
                      'w-6 h-6 rounded flex items-center justify-center shadow-sm flex-shrink-0',
                      mod.bg, mod.text,
                      'group-hover:scale-105 transition-transform'
                    )}>
                      <Icon size={12} />
                    </div>
                    
                    {/* 标签 - 横向，缩小字体 */}
                    <span className={clsx(
                      'text-[9px] font-bold text-center leading-none whitespace-nowrap',
                      isActive ? 'text-gray-900' : 'text-gray-700'
                    )}>{mod.label}</span>
                    
                    {/* 数量 */}
                    <div className={clsx(
                      'text-2xl font-black leading-none',
                      mod.text
                    )}>{mod.count}</div>
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        {/* 下部：选中模块的详情 - JSON 格式展示 */}
        <div className="flex-1 overflow-y-auto p-3 bg-light-bg">
          {selectedModule ? (
            <div className="space-y-2">
              {/* 详情标题栏 */}
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2.5">
                  <div className={clsx(
                    'w-8 h-8 rounded-xl flex items-center justify-center',
                    selectedModule.bg, selectedModule.text
                  )}>
                    <selectedModule.icon size={16} />
                  </div>
                  <span className="font-semibold text-light-text text-base">{selectedModule.label}</span>
                  <span className={clsx(
                    'text-xs px-2.5 py-1 rounded-full font-medium',
                    selectedModule.bg, selectedModule.text
                  )}>
                    {selectedModule.count} 条记录
                  </span>
                </div>
              </div>

              {/* JSON 格式详情展示 - 使用 JsonViewer 组件 */}
              <div className="bg-white rounded-xl border border-light-border shadow-sm overflow-hidden">
                <div className="flex items-center justify-between px-4 py-2.5 border-b border-light-border bg-light-bgSecondary">
                  <div className="flex items-center gap-2">
                    <FileText size={14} className="text-light-textMuted" />
                    <span className="text-xs font-medium text-light-text">详细数据</span>
                  </div>
                  <div className="flex items-center gap-2">
                    {loading && (
                      <>
                        <RefreshCw size={12} className="animate-spin text-primary-500" />
                        <span className="text-xs text-primary-600 font-medium">刷新中...</span>
                      </>
                    )}
                    {moduleDetail && !loading && (
                      <span className="text-xs text-emerald-600 font-medium">已加载</span>
                    )}
                  </div>
                </div>
                <div className="p-4 overflow-auto max-h-[calc(100vh-400px)]">
                  {moduleDetail ? (
                    <JsonViewer data={moduleDetail} />
                  ) : (
                    <div className="flex flex-col items-center justify-center py-12 text-light-textMuted">
                      <Globe size={48} className="mb-4 opacity-20" />
                      <p className="text-sm">点击上方模块加载详细数据</p>
                    </div>
                  )}
                </div>
              </div>
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center h-full text-light-textMuted">
              <Layers size={48} className="mb-4 opacity-30" />
              <p className="text-sm">点击上方模块查看详情</p>
            </div>
          )}
        </div>
      </div>

      {/* 详情弹窗 */}
      {selectedItem && (
        <DetailModal
          item={selectedItem}
          onClose={handleCloseDetail}
          getSeverityColor={getSeverityColor}
          getStatusColor={getStatusColor}
        />
      )}
    </div>
  );
};

// ==================== 概览标签页 ====================
const OverviewTab = ({
  stats,
  reconnaissance,
  services,
  webApplications,
  vulnerabilities,
  credentials,
  exploitation,
  privilegeEscalation,
  lateralMovement,
  sensitiveData,
  passwordCracking,
  wordlists,
  toolCommands,
  expandedSections,
  toggleSection,
  getSeverityColor,
  getStatusColor,
}) => {
  // 计算统计 - 优先使用 stats 数据，如果不存在则从原始数据计算
  const statCounts = {
    // 从 stats 获取（后端返回的统计数据）
    reconnaissance: stats?.reconnaissance
      ? ((stats.reconnaissance.domains || 0) + (stats.reconnaissance.ipAddresses || 0) + (stats.reconnaissance.whoisInfo || 0))
      // 从原始数据计算（备用）
      : (reconnaissance
          ? ((reconnaissance.domains?.length || 0) + (reconnaissance.ipAddresses?.length || 0) + (reconnaissance.whoisInfo?.length || 0))
          : 0),

    services: (typeof stats?.services === 'number') ? stats.services : (Array.isArray(services) ? services.length : 0),
    webApplications: (typeof stats?.webApplications === 'number') ? stats.webApplications : (Array.isArray(webApplications) ? webApplications.length : 0),

    vulnerabilities: (typeof stats?.vulnerabilities?.total === 'number') ? stats.vulnerabilities.total : (Array.isArray(vulnerabilities) ? vulnerabilities.length : 0),
    credentials: (typeof stats?.credentials?.total === 'number') ? stats.credentials.total : (Array.isArray(credentials) ? credentials.length : 0),

    exploitation: (typeof stats?.exploitation?.sessions === 'number') ? stats.exploitation.sessions : (exploitation?.sessions?.length || 0),
    privilegeEscalation: (typeof stats?.privilegeEscalation?.total === 'number') ? stats.privilegeEscalation.total : (Array.isArray(privilegeEscalation) ? privilegeEscalation.length : 0),
    lateralMovement: ((typeof stats?.lateralMovement?.pivoting === 'number' ? stats.lateralMovement.pivoting : 0) + (typeof stats?.lateralMovement?.movement === 'number' ? stats.lateralMovement.movement : 0)) || ((lateralMovement?.pivoting?.length || 0) + (lateralMovement?.movement?.length || 0)),

    sensitiveData: (typeof stats?.sensitiveData === 'number') ? stats.sensitiveData : (Array.isArray(sensitiveData) ? sensitiveData.length : 0),
    passwordCracking: (typeof stats?.passwordCracking?.total === 'number') ? stats.passwordCracking.total : (Array.isArray(passwordCracking) ? passwordCracking.length : 0),
    wordlists: (stats?.wordlists ? ((stats.wordlists.usernames?.length || 0) + (stats.wordlists.passwords?.length || 0)) : 0) || (wordlists ? ((wordlists.usernames?.length || 0) + (wordlists.passwords?.length || 0)) : 0),
    toolCommands: (typeof stats?.toolCommands === 'number') ? stats.toolCommands : (Array.isArray(toolCommands) ? toolCommands.length : 0),
  };

  // 高危漏洞数量 - 从 stats 获取
  const highRiskCount = stats?.vulnerabilities?.high + stats?.vulnerabilities?.critical || 0;

  // 有效凭证数量 - 从 stats 获取
  const validCredsCount = stats?.credentials?.valid || 0;

  return (
    <div className="space-y-3">
      {/* 统计卡片 - 3x4 网格 */}
      <div className="grid grid-cols-3 gap-2">
        <StatCard label="信息收集" value={statCounts.reconnaissance} icon={Search} color="blue" compact />
        <StatCard label="端口服务" value={statCounts.services} icon={Wifi} color="emerald" compact />
        <StatCard label="Web 应用" value={statCounts.webApplications} icon={Globe} color="cyan" compact />
        <StatCard label="漏洞" value={statCounts.vulnerabilities} icon={Shield} color="red" compact />
        <StatCard label="凭证" value={statCounts.credentials} icon={Key} color="amber" compact />
        <StatCard label="漏洞利用" value={statCounts.exploitation} icon={Unlock} color="purple" compact />
        <StatCard label="权限提升" value={statCounts.privilegeEscalation} icon={ArrowRight} color="pink" compact />
        <StatCard label="横向移动" value={statCounts.lateralMovement} icon={Network} color="indigo" compact />
        <StatCard label="敏感数据" value={statCounts.sensitiveData} icon={Lock} color="orange" compact />
        <StatCard label="密码破解" value={statCounts.passwordCracking} icon={Unlock} color="rose" compact />
        <StatCard label="密码字典" value={statCounts.wordlists} icon={BookOpen} color="teal" compact />
        <StatCard label="工具命令" value={statCounts.toolCommands} icon={Terminal} color="slate" compact />
      </div>

      {/* 高危漏洞 */}
      {highRiskCount > 0 && (
        <div className="bg-white rounded-lg p-2.5 border border-light-border shadow-sm">
          <div
            className="flex items-center justify-between cursor-pointer mb-2"
            onClick={() => toggleSection('highRiskVulns')}
          >
            <div className="flex items-center gap-1.5">
              {expandedSections.highRiskVulns ? (
                <ChevronDown size={14} className="text-light-textMuted" />
              ) : (
                <ChevronRight size={14} className="text-light-textMuted" />
              )}
              <span className="font-semibold text-light-text text-xs">高危漏洞</span>
              <span className="px-1.5 py-0.5 bg-red-100 text-red-600 rounded-full text-xs font-bold">{highRiskCount}</span>
            </div>
          </div>

          {expandedSections.highRiskVulns && (
            <div className="space-y-1.5">
              {vulnerabilities
                .filter((v) => ['critical', 'high'].includes(v.severity?.toLowerCase()))
                .slice(0, 5)
                .map((vuln) => (
                  <div key={vuln.id} className={clsx('p-2 rounded-lg border', getSeverityColor(vuln.severity))}>
                    <div className="flex items-center justify-between mb-0.5">
                      <span className="text-xs font-medium text-light-text truncate flex-1">{vuln.name}</span>
                      <span className="ml-1 px-1.5 py-0.5 rounded text-[10px] font-bold uppercase">{vuln.severity}</span>
                    </div>
                    <div className="text-[10px] text-light-textMuted">{vuln.affected?.target || vuln.target}</div>
                  </div>
                ))}
            </div>
          )}
        </div>
      )}

      {/* 有效凭证 */}
      {validCredsCount > 0 && (
        <div className="bg-white rounded-lg p-2.5 border border-light-border shadow-sm">
          <div className="flex items-center gap-1.5 mb-2">
            <Key size={14} className="text-amber-600" />
            <span className="font-semibold text-light-text text-xs">有效凭证</span>
            <span className="px-1.5 py-0.5 bg-amber-100 text-amber-600 rounded-full text-xs font-bold">{validCredsCount}</span>
          </div>
          <div className="space-y-1">
            {credentials.filter((c) => c.status === 'valid').slice(0, 5).map((cred) => (
              <div key={cred.id} className="p-1.5 rounded bg-amber-50 border border-amber-100">
                <div className="text-xs font-medium text-light-text truncate">{cred.auth?.username || cred.username}</div>
                <div className="text-[10px] text-light-textMuted truncate">{cred.target?.service || cred.type} @ {cred.target?.host || 'N/A'}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 最近工具执行 */}
      {toolCommands.length > 0 && (
        <div className="bg-white rounded-lg p-2.5 border border-light-border shadow-sm">
          <div className="flex items-center gap-1.5 mb-2">
            <Terminal size={14} className="text-slate-600" />
            <span className="font-semibold text-light-text text-xs">最近工具执行</span>
          </div>
          <div className="space-y-1.5">
            {toolCommands.slice(-5).reverse().map((tool, index) => (
              <div key={index} className="p-1.5 rounded bg-light-bgSecondary">
                <div className="flex items-center justify-between mb-0.5">
                  <span className="text-xs font-medium text-light-text truncate flex-1">{tool.tool}</span>
                  <span className="text-[10px] text-light-textMuted ml-2 whitespace-nowrap">{tool.phase}</span>
                </div>
                <div className="text-[10px] text-light-textMuted font-mono truncate">{tool.command}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

// ==================== 信息收集标签页 ====================
const ReconnaissanceTab = ({ reconnaissance, loading, expandedSections, toggleSection }) => {
  if (loading) return <LoadingState />;
  if (!reconnaissance) return <EmptyState message="暂无侦察信息" />;

  return (
    <div className="space-y-2">
      {/* 域名信息 */}
      {reconnaissance.domains?.length > 0 && (
        <div className="bg-white rounded-lg border border-light-border shadow-sm overflow-hidden">
          <div
            className="flex items-center justify-between p-2.5 cursor-pointer hover:bg-light-bgSecondary transition-colors"
            onClick={() => toggleSection('recon-domains')}
          >
            <div className="flex items-center gap-2">
              {expandedSections['recon-domains'] ? (
                <ChevronDown size={14} className="text-light-textMuted" />
              ) : (
                <ChevronRight size={14} className="text-light-textMuted" />
              )}
              <span className="font-semibold text-light-text text-xs">域名信息</span>
              <span className="text-xs text-light-textMuted bg-light-bgSecondary px-1.5 py-0.5 rounded-full">{reconnaissance.domains.length}</span>
            </div>
          </div>
          {expandedSections['recon-domains'] && (
            <div className="p-2.5 pt-0 space-y-1.5">
              {reconnaissance.domains.map((domain, idx) => (
                <div key={idx} className="p-2 rounded-lg bg-light-bgSecondary">
                  <div className="font-medium text-light-text text-xs mb-1">{domain.domain}</div>
                  <div className="text-[10px] text-light-textMuted space-y-0.5">
                    {domain.subdomains?.length > 0 && <div>子域名：{domain.subdomains.slice(0, 5).join(', ')}{domain.subdomains.length > 5 && '...'}</div>}
                    {domain.ips?.length > 0 && <div>IP: {domain.ips.join(', ')}</div>}
                  </div>
                  {domain.notes && <div className="text-[10px] text-light-textMuted mt-1 italic truncate">{domain.notes}</div>}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* IP 地址 */}
      {reconnaissance.ipAddresses?.length > 0 && (
        <div className="bg-white rounded-lg border border-light-border shadow-sm overflow-hidden">
          <div
            className="flex items-center justify-between p-2.5 cursor-pointer hover:bg-light-bgSecondary transition-colors"
            onClick={() => toggleSection('recon-ips')}
          >
            <div className="flex items-center gap-2">
              {expandedSections['recon-ips'] ? (
                <ChevronDown size={14} className="text-light-textMuted" />
              ) : (
                <ChevronRight size={14} className="text-light-textMuted" />
              )}
              <span className="font-semibold text-light-text text-xs">IP 地址</span>
              <span className="text-xs text-light-textMuted bg-light-bgSecondary px-1.5 py-0.5 rounded-full">{reconnaissance.ipAddresses.length}</span>
            </div>
          </div>
          {expandedSections['recon-ips'] && (
            <div className="p-2.5 pt-0 space-y-1.5">
              {reconnaissance.ipAddresses.map((ip, idx) => (
                <div key={idx} className="p-2 rounded-lg bg-light-bgSecondary">
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-medium text-light-text text-xs">{ip.ip}</span>
                    {ip.is_alive && <CheckCircle size={12} className="text-emerald-500" />}
                  </div>
                  <div className="text-[10px] text-light-textMuted space-y-0.5">
                    {ip.hostname && <div>主机名：{ip.hostname}</div>}
                    {ip.os && <div>系统：{ip.os}</div>}
                    {ip.mac && ip.mac !== 'N/A' && <div>MAC: {ip.mac}</div>}
                  </div>
                  {ip.notes && <div className="text-[10px] text-light-textMuted mt-1 italic truncate">{ip.notes}</div>}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* WHOIS 信息 */}
      {reconnaissance.whoisInfo?.length > 0 && (
        <div className="bg-white rounded-lg border border-light-border shadow-sm overflow-hidden">
          <div
            className="flex items-center justify-between p-2.5 cursor-pointer hover:bg-light-bgSecondary transition-colors"
            onClick={() => toggleSection('recon-whois')}
          >
            <div className="flex items-center gap-2">
              {expandedSections['recon-whois'] ? (
                <ChevronDown size={14} className="text-light-textMuted" />
              ) : (
                <ChevronRight size={14} className="text-light-textMuted" />
              )}
              <span className="font-semibold text-light-text text-xs">WHOIS 信息</span>
              <span className="text-xs text-light-textMuted bg-light-bgSecondary px-1.5 py-0.5 rounded-full">{reconnaissance.whoisInfo.length}</span>
            </div>
          </div>
          {expandedSections['recon-whois'] && (
            <div className="p-2.5 pt-0 space-y-1.5">
              {reconnaissance.whoisInfo.map((info, idx) => (
                <div key={idx} className="p-2 rounded-lg bg-light-bgSecondary">
                  <div className="font-medium text-light-text text-xs mb-1">{info.target}</div>
                  <div className="text-[10px] text-light-textMuted space-y-0.5">
                    {info.registrar && <div>注册商：{info.registrar}</div>}
                    {info.nameservers?.length > 0 && <div>DNS: {info.nameservers.slice(0, 3).join(', ')}{info.nameservers.length > 3 && '...'}</div>}
                    {info.created_date && <div>创建：{info.created_date}</div>}
                    {info.expiry_date && <div>过期：{info.expiry_date}</div>}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

// ==================== 端口服务标签页 ====================
const ServicesTab = ({ services, loading, expandedSections, toggleSection }) => {
  if (loading) return <LoadingState />;
  if (services.length === 0) return <EmptyState message="暂无端口服务信息" />;

  // 按 IP 分组
  const groupedByIp = services.reduce((acc, svc) => {
    if (!acc[svc.ip]) acc[svc.ip] = [];
    acc[svc.ip].push(svc);
    return acc;
  }, {});

  return (
    <div className="space-y-3">
      {Object.entries(groupedByIp).map(([ip, ipServices]) => (
        <div key={ip} className="bg-white rounded-xl border border-light-border shadow-sm overflow-hidden">
          <div
            className="flex items-center justify-between p-4 cursor-pointer hover:bg-light-bgSecondary transition-colors"
            onClick={() => toggleSection(`svc-${ip}`)}
          >
            <div className="flex items-center gap-2">
              {expandedSections[`svc-${ip}`] ? (
                <ChevronDown size={16} className="text-light-textMuted" />
              ) : (
                <ChevronRight size={16} className="text-light-textMuted" />
              )}
              <span className="font-semibold text-light-text text-sm">{ip}</span>
              <span className="text-xs text-light-textMuted bg-light-bgSecondary px-2 py-0.5 rounded-full">{ipServices.length} 个端口</span>
            </div>
          </div>
          {expandedSections[`svc-${ip}`] && (
            <div className="p-4 pt-0 space-y-2">
              {ipServices.map((svc, idx) => (
                <div key={idx} className="p-3 rounded-xl bg-light-bgSecondary border border-light-border">
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-medium text-light-text">{svc.port}/{svc.protocol}</span>
                    <span className={clsx('px-2 py-0.5 rounded-lg text-xs font-medium', svc.state === 'open' ? 'bg-emerald-100 text-emerald-700' : 'bg-gray-100 text-gray-700')}>
                      {svc.state}
                    </span>
                  </div>
                  <div className="text-sm text-light-text">{svc.service} {svc.version && `- ${svc.version}`}</div>
                  {svc.notes && <div className="text-xs text-light-textMuted mt-1 italic">{svc.notes}</div>}
                </div>
              ))}
            </div>
          )}
        </div>
      ))}
    </div>
  );
};

// ==================== Web 应用标签页 ====================
const WebApplicationsTab = ({ webApplications, loading, expandedSections, toggleSection }) => {
  if (loading) return <LoadingState />;
  if (webApplications.length === 0) return <EmptyState message="暂无 Web 应用信息" />;

  return (
    <div className="space-y-3">
      {webApplications.map((app, idx) => (
        <div key={idx} className="bg-white rounded-xl border border-light-border shadow-sm overflow-hidden">
          <div className="p-4">
            <div className="flex items-center justify-between mb-2">
              <a href={app.url} target="_blank" rel="noopener noreferrer" className="font-semibold text-primary-600 hover:underline text-sm">
                {app.url}
              </a>
              <div className="flex items-center gap-2">
                <span className={clsx('px-2 py-0.5 rounded-lg text-xs font-medium', app.status_code === 200 ? 'bg-emerald-100 text-emerald-700' : 'bg-amber-100 text-amber-700')}>
                  {app.status_code}
                </span>
                {app.https && <Lock size={14} className="text-emerald-500" />}
              </div>
            </div>
            <div className="text-sm text-light-text mb-2">{app.title}</div>
            <div className="flex flex-wrap gap-1 mb-2">
              {app.technologies?.map((tech, i) => (
                <span key={i} className="px-2 py-0.5 bg-blue-50 text-blue-600 rounded text-xs">{tech}</span>
              ))}
              {app.frameworks?.map((fw, i) => (
                <span key={i} className="px-2 py-0.5 bg-purple-50 text-purple-600 rounded text-xs">{fw}</span>
              ))}
            </div>
            {app.files?.some(f => f.includes('.git') || f.includes('backup') || f.includes('config')) && (
              <div className="flex items-center gap-1 text-xs text-amber-600 bg-amber-50 px-2 py-1 rounded">
                <AlertTriangle size={12} />
                <span>发现敏感文件：{app.files.filter(f => f.includes('.git') || f.includes('backup') || f.includes('config')).join(', ')}</span>
              </div>
            )}
            {app.login_panel && (
              <div className="flex items-center gap-1 text-xs text-purple-600 bg-purple-50 px-2 py-1 rounded mt-2">
                <Key size={12} />
                <span>登录页面</span>
              </div>
            )}
          </div>
        </div>
      ))}
    </div>
  );
};

// ==================== 漏洞标签页 ====================
const VulnerabilitiesTab = ({ vulnerabilities, loading, getSeverityColor }) => {
  if (loading) return <LoadingState />;
  if (vulnerabilities.length === 0) return <EmptyState message="暂无漏洞" />;

  return (
    <div className="space-y-2">
      {vulnerabilities.map((vuln) => (
        <div key={vuln.id} className={clsx('p-4 rounded-xl border shadow-sm', getSeverityColor(vuln.severity))}>
          <div className="flex items-start justify-between mb-2">
            <div className="flex-1">
              <div className="font-semibold text-light-text text-sm mb-1">{vuln.name}</div>
              <div className="text-xs opacity-80 leading-relaxed">{vuln.description}</div>
            </div>
            <span className="ml-2 px-2.5 py-1 rounded-lg text-xs font-bold uppercase">{vuln.severity}</span>
          </div>
          <div className="flex items-center gap-4 text-xs opacity-70 flex-wrap">
            <span>目标：{vuln.affected?.target || vuln.target}</span>
            {vuln.cve && vuln.cve !== 'N/A' && <span>CVE: {vuln.cve}</span>}
            {vuln.cvss && <span>CVSS: {vuln.cvss}</span>}
            <span className={clsx('px-2 py-0.5 rounded-lg', getStatusBg(vuln.status))}>{vuln.status}</span>
          </div>
        </div>
      ))}
    </div>
  );
};

// ==================== 凭证标签页 ====================
const CredentialsTab = ({ credentials, loading, getStatusColor }) => {
  if (loading) return <LoadingState />;
  if (credentials.length === 0) return <EmptyState message="暂无凭证" />;

  return (
    <div className="space-y-3">
      {credentials.map((cred) => (
        <div key={cred.id} className="p-4 bg-white rounded-xl border border-light-border shadow-sm">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <Key size={16} className="text-amber-500" />
              <span className="font-semibold text-light-text text-sm capitalize">{cred.type}</span>
            </div>
            <span className={clsx('px-2.5 py-1 rounded-lg text-xs font-medium', getStatusColor(cred.status))}>
              {cred.status}
            </span>
          </div>
          <div className="space-y-2 text-sm">
            <div className="flex justify-between p-2 rounded-lg bg-light-bgSecondary">
              <span className="text-light-textMuted">用户名:</span>
              <span className="text-light-text font-mono font-medium">{cred.auth?.username || 'N/A'}</span>
            </div>
            {cred.auth?.password && (
              <div className="flex justify-between p-2 rounded-lg bg-light-bgSecondary">
                <span className="text-light-textMuted">密码:</span>
                <span className="text-light-text font-mono font-medium">{cred.auth.password}</span>
              </div>
            )}
            <div className="flex justify-between p-2 rounded-lg bg-light-bgSecondary">
              <span className="text-light-textMuted">目标:</span>
              <span className="text-light-text text-xs">{cred.target?.host || cred.target?.service || 'N/A'}</span>
            </div>
            {cred.source && (
              <div className="p-2 rounded-lg bg-amber-50 border border-amber-200">
                <div className="text-xs text-amber-800">
                  <span className="font-medium">来源:</span> {cred.source}
                </div>
              </div>
            )}
          </div>
        </div>
      ))}
    </div>
  );
};

// ==================== 其他标签页组件 ====================

const ExploitationTab = ({ exploitation, loading }) => {
  if (loading) return <LoadingState />;
  if (!exploitation?.sessions?.length) return <EmptyState message="暂无漏洞利用会话" />;

  return (
    <div className="space-y-3">
      {exploitation.sessions.map((session) => (
        <div key={session.id} className="p-4 bg-white rounded-xl border border-light-border shadow-sm">
          <div className="flex items-center gap-2 mb-3">
            <Unlock size={16} className="text-purple-600" />
            <span className="font-semibold text-light-text text-sm">{session.id}</span>
          </div>
          <div className="space-y-2 text-sm">
            <div className="flex justify-between">
              <span className="text-light-textMuted">目标:</span>
              <span className="text-light-text">{session.target}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-light-textMuted">利用方式:</span>
              <span className="text-light-text">{session.exploit_used?.name}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-light-textMuted">Shell 类型:</span>
              <span className="text-light-text">{session.access?.shell_type}</span>
            </div>
            <div className="p-2 rounded-lg bg-purple-50 border border-purple-200">
              <div className="text-xs text-purple-800 font-mono">{session.exploit_used?.command}</div>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
};

const PrivilegeEscalationTab = ({ privilegeEscalation, loading }) => {
  if (loading) return <LoadingState />;
  if (!privilegeEscalation.length) return <EmptyState message="暂无权限提升记录" />;

  return (
    <div className="space-y-3">
      {privilegeEscalation.map((pe, idx) => (
        <div key={idx} className="p-4 bg-white rounded-xl border border-light-border shadow-sm">
          <div className="flex items-center gap-2 mb-3">
            <ArrowRight size={16} className="text-pink-600" />
            <span className="font-semibold text-light-text text-sm">权限提升</span>
            {pe.success && <CheckCircle size={14} className="text-emerald-500" />}
          </div>
          <div className="space-y-2 text-sm">
            <div className="flex justify-between">
              <span className="text-light-textMuted">主机:</span>
              <span className="text-light-text">{pe.host}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-light-textMuted">提权路径:</span>
              <span className="text-light-text">{pe.initial_user} → {pe.final_user}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-light-textMuted">方法:</span>
              <span className="text-light-text">{pe.method}</span>
            </div>
            <div className="p-2 rounded-lg bg-pink-50 border border-pink-200">
              <div className="text-xs text-pink-800 font-mono truncate">{pe.command}</div>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
};

const LateralMovementTab = ({ lateralMovement, loading }) => {
  if (loading) return <LoadingState />;
  if (!lateralMovement) return <EmptyState message="暂无横向移动信息" />;

  return (
    <div className="space-y-3">
      {lateralMovement.pivoting?.map((pivot, idx) => (
        <div key={idx} className="p-4 bg-white rounded-xl border border-light-border shadow-sm">
          <div className="flex items-center gap-2 mb-3">
            <Network size={16} className="text-indigo-600" />
            <span className="font-semibold text-light-text text-sm">端口转发</span>
          </div>
          <div className="space-y-2 text-sm">
            <div className="flex justify-between">
              <span className="text-light-textMuted">本地端口:</span>
              <span className="text-light-text font-mono">{pivot.local_port}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-light-textMuted">远程目标:</span>
              <span className="text-light-text">{pivot.remote_host}:{pivot.remote_port}</span>
            </div>
            {pivot.accessible_networks?.length > 0 && (
              <div className="p-2 rounded-lg bg-indigo-50 border border-indigo-200">
                <div className="text-xs text-indigo-800">可访问网段：{pivot.accessible_networks.join(', ')}</div>
              </div>
            )}
          </div>
        </div>
      ))}

      {lateralMovement.movement?.map((mv, idx) => (
        <div key={idx} className="p-4 bg-white rounded-xl border border-light-border shadow-sm">
          <div className="flex items-center gap-2 mb-3">
            <ArrowRight size={16} className="text-emerald-600" />
            <span className="font-semibold text-light-text text-sm">横向移动</span>
            {mv.success && <CheckCircle size={14} className="text-emerald-500" />}
          </div>
          <div className="space-y-2 text-sm">
            <div className="flex justify-between">
              <span className="text-light-textMuted">源主机:</span>
              <span className="text-light-text">{mv.source_host}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-light-textMuted">目标主机:</span>
              <span className="text-light-text">{mv.target_host}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-light-textMuted">方法:</span>
              <span className="text-light-text">{mv.method}</span>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
};

const SensitiveDataTab = ({ sensitiveData, loading }) => {
  if (loading) return <LoadingState />;
  if (!sensitiveData.length) return <EmptyState message="暂无敏感数据" />;

  return (
    <div className="space-y-3">
      {sensitiveData.map((data) => (
        <div key={data.id} className="p-4 bg-white rounded-xl border border-light-border shadow-sm">
          <div className="flex items-center gap-2 mb-3">
            <Lock size={16} className="text-orange-600" />
            <span className="font-semibold text-light-text text-sm capitalize">{data.type}</span>
            <span className="ml-auto px-2 py-0.5 bg-orange-100 text-orange-700 rounded-lg text-xs font-medium">{data.significance}</span>
          </div>
          <div className="space-y-2 text-sm">
            <div className="flex justify-between">
              <span className="text-light-textMuted">位置:</span>
              <span className="text-light-text font-mono text-xs">{data.location}</span>
            </div>
            <div className="p-2 rounded-lg bg-orange-50 border border-orange-200">
              <div className="text-xs text-orange-800">{data.content_summary}</div>
            </div>
            {data.files?.length > 0 && (
              <div className="flex flex-wrap gap-1">
                {data.files.map((f, i) => (
                  <span key={i} className="px-2 py-0.5 bg-gray-100 text-gray-700 rounded text-xs font-mono">{f}</span>
                ))}
              </div>
            )}
          </div>
        </div>
      ))}
    </div>
  );
};

const PasswordCrackingTab = ({ passwordCracking, loading }) => {
  if (loading) return <LoadingState />;
  if (!passwordCracking.length) return <EmptyState message="暂无密码破解记录" />;

  return (
    <div className="space-y-3">
      {passwordCracking.map((pc, idx) => (
        <div key={idx} className="p-4 bg-white rounded-xl border border-light-border shadow-sm">
          <div className="flex items-center gap-2 mb-3">
            <Unlock size={16} className="text-rose-600" />
            <span className="font-semibold text-light-text text-sm">密码破解</span>
            <span className="text-xs text-light-textMuted">{pc.hash_type}</span>
          </div>
          {pc.attempts?.map((attempt, i) => (
            <div key={i} className="mb-3 last:mb-0">
              <div className="flex items-center gap-2 mb-2">
                <Terminal size={14} className="text-slate-600" />
                <span className="text-sm font-medium text-light-text">{attempt.tool}</span>
                <span className="text-xs text-light-textMuted">耗时：{attempt.time_spent}</span>
                <span className="text-xs text-emerald-600 font-medium">破解：{attempt.cracked_count}</span>
              </div>
              {attempt.cracked?.map((c, j) => (
                <div key={j} className="p-2 rounded-lg bg-emerald-50 border border-emerald-200 mb-1">
                  <div className="text-xs font-mono">
                    <span className="text-emerald-800">{c.user}</span>:<span className="text-emerald-700 font-medium">{c.password}</span>
                  </div>
                </div>
              ))}
            </div>
          ))}
        </div>
      ))}
    </div>
  );
};

const WordlistsTab = ({ wordlists, loading }) => {
  if (loading) return <LoadingState />;
  if (!wordlists) return <EmptyState message="暂无密码字典" />;

  return (
    <div className="space-y-3">
      <div className="p-4 bg-white rounded-xl border border-light-border shadow-sm">
        <div className="flex items-center gap-2 mb-3">
          <BookOpen size={16} className="text-teal-600" />
          <span className="font-semibold text-light-text text-sm">收集的用户名</span>
          <span className="ml-auto px-2 py-0.5 bg-teal-100 text-teal-700 rounded-lg text-xs font-medium">{wordlists.usernames?.length || 0}</span>
        </div>
        <div className="flex flex-wrap gap-1">
          {wordlists.usernames?.map((u, i) => (
            <span key={i} className="px-2 py-0.5 bg-teal-50 text-teal-700 rounded text-xs font-mono">{u}</span>
          ))}
        </div>
      </div>

      <div className="p-4 bg-white rounded-xl border border-light-border shadow-sm">
        <div className="flex items-center gap-2 mb-3">
          <Lock size={16} className="text-rose-600" />
          <span className="font-semibold text-light-text text-sm">收集的密码</span>
          <span className="ml-auto px-2 py-0.5 bg-rose-100 text-rose-700 rounded-lg text-xs font-medium">{wordlists.passwords?.length || 0}</span>
        </div>
        <div className="flex flex-wrap gap-1">
          {wordlists.passwords?.map((p, i) => (
            <span key={i} className="px-2 py-0.5 bg-rose-50 text-rose-700 rounded text-xs font-mono">{p}</span>
          ))}
        </div>
      </div>

      {wordlists.common_strings?.length > 0 && (
        <div className="p-4 bg-white rounded-xl border border-light-border shadow-sm">
          <div className="flex items-center gap-2 mb-3">
            <FileText size={16} className="text-slate-600" />
            <span className="font-semibold text-light-text text-sm">常用字符串</span>
          </div>
          <div className="flex flex-wrap gap-1">
            {wordlists.common_strings.map((s, i) => (
              <span key={i} className="px-2 py-0.5 bg-gray-100 text-gray-700 rounded text-xs">{s}</span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

const ToolCommandsTab = ({ toolCommands, loading }) => {
  if (loading) return <LoadingState />;
  if (!toolCommands.length) return <EmptyState message="暂无工具命令记录" />;

  return (
    <div className="space-y-2">
      {toolCommands.map((tool, idx) => (
        <div key={idx} className="p-4 bg-white rounded-xl border border-light-border shadow-sm">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2">
              <Terminal size={16} className="text-slate-600" />
              <span className="font-semibold text-light-text text-sm">{tool.tool}</span>
              <span className="px-2 py-0.5 bg-slate-100 text-slate-700 rounded-lg text-xs">{tool.phase}</span>
            </div>
            <span className="text-xs text-light-textMuted">{tool.timestamp}</span>
          </div>
          <div className="p-2 rounded-lg bg-slate-50 border border-slate-200 mb-2">
            <div className="text-xs font-mono text-slate-800 truncate">{tool.command}</div>
          </div>
          {tool.output_file && (
            <div className="text-xs text-light-textMuted">输出：{tool.output_file}</div>
          )}
        </div>
      ))}
    </div>
  );
};

// ==================== 辅助组件 ====================

const StatCard = ({ label, value, icon: Icon, color, compact = false }) => {
  const colors = {
    blue: 'bg-blue-50 text-blue-600',
    emerald: 'bg-emerald-50 text-emerald-600',
    cyan: 'bg-cyan-50 text-cyan-600',
    red: 'bg-red-50 text-red-600',
    amber: 'bg-amber-50 text-amber-600',
    purple: 'bg-purple-50 text-purple-600',
    pink: 'bg-pink-50 text-pink-600',
    indigo: 'bg-indigo-50 text-indigo-600',
    orange: 'bg-orange-50 text-orange-600',
    rose: 'bg-rose-50 text-rose-600',
    teal: 'bg-teal-50 text-teal-600',
    slate: 'bg-slate-50 text-slate-600',
  };

  if (compact) {
    return (
      <div className="bg-white rounded-lg p-2 border border-light-border shadow-sm">
        <div className="flex items-center gap-1.5 mb-1">
          <div className={clsx('w-5 h-5 rounded flex items-center justify-center', colors[color])}>
            <Icon size={10} />
          </div>
          <span className="text-[10px] text-light-textMuted leading-none">{label}</span>
        </div>
        <div className="text-xl font-bold text-light-text">{value}</div>
      </div>
    );
  }

  return (
    <div className="bg-white rounded-xl p-3 border border-light-border shadow-sm">
      <div className="flex items-center gap-2 mb-1">
        <div className={clsx('w-6 h-6 rounded flex items-center justify-center', colors[color])}>
          <Icon size={12} />
        </div>
        <span className="text-xs text-light-textMuted">{label}</span>
      </div>
      <div className="text-2xl font-bold text-light-text">{value}</div>
    </div>
  );
};

const LoadingState = () => (
  <div className="flex items-center justify-center py-12">
    <RefreshCw size={24} className="animate-spin text-primary-500" />
  </div>
);

const EmptyState = ({ message }) => (
  <div className="text-center py-12">
    <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-light-bgSecondary flex items-center justify-center">
      <Globe size={24} className="text-light-textMuted/50" />
    </div>
    <p className="text-light-textMuted text-sm">{message}</p>
  </div>
);

const DetailModal = ({ item, onClose, getSeverityColor, getStatusColor }) => (
  <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4" onClick={onClose}>
    <div className="bg-white rounded-2xl max-w-2xl w-full max-h-[80vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
      <div className="p-6 border-b border-light-border flex items-center justify-between sticky top-0 bg-white">
        <h3 className="text-lg font-semibold text-light-text">{item.itemType || '详细信息'}</h3>
        <button onClick={onClose} className="p-2 hover:bg-light-bgSecondary rounded-lg transition-colors">
          <ChevronRight size={20} className="rotate-90" />
        </button>
      </div>
      <div className="p-6 space-y-4">
        <pre className="text-xs font-mono bg-light-bgSecondary p-4 rounded-lg overflow-x-auto whitespace-pre-wrap">
          {JSON.stringify(item, (key, value) => {
            if (key === 'itemType') return undefined;
            return value;
          }, 2)}
        </pre>
      </div>
    </div>
  </div>
);

const getStatusBg = (status) => {
  const colors = {
    new: 'bg-blue-100 text-blue-700',
    confirmed: 'bg-purple-100 text-purple-700',
    exploited: 'bg-red-100 text-red-700',
    fixed: 'bg-green-100 text-green-700',
  };
  return colors[status?.toLowerCase()] || 'bg-gray-100 text-gray-700';
};

export default InfoPanel;
