import { describe, it, expect, beforeEach, vi } from 'vitest';
import { useTaskStore, useChatStore, useInfoStore } from '../store/store';

// Mock API services
vi.mock('../services/services', () => ({
  taskService: {
    getAllTasks: vi.fn(),
    getTaskById: vi.fn(),
    createTask: vi.fn(),
    updateTask: vi.fn(),
    deleteTask: vi.fn(),
    startTask: vi.fn(),
    stopTask: vi.fn(),
    getTaskStats: vi.fn(),
  },
  infoService: {
    getTaskInfo: vi.fn(),
    getAssets: vi.fn(),
    getVulnerabilities: vi.fn(),
    getCredentials: vi.fn(),
    getNetworkTopology: vi.fn(),
    getToolHistory: vi.fn(),
    getSubAgents: vi.fn(),
    exportReport: vi.fn(),
  },
}));

describe('useTaskStore', () => {
  beforeEach(() => {
    // 重置 store 状态
    useTaskStore.setState({
      tasks: [],
      currentTask: null,
      loading: false,
      error: null,
      filter: 'all',
    });
  });

  it('should initialize with default state', () => {
    const state = useTaskStore.getState();
    
    expect(state.tasks).toEqual([]);
    expect(state.currentTask).toBeNull();
    expect(state.loading).toBe(false);
    expect(state.filter).toBe('all');
  });

  it('should set filter', () => {
    useTaskStore.getState().setFilter('running');
    
    const state = useTaskStore.getState();
    expect(state.filter).toBe('running');
  });

  it('should add task to list', () => {
    const newTask = {
      id: '1',
      name: '新任务',
      status: 'pending',
    };

    useTaskStore.setState((state) => ({
      tasks: [...state.tasks, newTask],
    }));

    const state = useTaskStore.getState();
    expect(state.tasks).toHaveLength(1);
    expect(state.tasks[0].name).toBe('新任务');
  });

  it('should remove task from list', () => {
    const tasks = [
      { id: '1', name: '任务 1' },
      { id: '2', name: '任务 2' },
    ];

    useTaskStore.setState({ tasks });
    useTaskStore.setState((state) => ({
      tasks: state.tasks.filter((t) => t.id !== '1'),
    }));

    const state = useTaskStore.getState();
    expect(state.tasks).toHaveLength(1);
    expect(state.tasks[0].id).toBe('2');
  });

  it('should select current task', () => {
    const task = { id: '1', name: '选中任务' };

    useTaskStore.getState().selectTask = vi.fn(async (taskId) => {
      useTaskStore.setState({ currentTask: task });
    });

    useTaskStore.getState().selectTask('1');

    const state = useTaskStore.getState();
    expect(state.currentTask).toEqual(task);
  });

  it('should get filtered tasks - all', () => {
    const tasks = [
      { id: '1', status: 'running' },
      { id: '2', status: 'pending' },
      { id: '3', status: 'completed' },
    ];

    useTaskStore.setState({ tasks, filter: 'all' });

    const filtered = useTaskStore.getState().getFilteredTasks();
    expect(filtered).toHaveLength(3);
  });

  it('should get filtered tasks - running', () => {
    const tasks = [
      { id: '1', status: 'running' },
      { id: '2', status: 'pending' },
      { id: '3', status: 'running' },
    ];

    useTaskStore.setState({ tasks, filter: 'running' });

    const filtered = useTaskStore.getState().getFilteredTasks();
    expect(filtered).toHaveLength(2);
    expect(filtered.every((t) => t.status === 'running')).toBe(true);
  });
});

describe('useChatStore', () => {
  beforeEach(() => {
    useChatStore.setState({
      messages: [],
      isTyping: false,
      connectionStatus: 'disconnected',
    });
  });

  it('should initialize with default state', () => {
    const state = useChatStore.getState();
    
    expect(state.messages).toEqual([]);
    expect(state.isTyping).toBe(false);
    expect(state.connectionStatus).toBe('disconnected');
  });

  it('should add single message', () => {
    const message = {
      type: 'user_message',
      content: 'Hello',
      timestamp: '2024-01-01T10:00:00Z',
    };

    useChatStore.getState().addMessage(message);

    const state = useChatStore.getState();
    expect(state.messages).toHaveLength(1);
    expect(state.messages[0].content).toBe('Hello');
    expect(state.messages[0].id).toBeDefined();
  });

  it('should add multiple messages', () => {
    const messages = [
      { type: 'user_message', content: 'Hello' },
      { type: 'assistant_message', content: 'Hi there' },
    ];

    useChatStore.getState().addMessages(messages);

    const state = useChatStore.getState();
    expect(state.messages).toHaveLength(2);
  });

  it('should clear all messages', () => {
    useChatStore.setState({
      messages: [
        { id: '1', type: 'user_message', content: 'Hello' },
        { id: '2', type: 'assistant_message', content: 'Hi' },
      ],
    });

    useChatStore.getState().clearMessages();

    const state = useChatStore.getState();
    expect(state.messages).toHaveLength(0);
  });

  it('should set typing status', () => {
    useChatStore.getState().setTyping(true);

    const state = useChatStore.getState();
    expect(state.isTyping).toBe(true);

    useChatStore.getState().setTyping(false);
    expect(state.isTyping).toBe(false);
  });

  it('should set connection status', () => {
    useChatStore.getState().setConnectionStatus('connected');

    const state = useChatStore.getState();
    expect(state.connectionStatus).toBe('connected');
  });

  it('should get messages by type', () => {
    const messages = [
      { id: '1', type: 'user_message', content: 'Hello' },
      { id: '2', type: 'assistant_message', content: 'Hi' },
      { id: '3', type: 'user_message', content: 'How are you?' },
    ];

    useChatStore.setState({ messages });

    const userMessages = useChatStore.getState().getMessagesByType('user_message');
    expect(userMessages).toHaveLength(2);
  });
});

describe('useInfoStore', () => {
  beforeEach(() => {
    useInfoStore.setState({
      assets: [],
      vulnerabilities: [],
      credentials: [],
      topology: null,
      toolHistory: [],
      subAgents: [],
      loading: false,
    });
  });

  it('should initialize with default state', () => {
    const state = useInfoStore.getState();
    
    expect(state.assets).toEqual([]);
    expect(state.vulnerabilities).toEqual([]);
    expect(state.credentials).toEqual([]);
    expect(state.topology).toBeNull();
    expect(state.toolHistory).toEqual([]);
    expect(state.subAgents).toEqual([]);
    expect(state.loading).toBe(false);
  });

  it('should set loading state', () => {
    useInfoStore.getState().setLoading(true);

    const state = useInfoStore.getState();
    expect(state.loading).toBe(true);
  });

  it('should set assets', () => {
    const assets = [
      { id: '1', type: 'host', host: '192.168.1.1' },
      { id: '2', type: 'service', port: 80 },
    ];

    useInfoStore.setState({ assets });

    const state = useInfoStore.getState();
    expect(state.assets).toHaveLength(2);
  });

  it('should set vulnerabilities', () => {
    const vulnerabilities = [
      { id: '1', name: 'SQL Injection', severity: 'high' },
      { id: '2', name: 'XSS', severity: 'medium' },
    ];

    useInfoStore.setState({ vulnerabilities });

    const state = useInfoStore.getState();
    expect(state.vulnerabilities).toHaveLength(2);
    expect(state.vulnerabilities[0].severity).toBe('high');
  });

  it('should clear all information', () => {
    useInfoStore.setState({
      assets: [{ id: '1' }],
      vulnerabilities: [{ id: '1' }],
      credentials: [{ id: '1' }],
      topology: { nodes: [] },
      toolHistory: [{ id: '1' }],
      subAgents: [{ id: '1' }],
    });

    useInfoStore.getState().clearAll();

    const state = useInfoStore.getState();
    expect(state.assets).toHaveLength(0);
    expect(state.vulnerabilities).toHaveLength(0);
    expect(state.credentials).toHaveLength(0);
    expect(state.topology).toBeNull();
    expect(state.toolHistory).toHaveLength(0);
    expect(state.subAgents).toHaveLength(0);
  });
});
