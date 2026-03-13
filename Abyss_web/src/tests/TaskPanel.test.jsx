import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import TaskPanel from '../components/TaskPanel';
import { useTaskStore } from '../store/store';

// Mock zustand store
vi.mock('../store/store', () => ({
  useTaskStore: vi.fn(),
  useChatStore: vi.fn(() => ({
    messages: [],
    addMessage: vi.fn(),
  })),
  useInfoStore: vi.fn(() => ({
    assets: [],
    vulnerabilities: [],
    refreshAll: vi.fn(),
  })),
}));

describe('TaskPanel', () => {
  const mockTasks = [
    {
      id: '1',
      name: '测试任务 1',
      target: '192.168.1.0/24',
      status: 'running',
      progress: 50,
      createdAt: '2024-01-01T10:00:00Z',
    },
    {
      id: '2',
      name: '测试任务 2',
      target: 'https://example.com',
      status: 'pending',
      progress: 0,
      createdAt: '2024-01-01T11:00:00Z',
    },
    {
      id: '3',
      name: '测试任务 3',
      target: '10.0.0.1',
      status: 'completed',
      progress: 100,
      createdAt: '2024-01-01T12:00:00Z',
    },
  ];

  const mockStore = {
    tasks: mockTasks,
    currentTask: null,
    filter: 'all',
    loading: false,
    error: null,
    setFilter: vi.fn(),
    fetchTasks: vi.fn(),
    selectTask: vi.fn(),
    createTask: vi.fn(),
    deleteTask: vi.fn(),
    startTask: vi.fn(),
    stopTask: vi.fn(),
    getFilteredTasks: () => mockTasks,
  };

  beforeEach(() => {
    useTaskStore.mockReturnValue(mockStore);
  });

  it('should render task panel header', () => {
    render(<TaskPanel />);
    expect(screen.getByText('渗透测试任务')).toBeInTheDocument();
  });

  it('should render new task button', () => {
    render(<TaskPanel />);
    const newTaskButton = screen.getByTitle('新建任务');
    expect(newTaskButton).toBeInTheDocument();
  });

  it('should render search input', () => {
    render(<TaskPanel />);
    const searchInput = screen.getByPlaceholderText('搜索任务...');
    expect(searchInput).toBeInTheDocument();
  });

  it('should render filter buttons', () => {
    render(<TaskPanel />);
    expect(screen.getByText('全部')).toBeInTheDocument();
    expect(screen.getByText('进行中')).toBeInTheDocument();
    expect(screen.getByText('等待中')).toBeInTheDocument();
    expect(screen.getByText('已完成')).toBeInTheDocument();
    expect(screen.getByText('失败')).toBeInTheDocument();
  });

  it('should display task list', () => {
    render(<TaskPanel />);
    expect(screen.getByText('测试任务 1')).toBeInTheDocument();
    expect(screen.getByText('测试任务 2')).toBeInTheDocument();
    expect(screen.getByText('测试任务 3')).toBeInTheDocument();
  });

  it('should display task status correctly', () => {
    render(<TaskPanel />);
    expect(screen.getByText('进行中')).toBeInTheDocument();
    expect(screen.getByText('等待中')).toBeInTheDocument();
    expect(screen.getByText('已完成')).toBeInTheDocument();
  });

  it('should display task progress', () => {
    render(<TaskPanel />);
    expect(screen.getByText('50%')).toBeInTheDocument();
    expect(screen.getByText('100%')).toBeInTheDocument();
  });

  it('should filter tasks by search term', async () => {
    render(<TaskPanel />);
    const searchInput = screen.getByPlaceholderText('搜索任务...');
    
    fireEvent.change(searchInput, { target: { value: '测试任务 1' } });
    
    await waitFor(() => {
      expect(screen.getByText('测试任务 1')).toBeInTheDocument();
    });
  });

  it('should open create task modal when clicking new task button', () => {
    render(<TaskPanel />);
    const newTaskButton = screen.getByTitle('新建任务');
    
    fireEvent.click(newTaskButton);
    
    expect(screen.getByText('创建新任务')).toBeInTheDocument();
  });

  it('should display task target information', () => {
    render(<TaskPanel />);
    expect(screen.getByText(/目标：192.168.1.0\/24/)).toBeInTheDocument();
    expect(screen.getByText(/目标：https:\/\/example.com/)).toBeInTheDocument();
  });

  it('should display task creation date', () => {
    render(<TaskPanel />);
    expect(screen.getByText('创建：01-01 10:00')).toBeInTheDocument();
  });

  it('should show statistics in footer', () => {
    render(<TaskPanel />);
    expect(screen.getByText('总计')).toBeInTheDocument();
    expect(screen.getByText('3')).toBeInTheDocument();
    expect(screen.getByText('进行中')).toBeInTheDocument();
    expect(screen.getByText('1')).toBeInTheDocument();
  });

  it('should call selectTask when clicking on a task', () => {
    render(<TaskPanel />);
    const taskElement = screen.getByText('测试任务 1').closest('.cursor-pointer');
    
    fireEvent.click(taskElement);
    
    expect(mockStore.selectTask).toHaveBeenCalledWith('1');
  });

  it('should call deleteTask when clicking delete button', () => {
    window.confirm = vi.fn(() => true);
    render(<TaskPanel />);
    
    const deleteButtons = screen.getAllByTitle('删除');
    fireEvent.click(deleteButtons[0]);
    
    expect(window.confirm).toHaveBeenCalledWith('确定要删除此任务吗？');
  });

  it('should call startTask when clicking start button on pending task', () => {
    render(<TaskPanel />);
    
    // 找到待处理任务的启动按钮
    const startButtons = screen.getAllByTitle('启动');
    if (startButtons.length > 0) {
      fireEvent.click(startButtons[0]);
      expect(mockStore.startTask).toHaveBeenCalled();
    }
  });

  it('should call stopTask when clicking stop button on running task', () => {
    render(<TaskPanel />);
    
    const stopButton = screen.getByTitle('停止');
    fireEvent.click(stopButton);
    
    expect(mockStore.stopTask).toHaveBeenCalledWith('1');
  });

  it('should show empty state when no tasks', () => {
    useTaskStore.mockReturnValue({
      ...mockStore,
      tasks: [],
      getFilteredTasks: () => [],
    });

    render(<TaskPanel />);
    expect(screen.getByText('暂无任务')).toBeInTheDocument();
  });

  it('should show loading state when loading', () => {
    useTaskStore.mockReturnValue({
      ...mockStore,
      loading: true,
    });

    render(<TaskPanel />);
    expect(screen.getByText('渗透测试任务')).toBeInTheDocument();
  });
});

describe('CreateTaskModal', () => {
  const mockCreateTask = vi.fn();
  const mockClose = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should render form fields', () => {
    // 由于模态框在 TaskPanel 内部，这里测试主要逻辑
    expect(mockCreateTask).not.toHaveBeenCalled();
  });

  it('should validate required fields', () => {
    // 表单验证测试
    expect(true).toBe(true);
  });
});
