import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import webSocketService from '../services/websocket';

describe('WebSocketService', () => {
  beforeEach(() => {
    // 重置服务状态
    webSocketService.disconnect();
    webSocketService.reconnectAttempts = 0;
    vi.clearAllMocks();
  });

  afterEach(() => {
    webSocketService.disconnect();
  });

  describe('connect', () => {
    it('should create WebSocket connection with correct URL', async () => {
      const mockWs = {
        addEventListener: vi.fn((event, handler) => {
          if (event === 'open') handler();
        }),
        readyState: 1,
      };

      const originalWebSocket = global.WebSocket;
      global.WebSocket = vi.fn(() => mockWs);

      await webSocketService.connect('test-task-123');

      expect(global.WebSocket).toHaveBeenCalled();
      const wsUrl = global.WebSocket.mock.calls[0][0];
      expect(wsUrl).toContain('ws://0.0.0.0:8765/ws/chat');
      expect(wsUrl).toContain('taskId=test-task-123');

      global.WebSocket = originalWebSocket;
    });

    it('should set isConnected to true on successful connection', async () => {
      const mockWs = {
        addEventListener: vi.fn((event, handler) => {
          if (event === 'open') handler();
        }),
        readyState: 1,
      };

      const originalWebSocket = global.WebSocket;
      global.WebSocket = vi.fn(() => mockWs);

      await webSocketService.connect('test-task-123');

      expect(webSocketService.isConnected).toBe(true);

      global.WebSocket = originalWebSocket;
    });

    it('should handle connection error', async () => {
      const mockWs = {
        addEventListener: vi.fn((event, handler) => {
          if (event === 'error') handler(new Error('Connection failed'));
        }),
        readyState: 3,
      };

      const originalWebSocket = global.WebSocket;
      global.WebSocket = vi.fn(() => mockWs);

      await expect(webSocketService.connect('test-task-123')).rejects.toThrow();

      global.WebSocket = originalWebSocket;
    });
  });

  describe('send', () => {
    it('should send message when connected', async () => {
      const mockSend = vi.fn();
      const mockWs = {
        addEventListener: vi.fn((event, handler) => {
          if (event === 'open') handler();
        }),
        send: mockSend,
        readyState: 1,
      };

      const originalWebSocket = global.WebSocket;
      global.WebSocket = vi.fn(() => mockWs);

      await webSocketService.connect('test-task-123');
      const result = webSocketService.send({ type: 'test', content: 'hello' });

      expect(result).toBe(true);
      expect(mockSend).toHaveBeenCalled();

      global.WebSocket = originalWebSocket;
    });

    it('should return false when not connected', () => {
      const result = webSocketService.send({ type: 'test', content: 'hello' });
      expect(result).toBe(false);
    });
  });

  describe('sendUserMessage', () => {
    it('should send user message with correct format', async () => {
      const mockSend = vi.fn();
      const mockWs = {
        addEventListener: vi.fn((event, handler) => {
          if (event === 'open') handler();
        }),
        send: mockSend,
        readyState: 1,
      };

      const originalWebSocket = global.WebSocket;
      global.WebSocket = vi.fn(() => mockWs);

      await webSocketService.connect('test-task-123');
      webSocketService.sendUserMessage('Hello, AI!', 'test-task-123');

      const sentData = JSON.parse(mockSend.mock.calls[0][0]);
      expect(sentData.type).toBe('user_message');
      expect(sentData.content).toBe('Hello, AI!');
      expect(sentData.taskId).toBe('test-task-123');
      expect(sentData.timestamp).toBeDefined();

      global.WebSocket = originalWebSocket;
    });
  });

  describe('onMessage', () => {
    it('should register and call message handlers', async () => {
      const mockHandler = vi.fn();
      const mockWs = {
        addEventListener: vi.fn((event, handler) => {
          if (event === 'open') handler();
        }),
        readyState: 1,
      };

      const originalWebSocket = global.WebSocket;
      global.WebSocket = vi.fn(() => mockWs);

      await webSocketService.connect('test-task-123');
      webSocketService.onMessage(mockHandler);

      // 模拟接收消息
      const message = { type: 'assistant_message', content: 'Hello' };
      webSocketService.notifyMessageHandlers(message);

      expect(mockHandler).toHaveBeenCalledWith(message);

      global.WebSocket = originalWebSocket;
    });

    it('should return unsubscribe function', () => {
      const mockHandler = vi.fn();
      const unsubscribe = webSocketService.onMessage(mockHandler);

      expect(typeof unsubscribe).toBe('function');
    });
  });

  describe('onStatusChange', () => {
    it('should register and call status handlers', () => {
      const mockHandler = vi.fn();
      webSocketService.onStatusChange(mockHandler);

      webSocketService.notifyStatusChange('connected');

      expect(mockHandler).toHaveBeenCalledWith('connected', false);
    });
  });

  describe('disconnect', () => {
    it('should close WebSocket connection', async () => {
      const mockClose = vi.fn();
      const mockWs = {
        addEventListener: vi.fn((event, handler) => {
          if (event === 'open') handler();
        }),
        close: mockClose,
        readyState: 1,
      };

      const originalWebSocket = global.WebSocket;
      global.WebSocket = vi.fn(() => mockWs);

      await webSocketService.connect('test-task-123');
      webSocketService.disconnect();

      expect(mockClose).toHaveBeenCalled();
      expect(webSocketService.isConnected).toBe(false);

      global.WebSocket = originalWebSocket;
    });
  });

  describe('getConnectionStatus', () => {
    it('should return correct status for each readyState', () => {
      // Closed
      webSocketService.ws = { readyState: 3 };
      expect(webSocketService.getConnectionStatus()).toBe('closed');

      // Connecting
      webSocketService.ws = { readyState: 0 };
      expect(webSocketService.getConnectionStatus()).toBe('connecting');

      // Open
      webSocketService.ws = { readyState: 1 };
      expect(webSocketService.getConnectionStatus()).toBe('connected');

      // Closing
      webSocketService.ws = { readyState: 2 };
      expect(webSocketService.getConnectionStatus()).toBe('closing');

      // No WebSocket
      webSocketService.ws = null;
      expect(webSocketService.getConnectionStatus()).toBe('closed');
    });
  });
});
