import '@testing-library/jest-dom';
import { cleanup } from '@testing-library/react';
import { afterEach, vi } from 'vitest';

// 每个测试后清理
afterEach(() => {
  cleanup();
});

// Mock window.location
Object.defineProperty(window, 'location', {
  configurable: true,
  value: {
    ...window.location,
    host: '0.0.0.0:80',
    protocol: 'http:',
  },
});

// Mock WebSocket
global.WebSocket = vi.fn().mockImplementation(() => ({
  addEventListener: vi.fn(),
  removeEventListener: vi.fn(),
  send: vi.fn(),
  close: vi.fn(),
  readyState: 1,
  OPEN: 1,
  CONNECTING: 0,
  CLOSING: 2,
  CLOSED: 3,
}));
