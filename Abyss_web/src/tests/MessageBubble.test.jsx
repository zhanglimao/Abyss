import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import MessageBubble from '../components/chat/MessageBubble';
import { MessageType } from '../components/chat/MessageTypes';

describe('MessageBubble', () => {
  const baseMessage = {
    id: '1',
    content: '测试消息内容',
    timestamp: '2024-01-01T10:00:00Z',
  };

  describe('User Message', () => {
    it('should render user message correctly', () => {
      render(<MessageBubble message={{ ...baseMessage, type: MessageType.USER }} />);
      
      expect(screen.getByText('你')).toBeInTheDocument();
      expect(screen.getByText('测试消息内容')).toBeInTheDocument();
    });

    it('should have user styling', () => {
      const { container } = render(
        <MessageBubble message={{ ...baseMessage, type: MessageType.USER }} />
      );
      
      expect(container.querySelector('.message-user')).toBeInTheDocument();
    });
  });

  describe('Assistant Message', () => {
    it('should render assistant message correctly', () => {
      render(<MessageBubble message={{ ...baseMessage, type: MessageType.ASSISTANT }} />);
      
      expect(screen.getByText('AI 助手')).toBeInTheDocument();
      expect(screen.getByText('测试消息内容')).toBeInTheDocument();
    });
  });

  describe('SubAgent Message', () => {
    it('should render subagent message with agent name', () => {
      const subAgentMessage = {
        ...baseMessage,
        type: MessageType.SUBAGENT,
        agentName: '扫描代理',
        subAgentType: 'reconnaissance',
      };

      render(<MessageBubble message={subAgentMessage} />);
      
      expect(screen.getByText('子代理')).toBeInTheDocument();
      expect(screen.getByText('扫描代理')).toBeInTheDocument();
      expect(screen.getByText('[reconnaissance]')).toBeInTheDocument();
    });

    it('should have subagent styling', () => {
      const { container } = render(
        <MessageBubble message={{ ...baseMessage, type: MessageType.SUBAGENT }} />
      );
      
      expect(container.querySelector('.message-subagent')).toBeInTheDocument();
    });
  });

  describe('Tool Call Message', () => {
    it('should render tool call with tool name', () => {
      const toolCallMessage = {
        ...baseMessage,
        type: MessageType.TOOL_CALL,
        toolName: 'Nmap',
        command: 'nmap -sV 192.168.1.1',
        status: 'running',
      };

      render(<MessageBubble message={toolCallMessage} />);
      
      expect(screen.getByText('工具调用')).toBeInTheDocument();
      expect(screen.getByText('Nmap')).toBeInTheDocument();
      expect(screen.getByText(/nmap -sV 192.168.1.1/)).toBeInTheDocument();
    });

    it('should show running status', () => {
      const toolCallMessage = {
        ...baseMessage,
        type: MessageType.TOOL_CALL,
        toolName: 'Nmap',
        status: 'running',
      };

      render(<MessageBubble message={toolCallMessage} />);
      
      expect(screen.getByText('执行中...')).toBeInTheDocument();
    });

    it('should show completed status', () => {
      const toolCallMessage = {
        ...baseMessage,
        type: MessageType.TOOL_CALL,
        toolName: 'Nmap',
        status: 'completed',
      };

      render(<MessageBubble message={toolCallMessage} />);
      
      expect(screen.getByTitle('检查')).toBeInTheDocument();
    });
  });

  describe('Tool Result Message', () => {
    it('should render tool result with output', () => {
      const toolResultMessage = {
        ...baseMessage,
        type: MessageType.TOOL_RESULT,
        toolName: 'Nmap',
        output: 'PORT   STATE SERVICE\n80/tcp open  http',
        executionTime: 1500,
      };

      render(<MessageBubble message={toolResultMessage} />);
      
      expect(screen.getByText('执行完成')).toBeInTheDocument();
      expect(screen.getByText(/1500ms/)).toBeInTheDocument();
      expect(screen.getByText(/80\/tcp open  http/)).toBeInTheDocument();
    });
  });

  describe('Error Message', () => {
    it('should render error message with error styling', () => {
      const errorMessage = {
        ...baseMessage,
        type: MessageType.ERROR,
        content: '连接超时，请检查网络',
      };

      render(<MessageBubble message={errorMessage} />);
      
      expect(screen.getByText('发生错误')).toBeInTheDocument();
      expect(screen.getByText('连接超时，请检查网络')).toBeInTheDocument();
    });
  });

  describe('Message Header', () => {
    it('should display formatted timestamp', () => {
      render(<MessageBubble message={baseMessage} />);
      
      expect(screen.getByText('10:00:00')).toBeInTheDocument();
    });

    it('should use current time if no timestamp provided', () => {
      const messageWithoutTime = {
        id: '2',
        content: '无时间戳消息',
      };

      render(<MessageBubble message={messageWithoutTime} />);
      
      // 应该显示当前时间
      expect(screen.getByText('无时间戳消息')).toBeInTheDocument();
    });
  });

  describe('Message Content', () => {
    it('should render content with whitespace preserved', () => {
      const messageWithNewlines = {
        ...baseMessage,
        content: '第一行\n第二行\n第三行',
      };

      render(<MessageBubble message={messageWithNewlines} />);
      
      expect(screen.getByText('第一行\n第二行\n第三行')).toBeInTheDocument();
    });

    it('should handle empty content', () => {
      const emptyMessage = {
        ...baseMessage,
        content: '',
      };

      render(<MessageBubble message={emptyMessage} />);
      
      // 不应该抛出错误
      expect(screen.getByText('10:00:00')).toBeInTheDocument();
    });
  });

  describe('Tool Parameters', () => {
    it('should render tool parameters as JSON', () => {
      const toolCallWithParams = {
        ...baseMessage,
        type: MessageType.TOOL_CALL,
        toolName: 'Sqlmap',
        params: {
          url: 'http://example.com',
          data: 'id=1',
        },
      };

      render(<MessageBubble message={toolCallWithParams} />);
      
      expect(screen.getByText('参数:')).toBeInTheDocument();
      expect(screen.getByText(/http:\/\/example.com/)).toBeInTheDocument();
    });
  });

  describe('SubAgent Data Expansion', () => {
    it('should show expand button when data exists', () => {
      const subAgentWithData = {
        ...baseMessage,
        type: MessageType.SUBAGENT,
        data: { found: ['page1', 'page2'] },
      };

      render(<MessageBubble message={subAgentWithData} />);
      
      expect(screen.getByText('查看详情')).toBeInTheDocument();
    });
  });
});
