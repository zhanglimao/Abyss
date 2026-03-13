import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    host: '0.0.0.0',  // 监听所有网络接口，支持容器访问
    proxy: {
      '/api': {
        target: 'http://0.0.0.0:80',
        changeOrigin: true
      },
      '/ws': {
        target: 'ws://0.0.0.0:8765',
        ws: true,
        changeOrigin: true  // 修改 WebSocket 请求的源
      }
    }
  },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: './src/tests/setup.js',
    css: true
  }
})
