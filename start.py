#!/usr/bin/env python3
import asyncio
import threading
import sys
import os

# 设置工作目录
os.chdir(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.getcwd())


def run_websocket():
    """在独立线程中运行 WebSocket 服务器"""
    try:
        from web.websocket import start_websocket
        print("WebSocket 服务器启动在 ws://0.0.0.0:8765")
        asyncio.run(start_websocket())
    except Exception as e:
        print(f"WebSocket 服务器启动失败：{e}")
        print("请确保安装了所有依赖：pip install -r requirements.txt")


def run_restful():
    """在独立线程中运行 RESTful API 服务器"""
    from web.restfull import app
    print("RESTful API 服务器启动在 http://0.0.0.0:80")
    app.run(host='0.0.0.0', port=80, debug=False, use_reloader=False)


def main():
    """主函数：启动两个服务器"""
    print("=" * 50)
    AbyssLogo = """
    █████╗ ██████╗ ██╗   ██╗███████╗███████╗
   ██╔══██╗██╔══██╗╚██╗ ██╔╝██╔════╝██╔════╝
   ███████║██████╔╝ ╚████╔╝ ███████╗███████╗
   ██╔══██║██╔══██╗  ╚██╔╝  ╚════██║╚════██║
   ██║  ██║██████╔╝   ██║   ███████║███████║
   ╚═╝  ╚═╝╚═════╝    ╚═╝   ╚══════╝╚══════╝
    """
    print(AbyssLogo)
    print("=" * 50)
    
    # 启动 WebSocket 服务器线程
    websocket_thread = threading.Thread(target=run_websocket, daemon=True)
    websocket_thread.start()
    
    # 在当前线程启动 RESTful 服务器（阻塞）
    run_restful()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n正在关闭服务器...")
