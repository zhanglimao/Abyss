import asyncio
import websockets
import json
import time
import traceback
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from task import TaskManager, TaskStatus
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from agents.pt import start_pt,stop_pt

async def run_sync_generator(gen_func, *args):
    """将同步生成器包装成异步生成器，在线程池中执行避免阻塞"""
    iterator = await asyncio.to_thread(lambda: iter(gen_func(*args)))

    while True:
        result = await asyncio.to_thread(lambda: _next_safe(iterator))
        if result is None:
            break
        yield result


def _next_safe(iterator):
    """安全地调用 next()，返回 None 表示迭代结束"""
    try:
        return next(iterator)
    except StopIteration:
        return None

async def process_message(websocket, data):
    # print("weboskcet处理消息:", data)
    """处理单个消息的协程，不阻塞主接收循环"""
    msg_type = data.get("type")
    if msg_type == "ping":
        await websocket.send(json.dumps({
            "type": "pong",
            "timestamp": time.time()
        }, ensure_ascii=False))
        return
    
    task_id = data.get("task_id")

    # 处理 task_stop 类型的消息，停止正在运行的任务
    if msg_type == "task_stop":
        task = TaskManager.get(task_id)
        if task:
            task.set_status(TaskStatus.FAILED)

        await websocket.send(json.dumps({
            "type": "task_stopped",
            "task_id": task_id,
            "status": "stopped"
        }, ensure_ascii=False))

        stop_pt()
        print(f"Task {task_id} stopped by user request")
        return
    
    if not task_id:
        await websocket.send(json.dumps({
            "status": "error",
            "message": "Missing task_id"
        }, ensure_ascii=False))
        return

    content = data.get("content")
    # print("content:",content)
    if not content:
        # print("!!!!!空内容消息!!!!!")
        return

    try:
        async for msg in run_sync_generator(start_pt, content):
            msg['task_id'] = task_id
            ret_msg = json.dumps(msg, ensure_ascii=False)
            await websocket.send(ret_msg)
        complate = {
            "status": "complate",
            "task_id": task_id
        }
        complate_msg = json.dumps(complate, ensure_ascii=False)
        await websocket.send(complate_msg)
    except Exception as e:
        error_msg = {
            "status": "error",
            "message": str(e),
            "task_id": task_id
        }
        await websocket.send(json.dumps(error_msg, ensure_ascii=False))
        traceback.print_exc()


async def handle_message(websocket):
    """接收消息并为每个消息启动独立协程处理，不阻塞"""
    try:
        async for message in websocket:
            print("message:", message)
            try:
                data = json.loads(message)
            except json.JSONDecodeError:
                await websocket.send(json.dumps({
                    "status": "error",
                    "message": "Invalid JSON format"
                }, ensure_ascii=False))
                continue

            asyncio.create_task(process_message(websocket, data))
    except websockets.exceptions.ConnectionClosed:
        print("客户端断开连接")
    except ConnectionResetError:
        print("连接被客户端重置")
    except Exception as e:
        print(f"连接错误：{e}")

async def start_websocket():
    async with websockets.serve(handle_message, "0.0.0.0", 8765):
        await asyncio.Future()  # 运行永久


if __name__ == "__main__":
    asyncio.run(start_websocket())
