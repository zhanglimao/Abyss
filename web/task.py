from typing import Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class TaskStatus:
    """任务状态枚举"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class Conversation:
    """对话对象"""
    content: any
    timestamp: datetime = field(default_factory=datetime.now)


class TaskManager:
    """
    通过 task_id 管理任务状态的对象
    """
    # 类变量，存储所有 task_id 对应的任务管理器实例
    _instances: Dict[str, 'TaskManager'] = {}

    def __init__(self, task_id: str):
        self.task_id = task_id
        self.status: str = TaskStatus.PENDING
        self.conversations: List[Conversation] = []
        self.created_at: datetime = datetime.now()
        self.updated_at: datetime = datetime.now()

    def add_conversation(self, msg:any) -> None:
        """添加一条对话记录"""
        self.conversations.append(Conversation(content=msg))
        self.updated_at = datetime.now()

    def get_conversations(self) -> List[Conversation]:
        """获取对话列表"""
        return self.conversations

    def set_status(self, status: str) -> None:
        """设置任务状态"""
        self.status = status
        self.updated_at = datetime.now()

    @staticmethod
    def get_or_create(task_id: str) -> 'TaskManager':
        """
        静态方法：查询当前是否有这个 task_id 对象，如果没有则创建一个
        """
        if task_id not in TaskManager._instances:
            TaskManager._instances[task_id] = TaskManager(task_id)
        return TaskManager._instances[task_id]

    @staticmethod
    def has_task(task_id: str) -> bool:
        """
        静态方法：检查是否存在指定的 task_id
        """
        return task_id in TaskManager._instances

    @staticmethod
    def get(task_id: str) -> Optional['TaskManager']:
        """
        静态方法：获取指定 task_id 的对象，如果不存在则返回 None
        """
        return TaskManager._instances.get(task_id)

    @staticmethod
    def remove(task_id: str) -> bool:
        """
        静态方法：移除指定的 task_id 对象
        """
        if task_id in TaskManager._instances:
            del TaskManager._instances[task_id]
            return True
        return False

    @staticmethod
    def list_all() -> Dict[str, 'TaskManager']:
        """
        静态方法：列出所有任务
        """
        return TaskManager._instances.copy()


# ============================================
# 使用示例
# ============================================
if __name__ == "__main__":
    # 1. 获取或创建任务（如果不存在则自动创建）
    task = TaskManager.get_or_create("task_123")
    
    # 2. 添加对话记录
    task.add_conversation("你好")
    task.add_conversation("有什么可以帮你？")
    task.add_conversation("帮我查一下天气")
    
    # 3. 设置任务状态
    task.set_status(TaskStatus.RUNNING)
    
    # 4. 查询对话列表
    conversations = task.get_conversations()
    for conv in conversations:
        print(f"[{conv.role}] {conv.content}")
    
    # 5. 检查任务是否存在
    exists = TaskManager.has_task("task_123")  # True
    not_exists = TaskManager.has_task("task_456")  # False
    
    # 6. 获取任务（不存在则返回 None）
    task2 = TaskManager.get("task_123")
    task3 = TaskManager.get("task_456")  # None
    
    # 7. 列出所有任务
    all_tasks = TaskManager.list_all()
    print(f"当前任务数：{len(all_tasks)}")
    
    # 8. 移除任务
    TaskManager.remove("task_123")
