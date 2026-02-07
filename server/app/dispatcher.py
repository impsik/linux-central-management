import asyncio
from typing import Dict, Optional

class Dispatcher:
    def __init__(self) -> None:
        self._queues: Dict[str, asyncio.Queue] = {}
        self._lock = asyncio.Lock()

    async def ensure_queue(self, agent_id: str) -> asyncio.Queue:
        async with self._lock:
            q = self._queues.get(agent_id)
            if not q:
                q = asyncio.Queue()
                self._queues[agent_id] = q
            return q

    async def push_job(self, agent_id: str, job: dict) -> None:
        q = await self.ensure_queue(agent_id)
        await q.put(job)

    async def pop_job(self, agent_id: str, timeout: int) -> Optional[dict]:
        q = await self.ensure_queue(agent_id)
        try:
            return await asyncio.wait_for(q.get(), timeout=timeout)
        except asyncio.TimeoutError:
            return None

dispatcher = Dispatcher()
