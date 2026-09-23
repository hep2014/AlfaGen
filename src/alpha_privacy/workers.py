"""Bounded offload: cancellation must not admit work while a worker still runs."""
import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context


class WorkerBusy(Exception):
    pass


class WorkerPool:
    def __init__(self, capacity=2, *, thread_name_prefix="privacy-large"):
        if not 1 <= capacity <= 32:
            raise ValueError("invalid_worker_capacity")
        self.capacity = capacity
        self.active = 0
        self.lock = threading.Lock()
        self.slots = asyncio.Queue(maxsize=capacity)
        for _ in range(capacity):
            self.slots.put_nowait(None)
        self.executor = ThreadPoolExecutor(max_workers=capacity,
                                            thread_name_prefix=thread_name_prefix)

    def inflight(self):
        with self.lock:
            return self.active

    async def run(self, function, *args, wait=False):
        context = copy_context()
        if wait:
            await self.slots.get()
        else:
            try:
                self.slots.get_nowait()
            except asyncio.QueueEmpty:
                raise WorkerBusy from None
        with self.lock:
            self.active += 1
        try:
            future = self.executor.submit(self._run, context, function, args)
        except BaseException:
            with self.lock:
                self.active -= 1
            self.slots.put_nowait(None)
            raise
        # Shield prevents cancellation of the HTTP task from cancelling a queued
        # job before its finally block can release the reserved slot.
        wrapped = asyncio.wrap_future(future)
        wrapped.add_done_callback(self._observe_completion)
        return await asyncio.shield(wrapped)

    def _observe_completion(self, future):
        self.slots.put_nowait(None)
        if not future.cancelled():
            # A cancelled caller may no longer await a worker exception.
            future.exception()

    def _run(self, context, function, args):
        try:
            return context.run(function, *args)
        finally:
            with self.lock:
                self.active -= 1

    def close(self):
        # Already admitted jobs retain their slots and finish even during shutdown.
        self.executor.shutdown(wait=False, cancel_futures=False)
