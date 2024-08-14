"""
Server runtime context
"""

import asyncio
import logging
import time

from .. import api_models, session_ctx
from . import exceptions, store

logger = logging.getLogger(__name__)

status_location = "/flex/api/v1/extract/tasks/{request_id}"


async def _task_runner(task: api_models.TaskStatusResponse, duration_sec: int):
    logger.info(f"Running task: {task}")
    # make illusion of a progress. devide duration_sec by 10
    for _ in range(duration_sec):
        await asyncio.sleep(1)
        task.update_ts = int(time.time())

    task.state = api_models.TaskState.completed
    task.update_ts = int(time.time())
    logger.info(f"Task completed: {task}")


async def create_task(
    request_id: str, command: api_models.CommandKind, duration_sec: int
) -> api_models.TaskStatusResponse:
    if request_id in store.tasks:
        task = store.tasks[request_id]
        if command != task.command_type:
            # conflict
            logger.warning(
                "request_id conflict",
                request_id=request_id,
            )
            raise exceptions.RequestIdConflict(request_id=task.request_id)
        logger.info(f"Task already exists: {task}")
    else:
        now = int(time.time())
        task = api_models.TaskStatusResponse(
            state=api_models.TaskState.running,
            create_ts=now,
            update_ts=now,
            request_id=request_id,
            owner="ocie",
            command_type=command,
            ref_id=session_ctx.trace_tag.get(),
            error="",
            location=status_location.format(request_id=request_id),
        )
        store.tasks[task.request_id] = task
        asyncio.create_task(_task_runner(task, duration_sec))
    return task


def get_task(request_id: str) -> api_models.TaskStatusResponse:
    return store.tasks.get(request_id, None)


def get_tasks() -> list[api_models.TaskStatusResponse]:
    return list(store.tasks.values())
