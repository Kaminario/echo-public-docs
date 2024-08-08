import logging

import fastapi

from .. import api_models, server_error_responses
from ..server_engine import tasks_manager

logger = logging.getLogger(__name__)
router = fastapi.APIRouter()


@router.get(
    tasks_manager.status_location,
    responses={fastapi.status.HTTP_404_NOT_FOUND: {"description": "Task Not Found"}},
    tags=["status"],
)
async def get_task(request_id: str) -> api_models.TaskStatusResponse:
    task = tasks_manager.get_task(request_id)
    if not task:
        raise server_error_responses.HTTPNotFoundError(detail="Task not found")
    return task


@router.get(
    "/api/ocie/v1/tasks",
    tags=["status"],
)
async def list_task() -> list[api_models.TaskStatusResponse]:
    return tasks_manager.get_tasks()
