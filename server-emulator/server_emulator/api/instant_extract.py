import logging

import fastapi

from .. import api_models, common
from ..server_engine import tasks_manager

logger = logging.getLogger(__name__)
router = fastapi.APIRouter()


def created_task_response(task: api_models.TaskStatusResponse) -> fastapi.Response:
    return fastapi.Response(
        task.model_dump_json(),
        media_type="application/json",
        status_code=fastapi.status.HTTP_202_ACCEPTED,
    )


@router.post(
    "/flex/api/v1/extract/replicate",
    responses={
        fastapi.status.HTTP_409_CONFLICT: {"description": "Request Id Conflict"},
        fastapi.status.HTTP_202_ACCEPTED: {"description": "Request Accepted"},
    },
    tags=["extract"],
)
async def replicate(
    request: api_models.ReplicateRequest,
) -> api_models.TaskStatusResponse:
    # in the future request_id will be accepted from the client
    # and 409 will be returned if the request_id is already in use
    # for now, we generate a new request_id
    request_id = common.url_safe_id()
    kind = api_models.CommandKind.replicate
    logger.info(f"Received request: {request}. {request_id=} {kind=}")
    task = await tasks_manager.create_task(
        request_id=request_id,
        command=kind,
        duration_sec=3,
    )
    return created_task_response(task)


@router.post(
    "/flex/api/v1/extract/capture",
    responses={
        fastapi.status.HTTP_409_CONFLICT: {"description": "Request Id Conflict"},
        fastapi.status.HTTP_202_ACCEPTED: {"description": "Request Accepted"},
    },
    tags=["extract"],
)
async def capture(
    request: api_models.CaptureRequest,
) -> api_models.TaskStatusResponse:
    request_id = common.url_safe_id()
    kind = api_models.CommandKind.capture
    logger.info(f"Received request: {request}. {request_id=} {kind=}")
    task = await tasks_manager.create_task(
        request_id=request_id,
        command=kind,
        duration_sec=3,
        result={"extract_id": common.url_safe_id(n=5)},
    )
    return created_task_response(task)


@router.post(
    "/flex/api/v1/extract/deploy",
    responses={
        fastapi.status.HTTP_409_CONFLICT: {"description": "Request Id Conflict"},
        fastapi.status.HTTP_202_ACCEPTED: {"description": "Request Accepted"},
    },
    tags=["extract"],
)
async def deploy(
    request: api_models.DeployRequest,
) -> api_models.TaskStatusResponse:
    request_id = common.url_safe_id()
    kind = api_models.CommandKind.deploy
    logger.info(f"Received request: {request}. {request_id=} {kind=}")
    task = await tasks_manager.create_task(
        request_id=request_id,
        command=kind,
        duration_sec=3,
    )
    return created_task_response(task)
