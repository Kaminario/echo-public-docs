import logging

import fastapi

from .. import api_models, common
from ..server_engine import tasks_manager

logger = logging.getLogger(__name__)
router = fastapi.APIRouter()


@router.post(
    "/flex/api/v1/extract/replicate",
    responses={
        fastapi.status.HTTP_409_CONFLICT: {"description": "Request Id Conflict"}
    },
    tags=["extract"],
)
async def create_clone(
    request: api_models.CreateCloneRequest,
) -> api_models.TaskStatusResponse:
    # in the future request_id will be accepted from the client
    # and 409 will be returned if the request_id is already in use
    # for now, we generate a new request_id
    request_id = common.url_safe_id()
    kind = api_models.CommandKind.create_clone
    logger.info(f"Received request: {request}. {request_id=} {kind=}")
    task = await tasks_manager.create_task(
        request_id=request_id,
        command=kind,
        duration_sec=3,
    )
    return task


@router.post(
    "/flex/api/v1/extract/capture",
    responses={
        fastapi.status.HTTP_409_CONFLICT: {"description": "Request Id Conflict"}
    },
    tags=["extract"],
)
async def create_extract(
    request: api_models.CreateExtractRequest,
) -> api_models.TaskStatusResponse:
    request_id = common.url_safe_id()
    kind = api_models.CommandKind.create_extract
    logger.info(f"Received request: {request}. {request_id=} {kind=}")
    task = await tasks_manager.create_task(
        request_id=request_id,
        command=kind,
        duration_sec=3,
    )
    return task


@router.post(
    "/flex/api/v1/extract/deploy",
    responses={
        fastapi.status.HTTP_409_CONFLICT: {"description": "Request Id Conflict"}
    },
    tags=["extract"],
)
async def import_extract(
    request: api_models.ImportExtractRequest,
) -> api_models.TaskStatusResponse:
    request_id = common.url_safe_id()
    kind = api_models.CommandKind.import_extract
    logger.info(f"Received request: {request}. {request_id=} {kind=}")
    task = await tasks_manager.create_task(
        request_id=request_id,
        command=kind,
        duration_sec=3,
    )
    return task
