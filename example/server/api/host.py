import logging
from typing import Annotated

import fastapi

from .. import api_models, server_error_responses
from ..server_engine import hosts_manager

MIN_HOST_ID_LENGTH = 3
MAX_HOST_ID_LENGTH = 32

host_id_validator = fastapi.Path(
    min_length=MIN_HOST_ID_LENGTH,
    max_length=MAX_HOST_ID_LENGTH,
    pattern="^[a-zA-Z][a-zA-Z0-9_-]+[a-zA-Z0-9]$",
    description="The ID of the host. Must start with letter, end with letter or number."
    " Only letters, numbers, underscore and hyphen are allowed."
    f" Min length {MIN_HOST_ID_LENGTH}, max length {MAX_HOST_ID_LENGTH}",
)

logger = logging.getLogger(__name__)
router = fastapi.APIRouter()


@router.put(
    "/api/hostess/v1/hosts/{host_id}",
    description="Register a new host",
    responses={
        fastapi.status.HTTP_409_CONFLICT: {"description": "Host already exists"}
    },
    tags=["hosts"],
)
async def register_host(
    host_id: Annotated[str, host_id_validator],
    dbvendor: api_models.DBVendor = api_models.DBVendor.mssql,
) -> api_models.CreateHostResponse:
    """
    creates host registration in flex includes access token for the agent for flex communication.
    """

    logger.info(f"Received request: {host_id}")
    try:
        token = hosts_manager.register_host(host_id=host_id, db_vendor=dbvendor)
    except hosts_manager.HostAlreadyRegistered:
        raise server_error_responses.HTTPConflictError(
            detail=f"Host '{host_id}' already exists."
        )
    return api_models.CreateHostResponse(
        host_id=host_id, db_vendor=dbvendor, token=token
    )


@router.delete(
    "/api/hostess/v1/hosts/{host_id}", description="Unregister a host", tags=["hosts"]
)
async def unregister(host_id: Annotated[str, host_id_validator]):
    hosts_manager.unregister_host(host_id)
    return fastapi.Response(status_code=fastapi.status.HTTP_204_NO_CONTENT)


@router.get(
    "/api/hostess/v1/hosts/{host_id}",
    description="get host information",
    tags=["hosts"],
)
async def get_host(host_id: Annotated[str, host_id_validator]) -> api_models.Host:
    host = hosts_manager.get_host(host_id=host_id)
    if not host:
        raise server_error_responses.HTTPNotFoundError(
            detail=f"Host '{host_id}' not found"
        )
    return host


@router.get(
    "/api/hostess/v1/hosts",
    description="list registered hosts information",
    tags=["hosts"],
)
async def list_hosts() -> list[api_models.Host]:
    return hosts_manager.get_hosts()


@router.get(
    "/api/hostess/v1/hosts/{host_id}/app-token",
    description="get application-token for host",
    tags=["hosts"],
)
async def app_token(host_id: Annotated[str, host_id_validator]) -> api_models.Token:
    token = hosts_manager.get_token(host_id)
    if not token:
        raise server_error_responses.HTTPNotFoundError(
            detail=f"Host's '{host_id}' token  not found"
        )
    return token
