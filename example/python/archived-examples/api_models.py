from enum import Enum
from typing import Optional

import pydantic


class DBVendor(str, Enum):
    mssql = "mssql"


class Cloud(str, Enum):
    GCP = "GCP"
    AWS = "AWS"
    AZURE = "AZURE"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def from_str(cls, vendor: str) -> "Cloud":
        return cls(vendor.upper())


class Host(pydantic.BaseModel):
    host_id: str
    db_vendor: DBVendor = DBVendor.mssql
    last_seen_ts: int = 0  # last time agent sent heartbeat
    host_name: str = ""
    host_iqn: str = ""
    host_os: str = ""
    host_os_version: str = ""
    agent_version: str = ""
    cloud_vendor: Optional[Cloud] = Cloud.UNKNOWN


class CreateHostResponse(pydantic.BaseModel):
    host_id: str
    db_vendor: DBVendor
    token: str


class ReplicateRequest(pydantic.BaseModel):
    database_id: str
    source_host_id: str
    destination_host_ids: list[str]


class CaptureRequest(pydantic.BaseModel):
    database_id: str
    source_host_id: str


class DeployRequest(pydantic.BaseModel):
    extract_id: str
    destination_host_ids: list[str]


class TaskState(str, Enum):
    running = "running"
    completed = "completed"
    failed = "failed"
    aborted = "aborted"


class CommandKind(str, Enum):
    replicate = "ReplicateCommand"
    capture = "CaptureCommand"
    deploy = "DeployCommand"


class TaskStatusResponse(pydantic.BaseModel):
    state: TaskState
    create_ts: int
    update_ts: int
    request_id: str
    owner: str
    command_type: CommandKind
    ref_id: str
    error: str = ""
    location: Optional[str] = None  # URI for polling
    result: Optional[dict] = None  # result of the task

    def is_failed(self):
        return self.state in (TaskState.failed, TaskState.aborted)

    def is_running(self):
        return self.state == TaskState.running

    def is_completed(self):
        return self.state == TaskState.completed


class CaptureExtractResponse(pydantic.BaseModel):
    extract_id: str