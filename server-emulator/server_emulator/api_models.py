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


class Token(pydantic.BaseModel):
    host_id: str
    token: str
    expire_ts: Optional[int] = None
    valid: bool


class CreateHostResponse(pydantic.BaseModel):
    host_id: str
    db_vendor: DBVendor
    token: str


class CreateCloneRequest(pydantic.BaseModel):
    database_id: str
    source_host_id: str
    destination_host_ids: list[str]


class CreateExtractRequest(pydantic.BaseModel):
    database_id: str
    source_host_id: str


class ImportExtractRequest(pydantic.BaseModel):
    extract_id: str
    destination_host_ids: list[str]


class TaskState(str, Enum):
    running = "running"
    completed = "completed"
    failed = "failed"
    aborted = "aborted"


class CommandKind(str, Enum):
    create_clone = "CreateCloneCommand"
    create_extract = "CreateExtractCommand"
    import_extract = "ImportExtractCommand"


class TaskStatusResponse(pydantic.BaseModel):
    state: TaskState
    create_ts: int
    update_ts: int
    request_id: str
    owner: str
    command_type: CommandKind
    ref_id: str
    error: str = ""
    location: Optional[str] = None  # URI for polling status
    result: Optional[dict] = None  # result of the task
    _result: Optional[dict] = None  # holds the result untill the task is completed

    def set_result(self, result: dict):
        # this method is used to set the result of the task
        # only after the task is completed
        # this result will be copied to self.result
        self._result = result

    def get_result(self):
        return self._result

    def is_failed(self):
        return self.state in (TaskState.failed, TaskState.aborted)

    def is_running(self):
        return self.state == TaskState.running

    def is_completed(self):
        return self.state == TaskState.completed
