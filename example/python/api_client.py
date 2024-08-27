from dataclasses import dataclass
from typing import Callable, Optional

import api_models
import requests

base_url = "http://{host}:{port}"


class BearerAuth(requests.auth.AuthBase):
    def __init__(self, token):
        self.token = token

    def __call__(self, r):
        r.headers["authorization"] = "Bearer " + self.token
        return r


@dataclass
class ClientHost:
    session: requests.Session
    make_endpoint: Callable[[str], str]

    def register(
        self, host_id: str, *, db_vendor: str
    ) -> api_models.CreateHostResponse:
        url = self.make_endpoint(f"/flex/api/v1/hosts/{host_id}")
        response = self.session.put(url, json={"db_vendor": db_vendor})
        response.raise_for_status()
        return api_models.CreateHostResponse(**response.json())

    def unregister(self, host_id) -> None:
        url = self.make_endpoint(f"/flex/api/v1/hosts/{host_id}")
        response = self.session.delete(url)
        response.raise_for_status()

    def get(self, host_id) -> api_models.Host:
        url = self.make_endpoint(f"/flex/api/v1/hosts/{host_id}")
        response = self.session.get(url)
        response.raise_for_status()
        return api_models.Host(**response.json())

    def list_hosts(self) -> list[api_models.Host]:
        url = self.make_endpoint("/flex/api/v1/hosts")
        response = self.session.get(url)
        response.raise_for_status()
        return [api_models.Host(**h) for h in response.json()]


@dataclass
class ClientTasks:
    session: requests.Session
    make_endpoint: Callable[[str], str]

    def get(self, request_id: str) -> api_models.Host:
        url = self.make_endpoint(f"/flex/api/v1/extract/tasks/{request_id}")
        response = self.session.get(url)
        response.raise_for_status()
        return api_models.TaskStatusResponse(**response.json())

    def list(self) -> list[api_models.Host]:
        url = self.make_endpoint("/flex/api/v1/extract/tasks")
        response = self.session.get(url)
        response.raise_for_status()
        return [api_models.TaskStatusResponse(**h) for h in response.json()]


@dataclass
class ClientAction:
    session: requests.Session
    make_endpoint: Callable[[str], str]

    def replicate(
        self, request: api_models.ReplicateRequest
    ) -> api_models.TaskStatusResponse:
        url = self.make_endpoint("/flex/api/v1/extract/replicate")
        response = self.session.post(url, json=request.dict())
        response.raise_for_status()
        return api_models.TaskStatusResponse(**response.json())

    def capture(
        self,
        request: api_models.CaptureRequest,
    ) -> api_models.TaskStatusResponse:
        url = self.make_endpoint("/flex/api/v1/extract/capture")
        response = self.session.post(url, json=request.dict())
        response.raise_for_status()
        return api_models.TaskStatusResponse(**response.json())

    def deploy(
        self,
        request: api_models.DeployRequest,
    ) -> api_models.TaskStatusResponse:
        url = self.make_endpoint("/flex/api/v1/extract/deploy")
        response = self.session.post(url, json=request.dict())
        response.raise_for_status()
        return api_models.TaskStatusResponse(**response.json())


class Client:
    def __init__(
        self, host: str, port: int, token: str, track_id: Optional[str] = None
    ):
        self.session = self.init_session(token, track_id)

        self.base_url = base_url.format(host=host, port=port)
        self.host = ClientHost(session=self.session, make_endpoint=self.make_endpoint)
        self.task = ClientTasks(session=self.session, make_endpoint=self.make_endpoint)
        self.action = ClientAction(
            session=self.session, make_endpoint=self.make_endpoint
        )

    def init_session(self, token: str, track_id: Optional[str] = None):
        session = requests.session()
        session.auth = BearerAuth(token)
        if track_id:
            session.headers = {"hs-ref-id": track_id}
        return session

    def make_endpoint(self, path):
        return f"{self.base_url}{path}"
