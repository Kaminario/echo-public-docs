import secrets
import time

import api_models
from api_client import Client


def url_safe_id(n=32):
    """Generate a random hex ID of 32 characters."""
    return secrets.token_urlsafe(nbytes=n)


def wait_for_task(cl, task_id):
    print(f"Waiting for {task_id=}")
    task = cl.task.get(task_id)
    while task.is_running():
        time.sleep(2)
        task = cl.task.get(task_id)
        print(task)
    print(f"DONE {task=}")
    return task


def _register_host(cl, host_id, vendor):
    cl.host.unregister(host_id)
    print(
        f"""Registering host {host_id}
parameters:
    host_id: {host_id}
    db_vendor: {vendor}"""
    )
    host_registration = cl.host.register(host_id, db_vendor=vendor)
    print(f"source_host_registration: {host_registration}")
    return host_registration


HOST_1 = "host1"
HOST_2 = "host2"


def replicate(cl):
    """
    register host01
    Create a clone of a database_01 from host01 to host02
    """

    source_host_id = HOST_1
    destination_host_id = HOST_2
    database_id = "3"
    vendor = api_models.DBVendor.mssql

    _register_host(cl, source_host_id, vendor)
    _register_host(cl, destination_host_id, vendor)

    replicate_request = api_models.ReplicateRequest(
        database_id="3",
        source_host_id=source_host_id,
        destination_host_ids=[destination_host_id],
    )
    print(
        f"""Creating a clone of database {database_id}
from host {source_host_id}
to host {destination_host_id}
parameters:
{replicate_request.model_dump_json(indent=2)}
"""
    )

    task = cl.action.replicate(replicate_request)
    print(f"committed task: {task.model_dump_json(indent=2)}")
    wait_for_task(cl, task.request_id)


def capture(cl) -> api_models.CaptureExtractResponse:
    """
    register host01
    Create an extract of a database_01 from host01
    """

    source_host_id = HOST_1
    database_id = "3"
    vendor = api_models.DBVendor.mssql

    _register_host(cl, source_host_id, vendor)

    capture_request = api_models.CaptureRequest(
        database_id="3",
        source_host_id=source_host_id,
    )
    print(
        f"""Creating an extract of database {database_id}
from host {source_host_id}
parameters:
{capture_request.model_dump_json(indent=2)}
"""
    )

    started_task = cl.action.capture(capture_request)
    print(f"committed task: {started_task.model_dump_json(indent=2)}")
    completed_task = wait_for_task(cl, started_task.request_id)
    return api_models.CaptureExtractResponse(**completed_task.result)


def deploy(cl, extract_id: str):
    """
    register host02
    Import an extract of a database_01 to host02
    """

    destination_host_id = HOST_2
    vendor = api_models.DBVendor.mssql

    _register_host(cl, destination_host_id, vendor)

    deploy_request = api_models.DeployRequest(
        extract_id=extract_id,
        destination_host_ids=[destination_host_id],
    )
    print(
        f"""Importing an extract {extract_id}
to host {destination_host_id}
parameters:
{deploy_request.model_dump_json(indent=2)}
"""
    )

    task = cl.action.deploy(deploy_request)
    print(f"committed task: {task.model_dump_json(indent=2)}")
    wait_for_task(cl, task.request_id)


def main():
    track_id = url_safe_id(n=8)
    print(f"track_id: {track_id}")

    cl = Client(host="0.0.0.0", port=8000, token="1111", track_id=track_id)

    replicate(cl)
    result = capture(cl)
    deploy(cl, result.extract_id)


if __name__ == "__main__":
    main()
