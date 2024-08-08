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
    while task.state != "completed":
        time.sleep(2)
        task = cl.task.get(task_id)
        print(task)
    print(f"DONE {task=}")


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


def create_clone(cl):
    """
    register host01
    Create a clone of a database_01 from host01 to host02
    """

    source_host_id = "host01"
    darget_host_id = "host02"
    database_id = "3"
    vendor = api_models.DBVendor.mssql

    _register_host(cl, source_host_id, vendor)
    _register_host(cl, darget_host_id, vendor)

    create_clone_request = api_models.CreateCloneRequest(
        database_id="3",
        source_host_id="host01",
        destination_host_ids=["host02"],
    )
    print(
        f"""Creating a clone of database {database_id}
from host {source_host_id}
to host {darget_host_id}
parameters:
{create_clone_request.model_dump_json(indent=2)}
"""
    )

    task = cl.action.create_clone(create_clone_request)
    print(f"committed task: {task.model_dump_json(indent=2)}")
    wait_for_task(cl, task.request_id)


def create_extract(cl):
    """
    register host01
    Create an extract of a database_01 from host01
    """

    source_host_id = "host01"
    database_id = "3"
    vendor = api_models.DBVendor.mssql

    _register_host(cl, source_host_id, vendor)

    create_extract_request = api_models.CreateExtractRequest(
        database_id="3",
        source_host_id=source_host_id,
    )
    print(
        f"""Creating an extract of database {database_id}
from host {source_host_id}
parameters:
{create_extract_request.model_dump_json(indent=2)}
"""
    )

    task = cl.action.create_extract(create_extract_request)
    print(f"committed task: {task.model_dump_json(indent=2)}")
    wait_for_task(cl, task.request_id)


def import_extract(cl):
    """
    register host02
    Import an extract of a database_01 to host02
    """

    destination_host_id = "host02"
    extract_id = "3"
    vendor = api_models.DBVendor.mssql

    _register_host(cl, destination_host_id, vendor)

    import_extract_request = api_models.ImportExtractRequest(
        extract_id="3",
        destination_host_ids=["host02"],
    )
    print(
        f"""Importing an extract {extract_id}
to host {destination_host_id}
parameters:
{import_extract_request.model_dump_json(indent=2)}
"""
    )

    task = cl.action.import_extract(import_extract_request)
    print(f"committed task: {task.model_dump_json(indent=2)}")
    wait_for_task(cl, task.request_id)


def main():
    track_id = url_safe_id(n=8)
    print(f"track_id: {track_id}")

    cl = Client(host="0.0.0.0", port=8000, token="1111", track_id=track_id)

    create_clone(cl)
    create_extract(cl)
    import_extract(cl)


if __name__ == "__main__":
    main()
