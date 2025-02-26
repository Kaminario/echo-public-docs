import os
import random
import sys
import time
from typing import Tuple

import fire
import requests

requests.packages.urllib3.disable_warnings()

# Environment Variables
FLEX_TOKEN = None
FLEX_IP = None

############################################
# Helper Functions
############################################


def _ensure_env():
    global FLEX_TOKEN, FLEX_IP

    FLEX_TOKEN = os.getenv("FLEX_TOKEN", "")
    FLEX_IP = os.getenv("FLEX_IP", "")

    if not FLEX_TOKEN or not FLEX_IP:
        print("FLEX_TOKEN and FLEX_IP environment variables must be set.")
        sys.exit(1)


def _go_no_go(msg):
    try:
        answer = input(f"{msg} [y/n]: ")
    except KeyboardInterrupt:
        answer = "n"
        print()

    if answer.lower() != "y":
        print("Aborted")
        sys.exit(0)


def _tracking_id():
    """random string [a-zA-Z0-9]{10}.
    used to identify request at flex
    """
    return "".join(
        random.choices(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=10
        )
    )


def _make_refresh(
    host_name: str,
    db_names: tuple[str],
    keep_backup: bool,
    snapshot_id: str,
) -> Tuple[bool, dict]:

    # perform a request to make a snapshot
    url = f"https://{FLEX_IP}/flex/api/v1/hosts/{host_name}/databases/_replace"

    headers = {
        "Authorization": f"Bearer {FLEX_TOKEN}",
        "hs-ref-id": _tracking_id(),
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    r = requests.post(
        url,
        json={
            "db_names": db_names,
            "keep_backup": keep_backup,
            "snapshot_id": snapshot_id,
        },
        verify=False,
        headers=headers,
    )
    if r.status_code // 100 != 2:
        return False, {"error": r.text}

    task = r.json()

    return _wait_for_task(task)


def _wait_for_task(task: dict) -> tuple[bool, dict]:
    """
    task structure example:
    {
        "state": "completed",
        "create_ts": 1735025889,
        "update_ts": 1735025908,
        "request_id": "Fj3U7QTsDDWL45ikk0bvk2tsanfC3HBJH2zVyJvfRLc",
        "owner": "ocie-0",
        "command_type": "CreateDBSnapshotCommand",
        "ref_id": "ADD62kMoLB",
        "error": "",
        "result": {"db_snapshot": {"id": "primary__5__1735025906"}},
        "location": "/api/ocie/v1/tasks/Fj3U7QTsDDWL45ikk0bvk2tsanfC3HBJH2zVyJvfRLc",
    }"""

    headers = {
        "Authorization": f"Bearer {FLEX_TOKEN}",
        "hs-ref-id": _tracking_id(),
        "Accept": "application/json",
    }
    while task["state"] == "running":
        time.sleep(5)
        print(".", end="", flush=True)  # no buffering, print right away
        url = f"https://{FLEX_IP}{task['location']}"
        r = requests.get(url, verify=False, headers=headers)
        if r.status_code // 100 == 2:
            task = r.json()

        if task["state"] == "running":
            continue

        print()
        # task states: "completed", "failed", "aborted"
        return task["state"] == "completed", task


############################################
# Main Command
############################################


def run(
    host_name: str,
    db_names: tuple[str],
    keep_backup: bool,
    snapshot_id: str,
):
    """This script refreshes a databases on host from a snapshot.

    Usage example:

    Set the following environment variables:
       - `FLEX_TOKEN`: Bearer token for Flex API authentication.
       - `FLEX_IP`: Flex server IP address.

    python refresh.py run --host-name <host-name> --db-names <db-name-1,db-name-2> --keep-backup <keep-backup> --snapshot-id <snapshot-id>

    Args:
        host_name (str): Host name to take snapshot from
        db_names (list[str]): List of database names to refresh
        keep_backup (bool): Keep backup of the current databases by renaming them
        -- (str): Snapshot id to refresh from
    """

    _ensure_env()

    print("Going to refresh databases:")
    if isinstance(db_names, str):
        db_names = (db_names,)

    for db_name in db_names:
        print(f"\t{db_name}")
    _go_no_go(msg="Do you want to continue?")

    print(f"refreshing")
    success, task = _make_refresh(host_name, db_names, keep_backup, snapshot_id)
    if not success:
        print(f"Failed to refresh databases. Error: {task['error']}")
    else:
        print(f"Databases refreshed successfully. Task: {task}")


if __name__ == "__main__":
    fire.Fire(run)
