# Copyright (c) 2025 Silk Technologies, Inc.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

import os
import random
import sys
import time
from enum import Enum
from typing import Tuple

import fire
import requests

requests.packages.urllib3.disable_warnings()

# Environment Variables
FLEX_TOKEN = os.getenv("FLEX_TOKEN", "")
FLEX_IP = os.getenv("FLEX_IP", "")

############################################
# Helper Functions
############################################


def log(msg: str, **kwargs):
    # print to stderr to avoid mixing with stdout
    print(msg, file=sys.stderr, **kwargs)


def _ensure_env():
    global FLEX_TOKEN, FLEX_IP

    if not FLEX_TOKEN or not FLEX_IP:
        log("FLEX_TOKEN and FLEX_IP environment variables must be set.")
        sys.exit(1)


class CLevel(str, Enum):
    crash = "crash"
    application = "application"


def _go_no_go(msg):
    try:
        answer = input(f"{msg} [y/n]: ")
    except KeyboardInterrupt:
        answer = "n"
        print()

    if answer.lower() != "y":
        log("Aborted")
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


def _host_topology(host_name):
    topo = _get_topology()
    return [t for t in topo if t["host"]["name"] == host_name][0]


def _get_topology():
    url = f"https://{FLEX_IP}/api/ocie/v1/topology"
    headers = {
        "Authorization": f"Bearer {FLEX_TOKEN}",
        "hs-ref-id": _tracking_id(),
        "Accept": "application/json",
    }
    r = requests.get(url, verify=False, headers=headers)

    if r.status_code // 100 != 2:
        log(f"Failed to get database topology. Error: {r.status_code} {r.text}")
        sys.exit(1)
    topology = r.json()

    return topology


def _map_db_id_2_db_name(host_topology: dict) -> dict[str, str]:
    db_id_2_dn_name = dict()
    for db in host_topology["databases"]:
        db_id_2_dn_name[db["id"]] = db["name"]
    return db_id_2_dn_name


def _make_snapshot(
    host_id: str,
    db_ids: set[str],
    name_prefix: str,
    consistency_level: CLevel,
) -> Tuple[bool, dict]:

    # perform a request to make a snapshot
    url = f"https://{FLEX_IP}/flex/api/v1/db_snapshots"

    headers = {
        "Authorization": f"Bearer {FLEX_TOKEN}",
        "hs-ref-id": _tracking_id(),
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    r = requests.post(
        url,
        json={
            "source_host_id": host_id,
            "database_ids": list(db_ids),
            "name_prefix": name_prefix,
            "consistency_level": str(consistency_level),
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
    name_prefix: str,
    consistency_level: CLevel = CLevel.crash,
):
    """This script creates a snapshot of all databases on the source host.

    Usage example:

    Set the following environment variables:
       - `FLEX_TOKEN`: Bearer token for Flex API authentication.
       - `FLEX_IP`: Flex server IP address.

    python snapshot_daily.py run --host-name <host-name> --name-prefix <prefix-for-snapshot> --consistency_level <crash|application>

    Args:
        host_name (str): Host name to take snapshot from
        name_prefix (str): Prefix for the snapshot name
        consistency_level (CLevel, optional): Consistency level ot the taken snapshot. Options are ["crash", "application"].
    """

    _ensure_env()

    # get_database_ids by host_id by vg
    topology = _host_topology(host_name)
    host_id = topology["host"]["id"]

    db_id_2_name = _map_db_id_2_db_name(topology)

    print(f"making snapshot/s of the host `{host_name}` with the following databases:")

    for db_name in db_id_2_name.values():
        print(f"\t{db_name}")

    _go_no_go(msg="Do you want to continue?")

    print(f"making snapshot")
    success, task = _make_snapshot(
        host_id, set(db_id_2_name.keys()), name_prefix, consistency_level
    )
    if not success:
        log(f"Failed to create snapshot. Error: {task['error']}")
    else:
        print(f"Snapshot created successfully. Task: {task}")


if __name__ == "__main__":
    fire.Fire(run)
