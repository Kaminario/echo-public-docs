import os
import random
import sys
import time
from typing import Tuple

import fire
import requests

# Disable SSL warnings from requests
requests.packages.urllib3.disable_warnings()

# Environment variables
FLEX_TOKEN = os.environ.get("FLEX_TOKEN")
FLEX_IP = os.environ.get("FLEX_IP")

# Validate environment variables
if not FLEX_TOKEN or not FLEX_IP:
    print("Error: FLEX_TOKEN and FLEX_IP environment variables must be set.")
    sys.exit(1)


def _go_no_go(msg: str):
    """Prompt the user for confirmation before proceeding."""
    try:
        answer = input(f"{msg} [y/n]: ")
    except KeyboardInterrupt:
        answer = "n"
        print()

    if answer.lower() != "y":
        print("Aborted")
        sys.exit(0)


def _tracking_id() -> str:
    """Generate a random tracking ID."""
    return "".join(
        random.choices(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=10
        )
    )


def _safe_request(method: str, url: str, headers: dict, data: dict = None):
    """Wrapper for making safe HTTP requests with error handling."""
    try:
        response = requests.request(
            method, url, headers=headers, json=data, verify=False
        )
        response.raise_for_status()
        return response
    except requests.exceptions.RequestException as e:
        print(f"Request error: {e}")
        sys.exit(1)


def _get_topology() -> dict:
    """Fetch the topology of the hosts and databases."""
    url = f"https://{FLEX_IP}/api/ocie/v1/topology"
    headers = {
        "Authorization": f"Bearer {FLEX_TOKEN}",
        "hs-ref-id": _tracking_id(),
        "Accept": "application/json",
    }
    response = _safe_request("GET", url, headers)
    return response.json()


def _host_topology(host_name: str) -> dict:
    """Retrieve the topology for a specific host."""
    topo = _get_topology()
    return next((t for t in topo if t["host"]["name"] == host_name), None)


def _group_dbs(host_topology: dict) -> Tuple[dict, dict]:
    """Group databases by volume group (VG)."""
    groups_ids = {}
    groups_names = {}
    for db in host_topology["databases"]:
        for file in db["files"]:
            vg_id = file["volume_group_id"]
            groups_ids.setdefault(vg_id, set()).add(db["id"])
            groups_names.setdefault(vg_id, set()).add(db["name"])
    return groups_ids, groups_names


def _make_snapshot(host_id: str, db_ids: set[str]) -> Tuple[bool, dict]:
    """Create a snapshot for the specified databases."""
    url = f"https://{FLEX_IP}/flex/api/v1/db_snapshots"
    headers = {
        "Authorization": f"Bearer {FLEX_TOKEN}",
        "hs-ref-id": _tracking_id(),
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    response = _safe_request(
        "POST",
        url,
        headers,
        {
            "source_host_id": host_id,
            "database_ids": list(db_ids),
        },
    )
    task = response.json()
    return _wait_for_task(task)


def _wait_for_task(task: dict, timeout: int = 600) -> Tuple[bool, dict]:
    """Wait for the task to complete within the given timeout."""
    headers = {
        "Authorization": f"Bearer {FLEX_TOKEN}",
        "hs-ref-id": _tracking_id(),
        "Accept": "application/json",
    }
    start_time = time.time()
    while task["state"] == "running":
        if time.time() - start_time > timeout:
            print("\nTask timed out.")
            return False, {"error": "Timeout exceeded"}
        time.sleep(5)
        print(".", end="", flush=True)
        url = f"https://{FLEX_IP}{task['location']}"
        response = _safe_request("GET", url, headers)
        task = response.json()
    print()
    return task["state"] == "completed", task


def run(host_name: str):
    """Create snapshots for all databases on the specified host."""
    topology = _host_topology(host_name)
    if not topology:
        print(f"Host `{host_name}` not found.")
        sys.exit(1)

    host_id = topology["host"]["id"]
    db_ids_by_vg, db_names_by_vg = _group_dbs(topology)

    print(f"Making snapshot(s) of the host `{host_name}` with the following databases:")
    for vg_id, db_names in db_names_by_vg.items():
        print(f"\tVG {vg_id}: {', '.join(db_names)}")

    _go_no_go(msg="Do you want to continue?")

    for vg_id, db_ids in db_ids_by_vg.items():
        db_names = db_names_by_vg[vg_id]
        print(f"Creating snapshot for VG {vg_id}: {', '.join(db_names)}")
        success, task = _make_snapshot(host_id, db_ids)
        if not success:
            print(f"Failed to create snapshot for VG {vg_id}. Error: {task['error']}")
            _go_no_go(msg="Do you want to continue?")
        else:
            snapshot_id = task["result"]["db_snapshot"]["id"]
            print(f"Snapshot created: `{snapshot_id}`")
            print(f"\tDatabases in the snapshot: {', '.join(db_names)}")


if __name__ == "__main__":
    fire.Fire()
