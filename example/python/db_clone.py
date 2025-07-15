# Copyright (c) 2025 Silk Technologies, Inc.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

import os
import random
import sys
import time
from enum import Enum
from datetime import date, datetime, timezone
from typing import Optional, Any

import fire
import requests

requests.packages.urllib3.disable_warnings()

# Environment Variables
FLEX_TOKEN = os.getenv("FLEX_TOKEN", "")
FLEX_IP = os.getenv("FLEX_IP", "")

############################################
# Helper Functions
############################################


def exit_with_error(msg: str, **kwargs):
    # print to stderr to avoid mixing with stdout
    print(msg, file=sys.stderr, **kwargs)
    sys.exit(1)


def _ensure_env():
    global FLEX_TOKEN, FLEX_IP

    if not FLEX_TOKEN or not FLEX_IP:
        exit_with_error("FLEX_TOKEN and FLEX_IP environment variables must be set.")


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
    """Generate a random string to track requests in Flex logs."""
    # Generate a 10-character alphanumeric string
    return "".join(
        random.choices(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=10
        )
    )


def _get_topology() -> dict[str, Any]:
    """Retrieve the full topology from the Flex API."""
    url = f"https://{FLEX_IP}/api/ocie/v1/topology"
    tracking_id = _tracking_id()
    headers = {
        "Authorization": f"Bearer {FLEX_TOKEN}",
        "hs-ref-id": tracking_id,
        "Accept": "application/json",
    }
    print(f"Fetching topology with tracking ID: {tracking_id}")

    response = requests.get(url, verify=False, headers=headers)

    # Handle HTTP errors
    if response.status_code // 100 != 2:
        exit_with_error(
            f"Failed to retrieve topology. Error: {response.status_code} {response.text}"
        )

    return response.json()


def _get_snapshot(
    host_topology: dict, dt: date, db_ids: set[str]
) -> tuple[Optional[datetime], Optional[str]]:
    """Find the most recent snapshot for a given date and database IDs.

    Args:
        host_topology (dict): The topology data for the host.
        dt (date): The date of the snapshot to find.
        db_ids (set[str]): The database IDs to match.

    Returns:
        tuple[Optional[datetime], Optional[str]]: The latest snapshot timestamp and ID, or (None, None) if not found.
    """
    matched_snapshots = []

    print(f"Searching for snapshots dated {dt} for databases: {db_ids}")
    for db in host_topology.get("databases", []):
        for snap in db.get("db_snapshots", []):
            snapshot_ts = datetime.fromtimestamp(snap["timestamp"], tz=timezone.utc)

            if snapshot_ts.date() != dt:
                continue

            # Ensure all required DB IDs are present in the snapshot
            if not db_ids.issubset(set(snap["db_ids"])):
                continue

            matched_snapshots.append((snapshot_ts, snap["id"]))

    # Return the latest matching snapshot, or (None, None) if no match
    return max(matched_snapshots, default=(None, None))


def _host_topology(host_name: str, topology: list[dict]) -> Optional[dict]:
    """Retrieve topology data for a specific host.

    Args:
        host_name (str): The name of the host to find.
        topology (List[dict]): The full topology data.

    Returns:
        dict: Topology data for the specified host, or None if not found.
    """
    for host in topology:
        if host["host"]["name"] == host_name:
            return host
    return None


def _host_names(topology: list[dict]) -> list[str]:
    """Retrieve a sorted list of host names from the topology.

    Args:
        topology (List[dict]): The full topology data.

    Returns:
        List[str]: A sorted list of host names.
    """
    return sorted(host["host"]["name"] for host in topology)


def _make_clone(snapshot_id: str, dest_host_id: str, dbs: dict[str, str], suffix: str):
    """Send a request to clone databases from a snapshot.

    Args:
        snapshot_id (str): The ID of the snapshot to clone.
        dest_host_id (str): The ID of the destination host.
        dbs (Dict[str, str]): A mapping of database names to IDs.
        suffix (str): The suffix to append to cloned database names.
    """
    post_data = {"destinations": []}
    for db_name, db_id in dbs.items():
        post_data["destinations"].append(
            {
                "host_id": dest_host_id,
                "db_id": db_id,
                "db_name": db_name + suffix,
            }
        )

    # perform a request to make a snapshot
    url = f"https://{FLEX_IP}/flex/api/v1/db_snapshots/{snapshot_id}/clone"

    tracking_id = _tracking_id()
    headers = {
        "Authorization": f"Bearer {FLEX_TOKEN}",
        "hs-ref-id": tracking_id,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    print(f"Cloning snapshot with tracking ID: {tracking_id}, data: {post_data}")

    response = requests.post(url, json=post_data, verify=False, headers=headers)

    # Handle HTTP errors
    if response.status_code // 100 != 2:
        exit_with_error(
            f"Failed to clone snapshot. Error: {response.status_code} {response.text}"
        )

    task = response.json()
    success, task = _wait_for_task(task)
    if not success:
        exit_with_error(
            f"Snapshot cloning failed. Error: {task.get('error', 'Unknown error')}"
        )
    else:
        print(f"Snapshot cloned successfully. Result: {task['result']}")


def _wait_for_task(task: dict) -> tuple[bool, dict]:
    """Poll the task API to check task completion.

    Args:
        task (dict): The task data returned from the initial request.

    Returns:
        tuple[bool, dict]: A boolean indicating success and the final task data.

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
        "Content-Type": "application/json",
    }

    while task["state"] == "running":
        time.sleep(5)
        print(".", end="", flush=True)  # no buffering, print right away
        url = f"https://{FLEX_IP}{task['location']}"
        response = requests.get(url, verify=False, headers=headers)

        if response.status_code // 100 == 2:
            task = response.json()

    print()  # Add a newline after dots
    # task states: "completed", "failed", "aborted"
    return task["state"] == "completed", task


############################################
# Main Command
############################################


def run(
    snap_date: str,
    src: str,
    dest: str,
    db_names: list[str],
    suffix: str,
):
    """Database Snapshot and Clone Script

    This script automates the process of creating Echo databases on
    the destination host from the latest snapshot taken on
    a specific day at the source host.

    Usage example:

    Set the following environment variables:
       - `FLEX_TOKEN`: Bearer token for Flex API authentication.
       - `FLEX_IP`: Flex server IP address.

    python db_clone.py --snap-date "2024-12-24" --src primary --dest dev-1 --db-names sales_us,sales_eu --suffix "_backup"


    Args:
        snap_date (str): Snapshot date in "yyyy-mm-dd" format.
        src (str): Source host name.
        dest (str): Destination host name.
        db_names (str): Comma-separated list of database names to clone.
        suffix (str): Suffix to append to cloned database names.
    """

    _ensure_env()

    print(f"Cloning databases from '{snap_date}' snapshot: {src} -> {dest}")
    print(f"Databases: {db_names}")
    print(f"Suffix: {suffix}")

    dt = date.fromisoformat(snap_date)

    if isinstance(db_names, str):
        db_names = [db_names]

    topology = _get_topology()

    src_topology = _host_topology(src, topology)
    if not src_topology:
        exit_with_error(
            f"Source host '{src}' not found. Available hosts: {_host_names(topology)}"
        )

    # Retrieve destination host topology
    dest_topology = _host_topology(dest, topology)
    if not dest_topology:
        exit_with_error(
            f"Destination host '{dest}' not found. Available hosts: {_host_names(topology)}"
        )

    dest_host_id = dest_topology["host"]["id"]

    db_map = {
        db["name"]: db["id"]
        for db in src_topology["databases"]
        if db["name"] in db_names
    }

    # validate we have all dbs and ids in the topology
    if len(db_map) != len(db_names):
        missing_dbs = set(db_names) - set(db_map.keys())
        exit_with_error(f"Missing databases: {missing_dbs}")

    # get snapshot id where all dbs are present
    snap_ts, snap_id = _get_snapshot(src_topology, dt, set(db_map.values()))

    if not snap_id:
        exit_with_error(
            f"No snapshot found for date {dt} containing all requested databases."
        )

    print(f"Cloning databases from snapshot '{snap_id}' taken on '{snap_ts}'")
    for db_name in db_names:
        print(f"{src}[{db_name}] -> {dest}[{db_name + suffix}]")

    _go_no_go("Proceed with cloning?")
    _make_clone(snap_id, dest_host_id, db_map, suffix)

    print(f"Cloning completed successfully. Snapshot ID: {snap_id}")


if __name__ == "__main__":
    fire.Fire(run)
