"""
Database Snapshot and Clone Script

This script automates the process of creating snapshots of databases on a source host
and cloning them to a destination host. It uses the Flex Topology API to retrieve
the list of hosts, databases, and volume groups (VGs) and handles snapshot creation
and cloning efficiently.

### Features:
- Retrieve database topology from the Flex Topology API.
- Identify and validate snapshots based on date and database IDs.
- Clone selected databases from a snapshot to a target host.
- Ensure safety with user confirmations before making changes.

### Prerequisites:
1. Python 3.6+
2. Install dependencies:
   ```
   pip install fire requests
   ```
3. Set the following environment variables:
   - `FLEX_TOKEN`: Bearer token for Flex API authentication.
   - `FLEX_IP`: Flex server IP address.

### Usage:
```bash
python db_clone.py --snap-date "2024-12-24" --src primary --dest dev-1 --db-names sales_us,sales_eu --suffix "_backup"
```
"""

import os
import random
import sys
import time
from datetime import date, datetime, timezone
from typing import Tuple, List, Dict, Optional

import fire
import requests

# Disable SSL warnings for requests (not recommended for production)
requests.packages.urllib3.disable_warnings()

# Environment Variables
FLEX_TOKEN = os.getenv("FLEX_TOKEN", "")
FLEX_IP = os.getenv("FLEX_IP", "")

if not FLEX_TOKEN or not FLEX_IP:
    print("FLEX_TOKEN and FLEX_IP environment variables must be set.")
    sys.exit(1)

############################################
# Helper Functions
############################################


def _go_no_go(msg: str):
    """Prompt the user for confirmation before proceeding."""
    try:
        answer = input(f"{msg} [y/n]: ")
    except KeyboardInterrupt:
        answer = "n"
        print()  # Handle newline after CTRL+C

    if answer.lower() != "y":
        print("Aborted by user.")
        sys.exit(0)


def _tracking_id() -> str:
    """Generate a random string to track requests in Flex logs."""
    # Generate a 10-character alphanumeric string
    return "".join(
        random.choices(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=10
        )
    )


def _get_topology() -> dict:
    """Retrieve the full topology from the Flex API."""
    url = f"https://{FLEX_IP}/api/ocie/v1/topology"
    headers = {
        "Authorization": f"Bearer {FLEX_TOKEN}",
        "hs-ref-id": _tracking_id(),
        "Accept": "application/json",
    }
    response = requests.get(url, verify=False, headers=headers)

    # Handle HTTP errors
    if response.status_code // 100 != 2:
        print(
            f"Failed to retrieve topology. Error: {response.status_code} {response.text}"
        )
        sys.exit(1)

    return response.json()


def _host_topology(host_name: str, topology: List[dict]) -> Optional[dict]:
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


def _host_names(topology: List[dict]) -> List[str]:
    """Retrieve a sorted list of host names from the topology.

    Args:
        topology (List[dict]): The full topology data.

    Returns:
        List[str]: A sorted list of host names.
    """
    return sorted(host["host"]["name"] for host in topology)


def _get_snapshot(
    host_topology: dict, dt: date, db_ids: set[str]
) -> Tuple[Optional[datetime], Optional[str]]:
    """Find the most recent snapshot for a given date and database IDs.

    Args:
        host_topology (dict): The topology data for the host.
        dt (date): The date of the snapshot to find.
        db_ids (set[str]): The database IDs to match.

    Returns:
        Tuple[Optional[datetime], Optional[str]]: The latest snapshot timestamp and ID, or (None, None) if not found.
    """
    matched_snapshots = []

    print(f"Searching for snapshots dated {dt} for databases: {db_ids}")
    for db in host_topology.get("databases", []):
        for snap in db.get("db_snapshots", []):
            snapshot_ts = datetime.fromtimestamp(snap["timestamp"], tz=timezone.utc)

            # Match snapshots by date
            if snapshot_ts.date() != dt:
                continue

            # Ensure all required DB IDs are present in the snapshot
            if not db_ids.issubset(set(snap["db_ids"])):
                continue

            matched_snapshots.append((snapshot_ts, snap["id"]))

    # Return the latest matching snapshot, or (None, None) if no match
    return max(matched_snapshots, default=(None, None))


def _make_snapshot(
    snapshot_id: str, dest_host_id: str, dbs: Dict[str, str], suffix: str
):
    """Send a request to clone databases from a snapshot.

    Args:
        snapshot_id (str): The ID of the snapshot to clone.
        dest_host_id (str): The ID of the destination host.
        dbs (Dict[str, str]): A mapping of database names to IDs.
        suffix (str): The suffix to append to cloned database names.
    """
    payload = {
        "destinations": [
            {
                "host_id": dest_host_id,
                "db_id": db_id,
                "db_name": db_name + suffix,
            }
            for db_name, db_id in dbs.items()
        ]
    }

    url = f"https://{FLEX_IP}/flex/api/v1/db_snapshots/{snapshot_id}/clone"
    headers = {
        "Authorization": f"Bearer {FLEX_TOKEN}",
        "hs-ref-id": _tracking_id(),
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    response = requests.post(url, json=payload, verify=False, headers=headers)

    # Handle HTTP errors
    if response.status_code // 100 != 2:
        print(
            f"Failed to clone snapshot. Error: {response.status_code} {response.text}"
        )
        sys.exit(1)

    task = response.json()
    success, task_result = _wait_for_task(task)

    if not success:
        print(
            f"Snapshot cloning failed. Error: {task_result.get('error', 'Unknown error')}"
        )
    else:
        print(f"Snapshot cloned successfully. Result: {task_result['result']}")


def _wait_for_task(task: dict) -> Tuple[bool, dict]:
    """Poll the task API to check task completion.

    Args:
        task (dict): The task data returned from the initial request.

    Returns:
        Tuple[bool, dict]: A boolean indicating success and the final task data.
    """
    headers = {
        "Authorization": f"Bearer {FLEX_TOKEN}",
        "hs-ref-id": _tracking_id(),
        "Accept": "application/json",
    }

    while task["state"] == "running":
        time.sleep(5)
        print(".", end="", flush=True)
        response = requests.get(
            f"https://{FLEX_IP}{task['location']}", verify=False, headers=headers
        )

        if response.status_code // 100 == 2:
            task = response.json()

    print()  # Add a newline after dots
    return task["state"] == "completed", task


############################################
# Main Command
############################################


def run(
    snap_date: str,
    src: str,
    dest: str,
    db_names: str,
    suffix: str,
):
    """Main function to orchestrate snapshot cloning.

    Args:
        snap_date (str): Snapshot date in "yyyy-mm-dd" format.
        src (str): Source host name.
        dest (str): Destination host name.
        db_names (str): Comma-separated list of database names to clone.
        suffix (str): Suffix to append to cloned database names.
    """
    print(f"Cloning databases from `{snap_date}` snapshot: {src} -> {dest}")
    print(f"Databases: {db_names}")
    print(f"Suffix: {suffix}")

    dt = date.fromisoformat(snap_date)

    topology = _get_topology()

    # Retrieve source host topology
    src_topology = _host_topology(src, topology)
    if not src_topology:
        print(
            f"Source host `{src}` not found. Available hosts: {_host_names(topology)}"
        )
        sys.exit(1)

    # Retrieve destination host topology
    dest_topology = _host_topology(dest, topology)
    if not dest_topology:
        print(
            f"Destination host `{dest}` not found. Available hosts: {_host_names(topology)}"
        )
        sys.exit(1)

    # Map database names to IDs
    db_map = {
        db["name"]: db["id"]
        for db in src_topology["databases"]
        if db["name"] in db_names
    }

    breakpoint()
    # Validate all databases are found
    if len(db_map) != len(db_names):
        missing_dbs = set(db_names) - set(db_map.keys())
        print(f"Missing databases: {missing_dbs}")
        sys.exit(1)

    # Find the relevant snapshot
    snap_ts, snap_id = _get_snapshot(src_topology, dt, set(db_map.values()))

    if not snap_id:
        print(f"No snapshot found for `{dt}` containing all requested databases.")
        sys.exit(1)

    print(f"Cloning databases from snapshot `{snap_id}` taken on `{snap_ts}`")
    for db_name in db_names:
        print(f"{src}[{db_name}] -> {dest}[{db_name + suffix}]")

    _go_no_go("Proceed with cloning?")
    _make_snapshot(snap_id, dest_topology["host"]["id"], db_map, suffix)


if __name__ == "__main__":
    fire.Fire(run)
