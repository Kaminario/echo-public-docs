"""
This code will create snapshot for all databases in the source host.
It assumes that all the volumes are on the same VG.
Otherwise, it will create a snapshot for the fists one (AlphaBet sorted)

It uses Topology API to get the list of hosts, databases, VGs.

requirements:
pip install fire

usage:
python db_clone.py run --snap-date "2024-12-24" --src primary --dest dev-1
      --db-names sales_us,sales_eu --suffix "_bbbb34"
"""

import os
import random
import sys
import time
from datetime import date, datetime, timezone
from typing import Tuple

import fire
import requests

requests.packages.urllib3.disable_warnings()


FLEX_TOKEN = os.environ["FLEX_TOKEN"]
FLEX_IP = os.environ["FLEX_IP"]


############################################
# helper functions
############################################


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
    """random string [a-zA-Z0-9]{10} used to identify request at flex"""
    return "".join(
        random.choices(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=10
        )
    )


def _get_topology():
    """
    retrieve topology from flex
    """
    url = f"https://{FLEX_IP}/api/ocie/v1/topology"
    headers = {
        "Authorization": f"Bearer {FLEX_TOKEN}",
        "hs-ref-id": _tracking_id(),
        "Accept": "application/json",
    }
    r = requests.get(url, verify=False, headers=headers)

    if r.status_code // 100 != 2:
        print(f"Failed to get db topology. Error: {r.status_code} {r.text}")
        sys.exit(1)
    topology = r.json()
    return topology


def _get_snapshot(
    host_topology: dict, dt: date, db_ids: set[str]
) -> Tuple[datetime, str]:
    """
    get the snapshot id for the given date and db_ids
    that are present in the host_topology
    """
    # the topology is alrteady filtered by host name
    # select latest snapshot for the given date and db_ids

    matched_snapshots = []

    print(f"Looking for snapshot of {dt} for databases: {db_ids}")
    for db in host_topology["databases"]:
        for snap in db["db_snapshots"]:
            # convert timestamp to datetime
            sts = datetime.fromtimestamp(snap["timestamp"], tz=timezone.utc)
            # compare date only
            if sts.date() != dt:
                continue

            # the date of the snapshot is the same
            # check all required db_ids are present
            if not db_ids.issubset(set(snap["db_ids"])):
                continue

            # store the timestamp, snapshot id
            matched_snapshots.append((sts, snap["id"]))
    # return the latest snapshot
    if not matched_snapshots:
        return None, None

    return max(matched_snapshots)


def _host_topology(host_name, topology=None):
    """
    get the only topology of the host
    """
    topos = [t for t in topology if t["host"]["name"] == host_name]
    if not topos:
        return None
    return topos[0]


def _host_names(topology):
    """
    list of existing host names
    """
    return sorted([t["host"]["name"] for t in topology])


############################################
# command
############################################


def run(
    snap_date: str,
    src: str,
    dest: str,
    db_names: list[str],
    suffix: str,
):
    """
    snap_date format is "yyyy-mm-dd"
    db_names are comma separated list of database names
    suffix is the suffix to add to the cloned databases names
    """
    print(f"Cloning databases from snapshot `{snap_date}` {src} -> {dest}")
    print(f"db_names: {db_names}")
    print(f"suffix: {suffix}")

    dt = date.fromisoformat(snap_date)

    if isinstance(db_names, str):
        db_names = [db_names]

    full_topology = _get_topology()

    src_host_topology = _host_topology(src, full_topology)
    if not src_host_topology:
        print(f"source host {src} not found")
        print(f"The options are {_host_names(full_topology)}")
        sys.exit(1)

    dest_host_topology = _host_topology(dest, full_topology)
    if not dest_host_topology:
        print(f"destination host {dest} not found")
        print(f"The options are {_host_names(full_topology)}")
        sys.exit(1)

    dest_host_id = dest_host_topology["host"]["id"]

    # get db_ids for the databases
    db_id_2_name = {
        db["name"]: db["id"]
        for db in src_host_topology["databases"]
        if db["name"] in db_names
    }

    # validate we have all dbs and ids in the topology
    if len(db_id_2_name) != len(db_names):
        print(f"some databases not found: {set(db_names) - set(db_id_2_name.keys())}")
        sys.exit(1)

    # get snapshot id where all dbs are present
    snap_ts, snapshot_id = _get_snapshot(
        src_host_topology, dt, set(db_id_2_name.values())
    )

    if not snapshot_id:
        print(f"snapshot for {dt} not found")
        sys.exit(1)

    print(
        f"going to clone the following databases from snap id '{snapshot_id}' taken on '{snap_ts}'"
    )

    for db_name in db_names:
        print(f"{src}[{db_name}] -> {dest}[{db_name + suffix}]")

    _go_no_go(msg="Do you want to continue?")

    _make_snapshot(snapshot_id, dest_host_id, db_id_2_name, suffix)


def _make_snapshot(
    snapshot_id: str, dest_host_id: str, dbs: dict[str, str], suffix: str
) -> Tuple[bool, dict]:

    payload = {"destinations": []}
    for db_name, db_id in dbs.items():
        payload["destinations"].append(
            {
                "host_id": dest_host_id,
                "db_id": db_id,
                "db_name": db_name + suffix,
            }
        )

    # perform a request to make a snapshot
    url = f"https://{FLEX_IP}/flex/api/v1/db_snapshots/{snapshot_id}/clone"

    headers = {
        "Authorization": f"Bearer {FLEX_TOKEN}",
        "hs-ref-id": _tracking_id(),
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    r = requests.post(
        url,
        json=payload,
        verify=False,
        headers=headers,
    )
    if r.status_code // 100 != 2:
        print(f"Failed to clone snapshot. Error: {r.status_code} {r.text}")
        sys.exit(1)

    task = r.json()
    success, task = _wait_for_task(task)
    if not success:
        print(f"Failed to clone. Error: {task['error']}")
    else:
        print(f"cloned. `{task['result']}`")


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


if __name__ == "__main__":
    fire.Fire()
