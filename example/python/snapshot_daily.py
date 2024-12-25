"""
This code will create snapshot for all databases in the source host.

It uses Topology API to get the list of hosts, databases, VGs.

requirements:
pip install fire

usage:
python snapshot_daily.py run --host-name <host name>
"""

import os
import random
import sys
import time
from typing import Tuple

import fire
import requests

requests.packages.urllib3.disable_warnings()


FLEX_TOKEN = os.environ["FLEX_TOKEN"]
FLEX_IP = os.environ["FLEX_IP"]


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
        print(f"Failed to get db topology. Error: {r.status_code} {r.text}")
        sys.exit(1)
    topology = r.json()

    return topology


def _group_dbs(host_topology: dict) -> dict:
    # currently we support only one VG per snapshot
    # so we will group all databases by VG

    # accomulate all databases by VG, order of the dbs is not important
    # groups_ids is an associative array where the key is VG id and the value is a set of db ids
    # groups_names is an associative array where the key is VG id and the value is a set of db names

    groups_ids = dict()
    groups_names = dict()
    for db in host_topology["databases"]:
        for file in db["files"]:
            # add the db to the VG
            if file["volume_group_id"] not in groups_ids:
                groups_ids[file["volume_group_id"]] = set()
                groups_names[file["volume_group_id"]] = set()

            groups_ids[file["volume_group_id"]].add(db["id"])
            groups_names[file["volume_group_id"]].add(db["name"])

    return groups_ids, groups_names


def _make_snapshot(host_id: str, db_ids: set[str]) -> Tuple[bool, dict]:

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
        },
        verify=False,
        headers=headers,
    )
    if r.status_code // 100 != 2:
        return False, {"error": r.text}

    task = r.json()

    return _wait_for_task(task)


def run(host_name: str):
    """
    Create snapshot for all databases in the source host related to a common VG
    If there is more than one VG it will create a snapshot for the fists one.

    It uses Topology API to get the list of hosts, databases, VGs.

    curl -k 'https://{FLEX_IP}/flex/api/v1/db_snapshots' -X POST -H 'Accept: application/json'
      -H 'hs-ref-id: trackid_123' -H 'Content-Type: application/json'
      --data-raw '{"source_host_id": "host_id","database_ids": ["5","6"],"destinations": []}'

    the call will return the status of a finished task.
    """

    # get_database_ids by host_id by vg
    topology = _host_topology(host_name)
    host_id = topology["host"]["id"]

    db_ids_by_vg, db_names_by_vg = _group_dbs(topology)

    print(f"making snapshot/s of the host `{host_name}` with the following databases:")
    for vg_id in db_ids_by_vg:
        db_ids = db_ids_by_vg[vg_id]
        db_names = db_names_by_vg[vg_id]
        for db_name in db_names:
            print(f"\t{db_name}")

    _go_no_go(msg="Do you want to continue?")

    for vg_id in db_ids_by_vg:
        db_ids = db_ids_by_vg[vg_id]
        db_names = db_names_by_vg[vg_id]
        print(f"making snapshot of databases: {db_names}")
        success, task = _make_snapshot(host_id, db_ids)
        if not success:
            print(f"Failed to create snapshot. Error: {task['error']}")
            _go_no_go(msg="Do you want to continue?")
        else:
            print(f"snapshot created: `{task['result']['db_snapshot']['id']}`")
            print(f"\tdbs in the snapshot: {db_names}")


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
