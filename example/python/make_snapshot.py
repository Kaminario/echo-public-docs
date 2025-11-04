# Copyright (c) 2025 Silk Technologies, Inc.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

import os
import random
import sys
import time
from enum import Enum
from optparse import OptionParser
from typing import Tuple

import requests

requests.packages.urllib3.disable_warnings()

# Environment Variables
FLEX_TOKEN = os.getenv("FLEX_TOKEN", "")
FLEX_IP = os.getenv("FLEX_IP", "")
is_interactive = False

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


def _go_no_go(msg):
    if not is_interactive:
        return
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


class CLevel(str, Enum):
    crash = "crash"
    application = "application"


def _host_topology(host_id):
    topo = _get_topology()
    return [t for t in topo if t["host"]["id"] == host_id][0]


def _get_topology():
    url = f"https://{FLEX_IP}/api/echo/v1/topology"
    tracking_id = _tracking_id()
    headers = {
        "Authorization": f"Bearer {FLEX_TOKEN}",
        "hs-ref-id": tracking_id,
        "Accept": "application/json",
    }
    print(f"Fetching topology with tracking ID: {tracking_id}")

    r = requests.get(url, verify=False, headers=headers)

    if r.status_code // 100 != 2:
        exit_with_error(
            f"Failed to get database topology. tracking_id: {tracking_id} Error: {r.status_code} {r.text}"
        )

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
    url = f"https://{FLEX_IP}/api/echo/v1/db_snapshots"

    tracking_id = _tracking_id()
    headers = {
        "Authorization": f"Bearer {FLEX_TOKEN}",
        "hs-ref-id": tracking_id,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    post_data = {
        "source_host_id": host_id,
        "database_ids": list(db_ids),
        "name_prefix": name_prefix,
        "consistency_level": consistency_level.value,
    }
    print(f"Creating snapshot with tracking ID: {tracking_id}, data: {post_data}")

    r = requests.post(
        url,
        json=post_data,
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
        "location": "/api/echo/v1/tasks/Fj3U7QTsDDWL45ikk0bvk2tsanfC3HBJH2zVyJvfRLc",
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
    host_id: str,
    name_prefix: str,
    consistency_level: CLevel = CLevel.crash,
    db_names: list[str] = None,
):
    """This script creates a snapshot of databases on the source host.

    Usage example:

    Set the following environment variables:
       - `FLEX_TOKEN`: Bearer token for Flex API authentication.
       - `FLEX_IP`: Flex server IP address.

    python make_snapshot.py --host-name <host-name> --name-prefix <prefix-for-snapshot> --consistency-level <crash|application> --db-names <comma-separated-db-names>

    Args:
        host_id (str): Name of the host to take snapshot from
        name_prefix (str): Prefix for the snapshot name
        consistency_level (CLevel): Consistency level of the taken snapshot. Options are ['crash', 'application']
        db_names (set[str]): List of database names to snapshot. If not provided, all databases will be snapshotted.
    """

    _ensure_env()

    # get_database_ids by host_id by vg
    topology = _host_topology(host_id)

    db_id_2_name = _map_db_id_2_db_name(topology)

    # If db_names is provided, filter the databases
    if db_names:
        available_db_names = set(db_id_2_name.values())

        # Check if all requested databases exist
        missing_dbs = db_names - available_db_names
        if missing_dbs:
            exit_with_error(
                f"Error: The following requested databases do not exist on host {host_id}: {missing_dbs}"
            )

        # Filter db_id_2_name to include only requested databases
        filtered_db_id_2_name = {
            db_id: name for db_id, name in db_id_2_name.items() if name in db_names
        }
        db_id_2_name = filtered_db_id_2_name

    print(
        f"going to make snapshot of the host `{host_id}` with the following databases: {list(db_id_2_name.values())}"
    )

    _go_no_go(msg="Do you want to continue?")

    success, task = _make_snapshot(
        host_id, set(db_id_2_name.keys()), name_prefix, consistency_level
    )
    if not success:
        exit_with_error(f"Failed to create snapshot. Error: {task['error']}")
    else:
        print(f"Snapshot created successfully. Task: {task}")


def parse_arguments():
    parser = OptionParser(
        usage="usage: %prog [options]",
        description="This script creates a snapshot of databases on the source host.",
    )
    parser.add_option(
        "-i",
        "--interactive",
        dest="interactive",
        action="store_true",
        default=False,
        help="Interactive mode",
    )
    parser.add_option(
        "--host-id",
        dest="host_id",
        help="Host id to take snapshot from",
        metavar="HOST_ID",
    )
    parser.add_option(
        "-p",
        "--name-prefix",
        dest="name_prefix",
        help="Prefix for the snapshot name",
        metavar="NAME_PREFIX",
    )
    parser.add_option(
        "-c",
        "--consistency-level",
        dest="consistency_level",
        default="crash",
        help="Consistency level of the taken snapshot. Options are ['crash', 'application']",
        metavar="CONSISTENCY_LEVEL",
    )
    parser.add_option(
        "-d",
        "--db-names",
        dest="db_names",
        default="",
        help="Comma-separated list of database names to snapshot. If not provided, all databases will be snapshotted.",
        metavar="DB_NAMES",
    )

    (options, _) = parser.parse_args()

    if not options.host_id or not options.name_prefix:
        parser.print_help()
        sys.exit(1)

    # Convert string to CLevel enum
    consistency_level = CLevel.crash
    if options.consistency_level == "application":
        consistency_level = CLevel.application

    # Convert db_names string to set
    if options.db_names:
        db_names = {name.strip() for name in options.db_names.split(",")}
    else:
        db_names = set()

    global is_interactive
    is_interactive = options.interactive

    return {
        "host_id": options.host_id,
        "name_prefix": options.name_prefix,
        "consistency_level": consistency_level,
        "db_names": db_names,
    }


if __name__ == "__main__":
    args = parse_arguments()
    run(**args)
