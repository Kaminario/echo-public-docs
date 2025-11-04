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


def _fetch_topology():
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


def map_db_name_2_db_id(host_topology: dict) -> dict[str, str]:
    mp = dict()
    for db in host_topology["databases"]:
        mp[db["name"]] = db["id"]
    return mp


def _find_snapshot(host_topology: dict, snapshot_id: str) -> dict:
    for db in host_topology["databases"]:
        for snap in db["db_snapshots"]:
            if snap["id"] == snapshot_id:
                return snap
    return None


def _construct_destination(
    host_ids: set[str], db_names: set[str], name_suffix: str, snapshot_id: str
) -> list[dict]:
    destinations = []

    topology = _fetch_topology()

    # the api accept db_ids, not db_names, we can get the db_id from the topology
    # run over all host and find the snapshot by it's id
    # this host should contain all the databases from snapshot

    for host_topology in topology:
        snap = _find_snapshot(host_topology, snapshot_id)
        if not snap:
            continue

        db_name_2_db_id = map_db_name_2_db_id(host_topology)
        break

    # create a list of destinations
    for host_id in host_ids:
        for db_name in db_names:
            destinations.append(
                {
                    "host_id": host_id,
                    "db_id": db_name_2_db_id[db_name],
                    "db_name": f"{db_name}_{name_suffix}",
                }
            )

    return destinations


def _make_echo_dbs(snapshot_id: str, destinations: list[dict]) -> Tuple[bool, dict]:
    """Create Echo databases from a snapshot."""

    # perform a request to make a snapshot
    url = f"https://{FLEX_IP}/api/echo/v1/db_snapshots/{snapshot_id}/echo_db"

    tracking_id = _tracking_id()
    headers = {
        "Authorization": f"Bearer {FLEX_TOKEN}",
        "hs-ref-id": tracking_id,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    post_data = {"destinations": destinations}
    print(f"Creating Echo databases with tracking ID: {tracking_id}, data: {post_data}")

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
    snapshot_id: str,
    host_ids: list[str],
    db_names: list[str],
    name_suffix: str,
):
    """This script clones databases from a snapshot to a new databases on the desired hosts.

    Usage example:

    Set the following environment variables:
       - `FLEX_TOKEN`: Bearer token for Flex API authentication.
       - `FLEX_IP`: Flex server IP address.

    python make_echo_db.py --snapshot-id <snapshot-id> --host-ids <host-id-1,host-id-2> --db-names <db-name-1,db-name-2> --name-suffix <suffix-for-new-db>

    Args:
        snapshot_id (str): Snapshot ID to restore from
        host_ids (list[str]): List of Destination Host names to restore the snapshot to
        db_names (list[str]): List of database names from a snapshot to restore
        name_suffix (str): Suffix for the new database names
    """

    _ensure_env()
    destinations = _construct_destination(host_ids, db_names, name_suffix, snapshot_id)
    print(f"Going to create Echo databases: {destinations}")
    _go_no_go(msg="Do you want to continue?")
    _make_echo_dbs(snapshot_id, destinations)


def parse_arguments():
    parser = OptionParser(
        usage="usage: %prog [options]",
        description="This script creates an instances of databases on the hosts",
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
        "-s",
        "--snapshot-id",
        dest="snapshot_id",
        help="Snapshot ID to restore from",
        metavar="SNAPSHOT_ID",
    )
    parser.add_option(
        "--host-ids",
        dest="host_ids",
        help="Comma-separated list of Destination Host names to restore the snapshot to",
        metavar="HOST_IDS",
    )
    parser.add_option(
        "--name-suffix",
        dest="name_suffix",
        help="Suffix for the new database names",
        metavar="NAME_SUFFIX",
    )
    parser.add_option(
        "--db-names",
        dest="db_names",
        help="Comma-separated list of database names to restore",
        type="string",
        metavar="DB_NAMES",
    )

    (options, _) = parser.parse_args()

    if not options.host_ids or not options.name_suffix:
        parser.print_help()
        sys.exit(1)

    global is_interactive
    is_interactive = options.interactive

    return {
        "snapshot_id": options.snapshot_id,
        "host_ids": options.host_ids.split(","),
        "db_names": options.db_names.split(","),
        "name_suffix": options.name_suffix,
    }


if __name__ == "__main__":
    args = parse_arguments()
    run(**args)
