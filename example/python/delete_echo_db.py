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


def _host_topology(host_id):
    topo = _get_topology()
    return [t for t in topo if t["host"]["id"] == host_id][0]


def _get_topology():
    url = f"https://{FLEX_IP}/api/ocie/v1/topology"
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


def _map_db_name_2_db_id(host_topology: dict) -> dict[str, str]:
    mp = dict()
    for db in host_topology["databases"]:
        mp[db["name"]] = db["id"]
    return mp


def _delete_echo_db(host_id: str, db_id: str) -> tuple[bool, dict]:
    """Delete an Echo database from the specified host."""

    url = f"https://{FLEX_IP}/flex/api/v1/ocie/clone"
    tracking_id = _tracking_id()
    headers = {
        "Authorization": f"Bearer {FLEX_TOKEN}",
        "hs-ref-id": tracking_id,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    post_data = {"host_id": host_id, "database_id": db_id}
    print(f"Deleting Echo database with tracking ID: {tracking_id}, data: {post_data}")

    r = requests.delete(
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


def run(host_id: str, db_names: list[str]):
    """This script deletes an Echo databases from the host.

    Usage example:

    Set the following environment variables:
       - `FLEX_TOKEN`: Bearer token for Flex API authentication.
       - `FLEX_IP`: Flex server IP address.

    python delete_echo_db.py --host-id <host-id> --db-name <db-name>

    Args:
        host_id (str): Name of the host to take snapshot from
        db_names (str): Databases names to delete
    """

    _ensure_env()

    # get_database_ids by host_id by vg
    topology = _host_topology(host_id)
    db_name_2_id = _map_db_name_2_db_id(topology)

    failures = []

    print(f" Going to delete Echo databases {db_names} from host '{host_id}'")

    _go_no_go(msg="Do you want to continue?")

    for db_name in db_names:
        db_id = db_name_2_id.get(db_name)
        if not db_id:
            print(f"Database '{db_name}' not found on host '{host_id}'")
            continue

        print(f"Deleting Echo database '{db_name}'")

        success, task = _delete_echo_db(host_id, db_id)
        if not success:
            failures.append((db_id, db_name, host_id, task))

    if failures:
        exit_with_error(f"Failed to delete databases. Error: {failures}")
    else:
        print(f"Echo databases deleted successfully.")


def parse_arguments():
    parser = OptionParser(
        usage="usage: %prog [options]",
        description="This script deletes Echo a databases from the host.",
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
        "--db-names",
        dest="db_names",
        help="Comma-separated list of database names to delete",
        metavar="DB_NAME",
    )

    (options, _) = parser.parse_args()

    if not options.host_id or not options.db_names:
        parser.print_help()
        sys.exit(1)

    global is_interactive
    is_interactive = options.interactive

    return {
        "host_id": options.host_id,
        "db_names": options.db_names.split(","),
    }


if __name__ == "__main__":
    args = parse_arguments()
    run(**args)
