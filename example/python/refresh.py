# Copyright (c) 2025 Silk Technologies, Inc.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

import os
import random
import sys
import time
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
        print("")

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
    host_id: str,
    db_names: tuple[str],
    keep_backup: bool,
    snapshot_id: str,
) -> Tuple[bool, dict]:

    # perform a request to refresh databases
    url = f"https://{FLEX_IP}/api/echo/v1/hosts/{host_id}/databases/_refresh"

    tracking_id = _tracking_id()
    headers = {
        "Authorization": f"Bearer {FLEX_TOKEN}",
        "hs-ref-id": tracking_id,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    post_data = {
        "db_names": db_names,
        "keep_backup": keep_backup,
        "snapshot_id": snapshot_id,
    }
    print(f"Making refresh request with tracking ID: {tracking_id}, data: {post_data}")

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
    host_id: str,
    db_names: tuple[str],
    keep_backup: bool,
    snapshot_id: str,
):
    """This script refreshes a databases on host from a snapshot.

    Usage example:

    Set the following environment variables:
       - `FLEX_TOKEN`: Bearer token for Flex API authentication.
       - `FLEX_IP`: Flex server IP address.

    python refresh.py --host-name <host-name> --db-names <db-name-1,db-name-2> --keep-backup --snapshot-id <snapshot-id>

    Args:
        host_id (str): Host id to take snapshot from
        db_names (list[str]): List of database names to refresh
        keep_backup (bool): Keep backup of the current databases by renaming them
        snapshot_id (str): Snapshot id to refresh from
    """

    _ensure_env()

    print(f"Going to refresh databases: {db_names}")

    _go_no_go(msg="Do you want to continue?")

    print(f"refreshing")
    success, task = _make_refresh(host_id, db_names, keep_backup, snapshot_id)
    if not success:
        exit_with_error(f"Failed to refresh databases. Error: {task['error']}")
    else:
        print(f"Databases refreshed successfully.")


def parse_arguments():
    parser = OptionParser(
        usage="usage: %prog [options]",
        description="This script refreshes databases on host from a snapshot.",
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
        help="Host name to take snapshot from",
        metavar="HOST_ID",
    )
    parser.add_option(
        "--db-names",
        dest="db_names",
        help="Comma-separated list of database names to refresh",
        metavar="DB_NAMES",
    )
    parser.add_option(
        "--keep-backup",
        dest="keep_backup",
        action="store_true",
        default=False,
        help="Keep backup of the current databases by renaming them",
    )
    parser.add_option(
        "--snapshot-id",
        dest="snapshot_id",
        help="Snapshot id to refresh from",
        metavar="SNAPSHOT_ID",
    )

    (options, _) = parser.parse_args()

    if not options.host_id or not options.db_names or not options.snapshot_id:
        parser.print_help()
        sys.exit(1)

    # Parse db_names to tuple
    db_names = tuple(options.db_names.split(","))

    global is_interactive
    is_interactive = options.interactive

    return {
        "host_id": options.host_id,
        "db_names": db_names,
        "keep_backup": options.keep_backup,
        "snapshot_id": options.snapshot_id,
    }


if __name__ == "__main__":
    args = parse_arguments()
    run(**args)
